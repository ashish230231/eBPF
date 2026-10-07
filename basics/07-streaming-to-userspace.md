# 07 — Streaming Events to User Space

`bpf_printk` + `trace_pipe` is a debugging toy: one global buffer, text only,
shared with every other BPF program, slow. A real sensor streams **structured
events** from the kernel to its own user-space process, which enriches,
filters, and ships them. This file covers that path end to end.

---

## 1. The two halves of a sensor

```
   ┌─────────────────────── KERNEL ───────────────────────┐
   │  BPF programs on hooks                                 │
   │    → build `struct event`                              │
   │    → push into RINGBUF / PERF buffer                   │
   └───────────────────────────┬──────────────────────────┘
                               │  shared memory (mmap)
   ┌───────────────────────────▼──────────────────────────┐
   │  USER SPACE: the loader / agent  (C, C++, Go, Rust)    │
   │    load + attach programs, configure maps               │
   │    poll buffer → callback per event                     │
   │    enrich (process tree, container, k8s metadata)       │
   │    apply rules / detections                             │
   │    output: JSON, gRPC, Kafka, SIEM...                   │
   └────────────────────────────────────────────────────────┘
```

The kernel side should do **as little as possible**: capture, filter
cheaply, emit. Heavy logic belongs in user space.

---

## 2. Defining the event — the contract

Define the event struct once in a header included by **both** sides:

```c
// sensor.h
#pragma once
#define TASK_COMM_LEN 16
#define MAX_FILENAME 256

enum event_type { EVT_EXEC = 1, EVT_EXIT, EVT_OPEN, EVT_CONNECT };

struct event {
    u32 type;                 // which event this is
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 ts_ns;
    u64 cgroup_id;
    int ret;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME];
};
```

Rules: fixed-width types, order fields largest-first to avoid padding,
zero-initialize, and put a `type` field first so one buffer can carry many
event kinds. Real sensors version their schema.

---

## 3. Ring buffer (`BPF_MAP_TYPE_RINGBUF`) — the modern way

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);      // bytes, power of 2, multiple of page size
} events SEC(".maps");
```

### Reserve / submit (zero-copy)

```c
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;                          // buffer full → event dropped (count it!)

    e->type = EVT_EXEC;
    e->pid  = bpf_get_current_pid_tgid() >> 32;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // ... fill the rest directly in the buffer

    bpf_ringbuf_submit(e, 0);              // or bpf_ringbuf_discard(e, 0) to cancel
    return 0;
}
```

You write **directly into the shared buffer** — no extra copy, and the
reserved space can be larger than the 512 B stack. The verifier ensures every
reserved record is either submitted or discarded on every path.

`bpf_ringbuf_output(&events, &local, sizeof(local), 0)` is the copy-based
alternative when you've built the event elsewhere.

### Why ringbuf beat perf buffer

| | Perf buffer (`PERF_EVENT_ARRAY`) | Ring buffer (`RINGBUF`) |
|---|---|---|
| Buffers | one **per CPU** | **one shared** |
| Memory | N CPUs × size, mostly idle | one size, used efficiently |
| Ordering | per-CPU only; user space must re-sort | **global order preserved** |
| Copy | always copies from stack | reserve/submit = zero-copy |
| Variable size | awkward | natural |
| Kernel | 4.4+ | **5.8+** |

Use ringbuf unless you must support pre-5.8 kernels; sensors that support old
kernels detect support at startup and fall back to perf buffer.

### Wakeup tuning

Every submit can wake the consumer — expensive at high rates. Flags:
- `BPF_RB_NO_WAKEUP` — don't wake; consumer will catch up on next poll.
- `BPF_RB_FORCE_WAKEUP` — wake now.

High-volume sensors batch: no-wakeup normally, force-wakeup when the buffer is
filling (`bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA)`).

---

## 4. The user-space loader with libbpf

### 4.1 Skeletons

Instead of manually finding programs/maps by name, generate a **skeleton**:

```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c sensor.bpf.c -o sensor.bpf.o
bpftool gen skeleton sensor.bpf.o > sensor.skel.h
```

`sensor.skel.h` embeds the whole `.o` as bytes and gives you a typed API:

```c
struct sensor_bpf {
    struct bpf_object *obj;
    struct { struct bpf_map *events; ... } maps;
    struct { struct bpf_program *handle_exec; ... } progs;
    struct { struct bpf_link *handle_exec; ... } links;
    struct sensor_bpf__rodata { u32 target_pid; } *rodata;
    struct sensor_bpf__bss    { u64 dropped; }    *bss;
};
sensor_bpf__open(), __load(), __attach(), __destroy(), __open_and_load()
```

Single self-contained binary: no `.o` file to ship separately.

### 4.2 The lifecycle

```
   open      parse ELF, prepare maps/programs (nothing in kernel yet)
     │       ← set .rodata config, resize maps, disable programs HERE
   load      create maps, apply CO-RE relocations, verifier + JIT
     │       ← populate config/policy maps HERE
   attach    create links → programs start firing
     │
   run       poll ring buffer, handle events
     │
   destroy   detach links, close fds → kernel frees everything
```

### 4.3 A minimal loader

```c
#include <signal.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include "sensor.h"
#include "sensor.skel.h"

static volatile bool exiting;
static void on_sig(int s) { exiting = true; }

static int handle_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;
    printf("%-8s pid=%-7u ppid=%-7u %s\n",
           e->type == EVT_EXEC ? "EXEC" : "?", e->pid, e->ppid, e->comm);
    return 0;
}

int main(void)
{
    struct sensor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    skel = sensor_bpf__open();
    if (!skel) return 1;

    skel->rodata->target_pid = 0;            // config before load

    if ((err = sensor_bpf__load(skel)))   goto out;   // verifier runs here
    if ((err = sensor_bpf__attach(skel))) goto out;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) { err = -1; goto out; }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR) { err = 0; break; }
        if (err < 0) break;
    }
out:
    ring_buffer__free(rb);
    sensor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
```

Build:

```bash
cc -g -O2 loader.c -lbpf -lelf -lz -o sensor
sudo ./sensor
```

Useful extras:
- `libbpf_set_print(fn)` — route libbpf's (and the verifier's) log messages.
- `bpf_program__set_autoload(prog, false)` — skip programs the kernel can't
  support, before load.
- `bpf_map__set_max_entries(map, n)` — size maps at runtime, before load.

---

## 5. Event loss and backpressure

The buffer is finite. If user space can't keep up, `bpf_ringbuf_reserve`
returns NULL and the event is **dropped**. For a security sensor, silent drops
are a blind spot attackers can exploit (flood events to hide one).

Mitigations:
1. **Count drops** in a `.bss` or per-CPU counter and report them.
2. **Filter in the kernel** so fewer events are emitted (file 08).
3. **Bigger buffer** (MBs, not KBs, in production).
4. **Fast consumer**: the callback should just copy/enqueue; do enrichment on
   other threads.
5. **Prioritize**: separate ring buffers for critical vs. noisy events.

---

## 6. Other user ↔ kernel channels

| Channel | Direction | Use |
|---|---|---|
| Ring/perf buffer | kernel → user | events |
| Hash/array maps | both | config, policy, counters, caches |
| `.rodata` | user → kernel (before load) | static config, feature flags |
| `.bss` / `.data` | both | runtime flags, counters |
| Pinned maps (`/sys/fs/bpf`) | between processes | survive agent restarts, share with other tools |

---

## 7. Language choices for the user-space side

| Language | Library | Seen in |
|---|---|---|
| C | libbpf | libbpf-bootstrap, bcc libbpf-tools |
| C++ | libbpf (+ RAII wrappers) | Falco (libscap/libsinsp) |
| Go | cilium/ebpf (pure Go, `bpf2go` codegen) | Cilium, Tetragon, Pixie, Inspektor Gadget |
| Rust | libbpf-rs, Aya | newer tools |
| Python | BCC | older tooling, prototyping |

The BPF side is always restricted C (or Rust via Aya); only the loader differs.

---

## Check yourself

- Why is `bpf_printk` unsuitable for a real sensor?
- What advantages does ringbuf have over perf buffer?
- What can you configure between `__open()` and `__load()` that you can't
  after?
- What happens when the ring buffer is full, and why is that a security issue?
- Why should the ring buffer callback be fast?
