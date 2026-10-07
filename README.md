# eBPF Learning Journey

A hands-on repo tracking my path from zero to reading and building
production-grade eBPF security sensors. Everything here is written from scratch,
compiled, loaded into the kernel, and observed running — no copy-paste.

Follow the full curriculum in [`LEARNING_PLAN.md`](./LEARNING_PLAN.md).

---

## What is eBPF?

**eBPF** (extended Berkeley Packet Filter) lets you run small, sandboxed programs
*inside the Linux kernel* — safely, and without writing a kernel module or
rebooting.

The name is historical baggage; modern eBPF has little to do with packet
filtering. The real idea:

> Attach your own tiny program to a kernel event (a syscall, a network packet, a
> function entry) and observe or react to it, at kernel speed, with safety
> guaranteed by an in-kernel **verifier**.

### Why it matters

The kernel sees everything: every process that starts, every file opened, every
network connection. Normally your user-space code can't touch any of that
directly. eBPF gives you a safe hook into it. That unlocks:

- **Observability** — tracing, profiling, metrics (bpftrace, Pixie).
- **Networking** — load balancing, routing, firewalls (Cilium).
- **Security** — runtime threat detection and enforcement (Falco, Tetragon).

### How it stays safe

Kernel code that crashes takes down the whole machine. So every eBPF program
must first pass the **verifier**, which proves it terminates, never touches
out-of-bounds memory, and stays within strict limits. Power of the kernel, with
guardrails.

### The core mental model

```
your .bpf.c  →  clang (target=bpf)  →  .bpf.o bytecode
             →  verifier (safety proof)  →  JIT (native code)
             →  attach to a hook  →  runs automatically on each event
             →  emits data  →  user space reads it
```

An eBPF program has **two halves**: the *kernel-side* program (`.bpf.c`) and a
*user-space* part that loads it and reads results back (via `bpftool` early on,
a C/C++ loader later).

---

## Repo structure

```
eBPF ashish/
├── LEARNING_PLAN.md         # 12-week curriculum
├── README.md                # this file
├── basics/                  # prerequisite knowledge map, true basics → production sensors
│   ├── README.md             # reading order
│   ├── 00-glossary.md        # every abbreviation (PID, TGID, BTF, CO-RE, LSM, XDP...)
│   ├── 01-os-fundamentals.md
│   ├── 02-c-and-toolchain-fundamentals.md
│   ├── 03-ebpf-execution-model.md
│   ├── 04-btf-and-core.md
│   ├── 05-hook-points-catalog.md
│   ├── 06-maps-and-state.md
│   ├── 07-streaming-to-userspace.md
│   └── 08-production-sensor-patterns.md
├── common/
│   └── vmlinux.h            # generated kernel types (git-ignored, see below)
├── 01-hello/
│   ├── hello.bpf.c          # first program: kprobe on execve + bpf_printk
│   ├── CONCEPTS.md           # foundational vocabulary, explained in order
│   └── BASIC_FLOW_CHART.md   # diagrams of the load → attach → run lifecycle
├── 02-kprobe-unlink/
│   ├── kprobe-unlink.bpf.c  # kprobe + kretprobe on do_unlinkat; BPF_CORE_READ
│   ├── CONCEPTS.md           # entry vs return, safe kernel reads, CO-RE
│   └── BASIC_FLOW_CHART.md   # two-probe timeline + read-helper boundary
├── 03-fentry-unlink/
│   ├── fentry-link.bpf.c    # fentry + fexit on do_unlinkat; direct field reads
│   ├── CONCEPTS.md           # trampoline, BTF, direct args, BPF_PROG macro
│   └── BASIC_FLOW_CHART.md   # trampoline pipeline + entry/exit timeline
├── 04-opensnoop/
│   ├── opensnoop.bpf.c      # tracepoint on sys_enter_openat; PID filter
│   ├── CONCEPTS.md           # tracepoints, const volatile globals, kernel filter
│   └── BASIC_FLOW_CHART.md   # pipeline + filter-decision tree + .rodata timing
├── 05-bashreadline/
│   ├── bashreadline.bpf.c   # uretprobe on /bin/bash:readline; user-space read
│   ├── CONCEPTS.md           # uprobes, file-based hooks, bpf_probe_read_user_str
│   └── BASIC_FLOW_CHART.md   # pipeline + kernel/user memory boundary diagram
└── 06-sigsnoop/
    ├── sigsnoop.bpf.c       # kill() entry/exit tracepoints correlated via hash map
    ├── CONCEPTS.md           # BPF_MAP_TYPE_HASH, update/lookup/delete_elem, TID keys
    └── BASIC_FLOW_CHART.md   # map-as-mailbox lifecycle + entry/exit ctx diagram
```

More lessons (`07-ringbuf`, ...) get added as the plan progresses.

---

## Prerequisites

- Linux with a modern kernel (5.15+ recommended; this repo was built on 6.6).
  WSL2 Ubuntu works.
- `clang` / LLVM (14+; 18 used here) to compile BPF bytecode.
- A working `bpftool` to generate `vmlinux.h`, load programs, and inspect them.
- Kernel BTF exposed at `/sys/kernel/btf/vmlinux` (standard on modern kernels).
- Root access — loading eBPF needs `sudo`.

Quick install on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y clang llvm linux-tools-generic
```

> On some setups (e.g. WSL) the `bpftool` wrapper can't find a kernel-matched
> binary. Use the real one directly, e.g.
> `/usr/lib/linux-tools/*/bpftool`.

---

## Generate `vmlinux.h`

`vmlinux.h` is a large, kernel-specific header generated from your kernel's BTF.
It's git-ignored, so generate it once after cloning:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > common/vmlinux.h
```

---

## Build & run: 01-hello

```bash
cd 01-hello

# 1. Compile the C source into BPF bytecode
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../common \
      -c hello.bpf.c -o hello.bpf.o

# 2. Load into the kernel + auto-attach the kprobe (verifier runs here)
sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello autoattach

# 3. Watch it fire on every process launch (execve)
sudo cat /sys/kernel/debug/tracing/trace_pipe
#    Ctrl+C to stop watching (program stays loaded)

# 4. Unload when done
sudo rm /sys/fs/bpf/hello
```

See [`01-hello/BASIC_FLOW_CHART.md`](./01-hello/BASIC_FLOW_CHART.md) for the full
lifecycle and [`01-hello/CONCEPTS.md`](./01-hello/CONCEPTS.md) for the vocabulary.

---

## Where to learn eBPF online

A curated list, roughly ordered from "start here" to "go deep."

### Start here — concepts

- [ebpf.io](https://ebpf.io/) — the official landing page. Read *What is eBPF*
  and the *Hook Overview* first.
- [ebpf.io — "What is eBPF?" guide](https://ebpf.io/what-is-ebpf/) — the single
  best conceptual intro.
- [Brendan Gregg's eBPF page](https://www.brendangregg.com/ebpf.html) —
  performance-focused, from one of the field's most prolific practitioners.

### Hands-on tutorials

- [eunomia-bpf — bpf-developer-tutorial](https://eunomia.dev/tutorials/) —
  progressive, example-driven lessons (the "Hello World" tutorial series). Great
  companion to this repo.
- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) — the canonical
  scaffold for real libbpf + CO-RE programs in C. Study these examples closely.
- [BCC tutorials](https://github.com/iovisor/bcc/blob/master/docs/tutorial.md) —
  the older BCC toolchain; still useful for quick Python-based experiments.
- [bpftrace](https://github.com/bpftrace/bpftrace) — a high-level tracing
  language; excellent for one-liners and learning what's *possible*.

### Reference & docs

- [Kernel BPF documentation](https://docs.kernel.org/bpf/) — the authoritative
  source: program types, maps, the verifier, helpers.
- [libbpf documentation](https://libbpf.readthedocs.io/) — the user-space
  library used by production sensors.
- [BPF helper reference (man page)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
  — every helper function you can call from a BPF program.
- [BPF CO-RE guide (Andrii Nakryiko)](https://nakryiko.com/posts/bpf-portability-and-co-re/)
  — the definitive explainer on Compile Once, Run Everywhere.
- [BPF ring buffer (Andrii Nakryiko)](https://nakryiko.com/posts/bpf-ringbuf/) —
  how modern sensors stream events to user space.

### Books

- *Learning eBPF* by Liz Rice (O'Reilly) — the best single book to start with.
- *BPF Performance Tools* by Brendan Gregg — deep, tracing/performance oriented.
- *Linux Observability with BPF* by Fontana & Calavera — concise practical intro.

### Production sensors to study (Month 3 of the plan)

- [Cilium](https://github.com/cilium/cilium) — eBPF-based networking & security.
- [Tetragon](https://github.com/cilium/tetragon) — runtime security observability
  and enforcement.
- [Falco](https://github.com/falcosecurity/falco) — cloud-native runtime threat
  detection.
- [Pixie](https://github.com/pixie-io/pixie) — auto-instrumented observability.

### Communities

- [eBPF Slack](https://ebpf.io/slack) — active community, good for questions.
- [eBPF Summit talks](https://ebpf.io/summit/) — recorded conference sessions.

---

## Progress

- [x] **Week 1 — Environment + first program.** `01-hello` compiles, loads, and
  prints on every `execve` via a kprobe + `bpf_printk`.
- [x] **kprobe/kretprobe — file deletion monitor.** `02-kprobe-unlink` hooks
  `do_unlinkat` on entry + return, reading the filename with `BPF_CORE_READ`.
- [x] **fentry/fexit — modern file deletion monitor.** `03-fentry-unlink` hooks
  the same function via a BPF trampoline, reads fields directly, and sees the
  return value alongside the arguments in `fexit`.
- [x] **Tracepoint + global variables — file-open snooper.** `04-opensnoop` hooks
  the stable `sys_enter_openat` tracepoint and filters by PID in the kernel using
  a `const volatile` global variable (`.rodata`) set from user space before load.
- [x] **Uprobe/uretprobe — bash command sniffer.** `05-bashreadline` hooks
  `readline`'s return inside `/bin/bash` itself, crossing the kernel/user-space
  boundary with `bpf_probe_read_user_str` to capture every typed command line.
- [x] **Hash maps — signal sniffer.** `06-sigsnoop` correlates `kill()`'s entry
  and exit tracepoints through a `BPF_MAP_TYPE_HASH` keyed by TID, combining
  data from two separate events into one printed record.
- [ ] Week 2 — libbpf skeleton + C user-space loader.
- [ ] Week 3 — Maps (per-PID syscall counter).
- [ ] Week 4 — Ring buffer event streaming.
- [ ] ... (see [`LEARNING_PLAN.md`](./LEARNING_PLAN.md))

---

*Learning in public. Everything here is written by hand to actually understand
it, not just to make it run.*
