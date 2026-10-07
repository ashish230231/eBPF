# 06 — Maps, State, and Reading Memory Safely

A BPF program has a 512-byte stack and forgets everything when it returns.
Everything a sensor *remembers* — process info, config, in-flight syscalls,
counters, events to ship to user space — lives in **maps**. This file covers
every map type that matters and the helpers for moving data safely.

---

## 1. What a map is

A **map** is a kernel-resident data structure, created through the `bpf()`
syscall and referenced by an fd. It can be accessed by:

- any number of BPF programs (sharing state between hooks)
- user space (via the fd: read config in, read results out)
- multiple invocations of the same program over time

```
     BPF prog A (exec hook)     BPF prog B (exit hook)
           │   write                  │   read/delete
           ▼                          ▼
     ┌─────────────────────────────────────┐
     │              MAP                      │   kernel memory
     └───────────────────┬─────────────────┘
                         │   read / write via bpf() syscall
                         ▼
                 user-space loader
```

## 2. Declaring maps (libbpf BTF style)

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct proc_info);
    // optional:
    // __uint(map_flags, BPF_F_NO_PREALLOC);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} procs SEC(".maps");
```

libbpf reads `.maps` from the ELF and creates each map before loading the
programs that reference them. Sizes are fixed at creation time.

## 3. Core map helpers (BPF side)

```c
void *bpf_map_lookup_elem(map, const void *key);           // pointer into map or NULL
long  bpf_map_update_elem(map, key, value, flags);         // BPF_ANY / BPF_NOEXIST / BPF_EXIST
long  bpf_map_delete_elem(map, key);
```

`lookup` returns a **pointer into the map's own memory** — writes through it
modify the map in place (no update call needed), and the verifier insists you
null-check it first.

User space has matching libbpf calls: `bpf_map__lookup_elem`,
`bpf_map__update_elem`, `bpf_map__delete_elem`, `bpf_map__get_next_key`
(iteration), and batch variants.

```bash
sudo bpftool map list
sudo bpftool map dump id <ID>          # pretty-printed using BTF
sudo bpftool map update id <ID> key 1 0 0 0 value ...
```

---

## 4. Map type catalog

### Generic storage

| Type | Shape | Use it for |
|---|---|---|
| `HASH` | key → value, dynamic | Per-PID/TID state, in-flight syscall correlation, process cache. |
| `ARRAY` | index 0..N-1 → value, preallocated, can't delete | Config, fixed counters, lookup tables. Fastest lookup. |
| `PERCPU_HASH` | per CPU copy of each value | High-frequency counters without contention. |
| `PERCPU_ARRAY` | per CPU array | Counters; **scratch buffers bigger than the 512 B stack**. |
| `LRU_HASH` | hash that evicts least-recently-used when full | Caches where losing old entries is OK — avoids "map full" failures. Production sensors use this a lot. |
| `LRU_PERCPU_HASH` | both | |
| `LPM_TRIE` | longest-prefix-match on keys | IP CIDR matching (`10.0.0.0/8`), path prefixes. |
| `BLOOM_FILTER` | membership test, false positives possible | Fast "definitely not in set" prefilter. |
| `QUEUE` / `STACK` | FIFO / LIFO, no keys | Simple work queues. |

### Event streaming (kernel → user space)

| Type | Notes |
|---|---|
| `RINGBUF` | One shared buffer for all CPUs, ordered, variable-size records, reserve/commit API. **The modern default** (5.8+). |
| `PERF_EVENT_ARRAY` | One buffer per CPU, copies data, events can interleave out of order across CPUs. Legacy / old-kernel fallback. |

Covered in detail in file 07.

### Program and map indirection

| Type | Use |
|---|---|
| `PROG_ARRAY` | Holds program fds; `bpf_tail_call(ctx, &progs, idx)` jumps into one. Used to split logic past size limits or dispatch per-syscall handlers (Falco does this). |
| `ARRAY_OF_MAPS` / `HASH_OF_MAPS` | Values are other maps — e.g. one inner policy map per container, swapped atomically. |

### Object-attached local storage

| Type | Attaches values to | Use |
|---|---|---|
| `TASK_STORAGE` | a `task_struct` | Per-task state that's freed automatically when the task dies — no manual cleanup, no PID reuse bugs. |
| `INODE_STORAGE` | an inode | Per-file labels/state (e.g. "this file was written by an untrusted process"). |
| `SK_STORAGE` | a socket | Per-connection state. |
| `CGRP_STORAGE` | a cgroup | Per-container state. |

These are increasingly preferred over `HASH` keyed by PID in modern sensors.

### Special

| Type | Use |
|---|---|
| `STACK_TRACE` | Stores stack traces captured by `bpf_get_stackid`. |
| `CGROUP_ARRAY` | Check cgroup membership. |
| `DEVMAP` / `CPUMAP` / `XSKMAP` | XDP redirect targets. |
| `SOCKMAP` / `SOCKHASH` | Socket redirection. |
| `ARENA` (6.9+) | Shared memory region with user space, pointer-based data structures. |

---

## 5. Global variables are maps too

```c
const volatile u32 target_pid = 0;     // .rodata  → read-only map, set before load
u64 events_dropped = 0;                // .bss     → read/write map
int config_flag = 1;                   // .data    → read/write map
```

libbpf turns each section into a single-entry array map. With a skeleton, user
space accesses them as plain struct fields:

```c
skel->rodata->target_pid = 1234;   // before load
skel->bss->events_dropped;         // read anytime after load
```

`.rodata` is frozen at load, so the verifier treats it as a **constant** and
can delete dead branches — great for feature flags.

---

## 6. Concurrency and correctness

The same program runs on all CPUs at once. Watch out for:

**Lost updates on shared counters:**
```c
u64 *cnt = bpf_map_lookup_elem(&counts, &key);
if (cnt) *cnt += 1;                       // ✗ racy across CPUs
if (cnt) __sync_fetch_and_add(cnt, 1);    // ✓ atomic
// or use a PERCPU map and sum in user space
```

**Multi-field updates:** use `struct bpf_spin_lock` inside the value, or
design so one writer owns each entry.

**PID reuse:** PIDs are recycled. If you never delete entries on exit, a new
process may inherit a dead one's state. Delete in `sched_process_exit`, use
LRU, or use `TASK_STORAGE`.

**Map full:** `update_elem` on a full `HASH` fails silently unless you check.
Count failures in a `.bss` counter so you know.

**Preallocation:** `HASH` preallocates all `max_entries` by default (fast, but
uses memory up front). `BPF_F_NO_PREALLOC` allocates lazily.

---

## 7. Entry/exit correlation pattern

The single most common sensor pattern:

```
   sys_enter_X  →  save args in HASH keyed by TID (pid_tgid)
   sys_exit_X   →  lookup by TID, combine with return value,
                   emit event, delete entry
```

Key by **TID**, not PID: two threads of one process can be inside the same
syscall simultaneously. (Day 6's `sigsnoop` is this pattern.)

---

## 8. Reading memory safely

Maps hold *your* data. But most interesting data — paths, command lines,
parent info — lives in kernel structs or user memory, which you must copy in
through helpers.

### The helpers

| Helper | Source | Notes |
|---|---|---|
| `bpf_probe_read_kernel(dst, size, src)` | kernel memory | Fixed size. |
| `bpf_probe_read_kernel_str(dst, size, src)` | kernel memory | Stops at NUL; returns length incl. NUL (or negative error). |
| `bpf_probe_read_user(dst, size, src)` | user memory | Can **fail** if page not resident (non-sleepable progs can't fault it in). |
| `bpf_probe_read_user_str(...)` | user memory | Same, string. |
| `bpf_copy_from_user(...)` | user memory | **Sleepable** programs only — can fault pages in, so it doesn't fail on swapped-out memory. |
| `bpf_probe_read(...)` | either (legacy) | Deprecated: ambiguous on architectures where user/kernel address spaces overlap. Use the explicit ones. |
| `BPF_CORE_READ(src, a, b, c)` | kernel | `src->a->b->c` with CO-RE relocation + safe reads at each hop. |
| `BPF_CORE_READ_STR_INTO(dst, src, a, b)` | kernel | String field. |
| direct `ptr->field` | kernel, typed BTF pointers only | Allowed in fentry/fexit/tp_btf/LSM/iter — the verifier knows the type and handles faults. |

### Which to use when

```
   pointer came from...                               use
   ──────────────────────────────────────────────    ──────────────────────────
   a syscall argument (path, buffer, argv)            bpf_probe_read_user(_str)
   a user-space function (uprobe arg/return)          bpf_probe_read_user(_str)
   kprobe arg / pt_regs / bpf_get_current_task()      BPF_CORE_READ
   fentry/fexit/LSM typed argument                    direct ->, or BPF_CORE_READ
```

### Strings and the stack limit

Paths can be 4096 bytes; the stack is 512. So:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[4096]);
} scratch SEC(".maps");

u32 zero = 0;
char *buf = bpf_map_lookup_elem(&scratch, &zero);
if (!buf) return 0;
bpf_probe_read_user_str(buf, 4096, path);
```

Or reserve the event directly in the ring buffer and read into it (file 07).

### Building a full path

A file's full path isn't stored anywhere as one string — the kernel has a
chain of `dentry` structs (one per path component) up to the mount root.
Sensors either:
- call `bpf_d_path()` (only allowed from certain hooks), or
- walk `dentry->d_parent` in a bounded loop, handling mount points.

This is one of the classic "hard parts" of a file-monitoring sensor.

### Reading argv

`execve`'s `argv` is an array of user pointers to strings. Sensors either loop
over `argv[i]` with `bpf_probe_read_user`, or read the contiguous region
`mm->arg_start..arg_end` in the new process's memory (from
`sched_process_exec`) in one go.

---

## 9. Getting process context

Typical "who did this" fields, and where they come from:

```c
u64 id    = bpf_get_current_pid_tgid();   // tgid = id >> 32, tid = (u32)id
u64 ug    = bpf_get_current_uid_gid();    // uid = (u32)ug, gid = ug >> 32
u64 cgid  = bpf_get_current_cgroup_id();  // container identity
u64 ts    = bpf_ktime_get_ns();
bpf_get_current_comm(&comm, sizeof(comm));

struct task_struct *t = (void *)bpf_get_current_task();
u32 ppid  = BPF_CORE_READ(t, real_parent, tgid);
u32 pidns = BPF_CORE_READ(t, nsproxy, pid_ns_for_children, ns.inum);   // namespace id
u64 start = BPF_CORE_READ(t, start_time);   // with tgid, a unique process key
```

**Unique process identity:** PID alone isn't unique over time (reuse). Sensors
use **(TGID, start_time)** as a stable process key.

---

## Check yourself

- Why does a sensor need maps at all?
- When would you choose `LRU_HASH` over `HASH`?
- How do you work with a 4 KiB path given a 512 B stack?
- Why is `*cnt += 1` on a shared map value a bug?
- What's wrong with keying a long-lived process cache by PID alone?
- Which read helper for: a syscall's path argument? `task->real_parent->tgid`
  in a kprobe? A typed argument in an LSM hook?
