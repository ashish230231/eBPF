# 03 — The eBPF Execution Model

Now that you know what the kernel is (file 01) and how C becomes an ELF object
(file 02), this file explains what eBPF actually *is*: a small, safe virtual
machine living inside the kernel.

---

## 1. The problem eBPF solves

You want to run your own code inside the kernel — to see every `execve`, every
network packet, every file open — because that's where the truth is.

Historically you had three options, all bad:

| Option | Problem |
|---|---|
| Change the kernel source and rebuild | Takes years to get upstream; can't ship to customers. |
| Write a **kernel module** | Full kernel privileges, zero safety. One bug = kernel panic on a customer's production server. Must be rebuilt for every kernel version. |
| Watch from user space (`/proc` polling, `ptrace`, audit logs) | Slow, lossy, racy, easy for attackers to evade. |

eBPF's idea: **let users load small programs into the kernel, but prove them
safe before running them.** You get kernel-level visibility with user-space-level
risk.

```
   kernel module:   your code ─────────────────────────► kernel (trusted blindly)
   eBPF:            your code ─► VERIFIER (prove safe) ─► kernel (sandboxed)
```

---

## 2. eBPF is a virtual machine

eBPF defines its own tiny instruction set — a **virtual CPU**:

- **11 registers**, 64-bit: `r0`–`r10`
  - `r0` — return value (from helpers, and your program's own return)
  - `r1`–`r5` — function arguments (`r1` holds `ctx` on entry)
  - `r6`–`r9` — callee-saved, survive helper calls
  - `r10` — read-only frame pointer (stack base)
- **512-byte stack** per program. That's it. (Big buffers go in maps.)
- ~100 instructions: arithmetic, load/store, jumps, `call` (helpers), `exit`.

```bash
llvm-objdump -d hello.bpf.o
#   0: r1 = 0x0 ll
#   2: r2 = 0xe
#   3: call 0x6        ← call helper #6 = bpf_trace_printk
#   4: r0 = 0x0
#   5: exit
```

Why a VM rather than native code? Because a small, simple, well-defined
instruction set is something the kernel can **analyze completely** before
running it. You can't prove arbitrary x86 safe; you can prove this.

---

## 3. The lifecycle of every eBPF program

```
   1. WRITE      restricted C (.bpf.c)
   2. COMPILE    clang -target bpf → ELF .o with bytecode
   3. LOAD       bpf(BPF_PROG_LOAD) syscall — user space hands bytecode to kernel
   4. VERIFY     kernel's verifier proves it safe — or rejects it with a log
   5. JIT        kernel translates bytecode → native machine code
   6. ATTACH     connect the program to a hook (kprobe, tracepoint, ...)
   7. RUN        every time the hook fires, the program runs, in kernel context
   8. COMMUNICATE  via maps / ring buffers ↔ user space
   9. DETACH     close the link/fd (or unpin) → program unloaded when no refs remain
```

Steps 3, 6, 9 are all done through **one syscall: `bpf()`**, with different
commands (`BPF_PROG_LOAD`, `BPF_MAP_CREATE`, `BPF_LINK_CREATE`, ...). libbpf and
bpftool are just convenient wrappers around it.

**Lifetime rule:** a BPF program or map stays alive as long as *something*
references it — an open fd in some process, a link, or a pin in `/sys/fs/bpf`.
That's why `bpftool prog load ... /sys/fs/bpf/x` keeps the program alive after
bpftool exits, and `rm /sys/fs/bpf/x` unloads it.

---

## 4. The verifier — the heart of eBPF safety

Before a single instruction runs, the verifier **simulates every possible path**
through your program and checks:

### 4.1 It must terminate
- The control-flow graph must not have unbounded loops.
- Before kernel 5.3: **no loops at all** (you'd `#pragma unroll`).
- 5.3+: **bounded loops** allowed if the verifier can prove a bound.
- 5.17+: `bpf_loop()` helper for larger iteration counts.
- Hard cap on total instructions *verified* (1 million on modern kernels).

### 4.2 Every memory access must be provably safe
The verifier tracks the **type** of every register at every instruction:

```
   PTR_TO_CTX          the ctx argument
   PTR_TO_STACK        your 512-byte stack
   PTR_TO_MAP_VALUE    a value returned from bpf_map_lookup_elem
   PTR_TO_MAP_VALUE_OR_NULL   ← same, but MUST be null-checked first!
   SCALAR_VALUE        a plain number (with tracked min/max range)
   PTR_TO_BTF_ID       typed kernel pointer (fentry/tp_btf/LSM)
   ...
```

This is why:

```c
struct event *e = bpf_map_lookup_elem(&m, &key);
e->ret = 0;              // ✗ REJECTED: "R0 invalid mem access 'map_value_or_null'"

if (!e) return 0;
e->ret = 0;              // ✓ after the check, type becomes PTR_TO_MAP_VALUE
```

And why array indexing needs bounds checks:

```c
buf[i] = 0;              // ✗ if verifier can't prove 0 <= i < sizeof(buf)
if (i >= sizeof(buf)) return 0;
buf[i] = 0;              // ✓ range now proven
```

### 4.3 No reading uninitialized memory
Stack bytes must be written before read — another reason for `= {}`.

### 4.4 Only allowed helpers
Each program type has a whitelist of helpers it may call. A tracing program
can't call networking helpers and vice versa. GPL-only helpers require a
GPL-compatible license string.

### 4.5 No arbitrary kernel pointer dereference
You can't just `*ptr` a kernel address (except typed `PTR_TO_BTF_ID` pointers in
fentry/LSM programs). You must use `bpf_probe_read_kernel()` or
`BPF_CORE_READ()`, which handle faults safely.

### Reading verifier errors
When rejected, the kernel returns a **verifier log** — the simulated
instruction trace with register states. It's verbose, but the last few lines
tell you exactly which instruction failed and why.

```bash
sudo bpftool prog load foo.bpf.o /sys/fs/bpf/foo -d    # -d = show debug/verifier log
```

Common messages:

| Message | Usual cause |
|---|---|
| `invalid mem access 'map_value_or_null'` | Forgot to null-check a map lookup. |
| `invalid access to map value, value_size=X off=Y size=Z` | Index/offset not bounds-checked. |
| `R1 type=scalar expected=fp` | Passed a number where a pointer was required. |
| `back-edge from insn X to Y` | Loop the verifier can't bound. |
| `cannot call GPL-restricted function` | Missing/non-GPL license. |
| `invalid read from stack off -X+0 size Y` | Reading uninitialized stack memory. |
| `BPF program is too large` / `processed 1000001 insns` | Too many paths/instructions — simplify or split with tail calls. |
| `unknown func bpf_xxx#N` | Helper not allowed for this program type or kernel too old. |

Learning to read these is half of eBPF development.

---

## 5. The JIT compiler

After verification, the kernel's **JIT** translates BPF bytecode into native
instructions (x86-64, ARM64...). BPF registers map 1:1 onto real CPU registers,
so the result runs at essentially native speed.

```bash
cat /proc/sys/net/core/bpf_jit_enable           # 1 = JIT on
sudo bpftool prog dump jited id <ID>            # see the generated x86
sudo bpftool prog dump xlated id <ID>           # see the verified bytecode
```

The JIT is why eBPF is suitable for hot paths like every packet or every
syscall.

---

## 6. Program types

A BPF program's **type** decides:
- where it can attach
- what `ctx` it receives
- which helpers it may call
- what its return value means

| Program type | Attaches to | ctx | Return value means |
|---|---|---|---|
| `KPROBE` | kprobes, uprobes | `struct pt_regs *` (CPU registers) | ignored |
| `TRACEPOINT` | static tracepoints | tracepoint-specific struct | ignored |
| `RAW_TRACEPOINT` | tracepoints, raw | raw args array | ignored |
| `TRACING` | fentry/fexit/fmod_ret, tp_btf, iter | typed function args (BTF) | ignored (fmod_ret: override) |
| `LSM` | LSM security hooks | typed hook args | **0 = allow, -EPERM = deny** |
| `XDP` | network driver RX | `struct xdp_md *` | `XDP_PASS / DROP / TX / REDIRECT` |
| `SCHED_CLS` (TC) | traffic control ingress/egress | `struct __sk_buff *` | `TC_ACT_OK / SHOT / ...` |
| `CGROUP_SKB`, `CGROUP_SOCK_ADDR`, ... | cgroup-scoped network events | various | allow / deny |
| `SOCKET_FILTER` | a socket | `__sk_buff` | how many bytes to keep |
| `PERF_EVENT` | perf counters / sampling | `bpf_perf_event_data` | ignored |

Note the split: **observability types** (kprobe, tracepoint, tracing) can only
*watch*; their return value is ignored. **Enforcement types** (LSM, XDP, TC,
cgroup) can *change what happens* — block a syscall, drop a packet. Security
sensors that only detect use the former; ones that also **prevent** need the
latter (Tetragon's enforcement uses LSM/`bpf_send_signal`/fmod_ret).

---

## 7. Helper functions — the only way out of the sandbox

A BPF program can't call arbitrary kernel functions. It can only call
**helpers** — a fixed, numbered list of kernel functions explicitly exposed for
BPF. ~200 exist. The ones every sensor uses:

| Helper | What it does |
|---|---|
| `bpf_get_current_pid_tgid()` | TGID<<32 \| TID of the current task |
| `bpf_get_current_uid_gid()` | GID<<32 \| UID |
| `bpf_get_current_comm(buf, size)` | Copy current task's `comm` |
| `bpf_get_current_task()` / `_btf()` | Pointer to current `task_struct` |
| `bpf_get_current_cgroup_id()` | Current cgroup ID → which container |
| `bpf_ktime_get_ns()` | Monotonic timestamp in ns |
| `bpf_ktime_get_boot_ns()` | Timestamp including suspend |
| `bpf_probe_read_kernel(_str)` | Safely copy kernel memory |
| `bpf_probe_read_user(_str)` | Safely copy user memory |
| `bpf_map_lookup_elem / update_elem / delete_elem` | Map access |
| `bpf_ringbuf_reserve / submit / discard / output` | Ring buffer events |
| `bpf_perf_event_output` | Perf buffer events |
| `bpf_printk` (`bpf_trace_printk`) | Debug print to trace_pipe |
| `bpf_send_signal(sig)` | Send a signal to the current task (e.g. kill a malicious process) |
| `bpf_override_return` | Force a kprobed function's return value (if allowed) |
| `bpf_tail_call` | Jump into another BPF program |
| `bpf_get_stackid` / `bpf_get_stack` | Capture stack traces |
| `bpf_d_path` | Resolve a `struct path` into a full path string (restricted) |

```bash
man 7 bpf-helpers
sudo bpftool feature probe | grep helper    # which helpers your kernel supports
```

**kfuncs** (kernel 5.13+) are a newer, more flexible mechanism: kernel functions
annotated as callable from BPF. Increasingly, new functionality ships as kfuncs
rather than numbered helpers.

---

## 8. Execution context: what you can and can't do

When your program runs, it runs **in the context of the event**:

- On a syscall tracepoint, it runs on the CPU and in the task that made the
  syscall. That's why `bpf_get_current_pid_tgid()` "knows" who you are.
- On XDP, it runs in a network interrupt context — there may be no meaningful
  "current task".

Constraints:

- **No sleeping** (in most program types) — you can't wait for I/O, take
  blocking locks, or fault in user pages. That's why `bpf_probe_read_user` can
  *fail* if the page isn't resident. ("Sleepable" BPF programs — `fentry.s`,
  `lsm.s`, `uprobe.s` — can, and get `bpf_copy_from_user`.)
- **No unbounded work.** It runs synchronously inside the hook; the
  triggering task is blocked until you return. Slow BPF = slow system.
- **Preemption/migration is disabled** while running, so per-CPU data is
  consistent.
- **Concurrency is real.** The same program runs simultaneously on all CPUs.
  Shared map values need atomics (`__sync_fetch_and_add`) or spin locks
  (`bpf_spin_lock`), or use per-CPU maps.

---

## 9. Memory model summary

```
   ┌─────────────── your BPF program ──────────────────┐
   │  stack: 512 bytes   (locals, small buffers)          │
   │  ctx:   read-only view of the event                  │
   │  maps:  the ONLY persistent state, and the ONLY      │
   │         shared state (between invocations, between   │
   │         programs, and with user space)               │
   │  globals: actually backed by maps (.data/.bss/.rodata)│
   └─────────────────────────────────────────────────────┘
          │  helpers: probe_read_kernel / probe_read_user
          ▼
   arbitrary kernel or user memory — read-only, via checked copies
```

No `malloc`. No heap. If you need a 4 KiB buffer, you use a per-CPU array map
with one entry as scratch space.

---

## 10. Kernel version matters

eBPF has grown fast. Features you can count on by kernel version (roughly):

| Kernel | Key features |
|---|---|
| 4.1–4.9 | kprobes, tracepoints, perf buffer, basic maps |
| 4.18 | BTF introduced |
| 5.2 | Larger programs (1M insns), global variables |
| 5.3 | Bounded loops |
| 5.5 | fentry/fexit, BTF-enabled tracepoints |
| 5.7 | BPF LSM |
| 5.8 | Ring buffer, `CAP_BPF` |
| 5.10 | Sleepable programs (LTS — common in prod) |
| 5.15 | LTS — common baseline for modern sensors |
| 6.x | kfuncs everywhere, BPF arena, more flexible verifier |

Production sensors must support a *range* (often 4.14 → latest, with feature
fallbacks). That's a big source of complexity — file 08.

```bash
uname -r
sudo bpftool feature probe       # exactly what your kernel supports
```

---

## Check yourself

- Why is eBPF a VM rather than letting you load native machine code?
- Name four things the verifier checks.
- Why must you null-check the result of `bpf_map_lookup_elem`?
- What's the difference between an observability program type and an
  enforcement program type?
- Why can't most BPF programs sleep, and what does that imply for reading
  user memory?
- Why is the same BPF program's map value potentially racy?
