# eBPF Day 4 — Tracepoints + Global Variables: Snoop `openat`, Filter by PID

Read this top to bottom. It builds on Days 1–3. By the end, every word in
`opensnoop.bpf.c` should mean something — especially the two headline ideas of
the day: **why we hook a tracepoint instead of a kprobe/fentry**, and **how a
single `const volatile` global variable lets user space filter events inside the
kernel before they're ever emitted**.

Days 2 and 3 both hooked an *internal* kernel function, `do_unlinkat` — first
with a kprobe (Day 2), then with fentry (Day 3). Both taught you the same warning:
that function name is an internal implementation detail and can change between
kernel versions. Day 4 finally uses the tool that removes that fragility: a
**tracepoint**, a stable hook the kernel developers promise not to break.

The concrete goal: watch every process that opens a file (the `openat` syscall),
print its PID — and be able to say "only show me PID 618" *without* the kernel
wasting any effort emitting the events you don't want.

---

## 1. What is a tracepoint?

A **tracepoint** is a *static*, pre-defined hook that kernel developers have
deliberately placed at meaningful spots in the code — syscall entry/exit,
scheduler events, and so on. Unlike a kprobe (which you dynamically plant on an
arbitrary instruction), a tracepoint is baked into the kernel at compile time and
comes with a **documented, stable interface**.

That stability is the whole point:

```
   kprobe / fentry  (Days 2–3)          tracepoint  (Day 4)
   ───────────────────────────          ───────────────────────────
   hook ANY function, dynamically       hook only pre-defined spots
   target = internal name (do_unlinkat) target = stable API name
   can break on a kernel upgrade        kernel devs promise not to break it
   raw pt_regs / typed args             a fixed, documented argument struct
```

You can list every tracepoint your kernel exposes:

```bash
sudo cat /sys/kernel/debug/tracing/available_events | grep openat
# syscalls:sys_enter_openat
# syscalls:sys_exit_openat
```

If it's in that list, it's a supported hook. That's the guarantee Days 2–3 didn't
have.

---

## 2. Why `sys_enter_openat` specifically

When a process opens a file, it issues the `openat` **system call** — the
interface between user space and the kernel. The kernel handles the request and
hands back a *file descriptor*, the number every later read/write refers to.

The kernel publishes a tracepoint at the **entry** of that syscall:

```
   syscalls:sys_enter_openat   ← fires the instant openat() is entered
```

We hook the *enter* side because that's where the interesting "a process is
about to open a file" signal lives, and where the calling PID is trivially
available. (There's a matching `sys_exit_openat` if you later want the returned
fd or error, exactly like fexit gave you the return value on Day 3.)

> Note on `open` vs `openat`: modern glibc routes almost everything through
> `openat` (the "at" variant that takes a directory fd for relative paths). So
> hooking `sys_enter_openat` alone catches the overwhelming majority of file
> opens. Some tutorials attach a second program to `sys_enter_open` for
> completeness; on a current system you'll see nearly everything from `openat`.

---

## 3. The SEC() for a tracepoint

Same `SEC()` mechanism as always, a new prefix that tells the loader "attach me
to a tracepoint, and here's which one":

```c
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{ ... }
```

Compare the whole progression — the target keeps getting more stable:

```
 Day 1:  SEC("kprobe/__x64_sys_execve")           dynamic, internal
 Day 2:  SEC("kprobe/do_unlinkat")  + kretprobe    dynamic, internal
 Day 3:  SEC("fentry/do_unlinkat")  + fexit        dynamic, internal (faster)
 Day 4:  SEC("tracepoint/syscalls/sys_enter_openat") STATIC, stable API
```

The context argument is a **`struct trace_event_raw_sys_enter *`** — a fixed,
BTF-described struct (it lives in your `vmlinux.h`) that carries the syscall's
arguments in a documented layout. That's the tracepoint's stable "argument
struct" from the table in section 1. For today we only need the PID, so we won't
dig fields out of `ctx` — but that's where the file path would come from if you
extended this.

---

## 4. Getting the PID — the same idiom as Days 2–3

Nothing new here, and that's deliberate — reuse cements it:

```c
u64 id  = bpf_get_current_pid_tgid();
u32 pid = id >> 32;
```

`bpf_get_current_pid_tgid()` returns a 64-bit value with **two things packed in**:

```
  ┌─────────────── 64 bits ───────────────┐
  │   TGID (upper 32)  │   PID/TID (lower 32)  │
  └────────────────────┴───────────────────────┘
         >> 32 keeps this half
```

In kernel terms the upper 32 bits are the **TGID**, which is what user space
calls the "process ID" (the number you see in `ps`). Shifting right by 32 keeps
that half. The lower 32 bits are the individual thread's id. We want the process,
so we shift. Same move you made on Days 2 and 3.

---

## 5. The star of the day: the `const volatile` global variable

This is the genuinely new concept. One line:

```c
/// @description "Process ID to trace"
const volatile int pid_target = 0;
```

Two qualifiers, two different audiences — this is the part worth slowing down on:

- **`const`** — *from the eBPF program's / kernel's point of view, this is
  read-only.* The BPF code may only read `pid_target`, never write it. This is
  what lets the **verifier** treat its value as a fixed constant it can reason
  about (and even optimize around), which keeps the program provably safe.

- **`volatile`** — *tells the compiler "someone outside may change this, don't
  optimize it away."* Without `volatile`, the compiler sees a `const` initialized
  to `0` that's never written and would happily fold it into a literal `0`,
  deleting the variable entirely. `volatile` forces it to keep a real storage
  slot — the slot user space will poke a new value into before the program runs.

Put together, `const volatile` means: **"a constant the kernel can't change, but
user space can configure once, before load."** It's the standard eBPF pattern for
passing runtime configuration into an otherwise-fixed kernel program.

### Where does the value actually live?

In the **`.rodata` (read-only data) section** of the compiled `.bpf.o`. That
section becomes a special, read-only BPF map when the object is loaded. The
sequence is:

```
  1. compile   → pid_target sits in .rodata with its initial value (0)
  2. user space (loader) → OPENS that .rodata map and writes your chosen PID
  3. load      → the kernel freezes .rodata read-only; the program starts
  4. run       → the BPF code reads pid_target, now holding your value
```

The critical timing detail: user space writes the value **between compile and the
program starting to run**. Once it's loaded and frozen, the kernel side only ever
reads it. That's why `const` (kernel: read-only) and `volatile` (user space:
writable before freeze) aren't a contradiction — they describe two different
moments in the lifecycle.

---

## 6. Filtering *in the kernel* — and why that matters

Here's the payoff, the filter itself:

```c
if (pid_target && pid_target != pid)
    return 0;                       // not our target → drop it, emit nothing

bpf_printk("Process ID: %d enter sys openat\n", pid);
```

Read the condition carefully:

- If `pid_target` is **0** (the default), `pid_target && ...` is false, the `if`
  never triggers, and **every** process's opens are printed. Zero acts as
  "trace everyone."
- If `pid_target` is set (say `618`), then for any process whose `pid` isn't
  `618`, the condition is true and we `return` early — **no `bpf_printk`, no
  event, nothing**.

Why this is the important idea, not just a convenience: the check runs **inside
the kernel, at the hook, before any data is produced**. The alternative —
printing everything and filtering in user space — means the kernel does the work
of formatting and shipping millions of events you'll immediately throw away.
`openat` fires constantly on a busy system, so kernel-side filtering is the
difference between a usable tool and a firehose. **Filter as early as possible,
where the event is born.**

(The original tutorial writes `return false;` in the drop branch. `false` is just
`0` here, so it behaves identically to the `return 0;` used elsewhere — a
tracepoint handler returning 0 simply means "handled, carry on.")

---

## 7. The `/// @description` annotation — a eunomia thing, not a C thing

The comment above the variable:

```c
/// @description "Process ID to trace"
const volatile int pid_target = 0;
```

is **not** normal C and the compiler ignores it. It's a marker read by the
**eunomia-bpf** toolchain (`ecc`/`ecli`). eunomia scans these annotations and
**auto-generates a command-line flag** — so `ecli` can offer `--pid_target` with
that description in its `-h` help, and you set the PID like:

```bash
sudo ecli run package.json --pid_target 618
```

That's a nice convenience *if you use eunomia*. See the next section for how this
maps onto **our** repo, which does not.

---

## 8. eunomia vs this repo's routine (important — read this)

The Day 4 tutorial text is written for **eunomia-bpf**: `ecc opensnoop.bpf.c` to
compile, `ecli run package.json` to run, `--pid_target` auto-generated from the
annotation. eunomia is a higher-level framework that wraps all the loading and
config-plumbing for you.

**Days 1–3 of this repo don't use eunomia.** We use the raw toolchain:

```
   eunomia (the tutorial)              this repo (Days 1–3, and here)
   ──────────────────────              ──────────────────────────────
   ecc opensnoop.bpf.c                 clang -target bpf ... -c ...
   ecli run package.json               sudo bpftool prog load ...
   --pid_target 618 (auto CLI)         no auto CLI; set .rodata via a loader
   /// @description drives help text    annotation is inert (bpftool ignores it)
   read output from trace_pipe          read output from trace_pipe (same!)
```

To stay consistent with the rest of the repo, treat Day 4 as a **tracepoint +
global-variable** lesson compiled and loaded the same way as Days 1–3:

```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../common \
      -c opensnoop.bpf.c -o opensnoop.bpf.o
sudo bpftool prog load opensnoop.bpf.o /sys/fs/bpf/opensnoop autoattach
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

The honest caveat about `pid_target` under bpftool: `bpftool prog load` gives you
no `--pid_target` flag (that flag only exists because eunomia generated it). With
the default `pid_target = 0`, the program traces **all** processes' opens, which
is exactly what you want to *see it work*. Actually **setting** the filter to a
specific PID requires writing into the `.rodata` map before the program is
frozen — which the convenient `bpftool prog load` path doesn't expose. That "set
a config value from user space before load" step is precisely the job of a real
libbpf **skeleton loader**, which is Week 2 of the plan. So:

> **Day 4 takeaway for this repo:** understand *why* `const volatile pid_target`
> exists and *how* kernel-side filtering works, and prove the tracepoint fires by
> running with the default (trace-all). The mechanics of actually injecting a
> chosen PID from user space land properly on Day-something soon, once we have a
> C loader instead of `bpftool prog load`.

---

## 9. Reused from earlier days (nothing new)

- **`bpf_get_current_pid_tgid() >> 32`** — identical PID idiom to Days 2–3.
- **`bpf_printk`** — same shared kernel trace buffer, still max 3 args, still read
  at `/sys/kernel/debug/tracing/trace_pipe`.
- **The GPL license line** — still mandatory, because `bpf_printk` is GPL-only:
  ```c
  char LICENSE[] SEC("license") = "GPL";
  ```
- **`vmlinux.h`** — still where `struct trace_event_raw_sys_enter` and friends
  come from; still generated once from your kernel's BTF.

---

## 10. Requirements & troubleshooting

Tracepoints are broadly available and less fussy than fentry, but:

1. **The tracepoint exists.** Confirm before you attach:
   `sudo cat /sys/kernel/debug/tracing/available_events | grep sys_enter_openat`.
2. **No output?** First rule out filtering: with `pid_target = 0` you should see
   a flood (almost everything opens files). If you compiled with a hard-coded
   `pid_target`, remember the drop branch silences non-matching PIDs.
3. **`trace_pipe` looks empty but the program is loaded.** Trigger some opens in
   another shell — e.g. `cat /etc/hostname`, or just `ls` — each one calls
   `openat`.
4. **Verify it attached:** `sudo bpftool prog show | grep -i openat`.

---

## 11. Tracepoint vs kprobe vs fentry — the one-table summary

```
                       kprobe (Day 2)     fentry (Day 3)      tracepoint (Day 4)
 ────────────────────  ────────────────   ────────────────   ──────────────────
 nature                dynamic probe      dynamic (trampoline) STATIC, built-in
 target                any function       any function        pre-defined spots
 target stability      internal → fragile internal → fragile  stable kernel API
 argument access       raw pt_regs        typed args          fixed ctx struct
 SEC() prefix          kprobe/            fentry/ , fexit/    tracepoint/...
 needs BTF             no                 yes                 no (uses vmlinux.h)
 today's new idea      —                  —                   stable hook +
                                                              global-var filter
```

The through-line of Days 2→3→4 is the *target* getting more trustworthy: from an
internal name you hope doesn't change, to a hook the kernel developers promise to
keep. That's why real production sensors lean heavily on tracepoints.

---

## The whole Day 4 pipeline in one line

```
opensnoop.bpf.c --clang--> .bpf.o (pid_target in .rodata)
  --verifier--> (JIT) --attach--> tracepoint syscalls:sys_enter_openat
  every openat: read PID  →  if pid_target set and != PID, DROP (kernel-side)
                          →  else bpf_printk("Process ID: N enter sys openat")
  --> /sys/kernel/debug/tracing/trace_pipe
```

Same compile→verify→attach→observe shape as every day so far. What's new is a
*stable* hook and a *configurable, kernel-side* filter — the two habits every
serious eBPF tool is built on.
