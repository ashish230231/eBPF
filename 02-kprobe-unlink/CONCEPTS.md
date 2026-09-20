# eBPF Day 2 — kprobe + kretprobe: Watching Files Get Deleted

Read this top to bottom. It builds directly on Day 1. By the end, every word in
`kprobe-unlink.bpf.c` should mean something to you — including *why you can't
just write `name->name`*, which is the real lesson of the day.

Day 1 taught the pipeline: compile → verify → attach → observe, with a single
blind hook that printed "hello" on every `execve`. Day 2 adds two genuinely new
powers:

1. **kprobe / kretprobe** — hook both the *entry* and the *return* of a kernel
   function, so you can read its **arguments** on the way in and its **return
   value** on the way out.
2. **Reading kernel memory safely** — pull real data (a filename) out of a
   kernel struct with `BPF_CORE_READ`.

The concrete goal: monitor every file deletion on the system. When someone runs
`rm test.txt`, you'll see *which* file and *whether* the delete succeeded.

---

## 1. What is a kprobe?

A **kprobe** (kernel probe) is a dynamic probe you can plant on almost *any*
function inside the running kernel — without recompiling or rebooting.

Think of it as a breakpoint that doesn't pause. When the kernel's execution
reaches the probed instruction, it detours into your callback, runs it, then
returns to the normal flow and carries on. Minimal disruption, easy to attach
and detach at runtime.

Under the hood this leans on CPU features: an exception/trap is used to divert
execution into your handler, and single-step debugging is used to still execute
the original probed instruction. Because of that hardware dependency, kprobes
are architecture-specific (x86-64, arm64, etc. — yours is x86-64).

**The kprobes family has three members:**

- **kprobe** — the fundamental one. Can be placed almost anywhere, even *inside*
  a function. It's the base the other two are built on.
- **kretprobe** — a specialization that fires on function **return**, giving you
  the return value.
- **jprobe** — an older method for grabbing arguments; largely obsolete now that
  `BPF_KPROBE` unpacks args for us. You won't use it.

For Day 2 you use **kprobe** (entry) + **kretprobe** (return) together.

---

## 2. kprobe vs kretprobe — entry vs exit

The same kernel function, hooked at two different moments:

```
        do_unlinkat(dfd, name)  is called
                │
    ┌───────────▼─────────────┐   <-- kprobe fires HERE (ENTRY)
    │  arguments are available │       you can read dfd + name (WHICH file)
    │  ... function body ...   │
    │  ... does the delete ... │
    └───────────┬─────────────┘   <-- kretprobe fires HERE (RETURN)
                │                     the return value is available
                ▼                     (WHETHER it succeeded: 0 or -errno)
          returns to caller
```

- **kprobe → the "what."** On entry the function's arguments are still sitting in
  registers, so you can see what it was asked to do.
- **kretprobe → the "result."** On return the answer is in the return-value
  register: `0` means success, a negative number is an errno-style failure
  (e.g. `-2` = `ENOENT`, "no such file").

Attach both and you get the full story of each deletion.

---

## 3. Why hook `do_unlinkat` (and not `unlink`)?

When a program deletes a file it calls the `unlink` (or `unlinkat`) **syscall**.
That syscall is a thin entry point; the actual work funnels into an internal
kernel worker function:

```c
int do_unlinkat(int dfd, struct filename *name);
```

- `dfd` — a directory file descriptor, the "at" part used for relative paths.
- `name` — a pointer to a kernel `struct filename` holding the path to delete.

We hook `do_unlinkat` because that's where the meaningful arguments live in a
clean, stable form. (You can confirm the symbol exists on your kernel with
`sudo grep ' do_unlinkat' /proc/kallsyms` — if it's there, it's a valid target.)

This is also a lesson in *choosing an attach point*: syscall entry stubs have
messy, arch-specific signatures, while the internal `do_*` worker often has the
tidy arguments you actually want.

---

## 4. The star of the show: why you CAN'T write `name->name`

This is the most important new idea in Day 2.

Your eBPF program runs in a **sandbox**. The verifier will **reject** any attempt
to directly dereference a raw kernel pointer, because a bad or stale pointer
could crash the entire kernel. So this, which looks perfectly normal in C:

```c
filename = name->name;   // ❌ verifier rejects this
```

...is not allowed. `name` points into kernel memory, and you must read across
that boundary through a **safe helper**, never by direct dereference.

On your kernel, `struct filename` looks like this (straight from `vmlinux.h`):

```c
struct filename {
    const char *name;    // <-- the path string we want
    const char *uptr;
    atomic_t    refcnt;
    struct audit_names *aname;
    const char  iname[0];
};
```

To reach `name->name` safely you use:

```c
filename = BPF_CORE_READ(name, name);   // ✅ safe + portable
```

---

## 5. What `BPF_CORE_READ` actually does

`BPF_CORE_READ(name, name)` does **two** jobs at once:

1. **Safe read.** It expands to a `bpf_probe_read_kernel()` call — the sanctioned
   way to copy bytes out of kernel memory into your program. If the pointer is
   bad, the helper fails gracefully instead of crashing the kernel.

2. **CO-RE relocation.** (Compile Once, Run Everywhere — the Day-1 concept.)
   Instead of baking in a hard-coded byte offset for the `name` field, it records
   a *relocation*: "find field `name` in `struct filename` at load time." When
   libbpf/bpftool loads your program on some machine, it patches in that kernel's
   real offset using its BTF. One compiled object, many kernel versions.

It also chains cleanly for nested reads, e.g. `BPF_CORE_READ(a, b, c)` reads
`a->b->c` with all the safety and relocation handled — you'll use that later.

The takeaway: **any time you follow a kernel pointer from eBPF, it goes through a
read helper.** Direct dereferences are for user-space C, not for the sandbox.

---

## 6. The `BPF_KPROBE` / `BPF_KRETPROBE` macros

A raw kprobe handler receives a single `struct pt_regs *ctx` — a snapshot of all
CPU registers at the probe point. Digging arguments out of registers by hand is
tedious and arch-specific. Two macros from `<bpf/bpf_tracing.h>` do it for you:

- **`BPF_KPROBE(name, arg1, arg2, ...)`** — declares an entry handler and unpacks
  the probed function's arguments into normal, correctly-typed parameters. So you
  write them exactly like the real kernel signature:

  ```c
  SEC("kprobe/do_unlinkat")
  int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name) { ... }
  ```

- **`BPF_KRETPROBE(name, ret)`** — declares a return handler and hands you the
  return value as a normal parameter:

  ```c
  SEC("kretprobe/do_unlinkat")
  int BPF_KRETPROBE(do_unlinkat_exit, long ret) { ... }
  ```

Note the two handlers have **different function names** (`do_unlinkat` vs
`do_unlinkat_exit`) even though they probe the same kernel function — they're two
separate eBPF programs in two separate ELF sections.

---

## 7. Getting the PID: `bpf_get_current_pid_tgid()`

Inside a probe you often want "who triggered this?" The helper
`bpf_get_current_pid_tgid()` returns a 64-bit value packing two IDs:

```
 63 ............................. 32 31 ............................. 0
 │        TGID (the "PID")          │        PID (the thread ID)       │
```

- **Top 32 bits** = the thread-group ID — what users normally call the **PID**.
- **Bottom 32 bits** = the individual kernel thread ID.

So the idiom you'll see everywhere is:

```c
pid_t pid = bpf_get_current_pid_tgid() >> 32;   // grab the top half = the PID
```

---

## 8. `SEC()` for kprobes — a quick recap from Day 1

`SEC()` places your function into a named ELF section so the loader knows where
to attach it. Day 1 you used `SEC("kprobe/__x64_sys_execve")`. Day 2 uses:

- `SEC("kprobe/do_unlinkat")`    → attach on **entry** of `do_unlinkat`.
- `SEC("kretprobe/do_unlinkat")` → attach on **return** of `do_unlinkat`.

Same mechanism as Day 1, now pointing at an internal kernel worker function and
adding the `kretprobe/` variant.

---

## 9. `bpf_printk` and `trace_pipe` — same as Day 1

Nothing new here, just reused. `bpf_printk()` writes to the shared kernel trace
buffer, which you read at:

```
/sys/kernel/debug/tracing/trace_pipe
```

Remember the limits: at most **3 arguments**, one global buffer shared by all BPF
programs, and it's slow for high-frequency events. Perfect for learning; later
lessons replace it with maps and ring buffers. On Day 2 each deletion produces
two lines — one from the kprobe (ENTRY) and one from the kretprobe (EXIT).

---

## 10. Why the GPL license line (again)

Still mandatory, same reason as Day 1: helpers like `bpf_printk` and the probe-read
helpers are **GPL-only**. Leave this out and the verifier refuses to let you call
them, and loading fails:

```c
char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

---

## 11. A few kprobe caveats worth knowing

You don't need these to make Day 2 work, but they explain the "gotchas" pros run
into and why kprobes are considered *less stable* than tracepoints:

- **Some functions can't be probed** — e.g. the kprobes implementation itself,
  and a handful like `do_page_fault`. Probing them would recurse or break the
  probe machinery.
- **Inlined functions may not be hookable** — if the compiler inlined a function,
  there's no single address to plant a probe on, so the hook may silently miss.
- **No recursion into probes** — if your callback calls a function that is itself
  probed, the second probe won't fire again; the kernel just bumps a "missed"
  counter. This prevents infinite loops.
- **Don't sleep in a callback** — preemption (and sometimes interrupts) are
  disabled while your probe runs, so never call anything that could give up the
  CPU (mutexes, semaphores, blocking allocs).
- **Function names aren't a stable API** — `do_unlinkat` is an internal name that
  *could* change between kernel versions. That's precisely the fragility that
  tracepoints (Week 5) and fentry are designed to reduce.

---

## The whole Day 2 pipeline in one line

```
kprobe-unlink.bpf.c --clang--> .bpf.o --verifier--> (JIT) --attach-->
  kprobe(do_unlinkat entry)  reads name via BPF_CORE_READ  --bpf_printk--> trace_pipe
  kretprobe(do_unlinkat ret) reads ret value               --bpf_printk--> trace_pipe
```

Once these terms feel comfortable, the code is short — and every line has a
reason to exist.
