# eBPF Hello World — Concepts You Need First

Read this top to bottom. Each term builds on the one before it. The goal is that
by the end, every word in `hello.bpf.c` means something to you.

---

## 1. What is eBPF?

**eBPF = extended Berkeley Packet Filter.**

Forget the name — it's historical baggage. Today eBPF has almost nothing to do
with packet filtering. Here's the real idea:

> eBPF lets you run small programs *inside the Linux kernel*, safely, without
> writing a kernel module or rebooting.

Why is that a big deal? The kernel is the core of the OS — it sees every process
that starts, every file opened, every network connection. Normally your code
runs in **user space** and can't peek into any of that directly. eBPF lets you
attach your own tiny program to a kernel event ("every time a process runs
`execve`, run my code") and observe or react to it.

**The catch:** kernel code that crashes takes the whole machine down. So eBPF
programs aren't allowed to run freely — they must first pass **the verifier**
(see below). That's the trade: you get kernel-level power, but only if you play
by strict safety rules.

**Where it's used:** observability (bpftrace), networking (Cilium), and security
sensors (Falco, Tetragon — and the one at your company). That's your endgame.

---

## 2. Kernel space vs. user space

Two worlds on every Linux machine:

- **User space** — where normal programs run (your shell, browser, the loader
  program you'll write later). Restricted. If it crashes, only that program dies.
- **Kernel space** — the privileged core. Manages memory, processes, hardware,
  syscalls. If it crashes, the *whole system* crashes.

An eBPF program has **two halves**:

- The **kernel-side** part (`hello.bpf.c` → compiled to BPF bytecode) — runs
  *in* the kernel, attached to an event.
- The **user-side** part (a "loader") — an ordinary program that loads the
  kernel-side part into the kernel and reads results back.

For our very first Hello World we skip the loader and use `bpftool` (a
command-line tool) to do the loading for us.

---

## 3. What is a syscall? (why we hook `execve`)

A **system call (syscall)** is how a user-space program asks the kernel to do
something privileged: open a file (`openat`), start a program (`execve`), send
data over the network (`write`), etc. It's the doorway between the two worlds.

Syscalls are great hook points because *everything* interesting goes through
them. Our Hello World hooks `execve` — the syscall that runs a new program — so
our code fires every time anything on the system launches.

---

## 4. What is clang / LLVM?

**clang** is a C compiler. **LLVM** is the larger toolkit clang is built on.

Normally clang compiles C into machine code for *your CPU* (x86-64, ARM, etc.).
But eBPF programs don't run on your CPU directly — they run on a **virtual
machine inside the kernel**. So we tell clang to compile our C into a special
target called **BPF bytecode** instead of x86 machine code.

    hello.bpf.c  --clang (target=bpf)-->  hello.bpf.o   (an ELF object file of BPF bytecode)

So clang's job here: turn your C into the instruction set the kernel's BPF VM
understands. That's why the plan installs clang/LLVM — gcc traditionally
couldn't target BPF as well.

---

## 5. What is BPF bytecode & the BPF virtual machine?

The kernel contains a small **virtual machine** that executes BPF instructions
(a simple RISC-like instruction set: ~10 registers, its own opcodes). Your
compiled `.o` file is a bundle of these instructions.

When loaded, the kernel can **JIT-compile** (Just-In-Time) that bytecode into
native machine code so it runs fast — but only *after* it has been verified safe.

---

## 6. What is the verifier?

Before the kernel runs any BPF bytecode, the **verifier** analyzes it and proves
it's safe. It checks things like:

- The program **always terminates** (no infinite loops; loops must be bounded).
- No reading/writing of **out-of-bounds or arbitrary memory**.
- All memory accesses are **within known limits**.
- The program stays within size/complexity budgets.

If any check fails, loading is **rejected** with a (verbose) error, and your
program never runs. Fighting the verifier *is* learning eBPF — expect it, read
its full log, it's precise even when it's annoying.

---

## 7. What is BTF and what is vmlinux.h?

To read kernel data structures (like `task_struct`), your program needs to know
their exact layout — field names, offsets, sizes. But that layout differs
between kernel versions.

- **BTF (BPF Type Format)** = structured type information about the kernel's data
  structures. Modern kernels expose their own BTF at `/sys/kernel/btf/vmlinux`.
- **vmlinux** = the name of the compiled Linux kernel image. (The `.h` isn't the
  kernel itself — just its *types*.)
- **vmlinux.h** = a giant C header we *generate* from that BTF. It contains every
  kernel struct/enum/type definition, so your program can `#include` it instead
  of dragging in hundreds of real kernel headers.

We generate it once with:

    bpftool btf dump file /sys/kernel/btf/vmlinux format c > common/vmlinux.h

---

## 8. What is CO-RE? (Compile Once, Run Everywhere)

The problem: a struct field might sit at a different offset on kernel 5.15 vs
6.6. If you hard-coded offsets, your program would break across machines.

**CO-RE** solves this. You compile *once* (against your `vmlinux.h`), and libbpf
records "relocations" — notes like "find field `X` in struct `Y` at load time."
When the program is loaded on some other kernel, libbpf patches the real offsets
using *that* kernel's BTF. One binary, many kernels. This is how production
sensors ship a single build that runs everywhere.

---

## 9. What is bpftool?

A Swiss-army command-line tool for BPF. We use it to:

- **Generate `vmlinux.h`** (dump the kernel's BTF as C).
- **Load & attach** our compiled program (so we don't need a C loader yet).
- **Inspect** what's loaded: `bpftool prog list`, `bpftool map dump`.

Note (your setup): plain `/usr/sbin/bpftool` is just a wrapper. On this WSL box
you need a real binary — install with `sudo apt install -y bpftool`.

---

## 10. What is bpf_printk & trace_pipe?

`bpf_printk()` is eBPF's `printf` for debugging. But its output does **not** go to
your terminal — it goes to a kernel trace buffer you read at:

    /sys/kernel/debug/tracing/trace_pipe

Limitations to remember: max 3 arguments, it's a single global buffer shared by
all BPF programs, and it's slow for high-frequency events. Great for learning,
not for production (later you'll use ring buffers instead).

---

## 11. What is SEC("...")?

`SEC()` is a macro that places your function into a named **ELF section** in the
compiled object. libbpf/bpftool read that section name to decide **where to
attach** your program. Examples:

- `SEC("kprobe/__x64_sys_execve")` — attach at the entry of the `execve` syscall
  via a **kprobe** (a dynamic kernel probe).
- `SEC("tp/syscalls/sys_enter_write")` — attach to the `sys_enter_write`
  **tracepoint** (a stable, kernel-defined hook point).
- `SEC("license")` — special: marks the variable holding the license string.

**kprobe vs tracepoint** (you'll go deep later): a *kprobe* can hook almost any
kernel function but is less stable across versions; a *tracepoint* is a
purpose-built, stable hook the kernel maintainers promise not to break.

---

## 12. Why the GPL license line?

Many BPF helper functions (including `bpf_printk`) are marked **GPL-only** in the
kernel. If your program doesn't declare a GPL-compatible license, the verifier
refuses to let you call those helpers. So every real program carries:

    char LICENSE[] SEC("license") = "Dual BSD/GPL";

It's not decoration — leave it out and loading fails.

---

## The whole pipeline in one line

    hello.bpf.c  --clang-->  hello.bpf.o  --verifier-->  (JIT)  --attach-->  runs on each execve  --bpf_printk-->  trace_pipe

Once these 12 terms feel comfortable, the actual code is short and every line
will have a reason to exist.
