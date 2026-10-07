# 04 — BTF and CO-RE: Running One Binary on Many Kernels

The hardest practical problem for a real sensor isn't writing the BPF code —
it's making the same compiled code work on every customer's kernel. This file
explains the problem and the machinery (BTF, CO-RE, `vmlinux.h`) that solves it.

---

## 1. The problem: kernel structs are not stable

Kernel code reads structs like `task_struct`:

```c
struct task_struct {
    ...                    // ~700 fields, hundreds of bytes in
    pid_t pid;
    pid_t tgid;
    ...
    struct task_struct *real_parent;
    ...
    char comm[16];
    ...
};
```

When your BPF program reads `task->tgid`, the compiler turns that into "read 4
bytes at offset **N** from `task`". But:

- Field order changes between kernel versions.
- Fields are added/removed.
- Config options (`CONFIG_...`) change which fields exist at all.
- Distros patch kernels.

So the offset of `tgid` might be 2384 on Ubuntu 5.15 and 2416 on RHEL 6.6.
Compile against one, run on the other → **you silently read garbage**.

Unlike syscalls (a stable ABI) and tracepoints (semi-stable), **internal kernel
structs carry zero stability promise.**

---

## 2. The old solution: BCC (compile on the target)

**BCC** (BPF Compiler Collection) solved this by shipping clang/LLVM *with the
tool* and compiling the BPF program **on every target machine, at startup**,
against that machine's kernel headers.

Downsides:
- Needs ~100+ MB of LLVM on every host.
- Needs kernel headers installed (often missing in prod).
- Compilation at startup is slow and CPU-heavy.
- Compile errors appear on customer machines.

You'll still see BCC in older tools and tutorials (Python front-ends,
`BPF(text=...)`).

---

## 3. BTF — BPF Type Format

**BTF** is compact metadata describing C types: every struct, its fields,
their types, their offsets. Think of it as "debug info, but small and
purpose-built".

There are two BTFs in play:

1. **Kernel BTF** — modern kernels (built with `CONFIG_DEBUG_INFO_BTF=y`, the
   default on most distros since ~2020) ship their own types at:
   ```bash
   ls -la /sys/kernel/btf/vmlinux
   bpftool btf dump file /sys/kernel/btf/vmlinux | grep -A5 "STRUCT 'task_struct'"
   ```
   This describes the exact layout of *this* running kernel.

2. **Program BTF** — `clang -g` emits a `.BTF` section in your `.o`
   describing *your* program's types (your event struct, your maps).

BTF powers many features beyond CO-RE: typed fentry/LSM arguments, map
key/value pretty-printing in `bpftool map dump`, and verifier type checking.

---

## 4. `vmlinux.h` — all kernel types in one header

Generate it from kernel BTF:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

It's a single huge header (often 100k+ lines) containing **every** kernel type.
Benefits:
- No need for kernel headers.
- No `#include <linux/sched.h>` dependency soup.

Caveat: it doesn't contain `#define` constants (macros don't exist in BTF), so
you sometimes redefine things like `TASK_COMM_LEN` or flag values yourself.

**Important:** the layouts in `vmlinux.h` are those of the kernel you generated
it from. Alone, that would just bake in *one* kernel's offsets. CO-RE is what
makes it portable.

---

## 5. CO-RE — Compile Once, Run Everywhere

The core idea: **don't hardcode the offset; record what you meant, and fix it
at load time.**

```
   COMPILE TIME (your machine)                    LOAD TIME (customer machine)
   ───────────────────────────                    ────────────────────────────
   BPF_CORE_READ(task, tgid)                       libbpf reads relocation:
     → emits instruction "read at offset 2384"       "task_struct.tgid"
     → AND a relocation record:                    libbpf looks up task_struct.tgid
       "this 2384 means task_struct.tgid"            in /sys/kernel/btf/vmlinux
                                                    → actual offset here is 2416
                                                    → PATCHES the instruction to 2416
                                                    → loads the fixed program
```

Three pieces cooperate:

1. **clang** — with `__attribute__((preserve_access_index))` (which `vmlinux.h`
   applies to all its structs) records relocations in `.BTF.ext` instead of
   treating offsets as final.
2. **Kernel BTF** — tells libbpf the real layout at runtime.
3. **libbpf** — matches relocations against kernel BTF and rewrites
   instructions before handing the program to the kernel.

Result: one `.o`, built once, loads correctly on 5.4, 5.15, 6.6, RHEL, Ubuntu,
Amazon Linux…

### The read macros

```c
#include <bpf/bpf_core_read.h>

// single field
pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);
//           = task->real_parent->tgid, each hop a safe CO-RE read

// into an existing variable
BPF_CORE_READ_INTO(&ppid, task, real_parent, tgid);

// strings
BPF_CORE_READ_STR_INTO(&buf, task, comm);

// user-space struct (CO-RE-relocated, but reading user memory)
BPF_CORE_READ_USER(...);
```

---

## 6. Handling fields that differ or don't exist

CO-RE also lets you **ask questions about the running kernel**:

```c
if (bpf_core_field_exists(task->some_new_field)) {
    // only executed (and only relocated) on kernels that have it
}

size_t sz = bpf_core_field_size(struct foo, bar);
bool has_type = bpf_core_type_exists(struct some_struct);
int val = bpf_core_enum_value(enum some_enum, SOME_VALUE);
```

When a field was **renamed** between versions, define "flavors": a struct named
`task_struct___old` with the old field name. libbpf ignores the `___suffix`
when matching, so you can probe both:

```c
struct task_struct___old { long state; } __attribute__((preserve_access_index));

if (bpf_core_field_exists(((struct task_struct___old *)t)->state))
    state = BPF_CORE_READ((struct task_struct___old *)t, state);
else
    state = BPF_CORE_READ(t, __state);   // renamed in 5.14
```

This is exactly the pattern real sensors are full of.

Kconfig values too:

```c
extern int LINUX_KERNEL_VERSION __kconfig;
extern bool CONFIG_SOMETHING __kconfig __weak;
```

---

## 7. What if the kernel has no BTF?

Older kernels (or custom builds without `CONFIG_DEBUG_INFO_BTF`) don't have
`/sys/kernel/btf/vmlinux`. Options:

- **BTFHub** — a community archive of pre-generated BTF files for thousands of
  distro kernels. Sensors ship (or download) the matching file and point libbpf
  at it (`btf_custom_path`).
- **`bpftool gen min_core_btf`** — shrinks a full BTF down to only the types
  your program uses, so you can embed BTF for hundreds of kernels in your
  binary cheaply.
- Fall back to BCC-style compilation (legacy).

Falco, Tracee, and Tetragon all handle this; it's a big part of "production
grade".

---

## 8. What CO-RE does *not* solve

- **Function names** — kprobing `do_unlinkat` breaks if the function is renamed
  or inlined. (Prefer tracepoints/LSM, or attach to several candidates.)
- **Semantics** — a field can keep its name but change meaning.
- **Missing features** — no CO-RE can make a 4.14 kernel support ring buffers.
  You detect support and fall back (e.g., perf buffer).
- **Helper availability** — probe at startup (`libbpf_probe_bpf_helper`).

---

## 9. Mental model

```
                         ┌───────────────────────┐
   your .bpf.c ──clang──►│ .o: bytecode           │
   + vmlinux.h            │     + .BTF (your types)│
                         │     + .BTF.ext (relocs)│
                         └──────────┬────────────┘
                                    │  ship this ONE file
                                    ▼
         ┌──────────────── customer machine ─────────────────┐
         │ libbpf: read relocs ◄──► /sys/kernel/btf/vmlinux    │
         │         patch offsets, drop unsupported branches    │
         │         → bpf(BPF_PROG_LOAD) → verifier → JIT       │
         └─────────────────────────────────────────────────────┘
```

---

## Check yourself

- Why can't you safely hardcode `task_struct` field offsets?
- How did BCC solve portability, and what did it cost?
- What are the two different BTFs involved in a CO-RE load?
- What exactly does libbpf change in your program at load time?
- How would you read a field that was renamed in kernel 5.14?
- Name one thing CO-RE cannot fix.
