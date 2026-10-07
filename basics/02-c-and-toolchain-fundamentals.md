# 02 — C and Toolchain Fundamentals

Both the kernel and eBPF programs are written in C, and real sensors use C or
C++ for the user-space side too. This file covers the C you actually need, then
how source code becomes something the kernel can run.

---

## 1. Types and fixed-width integers

C's basic types (`int`, `long`) change size between platforms. Kernel and BPF
code avoids that ambiguity with **fixed-width types**:

```c
u8   / __u8    // unsigned 8-bit   (0..255)
u16  / __u16   // unsigned 16-bit
u32  / __u32   // unsigned 32-bit  — PIDs, TIDs, UIDs
u64  / __u64   // unsigned 64-bit  — timestamps, pid_tgid, cgroup IDs
s32  / __s32   // signed 32-bit    — return values, errno
s64  / __s64   // signed 64-bit
```

The `__u32` (double underscore) variants are the ones exposed in user-space
headers, so they're used in structs shared between kernel and user space.

Casting between them truncates or extends:

```c
u64 x = 0x0000_01F4_0000_01F5;   // (illustrative)
u32 lo = (u32)x;     // keeps lower 32 bits → 0x1F5
u32 hi = x >> 32;    // shift down upper 32 bits → 0x1F4
```

That's exactly the `pid_tgid` unpacking trick.

---

## 2. Pointers

A **pointer** is a variable holding a memory address.

```c
int  x  = 42;
int *p  = &x;     // & = "address of"   → p holds x's address
int  y  = *p;     // * = "dereference"  → read what's AT that address (42)
```

Pointers to structs use `->`:

```c
struct task { int pid; char comm[16]; };
struct task *t = ...;
t->pid;           // same as (*t).pid
```

Chained pointers are everywhere in the kernel:

```c
task->real_parent->tgid      // "my parent's PID"
task->mm->exe_file->f_path.dentry->d_name.name   // "my executable's name"
```

**Why this is the #1 eBPF pain point:** in normal C, `task->real_parent->tgid`
just works. In eBPF, every one of those `->` might point at memory that's
invalid, or whose layout differs on this kernel. So you can't freely
dereference — you go through `BPF_CORE_READ(task, real_parent, tgid)` (files 04
and 06).

Arrays decay to pointers:

```c
char buf[80];
buf        // pointer to buf[0], type char *
&buf       // pointer to the whole array, type char (*)[80] — same address
sizeof(buf)  // 80 — sizeof sees the real array, not a pointer
```

---

## 3. Structs

A **struct** groups named fields:

```c
struct event {
    u32  pid;
    u32  tpid;
    int  sig;
    int  ret;
    char comm[16];
};

struct event e = {};      // zero-initialize everything
e.pid = 123;
```

### Memory layout and padding

The compiler lays fields out in order, but adds **padding** so each field is
aligned (a `u64` must start at an address divisible by 8):

```c
struct bad  { u8 a; u64 b; u8 c; };   // 1 + 7 pad + 8 + 1 + 7 pad = 24 bytes
struct good { u64 b; u8 a; u8 c; };   // 8 + 1 + 1 + 6 pad          = 16 bytes
```

Why you care:

1. **Event structs are shared between kernel and user space.** Both sides
   must agree on layout byte-for-byte, so you define them in one shared
   header.
2. **Uninitialized padding bytes leak kernel stack memory** to user space, and
   the verifier may reject reading them. Always `= {}` or `__builtin_memset`.
3. **Kernel struct layouts change between versions** — `task_struct` field
   offsets differ between 5.15 and 6.6. That's the whole problem CO-RE solves
   (file 04).

---

## 4. The preprocessor: #include, #define, macros

Before compiling, the **preprocessor** runs: pure text manipulation.

```c
#include "vmlinux.h"           // paste that file's contents here
#include <bpf/bpf_helpers.h>   // <> = search system include paths

#define MAX_ENTRIES 10240      // replace every MAX_ENTRIES with 10240
#define TASK_COMM_LEN 16
```

Macros can take arguments, and eBPF headers use them *heavily*:

```c
#define SEC(name) __attribute__((section(name), used))
```

So `SEC("kprobe/do_unlinkat") int foo(...)` becomes "put function `foo` in an
ELF section named `kprobe/do_unlinkat`". `BPF_KPROBE`, `BPF_PROG`,
`BPF_CORE_READ`, `__uint`, `__type` are all macros too — they expand into
ordinary (if ugly) C. When an eBPF compile error is confusing, it's usually
inside a macro expansion.

```bash
clang -E file.bpf.c -I../common | less    # see the code AFTER preprocessing
```

Conditional compilation:

```c
#ifdef __TARGET_ARCH_x86
   ...x86-specific code...
#endif
```

That's what `-D__TARGET_ARCH_x86` on the clang command line is for: BPF macros
like `BPF_KPROBE` need to know which CPU's registers hold function arguments.

---

## 5. Functions, `static`, `inline`

```c
static int helper(int x) { return x * 2; }
```

- **`static`** on a function = visible only in this file. In BPF, non-`SEC()`
  helper functions are typically `static`.
- **`static __always_inline`** = force the compiler to paste the body into the
  caller. Older kernels didn't support real BPF-to-BPF function calls, so
  everything had to be inlined; you'll see `__always_inline` everywhere in
  older sensor code.

---

## 6. `const`, `volatile`, globals

- **`const`** — "this code won't modify it".
- **`volatile`** — "something outside this code may change it; don't optimize
  reads away".
- Global variables live in ELF sections: initialized → `.data`, zero → `.bss`,
  `const` → `.rodata`.

In eBPF, `const volatile int pid_target = 0;` is the standard way to have a
config value user space sets *before* load: `.rodata` becomes a read-only map
the loader writes, then freezes.

---

## 7. How source becomes a program: the compilation pipeline

```
   foo.c
     │  1. PREPROCESS   (#include, #define expanded)
     ▼
   foo.i
     │  2. COMPILE      (C → LLVM IR → target assembly)
     ▼
   foo.s
     │  3. ASSEMBLE     (assembly → machine code)
     ▼
   foo.o   ← object file (ELF): code + data + symbols, not yet runnable
     │  4. LINK         (combine .o files + libraries → executable)
     ▼
   foo     ← executable (ELF)
```

`clang -c` stops after step 3 and gives you a `.o`. **eBPF stops there too**:
there's no link step; the `.o` *is* what gets loaded. The "linking" happens in
the kernel/libbpf at load time.

### Compilers, targets, LLVM

**clang** is a C compiler front-end built on **LLVM**. LLVM can generate code
for many CPU architectures ("targets"): x86-64, ARM64, RISC-V… and **BPF**.

```bash
clang -target bpf ...        # "generate eBPF bytecode, not x86 code"
llc --version | grep bpf     # see the BPF backend listed
```

The flags this repo uses:

| Flag | Meaning |
|---|---|
| `-target bpf` | Emit eBPF bytecode instead of host machine code. |
| `-O2` | Optimize. **Required in practice** — unoptimized BPF code is often rejected by the verifier (too many stack spills, unbounded patterns). |
| `-g` | Include debug info — and, crucially for BPF, **emit BTF** describing your program's types. Needed for CO-RE and for map type info. |
| `-c` | Compile only, produce `.o`, don't link. |
| `-D__TARGET_ARCH_x86` | Define a macro telling `bpf_tracing.h` which architecture's register layout to use. |
| `-I../common` | Add an include path (where `vmlinux.h` lives). |

---

## 8. ELF: the file format of compiled objects

**ELF** (Executable and Linkable Format) is how Linux stores compiled code. An
ELF file is a header plus a list of named **sections**:

```
   hello.bpf.o
   ┌────────────────────────────┐
   │ ELF header                  │  "I'm an ELF for machine=BPF"
   ├────────────────────────────┤
   │ section "kprobe/__x64_..."  │  ← your program's bytecode
   │ section ".maps"             │  ← map definitions
   │ section ".rodata"           │  ← const globals, printk format strings
   │ section "license"           │  ← "GPL"
   │ section ".BTF"              │  ← type info for your program
   │ section ".BTF.ext"          │  ← line info + CO-RE relocations
   │ section ".symtab"           │  ← symbol names
   └────────────────────────────┘
```

**This is how `SEC()` works.** The loader (libbpf/bpftool) opens the `.o`, walks
the sections, and reads the *names*:

- `kprobe/do_unlinkat` → "this is a kprobe program, attach to `do_unlinkat`"
- `tracepoint/syscalls/sys_enter_openat` → "tracepoint program, attach there"
- `.maps` → "create these maps first"
- `license` → "pass this to the kernel as the program's license"

Inspect any object yourself:

```bash
llvm-readelf -S hello.bpf.o            # list sections
llvm-objdump -d hello.bpf.o            # disassemble the BPF bytecode
bpftool btf dump file hello.bpf.o      # dump its BTF types
```

Normal executables are ELF too — which is how uprobes find `readline` inside
`/bin/bash`: by reading bash's ELF symbol table.

```bash
readelf -s /bin/bash | grep readline
nm -D /bin/bash | grep readline
```

---

## 9. Static vs. dynamic linking and shared libraries

User-space programs usually **dynamically link** shared libraries
(`libc.so.6`, `libssl.so`). The library is a separate ELF file loaded into the
process's memory at startup.

```bash
ldd /bin/bash        # which shared libraries bash uses
```

Sensor relevance: to capture HTTPS plaintext, sensors put **uprobes on
`SSL_write`/`SSL_read` inside `libssl.so`** — the one place data exists
unencrypted. If an app statically links its own TLS (Go programs do), you
must probe the app binary itself instead.

---

## 10. Libraries you'll use

| Library / tool | Side | Purpose |
|---|---|---|
| `bpf_helpers.h` | kernel (BPF) | `SEC()`, helper function declarations, `__uint`/`__type` map macros. |
| `bpf_tracing.h` | kernel (BPF) | `BPF_KPROBE`, `BPF_KRETPROBE`, `BPF_PROG`, register-access macros. |
| `bpf_core_read.h` | kernel (BPF) | `BPF_CORE_READ` and friends. |
| `vmlinux.h` | kernel (BPF) | All kernel types. |
| **libbpf** | user space | Open/load/attach BPF objects, maps, ring buffers. |
| `bpftool` | CLI | Inspect, load, generate `vmlinux.h` and skeletons. |
| **libelf**, **zlib** | user space | Dependencies of libbpf. |

Build systems: **make** (Makefile) is standard for BPF projects; **CMake** for
larger C++ sensors.

---

## 11. Minimum C++ you'll want later

Production user-space sides are often C++ (or Go/Rust). Useful pieces:

- `std::unordered_map` — process tree / fd caches in user space
- RAII (`std::unique_ptr` with a custom deleter) — guarantee BPF objects are
  destroyed on exit
- `std::thread` / `std::atomic` — consumer threads, shutdown flags
- `extern "C"` — calling C APIs (libbpf) from C++

The BPF (kernel) side is always restricted C — no C++ there.

---

## Check yourself

- Why does `(u32)x` give you the lower 32 bits of a `u64`?
- What does `SEC("kprobe/foo")` literally do to the compiled output?
- Why does an eBPF build stop at the `.o` stage?
- What does `-g` give you for BPF beyond normal debug info?
- Why must an event struct shared with user space have no uninitialized padding?
- How does a uprobe find the address of `readline` inside bash?
