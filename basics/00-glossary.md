# 00 — Glossary

Every abbreviation and short form you'll run into in eBPF code, docs, and
sensor source. Grouped by topic, roughly in the order you'll meet them. Keep
this open while reading the other files.

---

## Processes & the OS

| Term | Stands for | Plain meaning |
|------|-----------|---------------|
| **OS** | Operating System | The software that manages the hardware and runs every program (Linux, here). |
| **Kernel** | — | The core of the OS. Runs with full hardware privileges; everything else asks it for help. |
| **User space** | — | Where normal programs (bash, vim, your loader) run, with restricted privileges. |
| **Kernel space** | — | Where the kernel (and eBPF programs) run, with full privileges. |
| **Process** | — | A running program: code + its own memory + its own resources. |
| **Thread** | — | One independent line of execution *inside* a process. A process has ≥1 thread. |
| **PID** | Process ID | The number that identifies a process (what `ps` shows). |
| **TID** | Thread ID | The number that identifies one thread. The kernel internally calls every thread a "task" and gives each its own ID. |
| **TGID** | Thread Group ID | The kernel's name for what user space calls the PID: the ID shared by all threads in one process. For a single-threaded process, TGID == TID. |
| **PPID** | Parent Process ID | The PID of the process that created this one. |
| **TPID** | Target PID | *Not a kernel term* — just a variable name tutorials use for "the PID being acted on" (e.g. the receiver of a `kill()`). |
| **comm** | command (name) | The short name of a process's executable, max 16 bytes (`"bash"`, `"sshd"`). |
| **task / task_struct** | — | The kernel's internal record for one thread: its IDs, `comm`, parent, credentials, memory map, etc. |
| **UID / GID** | User ID / Group ID | Which user/group a process runs as. `0` = root. |
| **EUID** | Effective UID | The UID used for permission checks right now (can differ from UID, e.g. after `sudo`/setuid). |
| **syscall** | system call | The *only* doorway from user space into the kernel (`open`, `read`, `execve`, `kill`, ...). |
| **fd** | file descriptor | A small integer a process uses to refer to an open file/socket/pipe (0=stdin, 1=stdout, 2=stderr). |
| **signal** | — | An asynchronous notification sent to a process (`SIGKILL`, `SIGTERM`, `SIGINT`...). |
| **errno** | error number | The error code a failed syscall returns (`-2` = `ENOENT` "no such file", `-1` = `EPERM`, `-3` = `ESRCH` "no such process"). |
| **namespace** | — | Kernel feature that gives a process its own isolated view of something (PIDs, network, mounts). The basis of containers. |
| **cgroup** | control group | Kernel feature that groups processes to limit/account their resources. Also how containers are identified. |
| **container** | — | A process (tree) isolated with namespaces + cgroups. Not a VM — same kernel. |

---

## C & the toolchain

| Term | Stands for | Plain meaning |
|------|-----------|---------------|
| **C** | — | The language both the kernel and eBPF programs are written in. |
| **#define / macro** | — | Preprocessor text substitution, done before compilation. |
| **header (.h)** | — | A file of declarations (types, function signatures, macros) shared between source files. |
| **struct** | structure | A C type that groups several named fields together. |
| **pointer** | — | A variable holding a memory address. |
| **u8/u16/u32/u64** | unsigned N-bit int | Fixed-width integer types. `__u32` etc. are the user-space-visible variants. `s32`/`s64` are signed. |
| **clang** | — | The C compiler (part of LLVM) that can emit eBPF bytecode. |
| **LLVM** | (formerly) Low Level Virtual Machine | The compiler infrastructure clang is built on; contains the BPF backend. |
| **gcc** | GNU Compiler Collection | The other major C compiler; used for user-space loaders, newer versions can also target BPF. |
| **ELF** | Executable and Linkable Format | The standard Linux file format for compiled programs and object files (`.o`). BPF objects are ELF files too. |
| **section** | — | A named region inside an ELF file (`.text` = code, `.data`, `.rodata`, `.maps`, `license`...). |
| **.rodata** | read-only data | ELF section for constants. In eBPF, `const volatile` globals live here. |
| **.bss / .data** | — | ELF sections for zero-initialized / initialized writable globals. |
| **SEC()** | section | eBPF macro that places a function or variable into a named ELF section; the loader reads section names to decide how to attach. |
| **object file (.o)** | — | Compiled-but-not-linked output of a compiler. `hello.bpf.o` is one. |
| **symbol** | — | A named function or variable inside a binary (what a uprobe resolves `readline` against). |
| **Makefile / make** | — | Build automation: describes how to turn sources into outputs. |
| **CMake** | Cross-platform Make | A higher-level build system generator. |

---

## eBPF core

| Term | Stands for | Plain meaning |
|------|-----------|---------------|
| **BPF** | Berkeley Packet Filter | The original 1992 packet-filtering VM. Now usually used as shorthand for eBPF. |
| **eBPF** | extended BPF | The modern, general-purpose in-kernel VM this repo is about. |
| **cBPF** | classic BPF | The old original, still used by `tcpdump` filters and seccomp. |
| **bytecode** | — | The instruction format eBPF programs are compiled to (like Java bytecode, but for the kernel's BPF VM). |
| **verifier** | — | The kernel component that statically proves a BPF program is safe before allowing it to run. |
| **JIT** | Just-In-Time (compiler) | Turns verified BPF bytecode into native CPU instructions for speed. |
| **program type** | — | What *kind* of BPF program it is (kprobe, tracepoint, XDP, LSM...). Determines where it can attach, what context it gets, which helpers it may call. |
| **attach type** | — | Finer-grained "where exactly" within a program type. |
| **hook** | — | A point in the kernel (or a user program) where a BPF program can be attached. |
| **ctx** | context | The pointer argument every BPF program receives, describing the event that fired it. Its type depends on the program type. |
| **helper** | BPF helper function | A kernel function a BPF program is allowed to call (`bpf_printk`, `bpf_map_lookup_elem`, `bpf_get_current_pid_tgid`...). |
| **kfunc** | kernel function | Newer, more flexible alternative to helpers: kernel functions explicitly exported for BPF use. |
| **map** | — | A kernel-resident key/value data structure shared between BPF programs and user space. |
| **pin / bpffs** | BPF filesystem | `/sys/fs/bpf/` — a special filesystem where BPF programs/maps can be "pinned" so they outlive the process that loaded them. |
| **link** | BPF link | A kernel object representing "program X is attached to hook Y". Destroying the link detaches the program. |
| **tail call** | — | A BPF program jumping into another BPF program (no return). Used to chain logic beyond size limits. |
| **trace_pipe** | — | `/sys/kernel/debug/tracing/trace_pipe` — where `bpf_printk` output appears. Debug-only. |
| **GPL** | GNU General Public License | Many BPF helpers are GPL-only; your program must declare a GPL-compatible `LICENSE` to use them. |

---

## Portability

| Term | Stands for | Plain meaning |
|------|-----------|---------------|
| **BTF** | BPF Type Format | Compact metadata describing C types (struct layouts, field offsets). The kernel ships its own at `/sys/kernel/btf/vmlinux`. |
| **CO-RE** | Compile Once – Run Everywhere | Technique (built on BTF) that lets one compiled BPF program read kernel structs correctly on many kernel versions. |
| **vmlinux** | — | The uncompressed kernel image. |
| **vmlinux.h** | — | A giant header generated from the kernel's BTF containing *every* kernel type. Replaces including dozens of kernel headers. |
| **relocation** | — | A placeholder in the compiled object ("field X of struct Y") that the loader fixes up at load time for the actual running kernel. |
| **BPF_CORE_READ** | — | Macro that reads a (possibly nested) kernel struct field safely *and* emits a CO-RE relocation. |
| **libbpf** | — | The official C library for loading BPF objects, applying relocations, creating maps, attaching programs. |
| **skeleton (.skel.h)** | — | A header generated by `bpftool gen skeleton` giving a typed C API for one specific BPF object. |
| **bpftool** | — | The official CLI to inspect/load/attach BPF programs and maps, dump BTF, generate skeletons. |

---

## Hook types

| Term | Stands for | Plain meaning |
|------|-----------|---------------|
| **kprobe / kretprobe** | kernel probe / kernel return probe | Dynamic hook on entry / return of (almost) any kernel function. |
| **fentry / fexit** | function entry / exit | Faster, BTF-typed replacement for kprobe/kretprobe, via a BPF trampoline. |
| **tracepoint (tp)** | — | Static, stable hook deliberately placed by kernel developers. |
| **raw_tp** | raw tracepoint | Tracepoint without argument pre-processing: faster, lower-level. |
| **tp_btf** | BTF-enabled tracepoint | Raw tracepoint with typed arguments via BTF. |
| **uprobe / uretprobe** | user probe / user return probe | Hook on entry/return of a function inside a user-space binary. |
| **USDT** | User Statically-Defined Tracing | Stable tracepoints compiled into user-space programs (Python, Node, MySQL, ...). |
| **LSM** | Linux Security Module | Kernel security hook framework (SELinux, AppArmor). BPF-LSM lets BPF programs make allow/deny decisions. |
| **XDP** | eXpress Data Path | Hook at the network driver, before the kernel network stack — for very fast packet processing. |
| **TC** | Traffic Control | Hook in the kernel network stack (ingress/egress), after the packet becomes an `sk_buff`. |
| **skb / sk_buff** | socket buffer | The kernel's struct representing one network packet. |
| **sockops / sk_msg** | — | Socket-level hooks for TCP events and message redirection. |
| **perf_event** | performance event | Hook on hardware/software perf counters, e.g. CPU sampling for profilers. |
| **seccomp** | secure computing | Syscall filtering mechanism (uses cBPF). |

---

## Maps & data movement

| Term | Stands for | Plain meaning |
|------|-----------|---------------|
| **HASH** | hash map | Arbitrary key → value. |
| **ARRAY** | array map | Integer index 0..N-1 → value, all slots preallocated. |
| **PERCPU_*** | per-CPU | A variant with a separate copy of each value per CPU core — no locking, aggregate in user space. |
| **LRU** | Least Recently Used | Hash map that evicts the oldest entries when full instead of failing inserts. |
| **ringbuf** | ring buffer | Modern, shared, ordered queue for streaming events from kernel to user space. |
| **perf buffer** | perf event array | Older per-CPU event-streaming mechanism, superseded by ringbuf. |
| **PROG_ARRAY** | program array | Map holding other BPF programs — used for tail calls. |
| **map-of-maps** | — | A map whose values are other maps (`ARRAY_OF_MAPS`, `HASH_OF_MAPS`). |
| **BPF_ANY / BPF_NOEXIST / BPF_EXIST** | — | Flags for `bpf_map_update_elem`: upsert / insert-only / update-only. |
| **probe_read** | — | Family of helpers that safely copy memory into the BPF stack (`bpf_probe_read_kernel`, `bpf_probe_read_user`, `_str` variants). |

---

## Security & production

| Term | Stands for | Plain meaning |
|------|-----------|---------------|
| **CAP_BPF / CAP_PERFMON / CAP_SYS_ADMIN** | capabilities | Fine-grained root privileges needed to load BPF programs. |
| **EDR** | Endpoint Detection & Response | Category of security product that watches hosts for threats — what eBPF sensors often are. |
| **runtime security** | — | Detecting/blocking malicious behaviour *while* a workload runs (vs. scanning images beforehand). |
| **TOCTOU** | Time-Of-Check to Time-Of-Use | A race where data changes between when you inspect it and when it's used — a classic sensor blind spot. |
| **enrichment** | — | Adding context to a raw event in user space (container name, process tree, k8s pod). |
| **k8s** | Kubernetes | Container orchestrator; most cloud sensors run as a k8s DaemonSet (one per node). |
| **DaemonSet** | — | A k8s object that runs one copy of a pod on every node — the usual sensor deployment shape. |
