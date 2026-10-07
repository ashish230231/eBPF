# 01 — OS Fundamentals

An eBPF sensor is a program that watches *what the operating system is doing*.
You can't understand what it watches until you understand the OS itself. This
file starts from zero.

---

## 1. What an operating system is for

A computer has hardware: CPU cores, RAM, disks, network cards. Hundreds of
programs want to use that hardware at the same time. If each program talked to
the hardware directly, they'd overwrite each other's memory, corrupt each
other's files, and one buggy program could crash the whole machine.

The **operating system** sits between programs and hardware and acts as a
referee:

```
   ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
   │ bash │  │ vim  │  │ sshd │  │chrome│      programs
   └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘
      └─────────┴────┬────┴─────────┘
                     ▼
   ┌─────────────────────────────────────┐
   │          OPERATING SYSTEM            │      the referee
   │   (Linux kernel)                     │
   └─────────────────┬───────────────────┘
                     ▼
   ┌─────────────────────────────────────┐
   │   CPU   RAM   disk   network card    │      hardware
   └─────────────────────────────────────┘
```

The core of the OS is the **kernel**. "Linux" strictly means the Linux kernel;
Ubuntu is a distribution = kernel + a pile of user programs on top.

---

## 2. Kernel space vs. user space

The CPU itself enforces two privilege levels (x86 calls them "rings"):

```
   ┌──────────────────────────────────────────────┐
   │ USER SPACE  (ring 3, unprivileged)            │
   │   every normal program: bash, python, sshd    │
   │   - can only touch its OWN memory              │
   │   - cannot talk to hardware                    │
   │   - cannot see other processes' memory         │
   ├──────────────── the boundary ─────────────────┤
   │ KERNEL SPACE  (ring 0, privileged)             │
   │   the kernel, drivers, eBPF programs           │
   │   - can touch ALL memory                        │
   │   - can talk to hardware                        │
   │   - a bug here crashes the WHOLE machine        │
   └──────────────────────────────────────────────┘
```

This split is the single most important idea for eBPF:

- A **user-space** bug crashes one program. The kernel cleans up after it.
- A **kernel-space** bug crashes everything ("kernel panic").

Traditionally, the only way to add code to the kernel was a **kernel module** —
powerful, but a single mistake panics the machine. eBPF exists to let you run
code in kernel space *safely*. File 03 explains how.

---

## 3. Programs vs. processes

A **program** is a file on disk: `/usr/bin/bash` is just bytes.

A **process** is a program *while it's running*. Run bash in three terminals
and you have one program but three processes. Each process gets:

- its own **memory** (it believes it owns the whole address space — see §5)
- its own **PID** (Process ID), a number unique while it's alive
- its own **open files** (file descriptors, §7)
- its own **credentials** (which user it runs as — UID/GID)
- a **parent** (the process that started it — PPID)

```bash
ps -ef            # list all processes: UID, PID, PPID, command
echo $$           # PID of your current shell
cat /proc/$$/status   # everything the kernel knows about it
```

### How processes are born: fork + exec

Linux creates processes in two steps:

```
   bash (PID 100)
     │  fork()     → duplicates itself: now there are two bashes
     ├────────────► bash (PID 101, child, PPID 100)
     │                   │  execve("/usr/bin/ls")
     │                   ▼  → replaces its own code with ls's code
     │               ls (PID 101 — same PID, new program)
     │                   │  exit()
     ▼  wait()           ▼
   bash gets the prompt back
```

- **fork / clone** — create a copy of the current process.
- **execve** — throw away the current program, load a new one into this process.
- **exit** — terminate.
- **wait** — parent collects the child's exit status.

This matters enormously for sensors: "a new program ran" == "an `execve`
happened". Process-execution monitoring (the #1 thing security sensors do) is
mostly hooking `execve`. Day 1's `hello.bpf.c` hooked exactly that.

Every process forms a **tree** via parents. PID 1 (`systemd` or `init`) is the
root. Sensors reconstruct this tree to answer "what launched this?" (e.g.
"why did `nginx` spawn `bash` that spawned `curl`?" — classic attack chain).

```bash
pstree -p        # see the tree
```

---

## 4. Threads, and the PID / TID / TGID confusion

A process can do several things at once by having multiple **threads** — e.g.
a web server handling many requests. Threads in the same process share memory
and open files, but each has its own stack and CPU registers, and each can be
running on a different CPU core simultaneously.

Here's where the naming gets confusing. Inside the kernel, **every thread is a
"task"** with its own `struct task_struct` and its own ID. The kernel calls:

- each thread's own ID → **PID** (kernel term) — what user space calls **TID**
- the ID of the thread group (the process) → **TGID** — what user space calls **PID**

```
   Process "nginx" (what `ps` shows as PID 500)
   ┌─────────────────────────────────────────────┐
   │  thread 1: TID 500  ← main thread, TID == TGID│   TGID = 500 for all three
   │  thread 2: TID 501                             │
   │  thread 3: TID 502                             │
   └─────────────────────────────────────────────┘
```

That's why eBPF's `bpf_get_current_pid_tgid()` returns both packed into 64
bits, and why you `>> 32` to get the "PID as user space means it":

```
   bpf_get_current_pid_tgid()
   ┌──────── upper 32 bits ────────┬──────── lower 32 bits ────────┐
   │ TGID  (user-space "PID")       │ kernel "pid" (user-space "TID") │
   └────────────────────────────────┴─────────────────────────────────┘
      >> 32  → process ID            (u32) cast → thread ID
```

**Rule of thumb:** key per-process data by TGID; key per-syscall in-flight data
by TID (two threads of one process can be inside syscalls at the same moment).

---

## 5. Memory: virtual addresses

Every process sees its own private **virtual address space** — addresses
`0x0000...` to `0x7fff...` that look like its own whole machine. The CPU's
**MMU** (Memory Management Unit) translates each virtual address into a real
physical RAM address using **page tables** the kernel maintains per process.

```
   process A: virtual 0x400000 ──┐
                                  ├── MMU + page tables ──► physical RAM
   process B: virtual 0x400000 ──┘   (different physical pages!)
```

Consequences you'll hit in eBPF:

1. **The same address means different things in different processes.** A
   `char *` from bash's memory is meaningless outside bash.
2. **User memory might not be there.** Memory is managed in 4 KiB **pages**;
   a page can be swapped out or not yet loaded (a **page fault** brings it in).
   Kernel code — and eBPF — must never blindly dereference a user pointer.
   That's why eBPF has `bpf_probe_read_user()` (file 06).
3. **Kernel memory is mapped into every process's address space** (upper half)
   but only accessible in kernel mode.

A process's memory layout, roughly:

```
   high addresses
   ┌────────────────────┐
   │ kernel (hidden)     │
   ├────────────────────┤
   │ stack  ↓            │  local variables, function call frames
   │                     │
   │ shared libraries    │  libc.so, libreadline.so ...
   │                     │
   │ heap   ↑            │  malloc()'d memory
   ├────────────────────┤
   │ data / bss          │  global variables
   │ text                │  the program's machine code
   └────────────────────┘
   low addresses
```

---

## 6. System calls — the only door into the kernel

User-space programs can't touch hardware or other processes directly. When
they need something — open a file, send a packet, start a program — they ask
the kernel via a **system call (syscall)**.

```
   your program calls fopen("x.txt")     (C library function, user space)
        │
        ▼
   libc calls openat(...)                 (syscall wrapper)
        │  special CPU instruction: `syscall` (x86-64)
        │  → CPU switches to ring 0, jumps into the kernel
        ▼
   kernel: sys_openat → do_sys_open → ... (kernel functions)
        │  checks permissions, finds the file, allocates an fd
        ▼
   returns fd (e.g. 3) or a negative error (e.g. -2 ENOENT)
        │  CPU switches back to ring 3
        ▼
   your program continues
```

There are ~350 syscalls on x86-64. The ones security sensors care most about:

| Category | Syscalls |
|---|---|
| Process lifecycle | `execve`, `execveat`, `clone`, `fork`, `exit`, `exit_group` |
| Files | `openat`, `read`, `write`, `unlinkat`, `renameat`, `chmod`, `chown` |
| Network | `socket`, `connect`, `bind`, `listen`, `accept`, `sendto` |
| Privilege | `setuid`, `setgid`, `capset`, `ptrace` |
| Signals | `kill`, `tgkill` |
| Kernel extension | `init_module`, `finit_module`, `bpf` |
| Memory | `mmap`, `mprotect` (e.g. making memory executable) |

**Why this matters:** because syscalls are the *only* door, hooking the right
syscalls lets you see essentially everything a program does to the outside
world. That's the founding insight behind every eBPF security sensor.

```bash
strace ls          # watch every syscall `ls` makes
man 2 openat       # section 2 of the manual = syscalls
```

Each syscall has a number, and its arguments arrive in CPU registers (on
x86-64: `rdi, rsi, rdx, r10, r8, r9`). A syscall's return value is ≥0 on
success, or a **negative errno** on failure.

---

## 7. File descriptors — "everything is a file"

When a process opens something, the kernel returns a small integer: a **file
descriptor (fd)**. The process uses it for all later operations.

```
   fd 0 → stdin   (keyboard/terminal)
   fd 1 → stdout  (terminal)
   fd 2 → stderr  (terminal)
   fd 3 → /etc/passwd   (after openat)
   fd 4 → TCP socket to 1.2.3.4:443   (after socket + connect)
```

Linux treats almost everything as a file: regular files, directories, pipes,
sockets, terminals, devices (`/dev/sda`), even eBPF maps and programs (the
`bpf()` syscall hands back fds).

```bash
ls -l /proc/$$/fd      # your shell's open fds
```

Sensor relevance: a `write(fd=4, ...)` event is useless unless you know what fd
4 *is*. Sensors track fd → file/socket mappings, or read it from the kernel's
`struct file`.

---

## 8. Signals

A **signal** is an asynchronous poke sent to a process: "stop", "you crashed",
"user pressed Ctrl-C".

| Signal | # | Meaning |
|---|---|---|
| `SIGINT` | 2 | Ctrl-C — interrupt |
| `SIGKILL` | 9 | Kill immediately, can't be caught |
| `SIGSEGV` | 11 | Invalid memory access (segfault) |
| `SIGTERM` | 15 | Polite "please terminate" |
| `SIGSTOP` | 19 | Pause, can't be caught |
| `0` | 0 | Not a real signal — "does this PID exist and may I signal it?" |

Signals are sent via the `kill()` syscall (the name is historical — it sends
*any* signal). Sensor relevance: malware often kills security tools or other
processes; a sudden `SIGKILL` to your sensor is itself an alert.

---

## 9. Users, permissions, capabilities

Every process runs as a **UID** (user) and **GID** (group). UID 0 is **root**,
historically all-powerful.

Modern Linux splits root's power into ~40 **capabilities**, so a program can
have just the slice it needs:

- `CAP_NET_ADMIN` — configure networking
- `CAP_SYS_ADMIN` — the catch-all "almost root"
- `CAP_BPF` — load BPF programs (kernel 5.8+)
- `CAP_PERFMON` — tracing / perf events

Loading most tracing eBPF programs needs `CAP_BPF` + `CAP_PERFMON` (or just
root). That's why every command in this repo starts with `sudo`.

Sensor relevance: **privilege escalation** (a process going from UID 1000 to
UID 0 without a legitimate path like `sudo`) is one of the most important
things a security sensor detects.

---

## 10. Containers: namespaces + cgroups

A container is *not* a virtual machine. It's a normal process the kernel lies
to, using two features:

- **Namespaces** — give a process its own isolated view of a resource:
  - PID namespace → inside the container, it thinks it's PID 1
  - mount namespace → its own filesystem tree
  - network namespace → its own network interfaces
  - user, UTS (hostname), IPC, cgroup namespaces
- **cgroups** (control groups) — group processes to limit CPU/memory/IO, and
  label them. Every container has a cgroup; its **cgroup ID** is how sensors
  figure out "which container did this event come from?"

```
   host kernel (ONE kernel for everything)
   ├── process sshd            (host)
   ├── container A ─ nginx     (PID 1 inside, PID 4821 on host)
   └── container B ─ postgres  (PID 1 inside, PID 5102 on host)
```

Because there's only one kernel, **an eBPF program on the host sees every
container's activity**. That's exactly why eBPF is the dominant technology for
cloud/Kubernetes runtime security: one sensor per node watches every container
on it.

Watch out: PIDs differ between host and container namespaces. Kernel helpers
return host-namespace values.

---

## 11. Where the kernel exposes itself: /proc and /sys

The kernel publishes live state as fake files:

```bash
cat /proc/cpuinfo                 # CPU info
cat /proc/<pid>/cmdline           # a process's full command line
ls -l /proc/<pid>/exe             # its executable
cat /proc/kallsyms | head         # kernel symbol table (function addresses)
ls /sys/kernel/btf/vmlinux        # kernel type info (file 04)
ls /sys/kernel/debug/tracing      # ftrace / tracepoints / trace_pipe
ls /sys/fs/bpf                    # pinned BPF objects
```

Sensors read `/proc` at startup to learn about processes that were already
running before the sensor was loaded (eBPF only sees events from attach-time
onward).

---

## 12. The kernel is just C functions calling each other

Last foundational idea, and the one that makes kprobes make sense. Inside, the
kernel is millions of lines of C. A syscall enters at an entry function and
calls down through layers:

```
   openat syscall
     └─ __x64_sys_openat
          └─ do_sys_openat2
               └─ do_filp_open
                    └─ path_openat
                         └─ security_file_open   ← LSM hook (file 05)
                         └─ vfs_open ...
```

Every one of those is a real function with an address in `/proc/kallsyms`, and
(almost) any of them can be hooked by eBPF. Choosing *which layer* to hook is
one of the core design decisions of a sensor:

- **High up (syscall entry)** — sees the raw request, including paths the
  process supplied, but before the kernel resolves symlinks or checks
  permissions. Vulnerable to TOCTOU tricks.
- **Deep down (LSM hook, VFS)** — sees the kernel's resolved, final view of
  what's actually happening. More trustworthy, but function names are internal
  and can change between kernels.

File 05 is about exactly this trade-off.

---

## Check yourself

- What's the difference between a program and a process?
- Why can a user-space bug not crash the machine, but a kernel bug can?
- What does `execve` do, and why do sensors care?
- In the kernel, what's the difference between `pid` and `tgid`?
- Why can't kernel code just dereference a pointer that came from user space?
- Why does one eBPF program on a host see every container on it?
