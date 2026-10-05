# eBPF Day 5 — bashreadline Flow Chart

The whole journey of the bash command-line sniffer: from the C you write, to a
**uretprobe** planted on a *user-space* binary's function, through a safe
cross-address-space read, to messages in `trace_pipe`.

The big change from Days 1–4: for the first time, the thing being hooked
isn't kernel code at all — it's a function (`readline`) inside `/bin/bash`,
running entirely in user space.

---

## 1. The high-level pipeline

```
  ┌───────────────────────────┐
  │ bashreadline.bpf.c        │   You write this. One SEC(): a uretprobe.
  │   BPF_KRETPROBE(printret) │   Target: readline's RETURN value.
  └──────────┬─────────────────┘
             │  clang -target bpf -g -O2 ...
             ▼
  ┌────────────────────────────────┐
  │ bashreadline.bpf.o             │   ELF object with the compiled probe.
  └──────────┬─────────────────────┘
             │  bpftool prog load ... autoattach   (needs sudo)
             ▼
  ┌─────────────────────────────┐
  │         THE VERIFIER        │   Proves the program is safe — including
  │  (rejects unsafe programs)  │   the user-memory read, which MUST go
  └──────────┬──────────────────┘   through bpf_probe_read_user_str.
             │  passed ✓
             ▼
  ┌─────────────────────────────┐
  │            JIT              │   Bytecode -> native machine code.
  └──────────┬──────────────────┘
             │
             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  ATTACHED: kernel patches the readline() RETURN          │
  │  instruction INSIDE THE FILE /bin/bash with int3          │
  │  (a fast breakpoint) — not inside any one process.        │
  └──────────┬────────────────────────────────────────────────┘
             │  ANY process running /bin/bash hits this, now or later
             ▼
  ┌───────────────────────────────────────────────────────────────┐
  │  bash's readline() returns  →  int3 trap  →  kernel mode        │
  │  ── YOUR eBPF PROGRAM RUNS ──                                   │
  │  ret == NULL (Ctrl-D/EOF)?  → drop, return 0                    │
  │  else:                                                          │
  │     comm = bpf_get_current_comm()          (process name)       │
  │     pid  = bpf_get_current_pid_tgid() >> 32                     │
  │     str  = bpf_probe_read_user_str(ret)    ← CROSSES INTO       │
  │                                               USER-SPACE MEMORY │
  │     bpf_printk("PID %d (%s) read: %s", pid, comm, str)           │
  └──────────┬──────────────────────────────────────────────────────┘
             │  kernel restores the real instruction, single-steps it,
             │  control returns to bash — completely transparent to it
             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  /sys/kernel/debug/tracing/trace_pipe                    │   Read with:
  │  "PID 4821 (bash) read: ls -la"                           │   sudo cat trace_pipe
  │  "PID 4821 (bash) read: cat /etc/hostname"                │
  └─────────────────────────────────────────────────────────┘
```

---

## 2. Kernel-space vs user-space memory — the boundary this day crosses

```
        USER SPACE  (/bin/bash, one or more running instances)
  ┌───────────────────────────────────────────────────────────┐
  │  readline() assembles the typed line in ITS OWN memory      │
  │  readline() returns → char *ret points at that string        │
  └──────────────────────────┬────────────────────────────────┘
                             │  int3 trap on return
                             ▼
        KERNEL SPACE  (your eBPF program, running now)
  ┌───────────────────────────────────────────────────────────┐
  │  ret is just a NUMBER (a user-space address) here.          │
  │  Cannot dereference it directly — different address space,  │
  │  verifier forbids it outright.                               │
  │                                                              │
  │  bpf_probe_read_user_str(str, sizeof(str), ret)               │
  │    → kernel safely copies bytes FROM that user address        │
  │      INTO your BPF stack buffer `str`, checking validity      │
  │      the whole way (unlike Days 1–4's bpf_probe_read_kernel*, │
  │      which crossed BPF-stack ↔ kernel-struct instead)         │
  └───────────────────────────────────────────────────────────┘
```

This is the one new mental model for the day: Days 1–4 only ever read *kernel*
memory into your BPF program. Day 5 reads *user-space* memory into it — same
"never dereference directly, always go through a checked helper" discipline,
just a different address space on the other end.

---

## 3. Entry vs return — same shape as Day 2, new address space

```
                 Day 2 (kprobe/kretprobe)        Day 5 (uprobe/uretprobe)
                 on do_unlinkat (KERNEL)          on readline (USER SPACE)
                 ───────────────────────          ───────────────────────
  ENTRY probe    kprobe/do_unlinkat               uprobe//bin/bash:readline
                 read ARGUMENTS (dfd, name)       (not used today)

  RETURN probe   kretprobe/do_unlinkat            uretprobe//bin/bash:readline
                 read RETURN VALUE (long ret)     read RETURN VALUE (char *ret)
                 via BPF_KRETPROBE                via BPF_KRETPROBE (same macro!)
```

Day 5 only wires up the return side, because the payload we want — the
completed command line — only exists once `readline` is about to hand it
back.

---

## 4. Commands, mapped to the flow (this repo's bpftool routine)

```
 STEP         COMMAND
 ────────     ──────────────────────────────────────────────────────────────
 find target  which bash
              (note the real path — e.g. /bin/bash or /usr/bin/bash — and
               use THAT path inside your SEC() string)
 compile      clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../common \
                    -c bashreadline.bpf.c -o bashreadline.bpf.o
 load+attach  sudo bpftool prog load bashreadline.bpf.o /sys/fs/bpf/bashreadline autoattach
 verify       sudo bpftool prog show | grep -i printret   (expect one entry)
 trigger      open ANOTHER terminal, run a plain bash shell, type any command
              and press Enter (e.g. `ls`, `whoami`)
 observe      sudo cat /sys/kernel/debug/tracing/trace_pipe
 stop watch   Ctrl+C            (stops cat only; program STILL loaded)
 unload       sudo rm /sys/fs/bpf/bashreadline
 verify gone  sudo bpftool prog show | grep -i printret   (no output = gone)
```

(`bpftool` above = the real binary at `/usr/lib/linux-tools/*/bpftool` on this
box, per the README note.)

---

## 5. How Day 5 differs from Days 1–4 at a glance

```
                      Days 1–4 (kernel hooks)     Day 5 (uprobe)
 ───────────────────  ─────────────────────────   ─────────────────────────
 address space        kernel                      user space (/bin/bash)
 target addressing    kernel symbol / tp name      binary path + symbol
 patch location        kernel .text                 the FILE's own mapping
 read helper           bpf_probe_read_kernel*/CORE  bpf_probe_read_user_str
 scope                 whole kernel, all processes  every process running
                                                     that ONE binary
 today's new idea      —                            crossing kernel↔user
                                                     memory boundary safely
```

The through-line across all five days: same compile → verify → JIT → attach →
observe shape every time. What changes each day is *where* the hook lives and
*what* it's allowed to read — and Day 5 is the first day that hook lives
outside the kernel entirely.
