# eBPF Day 4 — opensnoop Flow Chart

The whole journey of the file-open snooper: from the C you write, to a **stable
tracepoint** firing on every `openat`, through a **kernel-side PID filter** driven
by a `const volatile` global variable, to messages in `trace_pipe`.

The big changes from Day 3: the hook is a **static tracepoint** (not a
dynamically-planted fentry trampoline), and there's a **configurable filter**
(`pid_target`) that decides — *inside the kernel* — which events even get born.

---

## 1. The high-level pipeline

```
  ┌──────────────────────┐
  │ opensnoop.bpf.c      │   You write this. One SEC(): a tracepoint.
  │  const volatile      │   pid_target lives here, defaults to 0 (trace all).
  │  int pid_target = 0; │
  └──────────┬───────────┘
             │  clang -target bpf -g -O2 ...
             ▼
  ┌────────────────────────────────┐
  │ opensnoop.bpf.o                │   ELF object. pid_target sits in the
  │   .text  = program bytecode    │   .rodata section with its initial value.
  │   .rodata= pid_target (=0)     │
  └──────────┬─────────────────────┘
             │  (loader may write pid_target into .rodata HERE, before load)
             │  bpftool prog load ... autoattach   (needs sudo)
             ▼
  ┌─────────────────────────────┐
  │         THE VERIFIER        │   Proves the program is safe. Because
  │  (rejects unsafe programs)  │   pid_target is const, it's a known constant.
  └──────────┬──────────────────┘
             │  passed ✓   (.rodata is now frozen READ-ONLY)
             ▼
  ┌─────────────────────────────┐
  │            JIT              │   Bytecode -> native machine code (fast).
  └──────────┬──────────────────┘
             │
             ▼
  ┌───────────────────────────────────────────────┐
  │  ATTACHED to the tracepoint:                   │
  │    syscalls:sys_enter_openat                   │
  │  (a STATIC, kernel-provided hook — stable API) │
  └──────────┬────────────────────────────────────┘
             │  every time ANY process calls openat()...
             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  pid = bpf_get_current_pid_tgid() >> 32                  │
  │  ── THE FILTER (see section 2) ──                        │
  │  if pid_target set AND != pid  →  DROP (return, no event) │
  │  else  →  bpf_printk("Process ID: %d enter sys openat")  │
  └──────────┬──────────────────────────────────────────────┘
             │  writes to the kernel trace buffer
             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  /sys/kernel/debug/tracing/trace_pipe                    │   Read with:
  │  "Process ID: 3840345 enter sys openat"                  │   sudo cat trace_pipe
  │  "Process ID: 3840345 enter sys openat"                  │
  └─────────────────────────────────────────────────────────┘
```

---

## 2. The filter decision — the heart of Day 4

Every single `openat`, on every process, runs through this gate *inside the
kernel* before any output is produced:

```
                 openat() called by some process
                              │
                              ▼
              pid = bpf_get_current_pid_tgid() >> 32
                              │
                              ▼
                  ┌───────────────────────┐
                  │ is pid_target == 0 ?  │
                  └───────┬───────────┬───┘
                     yes  │           │  no (a specific PID was configured)
                          ▼           ▼
                   ┌────────────┐  ┌───────────────────────┐
                   │ TRACE ALL  │  │ is pid == pid_target ? │
                   │ (print it) │  └────────┬──────────┬────┘
                   └────────────┘      yes  │          │  no
                                            ▼          ▼
                                      ┌──────────┐  ┌──────────────┐
                                      │  PRINT   │  │  DROP: return │
                                      │  event   │  │  nothing      │
                                      └──────────┘  └──────────────┘
```

The C that encodes it:

```c
if (pid_target && pid_target != pid)
    return 0;                       // drop — no event ever leaves the kernel
bpf_printk("Process ID: %d enter sys openat\n", pid);
```

Why it matters: the DROP happens *at the hook*, so the kernel never formats or
ships events you'd only discard in user space. On a busy box `openat` fires
constantly — filtering here is the difference between a tool and a firehose.

---

## 3. Where `pid_target` lives, and who touches it when

The whole `const volatile` trick is really about *timing* — two different actors
touch the variable at two different moments:

```
   TIME ───────────────────────────────────────────────────────────►

   compile          load-time (before freeze)        running
   ───────          ─────────────────────────        ───────
   pid_target        USER SPACE may write a           KERNEL side only
   placed in         chosen PID into the .rodata      READS pid_target.
   .rodata with      map here.                        Never writes it.
   value 0.          (volatile keeps the slot         (const guarantees this
                      alive so this write sticks.)     to the verifier.)
                              │
                              ▼
                     then kernel FREEZES .rodata read-only
```

- **`volatile`** → tells the *compiler* not to fold the unwritten `const 0` into a
  literal and delete it. Keeps a real storage slot for user space to write.
- **`const`** → tells the *verifier* the kernel side never mutates it, so it can
  be treated as a fixed constant (safe, optimizable).

Two qualifiers, two audiences, no contradiction — they describe different phases
of the lifecycle.

---

## 4. Two worlds: kernel space vs user space

```
        USER SPACE                        KERNEL SPACE
  ┌────────────────────┐          ┌──────────────────────────────────┐
  │  clang (compile)   │          │                                  │
  │  bpftool (load)  ──┼────────► │  verifier → JIT → attach          │
  │  (loader writes    │          │  tracepoint sys_enter_openat      │
  │   pid_target into  │          │  ── filter (pid_target) ──        │
  │   .rodata, if any) │          │  bpf_printk → trace buffer        │
  │  cat /etc/hostname ┼────────► │  openat() fires → handler runs    │
  │  cat trace_pipe    │ ◄─────── │  emitted (unless filtered out)    │
  └────────────────────┘  output  └──────────────────────────────────┘
```

---

## 5. Commands, mapped to the flow (this repo's bpftool routine)

```
 STEP        COMMAND
 ────────    ──────────────────────────────────────────────────────────────
 check hook  sudo cat /sys/kernel/debug/tracing/available_events | grep openat
             (expect: syscalls:sys_enter_openat)
 compile     clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../common \
                   -c opensnoop.bpf.c -o opensnoop.bpf.o
 load+attach sudo bpftool prog load opensnoop.bpf.o /sys/fs/bpf/opensnoop autoattach
 verify      sudo bpftool prog show | grep -i openat   (expect one entry)
 trigger     cat /etc/hostname      (in another shell — any command opens files)
 observe     sudo cat /sys/kernel/debug/tracing/trace_pipe
 stop watch  Ctrl+C            (stops cat only; program STILL loaded)
 unload      sudo rm /sys/fs/bpf/opensnoop
 verify gone sudo bpftool prog show | grep -i openat   (no output = gone)
```

(`bpftool` above = the real binary at `/usr/lib/linux-tools/*/bpftool` on this
box, per the README note.)

> Reminder from CONCEPTS §8: with `bpftool prog load` there is **no
> `--pid_target` flag** — that flag is a eunomia (`ecli`) feature generated from
> the `/// @description` annotation. Under bpftool the default `pid_target = 0`
> traces everything, which is exactly what you want to see the tracepoint work.
> Actually *injecting* a specific PID from user space needs a libbpf skeleton
> loader (a later week), not `bpftool prog load`.

---

## 6. eunomia path vs this repo (side by side)

```
                 eunomia (the tutorial)          this repo (Days 1–4)
 ─────────────   ──────────────────────          ──────────────────────
 compile         ecc opensnoop.bpf.c             clang -target bpf ... -c ...
 load + run      ecli run package.json           sudo bpftool prog load ...
 set the PID     --pid_target 618  (auto CLI)     write .rodata via a loader
                                                  (bpftool load: default only)
 help text       from /// @description            annotation is inert
 read output     trace_pipe                       trace_pipe   (same!)
```

Same concept either way; only the *loading/config plumbing* differs. This repo
stays on the raw toolchain to keep Day 4 consistent with Days 1–3.

---

## 7. Lifecycle summary

```
   write ──► compile ──► (loader may set pid_target) ──► load ──► verify ──►
   JIT ──► attach (tracepoint) ──► run on each openat
                                        │
                          ┌─────────────┴──────────────┐
                          │  filter: pid_target gate    │
                          │   0        → print all      │
                          │   == pid   → print          │
                          │   != pid   → drop silently  │
                          └─────────────┬──────────────┘
                                        │
                              observe (trace_pipe)
                                        │
                               unload (rm the pin)
```

---

## 8. How Day 4 differs from Day 3 at a glance

```
                      DAY 3 (fentry)              DAY 4 (tracepoint)
 ───────────────────  ─────────────────────────  ─────────────────────────
 hook type            dynamic (BPF trampoline)    STATIC, kernel-provided
 target               do_unlinkat (internal)      sys_enter_openat (stable API)
 target stability     may change across kernels   kernel devs promise to keep
 SEC() prefix         fentry/ , fexit/            tracepoint/syscalls/...
 context arg          typed function args         struct trace_event_raw_sys_enter
 new idea of the day  direct field reads          stable hook + config filter
 filtering            none                        kernel-side via pid_target
 needs BTF            yes                          no (still uses vmlinux.h types)
```

The through-line across Days 2→3→4: the *target* keeps getting more trustworthy —
from an internal name you hope survives an upgrade, to a hook the kernel promises
to keep stable. Plus, for the first time, the program is **configurable** from
user space without recompiling. Both are habits every production sensor relies on.
