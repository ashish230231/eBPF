# eBPF Day 6 — sigsnoop Flow Chart

The whole journey of the signal sniffer: from the C you write, to **two
tracepoints** (entry and exit of `kill()`) correlated through a **hash map**,
to one combined message in `trace_pipe`.

The big change from Days 1–5: for the first time, entry and exit don't just
each print their own line — they share a piece of kernel-resident memory (the
map) so the exit side can finish the sentence the entry side started.

---

## 1. The high-level pipeline

```
  ┌─────────────────────────────┐
  │ sigsnoop.bpf.c              │   You write this. TWO SEC()s: entry + exit
  │   struct event { ... }      │   tracepoints on kill(), sharing one map.
  │   values: HASH map (.maps)  │
  └──────────┬───────────────────┘
             │  clang -target bpf -g -O2 ...
             ▼
  ┌────────────────────────────────┐
  │ sigsnoop.bpf.o                 │   ELF object: two programs + one map
  │   .maps = "values" descriptor  │   descriptor (not yet a real map).
  └──────────┬─────────────────────┘
             │  bpftool prog load ... autoattach   (needs sudo)
             ▼
  ┌─────────────────────────────┐
  │         THE VERIFIER        │   Checks both programs AND that every
  │  (rejects unsafe programs)  │   map access (lookup/update/delete) is
  └──────────┬──────────────────┘   type- and bounds-safe.
             │  passed ✓
             │  kernel CREATES the real "values" hash map in kernel memory
             ▼
  ┌─────────────────────────────┐
  │            JIT              │   Both programs -> native machine code.
  └──────────┬──────────────────┘
             │
             ▼
  ┌───────────────────────────────────────────────────────────┐
  │  ATTACHED to TWO tracepoints:                              │
  │    syscalls:sys_enter_kill   →  kill_entry()                │
  │    syscalls:sys_exit_kill    →  kill_exit()                 │
  └──────────┬──────────────────────────────────────────────────┘
             │
             ▼  some process calls kill(tpid, sig)
  ┌───────────────────────────────────────────────────────────┐
  │  ENTRY: kill_entry(ctx)                                     │
  │    tpid = ctx->args[0], sig = ctx->args[1]                   │
  │    tid  = (u32)bpf_get_current_pid_tgid()   ← LOWER 32 bits  │
  │    event = {pid, tpid, sig, comm}                            │
  │    bpf_map_update_elem(values, &tid, &event, BPF_ANY)  ─────┐ │
  └───────────────────────────────────────────────────────────┤ │
                                                                │ │
                           values HASH MAP (kernel memory)      │ │
                       ┌───────────────────────────────────┐   │ │
                       │  tid → event{pid,tpid,sig,comm,ret}│ ◄─┘ │
                       └───────────────────────────────────┘     │
                                                                  │
             kill() returns ───────────────────────────────────── ┘
             ▼
  ┌───────────────────────────────────────────────────────────┐
  │  EXIT: kill_exit(ctx)                                       │
  │    tid = (u32)bpf_get_current_pid_tgid()   ← same TID         │
  │    eventp = bpf_map_lookup_elem(values, &tid)  ◄─────────────┤ reads it back
  │    if NULL → return (nothing to correlate)                   │
  │    eventp->ret = ctx->ret           (fills in the missing piece)
  │    bpf_printk(... pid, comm, sig ...)                         │
  │    bpf_printk(... tpid, ret ...)                              │
  │    bpf_map_delete_elem(values, &tid)      (remove it — done)  │
  └──────────┬──────────────────────────────────────────────────┘
             │
             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  /sys/kernel/debug/tracing/trace_pipe                    │   Read with:
  │  "PID 363 (bash) sent signal 0"                           │   sudo cat trace_pipe
  │  "to PID 1527, ret = 0"                                    │
  └─────────────────────────────────────────────────────────┘
```

---

## 2. Why a map, and not just two independent prints

```
        WITHOUT a map (Days 1–4's style)       WITH a map (Day 6)
  ┌───────────────────────────────┐      ┌───────────────────────────────┐
  │ entry fires → prints its data  │      │ entry fires → STORES its data  │
  │ exit  fires → prints its data  │      │ exit  fires → READS the stored │
  │                                 │      │               data, ADDS ret,  │
  │ Result: TWO separate,           │      │               prints ONE       │
  │ uncorrelated lines. You can't   │      │               combined record, │
  │ easily tell which entry line    │      │               then deletes it. │
  │ belongs to which exit line if   │      │                                 │
  │ many kill() calls overlap.      │      │ Result: exactly one entry's    │
  │                                 │      │ data is used per matching exit,│
  │                                 │      │ keyed precisely by TID.        │
  └───────────────────────────────┘      └───────────────────────────────┘
```

The map is what turns "two disjoint observations" into "one correlated
event" — the core new capability of the day.

---

## 3. The map as a mailbox — lifecycle of ONE entry

```
   TIME ──────────────────────────────────────────────────────────────►

   kill() called          kernel runs the         kill() returns
   by some thread          syscall                  to that thread
       │                                                   │
       ▼                                                   ▼
   ┌─────────────┐                                   ┌─────────────┐
   │ kill_entry   │                                   │ kill_exit    │
   │ runs         │                                   │ runs         │
   │              │                                   │              │
   │ WRITE:       │   map holds the event             │ READ:        │
   │ tid → event  │ ─────────────────────────────────►│ tid → event  │
   │ (update_elem)│   (sitting in kernel memory,       │ (lookup_elem)│
   │              │    waiting, keyed by TID)          │              │
   └─────────────┘                                   │ MUTATE:      │
                                                        │ event.ret=…  │
                                                        │              │
                                                        │ PRINT        │
                                                        │              │
                                                        │ DELETE:      │
                                                        │ tid entry    │
                                                        │ (delete_elem)│
                                                        └─────────────┘

   Entry → map → exit → gone. The map entry's entire life is exactly
   one kill() call's duration — never longer, never leaked.
```

---

## 4. Two tracepoints, two context struct shapes

```
                     sys_enter_kill                  sys_exit_kill
 ─────────────────   ──────────────────────────────  ──────────────────────
 struct type         trace_event_raw_sys_enter        trace_event_raw_sys_exit
 what it carries      generic args[6] (any syscall)    a single ret value
 what WE read         args[0] = tpid, args[1] = sig     ret = kill()'s result
 SEC() prefix          tracepoint/syscalls/              tracepoint/syscalls/
                       sys_enter_kill                    sys_exit_kill
```

Same `struct trace_event_raw_sys_enter` type from Day 4 — but for the first
time, we actually reach into `->args[]` instead of only computing the PID.

---

## 5. Commands, mapped to the flow (this repo's bpftool routine)

```
 STEP        COMMAND
 ────────    ──────────────────────────────────────────────────────────────
 check hooks sudo cat /sys/kernel/debug/tracing/available_events | grep kill
             (expect: syscalls:sys_enter_kill, syscalls:sys_exit_kill)
 compile     clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../common \
                   -c sigsnoop.bpf.c -o sigsnoop.bpf.o
 load+attach sudo /usr/lib/linux-tools/*/bpftool prog load sigsnoop.bpf.o \
                   /sys/fs/bpf/sigsnoop autoattach
 verify      sudo /usr/lib/linux-tools/*/bpftool prog show | grep -i kill
 verify map  sudo /usr/lib/linux-tools/*/bpftool map list | grep -i values
 trigger     kill -0 $$          (sends harmless signal 0 to your own shell)
             kill -0 <some_pid>  (try a real PID too)
 observe     sudo cat /sys/kernel/debug/tracing/trace_pipe
 stop watch  Ctrl+C            (stops cat only; program STILL loaded)
 unload      sudo rm /sys/fs/bpf/sigsnoop
 verify gone sudo /usr/lib/linux-tools/*/bpftool prog show | grep -i kill
```

(Use the real `bpftool` binary path, per the WSL note in the main README and
what Day 5 already confirmed works on this machine.)

---

## 6. How Day 6 differs from Day 4 at a glance

```
                      DAY 4 (opensnoop)            DAY 6 (sigsnoop)
 ───────────────────  ───────────────────────────  ───────────────────────────
 hook type            ONE tracepoint (enter only)   TWO tracepoints (enter+exit)
 state between events none needed                   HASH MAP (values)
 ctx fields read       none (PID only)               args[0], args[1], ret
 config mechanism      const volatile pid_target     (none today — map keyed
                        (.rodata, set before load)     dynamically by TID instead)
 today's new idea      stable hook + static filter    cross-event state via a map
```

The through-line: every day has added one new capability on top of the last.
Day 6's is the biggest structural one yet — a persistent, shared, kernel-side
data structure your BPF programs can read and write across completely
separate invocations, which is also the foundation every later "real" sensor
(ring buffers, per-PID counters, config maps) is built on.
