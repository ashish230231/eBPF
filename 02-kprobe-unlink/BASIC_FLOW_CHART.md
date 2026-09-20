# eBPF Day 2 — kprobe + kretprobe Flow Chart

The whole journey of the unlink monitor: from the C you write, to two probes
firing on every file deletion, to paired messages in `trace_pipe`.

The big change from Day 1: there are now **two** probes on the **same** kernel
function — one on entry, one on return.

---

## 1. The high-level pipeline

```
  ┌──────────────────────┐
  │ kprobe-unlink.bpf.c  │   You write this. Two SEC()s: kprobe + kretprobe.
  └──────────┬───────────┘
             │  clang -target bpf -g -O2 ...
             ▼
  ┌──────────────────────┐
  │ kprobe-unlink.bpf.o  │   ELF object: 2 BPF programs + BTF for CO-RE.
  └──────────┬───────────┘
             │  bpftool prog load ... autoattach   (needs sudo)
             ▼
  ┌─────────────────────────────┐
  │         THE VERIFIER        │   Proves BOTH programs are safe:
  │  (rejects unsafe programs)  │   terminates, no bad memory, reads are helpers.
  └──────────┬──────────────────┘
             │  passed ✓
             ▼
  ┌─────────────────────────────┐
  │            JIT              │   Bytecode -> native machine code (fast).
  └──────────┬──────────────────┘
             │
             ▼
  ┌───────────────────────────────────────────────┐
  │  ATTACHED to do_unlinkat at TWO points:        │
  │    • kprobe    -> function ENTRY               │
  │    • kretprobe -> function RETURN              │
  │  (both live in the kernel, pinned under /sys)  │
  └──────────┬────────────────────────────────────┘
             │  every time ANY process deletes a file (unlink)...
             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  ENTRY: BPF_CORE_READ(name, name) -> filename            │
  │         bpf_printk("KPROBE ENTRY pid=.. filename=..")     │
  │  RETURN: read ret value (0 = ok, <0 = error)             │
  │         bpf_printk("KPROBE EXIT pid=.. ret=..")           │
  └──────────┬──────────────────────────────────────────────┘
             │  writes to the kernel trace buffer
             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  /sys/kernel/debug/tracing/trace_pipe                    │   Read with:
  │  "KPROBE ENTRY pid = 9346, filename = test1"             │   sudo cat trace_pipe
  │  "KPROBE EXIT: pid = 9346, ret = 0"                      │
  └─────────────────────────────────────────────────────────┘
```

---

## 2. Entry vs return: the two-probe timeline

```
   process runs:  rm test1
        │
        ▼  syscall unlink -> kernel worker do_unlinkat(dfd, name)
   ┌────────────────────────────────────────────┐
   │  ENTER do_unlinkat                          │ ── kprobe fires ──►  read name  ─► "ENTRY ... filename=test1"
   │     (arguments available here)              │
   │     ... kernel actually unlinks the file ...│
   │  RETURN from do_unlinkat                    │ ── kretprobe fires ─►  read ret  ─► "EXIT ... ret=0"
   └────────────────────────────────────────────┘
        │
        ▼  control returns to rm
```

Key idea: one deletion → **two** trace lines, in order (ENTRY then EXIT).
The kprobe sees *what*; the kretprobe sees *the result*.

---

## 3. Why the read goes through a helper (the boundary)

```
        eBPF SANDBOX                          KERNEL MEMORY
  ┌────────────────────────┐          ┌────────────────────────────┐
  │ name  (kernel pointer) │          │  struct filename {         │
  │                        │          │     const char *name; ─────┼──► "test1"
  │  name->name  ❌ BANNED  │          │     ...                    │
  │                        │          │  }                         │
  │  BPF_CORE_READ(name,   │  safe    │                            │
  │      name)      ✅ ─────┼────────► │  bpf_probe_read_kernel     │
  │                        │  copy    │  + CO-RE offset relocation │
  └────────────────────────┘          └────────────────────────────┘
```

The verifier forbids dereferencing `name` directly. `BPF_CORE_READ` copies the
bytes safely AND records a relocation so the field offset is patched to match
whatever kernel you load on.

---

## 4. Two worlds: kernel space vs user space

```
        USER SPACE                        KERNEL SPACE
  ┌────────────────────┐          ┌────────────────────────────────┐
  │  clang (compile)   │          │                                │
  │  bpftool (load)    │ ───────► │  verifier → JIT → 2 probes     │
  │  rm test1  ────────┼────────► │  do_unlinkat entry  -> kprobe  │
  │  cat trace_pipe    │ ◄─────── │  do_unlinkat return -> kretprobe│
  │  (read output)     │  output  │  bpf_printk → trace buffer     │
  └────────────────────┘          └────────────────────────────────┘
```

---

## 5. Commands, mapped to the flow

```
 STEP        COMMAND
 ────────    ──────────────────────────────────────────────────────────────
 compile     clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../common \
                   -c kprobe-unlink.bpf.c -o kprobe-unlink.bpf.o
 load+attach sudo bpftool prog load kprobe-unlink.bpf.o /sys/fs/bpf/unlink autoattach
 trigger     touch test1 && rm test1     (in another shell)
 observe     sudo cat /sys/kernel/debug/tracing/trace_pipe
 stop watch  Ctrl+C            (stops cat only; programs STILL loaded)
 unload      sudo rm /sys/fs/bpf/unlink   (removes pin → programs unloaded)
 verify gone sudo bpftool prog show | grep do_unlinkat   (no output = gone)
```

(`bpftool` above = the real binary at `/usr/lib/linux-tools/*/bpftool` on this box.)

---

## 6. Lifecycle summary

```
   write ──► compile ──► load ──► verify ──► JIT ──► attach (x2) ──► run on each unlink
                                                                          │
                                                        ┌─────────────────┴─────────────────┐
                                                        │  kprobe: ENTRY  (what file)        │
                                                        │  kretprobe: EXIT (success/fail)    │
                                                        └─────────────────┬─────────────────┘
                                                                          │
                                                                observe (trace_pipe)
                                                                          │
                                                                 unload (rm the pin)
```
