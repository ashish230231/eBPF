# eBPF Day 3 — fentry / fexit Flow Chart

The whole journey of the modern unlink monitor: from the C you write, to two
probes firing on every file deletion through a **BPF trampoline**, to paired
messages in `trace_pipe`.

The big change from Day 2: the probes attach via a **trampoline** (not a
breakpoint), the reads are **direct** (no `BPF_CORE_READ`), and the exit probe
sees the **arguments AND the return value together**.

---

## 1. The high-level pipeline

```
  ┌──────────────────────┐
  │ fentry-link.bpf.c    │   You write this. Two SEC()s: fentry + fexit.
  └──────────┬───────────┘
             │  clang -target bpf -g -O2 ...
             ▼
  ┌──────────────────────┐
  │ fentry-link.bpf.o    │   ELF object: 2 BPF programs + BTF (required!).
  └──────────┬───────────┘
             │  bpftool prog load ... autoattach   (needs sudo)
             ▼
  ┌─────────────────────────────┐
  │         THE VERIFIER        │   Proves BOTH programs are safe. Because args
  │  (rejects unsafe programs)  │   are BTF-typed, direct field reads are OK.
  └──────────┬──────────────────┘
             │  passed ✓
             ▼
  ┌─────────────────────────────┐
  │            JIT              │   Bytecode -> native machine code (fast).
  └──────────┬──────────────────┘
             │
             ▼
  ┌───────────────────────────────────────────────┐
  │  ATTACHED to do_unlinkat via a TRAMPOLINE:     │
  │    • fentry -> function ENTRY                  │
  │    • fexit  -> function RETURN                 │
  │  (small generated machine code, no breakpoint) │
  └──────────┬────────────────────────────────────┘
             │  every time ANY process deletes a file (unlink)...
             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  ENTRY (fentry): read name->name DIRECTLY                │
  │         bpf_printk("fentry: pid=.. filename=..")         │
  │  RETURN (fexit): read name->name AND ret together        │
  │         bpf_printk("fexit: pid=.. filename=.. ret=..")   │
  └──────────┬──────────────────────────────────────────────┘
             │  writes to the kernel trace buffer
             ▼
  ┌─────────────────────────────────────────────────────────┐
  │  /sys/kernel/debug/tracing/trace_pipe                    │   Read with:
  │  "fentry: pid = 9290, filename = test_file"              │   sudo cat trace_pipe
  │  "fexit: pid = 9290, filename = test_file, ret = 0"      │
  └─────────────────────────────────────────────────────────┘
```

---

## 2. Entry vs exit: the two-probe timeline

```
   process runs:  rm test_file
        │
        ▼  syscall unlink -> kernel worker do_unlinkat(dfd, name)
   ┌────────────────────────────────────────────┐
   │  ENTER do_unlinkat                          │ ── fentry fires ──►  read name->name        ─► "fentry ... filename=test_file"
   │     (typed arguments available here)        │
   │     ... kernel actually unlinks the file ...│
   │  RETURN from do_unlinkat                    │ ── fexit fires ───►  read name->name + ret  ─► "fexit ... filename=test_file, ret=0"
   └────────────────────────────────────────────┘
        │
        ▼  control returns to rm
```

Key idea: one deletion → **two** trace lines (fentry then fexit). fentry sees
*what*; fexit sees *what AND the result* — that's the upgrade over Day 2's
kretprobe, which only saw the result.

---

## 3. Why the read is now DIRECT (trampoline vs Day 2's helper)

```
        DAY 2 — kprobe                          DAY 3 — fentry
  ┌────────────────────────────┐         ┌────────────────────────────┐
  │ ctx = raw pt_regs          │         │ trampoline hands you the   │
  │ (no type info)             │         │ REAL, BTF-typed arguments  │
  │                            │         │                            │
  │ name->name   ❌ BANNED      │         │ name->name   ✅ ALLOWED      │
  │ must use:                  │         │ verifier knows the layout  │
  │ BPF_CORE_READ(name, name)  │         │ from BTF, proves it safe   │
  └────────────────────────────┘         └────────────────────────────┘
```

On Day 2 the kprobe gave raw registers, so the verifier trusted nothing and
forced a helper read. On Day 3 the trampoline + BTF give fully typed pointers, so
the verifier can prove `name->name` is safe and lets you dereference directly.

---

## 4. Two worlds: kernel space vs user space

```
        USER SPACE                        KERNEL SPACE
  ┌────────────────────┐          ┌──────────────────────────────────┐
  │  clang (compile)   │          │                                  │
  │  bpftool (load)    │ ───────► │  verifier → JIT → trampoline     │
  │  rm test_file  ────┼────────► │  do_unlinkat entry  -> fentry    │
  │  cat trace_pipe    │ ◄─────── │  do_unlinkat return -> fexit     │
  │  (read output)     │  output  │  bpf_printk → trace buffer       │
  └────────────────────┘          └──────────────────────────────────┘
```

---

## 5. Commands, mapped to the flow

```
 STEP        COMMAND
 ────────    ──────────────────────────────────────────────────────────────
 compile     clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../common \
                   -c fentry-link.bpf.c -o fentry-link.bpf.o
 load+attach sudo bpftool prog loadall fentry-link.bpf.o /sys/fs/bpf/unlink autoattach
             (loadall, NOT load — this object has 2 programs; see CONCEPTS 8.5)
 verify both sudo bpftool prog show | grep -i unlink   (expect TWO entries)
 trigger     touch test_file && rm test_file     (in another shell)
 observe     sudo cat /sys/kernel/debug/tracing/trace_pipe
 stop watch  Ctrl+C            (stops cat only; programs STILL loaded)
 unload      sudo rm -rf /sys/fs/bpf/unlink   (removes pin dir → programs unloaded)
 verify gone sudo bpftool prog show | grep -i unlink   (no output = gone)
```

(`bpftool` above = the real binary at `/usr/lib/linux-tools/*/bpftool` on this box.)

---

## 6. Lifecycle summary

```
   write ──► compile ──► load ──► verify ──► JIT ──► attach x2 (trampoline) ──► run on each unlink
                                                                                     │
                                                        ┌────────────────────────────┴───────────────┐
                                                        │  fentry: ENTRY  (which file)                │
                                                        │  fexit:  EXIT   (which file + success/fail)  │
                                                        └────────────────────────────┬───────────────┘
                                                                                     │
                                                                           observe (trace_pipe)
                                                                                     │
                                                                            unload (rm the pin)
```

---

## 7. How Day 3 differs from Day 2 at a glance

```
                      DAY 2 (kprobe)              DAY 3 (fentry)
 ───────────────────  ─────────────────────────  ─────────────────────────
 attach mechanism     breakpoint / trap          BPF trampoline
 entry macro          BPF_KPROBE                  BPF_PROG
 exit macro           BPF_KRETPROBE               BPF_PROG
 SEC() prefixes       kprobe/ , kretprobe/        fentry/ , fexit/
 field read           BPF_CORE_READ(name, name)   name->name  (direct)
 exit sees args?      no (ret only)               yes (args + ret)
 needs BTF            no                          yes
 speed                baseline                    ~10x faster
```
