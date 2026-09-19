# eBPF Hello World — Basic Flow Chart

The whole journey of your first program, from the C you wrote to messages
showing up in `trace_pipe`.

---

## 1. The high-level pipeline

```
  ┌───────────────┐
  │  hello.bpf.c  │   You wrote this. C source, kernel-side.
  └───────┬───────┘
          │  clang -target bpf -g -O2 ...
          ▼
  ┌───────────────┐
  │  hello.bpf.o  │   ELF object full of BPF *bytecode* (+ BTF for CO-RE).
  └───────┬───────┘
          │  bpftool prog load ... autoattach   (needs sudo)
          ▼
  ┌─────────────────────────────┐
  │         THE VERIFIER        │   Kernel proves the program is SAFE:
  │  (rejects unsafe programs)  │   terminates, no bad memory access, in bounds.
  └───────┬─────────────────────┘
          │  passed ✓
          ▼
  ┌─────────────────────────────┐
  │           JIT               │   Bytecode -> native machine code (fast).
  └───────┬─────────────────────┘
          │
          ▼
  ┌─────────────────────────────┐
  │     ATTACHED to a hook      │   kprobe on __x64_sys_execve.
  │  (lives in the kernel now)  │   Pinned at /sys/fs/bpf/hello.
  └───────┬─────────────────────┘
          │  every time ANY process calls execve...
          ▼
  ┌─────────────────────────────┐
  │   hello() runs in-kernel    │   Calls bpf_printk("Hello, eBPF world!")
  └───────┬─────────────────────┘
          │  writes to the kernel trace buffer
          ▼
  ┌─────────────────────────────────────────────┐
  │  /sys/kernel/debug/tracing/trace_pipe        │   You read it with:
  │  "...: bpf_trace_printk: Hello, eBPF world!" │   sudo cat trace_pipe
  └─────────────────────────────────────────────┘
```

---

## 2. The three real steps (there is NO separate "run" step)

```
   LOAD  ─────►  ATTACH  ─────►  FIRES AUTOMATICALLY on each event
   (verify        (wire to        (you just OBSERVE via trace_pipe;
    + JIT)         the hook)        you never "start" it manually)
```

Key idea: once attached, the program runs by itself whenever the hooked event
happens. `cat trace_pipe` does NOT run your program — it only reads the output
your already-running program is producing.

---

## 3. Two worlds: kernel space vs user space

```
        USER SPACE                        KERNEL SPACE
  ┌────────────────────┐          ┌────────────────────────────┐
  │  clang (compile)   │          │                            │
  │  bpftool (load)    │ ───────► │  verifier → JIT → attached │
  │  cat trace_pipe    │ ◄─────── │  hello() fires on execve   │
  │  (read output)     │  output  │  bpf_printk → trace buffer │
  └────────────────────┘          └────────────────────────────┘
```

---

## 4. Commands, mapped to the flow

```
 STEP        COMMAND
 ────────    ──────────────────────────────────────────────────────────────
 compile     clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../common \
                   -c hello.bpf.c -o hello.bpf.o
 load+attach sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello autoattach
 observe     sudo cat /sys/kernel/debug/tracing/trace_pipe
 stop watch  Ctrl+C            (stops cat only; program STILL loaded)
 unload      sudo rm /sys/fs/bpf/hello     (removes pin → program unloaded)
 verify gone sudo bpftool prog show | grep hello   (no output = gone)
```

(`bpftool` above = the real binary at `/usr/lib/linux-tools/*/bpftool` on this box.)

---

## 5. Lifecycle summary

```
   write ──► compile ──► load ──► verify ──► JIT ──► attach ──► run on events
                                                                    │
                                                          observe (trace_pipe)
                                                                    │
                                                           unload (rm the pin)
```
