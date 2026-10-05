# eBPF Day 5 — Uprobe/Uretprobe: Capturing `readline` Calls in Bash

Read this top to bottom. It builds on Days 1–4. By the end, every word in
`bashreadline.bpf.c` should mean something — especially the headline idea of
the day: **hooking a function inside a *user-space* program**, not the kernel.

Days 1–4 all hooked something *inside the kernel*: `execve` (Day 1),
`do_unlinkat` via kprobe (Day 2) and fentry (Day 3), `sys_enter_openat` via a
tracepoint (Day 4). Every one of those targets lives in kernel code. Day 5
crosses a boundary: the function we hook, `readline`, runs entirely in **user
space**, inside `/bin/bash`. eBPF can reach across that boundary too — that's
what a **uprobe** is for.

The concrete goal: every time any running bash shell finishes reading a line
of input from the user, print the PID, the process name, and the exact text
that was typed — *before* bash even executes it.

---

## 1. What is a uprobe (and uretprobe)?

A **uprobe** (user-space probe) is the user-space counterpart to a kprobe.
Same idea, different address space:

```
   kprobe (Days 1–2)                    uprobe (Day 5)
   ───────────────────────────          ───────────────────────────
   dynamically planted on a             dynamically planted on a
   KERNEL function's instruction        USER-SPACE function's instruction
   target = kernel symbol               target = binary path + symbol/offset
   fires for kernel code execution      fires for a specific binary's code
```

Just like Day 2 had a kprobe (entry) and a kretprobe (return) on the *same*
kernel function, a uprobe has the same entry/return split:

```
   uprobe      → fires when the user-space function is ENTERED
   uretprobe   → fires when the user-space function RETURNS
```

Day 5 only needs the **return** side — we want readline's result (the string
the user typed), not its arguments — so the code uses a single `uretprobe`.

### How it actually works under the hood

The kernel can't "call into" an arbitrary user program the way it can jump to
its own code. Instead, when you attach a uprobe:

```
  1. attach     → kernel patches the target instruction in the BINARY FILE
                  (not a running process) with a fast breakpoint: int3 on x86
  2. any process executes that instruction (because it mapped that file)
  3. int3 traps → CPU switches to kernel mode → kernel finds the uprobe
  4. kernel runs your eBPF program (with access to user-space memory/regs)
  5. kernel restores the original instruction *for that execution*, single-steps
     past it, then returns control to the user-space program
```

This is why the doc up top says: *"uprobe is file-based."* The breakpoint is
planted on the **file on disk**, not on one process's memory. That has a
surprising consequence, covered next.

---

## 2. Why "file-based" matters — system-wide, not per-process

Because the instrumentation point lives in the binary file's mapping, **every
process that executes that file gets probed** — including bash shells that
haven't even started yet when you attach. Compare this to the earlier days:

```
 kprobe/tracepoint (Days 1–4)      uprobe (Day 5)
 ─────────────────────────────     ─────────────────────────────
 hooks a KERNEL function            hooks a spot in a FILE ON DISK
 fires for every process           fires for every process that runs
 that triggers that kernel path    that file (now AND in the future)
 one hook, one kernel image        one hook, potentially many running
                                    instances of /bin/bash simultaneously
```

This is the whole reason uprobes are powerful for observability: attach once,
and you see activity across the entire system — every existing and future
bash shell — without touching bash's code or restarting anything.

---

## 3. Why hook `readline` specifically

`readline` is the library function bash calls to read one line of interactive
input from the terminal and hand back the completed string (after the user
presses Enter — including tab-completion, history recall, editing, etc., all
resolved). Hooking its **return** gives us exactly the finished command line,
with none of the intermediate keystrokes to reassemble ourselves.

This is also *why* we need the user-space/kernel boundary at all: the kernel
has no idea what "a line the user typed into bash" means — that's an
application-level concept that only exists inside bash's own memory, after
bash's own C library code has assembled it. A kprobe or tracepoint, which only
sees kernel functions, structurally cannot see this. Only a uprobe, reaching
into the user-space process, can.

---

## 4. The SEC() for a uprobe — anatomy of the target string

```c
SEC("uretprobe//bin/bash:readline")
```

Compare the whole progression across the week — the *kind* of target keeps
changing, and now the *addressing scheme* changes too:

```
 Day 1:  SEC("kprobe/__x64_sys_execve")             kernel symbol name
 Day 2:  SEC("kprobe/do_unlinkat")  + kretprobe      kernel symbol name
 Day 3:  SEC("fentry/do_unlinkat")  + fexit          kernel symbol name
 Day 4:  SEC("tracepoint/syscalls/sys_enter_openat") kernel-defined event name
 Day 5:  SEC("uretprobe//bin/bash:readline")         BINARY PATH : SYMBOL
```

Breaking down `uretprobe//bin/bash:readline`:

```
   uretprobe   /   /bin/bash   :   readline
   ─────────   ─   ─────────   ─   ────────
   probe type      binary path     function/symbol
               (the extra leading
                slash is just the
                separator before an
                absolute path)
```

- The probe type is `uprobe` or `uretprobe` (entry vs return — same split as
  kprobe/kretprobe).
- The binary path tells the kernel **which file's mapping** to patch. It must
  be a path libbpf can actually open and read symbols from (a real file on
  disk, resolved at attach time).
- The symbol name (`readline`) is resolved against that binary's own symbol
  table to find the exact instruction offset to patch. (You can also give a
  raw numeric offset instead of a symbol name, for stripped binaries — not
  needed here since bash ships `readline`'s symbol.)

---

## 5. `BPF_KRETPROBE` — reused from Day 2, now on a user function

```c
BPF_KRETPROBE(printret, const void *ret)
```

This is the **exact same macro** Day 2 used for `do_unlinkat`'s kretprobe. It
still means "unpack the probed function's return value into a normal, typed
parameter." Nothing about the macro cares whether the probed function lives in
the kernel or in user space — a return value is a return value. That's the
reuse worth noticing: Day 5 introduces a new *target* (user space) but not a
new *macro*.

`readline`'s real C signature returns `char *` (the line it read, or `NULL` at
EOF/Ctrl-D). We declare the parameter as `const void *ret` because we're about
to treat it as an opaque user-space pointer, not dereference it directly.

---

## 6. The new helper: `bpf_probe_read_user_str`

Every prior day read *kernel* memory (`BPF_CORE_READ`, direct field access in
fentry). Day 5's pointer — `ret` — points into **user-space** memory (bash's
own heap, where the string it read lives). Kernel memory and user memory are
different address spaces with different safety rules, so eBPF gives you a
different helper:

```
  bpf_probe_read_kernel_str()   →  Days 1–4's world: read from KERNEL memory
  bpf_probe_read_user_str()     →  Day 5: read from USER-SPACE memory
```

```c
bpf_probe_read_user_str(str, sizeof(str), ret);
```

This safely copies up to `sizeof(str)` bytes from the user-space address `ret`
into the on-stack buffer `str`, stopping at a NUL terminator, and — crucially
— handles the case where that user memory might be unmapped or invalid without
crashing anything. Never dereference a user-space pointer directly (`*ret`) in
a BPF program; the verifier won't allow it, and even if it did, a bad address
would be unsafe. This helper is the sanctioned, checked path across the
kernel/user boundary — the direct analogue of `BPF_CORE_READ` for the
kernel/kernel-struct boundary you used on Day 2.

---

## 7. Guarding against `NULL`

```c
if (!ret)
    return 0;
```

`readline` returns `NULL` when there's no line to read — e.g., the user hits
Ctrl-D (EOF) to exit the shell, or the terminal is closed. Since `ret` becomes
our source pointer for `bpf_probe_read_user_str`, we bail out immediately
rather than trying to read from address `0`. Cheap, essential guard — same
"validate before you use it" instinct as bounds-checking anywhere else in BPF.

---

## 8. Reused from earlier days (nothing new)

- **`bpf_get_current_pid_tgid() >> 32`** — identical PID idiom, Days 2–4.
- **`bpf_get_current_comm()`** — new function name, but same idea as reading
  process identity; gets the `comm` (process name, e.g. `"bash"`) into a fixed
  buffer.
- **`bpf_printk`** — same shared kernel trace buffer, max 3 args, still read at
  `/sys/kernel/debug/tracing/trace_pipe`.
- **The GPL license line** — still mandatory:
  ```c
  char LICENSE[] SEC("license") = "GPL";
  ```
- **`vmlinux.h`** — included by convention for consistency with other days,
  though this particular program doesn't touch any kernel struct — everything
  it reads is on the user-space side.

---

## 9. Requirements & troubleshooting

1. **Find bash's real path first**, inside your actual WSL shell:
   `which bash` (often `/usr/bin/bash`, sometimes symlinked from `/bin/bash` —
   on Debian/Ubuntu they're usually the same file). Whatever path you get,
   that's what goes after the first `/` in the `SEC()` string.
2. **No output?** You must trigger a *new* bash read: open **another terminal
   window** running bash and type a command there and press Enter — typing in
   the same shell you loaded the probe from won't necessarily show anything
   useful if that shell's own line-reading is entangled with your commands.
3. **Verify it attached:** `sudo bpftool prog show | grep -i readline` (or
   `link show` — a uprobe attach shows up as a BPF **link**, same as the other
   auto-attached programs this repo has used).
4. **Permissions:** uprobes need the binary path to be readable by the
   attaching process (root, via `sudo`, is fine).
5. **Symbol not found errors** usually mean the path is wrong (not literally
   `/bin/bash` on your system) or the binary was stripped of that symbol —
   unlikely for a stock `bash`, but worth checking with
   `nm -D $(which bash) | grep readline` if attach fails.

---

## 10. Kprobe vs uprobe — the one-table summary

```
                       kprobe (Day 2)          uprobe (Day 5)
 ────────────────────  ────────────────────    ────────────────────────
 address space         kernel                  user space (one binary)
 target                kernel symbol           binary path + symbol/offset
 patched instruction    in kernel .text         in the FILE's mapping on disk
 scope                  whole kernel            every process running that file
 read helper            bpf_probe_read_kernel*  bpf_probe_read_user*
 SEC() prefix           kprobe/ , kretprobe/    uprobe/ , uretprobe/
 entry vs return        both available          both available (we use return)
 today's new idea       —                       crossing into user-space memory
```

The through-line: eBPF's entry/return probe pattern (Day 2) and its
"read memory safely across a boundary" pattern (Day 2's `BPF_CORE_READ`) both
carry over unchanged — Day 5 just moves the *boundary* from
kernel-struct-vs-BPF-stack to user-process-vs-kernel.

---

## The whole Day 5 pipeline in one line

```
bashreadline.bpf.c --clang--> .bpf.o
  --verifier--> (JIT) --attach--> uretprobe on /bin/bash's readline (return)
  every bash readline() return: if ret == NULL, drop
                                 else read the string from USER memory
                                 → bpf_printk("PID N (bash) read: <line>")
  --> /sys/kernel/debug/tracing/trace_pipe
```

Same compile→verify→attach→observe shape as every day so far. What's new is
the *address space* being probed — the first time this repo instruments code
that isn't the kernel at all.
