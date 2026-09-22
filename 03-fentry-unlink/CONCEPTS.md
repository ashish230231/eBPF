# eBPF Day 3 — fentry / fexit: The Modern Way to Trace Kernel Functions

Read this top to bottom. It builds directly on Day 2. By the end, every word in
`fentry-link.bpf.c` should mean something to you — especially *why you can now
write `name->name` directly*, which is the exact thing Day 2 told you was banned.

Day 2 monitored file deletion with a **kprobe** (entry) + **kretprobe** (return)
on `do_unlinkat`. It worked, but it came with two frictions:

1. You couldn't dereference kernel pointers directly — every field read had to go
   through `BPF_CORE_READ`.
2. kprobes are relatively slow, and the entry and return probes were two totally
   separate programs that couldn't share the arguments.

Day 3 solves both by switching to **fentry / fexit** — the same task, the same
target function, but a newer mechanism. Two new powers:

1. **Direct argument access** — read `name->name` like normal C, no helper macro.
2. **fexit sees arguments AND the return value together** — the "what" and the
   "result" in a single probe, which a kretprobe can't do.

The concrete goal is unchanged from Day 2: when someone runs `rm test_file`, see
*which* file and *whether* the delete succeeded — just done the modern way.

---

## 1. What are fentry and fexit?

- **fentry** = *function entry.* Fires the instant a kernel function is entered.
- **fexit**  = *function exit.*  Fires the instant it returns.

They are the modern successors to kprobe/kretprobe for tracing the entry and exit
of kernel functions. Introduced in **kernel 5.5 for x86** and **6.0 for ARM**.
Your kernel is **6.6**, so you're comfortably covered.

Conceptually they map one-to-one onto what you already know:

```
   Day 2 (older)          Day 3 (modern)
   ─────────────          ──────────────
   kprobe      ─────────► fentry     (entry: read the arguments)
   kretprobe   ─────────► fexit      (return: read the result)
```

Same idea — hook entry and exit — but a faster, cleaner implementation underneath.

---

## 2. The three big wins over kprobes

### Win 1 — Direct, natural access to arguments

With a kprobe you got a `struct pt_regs *` (raw CPU registers) and had to read
kernel memory through helpers. With fentry you get the **real, typed arguments**,
and you can dereference their fields directly:

```c
// Day 2 (kprobe): MUST go through a helper
filename = BPF_CORE_READ(name, name);      // safe read + CO-RE relocation

// Day 3 (fentry): just write it
bpf_printk("... %s", name->name);          // direct, allowed, and safe
```

Why is the direct read suddenly legal? See section 4 — it comes down to the BPF
trampoline and BTF giving the verifier full type information.

### Win 2 — fexit gives you inputs AND the return value at once

A **kretprobe** only ever hands you the return value. If you wanted the filename
*and* the outcome, you had to stash the argument on entry and correlate it on
return. **fexit** gives you both in the same call:

```c
SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    // name (input) AND ret (result) — both available right here.
    bpf_printk("fexit: filename = %s, ret = %ld\n", name->name, ret);
}
```

That's why Day 3's fexit line can print the filename *and* the return code
together — Day 2's kretprobe line could only print the return code.

### Win 3 — Performance (~10x faster)

fentry/fexit run roughly **10x faster** than kprobes. kprobes rely on a
breakpoint/trap mechanism (an exception diverts the CPU into your handler). 
fentry/fexit instead use a **BPF trampoline** — a small chunk of generated
machine code that jumps straight into your program with the arguments already
laid out. No trap, no single-step, far less overhead.

For a learning demo the speed doesn't matter. For a production sensor that fires
on high-frequency functions, it matters a lot.

---

## 3. Why hook `do_unlinkat` again (same as Day 2)

Nothing changed about the *target*. A program deleting a file calls the
`unlink`/`unlinkat` syscall, which funnels into the internal kernel worker:

```c
int do_unlinkat(int dfd, struct filename *name);
```

- `dfd`  — a directory file descriptor (the "at" part, for relative paths).
- `name` — pointer to a kernel `struct filename` holding the path to delete.

We hook `do_unlinkat` because that's where the arguments live in a clean, stable
form. What changed on Day 3 is only *how* we attach (fentry/fexit) and *how* we
read the fields (directly). Confirm the symbol exists on your kernel with
`sudo grep ' do_unlinkat' /proc/kallsyms`.

---

## 4. The magic: BPF trampoline + BTF (why direct reads are legal now)

This is the heart of Day 3. Two pieces work together.

### The BPF trampoline

When you attach an fentry/fexit program, the kernel generates a tiny piece of
machine code — a **trampoline** — that sits at the traced function's boundary. On
entry (or exit) it:

1. captures the function's arguments (and, for fexit, the return value),
2. lays them out in the exact shape your `BPF_PROG` handler expects,
3. calls your program directly.

No breakpoint, no exception, no single-stepping. That direct hand-off is where
the ~10x speedup comes from.

### BTF (BPF Type Format)

**BTF** is compact type information about the kernel — the layout of every struct,
the types of every function's arguments, etc. It's the same technology behind
`vmlinux.h` and CO-RE from Days 1–2. fentry/fexit **require** BTF, because the
trampoline needs to know the precise types and layout of the traced function's
arguments to hand them to you correctly.

### Putting it together — why `name->name` is now allowed

Because the trampoline provides genuine, **BTF-typed** pointers, the verifier
knows exactly what `name` points to and how `struct filename` is laid out. It can
therefore *prove* a read of `name->name` is safe and let you dereference it
directly. On Day 2 the kprobe gave you only raw registers with no such type
guarantee, so the verifier forced every read through `bpf_probe_read_kernel`
(which is what `BPF_CORE_READ` expands to).

> One-liner: **kprobe = raw registers, prove-nothing, use helpers.
> fentry = typed arguments via a trampoline, verifier trusts direct field reads.**

You still can't do anything reckless — the verifier is still in charge — but for
BTF-typed argument pointers, direct dereference is now on the table.

---

## 5. The `BPF_PROG` macro

Day 2 used `BPF_KPROBE` / `BPF_KRETPROBE`. Day 3 uses a single macro for both
fentry and fexit: **`BPF_PROG`** (from `<bpf/bpf_tracing.h>`).

Like its Day-2 cousins, it hides the messy plumbing and unpacks the traced
function's arguments into normal, correctly-typed parameters, so you write the
handler to match the real kernel signature:

```c
// entry: parameters mirror do_unlinkat(int dfd, struct filename *name)
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name) { ... }

// exit: same arguments, PLUS the return value appended at the end
SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret) { ... }
```

Two things to notice:

- **The return value is just an extra trailing parameter** (`long ret`) on the
  fexit handler. That's the whole mechanism for "inputs + result together."
- **The two handlers have different function names** (`do_unlinkat` vs
  `do_unlinkat_exit`) even though they trace the same kernel function — they're
  two separate eBPF programs in two separate ELF sections, exactly like Day 2.

---

## 6. `SEC()` for fentry/fexit

Same `SEC()` mechanism as before, new section prefixes that tell the loader to
build a trampoline instead of a kprobe:

- `SEC("fentry/do_unlinkat")` → attach at **entry** of `do_unlinkat`.
- `SEC("fexit/do_unlinkat")`  → attach at **return** of `do_unlinkat`.

Compare the progression:

```
 Day 1:  SEC("kprobe/__x64_sys_execve")
 Day 2:  SEC("kprobe/do_unlinkat")   +   SEC("kretprobe/do_unlinkat")
 Day 3:  SEC("fentry/do_unlinkat")   +   SEC("fexit/do_unlinkat")
```

---

## 7. Reused from earlier days (nothing new)

- **`bpf_get_current_pid_tgid() >> 32`** — same PID idiom as Day 2. The helper
  returns TGID in the top 32 bits (the "PID") and the thread ID in the bottom 32;
  the shift keeps the top half.
- **`bpf_printk`** — same shared kernel trace buffer, still max 3 args, still read
  at `/sys/kernel/debug/tracing/trace_pipe`. Each deletion produces two lines: one
  from fentry (entry) and one from fexit (exit).
- **The GPL license line** — still mandatory, because `bpf_printk` is GPL-only.

---

## 8. Requirements & troubleshooting

fentry/fexit have real prerequisites. If the program fails to **attach** (a
classic symptom is `failed to attach: ... -524`, where `-524 = ENOTSUPP`), work
through these:

1. **Kernel version.** Need 5.5+ on x86, 6.0+ on ARM. Check with `uname -r`.
   (Yours is 6.6 — fine.)
2. **BTF enabled.** fentry needs it. Check:
   `cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF` → want `=y`.
   (Or simply confirm `/sys/kernel/btf/vmlinux` exists — it does on your box.)
3. **The function is traceable.** Confirm it shows up:
   `sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep unlink`.
   If `do_unlinkat` isn't listed, it may be inlined or renamed on your kernel.
4. **General eBPF config.** `cat /boot/config-$(uname -r) | grep BPF` and look for
   `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`,
   `CONFIG_DEBUG_INFO_BTF=y`.

If your kernel is simply too old and can't be upgraded, fall back to the Day 2
kprobe approach — it doesn't need BTF or a trampoline.

---

## 8.5. The `load` vs `loadall` gotcha (learned the hard way)

This one bit me while running Day 3, and it's worth remembering because the
failure is **silent** — no error, no crash, just missing output.

This object contains **two** BPF programs (fentry + fexit). When you load it with:

```bash
sudo bpftool prog load fentry-link.bpf.o /sys/fs/bpf/fentry autoattach
```

`bpftool prog load` only reliably attaches the **first** program in the object.
The fentry probe attached and fired happily; the fexit probe was quietly skipped.
The load command still succeeded (exit 0, no warning), so the only symptom was
that `fexit:` lines never showed up in `trace_pipe`.

The way to catch it: after loading, count how many programs actually attached.

```bash
sudo bpftool prog show | grep -i unlink
```

If you see only **one** entry (`do_unlinkat`) instead of two, the second program
didn't attach.

**The fix is `loadall` instead of `load`:**

```bash
sudo bpftool prog loadall fentry-link.bpf.o /sys/fs/bpf/unlink autoattach
```

`loadall` is designed for objects with multiple programs — it loads and attaches
**every** program in the object, not just the first. After switching to it,
`prog show` listed both:

```
188: tracing  name do_unlinkat        (fentry)
190: tracing  name do_unlinkat_exit   (fexit)
```

...and the paired `fentry:` / `fexit:` lines finally appeared together.

Note that `loadall` pins to a **directory** (here `/sys/fs/bpf/unlink`) holding
one pin per program, so unload with a recursive remove:

```bash
sudo rm -rf /sys/fs/bpf/unlink
```

Takeaway: **whenever an object has more than one program, reach for `loadall`,
and always verify the attach count with `prog show` rather than trusting that a
successful load means everything attached.**

---

## 9. kprobe vs fentry — the one-table summary

```
                         kprobe / kretprobe (Day 2)   fentry / fexit (Day 3)
 ─────────────────────   ──────────────────────────   ──────────────────────
 mechanism               breakpoint / trap            BPF trampoline
 speed                   baseline                     ~10x faster
 argument access         raw pt_regs + helpers        real typed arguments
 read a struct field     BPF_CORE_READ (required)     direct: name->name
 return + args together  no (kretprobe = ret only)    yes (fexit)
 needs BTF               no                            yes
 min kernel              old / broadly available      5.5 x86 / 6.0 arm
 stability of target     internal name may change     same caveat (still do_*)
 macro                   BPF_KPROBE / BPF_KRETPROBE    BPF_PROG (both)
 SEC() prefix            kprobe/ , kretprobe/          fentry/ , fexit/
```

Note the last row of caveats: fentry is faster and cleaner, but you're **still**
hooking an internal function name (`do_unlinkat`) that could change between kernel
versions. Tracepoints (Week 5) are the tool that removes *that* fragility.

---

## The whole Day 3 pipeline in one line

```
fentry-link.bpf.c --clang--> .bpf.o --verifier--> (JIT) --attach via TRAMPOLINE-->
  fentry(do_unlinkat entry)  reads name->name directly   --bpf_printk--> trace_pipe
  fexit (do_unlinkat return) reads name->name AND ret     --bpf_printk--> trace_pipe
```

Same shape as Day 2, but the reads are direct and the exit probe sees everything
at once. Once these terms feel comfortable, the code is short — and every line has
a reason to exist.
