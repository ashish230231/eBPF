# eBPF Sensor Foundations

This folder is independent of the day-by-day lessons (`01-hello`, `02-kprobe-unlink`,
...). Those are hands-on exercises; **this is the prerequisite knowledge map** —
everything worth understanding, from true basics to production-grade, to read,
write, and reason about a real eBPF security sensor (the kind of tool Falco,
Tetragon, and Cilium are built from).

Read the files in order. Each one assumes only what came before it.

| # | File | What it covers |
|---|------|-----------------|
| 00 | [`00-glossary.md`](./00-glossary.md) | Every abbreviation you'll hit (PID, TID, TGID, BTF, CO-RE, ELF, JIT, ...) — keep this open as a reference while reading the rest. |
| 01 | [`01-os-fundamentals.md`](./01-os-fundamentals.md) | What a process/thread actually is, memory, kernel vs. user space, syscalls, file descriptors, signals — the OS vocabulary every sensor hooks into. |
| 02 | [`02-c-and-toolchain-fundamentals.md`](./02-c-and-toolchain-fundamentals.md) | The C you need (pointers, structs, macros), how source becomes a running program, what ELF is, what `clang -target bpf` actually produces. |
| 03 | [`03-ebpf-execution-model.md`](./03-ebpf-execution-model.md) | What eBPF actually is, why it's safe, the verifier, the JIT, program types, bytecode, helper functions. |
| 04 | [`04-btf-and-core.md`](./04-btf-and-core.md) | BTF, CO-RE, `vmlinux.h` — how one compiled program runs correctly across many different kernel versions. |
| 05 | [`05-hook-points-catalog.md`](./05-hook-points-catalog.md) | Every place you can attach a BPF program: kprobes, tracepoints, fentry/fexit, uprobes, LSM, XDP, TC, cgroup hooks — what each is for and when real sensors use it. |
| 06 | [`06-maps-and-state.md`](./06-maps-and-state.md) | Every BPF map type, and the helpers (`bpf_probe_read_*`, `BPF_CORE_READ`) used to move data safely across memory boundaries. |
| 07 | [`07-streaming-to-userspace.md`](./07-streaming-to-userspace.md) | Ring buffer vs. perf buffer, libbpf skeletons, the open→load→attach→poll lifecycle a real C/C++ loader goes through. |
| 08 | [`08-production-sensor-patterns.md`](./08-production-sensor-patterns.md) | How real sensors are actually built: in-kernel filtering, portability across kernels, performance, event loss, security model. |

Once you've read 00–08, the day-by-day lessons in the rest of this repo are
worked examples of exactly this material — `02-kprobe-unlink` is file 05's
kprobe section made concrete, `06-sigsnoop` is file 06's hash-map section made
concrete, and so on.
