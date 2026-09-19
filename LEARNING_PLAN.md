# eBPF Sensor Mastery — 3-Month Learning Plan

**Goal:** Go from zero to being able to read, understand, extend, and debug a production-grade eBPF security sensor (like the one at your company), writing everything in **C / C++**.

**Time budget:** ~2 hours/day, ~5 days/week (2 flex/catch-up days). ~12 weeks.

**Your environment (already verified):**
- WSL2 Ubuntu 24.04, kernel `6.6.87` (modern, full eBPF + CO-RE support)
- clang/LLVM 18.1.3, gcc 13.3, make 4.3
- libbpf 1.3.0 + headers installed
- Kernel BTF exposed at `/sys/kernel/btf/vmlinux` (CO-RE ready)
- ⚠️ One fix needed: working `bpftool` — see Week 1, Day 1.

---

## How to use this plan

- Each week has a **theme**, **daily 2h blocks**, a **deliverable** (code you write), and **checkpoints** (can you answer these without notes?).
- Every lesson is **hands-on**: you write kernel-side eBPF (`.bpf.c`) + a user-space loader (C, later C++).
- "Read" tasks are ~30 min max; the rest is coding. eBPF is learned by loading programs and watching them fail the verifier.
- Reference sites: [ebpf.io](https://ebpf.io/) (concepts), [eunomia.dev tutorials](https://eunomia.dev/tutorials/) (progressive examples), libbpf-bootstrap examples.

---

## MONTH 1 — Foundations: how eBPF works and how to run it

### Week 1 — Environment, mental model, first program
**Theme:** What eBPF *is*, the kernel/user-space split, and getting a program to run.

- **Day 1 (2h): Fix tooling + concepts.**
  - Install a working bpftool: `sudo apt update && sudo apt install -y linux-tools-generic`, then confirm the standalone binary works (`/usr/lib/linux-tools/*/bpftool version`). Generate `vmlinux.h`.
  - Read: [ebpf.io "What is eBPF"](https://ebpf.io/what-is-ebpf/) — intro + "Hook Overview" only.
  - Checkpoint: explain in one sentence why eBPF runs in the kernel but is safe.
- **Day 2 (2h): The verifier & the execution model.**
  - Read: ebpf.io verifier + JIT sections.
  - Write notes on: program types, the verifier's job, why loops used to be banned.
- **Day 3 (2h): Hello World (kprobe + `bpf_printk`).**
  - Attach to a syscall, print to `/sys/kernel/debug/tracing/trace_pipe`.
  - Load with bpftool first (no C loader yet).
- **Day 4 (2h): Understand the toolchain.**
  - Trace what happens: `.bpf.c` → clang → BPF ELF object → verifier → attach.
  - Inspect your object with `bpftool prog`, `llvm-objdump`.
- **Day 5 (2h): Consolidate.**
  - Rewrite Hello World from memory. Break it on purpose and read verifier errors.
- **Deliverable:** `01-hello/` runs and prints on syscall.
- **Checkpoints:** What are the 4 stages from source to running program? What is `trace_pipe`?

### Week 2 — libbpf skeletons & the program lifecycle in C
**Theme:** Load programs the *real* way, with a C user-space loader.

- **Day 1:** libbpf concepts — objects, skeletons, `bpftool gen skeleton`.
- **Day 2:** Write a C loader that opens → loads → attaches your Hello World, using the generated skeleton.
- **Day 3:** Understand `SEC()` annotations, auto-attach, and the object lifecycle (`open/load/attach/destroy`).
- **Day 4:** Add graceful shutdown (signal handling), error handling, `libbpf_set_print`.
- **Day 5:** Write a Makefile that builds bpf object + skeleton + loader in one `make`.
- **Deliverable:** `02-loader/` — self-contained C program you run with `sudo ./loader`.
- **Checkpoints:** What does a skeleton give you over raw libbpf calls? What is the object lifecycle?

### Week 3 — Maps: sharing data between kernel and user space
**Theme:** Maps are how a sensor moves data. This is core.

- **Day 1:** Read on map types (hash, array, per-CPU, LRU). Focus: hash + array.
- **Day 2:** Hash map that counts syscalls per PID in the kernel.
- **Day 3:** Read the map from user space in a loop; pretty-print counts.
- **Day 4:** Per-CPU maps and why they matter for performance (no locking).
- **Day 5:** Explore maps live with `bpftool map dump`.
- **Deliverable:** `03-maps/` — live per-PID syscall counter.
- **Checkpoints:** Why per-CPU maps? How does user space read a kernel map?

### Week 4 — Ring buffer: streaming events (how sensors actually emit data)
**Theme:** Real sensors stream structured events. This is the pattern you'll use forever.

- **Day 1:** Read on BPF ring buffer vs perf buffer; why ringbuf won.
- **Day 2:** Define a shared event struct; reserve/submit events in the kernel.
- **Day 3:** Consume events in user space with a callback; print structured output.
- **Day 4:** Add fields (pid, comm, timestamp); handle event loss.
- **Day 5:** Benchmark rough throughput; reflect on backpressure.
- **Deliverable:** `04-ringbuf/` — event stream from kernel to a C consumer.
- **Checkpoints:** Ringbuf vs perf buffer tradeoffs? What is `bpf_ringbuf_reserve/submit`?

---

## MONTH 2 — Observability building blocks a sensor uses

### Week 5 — Tracepoints, kprobes, fentry: choosing attach points
**Theme:** Where you hook determines stability and what you can see.

- **Day 1:** Read: tracepoints vs kprobes vs fentry/fexit. Stability tradeoffs.
- **Day 2:** Attach to the `sched_process_exec` tracepoint.
- **Day 3:** Convert a kprobe example to fentry; compare.
- **Day 4:** Read arguments safely; understand `BPF_CORE_READ`.
- **Day 5:** Map out which hooks a security sensor cares about (exec, open, connect, etc.).
- **Deliverable:** `05-tracepoints/` — exec tracer.
- **Checkpoints:** When to prefer a tracepoint over a kprobe? Why is fentry faster?

### Week 6 — CO-RE deep dive (Compile Once, Run Everywhere)
**Theme:** How real sensors ship one binary that runs across kernels.

- **Day 1:** Read: BTF, CO-RE relocations, why `vmlinux.h`.
- **Day 2:** Read nested `task_struct` fields with `BPF_CORE_READ`.
- **Day 3:** Handle optional/renamed fields with `bpf_core_field_exists`.
- **Day 4:** Understand how libbpf relocates at load time.
- **Day 5:** Inspect BTF with bpftool; read relocations in your object.
- **Deliverable:** `06-core/` — process-info reader robust across field layouts.
- **Checkpoints:** What problem does CO-RE solve? What is a relocation?

### Week 7 — Reading process, file, and network context
**Theme:** The data a sensor extracts to make decisions.

- **Day 1:** Process ancestry: walk parent pointers via `task_struct`.
- **Day 2:** File events: hook `openat`, capture filename + flags.
- **Day 3:** Extract UID/GID, cgroup id, namespace info.
- **Day 4:** Network basics: hook `tcp_connect`, read addr/port.
- **Day 5:** Combine into a richer event struct.
- **Deliverable:** `07-context/` — enriched process/file/net events.
- **Checkpoints:** How do you get a parent PID in-kernel? Where do you read a filename safely?

### Week 8 — Correctness, safety, and the verifier in depth
**Theme:** Why your program gets rejected, and how sensors stay within limits.

- **Day 1:** Read: verifier internals — bounded loops, helper restrictions.
- **Day 2:** Deliberately trigger and fix 5 classic verifier errors.
- **Day 3:** Bounds checks, `bpf_probe_read_kernel`, string handling.
- **Day 4:** Stack size limits, map-of-maps, tail calls (concept + small demo).
- **Day 5:** Review: refactor an earlier lesson to be verifier-clean and efficient.
- **Deliverable:** `08-verifier/` — notes + fixed examples.
- **Checkpoints:** Name 4 things the verifier enforces. Why bounded loops?

---

## MONTH 3 — Build a real sensor & study production patterns

### Week 9 — Mini security sensor v1 (C++)
**Theme:** Combine everything: ringbuf + tracepoints + CO-RE into a real tool.

- **Day 1:** Design: event schema, which hooks, output format.
- **Day 2:** Kernel side: exec + exit + open events into one ringbuf.
- **Day 3:** C++ user space: event loop, typed event handling, clean shutdown.
- **Day 4:** Add process tree tracking in user space (pid → parent map).
- **Day 5:** Polish output (JSON lines), test under load.
- **Deliverable:** `09-sensor-v1/` — working exec/file monitor in C++.

### Week 10 — Sensor v2: filtering, config, and performance
**Theme:** Make it production-shaped.

- **Day 1:** In-kernel filtering (by uid, comm, path prefix) to cut noise.
- **Day 2:** Config maps: user space pushes filter rules into a map.
- **Day 3:** Reduce overhead: per-CPU, minimize copies, batch.
- **Day 4:** Handle event loss + counters for dropped events.
- **Day 5:** Measure CPU overhead; document tradeoffs.
- **Deliverable:** `10-sensor-v2/` — configurable, filtered sensor.

### Week 11 — Study real production sensors
**Theme:** Read the code the pros write; map it to your company's sensor.

- **Day 1:** Tour [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) examples.
- **Day 2:** Study Tetragon or Falco architecture (docs + a couple of BPF sources).
- **Day 3:** Study how they structure event schemas and user-space processing.
- **Day 4:** Map their patterns to your company's sensor: attach points, maps, event flow.
- **Day 5:** Write a one-page "how our sensor probably works" hypothesis to validate at work.
- **Deliverable:** `11-study/` — annotated notes mapping OSS patterns to your sensor.

### Week 12 — Capstone + hardening
**Theme:** Finish strong, fill gaps.

- **Day 1:** Pick one missing capability (e.g., network flow tracking) and add it.
- **Day 2:** Add proper build (CMake), logging, and a README to your sensor.
- **Day 3:** Test on edge cases; handle failures gracefully.
- **Day 4:** Write up what you learned + a glossary.
- **Day 5:** Review the whole repo; list 5 topics for continued study (LSM BPF, XDP, uprobes, BTF-enabled tracing, CI for BPF).
- **Deliverable:** `12-capstone/` — your own documented eBPF sensor.

---

## Milestones (how you know you're on track)
- **End of Month 1:** You can load a libbpf program in C, use maps, and stream events via ring buffer.
- **End of Month 2:** You can attach to tracepoints/fentry, read kernel structs with CO-RE, and satisfy the verifier confidently.
- **End of Month 3:** You have your own working C++ eBPF sensor and can read/reason about production sensor code.

## Guardrails / tips
- Loading eBPF needs root. Expect to type your sudo password often (that's normal).
- When the verifier rejects a program, read the *full* log — it's verbose but precise.
- Commit each lesson to git so you can diff and revert.
- If a lesson takes 2 days, that's fine — depth beats speed.

## Repo layout (built as you progress)
```
eBPF ashish/
├── LEARNING_PLAN.md        # this file
├── common/
│   └── vmlinux.h           # generated from your kernel BTF (Week 1)
├── 01-hello/
├── 02-loader/
├── 03-maps/
├── 04-ringbuf/
├── 05-tracepoints/
├── 06-core/
├── 07-context/
├── 08-verifier/
├── 09-sensor-v1/
├── 10-sensor-v2/
├── 11-study/
└── 12-capstone/
```
