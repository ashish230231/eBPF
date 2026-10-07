# 08 — Production Sensor Patterns

Files 01–07 give you all the pieces. This file is about how they fit together
in a real, production-grade eBPF security sensor — and the hard problems that
separate a demo from something you'd run on 10,000 customer nodes.

---

## 1. Anatomy of a production sensor

```
 ┌───────────────────────────── each node ─────────────────────────────┐
 │                                                                        │
 │  KERNEL                                                                │
 │  ┌──────────────────────────────────────────────────────────────┐    │
 │  │ hooks: sched_process_exec/fork/exit, syscall tps, LSM, kprobes,│    │
 │  │        TC/cgroup, uprobes on libssl                            │    │
 │  │ in-kernel: context capture → filter → (enforce) → emit         │    │
 │  │ maps: config/policy, process cache, in-flight, drop counters   │    │
 │  └───────────────────────────┬──────────────────────────────────┘    │
 │                              │ ring buffer(s)                          │
 │  USER SPACE AGENT            ▼                                         │
 │  ┌──────────────────────────────────────────────────────────────┐    │
 │  │ loader (CO-RE, feature probing, fallbacks)                     │    │
 │  │ event decoder → process tree / state engine                    │    │
 │  │ enrichment: container runtime, k8s pod/namespace/labels        │    │
 │  │ rule engine / detections (+ policy pushed back into maps)      │    │
 │  │ exporter: JSON / gRPC / OTel / Kafka → backend / SIEM          │    │
 │  │ health: drops, CPU, memory, self-protection                    │    │
 │  └──────────────────────────────────────────────────────────────┘    │
 └──────────────────────────────────────────────────────────────────────┘
   deployed as a privileged DaemonSet (k8s) or systemd service
```

---

## 2. What a security sensor typically watches

| Category | Events | Detects |
|---|---|---|
| Process | exec (with argv, env, binary hash), fork, exit, setuid/setgid, capset | reverse shells, crypto miners, privilege escalation, `curl \| sh` |
| File | open/write on sensitive paths, unlink, rename, chmod, mount | tampering with `/etc/passwd`, `/etc/shadow`, SSH keys, log wiping |
| Network | connect, accept, bind, listen, DNS | C2 callbacks, lateral movement, unexpected listeners |
| Kernel integrity | module load, BPF load, ptrace, `/dev/mem`, kexec | rootkits, malicious BPF, process injection |
| Containers | namespace changes (`setns`, `unshare`), mounts of host paths, privileged ops | container escapes |
| Memory | `mprotect`/`mmap` with PROT_EXEC on anonymous memory, memfd_create + exec | fileless malware, shellcode |
| Application | TLS plaintext, HTTP, SQL (uprobes) | API abuse, data exfiltration |

---

## 3. In-kernel filtering — the most important performance idea

Emitting every syscall to user space costs CPU in the kernel *and* user
space. On a busy node that's millions of events/sec. Filter **as early as
possible, inside BPF**:

```c
// 1. static config (verifier eliminates dead code)
const volatile bool trace_file_events = true;
if (!trace_file_events) return 0;

// 2. cheap identity filters
if (tgid == agent_pid) return 0;                // never trace yourself!
u64 cg = bpf_get_current_cgroup_id();
if (bpf_map_lookup_elem(&ignored_cgroups, &cg)) return 0;

// 3. policy maps pushed from user space
if (!bpf_map_lookup_elem(&watched_comms, comm)) return 0;

// 4. prefix matching on paths
struct lpm_key k = { .prefixlen = len * 8 };   // LPM_TRIE on path bytes
if (!bpf_map_lookup_elem(&watched_paths, &k)) return 0;
```

Also: **aggregate in-kernel** when you only need counts (per-CPU counters)
rather than streaming each event.

**Always exclude the sensor's own activity** — otherwise its reads of
`/proc`, its network sends, etc., generate events, which generate more work: a
feedback loop.

---

## 4. Process tracking and enrichment

Raw events say "PID 4821 connected to 1.2.3.4". Useful alerts say "`nginx` in
pod `web-7f9c` (namespace `prod`) spawned `bash`, which ran `curl`, which
connected to 1.2.3.4".

Getting there:

1. **Snapshot at startup**: eBPF only sees events after attach. Read `/proc`
   (or use `iter/task`) to learn every existing process.
2. **Track lifecycle**: fork → add child with parent link; exec → update
   binary/args; exit → mark dead (delay removal so late events still resolve).
3. **Unique process key**: `(tgid, start_time)` — PIDs get reused.
4. **Container mapping**: cgroup ID → container ID (parse cgroup path) →
   runtime metadata (containerd/CRI-O/Docker socket) → k8s pod via the API
   server or kubelet.
5. **Cache in-kernel too**: a `HASH`/`TASK_STORAGE` of process info lets BPF
   attach parent/container context to events without user-space lookups.

---

## 5. Portability across kernels

Customers run everything: Ubuntu 18.04 (4.15) to latest, RHEL with backports,
Amazon Linux, Bottlerocket, GKE COS, ARM64.

Techniques:
- **CO-RE** for struct layouts (file 04); **BTFHub / embedded min BTF** when
  the kernel lacks BTF.
- **Feature probing at startup**: `libbpf_probe_bpf_prog_type`,
  `libbpf_probe_bpf_helper`, `libbpf_probe_bpf_map_type`, check
  `/sys/kernel/security/lsm`, check tracepoint existence.
- **Multiple program variants** for the same event; enable the best supported
  one with `bpf_program__set_autoload()` before load:
  ```
  fentry/X   → if BTF + 5.5+
  kprobe/X   → fallback
  ringbuf    → if 5.8+, else perf buffer
  LSM        → if "bpf" in active LSMs, else kprobe on security_* + send_signal
  ```
- **Several candidate function names** for kprobes (renames, `.isra.0`/`.cold`
  compiler-suffixed clones).
- **Multi-arch**: build for x86_64 and arm64 (`__TARGET_ARCH_arm64`); syscall
  tracepoint args are arch-neutral, `pt_regs` access is not.
- **CI matrix**: run the verifier on many kernels (e.g. using `vmtest`/
  `virtme-ng` VMs) — a program that passes on 6.6 may be rejected on 5.10.

---

## 6. Performance budget

A sensor is a guest on production machines. Typical targets: low single-digit
% CPU, bounded memory, no measurable latency for apps.

Levers:
- Hook choice: tracepoint/raw_tp/fentry ≫ kprobe ≫ uprobe in cost.
- Fewer, smarter hooks: one `raw_tp/sys_enter` + tail-call dispatch vs. 300
  separate tracepoints (Falco's approach).
- Filter early (§3); per-CPU maps for counters; avoid locks.
- Avoid reading large strings unless needed (paths, argv are the expensive
  parts).
- Ring buffer wakeup batching.
- Measure: `bpftool prog show` (with `sysctl kernel.bpf_stats_enabled=1`) gives
  `run_time_ns` and `run_cnt` per program; `perf top` for overall overhead.

```bash
sudo sysctl -w kernel.bpf_stats_enabled=1
sudo bpftool prog show       # look at run_time_ns / run_cnt
```

---

## 7. Correctness and evasion — think like an attacker

A security sensor must assume the monitored workload is adversarial.

| Attack on the sensor | Defence |
|---|---|
| **Flooding** to cause ring buffer drops, hiding the real event | drop counters + alerts, priority buffers, in-kernel filtering, aggregation |
| **TOCTOU**: change user-memory args after the sensor read them at syscall entry | read resolved kernel objects at LSM/`sched_process_exec`/fexit, not user strings |
| **Symlinks / relative paths / `..`** to dodge path rules | resolve via `struct path` / `bpf_d_path` in LSM hooks |
| **Uncommon syscalls**: `execveat`, `io_uring`, `openat2`, `vmsplice`, `sendfile`, `process_vm_writev` | hook below the syscall layer (LSM/VFS), cover syscall variants, watch io_uring |
| **`comm` spoofing** (`prctl(PR_SET_NAME)` changes comm freely) | identify by executable inode/path/hash, not comm |
| **Killing/tampering with the sensor** | watch signals/ptrace targeting the agent, LSM self-protection, pinned programs survive agent crash |
| **Unloading BPF / loading malicious BPF** | hook `bpf()` syscall / `lsm/bpf`; alert on unknown BPF programs |
| **Kernel modules / rootkits** | hook module load; BPF can't defend against a fully compromised kernel |
| **Short-lived processes** exiting before user space enriches them | capture essential context (argv, parent, cgroup) in-kernel at exec time |
| **PID reuse** confusing attribution | `(tgid, start_time)` keys, `TASK_STORAGE` |

Also: **don't block the wrong thing** — enforcement bugs take down customer
production. Enforcement usually starts in "audit/observe" mode.

---

## 8. Detection logic: where does it live?

- **In-kernel**: only cheap, deterministic filters and enforcement decisions
  that must be synchronous (block exec of a known-bad hash).
- **User space on the node**: stateful rules ("shell spawned by a web server",
  "process read `/etc/shadow` then made a network connection"), using the
  process tree.
- **Backend**: cross-host correlation, ML/anomaly detection, long-term
  baselines.

Rule formats you'll see: Falco rules (YAML conditions over event fields),
Tetragon `TracingPolicy` CRDs (declare hooks + selectors + actions — compiled
into BPF map entries at runtime), Sigma-like detections in backends.

---

## 9. Security and operations of the sensor itself

- **Privileges**: needs `CAP_BPF`, `CAP_PERFMON`, often `CAP_SYS_ADMIN` (and
  host PID/network namespace, `/sys` and `/proc` mounts) — the sensor is a
  very high-value target; keep it minimal and hardened.
- **Kernel lockdown / Secure Boot** can restrict some BPF features
  (e.g. `bpf_probe_write_user`, kprobes in integrity mode).
- **Unprivileged BPF** is disabled on most distros
  (`kernel.unprivileged_bpf_disabled=1`) — expect to require root.
- **Upgrades**: replace programs atomically (`bpf_link__update_program`) or
  keep pinned maps across restarts so state isn't lost.
- **Observability of the observer**: export drop counts, per-program
  run time, map fill levels, verifier failures per kernel version.
- **Graceful degradation**: if a hook can't attach on this kernel, run without
  it and *report* reduced coverage — never crash.

---

## 10. Testing

- **Unit-ish**: `BPF_PROG_TEST_RUN` lets you run some program types (XDP, TC,
  raw_tp, syscall) with synthetic input from user space.
- **Integration**: spin up a VM per kernel version, load the sensor, run a
  script of behaviours (exec, open, connect, privesc attempt), assert the
  expected events arrive.
- **Attack simulation**: tools like Atomic Red Team to check detections fire.
- **Load tests**: stress-ng / fork bombs / high-rate network to check drops
  and CPU.

---

## 11. Reference implementations to study

Read these in roughly this order — each builds on concepts in 01–08:

1. **libbpf-bootstrap** (`examples/c/bootstrap.bpf.c`) — exec/exit tracing with
   ringbuf, the cleanest minimal template.
2. **bcc `libbpf-tools/`** — `execsnoop`, `opensnoop`, `tcpconnect`,
   `sigsnoop`: small, production-quality CO-RE tools.
3. **Tracee** (Aqua) — broad event coverage, many syscalls + LSM-function
   kprobes, good signature engine.
4. **Tetragon** (Cilium/Isovalent) — policy-driven hooks, in-kernel filtering,
   enforcement; Go user space.
5. **Falco** (CNCF) — `modern_bpf` driver: raw syscall tracepoints + tail calls;
   C++ user space; YAML rules.
6. **Cilium** — networking side: XDP, TC, sockops at scale.

When you read their BPF code, map every piece back to this folder: which hook
(05), which maps and why (06), how events leave (07), how they handle
portability and evasion (04, 08).

---

## 12. The complete mental model

```
   OS concepts (01) define WHAT is worth watching
        ↓
   C + ELF (02) is HOW you express and package the watcher
        ↓
   the BPF VM + verifier (03) is WHERE it runs, and the RULES it obeys
        ↓
   BTF / CO-RE (04) is how it survives DIFFERENT KERNELS
        ↓
   hook points (05) decide WHAT IT CAN SEE and WHETHER IT CAN BLOCK
        ↓
   maps + safe reads (06) are its MEMORY and its EYES
        ↓
   ring buffers + loader (07) are its VOICE to user space
        ↓
   production patterns (08) make it FAST, PORTABLE, and HARD TO EVADE
```

---

## Check yourself

- Why must a sensor exclude its own PID from tracing?
- How would you attribute an event to a Kubernetes pod?
- Give two ways an attacker could make a naive syscall-entry `openat` sensor
  log the wrong path.
- How does a sensor handle a kernel where fentry isn't available?
- What's the danger of a sensor whose ring buffer can be flooded?
- Where should a "web server spawned a shell" detection live — kernel, node
  agent, or backend? Why?
