# 05 — Hook Points Catalog

A sensor is defined by **where it hooks**. The hook decides what you can see,
how trustworthy it is, how fast it runs, and how likely it is to break on the
next kernel. This file catalogs every major hook type and when real sensors use
each.

---

## 1. The big picture

```
   USER SPACE
   ┌─────────────────────────────────────────────────────────────┐
   │  app code / shared libs          ◄── uprobe / uretprobe / USDT │
   └─────────────────────────┬───────────────────────────────────┘
                             │ syscall
   KERNEL ───────────────────▼──────────────────────────────────────
   ┌─────────────────────────────────────────────────────────────┐
   │ syscall entry/exit             ◄── tracepoint syscalls:*       │
   │                                ◄── raw_tp sys_enter/sys_exit    │
   │   ↓                                                              │
   │ kernel functions               ◄── kprobe/kretprobe, fentry/fexit│
   │   ↓                                                              │
   │ security checks                ◄── BPF LSM (can DENY)            │
   │   ↓                                                              │
   │ subsystem events (sched, ...)  ◄── tracepoints sched:* etc.     │
   │                                                                  │
   │ network stack                  ◄── TC ingress/egress, cgroup skb │
   │                                ◄── socket / sockops / sk_msg     │
   │ network driver                 ◄── XDP                            │
   └─────────────────────────────────────────────────────────────┘
   HARDWARE ─ perf counters        ◄── perf_event
```

---

## 2. Comparison table

| Hook | SEC() prefix | Stability | Overhead | Can block? | Typical sensor use |
|---|---|---|---|---|---|
| kprobe / kretprobe | `kprobe/`, `kretprobe/` | ✗ internal fn names | medium (int3/ftrace) | no* | anything with no better hook |
| fentry / fexit | `fentry/`, `fexit/` | ✗ internal fn names | low (trampoline) | `fmod_ret` only | same as kprobe, faster; needs BTF |
| tracepoint | `tracepoint/<cat>/<name>` | ✓ stable-ish ABI | low | no | syscalls, sched, process exec/exit |
| raw tracepoint | `raw_tp/<name>` | ✓ | lowest | no | high-volume syscall capture |
| BTF tracepoint | `tp_btf/<name>` | ✓ | lowest | no | typed raw tracepoint |
| uprobe / uretprobe | `uprobe/`, `uretprobe/` | depends on the app | **high** (trap to kernel) | no | TLS plaintext, shells, app-level events |
| USDT | `usdt/` | ✓ app-defined | high | no | language runtimes, DBs |
| BPF LSM | `lsm/<hook>` | ✓ LSM hook API | low | **yes** | enforcement: block exec, file, network, BPF load |
| XDP | `xdp` | ✓ | lowest | **yes** (drop packets) | DDoS, firewall, load balancing |
| TC | `tc` / `classifier` | ✓ | low | **yes** | network policy, flow monitoring, egress |
| cgroup hooks | `cgroup/...`, `cgroup_skb/...` | ✓ | low | **yes** | per-container network/socket policy |
| perf_event | `perf_event` | ✓ | configurable | no | CPU profiling, sampling |

\* `bpf_override_return` can change a kprobed function's return on a small
whitelist of functions; `bpf_send_signal` can kill the caller.

---

## 3. kprobes and kretprobes

**What:** dynamically attach to the entry (kprobe) or return (kretprobe) of
nearly any kernel function listed in `/proc/kallsyms`.

```c
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(handle, int dfd, struct filename *name) { ... }

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(handle_ret, long ret) { ... }
```

**How:** the kernel patches the function's first instruction (via ftrace or an
`int3` breakpoint) to divert into your program. `ctx` is `struct pt_regs *` —
raw CPU registers; `BPF_KPROBE` unpacks them by calling convention.

**Strengths:** reach anything. If there's no tracepoint for what you need, a
kprobe can probably get it.

**Weaknesses:**
- Function names are **internal**: renamed, split, or **inlined** (then it
  doesn't exist as a symbol at all) across versions.
- Arguments are raw `pt_regs`; struct reads need `BPF_CORE_READ`.
- Some functions are blacklisted (`/sys/kernel/debug/kprobes/blacklist`).
- kretprobes have a limited number of concurrent instances (`maxactive`) — on
  very hot functions you can **miss returns**.

```bash
sudo grep do_unlinkat /proc/kallsyms
sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep unlink
```

---

## 4. fentry / fexit (and fmod_ret)

**What:** the modern replacement for kprobes. Needs BTF (kernel 5.5+).

```c
SEC("fentry/do_unlinkat")
int BPF_PROG(handle, int dfd, struct filename *name)
{ bpf_printk("%s", name->name); }      // direct deref allowed: typed BTF pointer

SEC("fexit/do_unlinkat")
int BPF_PROG(handle_exit, int dfd, struct filename *name, long ret) { ... }
```

**How:** a **BPF trampoline** — a small generated piece of native code — is
called from the function's entry; it calls your program with typed args. No
breakpoint trap.

**Advantages over kprobe:**
- Faster (direct call vs. trap).
- Typed args; direct pointer dereference of BTF types.
- `fexit` gets **both args and return value** (kretprobe only gets the return).
- `fmod_ret` can override the return value of functions marked for error
  injection — a form of enforcement.

**Same weakness:** still tied to internal function names.

---

## 5. Tracepoints

**What:** static hooks kernel developers placed deliberately, with a
documented argument format.

```bash
sudo ls /sys/kernel/debug/tracing/events/          # categories
sudo ls /sys/kernel/debug/tracing/events/syscalls/ | head
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
```

```c
SEC("tracepoint/syscalls/sys_enter_openat")
int handle(struct trace_event_raw_sys_enter *ctx)
{
    const char *path = (const char *)ctx->args[1];   // openat(dfd, path, flags, mode)
}
```

The most important ones for security sensors:

| Tracepoint | Why |
|---|---|
| `sched/sched_process_exec` | A program was executed — fires *after* exec succeeded, with the final filename. **The** process-exec hook. |
| `sched/sched_process_fork` | New process/thread created — build the process tree. |
| `sched/sched_process_exit` | Process ended — clean up state. |
| `syscalls/sys_enter_*`, `sys_exit_*` | Every syscall, args + return value. |
| `raw_syscalls/sys_enter`, `sys_exit` | All syscalls through one hook (filter by ID). |
| `sock/inet_sock_set_state` | TCP state changes — connections opened/closed. |
| `signal/signal_generate` | Signals sent. |
| `module/module_load` | Kernel module loaded — rootkit indicator. |

**Raw tracepoints** (`raw_tp/sys_enter`) skip the argument-formatting step:
you get raw args. Faster; high-volume sensors (Falco's modern probe) use them.
**`tp_btf/`** adds BTF typing on top.

**Weakness:** only exist where kernel devs put them. And syscall-entry
tracepoints see **user-supplied** arguments (e.g., the path *string* as given),
which may not equal what the kernel ends up doing (symlinks, relative paths,
TOCTOU races where user memory changes after you read it).

---

## 6. uprobes, uretprobes, and USDT

**What:** hooks inside **user-space** binaries and libraries.

```c
SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(handle, const char *ret) { ... }

SEC("uprobe//usr/lib/x86_64-linux-gnu/libssl.so.3:SSL_write")
int BPF_KPROBE(ssl_write, void *ssl, const void *buf, int num) { ... }
```

**How:** the kernel places an `int3` at that offset **in the file's page
cache**, so every process mapping that file traps into the kernel there.

**Sensor uses:**
- **TLS plaintext**: `SSL_write`/`SSL_read` (OpenSSL), `gnutls_record_send`,
  Go's `crypto/tls` — see traffic before encryption / after decryption.
- **Shell commands**: bash `readline`.
- **Language/runtime events**: Java, Python, Node via USDT probes.
- **Database queries**: MySQL/Postgres USDT or function uprobes.

**Weaknesses:**
- **Expensive**: every hit is a user→kernel→user round trip (~1–3 µs). Fine for
  rare functions, painful for hot ones.
- Must know the exact binary/library path and symbol (or offset); breaks when
  the app updates, is stripped, or is statically linked.
- Containers have their own filesystems — the path is the one in *that*
  container's mount namespace (attach via `/proc/<pid>/root/...`).
- **uretprobes are unreliable for Go**, which moves stacks — Go sensors use
  uprobes on each `RET` instruction instead.

**USDT** (User Statically-Defined Tracing) are *stable* probe points compiled
into applications on purpose (`DTRACE_PROBE` macros). The user-space analogue of
tracepoints.

```bash
readelf -n /usr/lib/.../libpython3.so | grep -A2 stapsdt     # list USDT probes
```

---

## 7. BPF LSM — enforcement

**What:** the **Linux Security Module** framework puts security hooks at every
security-relevant decision point (≈250 hooks). SELinux and AppArmor are LSMs.
**BPF LSM** (kernel 5.7+) lets you attach BPF programs to those hooks — and
**return an error to deny the operation**.

```c
SEC("lsm/bprm_check_security")          // about to execute a program
int BPF_PROG(check_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0) return ret;            // respect earlier denials
    if (is_blocked(bprm->filename))
        return -EPERM;                   // BLOCK the exec
    return 0;                            // allow
}
```

Key hooks:

| LSM hook | Fires when |
|---|---|
| `bprm_check_security` | a program is about to be executed |
| `file_open` | a file is opened (after path resolution — the *real* file) |
| `inode_unlink`, `inode_rename` | file deleted / renamed |
| `socket_connect`, `socket_bind` | network connect / bind |
| `task_kill` | a signal is about to be delivered |
| `bpf`, `bpf_prog` | someone loads BPF — detect/ban rogue BPF |
| `kernel_module_request`, `kernel_read_file` | module loading |
| `ptrace_access_check` | debugger attach / process injection |
| `capable` | a capability check |

**Why sensors love LSM hooks:**
- **Stable** API (hook names change rarely).
- Fire **after** path resolution, with kernel objects (`struct file`, `struct
  linux_binprm`) — no TOCTOU on user strings.
- Can **prevent**, not just detect.

**Requirement:** BPF must be in the active LSM list:

```bash
cat /sys/kernel/security/lsm          # needs "bpf" in this list
# else boot param: lsm=...,bpf
```

---

## 8. Networking hooks

### XDP — eXpress Data Path
Runs in the network **driver**, on raw packet bytes, before the kernel even
allocates an `sk_buff`. Millions of packets/sec per core.

```c
SEC("xdp")
int xdp_drop_bad(struct xdp_md *ctx) {
    // parse ethernet → ip → tcp from ctx->data .. ctx->data_end
    return XDP_DROP;   // or XDP_PASS / XDP_TX / XDP_REDIRECT
}
```
Uses: DDoS mitigation, firewalls, load balancers (Cilium, Katran). Ingress only.

### TC — Traffic Control (`SCHED_CLS`)
Runs in the kernel network stack on `struct __sk_buff`, **ingress and egress**.
Has socket/cgroup metadata XDP doesn't.

```c
SEC("tc")
int tc_egress(struct __sk_buff *skb) { return TC_ACT_OK; }   // or TC_ACT_SHOT (drop)
```
Uses: network policy, flow logging, egress filtering per container.
Modern kernels use **tcx** attach (6.6+) instead of the legacy qdisc API.

### Cgroup hooks
Attach to a **cgroup** (≈ a container), affect only its processes:
- `cgroup_skb/ingress|egress` — allow/drop packets
- `cgroup/connect4|6`, `cgroup/bind4|6` — intercept/rewrite/deny connect & bind
- `cgroup/sock_create` — deny socket creation
- `cgroup/dev` — device access control

### Socket-level
- `socket` filter — classic tcpdump-style
- `sockops` — TCP lifecycle events (connection established, RTT...)
- `sk_msg` / `sk_skb` — redirect data between sockets (service mesh acceleration)

**For security sensors**, the common pattern is: `kprobe/fentry` on
`tcp_connect`/`inet_csk_accept` or the `inet_sock_set_state` tracepoint for
**visibility** of connections with process context; TC/cgroup for
**enforcement** and flow data; XDP for high-rate filtering.

---

## 9. perf_event

Attach to hardware or software performance counters, e.g. "every 10 ms of CPU
time on each core". Program captures stack traces → flame graphs. Used by
profilers (Parca, Pyroscope), occasionally by sensors for anomaly detection
(e.g. cryptominer CPU usage).

---

## 10. Iterators and other special types

- **BPF iterators** (`iter/task`, `iter/tcp`, ...) — walk kernel data structures
  on demand. Sensors use `iter/task` at startup to snapshot all existing
  processes from kernel state rather than `/proc`.
- **`struct_ops`** — implement kernel interfaces in BPF (TCP congestion control,
  sched_ext schedulers).
- **Syscall programs** (`syscall`) — run from user space via `BPF_PROG_RUN`,
  used by loaders.

---

## 11. Choosing a hook — decision guide

```
  Need to BLOCK something?
     ├─ network packet, high rate      → XDP
     ├─ network, per-container policy  → TC / cgroup hooks
     └─ exec / file / socket / ptrace  → BPF LSM
                                          (fallback: kprobe + bpf_send_signal)

  Only need to OBSERVE?
     ├─ there's a tracepoint for it?   → tracepoint (raw_tp/tp_btf if hot)
     ├─ kernel function, kernel ≥ 5.5  → fentry/fexit
     ├─ kernel function, older kernel  → kprobe/kretprobe
     └─ inside an application          → USDT if available, else uprobe
```

**Rule of thumb for security:** observe at the *syscall* boundary to know what
was **requested**, and at the *LSM* boundary to know what **actually happened**.
Mature sensors use both.

---

## 12. What real sensors hook (simplified)

| Sensor | Main hooks |
|---|---|
| **Falco** (modern eBPF probe) | `raw_tp/sys_enter`, `raw_tp/sys_exit` (all syscalls, dispatch via tail calls), `sched_process_exec/fork/exit`, page faults, signal tracepoints |
| **Tetragon** | `sched_process_exec/exit`, kprobes on `security_*` functions and `wake_up_new_task`, user-configured kprobes/tracepoints/LSM/uprobes via TracingPolicy, enforcement via `bpf_send_signal` / `fmod_ret` / LSM |
| **Tracee** | many syscall tracepoints, `sched_*`, kprobes on `security_*` LSM functions, `cgroup` hooks, network TC |
| **Cilium** | TC, XDP, cgroup socket hooks, sockops |
| **Pixie** | uprobes on TLS libs + Go runtime, kprobes on socket syscalls |

---

## Check yourself

- Why might a kprobe on a function silently stop working after a kernel upgrade?
- What can `fexit` see that `kretprobe` can't?
- Why does `sched_process_exec` give more trustworthy data than
  `sys_enter_execve`?
- Why are uprobes much more expensive than kprobes?
- Which hook type would you use to block a container from connecting to a
  specific IP? To block a binary from executing?
- What must be true about `/sys/kernel/security/lsm` for BPF LSM to work?
