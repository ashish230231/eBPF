# eBPF Day 6 — Hash Maps: Correlating Entry/Exit with `kill()` Signal Tracing

Read this top to bottom. It builds on Days 1–5. By the end, every word in
`sigsnoop.bpf.c` should mean something — especially the headline idea of the
day: **a BPF hash map used as short-term scratch storage to connect two
separate events that happen at different times.**

Days 2 and 4 both split work across an entry probe and an exit probe
(`do_unlinkat`'s kprobe/kretprobe, `sys_enter_openat`/`sys_exit_openat`'s
tracepoints), but in both cases each side printed its own, independent line —
entry printed one thing, exit printed another. Day 6 goes one step further:
it wants **one single printed line that combines information only entry has
(who sent the signal, what signal) with information only exit has (did it
succeed)**. The two halves of that sentence are known at two different
moments in time, by two different invocations of your BPF program. A hash map
is the bridge between them.

The concrete goal: every time any process calls `kill()` to send a signal to
another process, print who sent it, who it was sent to, which signal, and
whether the kernel accepted it — as one complete picture, not two disjoint
lines.

---

## 1. The problem: entry and exit are two separate, stateless calls

`kill(pid_t pid, int sig)` is a system call with an entry tracepoint and an
exit tracepoint, exactly like Day 4's `openat`:

```
   syscalls:sys_enter_kill   ← fires when kill() is called (args available)
   syscalls:sys_exit_kill    ← fires when kill() returns  (return value available)
```

But here's the catch: **your BPF program has no memory between these two
firings.** Each SEC() handler is its own independent invocation — local
variables declared inside `kill_entry` are gone the instant it returns. By the
time `kill_exit` runs, it has no idea what `tpid` or `sig` the matching entry
call saw. You need somewhere *outside* either function's stack to stash that
information temporarily — somewhere both invocations can reach.

That's a BPF **map**: a kernel-resident key/value store your program can read
and write across invocations, even across different attached programs
entirely.

---

## 2. Declaring a hash map

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct event);
} values SEC(".maps");
```

This isn't a normal C struct instance — it's BPF's standard **map definition
idiom**. The anonymous `struct { ... }` plus `SEC(".maps")` tells the loader
"this isn't code, it's a map descriptor — create a real kernel map matching
this shape before the program runs." Each `__uint`/`__type` macro fills in one
property of the map:

```
   type        = BPF_MAP_TYPE_HASH   → classic key→value hash table
   max_entries = MAX_ENTRIES (10240) → how many entries it can hold at once
   key         = __u32                → the TID (thread ID) of the caller
   value       = struct event          → everything we want to remember
```

A **hash map** is the general-purpose map type: arbitrary keys, O(1)-ish
lookup, entries added and removed freely at runtime. (Contrast with an array
map, which is just indexed 0..N-1 and every slot always exists — not a fit
here, since we don't know in advance which TIDs will call `kill()`.)

---

## 3. The `struct event` — what we're stashing

```c
struct event {
    unsigned int pid;
    unsigned int tpid;
    int sig;
    int ret;
    char comm[TASK_COMM_LEN];
};
```

This is the **value** half of the map — everything entry knows (`pid`,
`tpid`, `sig`, `comm`) plus one field exit will fill in later (`ret`). Nothing
new here structurally — `TASK_COMM_LEN` is the same 16-byte kernel process-name
size from Day 5.

---

## 4. Why key by TID, not PID

```c
pid_tgid = bpf_get_current_pid_tgid();
tid = (__u32)pid_tgid;          // LOWER 32 bits this time
event.pid = pid_tgid >> 32;     // UPPER 32 bits, same as always
```

Notice the direction flips from every previous day: we've always shifted
*right* by 32 to get the PID (TGID). Here we *also* keep the **lower** 32
bits — cast straight to `__u32`, which truncates and keeps the bottom half —
to get the **TID** (thread ID).

```
  ┌─────────────── 64 bits ───────────────┐
  │   TGID (upper 32) = PID  │  TID (lower 32)  │
  └───────────────────────────┴──────────────────┘
       >> 32 → pid (as always)   (__u32) cast → tid (new today)
```

Why key the map by TID instead of PID? Because **syscalls are made by
individual threads, not processes as a whole**. A multi-threaded process can
have several threads each independently calling `kill()` at the same moment.
If we keyed by PID, two threads in the same process racing through
entry→exit at the same time could stomp on each other's map entry — thread
A's exit might read thread B's half-written event. Keying by TID guarantees
each in-flight `kill()` call gets its own, uncontested map slot, because no
two threads ever share a TID.

---

## 5. Writing to the map: `bpf_map_update_elem`

```c
bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
```

This is the "insert or overwrite" helper: given the map, a pointer to the key,
and a pointer to the value, it copies `event` into the map's internal storage
under that key. The last argument is a flag controlling what happens if the
key already exists:

```
   BPF_ANY     → write regardless (create if missing, overwrite if present) — used here
   BPF_NOEXIST → only write if the key is NOT already present (fail otherwise)
   BPF_EXIST   → only write if the key IS already present (fail otherwise)
```

We use `BPF_ANY` because we don't care whether a stale entry happens to exist
under this TID already (e.g., from a `kill()` call whose exit was somehow
missed) — we just want our fresh entry data written now, unconditionally.

---

## 6. Reading it back: `bpf_map_lookup_elem`

```c
eventp = bpf_map_lookup_elem(&values, &tid);
if (!eventp)
    return 0;
```

Given the map and a key, this returns **a pointer directly into the map's
kernel memory** holding that key's value — or `NULL` if nothing's stored
under that key. The null check matters for the same reason Day 5's `!ret`
check did: if entry never ran for this TID (or its event already got cleaned
up), there's nothing to correlate, so we bail out instead of dereferencing a
null pointer.

Because `eventp` points straight at the map's storage, writing through it —
`eventp->ret = ret;` — **modifies the value already in the map**, no second
`bpf_map_update_elem` call needed. That's the elegant part: entry *wrote* the
event, exit *mutates it in place* to add the missing piece, then prints the
now-complete record.

---

## 7. Cleaning up: `bpf_map_delete_elem`

```c
bpf_map_delete_elem(&values, &tid);
```

Maps don't clean themselves up. If you only ever insert and never delete, a
busy system would eventually fill `MAX_ENTRIES` and start failing inserts (or
worse, accumulate stale entries that get wrongly matched to an unrelated
*future* `kill()` call that happens to reuse the same TID). Since exit is the
last time we need this entry, it deletes its own key right after printing —
entry inserts, exit reads-and-removes. The map entry's lifetime is exactly one
`kill()` call's entry-to-exit window, never longer.

> **A quirk worth noticing in the original tutorial code:** it has a
> `cleanup:` label right above the delete call, but nothing ever `goto`s to
> it — the label is unused. Modern compilers may warn about this
> (`-Wunused-label`); it's harmless (the line still runs top-to-bottom
> normally), but it's dead decoration left over from a version of this
> function that probably had an early-exit path jumping there. Feel free to
> just delete the label when you write your own copy.

---

## 8. `probe_entry` / `probe_exit` — shared logic, two thin wrappers

```c
static int probe_entry(pid_t tpid, int sig) { ... }
static int probe_exit(void *ctx, int ret) { ... }

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
    pid_t tpid = (pid_t)ctx->args[0];
    int sig = (int)ctx->args[1];
    return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
    return probe_exit(ctx, ctx->ret);
}
```

Two actual BPF programs (`kill_entry`, `kill_exit` — the ones with `SEC()`),
each a **thin adapter** that pulls the right fields out of its tracepoint's
context struct, then hands off to a plain `static` helper function that does
the real work. This is a pattern worth keeping: separate "get the data out of
this specific ctx shape" from "what do we actually do with the data" — makes
the logic (map update, map lookup, printing) reusable and easier to read in
isolation from the tracepoint plumbing.

### `ctx->args[0]`, `ctx->args[1]` — a new way to read a tracepoint's arguments

Day 4 used `struct trace_event_raw_sys_enter *ctx` too, but never touched its
fields beyond getting the PID elsewhere. Here we finally read the syscall's
real arguments out of it:

```c
pid_t tpid = (pid_t)ctx->args[0];   // kill()'s 1st argument: pid_t pid
int sig    = (int)ctx->args[1];     // kill()'s 2nd argument: int sig
```

`struct trace_event_raw_sys_enter` stores **every syscall's arguments** in a
single generic `unsigned long args[6]` array (syscalls take at most 6 args),
regardless of which syscall it is. You match `args[N]` up against the real
function signature yourself and cast to the correct type. For
`kill(pid_t pid, int sig)`: `args[0]` is `pid`, `args[1]` is `sig`.

### `ctx->ret` on the exit side

`struct trace_event_raw_sys_exit` is the matching struct for exit tracepoints
— simpler, since a syscall only ever returns one value: `ctx->ret` holds it
directly, no array needed. That's `kill()`'s return value: `0` on success,
negative errno-style on failure (same convention Day 2's `do_unlinkat`
kretprobe return value followed).

---

## 9. Reused from earlier days (nothing new)

- **`bpf_get_current_pid_tgid()`** — same helper, Days 2–5; today we just also
  keep its lower half.
- **`bpf_get_current_comm()`** — identical to Day 5, writing into
  `event.comm` instead of a bare local array.
- **`bpf_printk`** — same shared trace buffer, max 3 args per call (hence this
  example splits one logical message across two `bpf_printk` calls).
- **`SEC("tracepoint/syscalls/...")`**, **entry/exit split** — same mechanism
  as Day 4's `sys_enter_openat`/the implied `sys_exit_openat`, just the first
  time this repo actually wires up both sides of one syscall.
- **The GPL-compatible license line** — still mandatory.

---

## 10. Requirements & troubleshooting

1. **Confirm the tracepoints exist:**
   `sudo cat /sys/kernel/debug/tracing/available_events | grep sys_.*_kill`
2. **No output?** Trigger a real signal: open another terminal and run
   `kill -0 $$` (sends signal 0 — "check if a process exists" — to your own
   shell; completely harmless, and exactly what the tutorial's own captured
   output shows: `sent signal 0`). Or `kill -0 <any running PID>`.
3. **Verify attach:** `sudo bpftool prog show | grep -i kill`.
4. **Entries never showing up / seem to leak:** if exit's lookup always comes
   back `NULL`, double check you're matching the *same* TID on both sides —
   easy mistake is accidentally using the PID (upper bits) as the map key on
   one side and TID (lower bits) on the other.

---

## 11. The whole Day 6 pipeline in one line

```
sigsnoop.bpf.c --clang--> .bpf.o (values hash map declared in .maps section)
  --verifier--> (JIT) --attach--> sys_enter_kill + sys_exit_kill tracepoints
  kill() called: entry reads (tpid, sig) from ctx->args[],
                 builds event{pid, tpid, sig, comm}, stores it keyed by TID
  kill() returns: exit looks up the same TID's event, fills in .ret,
                 bpf_printk's the combined record, deletes the map entry
  --> /sys/kernel/debug/tracing/trace_pipe
```

The through-line: Days 1–5 each added a new *kind of hook* or a new *kind of
memory to read*. Day 6 adds a new *kind of storage* — one that outlives a
single probe invocation and lets two separate events, at two separate
moments, be stitched into one coherent story.
