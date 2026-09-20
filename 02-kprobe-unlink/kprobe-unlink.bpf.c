// kprobe-unlink.bpf.c
// Day 2: monitor file deletion by probing the kernel function do_unlinkat.
// Two probes on the SAME function:
//   kprobe    -> fires on ENTRY, reads the arguments (WHICH file)
//   kretprobe -> fires on RETURN, reads the return value (did it succeed?)

#include "vmlinux.h"             // generated kernel type definitions (struct filename, pid_t, ...)
#include <bpf/bpf_helpers.h>     // SEC(), bpf_printk(), bpf_get_current_pid_tgid()
#include <bpf/bpf_tracing.h>     // BPF_KPROBE / BPF_KRETPROBE argument-unpacking macros
#include <bpf/bpf_core_read.h>   // BPF_CORE_READ() — safe, CO-RE-relocatable kernel reads

// GPL-compatible license is mandatory: bpf_printk and the read helpers are GPL-only.
// Leave this out and the verifier refuses to load the program.
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// --- ENTRY PROBE ---------------------------------------------------------------
// Attach on ENTRY of do_unlinkat(int dfd, struct filename *name).
// BPF_KPROBE unpacks the probed function's arguments into normal typed parameters,
// so dfd and name match the real kernel signature.
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;                 // process ID of whoever triggered the delete
    const char *filename;      // pointer to the path string inside struct filename

    // bpf_get_current_pid_tgid() packs TGID (top 32 bits) and thread ID (bottom 32).
    // Shifting right by 32 keeps the TGID — what we normally call the PID.
    pid = bpf_get_current_pid_tgid() >> 32;

    // We CANNOT write name->name directly: the verifier forbids dereferencing a raw
    // kernel pointer. BPF_CORE_READ reads name->name safely (via bpf_probe_read_kernel)
    // and records a CO-RE relocation so the field offset is correct on any kernel.
    filename = BPF_CORE_READ(name, name);

    // Print to the shared kernel trace buffer (max 3 args). Read it later from
    // /sys/kernel/debug/tracing/trace_pipe.
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}

// --- RETURN PROBE --------------------------------------------------------------
// Attach on RETURN of do_unlinkat. BPF_KRETPROBE hands us the return value `ret`.
// Note: different function name (do_unlinkat_exit) — it's a separate eBPF program.
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    // Same PID idiom as the entry probe.
    pid = bpf_get_current_pid_tgid() >> 32;

    // ret is the result of the delete: 0 = success, negative = errno-style failure
    // (e.g. -2 = ENOENT, "no such file").
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
