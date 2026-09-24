#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

const volatile int pid_target=0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return 0;

    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";