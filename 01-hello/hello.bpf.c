// hello.bpf.c
// Write your first eBPF program here, from scratch.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/__x64_sys_execve")

int hello(void *ctx){
    bpf_printk("Hello, eBPF world ! this is were programs are read.\n");
    return 0;
}
