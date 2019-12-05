#!/usr/bin/env python3

from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>

BPF_HASH(cache, u64, u64);

int start_go_main(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 start_time_ns = bpf_ktime_get_ns();
    cache.insert(&pid, &start_time_ns);
    bpf_trace_printk("Process started: %d\\n", pid);
    return 0;
}

int end_go_main(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 *start_time_ns = cache.lookup(&pid);
    if (start_time_ns == NULL) {
        return 0;
    }
    u64 duration_ns = bpf_ktime_get_ns() - (*start_time_ns);
    bpf_trace_printk("Process ended: %d (took %dns)\\n", pid, duration_ns);
    return 0;
}
"""

bpf = BPF(text=bpf_source)
bpf.attach_uprobe(name="hellobpf/hellobpf", sym="main.main", fn_name="start_go_main")
bpf.attach_uretprobe(name="hellobpf/hellobpf", sym="main.main", fn_name="end_go_main")
bpf.trace_print()
