#!/usr/bin/env python3

from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>

int trace_go_main(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("New process running with PID %d\\n", pid);
    return 0;
}
"""

bpf = BPF(text=bpf_source)
bpf.attach_uprobe(name="hellobpf/hellobpf", sym="main.main", fn_name="trace_go_main")
bpf.trace_print()
