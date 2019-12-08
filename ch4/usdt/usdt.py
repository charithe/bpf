#!/usr/bin/env python3

from bcc import BPF, USDT
import sys

bpf_source = """
#include <uapi/linux/ptrace.h>

int trace_binary_exec(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("New process running with PID %d\\n", pid);
    return 0;
}
"""

usdt_ctx = USDT(pid=int(sys.argv[1]))
usdt_ctx.enable_probe(probe="probe-main", fn_name="trace_binary_exec")
bpf = BPF(text=bpf_source, usdt_contexts=[usdt_ctx], debug=4)
bpf.trace_print()
