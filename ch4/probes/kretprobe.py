#!/usr/bin/env python3

from bcc import BPF

bpf_source = """
#include <uapi/linux/ptrace.h>

int kretprobe__sys_execve(struct pt_regs *ctx) {
    int ret_val;
    char comm[16];

    bpf_get_current_comm(&comm, sizeof(comm));
    ret_val = PT_REGS_RC(ctx);
    bpf_trace_printk("%s exited with %d", comm, ret_val);
    return 0;
}
"""

bpf = BPF(text=bpf_source)
execve_func = bpf.get_syscall_fnname("execve")
bpf.attach_kretprobe(event=execve_func, fn_name="kretprobe__sys_execve")
bpf.trace_print()
