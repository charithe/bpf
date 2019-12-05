#!/usr/bin/env python3

from bcc import BPF

bpf_source = """
int kprobe__sys_execve(void *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_trace_printk("executing %s", comm);
    return 0;
}
"""

bpf = BPF(text=bpf_source)
execve_func = bpf.get_syscall_fnname("execve")
bpf.attach_kprobe(event=execve_func, fn_name="kprobe__sys_execve")
bpf.trace_print()
