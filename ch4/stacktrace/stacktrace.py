#!/usr/bin/env python3

from bcc import BPF, PerfType, PerfSWConfig
from time import sleep
import sys
import signal


bpf_source = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

struct trace_t {
    int stack_id;
};

BPF_HASH(cache, struct trace_t);
BPF_STACK_TRACE(traces, 10000);

int collect_stack_traces(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != PROGRAM_PID) {
        return 0;
    }

    struct trace_t trace = {
        .stack_id = traces.get_stackid(&ctx->regs, BPF_F_USER_STACK)
    };

    if (trace.stack_id >= 0) {
        cache.increment(trace);
    }
    return 0;
}
"""

program_pid = sys.argv[1]
bpf_source = bpf_source.replace("PROGRAM_PID", program_pid)

bpf = BPF(text=bpf_source)
bpf.attach_perf_event(
        ev_type=PerfType.SOFTWARE,
        ev_config=PerfSWConfig.CPU_CLOCK,
        fn_name="collect_stack_traces",
        cpu=0,
        sample_freq=99)

try:
    sleep(999999999)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal.SIG_DFL)



cache = bpf["cache"]
traces = bpf["traces"]

bpf.detach_perf_event(ev_type=PerfType.SOFTWARE,ev_config=PerfSWConfig.CPU_CLOCK)
bpf.add_module("/usr/lib64/libc-2.30.so")

for trace, acc in sorted(cache.items(), key=lambda cache: cache[1].value):
    line = []
    if trace.stack_id < 0 and trace.stack_id  == -errno.EFAULT:
        line = ["Unknown stack"]
    else:
        stack_trace = list(traces.walk(trace.stack_id))
        for stack_address in reversed(stack_trace):
            line.extend(bpf.sym(stack_address, int(program_pid)))

    print(line)
    #frame = b";".join(line).decode("utf-8", "replace")
    #print(f"{frame} {acc.value}")
