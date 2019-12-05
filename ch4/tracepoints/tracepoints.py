#!/usr/bin/env python3

from bcc import BPF

# sudo bpftrace -lv tracepoint:net:net_dev_queue
# sudo bpftrace -d -e 't:net:net_dev_queue { @[args->data_loc_name] = count(); }'


bpf_source = """
struct net_dev_queue_args {
    void *skbaddr;
    unsigned int len;
    int data_loc_name;
};

int trace_net_dev_queue(struct net_dev_queue_args *args) {
    bpf_trace_printk(">>%d --> %d\\n",args->data_loc_name, args->len);
    return 0;
}
"""

bpf = BPF(text=bpf_source)
bpf.attach_tracepoint(tp="net:net_dev_queue", fn_name="trace_net_dev_queue")
bpf.trace_print()
