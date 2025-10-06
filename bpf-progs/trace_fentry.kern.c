#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LISENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/ovl_open")
int empty(void *ctx)
{
    bpf_printk("Traced :)\n");
    return 0;
}
