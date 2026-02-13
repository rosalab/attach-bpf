#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/__kmalloc_noprof")
int operator_test(void *ctx)
{
    bpf_printk("OPERATOR TEST!\n");
    return 0;
}
