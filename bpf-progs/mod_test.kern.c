#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LISENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/__x64_sys_getcwd")
int bpf_demo(void *ctx)
{
    __u64 val = 0;
    //int a = bpf_get_shared(ctx, &val);
    //bpf_printk("Result was %d\n", a);
    return 0;
}
