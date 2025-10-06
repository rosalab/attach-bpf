#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} my_map SEC(".maps");


char LISENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/__x64_sys_getcwd")
int empty(void *ctx)
{
    return 0;
}
