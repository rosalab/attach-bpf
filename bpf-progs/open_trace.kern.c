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

SEC("tp/syscalls/sys_enter_openat")
int empty(void *ctx)
{
    __u32 key = 0;
    __u32 * val = bpf_map_lookup_elem(&my_map, &key);
    if (!val) {
        return -1;
    }
    __u32 new = (*val) + 1;
    bpf_map_update_elem(&my_map, &key, &new, BPF_ANY);
    return 0;
}
