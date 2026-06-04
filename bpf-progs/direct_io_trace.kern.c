#include "vmlinux.h"
#include "funclatency.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, u32);
    __type(value, u64);
} starts SEC(".maps");

// Store the time of the entry
SEC("fentry/vfs_read")
int BPF_PROG(read_entry)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 nsec = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
    return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(read_exit)
{
    u64 *start;

    u64 nsec = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 delta;
    start = bpf_map_lookup_elem(&starts, &pid);
    if (!start)
        return 0;

    if (*start == 0)
        goto cleanup_exit;

    delta = nsec - *start;
    delta /= 1000;
    bpf_printk("Read took %ld ns\n", delta);
cleanup_exit:
    return 0;
}

SEC("fexit/ext4_should_use_dio")
int BPF_PROG(dio_trace)
{
    u64 is_dio = 0;
    if (bpf_get_func_ret(ctx, &is_dio))
        return 0;

    bpf_printk("DIO value is %llu\n", is_dio);
    return 0;
}

//SEC("fentry/ext4_file_read_iter")
//int BPF_PROG(dio_trace)
//{
//    struct kiocb * iocb_p = NULL;
//    struct kiocp iocb;
//    if(bpf_get_func_arg(ctx, 0, &iocb_p)) {
//        return 0;
//    }
//
//    // null check for the pointer
//    if (iocb_p == NULL) {
//        return 0;
//    }
//    
//    if (bpf_probe_read_kernel(&iocb, sizeof(iocb), iocb_p)) {
//        return 0;
//    }
//
//    
//
//    return 0;
//}

char LICENSE[] SEC("license") = "GPL";

