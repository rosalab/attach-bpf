#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("fentry/vfs_read")
int BPF_PROG(read_entry)
{
    return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(read_exit)
{
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

