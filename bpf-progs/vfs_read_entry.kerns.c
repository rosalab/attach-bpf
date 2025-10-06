#include "vmlinux.h"

//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// struct file *file, char __user *buf, size_t count, loff_t *pos

SEC("fentry/vfs_read")
int trace_vfs_read(void *ctx)
{
    __u64 file;
    __u64 buf;
    __u64 cnt;
    __u64 pos;

    bpf_get_func_arg(ctx, 0, &file);
    bpf_get_func_arg(ctx, 1, &buf);
    bpf_get_func_arg(ctx, 2, &cnt);
    bpf_get_func_arg(ctx, 3, &pos);
    //__u64 f_ops_ptr = 0;
    //long res = bpf_probe_read_kernel((void *)&f_ops_ptr, sizeof(void *), (void *)f_ops_ptr + offsetof(struct file, f_op));
    //bpf_printk("Count: %llu Res: %lld\nVFS Read %llu\n", cnt, res, f_ops_ptr);
    bpf_printk("File: %llu Buf: %llu Cnt: %llu Pos: %llu\n", file, buf, cnt, pos);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
