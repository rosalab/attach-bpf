// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

#include "fstrace.kern.h"

/* kfunc definitions */
extern struct file *fget_raw(unsigned int fd) __ksym;
extern int bpf_path_d_path(struct path *path, char *buf, size_t buf__sz) __ksym;
extern void bpf_put_file(struct file *file) __ksym;

struct inner_map {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 4096);
        __type(key, __u32);
        __type(value, __u32);
} fd_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
        __uint(max_entries, 4096);
        __type(key, __u32);
        __array(values, struct inner_map);
} pid_map SEC(".maps") = {
        .values = { &fd_map }
};


/* key: pid.  value: start time */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PIDS);
	__type(key, u32);
	__type(value, u64);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PIDS);
	__type(key, u32);
	__type(value, u64);
} trace SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, char[64]);
} path SEC(".maps");

__u32 hist[32] = {};

static inline int check_to_trace(int fd)
{
    u32 zero = 0;
    struct file * f;
    char str[128];
    // Use kfunc to get a file * for fd
    f = fget_raw(fd);
    if (!f)
        return 0;
    // Use kfunc to resolve path
    bpf_path_d_path(&f->f_path, str, 128);

    // Read prefix from configuration map
    char * prefix = (char *)bpf_map_lookup_elem(&path, &zero);
    if (!prefix)
        return 0;

    // Must roll own strcmp because configuration map is not read only
    long ret = 1;
    for (int i = 0; i < 64; i++) {
        if (prefix[i] == '\0' || str[i] == '\0') {
            break;
        }
        if (prefix[i] != str[i]) {
            ret = 0;
            break;
        }
    }
    bpf_put_file(f);
    return ret;
}

//SEC("tp/syscalls/sys_enter_open")
SEC("fexit/do_sys_open")
int trace_open_enter(void * ctx)
{
    u64 filename;
    u64 ret_fd;
    char * file;

    // Get the filename we are opening
    bpf_get_func_arg(ctx, 1, &filename);
    //bpf_printk("In prog\n");
    file = (char *)filename;
    if (!file)
        return 0;



    // Compare the filename

    // If matches then add the fd to the map
    bpf_get_func_ret(ctx, &ret_fd);

    bpf_printk("File was %s with fd %ld\n", file, ret_fd);



    //bpf_printk("Filename was %s\n", enter_ctx->filename);
    return 0;
}


SEC("fexit/do_sys_openat2")
int trace_open_exit(void * ctx)
{
    u64 ret_fd;
    // Get the fd we just opened
    bpf_get_func_ret(ctx, &ret_fd);
    if (check_to_trace(ret_fd)) {
        bpf_printk("Opened\n");
    }
    return 0;
}

SEC("fexit/ksys_read")
int trace_sys_read(void * ctx)
{
    u64 fd;
    bpf_get_func_arg(ctx, 0, &fd);
    if (check_to_trace(fd)) {
        bpf_printk("Read\n");
    }
    return 0;
}

SEC("fexit/ksys_write")
int trace_sys_write(void * ctx)
{
    u64 fd;
    bpf_get_func_arg(ctx, 0, &fd);
    if (check_to_trace(fd)) {
        bpf_printk("Write\n");
    }
    return 0;
}


SEC("fexit/path_init")
int trace_path_init(void * ctx)
{
    u64 path_name;
    char * path;
    bpf_get_func_ret(ctx, &path_name);
    path = (char *)path_name;
    if (!path)
        return 0;

    bpf_printk("Path was %s\n");
    return 0;
}

    

//SEC("tp/syscalls/sys_exit_open")
//int trace_open_exit(struct open_exit_ctx * exit_ctx)
//{
//    bpf_printk("Ret was %ld\n", exit_ctx->fd);
//    return 0;
//}
            

SEC("tp/syscalls/sys_enter_read")
int BPF_PROG(trace_read, u64 empty, u64 nr, u32 fd, char * buf, u64 buf_size)
{
    if (!buf) 
        return 0;
    //bpf_printk("Args are %d, %s, %ld\n", fd, buf, buf_size);
    u32 zero = 0;
    char string[256];
    u32 len = bpf_probe_read_user_str(string, 255, buf);
    //bpf_printk("Len is %d\n String was %s\n", len, string);
    
    char * str_prefix;
    str_prefix = (char *) bpf_map_lookup_elem(&path, &zero);
    if (str_prefix == NULL) 
        return 0;
    
    //bpf_printk("prefix was %s\n", str_prefix);
    //long res = bpf_strncmp(string, 256, str_prefix);
    //bpf_printk("Result was %ld\n", res);
    return 0;
}



/*
static void entry(void * ctx) {
    u64 zero = 0;
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id;
	u64 nsec;

    u64 buf_size;
    u64 string_ptr;

    // Get the path accessed

    bpf_get_func_arg(ctx, 1, &string_ptr);
    bpf_get_func_arg(ctx, 2, &buf_size);



    //bpf_printk("Syscall was %ld\n", *syscall_num);
    if (*to_trace) {
	    nsec = bpf_ktime_get_ns();
    	bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
    }
    else {
        bpf_map_update_elem(&starts, &pid, &zero, BPF_ANY);
    }
}

static void exit(void * ctx)
{
    u64 zero = 0;
	u64 *start;
	u64 nsec = bpf_ktime_get_ns();
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id;
	u64 slot, delta;

	start = bpf_map_lookup_elem(&starts, &pid);
	if (!start)
		return;

    if (*start == 0) 
        goto cleanup_exit;

	delta = nsec - *start;

	//case USEC:
	delta /= 1000;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hist[slot], 1);

cleanup_exit:
    //bpf_map_update_elem(&syscall, &pid, &zero, BPF_ANY);
}
*/

//SEC("fentry/dummy_file_read")
//int BPF_PROG(file_read_fentry)
//{
//    entry(ctx);
//    return 0;
//}
//
//SEC("fexit/dummy_file_read")
//int BPF_PROG(file_read_fexit)
//{
//    exit(ctx);
//    return 0;
//}
//
//SEC("fentry/dummy_file_write")
//int BPF_PROG(file_write_fentry)
//{
//	return probe_entry();
//}
//
//SEC("fexit/dummy_file_write")
//int BPF_PROG(file_write_fexit)
//{
//	return probe_return(F_WRITE);
//}
//
//SEC("fentry/dummy_file_open")
//int BPF_PROG(file_open_fentry)
//{
//	return probe_entry();
//}
//
//SEC("fexit/dummy_file_open")
//int BPF_PROG(file_open_fexit)
//{
//	return probe_return(F_OPEN);
//}
//
//SEC("fentry/dummy_file_sync")
//int BPF_PROG(file_sync_fentry)
//{
//	return probe_entry();
//}
//
//SEC("fexit/dummy_file_sync")
//int BPF_PROG(file_sync_fexit)
//{
//	return probe_return(F_FSYNC);
//}
//
//SEC("fentry/dummy_getattr")
//int BPF_PROG(getattr_fentry)
//{
//	return probe_entry();
//}
//
//SEC("fexit/dummy_getattr")
//int BPF_PROG(getattr_fexit)
//{
//	return probe_return(F_GETATTR);
//}

char LICENSE[] SEC("license") = "GPL";
