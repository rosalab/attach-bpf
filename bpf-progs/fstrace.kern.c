// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

#include "fstrace.kern.h"

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
	__type(value, char[4096]);
} path_prefix SEC(".maps");

__u32 hist[32] = {};

SEC("tp/syscalls/sys_enter_read")
int BPF_PROG(trace_read, u64 empty, u64 nr, u32 fd, char * buf, u64 buf_size)
{
    if (!buf) 
        return 0;
    bpf_printk("Args are %d, %s, %ld\n", fd, buf, buf_size);
    u32 zero = 0;
    char string[256];
    u32 len = bpf_probe_read_user_str(string, 255, buf);
    bpf_printk("Len is %d\n String was %s\n", len, string);
    
    char * str_prefix;
    str_prefix = (char *) bpf_map_lookup_elem(&path_prefix, &zero);
    if (str_prefix == NULL) 
        return 0;
    
    bpf_printk("prefix was %s\n", str_prefix);
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
