// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

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
} syscall SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 600);
	__type(key, u32);
	__type(value, u8);
} trace_syscall SEC(".maps");

__u32 hist[32] = {};

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_trace, struct pt_regs * pt, long syscall_id)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u64 * ptr = (u64 *)bpf_map_lookup_elem(&syscall, &pid);
    if (ptr == NULL) {
        return 0;
    }
    
    if (*ptr == 0) {
        return 0;
    }

    //bpf_map_update_elem(&syscall, &pid, &syscall_id, BPF_ANY);
    return 0;
}

//static void entry(void)
//{
//    u64 zero = 0;
//	u64 id = bpf_get_current_pid_tgid();
//	u32 pid = id;
//	u64 nsec;
//
//    u64 * syscall_num = (u64 *)bpf_map_lookup_elem(&syscall, &pid);
//    if (syscall_num == NULL)
//        return;
//
//    u8 * to_trace = (u8 *)bpf_map_lookup_elem(&trace_syscall, syscall_num);
//    if (to_trace == NULL)
//        return;
//    //bpf_printk("Syscall was %ld\n", *syscall_num);
//    if (*to_trace) {
//	    nsec = bpf_ktime_get_ns();
//    	bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
//    }
//    else {
//        bpf_map_update_elem(&starts, &pid, &zero, BPF_ANY);
//    }
//}
//
//SEC("fentry/__kmalloc_noprof")
//int BPF_PROG(dummy_fentry)
//{
//	entry();
//	return 0;
//}
//
//static void exit(void)
//{
//    u64 zero = 0;
//	u64 *start;
//	u64 nsec = bpf_ktime_get_ns();
//	u64 id = bpf_get_current_pid_tgid();
//	u32 pid = id;
//	u64 slot, delta;
//
//	start = bpf_map_lookup_elem(&starts, &pid);
//	if (!start)
//		return;
//
//    if (*start == 0) 
//        goto cleanup_exit;
//
//	delta = nsec - *start;
//
//	//case USEC:
//	delta /= 1000;
//	slot = log2l(delta);
//	if (slot >= MAX_SLOTS)
//		slot = MAX_SLOTS - 1;
//	__sync_fetch_and_add(&hist[slot], 1);
//
//cleanup_exit:
//    //bpf_map_update_elem(&syscall, &pid, &zero, BPF_ANY);
//}
//
//SEC("fexit/__kmalloc_noprof")
//int BPF_PROG(dummy_fexit)
//{
//	exit();
//	return 0;
//}

char LICENSE[] SEC("license") = "GPL";
