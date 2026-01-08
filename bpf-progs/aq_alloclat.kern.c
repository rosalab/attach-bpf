// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

/* key: pid.  value: start time */
//struct {
//	__uint(type, BPF_MAP_TYPE_HASH);
//	__uint(max_entries, MAX_PIDS);
//	__type(key, u32);
//	__type(value, u64);
//} starts SEC(".maps");

//struct {
//	__uint(type, BPF_MAP_TYPE_HASH);
//	__uint(max_entries, MAX_PIDS);
//	__type(key, u32);
//	__type(value, u64);
//} syscall SEC(".maps");

//struct {
//	__uint(type, BPF_MAP_TYPE_ARRAY);
//	__uint(max_entries, 600);
//	__type(key, u32);
//	__type(value, u8);
//} trace_syscall SEC(".maps");

__u32 hist[32] = {};

/* Do not need extra syscall BPF program */
//SEC("tp_btf/sys_enter")
//int BPF_PROG(sys_trace, struct pt_regs * pt, long syscall_id)
//{
//    u64 id = bpf_get_current_pid_tgid();
//    u32 pid = id;
//    bpf_map_update_elem(&syscall, &pid, &syscall_id, BPF_ANY);
//    return 0;
//}

static void entry(void *ctx)
{
    u64 *ts;
    ts = (u64 *)bpf_get_shared(ctx);
    *ts = bpf_ktime_get_ns();
}

SEC("fentry/__kmalloc_noprof")
int BPF_PROG(dummy_fentry)
{
	entry(ctx);
	return 0;
}

static void exit(void *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 *start = (u64 *)bpf_get_shared(ctx);
	u64 slot, delta;

	delta = ts - *start;
	delta /= 1000;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hist[slot], 1);
}

SEC("fexit/__kmalloc_noprof")
int BPF_PROG(dummy_fexit)
{
	exit(ctx);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
