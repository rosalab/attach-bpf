// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

//const volatile pid_t targ_tgid = 0;
//const volatile int units = 0;
//const volatile bool filter_cg = false;

//struct {
//	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
//	__type(key, u32);
//	__type(value, u32);
//	__uint(max_entries, 1);
//} cgroup_map SEC(".maps");

/* key: pid.  value: start time */
//struct {
//	__uint(type, BPF_MAP_TYPE_HASH);
//	__uint(max_entries, MAX_PIDS);
//	__type(key, u32);
//	__type(value, u64);
//} starts SEC(".maps");

__u32 hist[32] = {};

static void entry(void *ctx)
{
	//u64 id = bpf_get_current_pid_tgid();
	//u32 tgid = id >> 32;
	//u32 pid = id;
	u64 nsec;

    /* Filtering can be done by color */
	//if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
	//	return;

	//if (targ_tgid && targ_tgid != tgid)
	//	return;
	nsec = bpf_ktime_get_ns();
    *(__u64 *)bpf_get_shared(ctx) = nsec;
	//bpf_map_update_elem(&starts, &pid, &nsec, BPF_ANY);
}

SEC("fentry/__x64_sys_getcwd")
int BPF_PROG(dummy_fentry)
{
	entry(ctx);
	return 0;
}

static void exit(void *ctx)
{
	u64 *start;
	u64 nsec = bpf_ktime_get_ns();
	//u64 id = bpf_get_current_pid_tgid();
	//u32 pid = id;
	u64 slot, delta;

    /* Filtering can be done by color */
	//if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
	//	return;

	//start = bpf_map_lookup_elem(&starts, &pid);
    start = (__u64 *)bpf_get_shared(ctx);
	//if (!start)
	//	return;

	delta = nsec - *start;

	//switch (units) {
	//case USEC:
	//	delta /= 1000;
	//	break;
	//case MSEC:
	delta /= 1000000;
	//	break;
	//}

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hist[slot], 1);
}

SEC("fexit/__x64_sys_getcwd")
int BPF_PROG(dummy_fexit)
{
	exit(ctx);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
