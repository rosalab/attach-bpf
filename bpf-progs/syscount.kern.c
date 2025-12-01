// System call count and overall latency for all system calls
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on syscount(8) from BCC by Sasha Goldshtein
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
//#include "syscount.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} pid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct data_t {
    u64 count;
    u64 total_latency;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct data_t);
} data SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

    u32 *res = (u32 *)bpf_map_lookup_elem(&pid_map, &pid);
    if (res == NULL) {
        return 0;
    }
	u32 tid = id;
	u64 ts;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &tid, &ts, 0);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

    u32 *res = (u32 *)bpf_map_lookup_elem(&pid_map, &pid);
    if (res == NULL) {
        return 0;
    }

	u32 tid = id;

	u64 *start_ts, lat = 0;

    start_ts = bpf_map_lookup_elem(&start, &tid);
	if (!start_ts) {
        return 0;
    }

	lat = bpf_ktime_get_ns() - *start_ts;

	struct data_t *val;

    //if (!args) {
    //    return 0;
    //}

    u32 sys_num = (u32)args->id;
	/* this happens when there is an interrupt */
	if (sys_num == -1) {
		return 0;
	}


    val = (struct data_t *)bpf_map_lookup_elem(&data, &sys_num);
    if (!val) {
        struct data_t t;
        t.total_latency = lat;
        t.count = 1;
        bpf_map_update_elem(&data, &sys_num, &t, 0);
    }
    else {
        __sync_fetch_and_add(&val->count, 1);
        __sync_fetch_and_add(&val->total_latency, lat);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
