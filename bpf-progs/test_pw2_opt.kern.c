// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} starts SEC(".maps");

static void entry(void * ctx)
{
    __u32 tid = bpf_get_current_pid_tgid();
    u64 val = 0xdeadbeef;
    bpf_set_shared(ctx, &val, 8);
    //bpf_map_update_elem(&starts, &tid, &val, BPF_ANY);
    //bpf_get_shared(ctx, &t);
    //bpf_printk("Getting Shared after setting: %llx\n", t);
}

SEC("fentry/__x64_sys_getcwd")
int dummy_fentry(void * ctx)
{
	entry(ctx);
	return 0;
}

static void exit(void * ctx)
{
    u64 val = 0;
    u64 * valp;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    //valp = bpf_map_lookup_elem(&starts, &tid);
    //if (!valp) 
    //    return;
    
    bpf_get_shared(ctx, &val, 8);

    //bpf_map_delete_elem(&starts, &tid);
     
}

SEC("fexit/__x64_sys_getcwd")
int dummy_fexit(void * ctx)
{
	exit(ctx);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
