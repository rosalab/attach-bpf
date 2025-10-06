// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} starts SEC(".maps");


static void entry(void * ctx)
{
    //u64 addr = 0;
    __u64 ts = bpf_ktime_get_ns();
    *(__u64*)bpf_get_shared(ctx) = ts;
    //bpf_printk("Entry: ID: %u Value :%u\n", d->id, d->random_val);
    //bpf_printk("Hello\n");
    //if (addr == 1) {
    //}
    //*(u64 *)addr = 0xdeadbeef;
    //*stack = 0xdeadbeef;
    
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
    __u64 ts = bpf_ktime_get_ns();
    __u64 old = *(__u64 *)bpf_get_shared(ctx);


    struct my_data * d;
    //valp = bpf_map_lookup_elem(&starts, &tid);
    //if (!valp) 
    //    return;
    
    d = (struct my_data *)bpf_get_shared(ctx);
    //bpf_printk("Exit: Id: %u Value: %u\n", d->id, d->random_val);

    //bpf_map_delete_elem(&starts, &tid);
     
}

SEC("fexit/__x64_sys_getcwd")
int dummy_fexit(void * ctx)
{
	exit(ctx);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
