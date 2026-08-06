// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

#include "map_check_test.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 128);
	__type(key, u32);
	__type(value, struct map_check_value);
} check_map SEC(".maps");


SEC("tp/syscalls/sys_enter_getcwd")
int map_check_test(void *ctx)
{
    struct check_map_value * ptr;
    u32 key = 0;
    // Should make sure the type of ptr is struct map_check_value * 
    ptr = bpf_map_lookup_elem(&check_map, &key);
    if (!ptr)
        return -1;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
