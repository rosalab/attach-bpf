// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

__u32 hist[32] = {};

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
