// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "funclatency.h"
#include "bits.bpf.h"

#include "fstrace.kern.h"

//struct event {
//    int pid;
//};
//
//
///* kfunc definitions */
//extern struct file *fget_raw(unsigned int fd) __ksym;
//extern int bpf_path_d_path(struct path *path, char *buf, size_t buf__sz) __ksym;
//extern void bpf_put_file(struct file *file) __ksym;
//
//const char * open_str = "PID: %d opened %s\n";
////const char * read_str = "PID: %d read at %s with latency %ld\n";
//
//struct {
//        __uint(type, BPF_MAP_TYPE_RINGBUF);
//        __uint(max_entries, 32768);
//        __uint(key_size, 0);
//        __uint(value_size, 0);
//} rbuf SEC(".maps");
//
//struct inner_map {
//        __uint(type, BPF_MAP_TYPE_HASH);
//        __uint(max_entries, 4096);
//        __type(key, __u32);
//        __type(value, __u32);
//} fd_map SEC(".maps");
//
//struct {
//        __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
//        __uint(max_entries, 4096);
//        __type(key, __u32);
//        __array(values, struct inner_map);
//} pid_map SEC(".maps") = {
//        .values = { &fd_map }
//};
//
//
///* key: pid.  value: start time */
//struct {
//	__uint(type, BPF_MAP_TYPE_HASH);
//	__uint(max_entries, MAX_PIDS);
//	__type(key, u32);
//	__type(value, u64);
//} starts SEC(".maps");
//
//struct {
//	__uint(type, BPF_MAP_TYPE_HASH);
//	__uint(max_entries, MAX_PIDS);
//	__type(key, u32);
//	__type(value, u64);
//} trace SEC(".maps");
//
//struct {
//	__uint(type, BPF_MAP_TYPE_ARRAY);
//	__uint(max_entries, 1);
//	__type(key, u32);
//	__type(value, char[64]);
//} path SEC(".maps");
//
//__u32 hist[32] = {};
//
//static inline int check_to_trace(int fd, char * str)
//{
//    u32 zero = 0;
//    struct file * f;
//    //char str[128];
//    // Use kfunc to get a file * for fd
//    f = fget_raw(fd);
//    if (!f)
//        return 0;
//    // Use kfunc to resolve path
//    bpf_path_d_path(&f->f_path, str, 128);
//
//    // Read prefix from configuration map
//    char * prefix = (char *)bpf_map_lookup_elem(&path, &zero);
//    if (!prefix)
//        return 0;
//
//    //bpf_printk("%s : %s\n", prefix, str);
//    // Must roll own strcmp because configuration map is not read only
//    long ret = 1;
//    for (int i = 0; i < 64; i++) {
//        if (prefix[i] == '\0' || str[i] == '\0') {
//            break;
//        }
//        if (prefix[i] != str[i]) {
//            ret = 0;
//            break;
//        }
//    }
//    bpf_put_file(f);
//    return ret;
//}

SEC("fentry/__do_sys_empty_syscall")
int trace_sys_empty_enter(void *ctx)
{
    u64 *ts;
    ts = (u64 *)bpf_get_shared(ctx);
    *ts = bpf_ktime_get_ns();
    //u64 ts;
    //u32 tid = (u32) bpf_get_current_pid_tgid();
    //ts = bpf_ktime_get_ns();
    //bpf_map_update_elem(&starts, &tid, &ts, 0);
    return 0;
}

SEC("fexit/__do_sys_empty_syscall")
int trace_sys_empty_exit(void *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 *start = (u64 *)bpf_get_shared(ctx);
    u64 delta;
    delta = ts - *start;
    //u64 ts = bpf_ktime_get_ns();
    //if (check_to_trace(ret_fd, file)) {
    //u64 tgid = bpf_get_current_pid_tgid();
    //u32 tid = (u32) tgid;
    //u32 pid = tgid & 0xFFFFFFFF;
    //u64 * tsp = bpf_map_lookup_elem(&starts, &tid);
    //u64 lat = 0;
    //if (tsp != NULL) {
    //    lat = ts - *tsp;
    //}
    //bpf_map_delete_elem(&starts, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
