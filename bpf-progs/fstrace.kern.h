 //       field:unsigned short common_type;       offset:0;       size:2; signed:0;
 //       field:unsigned char common_flags;       offset:2;       size:1; signed:0;
 //       field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
 //       field:int common_pid;   offset:4;       size:4; signed:1;

 //       field:int __syscall_nr; offset:8;       size:4; signed:1;
 //       field:unsigned int fd;  offset:16;      size:8; signed:0;
 //       field:char * buf;       offset:24;      size:8; signed:0;
 //       field:size_t count;     offset:32;      size:8; signed:0;

struct read_ctx {
    char empty[8];
    unsigned int fd;
    char * buf;
    size_t count;
};
/*
name: sys_enter_open
ID: 713
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char * filename;    offset:16;      size:8; signed:0;
        field:int flags;        offset:24;      size:8; signed:0;
        field:umode_t mode;     offset:32;      size:8; signed:0;

print fmt: "filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
root@q:/linux-dev-env# cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_open/format
name: sys_exit_open
ID: 712
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret
*/

struct open_enter_ctx {
    char _[16];
    const char * filename;
};

struct open_exit_ctx {
    char _[16];
    long fd;
};
    
    
