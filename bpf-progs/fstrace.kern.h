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

