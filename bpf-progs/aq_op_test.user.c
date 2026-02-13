/**
 * User program for loading a single generic program and attaching
 * Usage: ./load.user bpf_file bpf_prog_name
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main(int argc, char *argv[])
{
    //if (argc != 3) {
    //    printf("Not enough args\n");
    //    printf("Expected: ./load.user bpf_file bpf_prog_name\n");
    //    return -1;
    //}

    char * bpf_path = "./aq_op_test.kern.o\0";
    char * entry = "operator_test";

    // setup a libbpf_opts struct
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    struct bpf_object * prog = bpf_object__open_file(bpf_path, &open_opts);
    if (!prog) {
        printf("Failed to open program file\n");
        return 0;
    }

    struct bpf_program * program_entry = bpf_object__find_program_by_name(prog, entry);


    // Try and load this program
    // This should make the map we need
    if (bpf_object__load(prog)) {
        printf("Failed");
        return 0;
    }

    int entry_fd = bpf_program__fd(program_entry);

    __u64 syscalls[1] = {469};
    __u64 len = 1;

    union color_palette pal;
    pal.entry_dep.syscalls = syscalls;
    pal.entry_dep.syscalls_len = len;
    
    bpf_set_color_palette(&pal, ENTRY_DEP, entry_fd);

    bpf_program__set_color(program_entry, 0x1, 0x2);

    printf("PID: %d\n", getpid());

    /*
     * Individual attaches become pairwise attachment (not general)
     * bpf_program__attach(program_entry);
     * bpf_program__attach(program_exit);
     */
    bpf_program__attach(program_entry);

    while (1) {
        sleep(1);
    }
    return 0;
}
