/**
 * User program for loading a single generic program and attaching
 * Usage: ./load.user bpf_file bpf_prog_name
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("Not enough args\n");
        printf("Expected: ./load.user bpf_file entry_prog_name exit_prog_name\n");
        return -1;
    }

    char * bpf_path = argv[1];
    char * entry_prog_name = argv[2];
    char * exit_prog_name = argv[3];

    // Open the shared1.kern object
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    open_opts.pw = true;
    struct bpf_object * prog = bpf_object__open_file(bpf_path, &open_opts);
    

    struct bpf_program * program1 = bpf_object__find_program_by_name(prog, entry_prog_name);
    struct bpf_program * program2 = bpf_object__find_program_by_name(prog, exit_prog_name);

    // Mark entry and exit programs
    //
    struct bpf_pw_info entry_info;
    struct bpf_pw_info exit_info;

    entry_info.pw_state = BPF_PW_ENTRY;
    entry_info.pw_stack_size = 8;

    exit_info.pw_state = BPF_PW_EXIT;
    exit_info.pw_stack_size = 8;

    bpf_program__set_pw(program1, &entry_info);
    bpf_program__set_pw(program2, &exit_info);

    bpf_program__set_color(program1, 0x2);
    bpf_program__set_color(program2, 0x2);

    // Mark entry and exit prog/get from annotation
    // Load entry and exit (they are connected together from load time)
    
    // Attach together

    // Try and load this program
    // This should make the map we need
    if (bpf_object__load(prog)) {
        printf("Failed");
        return 0;
    }


    if (program1 == NULL || program2 == NULL) {
        printf("Failed to find progs\n");
        return 0;
    }

    printf("PID: %d\n", getpid());

    getchar();
    
    bpf_program__attach_pw(program1, program2);

//    bpf_program__attach(program1);
 //   bpf_program__attach(program2);

    while (1) {
        sleep(1);
    }

    return 0;
}
