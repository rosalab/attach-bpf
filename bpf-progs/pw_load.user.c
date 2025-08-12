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
    struct bpf_object * prog = bpf_object__open(bpf_path);
    
    // Try and load this program
    // This should make the map we need
    if (bpf_object__load(prog)) {
        printf("Failed");
        return 0;
    }

    struct bpf_program * program1 = bpf_object__find_program_by_name(prog, entry_prog_name);
    struct bpf_program * program2 = bpf_object__find_program_by_name(prog, exit_prog_name);

    if (program1 == NULL || program2 == NULL) {
        printf("Failed to find progs\n");
        return 0;
    }

    printf("PID: %d\n", getpid());

    getchar();

    bpf_program__attach(program1);
    bpf_program__attach(program2);

    while (1) {
        sleep(1);
    }

    return 0;
}
