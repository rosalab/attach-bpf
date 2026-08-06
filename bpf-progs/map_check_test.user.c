#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "map_check_test.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int err;
    int prog_fd = -1;

    struct bpf_bytecode_annotation ann;
    ann.insn_off = 4;
    ann.btf_id = 12;

    /* Set up signal handlers for graceful exit */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Enable libbpf strict mode for modern (>= v1.0) API behavior */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /* 
     * 1. Open the BPF ELF object file.
     * This parses the object file but does not load it into the kernel yet.
     */
    obj = bpf_object__open_file("map_check_test.kern.o", NULL);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Failed to open BPF object file: %d\n", err);
        return 1;
    }

    /* 
     * 2. Find the specific BPF program by its function name.
     * Note: In modern BPF, programs are found by their function name, 
     * not their ELF section name.
     */
    prog = bpf_object__find_program_by_name(obj, "map_check_test");
    if (!prog) {
        fprintf(stderr, "Failed to find program 'map_check_test' in the object file.\n");
        err = -ENOENT;
        goto cleanup;
    }

    if (bpf_program__set_annotations(prog, &ann, 1))
        printf("Failed to set annotations for prog\n");


    /* 
     * 3. Load the BPF object into the kernel.
     * This step loads the programs AND any maps defined in the object file.
     */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object into kernel: %d\n", err);
        goto cleanup;
    }

    /* 4. Retrieve the file descriptor assigned by the kernel to the program */
    prog_fd = bpf_program__fd(prog);
    
    printf("Successfully loaded BPF program 'map_check_test'.\n");
    printf("Kernel Program File Descriptor: %d\n", prog_fd);
    printf("Holding program and maps open. Press Ctrl+C to exit...\n");

    /* Infinite loop until interrupted by SIGINT (Ctrl+C) or SIGTERM */
    while (!exiting) {
        sleep(1);
    }

    printf("\nReceived interrupt signal. Cleaning up...\n");

cleanup:
    /* 
     * Close the BPF object. This decrements the reference count of the 
     * programs and maps in the kernel. If the refcount hits zero, the 
     * kernel automatically cleans them up.
     */
    bpf_object__close(obj);
    
    return err ? 1 : 0;
}
