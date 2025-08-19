#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int main()
{
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    open_opts.pw = true;
    struct bpf_object * prog = bpf_object__open_file("./pw_fsdist.kern.o\0", &open_opts);
    
    struct bpf_program * p_read_fentry = bpf_object__find_program_by_name(prog, "file_read_fentry");
    struct bpf_program * p_write_fentry = bpf_object__find_program_by_name(prog, "file_write_fentry");
    struct bpf_program * p_open_fentry = bpf_object__find_program_by_name(prog, "file_open_fentry");
    struct bpf_program * p_sync_fentry = bpf_object__find_program_by_name(prog, "file_sync_fentry");
    struct bpf_program * p_getattr_fentry = bpf_object__find_program_by_name(prog, "getattr_fentry");

    struct bpf_program * p_read_fexit = bpf_object__find_program_by_name(prog, "file_read_fexit");
    struct bpf_program * p_write_fexit = bpf_object__find_program_by_name(prog, "file_write_fexit");
    struct bpf_program * p_open_fexit = bpf_object__find_program_by_name(prog, "file_open_fexit");
    struct bpf_program * p_sync_fexit = bpf_object__find_program_by_name(prog, "file_sync_fexit");
    struct bpf_program * p_getattr_fexit = bpf_object__find_program_by_name(prog, "getattr_fexit");

    struct bpf_pw_info entry_info;
    entry_info.pw_state = BPF_PW_ENTRY;
    entry_info.pw_stack_size = 8;

    struct bpf_pw_info exit_info;
    exit_info.pw_state = BPF_PW_EXIT;
    exit_info.pw_stack_size = 8;

    bpf_program__set_pw(p_read_fentry, &entry_info);
    bpf_program__set_pw(p_write_fentry, &entry_info);
    bpf_program__set_pw(p_open_fentry, &entry_info);
    bpf_program__set_pw(p_sync_fentry, &entry_info);
    bpf_program__set_pw(p_getattr_fentry, &entry_info);

    bpf_program__set_pw(p_read_fexit, &exit_info);
    bpf_program__set_pw(p_write_fexit, &exit_info);
    bpf_program__set_pw(p_open_fexit, &exit_info);
    bpf_program__set_pw(p_sync_fexit, &exit_info);
    bpf_program__set_pw(p_getattr_fexit, &exit_info);

    bpf_object__load(prog);

    bpf_program__attach_pw(p_read_fentry, p_read_fexit);
    bpf_program__attach_pw(p_write_fentry, p_write_fexit);
    bpf_program__attach_pw(p_open_fentry, p_open_fexit);
    bpf_program__attach_pw(p_sync_fentry, p_sync_fexit);
    bpf_program__attach_pw(p_getattr_fentry,  p_getattr_fexit);

    while(1) {
        sleep(1);
    }
    return 0;
}

