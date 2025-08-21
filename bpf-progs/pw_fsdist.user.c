#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "trace_helpers.h"
#include "fsdist.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

int exiting = 0;

 
static void sig_handler(int sig) {
    exiting = 1;
}

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (need_plus)
		printf("+");
}

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
	int stars_max = 40, idx_max = -1;
	unsigned int val, val_max = 0;
	unsigned long long low, high;
	int stars, width, i;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0)
			idx_max = i;
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
		idx_max <= 32 ? 19 : 29, val_type);

	if (idx_max <= 32)
		stars = stars_max;
	else
		stars = stars_max / 2;

	for (i = 0; i <= idx_max; i++) {
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		val = vals[i];
		width = idx_max <= 32 ? 10 : 20;
		printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
		print_stars(val, val_max, stars);
		printf("|\n");
	}
}

static char *file_op_names[] = {
	[F_READ] = "read",
	[F_WRITE] = "write",
	[F_OPEN] = "open",
	[F_FSYNC] = "fsync",
	[F_GETATTR] = "getattr",
};

struct hist hists[F_MAX_OP];

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

    struct bpf_map * map_hists = bpf_object__find_map_by_name(prog, "pw_fsdis.bss");
    if (!hists) {
        printf("Not found bss hists\n");
    }
    int idx = 0;
    bpf_map__lookup_elem(map_hists, &idx, 4, hists, sizeof(hists), 0);


    bpf_program__attach_pw(p_read_fentry, p_read_fexit);
    bpf_program__attach_pw(p_write_fentry, p_write_fexit);
    bpf_program__attach_pw(p_open_fentry, p_open_fexit);
    bpf_program__attach_pw(p_sync_fentry, p_sync_fexit);
    bpf_program__attach_pw(p_getattr_fentry,  p_getattr_fexit);

    signal(SIGINT, sig_handler);

    while(1) {
        sleep(1);
        if (exiting)
            break;
    }


    bpf_map__lookup_elem(map_hists, &idx, 4, hists, sizeof(hists), 0);
    
    for (enum fs_file_op op = F_READ; op < F_MAX_OP; op++) {
        struct hist hist = hists[op];
        printf("operation = '%s'\n", file_op_names[op]);
        print_log2_hist(hist.slots, MAX_SLOTS, "msecs");
        printf("\n");
    }


    return 0;
}

