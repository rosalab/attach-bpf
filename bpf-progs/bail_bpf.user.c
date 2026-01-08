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

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })
struct hist {
    __u32 slots[32];
};

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

struct hist hists;
int main(int argc, char *argv[])
{
    //if (argc != 3) {
    //    printf("Not enough args\n");
    //    printf("Expected: ./load.user bpf_file bpf_prog_name\n");
    //    return -1;
    //}

    char * bpf_path = "bail_bpf.kern.o";
    char * entry = "dummy_fentry";
    char * exit  = "dummy_fexit";
    char * trace = "sys_trace";

    //char * bpf_path = argv[1];
    //char * prog_name = argv[2];

    // Open the shared1.kern object
    struct bpf_object * prog = bpf_object__open(bpf_path);

    signal(SIGINT, sig_handler);
    
    // Try and load this program
    // This should make the map we need
    if (bpf_object__load(prog)) {
        printf("Failed");
        return 0;
    }

    struct bpf_map * map_hist = bpf_object__find_map_by_name(prog, "alloclat.bss");
    struct bpf_map * trace_syscall = bpf_object__find_map_by_name(prog, "trace_syscall");

    struct bpf_program * program_entry = bpf_object__find_program_by_name(prog, entry);
    struct bpf_program * program_exit = bpf_object__find_program_by_name(prog, exit);
    struct bpf_program * sys_trace = bpf_object__find_program_by_name(prog, "sys_trace");

    //bpf_program__set_color(program_entry, 0x2);
    //bpf_program__set_color(program_exit, 0x2);

    //if (program == NULL) {
    //    printf("Shared 1 failed\n");
    //    return 0;
    //}

    printf("PID: %d\n", getpid());

    getchar();
    __u8 one = 1;
    __u8 zero = 0;
    __u32 getcwd = 79;

    for (int i = 0; i < 600; i++) {
        bpf_map__update_elem(trace_syscall, &i, 4, &one, 1, 0);
    }
    //bpf_map__update_elem(trace_syscall, &getcwd, 4, &one, 1, 0);

    //bpf_program__attach(program_entry);
    //bpf_program__attach(program_exit);
    if(!bpf_program__attach(sys_trace)) {
        char err[256];
        libbpf_strerror(errno, err, 256);
        printf("Failed to attach sys_trace: %s\n", err);
    }

    while (1) {
        sleep(1);
        if (exiting)
            break;
    }

    int idx = 0;
    bpf_map__lookup_elem(map_hist, &idx, 4, &hists, sizeof(hists), 0);
    printf("Printing allocation latency histogram\n");
    print_log2_hist(hists.slots, 32, "usecs");
    return 0;
}
