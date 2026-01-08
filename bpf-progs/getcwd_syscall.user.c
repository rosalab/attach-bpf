#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

uint64_t run()
{
    struct timespec begin, end;
    char buf[256];
    //int fd = open("/dev/null", O_RDONLY, 0);
    clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
    for (int i = 0; i < 1000000; i++) {
       //read(fd, buf, 128);
       //open("/dev/null", O_RDONLY, 0);
       //syscall(467);
       getcwd(buf, 256);
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);
    //close(fd);

    uint64_t time = (end.tv_sec - begin.tv_sec) * 1000000000UL + (end.tv_nsec - begin.tv_nsec);
    //printf("Time is %lu nanoseconds\n", time);
    return time;
}

int main()
{
    //printf("PID: %d\n", getpid());
    //getchar();
    uint64_t results[10];
    run(); // Cache stuff?
    for (int i = 0; i < 10; i++) {
        results[i] = run();
        printf("%lu\n", results[i]);
    }
    return 0;
}
