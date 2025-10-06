#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_process_set_color 467
#define __NR_process_get_color 468

int main(int argc, char* argv[])
{
    int ret;
    if (argc != 2) {
        printf("Usage: ./get_process_color.user PID\n");
        return -1;
    }

    int pid = atoi(argv[1]);     

    unsigned long long pid_color;
    ret = syscall(__NR_process_get_color, pid, &pid_color);
    if (ret == -1) {
        printf("Failed to get color\n");
    }
    else {
        printf("Color of PID %d is %llu\n", pid, pid_color);
    }
    
    return ret;
}
