#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_process_set_color 467
#define __NR_process_get_color 468

int main(int argc, char* argv[])
{
    if (argc != 3) {
        printf("Usage: ./set_process_color.user PID COLOR\n");
        return -1;
    }

    int pid = atoi(argv[1]);     
    unsigned long long color;
    color = strtoull(argv[2], NULL, 0); 

    printf("PID is %d\nColor is %llu\n", pid, color);

    int ret = syscall(__NR_process_set_color, pid, color);
    if (ret == -1) {
        printf("Failed to set color\n");
    }

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
