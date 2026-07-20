#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <fcntl.h>

int main()
{
    int fd[2];

    fd[0] = open("/etc/hosts", O_RDONLY);
    syscall(469);
    fd[1] = open("/etc/legal", O_RDONLY);
    syscall(469);
    close(fd[0]);
    syscall(469);
    close(fd[1]);
    syscall(469);
    return 0;
}

