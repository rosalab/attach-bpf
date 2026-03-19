#include <stdio.h>
#include <fcntl.h>

int main()
{
    int fd = open("test_file", O_RDWR);
    printf("FD is: %d\n", fd);
    return 0;
}
