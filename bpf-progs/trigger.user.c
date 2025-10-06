#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

void main() {
    //open("/dev/null", O_RDONLY);
    getchar();
    char buf[256];
    getcwd(buf, 256);
    while (1) {
        getcwd(buf, 256);
        open("./test_file", O_RDONLY);
        getchar();
    }
}
