#include <stdio.h>

int my_func() __attribute__ ((section ("MYFUN")));

int my_func() {
    return 1;
}

int main() {
    printf("Res is: %d\n", my_func());
    return 0;
}

