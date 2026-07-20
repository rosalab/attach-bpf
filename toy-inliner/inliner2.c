#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

#include <stdlib.h>

void func()
{
}

void pr()
{
    printf("Output\n");
}

void instrument_func()
{
    char bytes[5];
    bytes[0] = 0xE9;    
    int offset = (func + 5) - pr;
    printf("offset is: %d\n", offset);
    memcpy(bytes+1, &offset, 4);
    memcpy(func, bytes, 5);
}


int main()
{
    printf("func: %x &func: %x\n", func, &func);
    printf("func mask %x\n", (unsigned long)func & ~(0xfff));
    if (mprotect((unsigned long)func & ~(0xfff) , 100, PROT_WRITE));
        perror(NULL);

    instrument_func();


    printf("Instrumented function\n");
    func();
    return 0;
}
