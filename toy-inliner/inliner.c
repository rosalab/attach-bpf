#include <stdlib.h>
#include <stdio.h>

#include <libelf.h>


void main()
{
    if (elf_version(EV_CURRENT) == EV_NONE) {
        printf("Failed to initialize libelf\n");
        exit(-1);
    }
    
    return 0;
}
