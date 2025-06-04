#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include <gelf.h>

void display_bytes(char *bytes, int len)
{
    char * p = bytes;
    while (p < (char *) bytes + len) {
        printf("%02x", *(unsigned short *)p & 0x000000ff);
        p++;
    }
    printf("\n");
}

void extract_bytes(int fd, char **bytes, int *len)
{
    Elf *e;
    Elf_Scn *scn;
    Elf_Data *data;
    GElf_Shdr shdr;
    size_t n, shstrndx, sz;
    char * name;
    char * p;

    e = elf_begin(fd, ELF_C_READ, NULL);
    elf_getshdrstrndx(e, &shstrndx);

    scn = NULL;
    while ((scn = elf_nextscn(e, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        name = elf_strptr(e, shstrndx, shdr.sh_name);
        if (!strcmp(name, ".text\0")) {
            printf("name is %s\n", name);
            printf("section header size: %lu\n", shdr.sh_size);

            data = NULL;
            data = elf_rawdata(scn, data);
            if (data == NULL) {
                printf("NULL Data\n");
                break;
            }
            p = (char *) data->d_buf;
            *bytes = calloc(1, data->d_size);
            printf("len: %lu\n", data->d_size);
            *len = data->d_size;
            memcpy(*bytes, p, data->d_size);
            printf("Found .text section\n");
            display_bytes(p, data->d_size);
            break;
        }
    }
    elf_end(e);
    close(fd);
}

int main(int argc, char *argv[])
{
    if (elf_version(EV_CURRENT) == EV_NONE) {
        printf("Failed to initialize libelf\n");
        exit(-1);
    }

    if (argc != 5) {
        printf("Usage: ./inliner main entry exit output\n");
        exit(-1);
    }

    char * entry;
    char * exit;
    char * main;

    int entry_len;
    int exit_len;
    int main_len;

    int main_fd = open(argv[1], O_RDONLY);
    int entry_fd = open(argv[2], O_RDONLY);
    int exit_fd = open(argv[3], O_RDONLY);

    extract_bytes(main_fd, &main, &main_len);
    extract_bytes(entry_fd, &entry, &entry_len);
    extract_bytes(exit_fd, &exit, &exit_len);

    display_bytes(main, main_len);
    display_bytes(entry, entry_len);
    display_bytes(exit, exit_len);
    
    return 0;
}
