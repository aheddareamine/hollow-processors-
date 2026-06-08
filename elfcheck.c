#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdio.h>
#include "elfcheck.h"

int elf_header_mismatch(pid_t pid, const char *exe_path, unsigned long base_addr)
{
    Elf64_Ehdr disk_hdr, mem_hdr;
    char mem_path[64];
    int fd;
    ssize_t n;

    fd = open(exe_path, O_RDONLY);
    if (fd < 0) return 0;
    n = read(fd, &disk_hdr, sizeof(disk_hdr));
    close(fd);
    if (n != (ssize_t)sizeof(disk_hdr)) return 0;
    if (memcmp(disk_hdr.e_ident, ELFMAG, SELFMAG) != 0) return 0;

    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    fd = open(mem_path, O_RDONLY);
    if (fd < 0) return 0;

    if (lseek(fd, (off_t)base_addr, SEEK_SET) == (off_t)-1) {
        close(fd);
        return 0;
    }
    n = read(fd, &mem_hdr, sizeof(mem_hdr));
    close(fd);
    if (n != (ssize_t)sizeof(mem_hdr)) return 0;

    if (memcmp(disk_hdr.e_ident, mem_hdr.e_ident, EI_NIDENT) != 0) return 1;
    if (disk_hdr.e_type    != mem_hdr.e_type)    return 1;
    if (disk_hdr.e_machine != mem_hdr.e_machine) return 1;

    return 0;
}
