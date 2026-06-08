#ifndef ELFCHECK_H
#define ELFCHECK_H

#include <sys/types.h>

int elf_header_mismatch(pid_t pid, const char *exe_path, unsigned long base_addr);

#endif
