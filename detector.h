#ifndef DETECTOR_H
#define DETECTOR_H

#include <stdio.h>
#include <sys/types.h>

#define MAX_PATH  512
#define MAX_LINE 1024

#define SEV_INFO  0
#define SEV_WARN  1
#define SEV_ALERT 2

struct mem_region {
    unsigned long start;
    unsigned long end;
    char perms[8];
    char path[MAX_PATH];
    int  is_exec;
    int  is_anon;
};

struct scan_result {
    pid_t pid;
    char  exe[MAX_PATH];
    int   anon_exec_count;
    int   elf_mismatch;
    int   suspicious;
};

extern int   g_verbose;
extern FILE *g_report_fp;

#endif
