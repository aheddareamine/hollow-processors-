#ifndef PROC_H
#define PROC_H

#include <sys/types.h>
#include "detector.h"

int get_exe_path(pid_t pid, char *buf, size_t n);
int parse_maps_line(const char *line, struct mem_region *r);

#endif
