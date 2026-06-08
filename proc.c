#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "proc.h"

int get_exe_path(pid_t pid, char *buf, size_t n)
{
    char link[64];
    ssize_t len;

    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    len = readlink(link, buf, n - 1);
    if (len < 0) return -1;
    buf[len] = '\0';
    return 0;
}

int parse_maps_line(const char *line, struct mem_region *r)
{
    unsigned long offset, inode;
    unsigned int  dev_maj, dev_min;
    char perms[8], path[MAX_PATH];
    int n;

    path[0] = '\0';
    n = sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %511[^\n]",
               &r->start, &r->end, perms, &offset,
               &dev_maj, &dev_min, &inode, path);
    if (n < 5) return -1;

    size_t plen = strlen(path);
    while (plen > 0 && (path[plen-1] == ' ' || path[plen-1] == '\t'))
        path[--plen] = '\0';

    strncpy(r->perms, perms, sizeof(r->perms) - 1);
    r->perms[sizeof(r->perms) - 1] = '\0';
    strncpy(r->path, path, sizeof(r->path) - 1);
    r->path[sizeof(r->path) - 1] = '\0';

    r->is_exec = (perms[2] == 'x');
    r->is_anon = (path[0] == '\0');
    return 0;
}
