#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include "scanner.h"
#include "proc.h"
#include "elfcheck.h"
#include "log.h"

int check_process(pid_t pid, struct scan_result *result)
{
    char maps_path[64];
    FILE *maps;
    char line[MAX_LINE];
    struct mem_region region;
    unsigned long base_addr = 0;
    int found_base = 0;

    memset(result, 0, sizeof(*result));
    result->pid = pid;

    if (get_exe_path(pid, result->exe, sizeof(result->exe)) < 0)
        strncpy(result->exe, "<no exe>", sizeof(result->exe) - 1);

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    maps = fopen(maps_path, "r");
    if (!maps) return -1;

    while (fgets(line, sizeof(line), maps)) {
        if (parse_maps_line(line, &region) < 0) continue;
        if (!region.is_exec) continue;

        if (!found_base && !region.is_anon && region.path[0] == '/' &&
            strcmp(region.path, result->exe) == 0) {
            base_addr  = region.start;
            found_base = 1;
            if (g_verbose)
                printf("  [%d] base=0x%lx  %s\n", pid, base_addr, region.path);
        }

        if (region.is_anon) {
            result->anon_exec_count++;
            if (g_verbose)
                printf("  [%d] anon-exec  0x%lx-0x%lx  %s\n",
                       pid, region.start, region.end, region.perms);
        }
    }
    fclose(maps);

    if (found_base && result->exe[0] == '/') {
        result->elf_mismatch = elf_header_mismatch(pid, result->exe, base_addr);
        if (result->elf_mismatch && g_verbose)
            printf("  [%d] ELF header mismatch!\n", pid);
    }

    result->suspicious = (result->elf_mismatch || result->anon_exec_count > 0);
    return 0;
}

void scan_all_processes(void)
{
    DIR *proc_dir;
    struct dirent *entry;
    struct scan_result result;
    char *endp;
    pid_t pid;
    int total = 0, flagged = 0;

    printf("[*] Scanning all processes...\n\n");

    proc_dir = opendir("/proc");
    if (!proc_dir) { perror("opendir /proc"); return; }

    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;
        pid = (pid_t)strtol(entry->d_name, &endp, 10);
        if (*endp != '\0' || pid <= 0 || pid == getpid()) continue;

        if (check_process(pid, &result) < 0) continue;
        total++;

        if (result.suspicious) {
            char msg[128];
            flagged++;
            if (result.elf_mismatch)
                log_event(&result, SEV_ALERT, "ELF header mismatch in memory");
            if (result.anon_exec_count > 0) {
                snprintf(msg, sizeof(msg), "anonymous executable regions: %d",
                         result.anon_exec_count);
                log_event(&result, SEV_WARN, msg);
            }
        } else if (g_verbose) {
            log_event(&result, SEV_INFO, "clean");
        }
    }
    closedir(proc_dir);

    printf("\n[*] Done — %d processes scanned, %d suspicious.\n", total, flagged);
}
