#define _GNU_SOURCE
/*
 * detector.c  —  Process Hollowing Detection System
 *
 * Detects process hollowing on Linux by:
 *   1. Comparing ELF headers between the on-disk binary and its loaded
 *      memory image via /proc/<pid>/mem
 *   2. Flagging truly anonymous (no backing file) executable memory regions,
 *      which have no legitimate reason to exist in normal processes
 *
 * Requires root (or CAP_SYS_PTRACE + CAP_SYS_ADMIN).
 *
 * Build:  make
 * Usage:  sudo ./detector [-v] [-p PID] [--monitor] [--report file.json]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <elf.h>

#define MAX_PATH   512
#define MAX_LINE  1024

#define SEV_INFO   0
#define SEV_WARN   1
#define SEV_ALERT  2

/* Globals set by CLI flags */
static int    g_verbose   = 0;
static FILE  *g_report_fp = NULL;
static volatile int g_running = 1;

/* One entry from /proc/<pid>/maps */
struct mem_region {
    unsigned long start;
    unsigned long end;
    char  perms[8];
    char  path[MAX_PATH];
    int   is_exec;
    int   is_anon;   /* 1 = no backing file at all */
};

/* Per-process scan result */
struct scan_result {
    pid_t pid;
    char  exe[MAX_PATH];
    int   anon_exec_count;
    int   elf_mismatch;
    int   suspicious;
};

/* ── Logging ────────────────────────────────────────────────────────── */

static void log_event(const struct scan_result *r, int sev, const char *msg)
{
    static const char *labels[] = { "INFO ", "WARN ", "ALERT" };
    char ts[16];
    time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));

    printf("[%s] [%s] pid=%-6d  %-35s  %s\n",
           ts, labels[sev], r->pid, r->exe, msg);

    if (g_report_fp)
        fprintf(g_report_fp,
                "{\"time\":\"%s\",\"level\":\"%s\",\"pid\":%d,"
                "\"exe\":\"%s\",\"msg\":\"%s\"}\n",
                ts, labels[sev], r->pid, r->exe, msg);
}

/* ── /proc helpers ──────────────────────────────────────────────────── */

static int get_exe_path(pid_t pid, char *buf, size_t n)
{
    char link[64];
    ssize_t len;

    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    len = readlink(link, buf, n - 1);
    if (len < 0) return -1;
    buf[len] = '\0';
    return 0;
}

/*
 * Parse one line from /proc/<pid>/maps.
 * Format: address perms offset dev inode [pathname]
 */
static int parse_maps_line(const char *line, struct mem_region *r)
{
    unsigned long offset, inode;
    unsigned int  dev_maj, dev_min;
    char perms[8], path[MAX_PATH];
    int  n;

    path[0] = '\0';
    n = sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %511[^\n]",
               &r->start, &r->end, perms,
               &offset, &dev_maj, &dev_min, &inode, path);
    if (n < 5) return -1;

    /* strip trailing spaces that may appear between inode and empty path */
    size_t plen = strlen(path);
    while (plen > 0 && (path[plen-1] == ' ' || path[plen-1] == '\t'))
        path[--plen] = '\0';

    strncpy(r->perms, perms, sizeof(r->perms) - 1);
    r->perms[sizeof(r->perms) - 1] = '\0';
    strncpy(r->path, path, sizeof(r->path) - 1);
    r->path[sizeof(r->path) - 1] = '\0';

    r->is_exec = (perms[2] == 'x');
    r->is_anon = (path[0] == '\0');   /* [vdso], [stack] etc. have names */
    return 0;
}

/* ── ELF header comparison ──────────────────────────────────────────── */

/*
 * Read sizeof(Elf64_Ehdr) bytes from /proc/<pid>/mem at base_addr
 * and compare the invariant fields against the on-disk binary.
 *
 * Returns 1 if a mismatch is detected, 0 if clean or unreadable.
 * We skip rather than false-positive on permission/read errors.
 */
static int elf_header_mismatch(pid_t pid, const char *exe_path,
                                unsigned long base_addr)
{
    Elf64_Ehdr disk_hdr, mem_hdr;
    char mem_path[64];
    int  fd;
    ssize_t n;

    fd = open(exe_path, O_RDONLY);
    if (fd < 0) return 0;
    n = read(fd, &disk_hdr, sizeof(disk_hdr));
    close(fd);
    if (n != (ssize_t)sizeof(disk_hdr)) return 0;

    /* skip non-ELF files (scripts, etc.) */
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

    /*
     * These fields are written once at load time and never legitimately
     * changed afterwards.  Any difference means the image was tampered.
     */
    if (memcmp(disk_hdr.e_ident, mem_hdr.e_ident, EI_NIDENT) != 0) return 1;
    if (disk_hdr.e_type    != mem_hdr.e_type)    return 1;
    if (disk_hdr.e_machine != mem_hdr.e_machine) return 1;

    return 0;
}

/* ── Single-process scan ────────────────────────────────────────────── */

static int check_process(pid_t pid, struct scan_result *result)
{
    char   maps_path[64];
    FILE  *maps;
    char   line[MAX_LINE];
    struct mem_region region;
    unsigned long base_addr = 0;
    int    found_base = 0;

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

        /* first executable file-backed region that matches the exe = base */
        if (!found_base && !region.is_anon && region.path[0] == '/' &&
            strcmp(region.path, result->exe) == 0) {
            base_addr  = region.start;
            found_base = 1;
            if (g_verbose)
                printf("  [%d] base=0x%lx  %s\n", pid, base_addr, region.path);
        }

        /* truly anonymous + executable is highly suspicious */
        if (region.is_anon) {
            result->anon_exec_count++;
            if (g_verbose)
                printf("  [%d] anon-exec  0x%lx-0x%lx  %s\n",
                       pid, region.start, region.end, region.perms);
        }
    }
    fclose(maps);

    if (found_base && result->exe[0] == '/') {
        result->elf_mismatch =
            elf_header_mismatch(pid, result->exe, base_addr);
        if (result->elf_mismatch && g_verbose)
            printf("  [%d] ELF header mismatch!\n", pid);
    }

    result->suspicious = (result->elf_mismatch || result->anon_exec_count > 0);
    return 0;
}

/* ── Full scan ──────────────────────────────────────────────────────── */

static void scan_all_processes(void)
{
    DIR *proc_dir;
    struct dirent *entry;
    struct scan_result result;
    char  *endp;
    pid_t  pid;
    int    total = 0, flagged = 0;

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
                snprintf(msg, sizeof(msg),
                         "anonymous executable regions: %d",
                         result.anon_exec_count);
                log_event(&result, SEV_WARN, msg);
            }
        } else if (g_verbose) {
            log_event(&result, SEV_INFO, "clean");
        }
    }
    closedir(proc_dir);

    printf("\n[*] Done — %d processes scanned, %d suspicious.\n",
           total, flagged);
}

/* ── ptrace monitor ─────────────────────────────────────────────────── */

static void on_sigint(int sig) { (void)sig; g_running = 0; }

/*
 * Attach to pid and watch for mmap(PROT_EXEC) and mprotect(PROT_EXEC).
 * PTRACE_SYSCALL fires twice per syscall: once on entry, once on exit.
 * We use a toggle to only inspect the entry stop.
 */
static void monitor_process(pid_t pid)
{
    int status;
    struct user_regs_struct regs;
    int attached  = 0;
    int on_entry  = 1;
    char path[64];

    snprintf(path, sizeof(path), "/proc/%d", pid);
    if (access(path, F_OK) != 0) {
        fprintf(stderr, "[-] PID %d not found\n", pid);
        return;
    }

    printf("[*] Attaching to PID %d...\n", pid);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace attach");
        return;
    }

    if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
        fprintf(stderr, "[-] Could not stop PID %d\n", pid);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    attached = 1;
    printf("[*] Attached. Watching syscalls (Ctrl-C to stop)...\n\n");
    signal(SIGINT, on_sigint);

    ptrace(PTRACE_SETOPTIONS, pid, 0,
           PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);

    while (g_running) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) break;
        if (waitpid(pid, &status, 0) < 0) break;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("[*] PID %d exited.\n", pid);
            attached = 0;
            break;
        }
        if (!WIFSTOPPED(status)) continue;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) continue;

        if (!on_entry) { on_entry = 1; continue; }   /* skip exit stop */
        on_entry = 0;

#ifdef __x86_64__
        long nr   = (long)regs.orig_rax;
        long prot = (long)regs.rdx;       /* 3rd arg */
#else
        long nr   = (long)regs.orig_eax;
        long prot = (long)regs.edx;
#endif

        /* syscall 9 = mmap, syscall 10 = mprotect; PROT_EXEC = 0x4 */
        if ((nr == 9 || nr == 10) && (prot & 0x4)) {
            struct scan_result tmp;
            memset(&tmp, 0, sizeof(tmp));
            tmp.pid = pid;
            get_exe_path(pid, tmp.exe, sizeof(tmp.exe));
            log_event(&tmp,
                      (nr == 10) ? SEV_ALERT : SEV_WARN,
                      (nr == 10) ? "mprotect(PROT_EXEC)" : "mmap(PROT_EXEC)");
        }
    }

    if (attached)
        ptrace(PTRACE_DETACH, pid, NULL, NULL);

    printf("[*] Detached from PID %d.\n", pid);
}

/* ── main ───────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    printf("Usage: sudo %s [OPTIONS]\n\n", prog);
    printf("  -p <PID>          Scan or monitor a specific process\n");
    printf("  -v                Verbose output\n");
    printf("  --monitor         Monitor syscalls via ptrace (requires -p)\n");
    printf("  --report <file>   Write detections to a JSON file\n");
    printf("  -h                Show this help\n\n");
    printf("Examples:\n");
    printf("  sudo %s                       # scan all processes\n", prog);
    printf("  sudo %s -v -p 1234            # verbose scan of one PID\n", prog);
    printf("  sudo %s -p 1234 --monitor     # live ptrace monitor\n", prog);
    printf("  sudo %s --report scan.json    # save findings to JSON\n\n", prog);
}

int main(int argc, char *argv[])
{
    pid_t  target      = 0;
    int    do_monitor  = 0;
    char  *report_path = NULL;
    int    opt;
    struct scan_result result;

    static struct option long_opts[] = {
        { "monitor", no_argument,       NULL, 'm' },
        { "report",  required_argument, NULL, 'r' },
        { "help",    no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "p:vmhr:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            target = (pid_t)atoi(optarg);
            if (target <= 0) {
                fprintf(stderr, "[-] Invalid PID: %s\n", optarg);
                return 1;
            }
            break;
        case 'v': g_verbose  = 1;       break;
        case 'm': do_monitor = 1;       break;
        case 'r': report_path = optarg; break;
        case 'h': usage(argv[0]);       return 0;
        default:  usage(argv[0]);       return 1;
        }
    }

    if (geteuid() != 0)
        fprintf(stderr,
                "[!] Warning: not running as root — some checks may fail.\n\n");

    if (report_path) {
        g_report_fp = fopen(report_path, "w");
        if (!g_report_fp) { perror("fopen report"); return 1; }
        printf("[*] Saving report to: %s\n\n", report_path);
    }

    if (do_monitor) {
        if (target <= 0) {
            fprintf(stderr, "[-] --monitor requires -p <PID>\n");
            if (g_report_fp) fclose(g_report_fp);
            return 1;
        }
        monitor_process(target);
    } else if (target > 0) {
        printf("[*] Scanning PID %d...\n\n", target);
        if (check_process(target, &result) < 0) {
            fprintf(stderr, "[-] Cannot read PID %d\n", target);
            if (g_report_fp) fclose(g_report_fp);
            return 1;
        }
        if (result.suspicious) {
            if (result.elf_mismatch)
                log_event(&result, SEV_ALERT, "ELF header mismatch in memory");
            if (result.anon_exec_count > 0) {
                char msg[64];
                snprintf(msg, sizeof(msg), "anonymous executable regions: %d",
                         result.anon_exec_count);
                log_event(&result, SEV_WARN, msg);
            }
        } else {
            log_event(&result, SEV_INFO, "no hollowing indicators found");
        }
    } else {
        scan_all_processes();
    }

    if (g_report_fp) {
        fclose(g_report_fp);
        printf("[*] Report saved.\n");
    }

    return 0;
}
