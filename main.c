#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "detector.h"
#include "scanner.h"
#include "monitor.h"
#include "log.h"

int   g_verbose   = 0;
FILE *g_report_fp = NULL;

static void usage(const char *prog)
{
    printf("Usage: sudo %s [OPTIONS]\n\n", prog);
    printf("  -p <PID>          Scan or monitor a specific process\n");
    printf("  -v                Verbose output\n");
    printf("  --monitor         Monitor syscalls via ptrace (requires -p)\n");
    printf("  --report <file>   Write detections to a JSON file\n");
    printf("  -h                Show this help\n\n");
    printf("Examples:\n");
    printf("  sudo %s\n", prog);
    printf("  sudo %s -v -p 1234\n", prog);
    printf("  sudo %s -p 1234 --monitor\n", prog);
    printf("  sudo %s --report scan.json\n\n", prog);
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
        case 'v': g_verbose   = 1;      break;
        case 'm': do_monitor  = 1;      break;
        case 'r': report_path = optarg; break;
        case 'h': usage(argv[0]);       return 0;
        default:  usage(argv[0]);       return 1;
        }
    }

    if (geteuid() != 0)
        fprintf(stderr, "[!] Not running as root — some checks may fail.\n\n");

    if (report_path) {
        g_report_fp = fopen(report_path, "w");
        if (!g_report_fp) { perror("fopen"); return 1; }
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
