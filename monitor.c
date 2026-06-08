#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "monitor.h"
#include "detector.h"
#include "proc.h"
#include "log.h"

static volatile int g_running = 1;

static void on_sigint(int sig) { (void)sig; g_running = 0; }

void monitor_process(pid_t pid)
{
    int status;
    struct user_regs_struct regs;
    int attached = 0;
    int on_entry = 1;
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

        if (!on_entry) { on_entry = 1; continue; }
        on_entry = 0;

#ifdef __x86_64__
        long nr   = (long)regs.orig_rax;
        long prot = (long)regs.rdx;
#else
        long nr   = (long)regs.orig_eax;
        long prot = (long)regs.edx;
#endif

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
