#include <stdio.h>
#include <time.h>
#include "log.h"

void log_event(const struct scan_result *r, int sev, const char *msg)
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
