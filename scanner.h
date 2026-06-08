#ifndef SCANNER_H
#define SCANNER_H

#include <sys/types.h>
#include "detector.h"

int  check_process(pid_t pid, struct scan_result *result);
void scan_all_processes(void);

#endif
