#ifndef LOG_H
#define LOG_H

#include "detector.h"

void log_event(const struct scan_result *r, int sev, const char *msg);

#endif
