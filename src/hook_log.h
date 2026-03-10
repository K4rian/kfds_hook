#ifndef HOOK_LOG_H
#define HOOK_LOG_H

#include "kfds_hook.h"

// ============================================================================
// LOG
// ============================================================================
void hook_log(hook_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

void hook_log_open(const char* path);
void hook_log_close(void);

#endif /* HOOK_LOG_H */