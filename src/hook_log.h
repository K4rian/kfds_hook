#ifndef HOOK_LOG_H
#define HOOK_LOG_H

// ============================================================================
// LOG TYPES
// ============================================================================
typedef enum {
  HOOK_LOG_LEVEL_DEBUG = 0,
  HOOK_LOG_LEVEL_INFO = 1,
  HOOK_LOG_LEVEL_WARN = 2,
  HOOK_LOG_LEVEL_ERROR = 3,
  HOOK_LOG_LEVEL_SILENT = 4
} hook_log_level_t;

// ============================================================================
// LOG FILE
// ============================================================================
void hook_log_open(const char *path);
void hook_log_close(void);

// ============================================================================
// LOG
// ============================================================================
void hook_log(hook_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define hook_log_debug(...) hook_log(HOOK_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define hook_log_info(...) hook_log(HOOK_LOG_LEVEL_INFO, __VA_ARGS__)
#define hook_log_warn(...) hook_log(HOOK_LOG_LEVEL_WARN, __VA_ARGS__)
#define hook_log_error(...) hook_log(HOOK_LOG_LEVEL_ERROR, __VA_ARGS__)

#endif /* HOOK_LOG_H */