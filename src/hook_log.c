#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "hook_config.h"
#include "hook_log.h"
#include "kfds_hook.h"

// ============================================================================
// LOG GLOBAL STATE
// ============================================================================
static FILE *g_log_file = NULL;

// ============================================================================
// LOG
// ============================================================================
static inline void hook_log_ts(FILE *fp) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm_info;
  gmtime_r(&ts.tv_sec, &tm_info);
  char tbuf[32];
  strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm_info);
  fprintf(fp, "[kfds_hook %s.%06ldZ] ", tbuf, ts.tv_nsec / 1000);
}

void hook_log(hook_log_level_t level, const char *fmt, ...) {
  if (level > g_config.log_level)
    return;

  // Re-entrance guard
  static _Thread_local int active = 0;
  if (active)
    return;
  active = 1;

  va_list args;
  fprintf(stderr, "[kfds_hook] ");
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  if (g_log_file) {
    hook_log_ts(g_log_file);
    va_start(args, fmt);
    vfprintf(g_log_file, fmt, args);
    va_end(args);
    fflush(g_log_file);
  }
  active = 0;
}

// ============================================================================
// LOG FILE
// ============================================================================
void hook_log_open(const char *path) {
  hook_log_close();

  g_log_file = fopen(path, "a");
  if (!g_log_file)
    fprintf(stderr, "kfds_hook: warning: could not open log_file %s: %s\n",
            g_config.log_file, strerror(errno));
}

void hook_log_close(void) {
  if (g_log_file) {
    fclose(g_log_file);
    g_log_file = NULL;
  }
}