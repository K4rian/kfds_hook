#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "hook_config.h"
#include "hook_log.h"

// ============================================================================
// LOG STATIC STATE
// ============================================================================
static const char *const log_prefixes[] = {
    [HOOK_LOG_LEVEL_DEBUG] = "DEBUG",
    [HOOK_LOG_LEVEL_INFO] = "INFO ",
    [HOOK_LOG_LEVEL_WARN] = "WARN ",
    [HOOK_LOG_LEVEL_ERROR] = "ERROR",
};
static FILE *log_file = NULL;

// ============================================================================
// LOG
// ============================================================================
static void hook_log_ts(FILE *fp) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm_info;
  gmtime_r(&ts.tv_sec, &tm_info);
  char tbuf[32];
  strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm_info);
  fprintf(fp, "%s.%06ldZ", tbuf, ts.tv_nsec / 1000);
}

void hook_log(hook_log_level_t level, const char *fmt, ...) {
  if (level < g_config.log_level)
    return;

  // Re-entrance guard
  static _Thread_local int active = 0;
  if (active)
    return;
  active = 1;

  const char *prefix = (level < (hook_log_level_t)(sizeof(log_prefixes) /
                                                   sizeof(log_prefixes[0])))
                           ? log_prefixes[level]
                           : "?????";
  FILE *targets[2];
  int ntargets = 0;
  if (level >= HOOK_LOG_LEVEL_WARN || log_file == NULL)
    targets[ntargets++] = stderr;
  if (log_file)
    targets[ntargets++] = log_file;

  for (int i = 0; i < ntargets; i++) {
    va_list args;
    fprintf(targets[i], "[kfds_hook ");
    hook_log_ts(targets[i]);
    fprintf(targets[i], "] [%s] ", prefix);
    va_start(args, fmt);
    vfprintf(targets[i], fmt, args);
    va_end(args);
    if (targets[i] == log_file)
      fflush(log_file);
  }
  active = 0;
}

// ============================================================================
// LOG FILE
// ============================================================================
void hook_log_open(const char *path) {
  hook_log_close();

  log_file = fopen(path, "a");
  if (!log_file)
    fprintf(stderr, "[WARN] kfds_hook: could not open log_file %s: %s\n", path,
            strerror(errno));
}

void hook_log_close(void) {
  if (log_file) {
    fclose(log_file);
    log_file = NULL;
  }
}