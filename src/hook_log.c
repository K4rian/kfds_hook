#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "hook_config.h"
#include "hook_log.h"

// ============================================================================
// LOG DEFINES
// ============================================================================
#define LOG_MAX_BYTES (5 * 1024 * 1024) // 5MB
#define LOG_MAX_ROTATE 5                // keep .1 to .5

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
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// LOG FILE
// ============================================================================
/*
 * Writes an ISO-8601 UTC timestamp with millisecond precision to fp.
 * Format: YYYY-MM-DD HH:MM:SS.mmmZ
 */
static void log_write_timestamp(FILE *fp) {
  struct timespec ts = {0};
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    fprintf(stderr, "[WARN] kfds_hook: clock_gettime failed: %s\n",
            strerror(errno));

  struct tm tm_info;
  gmtime_r(&ts.tv_sec, &tm_info);
  char tbuf[32];
  strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm_info);
  fprintf(fp, "%s.%03ldZ", tbuf, ts.tv_nsec / 1000000);
}

/*
 * Writes a visual separator line with the current timestamp to fp.
 * Used to mark the start of each log session and post-rotation.
 */
static void log_write_separator(FILE *fp) {
  fprintf(fp, "\n================== ");
  log_write_timestamp(fp);
  fprintf(fp, " ==================\n\n");
  fflush(fp);
}

/*
 * Rotate log files if the current log exceeds LOG_MAX_BYTES.
 * Rotation follows the logrotate convention:
 *   X.log.5 deleted
 *   X.log.4 -> X.log.5
 *   ...
 *   X.log.1 -> X.log.2
 *   X.log   -> X.log.1
 * A fresh X.log is then opened.
 *
 * log_file is closed and reopened on rotation.
 * Must be called with log_mutex held.
 */
static void log_rotate(const char *log_path) {
  if (!log_file)
    return;

  // Check current file size
  long size = ftell(log_file);
  if (size < 0) {
    fprintf(stderr, "[WARN] kfds_hook: ftell failed: %s\n", strerror(errno));
    return;
  }
  if (size < LOG_MAX_BYTES)
    return;

  fclose(log_file);
  log_file = NULL;

  // Shift X.log.N -> X.log.N+1, starting from the oldest
  char src[PATH_MAX], dst[PATH_MAX];
  for (int i = LOG_MAX_ROTATE - 1; i >= 1; i--) {
    snprintf(src, sizeof(src), "%s.%d", log_path, i);
    snprintf(dst, sizeof(dst), "%s.%d", log_path, i + 1);
    rename(src, dst); // silent if src doesn't exist
  }

  // X.log -> X.log.1
  snprintf(dst, sizeof(dst), "%s.1", log_path);
  rename(log_path, dst);

  // Open fresh X.log
  log_file = fopen(log_path, "a");
  if (!log_file) {
    fprintf(stderr,
            "[WARN] kfds_hook: could not reopen log after rotation %s: %s\n",
            log_path, strerror(errno));
    return;
  }
  log_write_separator(log_file);
}

/*
 * Opens the log file at path, appending to any existing content.
 * Writes a session separator on success.
 * Called during hook init from a single thread, no locking needed.
 */
void hook_log_open(const char *path) {
  hook_log_close();

  log_file = fopen(path, "a");
  if (!log_file) {
    fprintf(stderr, "[WARN] kfds_hook: could not open log_file %s: %s\n", path,
            strerror(errno));
    return;
  }
  log_write_separator(log_file);
}

/*
 * Closes the log file if open.
 * Called during hook teardown from a single thread, no locking needed.
 */
void hook_log_close(void) {
  if (log_file) {
    fclose(log_file);
    log_file = NULL;
  }
}

// ============================================================================
// LOG
// ============================================================================
/*
 * Writes a log message at the given level to stderr and, if open, to the
 * log file. Messages below the user-defined log level are discarded.
 *
 * File format:   [kfds_hook] <DATE> [<PREFIX>] <MESSAGE>
 * stderr format: [kfds_hook] [<PREFIX>] <MESSAGE>
 *
 * Thread-safe: log_mutex serialises access to log_file across threads.
 * The _Thread_local re-entrance guard prevents recursive logging within
 * the same thread (e.g. if a logging helper itself calls hook_log).
 */
void hook_log(hook_log_level_t level, const char *fmt, ...) {
  if (level < g_config.log_level)
    return;

  // Re-entrance guard: prevents recursive logging within the same thread
  static _Thread_local int active = 0;
  if (active)
    return;
  active = 1;

  // Lock before any access to the log file
  pthread_mutex_lock(&log_mutex);

  if (log_file)
    log_rotate(g_config.log_file);

  const char *prefix = (level < (hook_log_level_t)(sizeof(log_prefixes) /
                                                   sizeof(log_prefixes[0])))
                           ? log_prefixes[level]
                           : "?????";
  FILE *targets[2];
  int ntargets = 0;

  targets[ntargets++] = stderr;
  if (log_file)
    targets[ntargets++] = log_file;

  for (int i = 0; i < ntargets; i++) {
    va_list args;
    va_start(args, fmt);

    if (targets[i] == log_file) {
      fprintf(targets[i], "[kfds_hook] ");
      log_write_timestamp(targets[i]);
      fprintf(targets[i], " [%s] ", prefix);
    } else {
      fprintf(targets[i], "[kfds_hook] [%s] ", prefix);
    }

    vfprintf(targets[i], fmt, args);
    va_end(args);

    if (targets[i] == log_file)
      fflush(log_file);
  }
  pthread_mutex_unlock(&log_mutex);
  active = 0;
}