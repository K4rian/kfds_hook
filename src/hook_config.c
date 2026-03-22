#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hook_config.h"
#include "hook_log.h"
#include "hook_sha256.h"
#include "inih/ini.h"

// ============================================================================
// CONFIG GLOBAL STATE
// ============================================================================
hook_config_t g_config = {
    .hook_enabled = 1,
    .security_patch = 1,
    .ucc_checksum = KFDS_UCC_CHECKSUM,
#ifdef DEBUG
    .log_level = HOOK_LOG_LEVEL_DEBUG,
#else
    .log_level = HOOK_LOG_LEVEL_INFO,
#endif
    .log_file = "",
    .heartbeat_interval = 0,
    .socket_path = "/tmp/kfds_hook.sock",
    .socket_maxpoll = 10,
    .socket_deadline = 2,
    .debug_dump_dir = "./dump",
};

// ============================================================================
// CONFIG HANDLER
// ============================================================================
/*
 * Called once per key/value pair found in the config file.
 * Populates the hook_config_t pointed to by user.
 * Returns 1 to continue parsing, 0 to abort.
 * Unknown keys are silently ignored to allow forward-compatible config files.
 */
static int config_handler(void *user, const char *section, const char *name,
                          const char *value) {
  hook_config_t *c = (hook_config_t *)user;
  if (!name || !value)
    return 1; // section header, skip

#define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)
  if (MATCH("hook", "hook_enabled")) {
    c->hook_enabled = atoi(value);
  } else if (MATCH("hook", "security_patch")) {
    c->security_patch = atoi(value);
  } else if (MATCH("hook", "ucc_checksum")) {
    strncpy(c->ucc_checksum, value, sizeof(c->ucc_checksum) - 1);
    c->ucc_checksum[sizeof(c->ucc_checksum) - 1] = '\0';
  } else if (MATCH("hook", "log_level")) {
    if (strcmp(value, "debug") == 0)
      c->log_level = HOOK_LOG_LEVEL_DEBUG;
    else if (strcmp(value, "info") == 0)
      c->log_level = HOOK_LOG_LEVEL_INFO;
    else if (strcmp(value, "warn") == 0)
      c->log_level = HOOK_LOG_LEVEL_WARN;
    else if (strcmp(value, "error") == 0)
      c->log_level = HOOK_LOG_LEVEL_ERROR;
    else if (strcmp(value, "silent") == 0)
      c->log_level = HOOK_LOG_LEVEL_SILENT;
    else
      c->log_level = HOOK_LOG_LEVEL_INFO;
  } else if (MATCH("hook", "log_file")) {
    strncpy(c->log_file, value, sizeof(c->log_file) - 1);
  } else if (MATCH("hook", "heartbeat_interval")) {
    c->heartbeat_interval = atoi(value);
    if (c->heartbeat_interval < 0)
      c->heartbeat_interval = 0;
  } else if (MATCH("socket", "socket_path")) {
    strncpy(c->socket_path, value, sizeof(c->socket_path) - 1);
  } else if (MATCH("socket", "socket_maxpoll")) {
    c->socket_maxpoll = atoi(value);
    if (c->socket_maxpoll < 0)
      c->socket_maxpoll = 0;
  } else if (MATCH("socket", "socket_deadline")) {
    c->socket_deadline = atoi(value);
    if (c->socket_deadline < 1)
      c->socket_deadline = 1;
    else if (c->socket_deadline > 30)
      c->socket_deadline = 30;
  } else if (MATCH("debug", "debug_dump_dir")) {
    strncpy(c->debug_dump_dir, value, sizeof(c->debug_dump_dir) - 1);
  }
#undef MATCH
  return 1;
}

// ============================================================================
// CONFIG ENV OVERRIDES
// ============================================================================
/*
 * Applies environment variable overrides to the config struct.
 * Called after ini_parse, env variables always take priority over the
 * config file. Unknown or empty variables are silently ignored.
 *
 * KFDSH_CONFIG             handled separately in hook_load_config()
 * KFDSH_ENABLED            hook_enabled
 * KFDSH_SECURITY_PATCH     security_patch
 * KFDSH_UCC_CHECKSUM       ucc_checksum
 * KFDSH_LOG_LEVEL          log_level (debug|info|warn|error|silent)
 * KFDSH_LOG_FILE           log_file
 * KFDSH_SOCKET_PATH        socket_path
 * KFDSH_SOCKET_MAXPOLL     socket_maxpoll
 * KFDSH_SOCKET_DEADLINE    socket_deadline
 * KFDSH_HEARTBEAT_INTERVAL heartbeat_interval
 * KFDSH_DEBUG_DUMP_DIR     debug_dump_dir
 */
static void apply_env_overrides(hook_config_t *c) {
  const char *v;

  // Hook
  if ((v = getenv("KFDSH_ENABLED")) && *v)
    c->hook_enabled = atoi(v);
  if ((v = getenv("KFDSH_SECURITY_PATCH")) && *v)
    c->security_patch = atoi(v);
  if ((v = getenv("KFDSH_UCC_CHECKSUM")) && *v) {
    strncpy(c->ucc_checksum, v, sizeof(c->ucc_checksum) - 1);
    c->ucc_checksum[sizeof(c->ucc_checksum) - 1] = '\0';
  }
  if ((v = getenv("KFDSH_LOG_LEVEL")) && *v) {
    if (strcmp(v, "debug") == 0)
      c->log_level = HOOK_LOG_LEVEL_DEBUG;
    else if (strcmp(v, "info") == 0)
      c->log_level = HOOK_LOG_LEVEL_INFO;
    else if (strcmp(v, "warn") == 0)
      c->log_level = HOOK_LOG_LEVEL_WARN;
    else if (strcmp(v, "error") == 0)
      c->log_level = HOOK_LOG_LEVEL_ERROR;
    else if (strcmp(v, "silent") == 0)
      c->log_level = HOOK_LOG_LEVEL_SILENT;
  }
  if ((v = getenv("KFDSH_LOG_FILE")) && *v)
    strncpy(c->log_file, v, sizeof(c->log_file) - 1);
  if ((v = getenv("KFDSH_HEARTBEAT_INTERVAL")) && *v) {
    c->heartbeat_interval = atoi(v);
    if (c->heartbeat_interval < 0)
      c->heartbeat_interval = 0;
  }

  // Socket
  if ((v = getenv("KFDSH_SOCKET_PATH")) && *v)
    strncpy(c->socket_path, v, sizeof(c->socket_path) - 1);
  if ((v = getenv("KFDSH_SOCKET_MAXPOLL")) && *v) {
    c->socket_maxpoll = atoi(v);
    if (c->socket_maxpoll < 0)
      c->socket_maxpoll = 0;
  }
  if ((v = getenv("KFDSH_SOCKET_DEADLINE")) && *v) {
    c->socket_deadline = atoi(v);
    if (c->socket_deadline < 1)
      c->socket_deadline = 1;
    if (c->socket_deadline > 30)
      c->socket_deadline = 30;
  }

  // Debug
  if ((v = getenv("KFDSH_DEBUG_DUMP_DIR")) && *v)
    strncpy(c->debug_dump_dir, v, sizeof(c->debug_dump_dir) - 1);
}

// ============================================================================
// CONFIG
// ============================================================================
/*
 * Loads configuration from the file at KFDS_HOOK_CONFIG (env) or
 * ./kfds_hook.ini (default). Use default values as fallback.
 * Parse errors are logged but do not abort, successfully parsed keys are
 * applied and the rest remain at their defaults.
 * Also opens the log file, verifies the binary checksum if configured,
 * and dumps the resolved config at debug level.
 */
void hook_load_config(void) {
  // Parse config file
  const char *path = getenv("KFDSH_CONFIG");
  int explicit_path = (path && *path);
  if (!explicit_path)
    path = "./kfds_hook.ini";

  int r = -1;
  if (explicit_path || access(path, F_OK) == 0)
    r = ini_parse(path, config_handler, &g_config);

  // Apply env overrides, take priority over the config file
  apply_env_overrides(&g_config);

  // Open the log file now before the first log call
  if (g_config.log_file[0])
    hook_log_open(g_config.log_file);

  if (r == -1) {
    if (explicit_path)
      hook_log_warn("no config file at %s\n", path);
  } else if (r > 0) {
    hook_log_error("config parse error at line %d in %s\n", r, path);
  } else {
    hook_log_info("config loaded from %s\n", path);
  }

  // Verify binary checksum if set
  if (g_config.ucc_checksum[0]) {
    char actual[65];
    if (!sha256_file("/proc/self/exe", actual)) {
      hook_log_error("FATAL: could not read /proc/self/exe for checksum\n");
      g_config.hook_enabled = 0;
    } else if (strcasecmp(actual, g_config.ucc_checksum) != 0) {
      hook_log_error("FATAL: binary checksum mismatch!\n");
      hook_log_error("  expected: %s\n", g_config.ucc_checksum);
      hook_log_error("  actual:   %s\n", actual);
      hook_log_error("  Hook installation aborted. Update ucc_checksum in "
                     "kfds_hook.ini.\n");
      g_config.hook_enabled = 0;
    } else {
      hook_log_debug("checksum OK: %s\n", actual);
    }
  }

  // Dump resolved config at debug level
  hook_log_debug("log_level=%d log_file=%s hearbeat_interval=%d "
                 "socket=%s maxpoll=%d/s deadline=%ds "
                 "debug_dump_dir=%s\n",
                 g_config.log_level, g_config.log_file,
                 g_config.heartbeat_interval, g_config.socket_path,
                 g_config.socket_maxpoll, g_config.socket_deadline,
                 g_config.debug_dump_dir);
}