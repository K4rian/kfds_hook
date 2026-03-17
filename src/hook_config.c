#include <stdlib.h>
#include <string.h>

#include "hook_config.h"
#include "hook_log.h"
#include "hook_sha256.h"
#include "inih/ini.h"

// ============================================================================
// CONFIG GLOBAL STATE
// ============================================================================
hook_config_t g_config = {
    .hook_enabled = 1,
    .ucc_checksum = KFDS_UCC_CHECKSUM,
#ifdef DEBUG
    .log_level = HOOK_LOG_LEVEL_DEBUG,
#else
    .log_level = HOOK_LOG_LEVEL_INFO,
#endif
    .log_file = "",
    .socket_path = "/tmp/kfds_hook.sock",
    .socket_maxpoll = 100,
    .socket_deadline = 2,
    .debug_dump_dir = "./dump",
};

// ============================================================================
// CONFIG HANDLER
// ============================================================================
static int config_handler(void *user, const char *section, const char *name,
                          const char *value) {
  hook_config_t *c = (hook_config_t *)user;
  if (!name || !value)
    return 1; // section header, skip

#define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)
  if (MATCH("hook", "hook_enabled")) {
    c->hook_enabled = atoi(value);
  } else if (MATCH("hook", "ucc_checksum")) {
    strncpy(c->ucc_checksum, value, 64);
    c->ucc_checksum[64] = '\0';
  } else if (MATCH("hook", "log_level")) {
    if (strcmp(value, "debug") == 0)
      g_config.log_level = HOOK_LOG_LEVEL_DEBUG;
    else if (strcmp(value, "info") == 0)
      g_config.log_level = HOOK_LOG_LEVEL_INFO;
    else if (strcmp(value, "warn") == 0)
      g_config.log_level = HOOK_LOG_LEVEL_WARN;
    else if (strcmp(value, "error") == 0)
      g_config.log_level = HOOK_LOG_LEVEL_ERROR;
    else if (strcmp(value, "silent") == 0)
      g_config.log_level = HOOK_LOG_LEVEL_SILENT;
    else
      g_config.log_level = HOOK_LOG_LEVEL_INFO;
  } else if (MATCH("hook", "log_file")) {
    strncpy(c->log_file, value, sizeof(c->log_file) - 1);
  } else if (MATCH("socket", "socket_path")) {
    strncpy(c->socket_path, value, sizeof(c->socket_path) - 1);
  } else if (MATCH("socket", "socket_maxpoll")) {
    c->socket_maxpoll = atoi(value);
  } else if (MATCH("socket", "socket_deadline")) {
    c->socket_deadline = atoi(value);
    if (c->socket_deadline < 1)
      c->socket_deadline = 1;
  } else if (MATCH("debug", "debug_dump_dir")) {
    strncpy(c->debug_dump_dir, value, sizeof(c->debug_dump_dir) - 1);
  }
#undef MATCH
  return 1;
}

// ============================================================================
// CONFIG
// ============================================================================
void hook_load_config(void) {
  // Resolve config path env override
  const char *path = getenv("KFDS_HOOK_CONFIG");
  if (!path || !*path)
    path = "./kfds_hook.ini";

  int r = ini_parse(path, config_handler, &g_config);

  // Open the log file now before the first log call
  if (g_config.log_file[0])
    hook_log_open(g_config.log_file);

  if (r == -1) {
    // File not found, silently use defaults
    hook_log_warn("no config file at %s, using defaults\n", path);
  } else if (r > 0) {
    hook_log_error("config parse error at line %d in %s\n", r, path);
  } else {
    hook_log_info("config loaded from %s\n", path);
  }

  // Verify ucc-bin-real checksum if set
  if (g_config.ucc_checksum[0]) {
    char actual[65];
    if (!sha256_file("/proc/self/exe", actual)) {
      hook_log_error("FATAL: could not read /proc/self/exe for checksum\n");
      g_config.hook_enabled = 0;
    } else if (strcasecmp(actual, g_config.ucc_checksum) != 0) {
      hook_log_error("FATAL: binary checksum mismatch!\n");
      hook_log_error("  expected: %s\n", g_config.ucc_checksum);
      hook_log_error("  actual:   %s\n", actual);
      hook_log_error("  Hook installation aborded. Update ucc_checksum in "
                     "kfds_hook.ini.\n");
      g_config.hook_enabled = 0;
    } else {
      hook_log_debug("checksum OK: %s\n", actual);
    }
  }

  hook_log_debug("log_level=%d log_file=%s socket=%s maxpoll=%d/s deadline=%ds "
                 "debug_dump_dir=%s\n",
                 g_config.log_level, g_config.log_file, g_config.socket_path,
                 g_config.socket_maxpoll, g_config.socket_deadline,
                 g_config.debug_dump_dir);
}