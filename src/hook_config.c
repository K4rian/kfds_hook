#include <stdlib.h>
#include <string.h>

#include "inih/ini.h"

#include "hook_config.h"
#include "hook_log.h"
#include "kfds_hook.h"

// ============================================================================
// CONFIG GLOBAL STATE
// ============================================================================
hook_config_t g_config = {
    .hook_enabled = 1,
    .log_level = HOOK_LOG_LEVEL_ALL,
    .log_file = "",
};

// ============================================================================
// CONFIG
// ============================================================================
static int config_handler(void *user, const char *section, const char *name,
                          const char *value) {
  hook_config_t *c = (hook_config_t *)user;
  if (!name || !value)
    return 1; // section header, skip

#define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)
  if (MATCH("hook", "log_level")) {
    if (strcmp(value, "all") == 0)
      c->log_level = HOOK_LOG_LEVEL_ALL;
    else if (strcmp(value, "errors") == 0)
      c->log_level = HOOK_LOG_LEVEL_ERRORS;
    else if (strcmp(value, "silent") == 0)
      c->log_level = HOOK_LOG_LEVEL_SILENT;
  } else if (MATCH("hook", "log_file")) {
    strncpy(c->log_file, value, sizeof(c->log_file) - 1);
  }
#undef MATCH
  return 1;
}

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
    hook_log(HOOK_LOG_LEVEL_ALL, "no config file at %s, using defaults\n",
             path);
  } else if (r > 0) {
    hook_log(HOOK_LOG_LEVEL_ALL, "config parse error at line %d in %s\n", r,
             path);
  } else {
    hook_log(HOOK_LOG_LEVEL_ALL, "config loaded from %s\n", path);
  }
  hook_log(HOOK_LOG_LEVEL_ALL, "log_level=%d\n", g_config.log_level);
}