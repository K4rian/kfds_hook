#ifndef HOOK_CONFIG_H
#define HOOK_CONFIG_H

#include "hook_log.h"

// ============================================================================
// CONFIG TYPES
// ============================================================================
typedef struct {
  int hook_enabled;           // 0 = skip hook installation entirely
  hook_log_level_t log_level; // debug, info, warn, error, silent
  char log_file[256];         // path for file logging, empty = stderr only

  char socket_path[108];      // Unix socket path (max 107 + NUL)
  int socket_maxpoll;         // TBI
  int socket_deadline;        // command timeout seconds
} hook_config_t;

// ============================================================================
// CONFIG GLOBAL STATE
// ============================================================================
extern hook_config_t g_config;

// ============================================================================
// CONFIG
// ============================================================================
void hook_load_config(void);

#endif /* HOOK_CONFIG_H */