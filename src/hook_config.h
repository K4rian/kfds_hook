#ifndef HOOK_CONFIG_H
#define HOOK_CONFIG_H

#include "kfds_hook.h"

// ============================================================================
// CONFIG TYPES
// ============================================================================
typedef struct {
  int hook_enabled;           // 0 = skip hook installation entirely
  hook_log_level_t log_level; // SILENT / ERRORS / ALL
  char log_file[256];         // path for file logging, empty = stderr only
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