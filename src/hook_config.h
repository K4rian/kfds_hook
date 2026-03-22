#ifndef HOOK_CONFIG_H
#define HOOK_CONFIG_H

#include "hook_log.h"

// ============================================================================
// CONFIG DEFINES
// ============================================================================
#define KFDS_UCC_CHECKSUM                                                      \
  "1ddb2110e71400137dc4fc527af94458556b08c0649f5ba65307f95811484756"

// ============================================================================
// CONFIG TYPES
// ============================================================================
typedef struct {
  int hook_enabled;           // 0 = skip hook installation entirely
  int security_patch;         // 0 = enable file security check
  char ucc_checksum[65];      // SHA256 hex to verify, empty = skip
  hook_log_level_t log_level; // debug, info, warn, error, silent
  char log_file[256];         // path for file logging, empty = stderr only
  int heartbeat_interval;     // heartbeat log interval in seconds, 0 = disabled

  char socket_path[108];      // Unix socket path (max 107 + NUL)
  int socket_maxpoll;         // max commands dispatched per second, 0 = disabled
  int socket_deadline;        // command timeout seconds

  char debug_dump_dir[256];   // dump directory path
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