#ifndef KFDSL_HOOK_H
#define KFDSL_HOOK_H

// ============================================================================
// HOOK REVISION
// ============================================================================
#define HOOK_REVISION "1"

// ============================================================================
// HOOK TYPES
// ============================================================================
typedef enum {
  HOOK_LOG_LEVEL_SILENT = 0,
  HOOK_LOG_LEVEL_ERRORS = 1,
  HOOK_LOG_LEVEL_ALL = 2,
} hook_log_level_t;

#endif /* KFDSL_HOOK_H */