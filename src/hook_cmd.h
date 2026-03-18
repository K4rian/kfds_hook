#ifndef HOOK_CMD_H
#define HOOK_CMD_H

// ============================================================================
// COMMAND TYPES
// ============================================================================
typedef struct {
  void *level_info;
  void *game_info;
} cmd_ctx_t;

typedef void (*cmd_fn_t)(cmd_ctx_t *ctx);

typedef struct {
  const char *name;
  cmd_fn_t fn;
  int needs_level; // 1 = get_level_objects() required before dispatch
} cmd_entry_t;

// ============================================================================
// COMMAND DISPATCHER
// ============================================================================
void hook_command_dispatch(void);

#endif /* HOOK_CMD_H */