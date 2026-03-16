#ifndef HOOK_CMD_DEBUG_H
#define HOOK_CMD_DEBUG_H

#ifdef DEBUG

// ============================================================================
// DEBUG COMMANDS
// ============================================================================
void cmd_debug_gri_dump(void);
void cmd_debug_pri_dump(void);
void cmd_debug_actors_dump(void);
void cmd_debug_pc_dump(void);
void cmd_debug_pcpawn_dump(void);
void cmd_debug_pcnetconn_dump(void);
void cmd_debug_gnames_dump(void);
void cmd_debug_cfg_empty_section(void);

// ============================================================================
// DEBUG COMMAND DISPATCHER
// ============================================================================
void hook_debug_command_dispatch(char* cmd);

#endif /* DEBUG */

#endif /* HOOK_CMD_DEBUG_H */