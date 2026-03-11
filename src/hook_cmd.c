#include <string.h>

#include "hook_cmd.h"
#include "hook_json.h"
#include "hook_log.h"
#include "hook_socket.h"
#include "kfds_hook.h"

// ============================================================================
// PING
// ============================================================================
static void cmd_ping(void) {
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_str(&jb, HOOK_REVISION);
  jb_raw(&jb, "}");
  hook_socket_finish_json(&jb);
}

// ============================================================================
// COMMAND DISPATCHER
// ============================================================================
void hook_command_dispatch(void) {
  const char *cmd = g_socket_slot.req.cmd;
  hook_log_debug("Executing cmd: %s\n", cmd);

  // Ping
  if (strcmp(cmd, "Ping") == 0) {
    cmd_ping();
  }
  return;
}