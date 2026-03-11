#include <string.h>

#include "hook_cmd.h"
#include "hook_engine.h"
#include "hook_json.h"
#include "hook_log.h"
#include "hook_socket.h"
#include "kfds_hook.h"

// ============================================================================
// COMMAND HELPERS
// ============================================================================
/*
 * Convert g_socket_slot.req.args[idx] (UTF-8) to ucs2_t for engine calls
 * Produces empty string if idx >= argument count
 * Uses utf8_to_ucs2, locale-independent, no mbstowcs
 */
static void arg_to_ucs2(int idx, ucs2_t *buf, size_t buf_len) {
  if (idx >= g_socket_slot.req.argc) {
    buf[0] = 0;
    return;
  }
  utf8_to_ucs2(g_socket_slot.req.args[idx], buf, buf_len);
}

// ============================================================================
// COMMMAND - PING
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
// COMMAND - CONSOLE
// ============================================================================
static void cmd_exec(void) {
  // At least one command must be given
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: Command");
    return;
  }

  ucs2_t buf[ARG_MAX_CHARS];
  arg_to_ucs2(0, buf, ARG_MAX_CHARS);

  void *glog = *(void **)ADDR_GLOG_PTR;
  int handled = UGameEngine_Exec((void *)GGameEngine, buf, glog);

  hook_log_debug("Exec: '%s' handled=%d\n", g_socket_slot.req.args[0], handled);
  hook_socket_finish_ok();
}

// ============================================================================
// COMMAND - MAP CHANGE
// ============================================================================
static void cmd_server_travel(void *level_info) {
  // Can't change on an empty map URL
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: MapURL");
    return;
  }

  ucs2_t buf[ARG_MAX_CHARS];
  arg_to_ucs2(0, buf, ARG_MAX_CHARS);

  FString url;
  FString_ctor(&url, buf);
  ALevelInfo_eventServerTravel(level_info, &url, 0);
  FString_dtor(&url);

  hook_log_debug("ServerTravel: '%s'\n", g_socket_slot.req.args[0]);
  hook_socket_finish_ok();
}

// ============================================================================
// COMMAND - ADMIN SERVER MESSAGE
// ============================================================================
static void cmd_say(void *game_info) {
  // Can't say anything if there's nothing to say
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: Message");
    return;
  }

  ucs2_t buf[ARG_MAX_CHARS];
  arg_to_ucs2(0, buf, ARG_MAX_CHARS);

  FString fmsg;
  FName ftype = {0}; // zero-init avoids stack corruption
  FString_ctor(&fmsg, buf);
  AGameInfo_eventBroadcast(game_info, NULL, &fmsg, ftype);
  FString_dtor(&fmsg);

  hook_log_debug("Say: '%s'\n", g_socket_slot.req.args[0]);
  hook_socket_finish_ok();
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
    return;
  }

  // Level objects required for all remaining commands
  void *level_info = NULL, *game_info = NULL;
  if (!get_level_objects(&level_info, &game_info)) {
    hook_log_error("level objects not ready\n");
    hook_socket_finish_err("level not ready");
    return;
  }

  // Exec - Console
  if (strcmp(cmd, "Exec") == 0) {
    cmd_exec();
    return;
  }

  // Server Travel - Map Change
  if (strcmp(cmd, "ServerTravel") == 0) {
    cmd_server_travel(level_info);
    return;
  }

  // Say - Admin Server Message
  if (strcmp(cmd, "Say") == 0) {
    cmd_say(game_info);
    return;
  }
}