#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hook_cmd.h"
#include "hook_engine.h"
#include "hook_json.h"
#include "hook_log.h"
#include "hook_socket.h"
#include "kfds_hook.h"

#ifdef DEBUG
#include "hook_cmd_debug.h"
#endif

// ============================================================================
// COMMAND HELPERS
// ============================================================================
/*
 * Convert g_socket_slot.req.args[idx] (UTF-8) to ucs2_t for engine calls.
 * Produces empty string if idx >= argument count.
 * Uses utf8_to_ucs2, locale-independent, no mbstowcs.
 */
static void arg_to_ucs2(int idx, ucs2_t *buf, size_t buf_len) {
  if (idx >= g_socket_slot.req.argc) {
    buf[0] = 0;
    return;
  }
  utf8_to_ucs2(g_socket_slot.req.args[idx], buf, buf_len);
}

/*
 * Read a FURL FString field from ULevel into a UTF-8 buffer.
 * Writes empty string if null or empty.
 */
static void furl_get_utf8(void *level, int offset, char *dst, size_t dst_len) {
  FString *fs = (FString *)((uint8_t *)level + offset);
  if (!fs->Data || fs->Num <= 0) {
    dst[0] = '\0';
    return;
  }
  ucs2_to_utf8(fs->Data, dst, dst_len);
}

/*
 * Writes a string value to a GRI FString field at the given offset.
 * If the new value fits within the existing FString buffer (new_num <= Max),
 * it is written in-place. Otherwise a new buffer is allocated via FString_ctor
 * and swapped in. The old buffer is intentionally leaked since thre's no
 * safe way to free Unreal's heap allocations from outside the engine.
 */
static int gri_set_str(int offset, const char *value) {
  void *gri = find_gri();
  if (!gri) {
    hook_socket_finish_err("GRI not found");
    return 0;
  }

  ucs2_t new_val[ARG_MAX_CHARS] = {0};
  utf8_to_ucs2(value, new_val, ARG_MAX_CHARS);

  int new_len = 0;
  while (new_val[new_len])
    new_len++;
  int new_num = new_len + 1;

  FString *fstr = (FString *)((uint8_t *)gri + offset);
  hook_log_debug("gri_set_str: field=+0x%x Data=%p Num=%d Max=%d new_num=%d\n",
                 offset, (void *)fstr->Data, fstr->Num, fstr->Max, new_num);

  if (fstr->Max > 0 && new_num <= fstr->Max) {
    memcpy(fstr->Data, new_val, (size_t)new_num * sizeof(ucs2_t));
    fstr->Num = new_num;
    hook_log_debug("gri_set_str: wrote in-place\n");
  } else {
    FString tmp = {0};
    FString_ctor(&tmp, new_val);
    fstr->Data = tmp.Data;
    fstr->Num = tmp.Num;
    fstr->Max = tmp.Max;

    hook_log_debug("gri_set_str: allocated new buffer (old buffer leaked)\n");
  }
  return 1;
}

/*
 * Writes an integer value to a GRI int field at the given offset.
 * value is a decimal string converted afterward.
 */
static int gri_set_int(int offset, const char *value) {
  void *gri = find_gri();
  if (!gri) {
    hook_socket_finish_err("GRI not found");
    return 0;
  }

  int v = (int)strtol(value, NULL, 10);
  *(int *)((uint8_t *)gri + offset) = v;

  hook_log_debug("gri_set_int: field=+0x%x value=%d\n", offset, v);
  return 1;
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
  int handled = UGameEngine_Exec((void *)hook_engine_get(), buf, glog);

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
// COMMAND - SERVER INFO
// ============================================================================
void cmd_get_server_info(void) {
  void *gri = find_gri();
  if (!gri) {
    hook_socket_finish_err("GRI not found");
    return;
  }

  char tmp[ARG_MAX_CHARS];
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":{");

  // String fields
  static const struct {
    const char *key;
    int offset;
  } str_fields[] = {
      {"server_name", GRI_OFFSET_ServerName},
      {"short_name", GRI_OFFSET_ShortName},
      {"admin_name", GRI_OFFSET_AdminName},
      {"admin_email", GRI_OFFSET_AdminEmail},
      {"motd", GRI_OFFSET_MessageOfTheDay},
  };
  for (int i = 0; i < 5; i++) {
    if (i > 0)
      jb_raw(&jb, ",");

    FString *fs = (FString *)((uint8_t *)gri + str_fields[i].offset);
    jb_str(&jb, str_fields[i].key);
    jb_raw(&jb, ":");

    if (fs->Data && fs->Num > 0) {
      ucs2_to_utf8(fs->Data, tmp, sizeof(tmp));
      jb_str(&jb, tmp);
    } else {
      jb_raw(&jb, "\"\"");
    }
  }

  // Int field
  jb_raw(&jb, ",");
  jb_str(&jb, "server_region");
  jb_raw(&jb, ":");
  jb_int(&jb, *(int *)((uint8_t *)gri + GRI_OFFSET_ServerRegion));

  // Byte fields
  jb_raw(&jb, ",\"base_difficulty\":");
  jb_int(&jb, *(uint8_t *)((uint8_t *)gri + GRI_OFFSET_BaseDifficulty));
  jb_raw(&jb, ",\"final_wave\":");
  jb_int(&jb, *(uint8_t *)((uint8_t *)gri + GRI_OFFSET_FinalWave));

  // Float field
  jb_raw(&jb, ",\"game_diff\":");
  float gd = *(float *)((uint8_t *)gri + GRI_OFFSET_GameDiff);
  char fbuf[32];
  snprintf(fbuf, sizeof(fbuf), "%.6g", gd);
  jb_raw(&jb, fbuf);

  jb_raw(&jb, "}}");

  // TODO: lOG
  hook_socket_finish_json(&jb);
}

static void cmd_get_level_url(void) {
  void *level =
      *(void **)((uint8_t *)hook_engine_get() + UGAMEENGINE_LEVEL_OFFSET);
  if (!level) {
    hook_socket_finish_err("level not ready");
    return;
  }

  char tmp[ARG_MAX_CHARS];
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":{");

  jb_raw(&jb, "\"protocol\":");
  furl_get_utf8(level, FURL_OFFSET_Protocol, tmp, sizeof(tmp));
  jb_str(&jb, tmp);

  jb_raw(&jb, ",\"host\":");
  furl_get_utf8(level, FURL_OFFSET_Host, tmp, sizeof(tmp));
  jb_str(&jb, tmp);

  jb_raw(&jb, ",\"port\":");
  jb_int(&jb, *(int *)((uint8_t *)level + FURL_OFFSET_Port));

  jb_raw(&jb, ",\"map\":");
  furl_get_utf8(level, FURL_OFFSET_Map, tmp, sizeof(tmp));
  jb_str(&jb, tmp);

  jb_raw(&jb, ",\"portal\":");
  furl_get_utf8(level, FURL_OFFSET_Portal, tmp, sizeof(tmp));
  jb_str(&jb, tmp);

  jb_raw(&jb, ",\"valid\":");
  jb_bool(&jb, *(int *)((uint8_t *)level + FURL_OFFSET_Valid));

  // Options
  FString *op_array = (FString *)((uint8_t *)level + FURL_OFFSET_Op);
  int op_num = op_array->Num;
  FString *op_data = (FString *)op_array->Data;

  jb_raw(&jb, ",\"options\":[");
  if (op_data && op_num > 0) {
    char tmp[ARG_MAX_CHARS];
    int first = 1;
    for (int i = 0; i < op_num; i++) {
      FString *entry = &op_data[i];
      if (!entry->Data || entry->Num <= 0)
        continue;
      if (!first)
        jb_raw(&jb, ",");
      first = 0;
      ucs2_to_utf8(entry->Data, tmp, sizeof(tmp));
      jb_str(&jb, tmp);
    }
  }
  jb_raw(&jb, "]");
  //

  jb_raw(&jb, "}}");

  // TODO: LOG
  hook_socket_finish_json(&jb);
}

/*
 * Sets the server name shown in the server browser.
 * Change is lost on map change.
 */
static void cmd_set_live_server_name(void) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: ServerName");
    return;
  }
  if (!gri_set_str(GRI_OFFSET_ServerName, g_socket_slot.req.args[0]))
    return;
  hook_socket_finish_ok();
}

/*
 * Sets the server short name.
 * Change is lost on map change.
 */
static void cmd_set_live_short_name(void) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: ShortName");
    return;
  }
  if (!gri_set_str(GRI_OFFSET_ShortName, g_socket_slot.req.args[0]))
    return;
  hook_socket_finish_ok();
}

/*
 * Sets the admin name shown in the server browser.
 * Change is lost on map change.
 */
static void cmd_set_live_admin_name(void) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: AdminName");
    return;
  }
  if (!gri_set_str(GRI_OFFSET_AdminName, g_socket_slot.req.args[0]))
    return;
  hook_socket_finish_ok();
}

/*
 * Sets the admin email shown in the server browser.
 * Change is lost on map change.
 */
static void cmd_set_live_admin_email(void) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: AdminEmail");
    return;
  }
  if (!gri_set_str(GRI_OFFSET_AdminEmail, g_socket_slot.req.args[0]))
    return;
  hook_socket_finish_ok();
}

/*
 * Sets the server region.
 * Change is lost on map change.
 */
static void cmd_set_live_server_region(void) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: Region");
    return;
  }
  if (!gri_set_int(GRI_OFFSET_ServerRegion, g_socket_slot.req.args[0]))
    return;
  hook_socket_finish_ok();
}

/*
 * Sets the message of the day shown on the server.
 * Change is lost on map change.
 */
static void cmd_set_live_motd(void) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: MessageOfTheDay");
    return;
  }
  if (!gri_set_str(GRI_OFFSET_MessageOfTheDay, g_socket_slot.req.args[0]))
    return;
  hook_socket_finish_ok();
}

// ============================================================================
// COMMAND - WAVE STATE
// ============================================================================
static void cmd_get_wave_state(void) {
  void *gri = find_gri();
  if (!gri) {
    hook_socket_finish_err("GRI not found");
    return;
  }

  uint8_t *base = (uint8_t *)gri;

  // WaveNumber: 0-indexed in engine (wave 1 = 0, wave 4 = 3)
  // bWaveInProgress at +0x5fc: 1=wave active, 0=trader/lobby
  // Both read as uint8_t and stored as single byte
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":{");
  jb_raw(&jb, "\"wave_in_progress\":");
  jb_bool(&jb, *(uint8_t *)(base + GRI_OFFSET_bWaveInProgress));
  jb_raw(&jb, ",\"wave_number\":");
  jb_int(&jb, *(uint8_t *)(base + GRI_OFFSET_WaveNumber));
  jb_raw(&jb, ",\"final_wave\":");
  jb_int(&jb, *(uint8_t *)(base + GRI_OFFSET_FinalWave));
  jb_raw(&jb, ",\"num_monsters\":");
  jb_int(&jb, *(int *)(base + GRI_OFFSET_numMonsters));
  jb_raw(&jb, ",\"time_to_next_wave\":");
  jb_int(&jb, *(int *)(base + GRI_OFFSET_TimeToNextWave));
  jb_raw(&jb, ",\"base_difficulty\":");
  jb_int(&jb, *(uint8_t *)(base + GRI_OFFSET_BaseDifficulty));
  jb_raw(&jb, ",\"game_diff\":");

  float gd = *(float *)(base + GRI_OFFSET_GameDiff);
  char fbuf[32];
  snprintf(fbuf, sizeof(fbuf), "%.6g", gd);
  jb_raw(&jb, fbuf);

  jb_raw(&jb, ",\"game_started\":");
  jb_bool(&jb, is_game_started());
  jb_raw(&jb, "}}");

  // TODO: lOG
  hook_socket_finish_json(&jb);
}

// ============================================================================
// COMMAND - SKIP TRADER
// ============================================================================
/*
 * Forces trader countdown to 6 seconds.
 * Targets KFGameType.WaveCountDown, NOT GRI.TimeToNextWave.
 * GRI.TimeToNextWave is a replicated mirror and overwritten from WaveCountDown
 * every tick, so writing it directly has no lasting effect.
 * Value below 5 breaks the internal script logic and lead to unexpected
 * behavior.
 */
static void cmd_skip_trader(void *game_info) {
  int wip = 
        *(int *)((uint8_t *)game_info + GAMETYPE_OFFSET_bWaveInProgress);
  int doorsopen =
      *(int *)((uint8_t *)game_info + GAMETYPE_OFFSET_bTradingDoorsOpen);
  if (wip || !doorsopen) {
    hook_socket_finish_err("not in trader time");
    return;
  }

  // Already at or below minimum
  int countdown =
      *(int *)((uint8_t *)game_info + GAMETYPE_OFFSET_WaveCountDown);
  if (countdown <= 6) {
    hook_socket_finish_ok();
    return;
  }

  *(int *)((uint8_t *)game_info + GAMETYPE_OFFSET_WaveCountDown) = 6;
  hook_socket_finish_ok();
}

// ============================================================================
// COMMAND DISPATCHER
// ============================================================================
void hook_command_dispatch(void) {
  const char *cmd = g_socket_slot.req.cmd;
  hook_log_debug("Executing cmd: %s\n", cmd);

  // TODO: Dispatch table

  // Ping
  if (strcmp(cmd, "Ping") == 0) {
    cmd_ping();
    return;
  }

  // --------------------------------------------------------------------------

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

  // ServerInfo - Get Server Info
  if (strcmp(cmd, "ServerInfo") == 0) {
    cmd_get_server_info();
    return;
  }

  // LevelURL - Get Level URL with options
  if (strcmp(cmd, "LevelURL") == 0) {
    cmd_get_level_url();
    return;
  }

  // WaveState - Get Wave State
  if (strcmp(cmd, "WaveState") == 0) {
    cmd_get_wave_state();
    return;
  }

  // SkipTrader - Set Trader Countdown to 6s
  if (strcmp(cmd, "SkipTrader") == 0) {
    cmd_skip_trader(game_info);
    return;
  }

  // SetLiveServerName - Set Server Name
  // Do not survive a map change
  if (strcmp(cmd, "SetLiveServerName") == 0) {
    cmd_set_live_server_name();
    return;
  }

  // SetLiveShortName - Set Short Server Name
  // Do not survive a map change
  if (strcmp(cmd, "SetLiveShortName") == 0) {
    cmd_set_live_short_name();
    return;
  }

  // SetLiveAdminName - Set Admin Name
  // Do not survive a map change
  if (strcmp(cmd, "SetLiveAdminName") == 0) {
    cmd_set_live_admin_name();
    return;
  }

  // SetLiveAdminMail - Set Admin Mail
  // Do not survive a map change
  if (strcmp(cmd, "SetLiveAdminMail") == 0) {
    cmd_set_live_admin_email();
    return;
  }

  // SetLiveServerRegion - Set Server Region
  // Do not survive a map change
  if (strcmp(cmd, "SetLiveServerRegion") == 0) {
    cmd_set_live_server_region();
    return;
  }

  // SetLiveMOTD - Set Message of the Day
  // Do not survive a map change
  if (strcmp(cmd, "SetLiveMOTD") == 0) {
    cmd_set_live_motd();
    return;
  }

  // --------------------------------------------------------------------------

#ifdef DEBUG
  // GameReplicationInfo (GRI) hex dump to file
  if (strcmp(cmd, "DebugGRIDump") == 0) {
    cmd_debug_gri_dump();
    return;
  }

  // PlayerReplicationInfo (PRI) hex dump to file
  if (strcmp(cmd, "DebugPRIDump") == 0) {
    cmd_debug_pri_dump();
    return;
  }

  // Actor list hex dump to file
  if (strcmp(cmd, "DebugActorsDump") == 0) {
    cmd_debug_actors_dump();
    return;
  }

  // PlayerController (PC) list hex dump to file
  if (strcmp(cmd, "DebugPCDump") == 0) {
    cmd_debug_pc_dump();
    return;
  }

  // PlayerController (PC) Pawn hex dump to file
  if (strcmp(cmd, "DebugPCPawnDump") == 0) {
    cmd_debug_pcpawn_dump();
    return;
  }

  // PlayerController (PC) Network Connection hex dump to file
  if (strcmp(cmd, "DebugPCNetConnDump") == 0) {
    cmd_debug_pcnetconn_dump();
    return;
  }
#endif
}