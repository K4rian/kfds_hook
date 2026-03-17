#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hook_cmd.h"
#include "hook_engine.h"
#include "hook_json.h"
#include "hook_log.h"
#include "hook_socket.h"
#include "hook_ucs2.h"
#include "kfds_hook.h"

#ifdef DEBUG
#include "hook_cmd_debug.h"
#endif

//
// TODO: Cleanup
//

// ============================================================================
// COMMAND DEFINES
// ============================================================================
#define CFG_BUF_CHARS        1024 // max config value / section / key (UTF-8)
#define CFG_DEL_SEC_BUF      (CFG_BUF_CHARS * 4)
#define CFG_DEL_MAX_ENTRIES  512

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
 * and swapped in. The old buffer is intentionally leaked since there's no
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

/*
 * Helper shared by several config destructive functions.
 * Performs the GetSection->filter->EmptySection->reinject->Flush entirely in C.
 * section,
 * key,
 * file:     UCS-2 strings (file may be NULL for GConfig default)
 * value:    UCS-2 value to match exactly (case-sensitive)
 *           NULL = key-only mode: delete all entries whose key matches
 * max_del:  0 = delete all matches, N = delete at most N occurrences
 * Returns:  number of entries deleted, 0 if no matches, -1 on internal error.
 */
static int cfg_delete_entries(void *gcfg, const ucs2_t *section,
                              const ucs2_t *key, const ucs2_t *value,
                              const ucs2_t *file, int max_del) {
  // Read all entries from the section
  ucs2_t raw[CFG_DEL_SEC_BUF];
  memset(raw, 0, sizeof(raw));
  GConfig_GetSection(gcfg, section, raw, CFG_DEL_SEC_BUF, file);

  // Parse and filter
  ucs2_t survivors[CFG_DEL_MAX_ENTRIES][ARG_MAX_CHARS * 2];
  int survivor_cnt = 0;
  int deleted_cnt = 0;

  int ri = 0;
  while (ri < CFG_DEL_SEC_BUF - 1 && survivor_cnt < CFG_DEL_MAX_ENTRIES) {
    if (raw[ri] == 0)
      break;

    int start = ri;
    while (ri < CFG_DEL_SEC_BUF - 1 && raw[ri])
      ri++;
    int entry_len = ri - start;
    ri++; // skip null separator

    if (entry_len <= 0 || entry_len >= ARG_MAX_CHARS * 2)
      continue;

    ucs2_t entry[ARG_MAX_CHARS * 2];
    memcpy(entry, raw + start, entry_len * sizeof(ucs2_t));
    entry[entry_len] = 0;

    ucs2_t ekey[256] = {0};
    ucs2_t eval[ARG_MAX_CHARS] = {0};
    ucs2_split_eq(entry, ekey, 256, eval, ARG_MAX_CHARS);

    int should_delete = 0;
    if (ucs2_icmp(ekey, key) == 0) {
      if (value == NULL) {
        // key-only mode
        if (max_del == 0 || deleted_cnt < max_del)
          should_delete = 1;
      } else {
        // exact key+value match (case-sensitive on value)
        int i = 0;
        while (eval[i] && value[i] && eval[i] == value[i])
          i++;
        if (eval[i] == 0 && value[i] == 0) {
          if (max_del == 0 || deleted_cnt < max_del)
            should_delete = 1;
        }
      }
    }

    if (should_delete) {
      deleted_cnt++;
    } else {
      memcpy(survivors[survivor_cnt], entry, (entry_len + 1) * sizeof(ucs2_t));
      survivor_cnt++;
    }
  }

  if (deleted_cnt == 0)
    return 0;

  // Wipe section
  GConfig_EmptySection(gcfg, section, file);

  // Re-inject survivors (unique=0, preserve duplicates for arrays)
  for (int si = 0; si < survivor_cnt; si++) {
    ucs2_t skey[256] = {0};
    ucs2_t sval[ARG_MAX_CHARS] = {0};
    ucs2_split_eq(survivors[si], skey, 256, sval, ARG_MAX_CHARS);
    GConfig_SetString(gcfg, section, skey, sval, file, 0);
  }

  // Flush wit bRead=1: write to disk, preserve cache
  GConfig_Flush(gcfg, 1, file);

  return deleted_cnt;
}

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
// CONSOLE
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
// MAP CHANGE (TRAVEL)
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
// ADMIN SERVER MESSAGE
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
  FName ftype = {FNAME_ServerSay};
  FString_ctor(&fmsg, buf);
  AGameInfo_eventBroadcast(game_info, NULL, &fmsg, ftype);
  FString_dtor(&fmsg);

  hook_log_debug("Say: '%s'\n", g_socket_slot.req.args[0]);
  hook_socket_finish_ok();
}

static void cmd_announce(void *game_info) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: Message");
    return;
  }

  ucs2_t buf[ARG_MAX_CHARS];
  arg_to_ucs2(0, buf, ARG_MAX_CHARS);

  FString fmsg;
  FName ftype = {FNAME_CriticalEvent};
  FString_ctor(&fmsg, buf);
  AGameInfo_eventBroadcast(game_info, NULL, &fmsg, ftype);
  FString_dtor(&fmsg);

  hook_log_debug("Announce: '%s'\n", g_socket_slot.req.args[0]);
  hook_socket_finish_ok();
}

// ============================================================================
// SERVER INFO
// ============================================================================
static void cmd_get_server_info(void) {
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

  // Float fields
  jb_raw(&jb, ",\"game_diff\":");
  float gd = *(float *)((uint8_t *)gri + GRI_OFFSET_GameDiff);
  char fbuf[32];
  snprintf(fbuf, sizeof(fbuf), "%.6g", gd);
  jb_raw(&jb, fbuf);

  jb_raw(&jb, ",\"max_tick_rate\":");
  float rate = UGameEngine_GetMaxTickRate((void *)hook_engine_get());
  jb_float(&jb, rate);
  jb_raw(&jb, "}");

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

// ============================================================================
// PLAYERS
// ============================================================================
/*
 * Returns all connected players.
 * Traversal: actor list -> is_player_controller -> PC -> PRI (for stats)
 *                                               -> PC -> NetConn (for network)
 *                                               -> PC -> Pawn (for hp/armor)
 * PRI.Owner points to GRI, NOT to the owning PC, cannot traverse PRI->PC.
 * WebAdmin (UTServerAdminSpectator) actor skipped.
 * Ping: uint8 at PRI+0x3c0, displayed ms=raw*4 (TBC).
 * Dosh: float32.
 * Health: int at Pawn+0x480. -1 if Pawn is NULL (player dead/spectating).
 * Armor: float at Pawn+0x774, cast to int. -1 if Pawn is NULL.
 * Perk: UClass* at PRI+0x5f4, name via UObject_GetName,
 *       "KFVet" prefix stripped, null if pointer is NULL.
 * Perk Level: int at PRI+0x5f8, 1-indexed (1-6).
 */
static void cmd_get_players(void) {
  void *level =
      *(void **)((uint8_t *)hook_engine_get() + UGAMEENGINE_LEVEL_OFFSET);
  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":[");
  int first = 1;

  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;
    if (!is_player_controller(UObject_GetName(actor)))
      continue;

    void *pri = *(void **)((uint8_t *)actor + APLAYERCONTROLLER_OFFSET_PRI);
    if (!pri)
      continue;

    FString *name_fs = (FString *)((uint8_t *)pri + PRI_OFFSET_PlayerName);
    if (!name_fs->Data || name_fs->Num <= 1)
      continue;

    void *netconn =
        *(void **)((uint8_t *)actor + APLAYERCONTROLLER_OFFSET_NETCONN);
    uint64_t steamid =
        netconn ? *(uint64_t *)((uint8_t *)netconn + UNETCONN_OFFSET_STEAMID)
                : 0;
    if (steamid == 0 && netconn)
      steamid = *(uint64_t *)((uint8_t *)netconn + UNETCONN_OFFSET_STEAMID_ALT);

    char ip[64] = {0};
    if (netconn) {
      FString *ip_fs = (FString *)((uint8_t *)netconn + UNETCONN_OFFSET_IP);
      if (ip_fs->Data && ip_fs->Num > 1 && ip_fs->Num <= 64)
        ucs2_to_utf8(ip_fs->Data, ip, sizeof(ip));
    }

    uint8_t ping_raw = *(uint8_t *)((uint8_t *)pri + PRI_OFFSET_Ping);
    int ping_ms = (int)ping_raw * 4;
    float dosh = *(float *)((uint8_t *)pri + PRI_OFFSET_Dosh);
    int kills = *(int *)((uint8_t *)pri + PRI_OFFSET_Kills);
    int deaths = *(int *)((uint8_t *)pri + PRI_OFFSET_Deaths);
    // TODO: assists

    // Health and armor from Pawn: -1 if dead/spectating (Pawn == NULL)
    void *pawn = *(void **)((uint8_t *)actor + APLAYERCONTROLLER_OFFSET_PAWN);
    int health = -1;
    int armor = -1;
    if (pawn) {
      health = *(int *)((uint8_t *)pawn + APAWN_OFFSET_Health);
      armor = (int)*(float *)((uint8_t *)pawn + APAWN_OFFSET_ShieldStrength);
    }

    // Perk name and level from PRI
    // Since ClientVeteranSkill is a UClass*, call UObject_GetName() on it
    // Strip "KFVet" prefix if present, and leave raw name for custom perk mods
    // that don't follow the naming convention
    // perk_level is 1-indexed (1-6), matching in-game display
    // Both fields are null if the pointer is NULL (shouldn't happen mid-wave)
    char perk_name[64] = "";
    int perk_level = 0;

    void *vet_class =
        *(void **)((uint8_t *)pri + PRI_OFFSET_ClientVeteranSkill);
    if (vet_class) {
      const ucs2_t *vname = UObject_GetName(vet_class);
      if (vname) {
        // Check for "KFVet" prefix and strip if present
        int strip = (vname[0] == 'K' && vname[1] == 'F' && vname[2] == 'V' &&
                     vname[3] == 'e' && vname[4] == 't');
        const ucs2_t *src = strip ? vname + 5 : vname;
        int j = 0;
        while (src[j] && j < 63) {
          perk_name[j] = (char)src[j];
          j++;
        }
        perk_name[j] = '\0';
      }
      perk_level =
          *(int *)((uint8_t *)pri + PRI_OFFSET_ClientVeteranSkillLevel);
    }

    char name_utf8[ARG_MAX_CHARS];
    ucs2_to_utf8(name_fs->Data, name_utf8, sizeof(name_utf8));

    if (!first)
      jb_raw(&jb, ",");
    first = 0;

    jb_raw(&jb, "{");
    jb_raw(&jb, "\"name\":");
    jb_str(&jb, name_utf8);
    jb_raw(&jb, ",\"steamid\":");
    jb_uint64_str(&jb, steamid);
    jb_raw(&jb, ",\"ip\":");
    jb_str(&jb, ip);
    jb_raw(&jb, ",\"ping\":");
    jb_int(&jb, ping_ms);
    jb_raw(&jb, ",\"dosh\":");
    jb_int(&jb, (int)dosh);
    jb_raw(&jb, ",\"kills\":");
    jb_int(&jb, kills);
    jb_raw(&jb, ",\"deaths\":");
    jb_int(&jb, deaths);
    jb_raw(&jb, ",\"health\":");
    jb_int(&jb, health);
    jb_raw(&jb, ",\"armor\":");
    jb_int(&jb, armor);
    if (perk_name[0]) {
      jb_raw(&jb, ",\"perk\":");
      jb_str(&jb, perk_name);
      jb_raw(&jb, ",\"perk_level\":");
      jb_int(&jb, perk_level);
    } else {
      jb_raw(&jb, ",\"perk\":null,\"perk_level\":null");
    }
    jb_raw(&jb, "}");
  }

  jb_raw(&jb, "]}");

  hook_socket_finish_json(&jb);
}

/*
 * Kicks a player by SteamID64.
 * Uses Cast_APlayerController to confirm each actor is a PC.
 * Skips UTServerAdminSpectator (WebAdmin).
 */
static void cmd_kick(void *game_info) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: SteamID64");
    return;
  }

  uint64_t target = (uint64_t)strtoull(g_socket_slot.req.args[0], NULL, 10);
  if (target == 0) {
    hook_socket_finish_err("invalid SteamID");
    return;
  }

  void *level =
      *(void **)((uint8_t *)hook_engine_get() + UGAMEENGINE_LEVEL_OFFSET);
  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);

  int kicked = 0;
  for (int i = 0; i < actor_count && !kicked; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;

    void *pc = Cast_APlayerController(actor);
    if (!pc)
      continue;

    const ucs2_t *objname = UObject_GetName(pc);
    if (!objname)
      continue;
    // Skip UTServerAdminSpectator
    if (objname[0] == 'U' && objname[1] == 'T' && objname[2] == 'S' &&
        objname[3] == 'e')
      continue;

    void *netconn =
        *(void **)((uint8_t *)pc + APLAYERCONTROLLER_OFFSET_NETCONN);
    if (!netconn)
      continue;

    uint64_t steamid =
        *(uint64_t *)((uint8_t *)netconn + UNETCONN_OFFSET_STEAMID);
    if (steamid == 0)
      steamid = *(uint64_t *)((uint8_t *)netconn + UNETCONN_OFFSET_STEAMID_ALT);

    hook_log_debug("kick: pc=%p steamid=%" PRIu64 " target=%" PRIu64 "\n", pc,
                   steamid, target);

    if (steamid == target) {
      AGameInfo_eventKickIdler(game_info, pc);
      kicked = 1;
    }
  }
  kicked ? hook_socket_finish_ok() : hook_socket_finish_err("player not found");
}

/*
 * Sends a private message to one specific player via ClientMessage RPC.
 * Message is visible only to the target.
 * Bypasses the broadcast chain entirely.
 */
static void cmd_send_player_message(void) {
  if (g_socket_slot.req.argc < 2) {
    hook_socket_finish_err("args: SteamID64, Message");
    return;
  }

  uint64_t target_id = (uint64_t)strtoull(g_socket_slot.req.args[0], NULL, 10);
  if (target_id == 0) {
    hook_socket_finish_err("invalid SteamID");
    return;
  }

  void *level =
      *(void **)((uint8_t *)hook_engine_get() + UGAMEENGINE_LEVEL_OFFSET);
  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);

  // Build prefixed message
  static const char prefix[] = "[Server->You]: ";
  const size_t prefix_len = sizeof(prefix) - 1;
  const size_t msg_len = strlen(g_socket_slot.req.args[1]);
  const size_t copy_len = msg_len < (ARG_MAX_CHARS - prefix_len - 1)
                              ? msg_len
                              : (ARG_MAX_CHARS - prefix_len - 1);
  char prefixed[ARG_MAX_CHARS];
  memcpy(prefixed, prefix, prefix_len);
  memcpy(prefixed + prefix_len, g_socket_slot.req.args[1], copy_len);
  prefixed[prefix_len + copy_len] = '\0';

  ucs2_t msg_ucs2[ARG_MAX_CHARS] = {0};
  utf8_to_ucs2(prefixed, msg_ucs2, ARG_MAX_CHARS);

  FString msg_fstr = {0};
  FString_ctor(&msg_fstr, msg_ucs2);
  FName ftype = {FNAME_ServerSay};

  int found = 0;
  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;
    if (!is_player_controller(UObject_GetName(actor)))
      continue;

    void *netconn =
        *(void **)((uint8_t *)actor + APLAYERCONTROLLER_OFFSET_NETCONN);
    if (!netconn)
      continue;

    uint64_t sid = *(uint64_t *)((uint8_t *)netconn + UNETCONN_OFFSET_STEAMID);
    if (sid == 0)
      sid = *(uint64_t *)((uint8_t *)netconn + UNETCONN_OFFSET_STEAMID_ALT);
    if (sid != target_id)
      continue;

    APlayerController_eventClientMessage(actor, &msg_fstr, ftype);
    found = 1;
    break;
  }
  FString_dtor(&msg_fstr);

  found ? hook_socket_finish_ok() : hook_socket_finish_err("player not found");
}

// ============================================================================
// ZEDS
// ============================================================================
/*
 * Returns all living zeds in the current wave.
 * Traverses the actor list and filters for actors whose class name starts with
 * "Zombie". Dead zeds (Health <= 0) are excluded.
 * Fields per zed:
 *   "class"  -> class name with "Zombie" prefix stripped (e.g. "Clot", "Boss")
 *   "health" -> current HP (int, always > 0)
 */
static void cmd_get_zeds(void) {
  void *level =
      *(void **)((uint8_t *)hook_engine_get() + UGAMEENGINE_LEVEL_OFFSET);
  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":[");
  int first = 1;

  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;

    const ucs2_t *name = UObject_GetName(actor);
    if (!is_zed_actor(name))
      continue;

    int health = *(int *)((uint8_t *)actor + APAWN_OFFSET_Health);
    if (health <= 0)
      continue;

    // Strip "Zombie" prefix (6 chars) for a cleaner class name
    char class_buf[64] = "";
    const ucs2_t *src = name + 6;
    int j = 0;
    // Skip trailing _NNN instance suffix (e.g. "Clot_12" → "Clot") */
    while (src[j] && src[j] != '_' && j < 63) {
      class_buf[j] = (char)src[j];
      j++;
    }
    class_buf[j] = '\0';

    if (!first)
      jb_raw(&jb, ",");
    first = 0;
    jb_raw(&jb, "{\"class\":");
    jb_str(&jb, class_buf);
    jb_raw(&jb, ",\"health\":");
    jb_int(&jb, health);
    jb_raw(&jb, "}");
  }
  jb_raw(&jb, "]}");

  hook_socket_finish_json(&jb);
}

/*
 * Instantly kills all living zeds in the current wave.
 * Same actor traversal as cmd_get_zeds. Sets Health to 0 on every living
 * monster actor. The engine's death event fires naturally on the next tick
 * (the hook does not need to call it explicitly).
 */
static void cmd_kill_zeds(void) {
  void *level =
      *(void **)((uint8_t *)hook_engine_get() + UGAMEENGINE_LEVEL_OFFSET);
  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);

  int killed = 0;
  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;
    if (!is_zed_actor(UObject_GetName(actor)))
      continue;

    int health = *(int *)((uint8_t *)actor + APAWN_OFFSET_Health);
    if (health <= 0)
      continue;

    // Call through the normal death path:
    // fires Died(), death animation, ragdoll, and proper actor cleanup.
    // Damage of 100000 ensures death regardless of difficulty or monster HP.
    // NULL instigator and damage type are safe.
    AActor_eventTakeDamage(actor, 100000,    // damage
                           NULL,             // instigator APawn
                           0.0f, 0.0f, 0.0f, // HitLocation FVector
                           0.0f, 0.0f, 0.0f, // Momentum FVector
                           NULL,             // DamageType UClass*
                           0);               // extra
    killed++;
  }

  hook_log_debug("KillZeds: killed %d zed(s)\n", killed);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":{\"killed\":");
  jb_int(&jb, killed);
  jb_raw(&jb, "}}");

  hook_socket_finish_json(&jb);
}

// ============================================================================
// ACCESS CONTROL
// ============================================================================
/*
 * Reads the live GamePassword from AccessControl.
 * Returns empty string if the password is not set.
 */
static void cmd_get_game_password(void) {
  void *ac = find_access_control();
  if (!ac) {
    hook_socket_finish_err("AccessControl not found");
    return;
  }

  FString *fs = (FString *)((uint8_t *)ac + ACCESSCONTROL_OFFSET_GamePassword);
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  if (fs->Data && fs->Num > 0)
    jb_ucs2(&jb, fs->Data);
  else
    jb_raw(&jb, "\"\"");
  jb_raw(&jb, "}");

  hook_socket_finish_json(&jb);
}

/*
 * Reads the live AdminPassword from AccessControl.
 * Returns empty string if the password is not set.
 */
static void cmd_get_admin_password(void) {
  void *ac = find_access_control();
  if (!ac) {
    hook_socket_finish_err("AccessControl not found");
    return;
  }

  FString *fs = (FString *)((uint8_t *)ac + ACCESSCONTROL_OFFSET_AdminPassword);
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  if (fs->Data && fs->Num > 0)
    jb_ucs2(&jb, fs->Data);
  else
    jb_raw(&jb, "\"\"");
  jb_raw(&jb, "}");

  hook_socket_finish_json(&jb);
}

/*
 * Returns the live IPPolicies TArray as a JSON string array.
 * Each entry is a policy string, e.g. "ACCEPT;*" or "DENY;1.2.3.4".
 * Reflects the current in-memory state.
 */
static void cmd_get_ip_policies(void) {
  void *ac = find_access_control();
  if (!ac) {
    hook_socket_finish_err("AccessControl not found");
    return;
  }

  TArrayFString *arr =
      (TArrayFString *)((uint8_t *)ac + ACCESSCONTROL_OFFSET_IPPolicies);
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":[");

  if (!arr->Data || arr->Num <= 0) {
    jb_raw(&jb, "]}");
    hook_socket_finish_json(&jb);
    return;
  }

  char utf8[ARG_MAX_CHARS];
  int first = 1;
  for (int i = 0; i < arr->Num; i++) {
    FString *entry = &arr->Data[i];
    if (!entry->Data || entry->Num <= 0 || entry->Num > 512)
      continue;

    if (!first)
      jb_raw(&jb, ",");
    first = 0;

    ucs2_to_utf8(entry->Data, utf8, sizeof(utf8));
    jb_str(&jb, utf8);
  }
  jb_raw(&jb, "]}");

  hook_socket_finish_json(&jb);
}

/*
 * Returns the live BannedIDs TArray as a structured JSON array.
 * Each entry is split on the first space: left=SteamID, right=PlayerName.
 */
static void cmd_get_banned_ids(void) {
  void *ac = find_access_control();
  if (!ac) {
    hook_socket_finish_err("AccessControl not found");
    return;
  }

  TArrayFString *arr =
      (TArrayFString *)((uint8_t *)ac + ACCESSCONTROL_OFFSET_BannedIDs);
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":[");

  if (!arr->Data || arr->Num <= 0) {
    jb_raw(&jb, "]}");
    hook_socket_finish_json(&jb);
    return;
  }

  char utf8[ARG_MAX_CHARS];
  int first = 1;
  for (int i = 0; i < arr->Num; i++) {
    FString *entry = &arr->Data[i];
    if (!entry->Data || entry->Num <= 0 || entry->Num > 512)
      continue;
    ucs2_to_utf8(entry->Data, utf8, sizeof(utf8));

    // Split "<steamid> <name>" on first space
    char *space = strchr(utf8, ' ');
    char id_buf[32] = {0};
    char name_buf[128] = {0};
    if (space) {
      int id_len = (int)(space - utf8);
      if (id_len >= (int)sizeof(id_buf))
        id_len = sizeof(id_buf) - 1;
      memcpy(id_buf, utf8, id_len);
      strncpy(name_buf, space + 1, sizeof(name_buf) - 1);
    } else {
      strncpy(id_buf, utf8, sizeof(id_buf) - 1);
      strncpy(name_buf, "?", sizeof(name_buf) - 1);
    }

    if (!first)
      jb_raw(&jb, ",");
    first = 0;
    jb_raw(&jb, "{\"id\":");
    jb_str(&jb, id_buf);
    jb_raw(&jb, ",\"name\":");
    jb_str(&jb, name_buf);
    jb_raw(&jb, "}");
  }
  jb_raw(&jb, "]}");

  hook_socket_finish_json(&jb);
}

// ============================================================================
// LIVE
// ============================================================================
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

/*
 * Sets the game difficulty and syncs both GRI fields:
 * BaseDifficulty (UI display) and GameDiff (tab overlay, cosmetic).
 * Effect is immediate and per-spawn: GameDifficulty is reads each time a new
 * monster is spawned to calculate stats. Already-spawned zeds are not
 * retroactively affected. Already-connected players may not see the UI change
 * right away, they need to relog or wait for the next match.
 * This is a client-side replication issue, visual only.
 * Change is lost on map change.
 */
static void cmd_set_live_game_difficulty(void *game_info) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: Difficulty");
    return;
  }

  float new_diff = strtof(g_socket_slot.req.args[0], NULL);
  // if (new_diff != 1.0f && new_diff != 2.0f && new_diff != 4.0f &&
  //     new_diff != 5.0f && new_diff != 7.0f) {
  //   hook_socket_finish_err(
  //       "invalid difficulty value");
  //   return;
  // }

  // Read and write GameDifficulty via memcpy to avoid strict aliasing UB
  uint8_t *ptr = (uint8_t *)game_info + GAMETYPE_OFFSET_GameDifficulty;
  float old_diff;
  memcpy(&old_diff, ptr, sizeof(old_diff));
  memcpy(ptr, &new_diff, sizeof(new_diff));

  hook_log_debug("SetLiveGameDifficulty: %.6g -> %.6g\n", (double)old_diff,
                 (double)new_diff);

  // Sync GRI fields so the UI stays consistent.
  // find_gri() may return NULL during a level transition
  void *gri = find_gri();
  if (gri) {
    // BaseDifficulty drives the difficulty string and wave counter
    // display in the lobby and scoreboard. Written as a single byte
    uint8_t new_base_diff = (uint8_t)(int)new_diff;
    *((uint8_t *)gri + GRI_OFFSET_BaseDifficulty) = new_base_diff;
    hook_log_debug(
        "SetLiveGameDifficulty: GRI+0x5c9 (BaseDifficulty) synced to %d\n",
        (int)new_base_diff);

    // GameDiff (float), cosmetic copy, drives tab overlay difficulty name
    memcpy((uint8_t *)gri + GRI_OFFSET_GameDiff, &new_diff, sizeof(new_diff));
    hook_log_debug(
        "SetLiveGameDifficulty: GRI+0x678 (GameDiff) synced to %.6g\n",
        (double)new_diff);
  } else {
    hook_log_debug("SetLiveGameDifficulty: GRI not found, "
                   "BaseDifficulty and GameDiff not updated\n");
  }

  char old_str[32], new_str[32];
  snprintf(old_str, sizeof(old_str), "%.6g", (double)old_diff);
  snprintf(new_str, sizeof(new_str), "%.6g", (double)new_diff);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":{\"old\":");
  jb_raw(&jb, old_str);
  jb_raw(&jb, ",\"new\":");
  jb_raw(&jb, new_str);
  jb_raw(&jb, "}}");

  hook_socket_finish_json(&jb);
}

/*
 * Sets the maximum number of players allowed on the server.
 * Effect is immediate: the engine checks MaxPlayers on each new connection
 * attempt, so new joins are capped at the updated value right away.
 * Already-connected players are not kicked.
 * Change is lost on map change.
 */
static void cmd_set_live_max_players(void *game_info) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: MaxPlayers");
    return;
  }

  // Let's be EXTRA generous here
  int new_max = (int)strtol(g_socket_slot.req.args[0], NULL, 10);
  if (new_max < 1 || new_max > 32) {
    hook_socket_finish_err("MaxPlayers must be between 1 and 32");
    return;
  }

  uint8_t *ptr = (uint8_t *)game_info + GAMETYPE_OFFSET_MaxPlayers;
  int old_max;
  memcpy(&old_max, ptr, sizeof(old_max));
  memcpy(ptr, &new_max, sizeof(new_max));

  hook_log_debug("SetLiveMaxPlayers: %d -> %d\n", old_max, new_max);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":{\"old\":");
  jb_int(&jb, old_max);
  jb_raw(&jb, ",\"new\":");
  jb_int(&jb, new_max);
  jb_raw(&jb, "}}");

  hook_socket_finish_json(&jb);
}

/*
 * Sets a new game password.
 * If the new value fits within the existing FString buffer (new_num <= Max),
 * it is written in-place. Otherwise a new buffer is allocated via FString_ctor
 * and swapped in. The old buffer is intentionally leaked.
 * Effect is immediate, change is lost on map change.
 */
static void cmd_set_live_game_password(void) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: Password");
    return;
  }

  void *ac = find_access_control();
  if (!ac) {
    hook_socket_finish_err("AccessControl not found");
    return;
  }

  ucs2_t new_val[ARG_MAX_CHARS] = {0};
  arg_to_ucs2(0, new_val, ARG_MAX_CHARS);

  int new_len = 0;
  while (new_val[new_len])
    new_len++;
  int new_num = new_len + 1; // include NT

  FString *fs = (FString *)((uint8_t *)ac + ACCESSCONTROL_OFFSET_GamePassword);
  hook_log_debug("SetLiveGamePassword: Data=%p Num=%d Max=%d new_num=%d\n",
                 (void *)fs->Data, fs->Num, fs->Max, new_num);

  if (fs->Max > 0 && new_num <= fs->Max) {
    memcpy(fs->Data, new_val, (size_t)new_num * sizeof(ucs2_t));
    fs->Num = new_num;
    hook_log_debug("SetLiveGamePassword: wrote in-place\n");
  } else {
    FString tmp = {0};
    FString_ctor(&tmp, new_val);
    fs->Data = tmp.Data;
    fs->Num = tmp.Num;
    fs->Max = tmp.Max;
    hook_log_debug("SetLiveGamePassword: allocated new buffer (old leaked)\n");
  }

  hook_socket_finish_ok();
}

// ============================================================================
// WAVE STATE
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
// SKIP TRADER
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
  int wip = *(int *)((uint8_t *)game_info + GAMETYPE_OFFSET_bWaveInProgress);
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
  hook_log_debug("SkipTrader: %d -> 6\n", countdown);

  hook_socket_finish_ok();
}

// ============================================================================
// CONFIG
// ============================================================================
/*
 * Retrieves a string value from GConfig.
 * Args: Section, Key [, File]
 * File is optional, omit or pass empty string to use GConfig default.
 */
static void cmd_cfg_get_str(void) {
  if (g_socket_slot.req.argc < 2) {
    hook_socket_finish_err("args: Section, Key [, File]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t key[256] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);
  arg_to_ucs2(1, key, 256);

  if (g_socket_slot.req.argc > 2 && g_socket_slot.req.args[2][0]) {
    arg_to_ucs2(2, file, 256);
    fp = file;
  }

  ucs2_t out[ARG_MAX_CHARS] = {0};
  if (!GConfig_GetString(gcfg, sec, key, out, ARG_MAX_CHARS, fp)) {
    hook_socket_finish_err("not found");
    return;
  }

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_ucs2(&jb, out);
  jb_raw(&jb, "}");

  hook_socket_finish_json(&jb);
}

/*
 * Retrieves an integer value from GConfig.
 * Args: Section, Key [, File]
 */
static void cmd_cfg_get_int(void) {
  if (g_socket_slot.req.argc < 2) {
    hook_socket_finish_err("args: Section, Key [, File]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t key[256] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);
  arg_to_ucs2(1, key, 256);

  if (g_socket_slot.req.argc > 2 && g_socket_slot.req.args[2][0]) {
    arg_to_ucs2(2, file, 256);
    fp = file;
  }

  int out = 0;
  if (!GConfig_GetInt(gcfg, sec, key, &out, fp)) {
    hook_socket_finish_err("not found");
    return;
  }

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_int(&jb, out);
  jb_raw(&jb, "}");

  hook_socket_finish_json(&jb);
}

/*
 * Retrieves a float value from GConfig.
 * Args: Section, Key [, File]
 */
static void cmd_cfg_get_float(void) {
  if (g_socket_slot.req.argc < 2) {
    hook_socket_finish_err("args: Section, Key [, File]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t key[256] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);
  arg_to_ucs2(1, key, 256);

  if (g_socket_slot.req.argc > 2 && g_socket_slot.req.args[2][0]) {
    arg_to_ucs2(2, file, 256);
    fp = file;
  }

  float out = 0.0f;
  if (!GConfig_GetFloat(gcfg, sec, key, &out, fp)) {
    hook_socket_finish_err("not found");
    return;
  }

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_float(&jb, out);
  jb_raw(&jb, "}");

  hook_socket_finish_json(&jb);
}

/*
 * Retrieves a boolean value from GConfig.
 * Args: Section, Key [, File]
 */
static void cmd_cfg_get_bool(void) {
  if (g_socket_slot.req.argc < 2) {
    hook_socket_finish_err("args: Section, Key [, File]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t key[256] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);
  arg_to_ucs2(1, key, 256);

  if (g_socket_slot.req.argc > 2 && g_socket_slot.req.args[2][0]) {
    arg_to_ucs2(2, file, 256);
    fp = file;
  }

  int out = 0;
  if (!GConfig_GetBool(gcfg, sec, key, &out, fp)) {
    hook_socket_finish_err("not found");
    return;
  }

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_bool(&jb, out);
  jb_raw(&jb, "}");

  hook_socket_finish_json(&jb);
}

/*
 * Sets a string value in GConfig.
 * Args:   Section, Key, Value [, File [, Unique]]
 * File    optional, empty string uses GConfig default.
 * Unique: optional, "1" = replace if key exists, otherwise append.
 *         Default is 0 (always append).
 * Note: changes are in-memory only until CfgFlush is called.
 */
static void cmd_cfg_set_str(void) {
  if (g_socket_slot.req.argc < 3) {
    hook_socket_finish_err("args: Section, Key, Value [, File [, Unique]]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t key[256] = {0};
  ucs2_t val[ARG_MAX_CHARS] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);
  arg_to_ucs2(1, key, 256);
  arg_to_ucs2(2, val, ARG_MAX_CHARS);

  if (g_socket_slot.req.argc > 3 && g_socket_slot.req.args[3][0]) {
    arg_to_ucs2(3, file, 256);
    fp = file;
  }

  int unique =
      g_socket_slot.req.argc > 4 && strcmp(g_socket_slot.req.args[4], "1") == 0;

  GConfig_SetString(gcfg, sec, key, val, fp, unique);

  hook_socket_finish_ok();
}

/*
 * Sets an integer value in GConfig.
 * Args: Section, Key, Value [, File]
 * Note: changes are in-memory only until CfgFlush is called.
 */
static void cmd_cfg_set_int(void) {
  if (g_socket_slot.req.argc < 3) {
    hook_socket_finish_err("args: Section, Key, Value [, File]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t key[256] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);
  arg_to_ucs2(1, key, 256);

  if (g_socket_slot.req.argc > 3 && g_socket_slot.req.args[3][0]) {
    arg_to_ucs2(3, file, 256);
    fp = file;
  }

  int v = (int)strtol(g_socket_slot.req.args[2], NULL, 10);
  GConfig_SetInt(gcfg, sec, key, v, fp);

  hook_socket_finish_ok();
}

/*
 * Sets a float value in GConfig.
 * Args: Section, Key, Value [, File]
 * Note: changes are in-memory only until CfgFlush is called.
 */
static void cmd_cfg_set_float(void) {
  if (g_socket_slot.req.argc < 3) {
    hook_socket_finish_err("args: Section, Key, Value [, File]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t key[256] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);
  arg_to_ucs2(1, key, 256);

  if (g_socket_slot.req.argc > 3 && g_socket_slot.req.args[3][0]) {
    arg_to_ucs2(3, file, 256);
    fp = file;
  }

  float v = strtof(g_socket_slot.req.args[2], NULL);
  GConfig_SetFloat(gcfg, sec, key, v, fp);

  hook_socket_finish_ok();
}

/*
 * Sets a boolean value in GConfig.
 * Args: Section, Key, Value [, File]
 * Value: "1", "true", "True", "TRUE" = true, anything else = false.
 * Note: changes are in-memory only until CfgFlush is called.
 */
static void cmd_cfg_set_bool(void) {
  if (g_socket_slot.req.argc < 3) {
    hook_socket_finish_err("args: Section, Key, Value [, File]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t key[256] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);
  arg_to_ucs2(1, key, 256);

  if (g_socket_slot.req.argc > 3 && g_socket_slot.req.args[3][0]) {
    arg_to_ucs2(3, file, 256);
    fp = file;
  }

  const char *b = g_socket_slot.req.args[2];
  int v = (b[0] == '1' || strcmp(b, "true") == 0 || strcmp(b, "True") == 0 ||
           strcmp(b, "TRUE") == 0);
  GConfig_SetBool(gcfg, sec, key, v, fp);

  hook_socket_finish_ok();
}

/*
 * Retrieves all key=value pairs from a GConfig section.
 * Args: Section [, File]
 * File: optionl, empty string uses GConfig default.
 * GConfig_GetSection returns a double-null-terminated flat buffer:
 *   "Key1=Val1\0Key2=Val2\0\0"
 * Parses it into a JSON array of strings.
 * Buffer size is CFG_BUF_CHARS*4 UCS-2 chars,
 * very large sections may be truncated silently.
 */
static void cmd_cfg_get_section(void) {
  if (g_socket_slot.req.argc < 1) {
    hook_socket_finish_err("args: Section [, File]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);

  if (g_socket_slot.req.argc > 1 && g_socket_slot.req.args[1][0]) {
    arg_to_ucs2(1, file, 256);
    fp = file;
  }

  ucs2_t raw[CFG_BUF_CHARS * 4] = {0};
  GConfig_GetSection(gcfg, sec, raw, CFG_BUF_CHARS * 4, fp);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":[");

  int first = 1;
  int ri = 0;
  while (ri < CFG_BUF_CHARS * 4 - 1) {
    if (raw[ri] == 0)
      break; // double-null = end of section

    // find end of this entry
    int start = ri;
    while (raw[ri])
      ri++;

    // copy entry to temp buffer
    int entry_len = ri - start;
    int copy_len =
        entry_len < ARG_MAX_CHARS - 1 ? entry_len : ARG_MAX_CHARS - 1;
    ucs2_t entry[ARG_MAX_CHARS] = {0};
    memcpy(entry, raw + start, copy_len * sizeof(ucs2_t));

    char entry_utf8[ARG_MAX_CHARS] = {0};
    ucs2_to_utf8(entry, entry_utf8, sizeof(entry_utf8));

    if (!first)
      jb_raw(&jb, ",");
    first = 0;

    jb_str(&jb, entry_utf8);

    ri++; // skip null separator
  }
  jb_raw(&jb, "]}");

  hook_socket_finish_json(&jb);
}

/*
 * Deletes entries matching Section+Key+Value from GConfig.
 * Args: Section, Key, Value [, File]
 * File: optional, empty string uses GConfig default.
 */
static void cmd_cfg_delete_str(void) {
  if (g_socket_slot.req.argc < 3) {
    hook_socket_finish_err("args: Section, Key, Value [, File]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t key[256] = {0};
  ucs2_t val[ARG_MAX_CHARS] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);
  arg_to_ucs2(1, key, 256);
  arg_to_ucs2(2, val, ARG_MAX_CHARS);

  if (g_socket_slot.req.argc > 3 && g_socket_slot.req.args[3][0]) {
    arg_to_ucs2(3, file, 256);
    fp = file;
  }

  int deleted = cfg_delete_entries(gcfg, sec, key, val, fp, 0);
  if (deleted == 0) {
    hook_socket_finish_err("no matching entries found");
    return;
  }

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":{\"deleted\":");
  jb_int(&jb, deleted);
  jb_raw(&jb, "}}");

  hook_socket_finish_json(&jb);
}

/*
 * Deletes all entries matching Section+Key from GConfig (value ignored).
 * Args: Section, Key [, File [, Max]]
 * File: optional, empty string uses GConfig default.
 * Max:  optional, 0 = delete all matches, N = delete at
 * most N occurrences.
 */
static void cmd_cfg_delete_key_str(void) {
  if (g_socket_slot.req.argc < 2) {
    hook_socket_finish_err("args: Section, Key [, File [, Max]]");
    return;
  }

  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t sec[256] = {0};
  ucs2_t key[256] = {0};
  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  arg_to_ucs2(0, sec, 256);
  arg_to_ucs2(1, key, 256);

  if (g_socket_slot.req.argc > 2 && g_socket_slot.req.args[2][0]) {
    arg_to_ucs2(2, file, 256);
    fp = file;
  }

  int max_del = g_socket_slot.req.argc > 3
                    ? (int)strtol(g_socket_slot.req.args[3], NULL, 10)
                    : 0;

  int deleted = cfg_delete_entries(gcfg, sec, key, NULL, fp, max_del);
  if (deleted == 0) {
    hook_socket_finish_err("no matching entries found");
    return;
  }

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":{\"deleted\":");
  jb_int(&jb, deleted);
  jb_raw(&jb, "}}");

  hook_socket_finish_json(&jb);
}

/*
 * Flushes GConfig in-memory cache to disk.
 * Args: [File]
 * File: optional, empty string flushes all files.
 * Call after any CfgSet* to persist changes across level changes.
 */
static void cmd_cfg_flush(void) {
  void *gcfg = get_gconfig();
  if (!gcfg) {
    hook_socket_finish_err("GConfig not ready");
    return;
  }

  ucs2_t file[256] = {0};
  ucs2_t *fp = NULL;

  if (g_socket_slot.req.argc > 0 && g_socket_slot.req.args[0][0]) {
    arg_to_ucs2(0, file, 256);
    fp = file;
  }

  // bRead=1 -> write to disk, preserve cache
  // bRead=0 -> write then evict from cache
  GConfig_Flush(gcfg, 1, fp);

  hook_socket_finish_ok();
}

// ============================================================================
// COMMAND DISPATCHER
// ============================================================================
void hook_command_dispatch(void) {
  char cmd[CMD_MAX_CHARS];
  strncpy(cmd, g_socket_slot.req.cmd, sizeof(cmd) - 1);
  cmd[sizeof(cmd) - 1] = '\0';
  for (int i = 0; cmd[i]; i++)
    cmd[i] = tolower((unsigned char)cmd[i]);

#ifdef DEBUG
  if (strncmp(cmd, "debug", 5) == 0) {
    hook_debug_command_dispatch(cmd);
    return;
  }
#endif

  hook_log_debug("Executing cmd: %s\n", cmd);

  // TODO: Dispatch table

  // Ping
  if (strcmp(cmd, "ping") == 0) {
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
  if (strcmp(cmd, "exec") == 0) {
    cmd_exec();
    return;
  }

  // Server Travel - Map Change
  if (strcmp(cmd, "servertravel") == 0) {
    cmd_server_travel(level_info);
    return;
  }

  // Say - Admin Server Message
  if (strcmp(cmd, "say") == 0) {
    cmd_say(game_info);
    return;
  }

  // Announce - Admin Announcement
  if (strcmp(cmd, "announce") == 0) {
    cmd_announce(game_info);
    return;
  }

  // ServerInfo - Get Server Info
  if (strcmp(cmd, "serverinfo") == 0) {
    cmd_get_server_info();
    return;
  }

  // LevelURL - Get Level URL with options
  if (strcmp(cmd, "levelurl") == 0) {
    cmd_get_level_url();
    return;
  }

  // WaveState - Get Wave State
  if (strcmp(cmd, "wavestate") == 0) {
    cmd_get_wave_state();
    return;
  }

  // SkipTrader - Set Trader Countdown to 6s
  if (strcmp(cmd, "skiptrader") == 0) {
    cmd_skip_trader(game_info);
    return;
  }

  // Players - Get all connected players
  if (strcmp(cmd, "players") == 0) {
    cmd_get_players();
    return;
  }

  // Kick - Kick a player by SteamID64
  if (strcmp(cmd, "kick") == 0) {
    cmd_kick(game_info);
    return;
  }

  // SendPlayerMessage - Send a message to a connected player
  if (strcmp(cmd, "sendplayermessage") == 0) {
    cmd_send_player_message();
    return;
  }

  // Zeds - List all living Zeds in the current wave
  if (strcmp(cmd, "zeds") == 0) {
    cmd_get_zeds();
    return;
  }

  // KillZeds - Kill all living Zeds in the current wave
  if (strcmp(cmd, "killzeds") == 0) {
    cmd_kill_zeds();
    return;
  }

  // GamePassword - Get the current game's password
  if (strcmp(cmd, "gamepassword") == 0) {
    cmd_get_game_password();
    return;
  }

  // AdminPassword - Get the current admin's password
  if (strcmp(cmd, "adminpassword") == 0) {
    cmd_get_admin_password();
    return;
  }

  // IPPolicies - Get the current IP access control policies
  if (strcmp(cmd, "ippolicies") == 0) {
    cmd_get_ip_policies();
    return;
  }

  // BannedIDs - Get the current Steam ID ban list
  if (strcmp(cmd, "bannedids") == 0) {
    cmd_get_banned_ids();
    return;
  }

  // --------------------------------------------------------------------------

  // SetLiveServerName - Set Server Name
  // Do not survive a map change
  if (strcmp(cmd, "setliveservername") == 0) {
    cmd_set_live_server_name();
    return;
  }

  // SetLiveShortName - Set Short Server Name
  // Do not survive a map change
  if (strcmp(cmd, "setliveshortname") == 0) {
    cmd_set_live_short_name();
    return;
  }

  // SetLiveAdminName - Set Admin Name
  // Do not survive a map change
  if (strcmp(cmd, "setliveadminname") == 0) {
    cmd_set_live_admin_name();
    return;
  }

  // SetLiveAdminMail - Set Admin Mail
  // Do not survive a map change
  if (strcmp(cmd, "setliveadminmail") == 0) {
    cmd_set_live_admin_email();
    return;
  }

  // SetLiveServerRegion - Set Server Region
  // Do not survive a map change
  if (strcmp(cmd, "setliveserverregion") == 0) {
    cmd_set_live_server_region();
    return;
  }

  // SetLiveMOTD - Set Message of the Day
  // Do not survive a map change
  if (strcmp(cmd, "setlivemotd") == 0) {
    cmd_set_live_motd();
    return;
  }

  // SetLiveGameDifficulty - Set Game Difficulty
  // Do not survive a map change
  if (strcmp(cmd, "setlivegamedifficulty") == 0) {
    cmd_set_live_game_difficulty(game_info);
    return;
  }

  // SetLiveMaxPlayer - Set Max Players
  // Do not survive a map change
  if (strcmp(cmd, "setlivemaxplayer") == 0) {
    cmd_set_live_max_players(game_info);
    return;
  }

  // SetLiveGamePassword - Set Game Password
  // Do not survive a map change
  if (strcmp(cmd, "setlivegamepassword") == 0) {
    cmd_set_live_game_password();
    return;
  }

  // --------------------------------------------------------------------------

  if (strcmp(cmd, "cfggetstr") == 0) {
    cmd_cfg_get_str();
    return;
  }

  if (strcmp(cmd, "cfggetint") == 0) {
    cmd_cfg_get_int();
    return;
  }

  if (strcmp(cmd, "cfggetfloat") == 0) {
    cmd_cfg_get_float();
    return;
  }

  if (strcmp(cmd, "cfggetbool") == 0) {
    cmd_cfg_get_bool();
    return;
  }

  if (strcmp(cmd, "cfgsetstr") == 0) {
    cmd_cfg_set_str();
    return;
  }

  if (strcmp(cmd, "cfgsetint") == 0) {
    cmd_cfg_set_int();
    return;
  }

  if (strcmp(cmd, "cfgsetfloat") == 0) {
    cmd_cfg_set_float();
    return;
  }

  if (strcmp(cmd, "cfgsetbool") == 0) {
    cmd_cfg_set_bool();
    return;
  }

  if (strcmp(cmd, "cfgflush") == 0) {
    cmd_cfg_flush();
    return;
  }

  if (strcmp(cmd, "cfggetsection") == 0) {
    cmd_cfg_get_section();
    return;
  }

  if (strcmp(cmd, "cfgdeletestr") == 0) {
    cmd_cfg_delete_str();
    return;
  }

  if (strcmp(cmd, "cfgdeletekeystr") == 0) {
    cmd_cfg_delete_key_str();
    return;
  }
}