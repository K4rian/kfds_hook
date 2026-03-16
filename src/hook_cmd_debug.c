#ifdef DEBUG

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "hook_cmd_debug.h"
#include "hook_config.h"
#include "hook_engine.h"
#include "hook_log.h"
#include "hook_socket.h"

// ============================================================================
// DEBUG COMMAND HELPERS
// ============================================================================
/*
 * Write a hex+ASCII dump of [scan_size] bytes from [ptr] to [f]
 * label is printed as a section header
 */
static void hexdump_to(FILE *f, const char *label, void *ptr, int scan_size) {
  uint8_t *base = (uint8_t *)ptr;
  // Shouldn't happen
  if (scan_size <= 0) {
    fprintf(f, "%s @ %p: (empty or invalid scan_size=%d)\n", label, ptr,
            scan_size);
    return;
  }

  fprintf(f, "%s @%p:\n", label, ptr);
  for (int off = 0; off < scan_size; off++) {
    if (off % 16 == 0) {
      fprintf(f, "  +0x%03x: ", off);
    }
    fprintf(f, "%02x ", base[off]);
    if (off % 16 == 15) {
      fprintf(f, " |");
      for (int k = off - 15; k <= off; k++) {
        fprintf(f, "%c", (base[k] >= 0x20 && base[k] < 0x7f) ? base[k] : '.');
      }
      fprintf(f, "|\n");
    }
  }

  int remainder = scan_size % 16;
  if (remainder != 0) {
    for (int i = remainder; i < 16; i++) {
      fprintf(f, "   ");
    }
    fprintf(f, " |");
    for (int k = scan_size - remainder; k < scan_size; k++) {
      fprintf(f, "%c", (base[k] >= 0x20 && base[k] < 0x7f) ? base[k] : '.');
    }
    fprintf(f, "|\n");
  }
  fprintf(f, "\n");
}

/*
 * Open a log file for a debug dump command
 *
 * If override_path is non-NULL and non-empty, it is used as the full file
 * path directly. Otherwise, g_config.debug_dump_dir is created if
 * needed and a timestamped filename is generated:
 *   <g_config.debug_dump_dir>/<timestamp_ms>_<cmd_name>.log
 *
 * Returns FILE* on success, NULL on failure
 */
static FILE *dump_open(const char *cmd_name, const char *override_path,
                       char *path_out, size_t path_len) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int64_t ms = (int64_t)ts.tv_sec * 1000 + (int64_t)ts.tv_nsec / 1000000;

  if (override_path && override_path[0] != '\0') {
    // User-supplied path, use as-is, no directory creation
    if (snprintf(path_out, path_len, "%s", override_path) >= (int)path_len) {
      hook_log_error("dump_open: override_path too long (max %zu): %s\n",
                     path_len, override_path);
      return NULL;
    }
  } else {
    // Default: timestamped file under g_config.debug_dump_dir
    if (mkdir(g_config.debug_dump_dir, 0755) != 0 && errno != EEXIST) {
      hook_log_error("dump_open: mkdir(%s) failed: %s\n",
                     g_config.debug_dump_dir, strerror(errno));
      return NULL;
    }
    if (snprintf(path_out, path_len, "%s/%" PRId64 "_%s.log",
                 g_config.debug_dump_dir, ms, cmd_name) >= (int)path_len) {
      hook_log_error("dump_open: generated path too long (max %zu)\n",
                     path_len);
      return NULL;
    }
  }

  FILE *f = fopen(path_out, "w");
  if (!f) {
    hook_log_error("dump_open: fopen(%s) failed: %s\n", path_out,
                   strerror(errno));
    return NULL;
  }

  // File header
  char timebuf[32];
  struct tm *tm_info = localtime(&ts.tv_sec);
  strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
  fprintf(f, "#\n# %s | %s.%03d\n#\n", cmd_name, timebuf, (int)(ms % 1000));
  return f;
}

// ============================================================================
// DEBUG COMMANDS
// ============================================================================
/*
 * Dumps the GameReplicationInfo (GRI) memory layout.
 */
void cmd_debug_gri_dump(void) {
  char path[512];
  FILE *f = dump_open("GRIDump",
                      g_socket_slot.req.argc > 0 && g_socket_slot.req.args[0][0]
                          ? g_socket_slot.req.args[0]
                          : NULL,
                      path, sizeof(path));
  if (!f) {
    hook_socket_finish_err("failed to open dump file");
    return;
  }

  void *gri = find_gri();
  if (!gri) {
    fclose(f);
    hook_socket_finish_err("GRI not found");
    return;
  }

  char label[64];
  snprintf(label, sizeof(label), "GRI=%p +0x580..+0x7ff", gri);
  hexdump_to(f, label, (uint8_t *)gri + 0x580, 0x280);

  fclose(f);
  hook_log_debug("GRIDump saved to %s\n", path);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_str(&jb, path);
  jb_raw(&jb, "}");
  hook_socket_finish_json(&jb);
}

/*
 * Dumps the PlayerReplicationInfo (PRI) memory layout.
 */
void cmd_debug_pri_dump(void) {
  char path[512];
  FILE *f = dump_open("PRIDump",
                      g_socket_slot.req.argc > 0 && g_socket_slot.req.args[0][0]
                          ? g_socket_slot.req.args[0]
                          : NULL,
                      path, sizeof(path));

  if (!f) {
    hook_socket_finish_err("failed to open dump file");
    return;
  }

  void *gri = find_gri();
  if (!gri) {
    fclose(f);
    hook_socket_finish_err("GRI not found");
    return;
  }

  void **pri_data = *(void ***)((uint8_t *)gri + 0x47c);
  int pri_num = *(int *)((uint8_t *)gri + 0x480);
  if (!pri_data || pri_num <= 0) {
    fclose(f);
    hook_socket_finish_err("no players");
    return;
  }

  for (int p = 0; p < pri_num; p++) {
    void *pri = pri_data[p];
    if (!pri)
      continue;

    const ucs2_t *name = UObject_GetName(pri);
    char label[128];
    char name_buf[64] = "(unknown)";
    if (name) {
      int j = 0;
      while (name[j] && j < 63) {
        name_buf[j] = (char)name[j];
        j++;
      }
      name_buf[j] = '\0';
    }
    snprintf(label, sizeof(label), "PRI[%d]=%p (%s) +0x000..+0x5ff", p, pri,
             name_buf);
    hexdump_to(f, label, (uint8_t *)pri + 0x000, 0x600);
  }

  fclose(f);
  hook_log_debug("PRIDump saved to %s\n", path);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_str(&jb, path);
  jb_raw(&jb, "}");
  hook_socket_finish_json(&jb);
}

/*
 * Dumps every non-null actor in the level actor list.
 * Output per actor: index, pointer, and full UObject name.
 */
void cmd_debug_actors_dump(void) {
  char path[512];
  FILE *f = dump_open("ActorsDump",
                      g_socket_slot.req.argc > 0 && g_socket_slot.req.args[0][0]
                          ? g_socket_slot.req.args[0]
                          : NULL,
                      path, sizeof(path));

  if (!f) {
    hook_socket_finish_err("failed to open dump file");
    return;
  }

  void *ge = hook_engine_get();
  if (!ge) {
    fclose(f);
    hook_socket_finish_err("GGameEngine is NULL");
  }
  void *level = *(void **)((uint8_t *)ge + UGAMEENGINE_LEVEL_OFFSET);
  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);

  fprintf(f, "Actor list | %d slots\n\n", actor_count);
  fprintf(f, "%-6s  %-12s  %s\n", "index", "pointer", "name");
  fprintf(f, "------  ------------  ----\n");

  int non_null = 0;
  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;

    const ucs2_t *name = UObject_GetName(actor);
    char name_utf8[256] = "(null)";
    if (name)
      ucs2_to_utf8(name, name_utf8, sizeof(name_utf8));

    fprintf(f, "%-6d  %p  %s\n", i, actor, name_utf8);
    non_null++;
  }
  fprintf(f, "\n%d actors total, %d non-null.\n", actor_count, non_null);

  fclose(f);
  hook_log_debug("ActorsDump saved to %s (%d actors)\n", path, non_null);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_str(&jb, path);
  jb_raw(&jb, "}");
  hook_socket_finish_json(&jb);
}

/*
 * Dumps every connected PlayerController, PC+0x000..+0x5ff.
 * Used to locate the Pawn* pointer on the PC object.
 */
void cmd_debug_pc_dump(void) {
  char path[512];
  FILE *f = dump_open("PCDump",
                      g_socket_slot.req.argc > 0 && g_socket_slot.req.args[0][0]
                          ? g_socket_slot.req.args[0]
                          : NULL,
                      path, sizeof(path));

  if (!f) {
    hook_socket_finish_err("failed to open dump file");
    return;
  }

  void *ge = hook_engine_get();
  if (!ge) {
    fclose(f);
    hook_socket_finish_err("GGameEngine is NULL");
  }
  void *level = *(void **)((uint8_t *)ge + UGAMEENGINE_LEVEL_OFFSET);
  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);

  int dumped = 0;
  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;
    if (!is_player_controller(UObject_GetName(actor)))
      continue;

    void *netconn =
        *(void **)((uint8_t *)actor + APLAYERCONTROLLER_OFFSET_NETCONN);
    if (!netconn)
      continue; /* skip non-human PCs (WebAdmin, bots) */

    const ucs2_t *name = UObject_GetName(actor);
    char name_buf[64] = "(unknown)";
    if (name) {
      int j = 0;
      while (name[j] && j < 63) {
        name_buf[j] = (char)name[j];
        j++;
      }
      name_buf[j] = '\0';
    }

    char label[128];
    snprintf(label, sizeof(label), "PC[%d]=%p (%s) +0x000..+0x5ff", dumped,
             actor, name_buf);
    hexdump_to(f, label, (uint8_t *)actor, 0x600);
    dumped++;
  }

  if (dumped == 0)
    fprintf(f, "No connected human PlayerControllers found.\n");

  fclose(f);
  hook_log_debug("PCDump saved to %s (%d PCs)\n", path, dumped);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_str(&jb, path);
  jb_raw(&jb, "}");
  hook_socket_finish_json(&jb);
}

/*
 * Dumps every human player's Pawn object.
 * Follows PC+0x360 (APLAYERCONTROLLER_OFFSET_PAWN) to reach the Pawn actor.
 * Skips players with NULL Pawn (dead/spectating).
 */
void cmd_debug_pcpawn_dump(void) {
  char path[512];
  FILE *f = dump_open("PCPawnDump",
                      g_socket_slot.req.argc > 0 && g_socket_slot.req.args[0][0]
                          ? g_socket_slot.req.args[0]
                          : NULL,
                      path, sizeof(path));

  if (!f) {
    hook_socket_finish_err("failed to open dump file");
    return;
  }

  void *ge = hook_engine_get();
  if (!ge) {
    fclose(f);
    hook_socket_finish_err("GGameEngine is NULL");
  }
  void *level = *(void **)((uint8_t *)ge + UGAMEENGINE_LEVEL_OFFSET);
  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);

  int dumped = 0;
  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;
    if (!is_player_controller(UObject_GetName(actor)))
      continue;

    void *netconn =
        *(void **)((uint8_t *)actor + APLAYERCONTROLLER_OFFSET_NETCONN);
    if (!netconn)
      continue; // skip non-human PCs

    void *pawn = *(void **)((uint8_t *)actor + APLAYERCONTROLLER_OFFSET_PAWN);
    if (!pawn) {
      fprintf(f, "PC[%d]=%p | Pawn is NULL (dead/spectating)\n\n", dumped,
              actor);
      dumped++;
      continue;
    }

    const ucs2_t *pawn_name = UObject_GetName(pawn);
    char pawn_name_buf[64] = "(unknown)";
    if (pawn_name) {
      int j = 0;
      while (pawn_name[j] && j < 63) {
        pawn_name_buf[j] = (char)pawn_name[j];
        j++;
      }
      pawn_name_buf[j] = '\0';
    }

    char label[128];
    snprintf(label, sizeof(label), "Pawn[%d]=%p (%s) +0x000..+0x3ff", dumped,
             pawn, pawn_name_buf);
    hexdump_to(f, label, (uint8_t *)pawn, 0x400);
    dumped++;
  }

  if (dumped == 0)
    fprintf(f, "No connected human PlayerControllers found.\n");

  fclose(f);
  hook_log_debug("PCPawnDump saved to %s (%d entries)\n", path, dumped);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_str(&jb, path);
  jb_raw(&jb, "}");
  hook_socket_finish_json(&jb);
}

/*
 * Dumps every PlayerController network connection (excluding WebAdmin).
 */
void cmd_debug_pcnetconn_dump(void) {
  char path[512];
  FILE *f = dump_open("PCNetConnDump",
                      g_socket_slot.req.argc > 0 && g_socket_slot.req.args[0][0]
                          ? g_socket_slot.req.args[0]
                          : NULL,
                      path, sizeof(path));

  if (!f) {
    hook_socket_finish_err("failed to open dump file");
    return;
  }

  void *ge = hook_engine_get();
  if (!ge) {
    fclose(f);
    hook_socket_finish_err("GGameEngine is NULL");
  }
  void *level = *(void **)((uint8_t *)ge + UGAMEENGINE_LEVEL_OFFSET);
  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);

  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor || !is_player_controller(UObject_GetName(actor)))
      continue;

    void *netconn =
        *(void **)((uint8_t *)actor + APLAYERCONTROLLER_OFFSET_NETCONN);
    if (!netconn)
      continue;

    char label[64];
    snprintf(label, sizeof(label), "PC=%p NetConn=%p", actor, netconn);
    hexdump_to(f, label, netconn, 0x500);
  }

  fclose(f);
  hook_log_debug("PCNetConnDump saved to %s\n", path);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_str(&jb, path);
  jb_raw(&jb, "}");
  hook_socket_finish_json(&jb);
}

/*
 * Dumps all GNames entries to a file.
 * Output format: index, name string per line.
 */
void cmd_debug_gnames_dump(void) {
  char path[512];
  FILE *f = dump_open("GNamesDump",
                      g_socket_slot.req.argc > 0 && g_socket_slot.req.args[0][0]
                          ? g_socket_slot.req.args[0]
                          : NULL,
                      path, sizeof(path));
  if (!f) {
    hook_socket_finish_err("failed to open dump file");
    return;
  }

  void **data = *(void ***)ADDR_GNAMES;
  int num = *(int *)(ADDR_GNAMES + 4);

  fprintf(f, "GNames: %d entries\n\n", num);
  for (int i = 0; i < num; i++) {
    void *entry = data[i];
    if (!entry)
      continue;
    const ucs2_t *entry_name = (const ucs2_t *)((uint8_t *)entry + 0x0c);
    char name_utf8[256] = {0};
    ucs2_to_utf8(entry_name, name_utf8, sizeof(name_utf8));
    fprintf(f, "[%d] %s\n", i, name_utf8);
  }

  fclose(f);
  hook_log_debug("GNamesDump saved to %s\n", path);

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_str(&jb, path);
  jb_raw(&jb, "}");
  hook_socket_finish_json(&jb);
}

/*
 * Empties a GConfig section and flushes to disk.
 * Args: Section [, File]
 * File: optional, empty string uses GConfig default.
 * WARNING: destructive; removes the entire section with
 * all K/V pairs, including the header.
 */
void cmd_debug_cfg_empty_section(void) {
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

  utf8_to_ucs2(g_socket_slot.req.args[0], sec, 256);
  if (g_socket_slot.req.argc > 1 && g_socket_slot.req.args[1][0]) {
    utf8_to_ucs2(g_socket_slot.req.args[1], file, 256);
    fp = file;
  }

  hook_log_debug("CfgEmptySection: calling EmptySection on [%s]\n",
                 g_socket_slot.req.args[0]);

  GConfig_EmptySection(gcfg, sec, fp);
  GConfig_Flush(gcfg, 1, fp);

  hook_log_debug("CfgEmptySection: done, flushed\n");

  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true,\"d\":");
  jb_str(&jb, g_socket_slot.req.args[0]);
  jb_raw(&jb, "}");
  hook_socket_finish_json(&jb);
}
#endif /* DEBUG */