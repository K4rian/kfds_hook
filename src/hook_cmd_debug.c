#ifdef DEBUG

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "hook_cmd_debug.h"
#include "hook_config.h"
#include "hook_log.h"
#include "hook_socket.h"
#include "hook_engine.h"

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

#endif /* DEBUG */