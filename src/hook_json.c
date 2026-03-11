#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "hook_json.h"
#include "hook_socket_defs.h"
#include "hook_ucs2.h"

// ============================================================================
// JSON
// ============================================================================
/*
 * Append a single byte directly, avoids the strlen() call that jb_raw
 * would perform for every plain ASCII character in jb_str
 */
static inline void jb_rawc(json_buf_t *jb, char c) {
  if (jb->overflow)
    return;

  if (jb->pos >= RESP_MAX_BYTES - 1) {
    jb->overflow = 1;
    return;
  }
  jb->buf[jb->pos++] = c;
  jb->buf[jb->pos] = '\0';
}

void jb_init(json_buf_t *jb) {
  jb->pos = 0;
  jb->overflow = 0;
  jb->buf[0] = '\0';
}

/*
 * Append a raw string (no escaping)
 */
void jb_raw(json_buf_t *jb, const char *s) {
  if (jb->overflow)
    return;

  size_t len = strlen(s);
  if (jb->pos + (int)len >= RESP_MAX_BYTES - 1) {
    jb->overflow = 1;
    return;
  }
  memcpy(jb->buf + jb->pos, s, len);
  jb->pos += (int)len;
  jb->buf[jb->pos] = '\0';
}

/*
 * Append a JSON-escaped quoted string.
 */
void jb_str(json_buf_t *jb, const char *s) {
  jb_rawc(jb, '"');
  for (; *s; s++) {
    if (*s == '"') {
      jb_raw(jb, "\\\"");
    } else if (*s == '\\') {
      jb_raw(jb, "\\\\");
    } else if (*s == '\n') {
      jb_raw(jb, "\\n");
    } else if (*s == '\r') {
      jb_raw(jb, "\\r");
    } else if (*s == '\t') {
      jb_raw(jb, "\\t");
    } else if ((unsigned char)*s < 0x20) {
      char esc[8];
      snprintf(esc, sizeof(esc), "\\u%04x", (unsigned char)*s);
      jb_raw(jb, esc);
    } else {
      jb_rawc(jb, *s); // plain ASCII: single-byte write, no strlen
    }
  }
  jb_rawc(jb, '"');
}

void jb_int(json_buf_t *jb, int v) {
  char tmp[32];
  snprintf(tmp, sizeof(tmp), "%d", v);
  jb_raw(jb, tmp);
}

void jb_uint64_str(json_buf_t *jb, uint64_t v) {
  // As quoted string, avoids float precision loss in JSON parsers
  char tmp[32];
  snprintf(tmp, sizeof(tmp), "\"%" PRIu64 "\"", v);
  jb_raw(jb, tmp);
}

void jb_bool(json_buf_t *jb, int v) { 
  jb_raw(jb, v ? "true" : "false");
}

void jb_float(json_buf_t *jb, float v) {
  char tmp[32];
  snprintf(tmp, sizeof(tmp), "%g", (double)v);
  jb_raw(jb, tmp);
}

/*
 * Append a ucs2_t engine string as a JSON quoted+esc string
 */
void jb_ucs2(json_buf_t *jb, const ucs2_t *src) {
  char utf8[ARG_MAX_CHARS * 2];
  ucs2_to_utf8(src, utf8, sizeof(utf8));
  jb_str(jb, utf8);
}

/*
 * Append a quoted key followed by a colon
 */
void jb_key(json_buf_t *jb, const char *key) {
  jb_str(jb, key);
  jb_rawc(jb, ':');
}

void jb_key_str(json_buf_t *jb, const char *key, const char *val) {
  jb_key(jb, key);
  jb_str(jb, val);
}

void jb_key_int(json_buf_t *jb, const char *key, int val) {
  jb_key(jb, key);
  jb_int(jb, val);
}