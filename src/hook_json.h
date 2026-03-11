#ifndef HOOK_JSON_H
#define HOOK_JSON_H

#include <inttypes.h>

#include "hook_ucs2.h"

// ============================================================================
// JSON TYPES
// ============================================================================
/*
 * Simple append-only JSON output builder.
 * All output is UTF-8. No dynamic allocation.
 * On overflow, further writes are silently dropped and overflow flag is set.
 */
typedef struct {
  char buf[8192];
  int pos;
  int overflow;
} json_buf_t;

// ============================================================================
// JSON
// ============================================================================
void jb_init(json_buf_t *jb);
void jb_raw(json_buf_t *jb, const char *s);
void jb_str(json_buf_t *jb, const char *s);
void jb_int(json_buf_t *jb, int v);
void jb_uint64_str(json_buf_t *jb, uint64_t v);
void jb_bool(json_buf_t *jb, int v);
void jb_float(json_buf_t *jb, float v);
void jb_ucs2(json_buf_t *jb, const ucs2_t *src);
void jb_key(json_buf_t *jb, const char *key);
void jb_key_str(json_buf_t *jb, const char *key, const char *val);
void jb_key_int(json_buf_t *jb, const char *key, int val);

#endif /* HOOK_JSON_H */