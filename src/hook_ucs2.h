#ifndef HOOK_UCS2_H
#define HOOK_UCS2_H

#include <stdint.h>
#include <string.h>

// ============================================================================
// UCS2 TYPES
// ============================================================================
/*
 * Engine-facing string type (2-byte, Windows ABI)
 * Linux wchar_t is 4 bytes
 */
typedef uint16_t ucs2_t;

// ============================================================================
// UCS2
// ============================================================================
void ucs2_to_utf8(const ucs2_t *src, char *dst, size_t dst_len);
size_t utf8_to_ucs2(const char *src, ucs2_t *dst, size_t dst_len);

int ucs2_icmp(const ucs2_t *a, const ucs2_t *b);
int ucs2_split_eq(const ucs2_t *entry, ucs2_t *key_buf, int key_len,
                  ucs2_t *val_buf, int val_len);

int ucs2_len(const ucs2_t *s);
int ucs2_starts_with_ascii(const ucs2_t *s, const char *p);
int ucs2_contains_ascii(const ucs2_t *s, const char *p);

#endif /* HOOK_UCS2_H */