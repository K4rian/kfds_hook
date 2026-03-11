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

#endif /* HOOK_UCS2_H */