#ifndef HOOK_UCS2_H
#define HOOK_UCS2_H

#include <stdint.h>

// ============================================================================
// UCS2 TYPES
// ============================================================================
/*
 * Engine-facing string type (2-byte, Windows ABI)
 * Linux wchar_t is 4 bytes
 */
typedef uint16_t ucs2_t;

#endif /* HOOK_UCS2_H */