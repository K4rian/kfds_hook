
#include <stddef.h>
#include <string.h>
#include <wctype.h>

#include "hook_ucs2.h"

// ============================================================================
// UCS2
// ============================================================================
/*
 * Locale-independent UCS-2 -> UTF-8 conversion
 *
 * Directly encodes each UCS-2 codepoint (BMP only, U+0000..U+FFFF)
 * into UTF-8, without going through wchar_t or wcstombs. Writes at
 * most dst_len-1 bytes and always NUL-terminates
 */
void ucs2_to_utf8(const ucs2_t *src, char *dst, size_t dst_len) {
  if (!dst_len)
    return;

  unsigned char *d = (unsigned char *)dst;
  size_t di = 0;
  for (; *src; src++) {
    uint32_t cp = *src;
    if (cp < 0x80) {
      if (di + 1 >= dst_len)
        break;
      d[di++] = (unsigned char)cp;
    } else if (cp < 0x800) {
      if (di + 2 >= dst_len)
        break;
      d[di++] = (unsigned char)(0xC0 | (cp >> 6));
      d[di++] = (unsigned char)(0x80 | (cp & 0x3F));
    } else {
      if (di + 3 >= dst_len)
        break;
      d[di++] = (unsigned char)(0xE0 | (cp >> 12));
      d[di++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
      d[di++] = (unsigned char)(0x80 | (cp & 0x3F));
    }
  }
  d[di] = '\0';
}

/*
 * Locale-independent UTF-8 -> UCS-2 conversion
 *
 * Directly decodes UTF-8 into UCS-2 codepoints, without going through
 * wchar_t or mbstowcs. Invalid byte sequences and codepoints outside
 * the BMP (U+10000+) are replaced with U+FFFD. Writes at most
 * dst_len-1 codepoints and always NUL-terminates
 *
 * This fixes the silent data corruption that occurred when the server
 * process ran with LC_CTYPE=C (the default on many servers) and
 * any string contained non-ASCII characters
 *
 * Returns the number of UCS-2 chars written (excluding NUL)
 */
size_t utf8_to_ucs2(const char *src, ucs2_t *dst, size_t dst_len) {
  if (!dst_len)
    return 0;

  const unsigned char *s = (const unsigned char *)src;
  size_t di = 0;
  while (*s && di < dst_len - 1) {
    uint32_t cp;
    if (s[0] < 0x80) {
      cp = s[0];
      s += 1;
    } else if ((s[0] & 0xE0) == 0xC0 && (s[1] & 0xC0) == 0x80) {
      cp = ((uint32_t)(s[0] & 0x1F) << 6) | (s[1] & 0x3F);
      s += 2;
    } else if ((s[0] & 0xF0) == 0xE0 && (s[1] & 0xC0) == 0x80 &&
               (s[2] & 0xC0) == 0x80) {
      cp = ((uint32_t)(s[0] & 0x0F) << 12) | ((uint32_t)(s[1] & 0x3F) << 6) |
           (s[2] & 0x3F);
      s += 3;
    } else {
      // Invalid or out-of-BMP (4b) sequence: replacement char, skip 1 byte
      cp = 0xFFFD;
      s += 1;
    }
    if (cp > 0xFFFF)
      cp = 0xFFFD; // surrogate / out-of-BMP fallback
    dst[di++] = (ucs2_t)cp;
  }
  dst[di] = 0;
  return di;
}

/*
 * Case-insensitive comparison of two UCS2 strings.
 * Uses towlower on each code unit, sufficient for ASCII key names.
 * Returns 0 if equal, non-zero otherwise.
 */
int ucs2_icmp(const ucs2_t *a, const ucs2_t *b) {
  while (*a && *b) {
    ucs2_t ca = (ucs2_t)towlower((wchar_t)*a);
    ucs2_t cb = (ucs2_t)towlower((wchar_t)*b);
    if (ca != cb)
      return (int)ca - (int)cb;
    a++;
    b++;
  }
  return (int)towlower((wchar_t)*a) - (int)towlower((wchar_t)*b);
}

/*
 * Split a "Key=Value" UCS2 entry on the first '='.
 * Writes key into key_buf (up to key_len chars) and value into val_buf
 * (up to val_len chars). Both are NUL-terminated.
 * Returns 1 if '=' was found, 0 if not (entry copied to key_buf as-is).
 */
int ucs2_split_eq(const ucs2_t *entry, ucs2_t *key_buf, int key_len,
                         ucs2_t *val_buf, int val_len) {
  int i = 0;
  while (entry[i] && entry[i] != (ucs2_t)'=')
    i++;
  if (!entry[i]) {
    // No '=' found
    int n = i < key_len - 1 ? i : key_len - 1;
    memcpy(key_buf, entry, n * sizeof(ucs2_t));
    key_buf[n] = 0;
    val_buf[0] = 0;
    return 0;
  }

  int kn = i < key_len - 1 ? i : key_len - 1;
  memcpy(key_buf, entry, kn * sizeof(ucs2_t));
  key_buf[kn] = 0;

  const ucs2_t *vstart = entry + i + 1;
  int vn = 0;
  while (vstart[vn] && vn < val_len - 1)
    vn++;

  memcpy(val_buf, vstart, vn * sizeof(ucs2_t));
  val_buf[vn] = 0;
  return 1;
}