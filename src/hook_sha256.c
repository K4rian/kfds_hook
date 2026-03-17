#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hook_sha256.h"

// ============================================================================
// SHA256 DEFINES
// ============================================================================
#define SHA256_BLOCK 64
#define SHA256_DIGEST 32

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_S0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SHA256_S1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SHA256_G0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SHA256_G1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))
#define SHA256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// ============================================================================
// SHA256 TYPES
// ============================================================================
typedef struct {
  uint32_t state[8];
  uint64_t count;
  uint8_t buf[SHA256_BLOCK];
} sha256_ctx_t;

// ============================================================================
// SHA256 STATIC STATE
// ============================================================================
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// ============================================================================
// SHA256
// ============================================================================
static void sha256_init(sha256_ctx_t *ctx) {
  ctx->count = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t *data) {
  uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
  for (int i = 0; i < 16; i++)
    w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
           ((uint32_t)data[i * 4 + 2] << 8) | (uint32_t)data[i * 4 + 3];
  for (int i = 16; i < 64; i++)
    w[i] = SHA256_G1(w[i - 2]) + w[i - 7] + SHA256_G0(w[i - 15]) + w[i - 16];

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (int i = 0; i < 64; i++) {
    t1 = h + SHA256_S1(e) + SHA256_CH(e, f, g) + sha256_k[i] + w[i];
    t2 = SHA256_S0(a) + SHA256_MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
  size_t used = ctx->count % SHA256_BLOCK;
  ctx->count += len;
  if (used) {
    size_t fill = SHA256_BLOCK - used;
    if (len < fill) {
      memcpy(ctx->buf + used, data, len);
      return;
    }
    memcpy(ctx->buf + used, data, fill);
    sha256_transform(ctx, ctx->buf);
    data += fill;
    len -= fill;
  }
  while (len >= SHA256_BLOCK) {
    sha256_transform(ctx, data);
    data += SHA256_BLOCK;
    len -= SHA256_BLOCK;
  }
  if (len)
    memcpy(ctx->buf, data, len);
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST]) {
  size_t used = ctx->count % SHA256_BLOCK;
  ctx->buf[used++] = 0x80;
  if (used > 56) {
    memset(ctx->buf + used, 0, SHA256_BLOCK - used);
    sha256_transform(ctx, ctx->buf);
    used = 0;
  }
  memset(ctx->buf + used, 0, 56 - used);
  
  // Write message bit-length as 64-bit big-endian into buf[56..63]
  uint64_t bc = ctx->count * 8;
  ctx->buf[56] = (bc >> 56) & 0xff;
  ctx->buf[57] = (bc >> 48) & 0xff;
  ctx->buf[58] = (bc >> 40) & 0xff;
  ctx->buf[59] = (bc >> 32) & 0xff;
  ctx->buf[60] = (bc >> 24) & 0xff;
  ctx->buf[61] = (bc >> 16) & 0xff;
  ctx->buf[62] = (bc >> 8) & 0xff;
  ctx->buf[63] = bc & 0xff;
  sha256_transform(ctx, ctx->buf);

  for (int i = 0; i < 8; i++) {
    digest[i * 4 + 0] = (ctx->state[i] >> 24) & 0xff;
    digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xff;
    digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xff;
    digest[i * 4 + 3] = ctx->state[i] & 0xff;
  }
}

/*
 * Compute SHA256 of a file.
 * Returns 1 on success, 0 on error.
 */
int sha256_file(const char *path, char out_hex[65]) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return 0;

  sha256_ctx_t ctx;
  sha256_init(&ctx);
  uint8_t buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    sha256_update(&ctx, buf, n);
  fclose(f);

  uint8_t digest[SHA256_DIGEST];
  sha256_final(&ctx, digest);
  for (int i = 0; i < SHA256_DIGEST; i++)
    snprintf(out_hex + i * 2, 3, "%02x", digest[i]);
  out_hex[64] = '\0';

  return 1;
}