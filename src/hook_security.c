#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "hook_log.h"
#include "hook_security.h"

// ============================================================================
// SECURITY DEFINES
// ============================================================================
/*
 * Single query point for the integrity check result.
 * Original logic: return bPassedSecurityCheckServer ||
 * bPassedSecurityCheckClient
 * Patch: mov eax, 1 | ret
 * Always return 1 regardless of boolean state.
 * Confirmed: @0x083d6979
 */
#define ADDR_PassedSecurityCheck 0x083d6979

/*
 * FOutputDevice::Logf call sites emitting "STEAMSTATS: SECURITY CHECK FAILED".
 * Each define is the start of the full argument setup + call sequence.
 * Lengths are exact byte counts confirmed from disassembly.
 * SteamPolicyUpdatedCallback (@0x083d6999):
 *   Log #1: fired when bPassedSecurityCheckServer was 0,
 *           now non-zero (MD5 mismatch)
 *   Log #2: fired when old value mismatch condition triggers
 * CheckMD5s (@0x083daac0):
 *   Log #3: (loop 1) per-file failure (iterates GObjLoaders)
 *   Log #4: (loop 2) per-file failure (iterates GObjObjects)
 *   Log #5: (final) package-level failure after both loops
 */
#define ADDR_SECFAIL_LOG_1     0x083d69dc
#define ADDR_SECFAIL_LOG_1_LEN 21
#define ADDR_SECFAIL_LOG_2     0x083d6a03
#define ADDR_SECFAIL_LOG_2_LEN 21
#define ADDR_SECFAIL_LOG_3     0x083dadc2
#define ADDR_SECFAIL_LOG_3_LEN 35
#define ADDR_SECFAIL_LOG_4     0x083daee7
#define ADDR_SECFAIL_LOG_4_LEN 35
#define ADDR_SECFAIL_LOG_5     0x083daf33
#define ADDR_SECFAIL_LOG_5_LEN 42

// SteamOnMapChange, zeroes both booleans on every map change
#define ADDR_MAPCLEAR_CLIENT     0x083d6903
#define ADDR_MAPCLEAR_CLIENT_LEN 10
#define ADDR_MAPCLEAR_SERVER     0x083d690d
#define ADDR_MAPCLEAR_SERVER_LEN 10

// SteamPolicyUpdatedCallback, zeroes server boolean when Steam not ready
#define ADDR_POLICYUPDATE_CLEAR_SERVER     0x083d6a42
#define ADDR_POLICYUPDATE_CLEAR_SERVER_LEN 10

// Boolean addresses, written to 1 at init after all patches applied
#define ADDR_bPassedSecurityCheckClient 0x088dc044
#define ADDR_bPassedSecurityCheckServer 0x088dc048

// ============================================================================
// SECURITY STATIC STATE
// ============================================================================
static const uint8_t patch_ret1[] = {
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xc3                                          // ret
};

// ============================================================================
// SECURITY HELPERS
// ============================================================================
/*
 * Remaps the page containing addr as RWX, writes len bytes from data,
 * then restores RX. Assumes the patch fits within a single 4096-byte page.
 * Returns 1 on success, 0 on mprotect failure.
 */
static int patch_mem(uintptr_t addr, const uint8_t *data, size_t len) {
  void *target = (void *)addr;
  uintptr_t page = addr & ~(uintptr_t)(4096 - 1);

  if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    hook_log_error("patch_mem: mprotect RWX failed at 0x%08x\n", addr);
    return 0;
  }
  memcpy(target, data, len);
  if (mprotect((void *)page, 4096, PROT_READ | PROT_EXEC) != 0) {
    hook_log_error("patch_mem: mprotect RX failed at 0x%08x\n", addr);
    return 0;
  }
  return 1;
}

/*
 * Fills len bytes at addr with 0x90 (NOP).
 * len must not exceed 64 bytes.
 * Returns 1 on success, 0 on error.
 */
static int nop_range(uintptr_t addr, size_t len) {
  uint8_t nops[64];
  if (len > sizeof(nops)) {
    hook_log_error("nop_range: len %zu exceeds NOP buffer at 0x%08x\n", len,
                   addr);
    return 0;
  }
  memset(nops, 0x90, len);
  return patch_mem(addr, nops, len);
}

// ============================================================================
// SECURITY
// ============================================================================
void hook_security_patch(void) {
  // Patch PassedSecurityCheck to always return 1
  if (!patch_mem(ADDR_PassedSecurityCheck, patch_ret1, sizeof(patch_ret1)))
    goto failed;
  hook_log_debug("PassedSecurityCheck patched at 0x%08x\n",
                 ADDR_PassedSecurityCheck);

  // Suppress "STEAMSTATS: SECURITY CHECK FAILED" log calls
  if (!nop_range(ADDR_SECFAIL_LOG_1, ADDR_SECFAIL_LOG_1_LEN))
    goto failed;
  hook_log_debug("SECURITY CHECK FAILED log #1 suppressed at 0x%08x\n",
                 ADDR_SECFAIL_LOG_1);

  if (!nop_range(ADDR_SECFAIL_LOG_2, ADDR_SECFAIL_LOG_2_LEN))
    goto failed;
  hook_log_debug("SECURITY CHECK FAILED log #2 suppressed at 0x%08x\n",
                 ADDR_SECFAIL_LOG_2);

  if (!nop_range(ADDR_SECFAIL_LOG_3, ADDR_SECFAIL_LOG_3_LEN))
    goto failed;
  hook_log_debug("SECURITY CHECK FAILED log #3 suppressed at 0x%08x\n",
                 ADDR_SECFAIL_LOG_3);

  if (!nop_range(ADDR_SECFAIL_LOG_4, ADDR_SECFAIL_LOG_4_LEN))
    goto failed;
  hook_log_debug("SECURITY CHECK FAILED log #4 suppressed at 0x%08x\n",
                 ADDR_SECFAIL_LOG_4);

  if (!nop_range(ADDR_SECFAIL_LOG_5, ADDR_SECFAIL_LOG_5_LEN))
    goto failed;
  hook_log_debug("SECURITY CHECK FAILED log #5 suppressed at 0x%08x\n",
                 ADDR_SECFAIL_LOG_5);

  // NOP out the zero-writes so map changes can't reset the booleans
  if (!nop_range(ADDR_MAPCLEAR_CLIENT, ADDR_MAPCLEAR_CLIENT_LEN))
    goto failed;
  hook_log_debug("SteamOnMapChange client clear suppressed\n");

  if (!nop_range(ADDR_MAPCLEAR_SERVER, ADDR_MAPCLEAR_SERVER_LEN))
    goto failed;
  hook_log_debug("SteamOnMapChange server clear suppressed\n");

  if (!nop_range(ADDR_POLICYUPDATE_CLEAR_SERVER,
                 ADDR_POLICYUPDATE_CLEAR_SERVER_LEN))
    goto failed;
  hook_log_debug("SteamPolicyUpdatedCallback server clear suppressed\n");

  // Force both booleans to 1
  // use memcpy to avoid strict aliasing UB on direct pointer cast
  int one = 1;
  memcpy((void *)ADDR_bPassedSecurityCheckClient, &one, sizeof(one));
  memcpy((void *)ADDR_bPassedSecurityCheckServer, &one, sizeof(one));
  hook_log_debug("bPassedSecurityCheckClient and bPassedSecurityCheckServer "
                 "forced to 1\n");

  hook_log_info("Security Check patched successfully\n");
  return;

failed:
    hook_log_error("Security Check patching failed\n");
}