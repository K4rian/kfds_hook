#include <errno.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/un.h>

#include "hook_engine.h"
#include "hook_log.h"
#include "hook_trampoline.h"

// ============================================================================
// TRAMPOLINE STATIC STATE
// ============================================================================
static uint8_t tick_original_bytes[5];
static UGameEngine_Tick_fn tick_trampoline = NULL;

// ============================================================================
// HOOKED FUNCTIONS
// ============================================================================
/*
 * Runs on every game tick
 */
static void hooked_Tick(void *self, float delta_seconds) {
  hook_engine_tick(self);
  tick_trampoline(self, delta_seconds);
}

// ============================================================================
// TRAMPOLINE
// ============================================================================
/*
 * Patches UGameEngine::Tick with a 5-byte relative JMP to hooked_Tick.
 * A trampoline stub containing the original 5 bytes + JMP back to Tick+5
 * is allocated via mmap so the original function still executes in full
 *
 *  Tick+0:     E9 XX XX XX XX                   -> jmp hooked_Tick
 *  Tick+5:     [original code]
 *  trampoline: [original 5 bytes] E9 XX XX XX X -> jmp Tick+5
 */
void hook_trampoline_install(void) {
  void *target = (void *)ADDR_UGameEngine_Tick;

  uint8_t *trampoline = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (trampoline == MAP_FAILED) {
    hook_log_error("mmap failed: %s\n", strerror(errno));
    return;
  }

  uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
  if (mprotect((void *)page, 8192, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    hook_log_error("mprotect failed: %s\n", strerror(errno));
    return;
  }

  memcpy(tick_original_bytes, target, 5);
  memcpy(trampoline, tick_original_bytes, 5);

  trampoline[5] = 0xE9;
  *(int32_t *)(trampoline + 6) =
      (int32_t)((uint8_t *)target + 5 - (trampoline + 5 + 5));
  tick_trampoline = (UGameEngine_Tick_fn)trampoline;

  uint8_t jmp[5];
  jmp[0] = 0xE9;
  *(int32_t *)(jmp + 1) =
      (int32_t)((uint8_t *)hooked_Tick - ((uint8_t *)target + 5));

  memcpy(target, jmp, 5);

  hook_log_debug("Tick hooked at %p, trampoline at %p\n", target,
                 (void *)trampoline);
}