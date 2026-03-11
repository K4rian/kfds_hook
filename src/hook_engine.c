#include <stddef.h>

#include "hook_engine.h"

// ============================================================================
// ENGINE GLOBAL STATE
// ============================================================================
void *GGameEngine = NULL;

FString_ctor_fn FString_ctor = (FString_ctor_fn)ADDR_FString_ctor_wchar;
FString_dtor_fn FString_dtor = (FString_dtor_fn)ADDR_FString_dtor;

// ============================================================================
// ENGINE
// ============================================================================
void game_engine_store(void *engine) {
  __atomic_store_n(&GGameEngine, engine, __ATOMIC_RELEASE);
}

void *game_engine_load(void) {
  return __atomic_load_n(&GGameEngine, __ATOMIC_ACQUIRE);
}

int is_server_busy(void *engine) {
  if (!engine)
    return 1;

  void *pending =
      *(void **)((uint8_t *)engine + UGAMEENGINE_PENDING_LEVEL_OFFSET);
  return pending != NULL;
}