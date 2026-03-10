#include <stddef.h>

#include "hook_engine.h"

// ============================================================================
// ENGINE GLOBAL STATE
// ============================================================================
void *GGameEngine = NULL;

// ============================================================================
// ENGINE
// ============================================================================
#define GGameEngine_store(v) \
    __atomic_store_n(&GGameEngine, (v), __ATOMIC_RELEASE)
#define GGameEngine_load() \
    __atomic_load_n(&GGameEngine, __ATOMIC_ACQUIRE)

void game_engine_store(void *engine) {
    GGameEngine_store(engine);
}

void *game_engine_load(void) {
    return GGameEngine_load();
}