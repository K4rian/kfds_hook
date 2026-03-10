#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include "hook_ucs2.h"

// ============================================================================
// ENGINE FUNCTION ADDRESSES
// ============================================================================
#define ADDR_UGameEngine_Tick 0x08143866

// ============================================================================
// ENGINE TYPES
// ============================================================================
/*
 * FString = TArray<ucs2_t> -> {Data*, Num, Max}
 * Num includes null terminator
 */
typedef struct {
  ucs2_t *Data;
  int Num;
  int Max;
} FString;

// ============================================================================
// ENGINE GLOBAL STATE
// ============================================================================
/*
 * Captured on the first hooked_Tick call, never changed again
 *
 * Written by the game thread (hooked_Tick)
 *
 * Use GGameEngine_store() for the single write and GGameEngine_load() for
 * any read. Reads that are always on the game thread may access GGameEngine 
 * directly
 */
extern void *GGameEngine;

// ============================================================================
// ENGINE
// ============================================================================
void  game_engine_store(void *engine);
void *game_engine_load(void);

// ============================================================================
// ENGINE FUNCTION POINTERS
// ============================================================================
typedef void (*UGameEngine_Tick_fn)(void *, float);

// ============================================================================
// ENGINE FUNCTION INSTANCES
// ============================================================================
// TODO

#endif /* HOOK_ENGINE_H */