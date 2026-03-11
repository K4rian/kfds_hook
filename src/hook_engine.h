#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include "hook_ucs2.h"

// ============================================================================
// ENGINE FUNCTION ADDRESSES
// ============================================================================
#define ADDR_UGameEngine_Tick 0x08143866

/*
 * FString memory management
 * Confirmed: eventBroadcast @0x8129eec
 */
#define ADDR_FString_ctor_wchar 0x0804e1fe
#define ADDR_FString_dtor 0x0804e4a6

// ============================================================================
// ENGINE STRUCT OFFSETS
// ============================================================================
/*
 * UGameEngine
 *   +0x034  UPendingLevel*
 *           non-null during level transition
 *           confirmed: NotifyLevelChange
 *   +0x114  ULevel*
 *           confirmed: Tick @0x8143b5a
 */
#define UGAMEENGINE_PENDING_LEVEL_OFFSET 0x034
#define UGAMEENGINE_LEVEL_OFFSET 0x114

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

/*
 * TArrayFString = TArray<FString> -> {Data*, Num, Max}
 * Data points to a contiguous array of FString structs
 */
typedef struct {
  FString *Data;
  int Num;
  int Max;
} TArrayFString;

/*
 * FName = Single int (GNames index) in this build
 * Confirmed by eventBroadcast call: only 4 bytes pushed
 * Pass by VALUE (mangled suffix "5FName", no P/R prefix)
 */
typedef struct {
  int Index;
} FName;

// ============================================================================
// ENGINE FUNCTION POINTERS
// ============================================================================
typedef void (*UGameEngine_Tick_fn)(void *, float);

typedef void (*FString_ctor_fn)(FString *, const ucs2_t *);
typedef void (*FString_dtor_fn)(FString *);

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

extern FString_ctor_fn FString_ctor;
extern FString_dtor_fn FString_dtor;

// ============================================================================
// ENGINE
// ============================================================================
void game_engine_store(void *engine);
void *game_engine_load(void);

int is_server_busy(void *engine);

#endif /* HOOK_ENGINE_H */