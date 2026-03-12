#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include "hook_ucs2.h"

// ============================================================================
// ENGINE FUNCTION ADDRESSES
// ============================================================================
#define ADDR_UObject_GetName 0x08076642

#define ADDR_UGameEngine_Tick 0x08143866
#define ADDR_UGameEngine_Exec 0x08129874

#define ADDR_ULevel_GetLevelInfo 0x080de61a
#define ADDR_ALevelInfo_eventServerTravel 0x08146612
#define ADDR_AGameInfo_eventBroadcast 0x081468d8

/*
 * FString memory management
 * Confirmed: eventBroadcast @0x8129eec
 */
#define ADDR_FString_ctor_wchar 0x0804e1fe
#define ADDR_FString_dtor 0x0804e4a6

/*
 * GLog: FOutputDevice* passed to UGameEngine::Exec as output device
 * GNull: null FOutputDevice*, suppresses all output
 */
#define ADDR_GNULL_PTR 0x0878b7e8
#define ADDR_GLOG_PTR 0x0878b7e0

// ============================================================================
// ENGINE STRUCT OFFSETS
// ============================================================================
/*
 * UGameEngine
 *   +0x034  UPendingLevel*
 *           non-null during level transition
 *           Confirmed: NotifyLevelChange
 *   +0x114  ULevel*
 *           Confirmed: Tick @0x8143b5a
 */
#define UGAMEENGINE_PENDING_LEVEL_OFFSET 0x034
#define UGAMEENGINE_LEVEL_OFFSET 0x114

/*
 * ALevelInfo
 *   +0x5f4  AGameInfo* (KFGameType)
 *           Confirmed: SpawnPlayActor at @0x8153165
 */
#define ALEVELINFO_GAMEINFO_OFFSET 0x5f4

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
typedef const ucs2_t *(*UObject_GetName_fn)(void *);

typedef void (*UGameEngine_Tick_fn)(void *, float);
typedef int (*UGameEngine_Exec_fn)(void *, const ucs2_t *, void *);

typedef void *(*ULevel_GetLevelInfo_fn)(void *);
typedef void (*ALevelInfo_eventServerTravel_fn)(void *, const FString *,
                                                unsigned int);

typedef void (*AGameInfo_eventBroadcast_fn)(void *, void *, const FString *,
                                            FName);

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

extern UObject_GetName_fn UObject_GetName;

extern UGameEngine_Exec_fn UGameEngine_Exec;

extern ULevel_GetLevelInfo_fn ULevel_GetLevelInfo;
extern ALevelInfo_eventServerTravel_fn ALevelInfo_eventServerTravel;

extern AGameInfo_eventBroadcast_fn AGameInfo_eventBroadcast;

extern FString_ctor_fn FString_ctor;
extern FString_dtor_fn FString_dtor;

// ============================================================================
// ENGINE
// ============================================================================
void game_engine_store(void *engine);
void *game_engine_load(void);

// ============================================================================
// ENGINE HELPERS
// ============================================================================
int is_server_busy(void *engine);
int get_level_objects(void **out_level_info, void **out_game_info);
void *find_gri(void);

#endif /* HOOK_ENGINE_H */