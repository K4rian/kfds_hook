#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H

#include "hook_ucs2.h"

// ============================================================================
// ENGINE FUNCTION ADDRESSES
// ============================================================================
#define ADDR_UObject_GetName 0x08076642

#define ADDR_UGameEngine_Tick 0x08143866
#define ADDR_UGameEngine_Exec 0x08129874

#define ADDR_ULevel_GetLevelInfo          0x080de61a
#define ADDR_ALevelInfo_eventServerTravel 0x08146612
#define ADDR_AGameInfo_eventBroadcast     0x081468d8

/*
 * FString memory management
 * Confirmed: eventBroadcast @0x8129eec
 */
#define ADDR_FString_ctor_wchar 0x0804e1fe
#define ADDR_FString_dtor       0x0804e4a6

/*
 * GLog: FOutputDevice* passed to UGameEngine::Exec as output device
 * GNull: null FOutputDevice*, suppresses all output
 */
#define ADDR_GNULL_PTR 0x0878b7e8
#define ADDR_GLOG_PTR  0x0878b7e0

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
#define UGAMEENGINE_LEVEL_OFFSET         0x114

/*
 * FURL
 *   ULevel+0x48
 *   Confirmed: execGetLocalURL @0x8262202
 *              execGetAddressURL @0x8262481
 *   +0x48  Protocol  FString
 *   +0x54  Host      FString
 *   +0x60  Port      int
 *   +0x64  Map       FString
 *   +0x70  Op        TArray<FString> (options: "Game=...", "Mutator=...", etc.)
 *   +0x7c  Portal    FString
 *   +0x88  Valid     int (1=parsed OK)
 */
#define FURL_OFFSET_Protocol 0x48
#define FURL_OFFSET_Host     0x54
#define FURL_OFFSET_Port     0x60
#define FURL_OFFSET_Map      0x64
#define FURL_OFFSET_Op       0x70
#define FURL_OFFSET_Portal   0x7c
#define FURL_OFFSET_Valid    0x88

/*
 * ALevelInfo
 *   +0x5f4  AGameInfo* (KFGameType)
 *           Confirmed: SpawnPlayActor at @0x8153165
 */
#define ALEVELINFO_GAMEINFO_OFFSET 0x5f4

/*
 * AGameReplicationInfo (GRI)
 *   +0x3fc  ServerName       FString
 *   +0x408  ShortName        FString
 *   +0x414  AdminName        FString
 *   +0x420  AdminEmail       FString
 *   +0x42c  ServerRegion     int
 *   +0x430  MessageOfTheDay  FString
 *   +0x5c8  WaveNumber       byte
 *   +0x5c9  BaseDifficulty   byte
 *   +0x5ca  FinalWave        byte
 *   +0x5cc  numMonsters      int
 *   +0x5d0  bWaveInProgress  int
 *   +0x5f8  TimeToNextWave   int   (replication of KFGameType.WaveCountDown)
 *   +0x5fc  bWaveInProgress  bool  (1=wave active, 0=trader/lobby)
 *   +0x678  GameDiff         float (replication of BaseDifficulty)
 */
#define GRI_OFFSET_ServerName      0x3fc
#define GRI_OFFSET_ShortName       0x408
#define GRI_OFFSET_AdminName       0x414
#define GRI_OFFSET_AdminEmail      0x420
#define GRI_OFFSET_ServerRegion    0x42c
#define GRI_OFFSET_MessageOfTheDay 0x430
#define GRI_OFFSET_WaveNumber      0x5c8
#define GRI_OFFSET_BaseDifficulty  0x5c9
#define GRI_OFFSET_FinalWave       0x5ca
#define GRI_OFFSET_numMonsters     0x5cc
#define GRI_OFFSET_TimeToNextWave  0x5f8
#define GRI_OFFSET_bWaveInProgress 0x5fc
#define GRI_OFFSET_GameDiff        0x678

/*
 * APlayerController
 *   +0x360  APawn*
 *           NULL when dead, set when alive/spawned
 *   +0x490  APlayerReplicationInfo*
 *   +0x514  UNetConnection*
 */
#define APLAYERCONTROLLER_OFFSET_PAWN    0x360
#define APLAYERCONTROLLER_OFFSET_PRI     0x490
#define APLAYERCONTROLLER_OFFSET_NETCONN 0x514

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
void hook_engine_tick(void *self);
void *hook_engine_get(void);

// ============================================================================
// ENGINE HELPERS
// ============================================================================
int is_server_busy(void);
int is_game_started(void);
int is_player_controller(const ucs2_t *name);
int get_level_objects(void **out_level_info, void **out_game_info);
void *find_gri(void);

#endif /* HOOK_ENGINE_H */