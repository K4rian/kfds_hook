#ifndef HOOK_ENGINE_H
#define HOOK_ENGINE_H
// clang-format off

#include "hook_ucs2.h"

// ============================================================================
// ENGINE FUNCTION ADDRESSES
// ============================================================================
#define ADDR_UObject_GetName                      0x08076642

#define ADDR_UGameEngine_Tick                     0x08143866
#define ADDR_UGameEngine_Exec                     0x08129874
#define ADDR_UGameEngine_GetMaxTickRate           0x08141bba

#define ADDR_ULevel_GetLevelInfo                  0x080de61a

#define ADDR_ALevelInfo_eventServerTravel         0x08146612

#define ADDR_AGameInfo_eventBroadcast             0x081468d8
#define ADDR_AGameInfo_eventKickIdler             0x08173b2a

#define ADDR_AActor_eventTakeDamage               0x085db274

#define ADDR_APlayerController_eventClientMessage 0x080fcd8e
/*
 * Dynamic cast, returns non-NULL only if the object is an
 * APlayerController or subclass.
 */
#define ADDR_Cast_APlayerController               0x080897be

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
#define ADDR_GNULL_PTR  0x0878b7e8
#define ADDR_GLOG_PTR   0x0878b7e0

/*
 * Global FConfigCacheIni* singleton.
 * All GConfig methods take ucs2_t* (2-byte).
 */
#define ADDR_GCONFIG_PTR          0x0890d218
#define ADDR_GConfig_GetString    0x080583f8
#define ADDR_GConfig_SetString    0x0805887e
#define ADDR_GConfig_GetInt       0x080591a0
#define ADDR_GConfig_SetInt       0x080593ee
#define ADDR_GConfig_GetFloat     0x08059254
#define ADDR_GConfig_SetFloat     0x08059488
#define ADDR_GConfig_GetBool      0x08059308
#define ADDR_GConfig_SetBool      0x08059522
#define ADDR_GConfig_Flush        0x0805814a
#define ADDR_GConfig_GetSection   0x08058552
#define ADDR_GConfig_EmptySection 0x08058a88

/*
 * TArray<FNameEntry*>, global name table
 *   FNameEntry+0x0c = name string (ASCII)
 *   Confirmed: FName::operator* @0x804eafe
 */
#define ADDR_GNAMES 0x089c4c60

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
 * APlayerReplicationInfo (PRI)
 *   +0x3b4  Dosh                     float32
 *   +0x3c0  Ping                     uint8
 *   +0x3cc  Deaths                   int
 *   +0x3d0  PlayerName               FString
 *   +0x45c  Kills                    int
 *   +0x5f4  ClientVeteranSkill       UClass*
 *   +0x5f8  ClientVeteranSkillLevel  int
 */
#define PRI_OFFSET_Dosh                    0x3b4
#define PRI_OFFSET_Ping                    0x3c0
#define PRI_OFFSET_Deaths                  0x3cc
#define PRI_OFFSET_PlayerName              0x3d0
#define PRI_OFFSET_Kills                   0x45c
#define PRI_OFFSET_ClientVeteranSkill      0x5f4
#define PRI_OFFSET_ClientVeteranSkillLevel 0x5f8

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

/*
 * KFPawn (Pawn actor, accessed via PC+0x360)
 *   +0x480  Health          int
 *   +0x774  ShieldStrength  float
 */
#define APAWN_OFFSET_Health         0x480
#define APAWN_OFFSET_ShieldStrength 0x774

/*
 * UNetConnection
 *   +0x088  RemoteAddr  FString  (IP string)
 *   +0x460  SteamID64   uint64_t (temp, destroyed after a level change)
 *   +0x484  SteamID64   uint64_t
 *   +0x49c  SteamID64   uint64_t
 */
#define UNETCONN_OFFSET_IP          0x088
#define UNETCONN_OFFSET_STEAMID     0x484
#define UNETCONN_OFFSET_STEAMID_ALT 0x49c

/*
 * KFGameType (Invasion)
 *   +0x03bc  GameDifficulty     float
 *   +0x049c  MaxPlayers         int
 *   +0x1568  bTradingDoorsOpen  bool (1=trader, 0=wave)
 *   +0x1578  WaveCountDown      int  (countdown seconds)
 *   +0x157c  bWaveInProgress    bool (0=trader, 1=wave)
 */
#define GAMETYPE_OFFSET_GameDifficulty    0x03bc
#define GAMETYPE_OFFSET_MaxPlayers        0x049c
#define GAMETYPE_OFFSET_bTradingDoorsOpen 0x1568
#define GAMETYPE_OFFSET_WaveCountDown     0x1578
#define GAMETYPE_OFFSET_bWaveInProgress   0x157c

/*
 * AccessControl
 *   +0x3ec  IPPolicies     TArray<FString>
 *   +0x460  AdminPassword  FString
 *   +0x46c  GamePassword   FString
 *   +0x480  BannedIDs      TArray<FString>
 */
#define ACCESSCONTROL_OFFSET_IPPolicies    0x3ec
#define ACCESSCONTROL_OFFSET_AdminPassword 0x460
#define ACCESSCONTROL_OFFSET_GamePassword  0x46c
#define ACCESSCONTROL_OFFSET_BannedIDs     0x480

/*
 * FName indices for AGameInfo::eventBroadcast and
 * APlayerController::eventClientMessage message type routing.
 * Controls chat channel styling (color, format, display size).
 */
// #define FNAME_Event         710
// #define FNAME_Say           2038
// #define FNAME_TeamSay       2037
#define FNAME_ServerSay     2643
// #define FNAME_ServerTeamSay 2644
#define FNAME_CriticalEvent 5863

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
typedef float (*UGameEngine_GetMaxTickRate_fn)(void *);

typedef void *(*ULevel_GetLevelInfo_fn)(void *);

typedef void (*ALevelInfo_eventServerTravel_fn)(void *, const FString *,
                                                unsigned int);

typedef void (*AGameInfo_eventBroadcast_fn)(void *, void *, const FString *,
                                            FName);
typedef void (*AGameInfo_eventKickIdler_fn)(void *, void *);

typedef void (*AActor_eventTakeDamage_fn)(void*  self,
                                          int    damage,
                                          void*  instigator,
                                          float  hlx, float hly, float hlz,
                                          float  mx,  float my,  float mz,
                                          void*  damage_type,
                                          int    extra);

typedef void (*APlayerController_eventClientMessage_fn)(void *, 
                                                       FString const *, FName);
typedef void *(*Cast_APlayerController_fn)(void *);

typedef void (*FString_ctor_fn)(FString *, const ucs2_t *);
typedef void (*FString_dtor_fn)(FString *);

typedef int  (*GConfig_GetString_fn)(void*, const ucs2_t*, const ucs2_t*, 
                                      ucs2_t*, int, const ucs2_t*);
// GConfig_SetString mode flag (last param):
//  0 = always append
//  1 = replace if key exists, otherwise append
typedef void (*GConfig_SetString_fn)(void*, const ucs2_t*, const ucs2_t*, 
                                    const ucs2_t*, const ucs2_t*, int);
typedef int  (*GConfig_GetInt_fn)(void*, const ucs2_t*, const ucs2_t*, 
                                  int*,   const ucs2_t*);
typedef void (*GConfig_SetInt_fn)(void*, const ucs2_t*, const ucs2_t*, 
                                  int,    const ucs2_t*);
typedef int  (*GConfig_GetFloat_fn)(void*, const ucs2_t*, const ucs2_t*, 
                                  float*, const ucs2_t*);
typedef void (*GConfig_SetFloat_fn)(void*, const ucs2_t*, const ucs2_t*, 
                                   float,  const ucs2_t*);
typedef int  (*GConfig_GetBool_fn)(void*, const ucs2_t*, const ucs2_t*, 
                                  int*,   const ucs2_t*);
typedef void (*GConfig_SetBool_fn)(void*, const ucs2_t*, const ucs2_t*, 
                                  int,    const ucs2_t*);
typedef void (*GConfig_Flush_fn)(void*, int, const ucs2_t*);
typedef int  (*GConfig_GetSection_fn)(void*, const ucs2_t*, ucs2_t*, 
                                     int, const ucs2_t*);
typedef void (*GConfig_EmptySection_fn)(void*, const ucs2_t*, 
                                       const ucs2_t*);

// ============================================================================
// ENGINE GLOBAL STATE
// ============================================================================
extern UObject_GetName_fn UObject_GetName;

extern UGameEngine_Exec_fn UGameEngine_Exec;
extern UGameEngine_GetMaxTickRate_fn UGameEngine_GetMaxTickRate;

extern ULevel_GetLevelInfo_fn ULevel_GetLevelInfo;

extern ALevelInfo_eventServerTravel_fn ALevelInfo_eventServerTravel;

extern AGameInfo_eventBroadcast_fn AGameInfo_eventBroadcast;
extern AGameInfo_eventKickIdler_fn AGameInfo_eventKickIdler;

extern AActor_eventTakeDamage_fn AActor_eventTakeDamage;

extern APlayerController_eventClientMessage_fn
    APlayerController_eventClientMessage;
extern Cast_APlayerController_fn Cast_APlayerController;

extern FString_ctor_fn FString_ctor;
extern FString_dtor_fn FString_dtor;

extern GConfig_GetString_fn    GConfig_GetString;
extern GConfig_SetString_fn    GConfig_SetString;
extern GConfig_GetInt_fn       GConfig_GetInt;
extern GConfig_SetInt_fn       GConfig_SetInt;
extern GConfig_GetFloat_fn     GConfig_GetFloat;
extern GConfig_SetFloat_fn     GConfig_SetFloat;
extern GConfig_GetBool_fn      GConfig_GetBool;
extern GConfig_SetBool_fn      GConfig_SetBool;
extern GConfig_Flush_fn        GConfig_Flush;
extern GConfig_GetSection_fn   GConfig_GetSection;
extern GConfig_EmptySection_fn GConfig_EmptySection;

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
int is_zed_actor(const ucs2_t *name);
int get_level_objects(void **out_level_info, void **out_game_info);
void* get_gconfig(void);
void *find_gri(void);
void *find_access_control(void);

// clang-format on
#endif /* HOOK_ENGINE_H */