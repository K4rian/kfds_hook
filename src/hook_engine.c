#include <stddef.h>
#include <stdint.h>

#include "hook_cmd.h"
#include "hook_engine.h"
#include "hook_log.h"
#include "hook_policy.h"
#include "hook_socket.h"
#include "hook_ucs2.h"

// ============================================================================
// ENGINE DEFINES
// ============================================================================
#define GAME_STARTED_PROBE_INTERVAL 30  // Check once per second at 30 Hz

// ============================================================================
// ENGINE STATIC STATE
// ============================================================================
/*
 * Captured on the first hook_engine_tick() call, never changed again.
 * Written once by the game thread via atomic store and read via
 * hook_engine_get().
 */
static void *GGameEngine = NULL;

static void *last_level_ptr = NULL;     // Tracks level changes via UGameEngine
static int game_started = 0;            // Set on bWaveInProgress transition
static int game_started_tick_count = 0; // Tick counter for game_started probe

// ============================================================================
// ENGINE GLOBAL STATE
// ============================================================================
UObject_GetName_fn UObject_GetName = (UObject_GetName_fn)ADDR_UObject_GetName;

UGameEngine_Exec_fn UGameEngine_Exec =
    (UGameEngine_Exec_fn)ADDR_UGameEngine_Exec;
UGameEngine_GetMaxTickRate_fn UGameEngine_GetMaxTickRate =
    (UGameEngine_GetMaxTickRate_fn)ADDR_UGameEngine_GetMaxTickRate;

ULevel_GetLevelInfo_fn ULevel_GetLevelInfo =
    (ULevel_GetLevelInfo_fn)ADDR_ULevel_GetLevelInfo;

ALevelInfo_eventServerTravel_fn ALevelInfo_eventServerTravel =
    (ALevelInfo_eventServerTravel_fn)ADDR_ALevelInfo_eventServerTravel;

AGameInfo_eventBroadcast_fn AGameInfo_eventBroadcast =
    (AGameInfo_eventBroadcast_fn)ADDR_AGameInfo_eventBroadcast;
AGameInfo_eventKickIdler_fn AGameInfo_eventKickIdler =
    (AGameInfo_eventKickIdler_fn)ADDR_AGameInfo_eventKickIdler;

AActor_eventTakeDamage_fn AActor_eventTakeDamage =
    (AActor_eventTakeDamage_fn)ADDR_AActor_eventTakeDamage;

APlayerController_eventClientMessage_fn APlayerController_eventClientMessage =
    (APlayerController_eventClientMessage_fn)
        ADDR_APlayerController_eventClientMessage;
Cast_APlayerController_fn Cast_APlayerController =
    (Cast_APlayerController_fn)ADDR_Cast_APlayerController;

FString_ctor_fn FString_ctor = (FString_ctor_fn)ADDR_FString_ctor;
FString_dtor_fn FString_dtor = (FString_dtor_fn)ADDR_FString_dtor;

GConfig_GetString_fn GConfig_GetString =
    (GConfig_GetString_fn)ADDR_GConfig_GetString;
GConfig_SetString_fn GConfig_SetString =
    (GConfig_SetString_fn)ADDR_GConfig_SetString;
GConfig_GetInt_fn GConfig_GetInt =
    (GConfig_GetInt_fn)ADDR_GConfig_GetInt;
GConfig_SetInt_fn GConfig_SetInt =
    (GConfig_SetInt_fn)ADDR_GConfig_SetInt;
GConfig_GetFloat_fn GConfig_GetFloat =
    (GConfig_GetFloat_fn)ADDR_GConfig_GetFloat;
GConfig_SetFloat_fn GConfig_SetFloat =
    (GConfig_SetFloat_fn)ADDR_GConfig_SetFloat;
GConfig_GetBool_fn GConfig_GetBool =
    (GConfig_GetBool_fn)ADDR_GConfig_GetBool;
GConfig_SetBool_fn GConfig_SetBool =
    (GConfig_SetBool_fn)ADDR_GConfig_SetBool;
GConfig_Flush_fn GConfig_Flush =
    (GConfig_Flush_fn)ADDR_GConfig_Flush;
GConfig_GetSection_fn GConfig_GetSection =
    (GConfig_GetSection_fn)ADDR_GConfig_GetSection;
GConfig_EmptySection_fn GConfig_EmptySection =
    (GConfig_EmptySection_fn)ADDR_GConfig_EmptySection;

// ============================================================================
// ENGINE
// ============================================================================
static void update_game_state(void) {
  void *engine = hook_engine_get();
  if (!engine)
    return;

  // Level change detection
  void *cur_level = *(void **)((uint8_t *)engine + UGAMEENGINE_OFFSET_Level);
  if (cur_level && last_level_ptr && cur_level != last_level_ptr) {
    hook_log_debug("level change detected (%p -> %p)\n", last_level_ptr,
                   cur_level);
    game_started = 0;
    game_started_tick_count = 0;
    hook_log_debug("game_started reset\n");
    hook_policy_on_level_change();
  }
  if (cur_level)
    last_level_ptr = cur_level;

  // Increment every tick, probe fires every GAME_STARTED_PROBE_INTERVAL ticks
  if (!game_started && cur_level) {
    if ((game_started_tick_count++ % GAME_STARTED_PROBE_INTERVAL) == 0) {
      void *gri = find_gri();
      if (gri) {
        uint8_t wip = *(uint8_t *)((uint8_t *)gri + GRI_OFFSET_bWaveInProgress);
        if (wip) {
          game_started = 1;
          hook_log_debug("game_started set\n");
        }
      }
    }
  }
}

/*
 * Triggers on every game tick.
 * Captures GGameEngine on first call.
 */
void hook_engine_tick(void *self) {
  if (!GGameEngine) {
    __atomic_store_n(&GGameEngine, self, __ATOMIC_RELEASE);
    hook_log_debug("UGameEngine* captured: %p\n", self);
  }

  update_game_state();
  hook_policy_update_bans();

  if (hook_socket_poll() && !is_server_busy())
    hook_command_dispatch();
}

void *hook_engine_get(void) {
  return __atomic_load_n(&GGameEngine, __ATOMIC_ACQUIRE);
}

// ============================================================================
// ENGINE HELPERS
// ============================================================================
/*
 * Returns 1 if the engine is not ready to process commands:
 * engine pointer is NULL or a level transition is in progress.
 */
int is_server_busy(void) {
  void *engine = hook_engine_get();
  if (!engine)
    return 1;

  void *pending =
      *(void **)((uint8_t *)engine + UGAMEENGINE_OFFSET_PendingLevel);
  return pending != NULL;
}

/*
 * Returns 1 if the current game session has started (first bWaveInProgress
 * false->true transition observed), 0 otherwise.
 */
int is_game_started(void) {
  return game_started;
}

/*
 * Returns 1 if the UObject name contains "PlayerController" as a substring.
 * Names shorter than 16 chars exit immediately without scanning.
 */
int is_player_controller(const ucs2_t *name) {
  return name && ucs2_contains_ascii(name, "PlayerController");
}

/* Returns 1 if the actor class name starts with "Zombie" and is not a
 * non-pawn map actor. KF monster classes are all named Zombie*, but so are
 * ZombiePathNode and ZombieVolume actors placed by the mapper -> exclude them.
 */
int is_zed_actor(const ucs2_t *name) {
  if (!name || !ucs2_starts_with_ascii(name, "Zombie")) 
    return 0;
  if (ucs2_starts_with_ascii(name + 6, "Path")) 
    return 0;
  if (ucs2_starts_with_ascii(name + 6, "Volu")) 
    return 0;
  return 1;
}

/*
 * Resolves the active level objects from GGameEngine.
 * Returns 1 and populates out_level_info and out_game_info on success.
 * Returns 0 if the engine is not fully initialised or a level transition
 * is in progress.
 */
int get_level_objects(void **out_level_info, void **out_game_info) {
  void *engine = hook_engine_get();
  if (!engine)
    return 0;

  void *level = *(void **)((uint8_t *)engine + UGAMEENGINE_OFFSET_Level);
  if (!level)
    return 0;

  void *level_info = ULevel_GetLevelInfo(level);
  if (!level_info)
    return 0;

  void *game_info =
      *(void **)((uint8_t *)level_info + ALEVELINFO_OFFSET_GameInfo);
  if (!game_info)
    return 0;

  *out_level_info = level_info;
  *out_game_info = game_info;
  return 1;
}

/*
 * Returns the GConfig (FConfigCacheIni*) singleton pointer.
 * Dereferences ADDR_GCONFIG_PTR, returns NULL if not yet initialized.
 * All GConfig_* calls require a non-NULL return value.
 */
void *get_gconfig(void) {
  return *(void **)ADDR_GCONFIG_PTR;
}

/*
 * Find the GRI actor by scanning for an object whose name starts with "GameR".
 */
void *find_gri(void) {
  void *engine = hook_engine_get();
  if (!engine)
    return NULL;

  void *level = *(void **)((uint8_t *)engine + UGAMEENGINE_OFFSET_Level);
  if (!level)
    return NULL;

  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);
  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;

    const ucs2_t *name = UObject_GetName(actor);
    if (name && ucs2_contains_ascii(name, "GameR")) 
      return actor;
  }
  return NULL;
}

/*
 * Find the AccessControl actor by scanning for an object whose name contains
 * "AccessControl".
 * AccessControl -> Info -> Actor, so it lives in the actor
 * list alongside GRI. Typically only one instance exists per level.
 * Scan by name rather than following GameInfo+offset to avoid needing
 * a confirmed offset for the AccessControl* field on GameInfo.
 */
void *find_access_control(void) {
  void *engine = hook_engine_get();
  if (!engine)
    return NULL;

  void *level = *(void **)((uint8_t *)engine + UGAMEENGINE_OFFSET_Level);
  if (!level)
    return NULL;

  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);
  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;

    const ucs2_t *name = UObject_GetName(actor);
    if (name && ucs2_contains_ascii(name, "AccessControl")) 
      return actor;
  }
  return NULL;
}