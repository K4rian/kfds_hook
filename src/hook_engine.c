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
// Check once per second at 30 Hz
#define GAME_STARTED_PROBE_INTERVAL 30

// ============================================================================
// ENGINE STATIC STATE
// ============================================================================
/*
 * Captured on the first hook_engine_tick() call, never changed again.
 * Written once by the game thread via atomic store and read via
 * hook_engine_get().
 */
static void *GGameEngine = NULL;
/*
 * Tracks level changes via UGameEngine
 */
static void *last_level_ptr = NULL;
/*
 * Set on bWaveInProgress transition
 */
static int game_started = 0;
/*
 * Tick counter for game_started probe
 * Starting at 1 defers the first probe by one full interval, 
 * giving the level time to settle.
 */
static unsigned int game_started_tick_count = 1;

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
/*
 * Updates level change detection and game_started state.
 * Called on every tick, probes bWaveInProgress once per
 * GAME_STARTED_PROBE_INTERVAL ticks until the game session starts.
 */
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
    game_started_tick_count = 1;
    hook_log_debug("game_started reset\n");
    hook_policy_on_level_change();
  }
  if (cur_level)
    last_level_ptr = cur_level;

  // Poll for bWaveInProgress once per GAME_STARTED_PROBE_INTERVAL ticks
  if (!game_started && cur_level) {
    if ((game_started_tick_count++ % GAME_STARTED_PROBE_INTERVAL) == 0) {
      void *gri = hook_engine_get_gri();
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
  // This function is the sole writer and always runs on the game thread,
  // so no concurrent write is possible. The RELEASE store pairs with the
  // ACQUIRE load in hook_engine_get() to guarantee the socket thread
  // observes the pointer once set
  if (!GGameEngine) {
    __atomic_store_n(&GGameEngine, self, __ATOMIC_RELEASE);
    hook_log_debug("UGameEngine* captured: %p\n", self);
  }

  update_game_state();
  hook_policy_update_bans();

  // Double-check busy state: a level transition may have begun after
  // handle_client's initial check and before poll returned
  if (hook_socket_poll() && !hook_engine_is_server_busy())
    hook_command_dispatch();
}

/*
 * Returns the captured GGameEngine pointer, or NULL if the first
 * tick has not yet occurred. Safe to call from any thread.
 */
void *hook_engine_get(void) {
  return __atomic_load_n(&GGameEngine, __ATOMIC_ACQUIRE);
}

/*
 * Returns the GConfig (FConfigCacheIni*) singleton pointer.
 * Callers must ensure the engine is fully initialised before 
 * calling this function.
 * All GConfig_* calls require a non-NULL return value.
 */
void *hook_engine_get_gconfig(void) {
  return *(void **)ADDR_GCONFIG_PTR;
}

// ============================================================================
// ENGINE HELPERS
// ============================================================================
/*
 * Returns 1 if the engine is not ready to process commands:
 * engine pointer is NULL or a level transition is in progress.
 */
int hook_engine_is_server_busy(void) {
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
int hook_engine_is_game_started(void) {
  return game_started;
}

/*
 * Returns 1 if the UObject name contains "PlayerController" as a substring.
 * Names shorter than 16 chars exit immediately without scanning.
 */
int hook_engine_is_player_controller(const ucs2_t *name) {
  return name && ucs2_contains_ascii(name, "PlayerController");
}

/* Returns 1 if the actor class name starts with "Zombie" and is not a
 * non-pawn map actor. KF monster classes are all named Zombie*, but so are
 * ZombiePathNode and ZombieVolume actors placed by the mapper -> exclude them.
 */
int hook_engine_is_zed_actor(const ucs2_t *name) {
  if (!name || !ucs2_starts_with_ascii(name, "Zombie")) 
    return 0;
  // name+6 is safe since "Zombie" matched above guarantees at
  // least 6 characters before the null terminator
  if (ucs2_starts_with_ascii(name + 6, "Path"))
    return 0;
  if (ucs2_starts_with_ascii(name + 6, "Volu"))
    return 0;
  return 1;
}

/*
 * Retrieves the current level pointer.
 */
void *hook_engine_get_level(void) {
  void *engine = hook_engine_get();
  if (!engine)
    return NULL;
  return *(void **)((uint8_t *)engine + UGAMEENGINE_OFFSET_Level);
}

/*
 * Retrieves the actors and count from the current level.
 * Returns 1 and populates out_actors/out_count on success, 0 if not ready.
 */
int hook_engine_get_level_actors(void ***out_actors, int *out_count) {
  void *level = hook_engine_get_level();
  if (!level)
    return 0;
  *out_actors = *(void ***)((uint8_t *)level + ULEVEL_OFFSET_Actors);
  *out_count = *(int *)((uint8_t *)level + ULEVEL_OFFSET_Actors_Num);
  return 1;
}

/*
 * Resolves the active level info objects from GGameEngine.
 * Returns 1 and populates out_level_info and out_game_info on success.
 * Returns 0 only if the engine or level info pointers are not yet available.
 */
int hook_engine_get_level_info(void **out_level_info, void **out_game_info) {
  void *level = hook_engine_get_level();
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
 * Scans the current level's actor list for the first actor whose UObject
 * name starts with actor_name. 
 * Returns NULL if not found or level not ready.
 */
static void *hook_engine_find_level_actor(const char *actor_name) {
  void **actors = NULL;
  int actor_count = 0;
  if (!hook_engine_get_level_actors(&actors, &actor_count))
    return NULL;

  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;

    const ucs2_t *name = UObject_GetName(actor);
    if (name && ucs2_starts_with_ascii(name, actor_name))
      return actor;
  }
  return NULL;
}

/*
 * Find the GRI actor by scanning for an object whose name starts
 * with "KFGameRep". Confirmed name: KFGameReplicationInfo.
 */
void *hook_engine_get_gri(void) {
  return hook_engine_find_level_actor("KFGameRep");
}

/*
 * Find the AccessControl actor by scanning for an object whose name starts
 * with "AccessControl". AccessControl -> Info -> Actor, so it lives in the
 * actor list alongside GRI. Scan by name rather than following
 * GameInfo+offset to avoid needing a confirmed offset for the
 * AccessControl* field on GameInfo.
 */
void *hook_engine_get_access_control(void) {
  return hook_engine_find_level_actor("AccessControl");
}