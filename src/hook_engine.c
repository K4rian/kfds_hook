#include <stddef.h>

#include "hook_cmd.h"
#include "hook_engine.h"
#include "hook_log.h"
#include "hook_socket.h"

// ============================================================================
// ENGINE DEFINES
// ============================================================================
#define GAME_STARTED_PROBE_INTERVAL 30 // Check once per second at 30 Hz

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

FString_ctor_fn FString_ctor = (FString_ctor_fn)ADDR_FString_ctor_wchar;
FString_dtor_fn FString_dtor = (FString_dtor_fn)ADDR_FString_dtor;

// ============================================================================
// ENGINE
// ============================================================================
static void update_game_state(void) {
  void *engine = hook_engine_get();
  if (!engine)
    return;

  // Level change detection
  void *cur_level = *(void **)((uint8_t *)engine + UGAMEENGINE_LEVEL_OFFSET);
  if (cur_level && last_level_ptr && cur_level != last_level_ptr) {
    hook_log_debug("level change detected (%p -> %p)\n", last_level_ptr,
                   cur_level);
    game_started = 0;
    game_started_tick_count = 0;
  }
  if (cur_level)
    last_level_ptr = cur_level;

  // game_started probe, once per GAME_STARTED_PROBE_INTERVAL ticks
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
      *(void **)((uint8_t *)engine + UGAMEENGINE_PENDING_LEVEL_OFFSET);
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
  if (!name)
    return 0;

  int len = 0;
  while (name[len])
    len++;

  if (len < 16)
    return 0;

  for (int j = 0; j <= len - 16; j++) {
    if (name[j] == 'P' && name[j + 1] == 'l' && name[j + 2] == 'a' &&
        name[j + 3] == 'y' && name[j + 4] == 'e' && name[j + 5] == 'r' &&
        name[j + 6] == 'C' && name[j + 7] == 'o' && name[j + 8] == 'n' &&
        name[j + 9] == 't' && name[j + 10] == 'r' && name[j + 11] == 'o' &&
        name[j + 12] == 'l' && name[j + 13] == 'l' && name[j + 14] == 'e' &&
        name[j + 15] == 'r')
      return 1;
  }
  return 0;
}

/* Returns 1 if the actor class name starts with "Zombie" and is not a
 * non-pawn map actor. KF monster classes are all named Zombie*, but so are
 * ZombiePathNode and ZombieVolume actors placed by the mapper -> exclude them.
 */
int is_zed_actor(const ucs2_t *name) {
  if (!name)
    return 0;
  if (!(name[0] == 'Z' && name[1] == 'o' && name[2] == 'm' && name[3] == 'b' &&
        name[4] == 'i' && name[5] == 'e'))
    return 0;
  // Exclude ZombiePathNode
  if (name[6] == 'P' && name[7] == 'a' && name[8] == 't' && name[9] == 'h')
    return 0;
  // Exclude ZombieVolume
  if (name[6] == 'V' && name[7] == 'o' && name[8] == 'l' && name[9] == 'u')
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

  void *level = *(void **)((uint8_t *)engine + UGAMEENGINE_LEVEL_OFFSET);
  if (!level)
    return 0;

  void *level_info = ULevel_GetLevelInfo(level);
  if (!level_info)
    return 0;

  void *game_info =
      *(void **)((uint8_t *)level_info + ALEVELINFO_GAMEINFO_OFFSET);
  if (!game_info)
    return 0;

  *out_level_info = level_info;
  *out_game_info = game_info;
  return 1;
}

/*
 * Find the GRI actor by scanning for an object whose name starts with "GameR".
 */
void *find_gri(void) {
  void *engine = hook_engine_get();
  if (!engine)
    return NULL;

  void *level = *(void **)((uint8_t *)engine + UGAMEENGINE_LEVEL_OFFSET);
  if (!level)
    return NULL;

  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);
  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;

    const ucs2_t *name = UObject_GetName(actor);
    if (!name)
      continue;

    for (int j = 0; name[j]; j++)
      if (name[j] == 'G' && name[j + 1] == 'a' && name[j + 2] == 'm' &&
          name[j + 3] == 'e' && name[j + 4] == 'R')
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

  void *level = *(void **)((uint8_t *)engine + UGAMEENGINE_LEVEL_OFFSET);
  if (!level)
    return NULL;

  void **actors = *(void ***)((uint8_t *)level + 0x30);
  int actor_count = *(int *)((uint8_t *)level + 0x34);
  for (int i = 0; i < actor_count; i++) {
    void *actor = actors[i];
    if (!actor)
      continue;
  
    const ucs2_t *name = UObject_GetName(actor);
    if (!name)
      continue;
  
    // Match "AccessControl"
    // 13 chars, check length first
    int len = 0;
    while (name[len])
      len++;
    if (len < 13)
      continue;
  
    for (int j = 0; j <= len - 13; j++)
      if (name[j] == 'A' && name[j + 1] == 'c' && name[j + 2] == 'c' &&
          name[j + 3] == 'e' && name[j + 4] == 's' && name[j + 5] == 's' &&
          name[j + 6] == 'C' && name[j + 7] == 'o' && name[j + 8] == 'n' &&
          name[j + 9] == 't' && name[j + 10] == 'r' && name[j + 11] == 'o' &&
          name[j + 12] == 'l')
        return actor;
  }
  return NULL;
}