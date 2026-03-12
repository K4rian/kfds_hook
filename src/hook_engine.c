#include <stddef.h>

#include "hook_engine.h"

// ============================================================================
// ENGINE GLOBAL STATE
// ============================================================================
void *GGameEngine = NULL;

UObject_GetName_fn UObject_GetName = 
    (UObject_GetName_fn)ADDR_UObject_GetName;

UGameEngine_Exec_fn UGameEngine_Exec =
    (UGameEngine_Exec_fn)ADDR_UGameEngine_Exec;

ULevel_GetLevelInfo_fn ULevel_GetLevelInfo =
    (ULevel_GetLevelInfo_fn)ADDR_ULevel_GetLevelInfo;
ALevelInfo_eventServerTravel_fn ALevelInfo_eventServerTravel =
    (ALevelInfo_eventServerTravel_fn)ADDR_ALevelInfo_eventServerTravel;

AGameInfo_eventBroadcast_fn AGameInfo_eventBroadcast =
    (AGameInfo_eventBroadcast_fn)ADDR_AGameInfo_eventBroadcast;

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

// ============================================================================
// ENGINE HELPERS
// ============================================================================
/*
 * Returns 1 if the engine is not ready to process commands:
 * engine pointer is NULL or a level transition is in progress
 */
int is_server_busy(void *engine) {
  if (!engine)
    return 1;

  void *pending =
      *(void **)((uint8_t *)engine + UGAMEENGINE_PENDING_LEVEL_OFFSET);
  return pending != NULL;
}

/*
 * Resolves the active level objects from GGameEngine
 * Returns 1 and populates out_level_info and out_game_info on success
 * Returns 0 if the engine is not fully initialised or a level transition
 * is in progress
 */
int get_level_objects(void **out_level_info, void **out_game_info) {
  void *level = *(void **)((uint8_t *)GGameEngine + UGAMEENGINE_LEVEL_OFFSET);
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
 * Find the GRI actor by scanning for an object whose name starts with "GameR"
 */
void *find_gri(void) {
  void *level = *(void **)((uint8_t *)GGameEngine + UGAMEENGINE_LEVEL_OFFSET);
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