#include <stdlib.h>
#include <string.h>

#include "hook_engine.h"
#include "hook_log.h"
#include "hook_policy.h"

// ============================================================================
// POLICY STATIC STATE
// ============================================================================
/*
 * Session ban lists, rebuilt into live AccessControl TArrays after each
 * level change.
 *
 * Entries are plain UTF-8 strings:
 *   IP bans:    "DENY;<ip>"
 *   Steam bans: "<steamid64> <name>"
 */
static char session_ip_bans[POLICY_SESSION_BAN_MAX][POLICY_SESSION_BAN_STR];
static char session_steam_bans[POLICY_SESSION_BAN_MAX][POLICY_SESSION_BAN_STR];
static int session_ip_ban_cnt = 0;
static int session_steam_ban_cnt = 0;

/*
 * Set to 1 on level change detection.
 * Cleared after bans been repopulated.
 */
static int repopulate_bans_pending = 0;

// ============================================================================
// POLICY HELPERS
// ============================================================================
/*
 * Re-appends session ban entries to the live AccessControl TArrays after a
 * level change. The engine reloads IPPolicies and BannedIDs from ini on
 * ServerTravel, any bans added this session must be re-injected.
 *
 * IP bans:    TArray is always pre-allocated by the engine, cap at Max.
 * Steam bans: TArray may be uninitialized if ini had no BannedIDs at startup.
 */
static void repopulate_bans(void) {
  void *ac = hook_engine_get_access_control();
  if (!ac) {
    hook_log_debug("repopulate_bans: AccessControl not found\n");
    return;
  }

  // Re-append IP bans
  TArrayFString *ip_arr =
      (TArrayFString *)((uint8_t *)ac + ACCESSCONTROL_OFFSET_IPPolicies);
  hook_log_debug("repopulate_bans: IPPolicies Num=%d after travel, "
                 "re-appending %d session entries\n",
                 ip_arr->Num, session_ip_ban_cnt);

  for (int i = 0; i < session_ip_ban_cnt; i++) {
    if (!ip_arr->Data || ip_arr->Num >= ip_arr->Max) {
      hook_log_warn("repopulate_bans: IPPolicies full at slot %d\n", i);
      break;
    }
    ucs2_t ubuf[POLICY_SESSION_BAN_STR] = {0};
    utf8_to_ucs2(session_ip_bans[i], ubuf, POLICY_SESSION_BAN_STR);
    FString_ctor(&ip_arr->Data[ip_arr->Num], ubuf);
    ip_arr->Num++;
    hook_log_debug("repopulate_bans: re-added IP \"%s\"\n", session_ip_bans[i]);
  }

  // Re-append Steam bans
  TArrayFString *st_arr =
      (TArrayFString *)((uint8_t *)ac + ACCESSCONTROL_OFFSET_BannedIDs);
  hook_log_debug("repopulate_bans: BannedIDs Num=%d after travel, "
                 "re-appending %d session entries\n",
                 st_arr->Num, session_steam_ban_cnt);

  // Bootstrap uninitialized TArray if needed
  if (session_steam_ban_cnt > 0 && (!st_arr->Data || st_arr->Max == 0)) {
    st_arr->Data =
        (FString *)calloc(POLICY_BANNEDIDS_INITIAL_MAX, sizeof(FString));
    if (!st_arr->Data) {
      hook_log_warn("repopulate_bans: BannedIDs TArray alloc failed "
                    "| steam bans lost\n");
      goto done;
    }
    st_arr->Num = 0;
    st_arr->Max = POLICY_BANNEDIDS_INITIAL_MAX;
    hook_log_debug("repopulate_bans: bootstrapped BannedIDs TArray "
                   "Max=%d\n",
                   POLICY_BANNEDIDS_INITIAL_MAX);
  }

  for (int i = 0; i < session_steam_ban_cnt; i++) {
    if (!st_arr->Data || st_arr->Num >= st_arr->Max) {
      hook_log_warn("repopulate_bans: BannedIDs full at slot %d\n", i);
      break;
    }
    ucs2_t ubuf[POLICY_SESSION_BAN_STR] = {0};
    utf8_to_ucs2(session_steam_bans[i], ubuf, POLICY_SESSION_BAN_STR);
    FString_ctor(&st_arr->Data[st_arr->Num], ubuf);
    st_arr->Num++;
    hook_log_debug("repopulate_bans: re-added Steam \"%s\"\n",
                   session_steam_bans[i]);
  }

done:
  hook_log_debug("repopulate_bans: done | IPPolicies Num=%d, "
                 "BannedIDs Num=%d\n",
                 ip_arr->Num, st_arr->Num);
}

// ============================================================================
// POLICY
// ============================================================================
/*
 * Called on level pointer change.
 * Schedules a ban repopulation for the next safe tick.
 * Deferred to hook_policy_update_bans() to avoid running
 * during a level transition.
 */
void hook_policy_on_level_change(void) {
  repopulate_bans_pending = 1;
}

/*
 * Called every tick after the game state being updated.
 * Call repopulate_bans() once the engine is no longer busy,
 * then clears the pending flag.
 * No-op if no repopulation is scheduled or if the engine
 * is still in a level transition.
 */
void hook_policy_update_bans(void) {
  if (repopulate_bans_pending && !hook_engine_is_server_busy()) {
    repopulate_bans_pending = 0;
    repopulate_bans();
  }
}

/*
 * Appends a policy string to the session IP ban list.
 * Returns 1 on success, 0 if the list is full.
 */
int hook_policy_add_session_ip_ban(const char *policy) {
  if (session_ip_ban_cnt >= POLICY_SESSION_BAN_MAX)
    return 0;

  size_t len = strlen(policy);
  if (len >= POLICY_SESSION_BAN_STR)
    len = POLICY_SESSION_BAN_STR - 1;
  memcpy(session_ip_bans[session_ip_ban_cnt], policy, len);
  session_ip_bans[session_ip_ban_cnt][len] = '\0';
  session_ip_ban_cnt++;
  return 1;
}

/*
 * Removes the session IP ban entry at index idx.
 * Shifts remaining entries left. No-op if idx is out of range.
 */
void hook_policy_remove_session_ip_ban(int idx) {
  if (idx < 0 || idx >= session_ip_ban_cnt)
    return;

  int tail = session_ip_ban_cnt - idx - 1;
  if (tail > 0) {
    memmove(session_ip_bans[idx], session_ip_bans[idx + 1],
            (size_t)tail * sizeof(session_ip_bans[0]));
  }
  session_ip_ban_cnt--;
}

/*
 * Returns the number of active session IP bans.
 */
int hook_policy_get_session_ip_ban_cnt(void) {
  return session_ip_ban_cnt;
}

/*
 * Returns the session IP ban string at index idx.
 * Returns NULL if idx is out of range.
 */
const char *hook_policy_get_session_ip_ban(int idx) {
  if (idx < 0 || idx >= session_ip_ban_cnt)
    return NULL;
  return session_ip_bans[idx];
}

/*
 * Appends an entry string to the session Steam ban list.
 * Returns 1 on success, 0 if the list is full.
 */
int hook_policy_add_session_steam_ban(const char *entry) {
  if (session_steam_ban_cnt >= POLICY_SESSION_BAN_MAX)
    return 0;

  size_t len = strlen(entry);
  if (len >= POLICY_SESSION_BAN_STR)
    len = POLICY_SESSION_BAN_STR - 1;
  memcpy(session_steam_bans[session_steam_ban_cnt], entry, len);
  session_steam_bans[session_steam_ban_cnt][len] = '\0';
  session_steam_ban_cnt++;
  return 1;
}

/*
 * Removes the session Steam ban entry at index idx.
 * Shifts remaining entries left. No-op if idx is out of range.
 */
void hook_policy_remove_session_steam_ban(int idx) {
  if (idx < 0 || idx >= session_steam_ban_cnt)
    return;

  int tail = session_steam_ban_cnt - idx - 1;
  if (tail > 0) {
    memmove(session_steam_bans[idx], session_steam_bans[idx + 1],
            (size_t)tail * sizeof(session_steam_bans[0]));
  }
  session_steam_ban_cnt--;
}

/*
 * Returns the number of active session Steam bans.
 */
int hook_policy_get_session_steam_ban_cnt(void) {
  return session_steam_ban_cnt;
}

/*
 * Returns the session Steam ban string at index idx.
 * Returns NULL if idx is out of range.
 */
const char *hook_policy_get_session_steam_ban(int idx) {
  if (idx < 0 || idx >= session_steam_ban_cnt)
    return NULL;
  return session_steam_bans[idx];
}