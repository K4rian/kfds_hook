#ifndef HOOK_POLICY_H
#define HOOK_POLICY_H

// ============================================================================
// POLICY DEFINES
// ============================================================================
#define POLICY_SESSION_BAN_MAX        64  // Max ban entry per session
#define POLICY_SESSION_BAN_STR        128 // Max string length
#define POLICY_BANNEDIDS_INITIAL_MAX  64  // Array size

// ============================================================================
// POLICY
// ============================================================================
void hook_policy_on_level_change(void);
void hook_policy_update_bans(void);

int hook_policy_add_session_ip_ban(const char *policy);
void hook_policy_remove_session_ip_ban(int idx);
int hook_policy_get_session_ip_ban_cnt(void);
const char *hook_policy_get_session_ip_ban(int idx);

int hook_policy_add_session_steam_ban(const char *entry);
void hook_policy_remove_session_steam_ban(int idx);
int hook_policy_get_session_steam_ban_cnt(void);
const char *hook_policy_get_session_steam_ban(int idx);

#endif /* HOOK_POLICY_H */