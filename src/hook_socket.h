#ifndef HOOK_SOCKET_H
#define HOOK_SOCKET_H

#include <pthread.h>

#include "hook_json.h"
#include "hook_socket_defs.h"

// ============================================================================
// SOCKET TYPES
// ============================================================================
/*
 * Parsed inbound command
 * Populated by parse_request() in the socket thread
 * Consumed by execute_pending_command() on the game thread
 */
typedef struct {
  char type;                          // 'X' = command, 'S' = status query
  char cmd[CMD_MAX_CHARS];            // command name
  char args[MAX_ARGS][ARG_MAX_CHARS]; // positional UTF-8 arguments
  int argc;                           // number of args provided
} hook_socket_request_t;

/*
 * Single-slot p/c: socket thread produces, game thread consumes
 *   Socket thread: lock -> fill req -> cmd_ready=1 -> signal cmd_cond
 *                  -> wait on resp_cond -> copy response -> unlock
 *
 *   Game thread:   trylock -> if cmd_ready && !busy -> unlock
 *                  -> dispatch command -> finish json
 *
 *   finish json:   lock -> write response -> resp_ready=1
 *                  -> signal resp_cond -> unlock
 */
typedef struct {
  hook_socket_request_t req;
  char response[RESP_MAX_BYTES];
  int cmd_ready;
  int resp_ready;
  pthread_mutex_t mutex;
  pthread_cond_t cmd_cond;
  pthread_cond_t resp_cond;
} hook_socket_slot_t;

// ============================================================================
// SOCKET GLOBAL STATE
// ============================================================================
// Only intended for commands (hook_cmd.c)
extern hook_socket_slot_t g_socket_slot;

// ============================================================================
// SOCKET PARSER
// ============================================================================
void hook_socket_finish_json(json_buf_t *jb);
void hook_socket_finish_ok(void);
void hook_socket_finish_err(const char *reason);

// ============================================================================
// SOCKET
// ============================================================================
void hook_socket_start(void);
void hook_socket_stop(void);
int hook_socket_poll(void);

#endif /* HOOK_SOCKET_H */