#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "hook_config.h"
#include "hook_engine.h"
#include "hook_log.h"
#include "hook_socket.h"
#include "jsmn/jsmn.h"

// ============================================================================
// JSMN
// ============================================================================
#define JSMN_MAX_TOKENS 64

// ============================================================================
// SOCKET TYPES
// ============================================================================
typedef enum {
  RESP_INTERNAL_ERR,
  RESP_INVALID_JSON,
  RESP_BUSY,
  RESP_TIMEOUT,
  RESP_UNKNOWN_TYPE,
  RESP_READY,
  RESP_NOT_READY,
  RESP_OVERFLOW,
  RESP_RATE_LIMITED
} hook_response_t;

typedef struct {
  const char *msg;
  size_t len;
} response_t;

#define RESP_ENTRY(s) {(s), sizeof(s) - 1}
static const response_t default_resp_table[] = {
    [RESP_INTERNAL_ERR] =
        RESP_ENTRY("{\"ok\":false,\"e\":\"internal error\"}\n"),
    [RESP_INVALID_JSON] = RESP_ENTRY("{\"ok\":false,\"e\":\"invalid JSON\"}\n"),
    [RESP_BUSY] = RESP_ENTRY("{\"ok\":false,\"e\":\"busy\"}\n"),
    [RESP_TIMEOUT] = RESP_ENTRY("{\"ok\":false,\"e\":\"timeout\"}\n"),
    [RESP_UNKNOWN_TYPE] = RESP_ENTRY("{\"ok\":false,\"e\":\"unknown type\"}\n"),
    [RESP_READY] = RESP_ENTRY("{\"ready\":true}\n"),
    [RESP_NOT_READY] = RESP_ENTRY("{\"ready\":false}\n"),
    [RESP_OVERFLOW] = RESP_ENTRY("{\"ok\":false,\"e\":\"response overflow\"}"),
    [RESP_RATE_LIMITED] = RESP_ENTRY("{\"ok\":false,\"e\":\"rate limited\"}\n"),
};
#undef RESP_ENTRY

// ============================================================================
// SOCKET GLOBAL STATE
// ============================================================================
hook_socket_slot_t g_socket_slot = {0};

// ============================================================================
// SOCKET STATIC STATE
// ============================================================================
static pthread_t socket_thread_handle;
static int socket_thread_running = 0;
static int server_fd = -1;
static int slot_initialised = 0;

// ============================================================================
// SOCKET PARSER
// ============================================================================
/*
 * Returns 1 if token content equals s, 0 otherwise
 */
static int jsmn_eq(const char *js, const jsmntok_t *tok, const char *s) {
  return tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
         memcmp(js + tok->start, s, (size_t)(tok->end - tok->start)) == 0;
}

/*
 * Copy token content into dst, null-terminated, truncated to dst_len-1
 */
static void jsmn_copy(const char *js, const jsmntok_t *tok, char *dst,
                      size_t dst_len) {
  if (dst == NULL || dst_len == 0)
    return;

  size_t len = (size_t)(tok->end - tok->start);
  if (len >= dst_len)
    len = dst_len - 1;
  memcpy(dst, js + tok->start, len);
  dst[len] = '\0';
}

/*
 * Returns 1 if the current second's command budget is exhausted, 0 otherwise.
 * Called exclusively from the socket thread, no locking required.
 */
static int is_rate_limited(void) {
  if (g_config.socket_maxpoll <= 0)
    return 0;

  static int poll_count = 0;
  static time_t poll_window = 0;

  time_t now = time(NULL);
  if (now != poll_window) {
    poll_window = now;
    poll_count = 0;
  }
  if (poll_count >= g_config.socket_maxpoll)
    return 1;

  poll_count++;
  return 0;
}

/*
 * Parse incoming JSON into hook_socket_request_t
 * Expected shape:
 *   {"t":"S"}
 *   {"t":"X","c":"CommandName","a":["arg0","arg1",...]}
 *
 * Returns 1 on success, 0 on parse error or unrecognized shape
 */
static int parse_request(const char *js, size_t len,
                         hook_socket_request_t *req) {
  jsmn_parser p;
  jsmn_init(&p);

  jsmntok_t tokens[JSMN_MAX_TOKENS];

  int r = jsmn_parse(&p, js, len, tokens, JSMN_MAX_TOKENS);
  if (r < 1 || tokens[0].type != JSMN_OBJECT)
    return 0;

  memset(req, 0, sizeof(*req));

  int type_found = 0;
  int i = 1;
  for (int pair = 0; pair < tokens[0].size && i + 1 < r; pair++) {
    jsmntok_t *key = &tokens[i];
    jsmntok_t *val = &tokens[i + 1];

    if (jsmn_eq(js, key, "t")) {
      // Type field: must be exactly one character
      if (val->end - val->start != 1)
        return 0;
      req->type = js[val->start];
      type_found = 1;
      i += 2;
    } else if (jsmn_eq(js, key, "c")) {
      // Command name
      jsmn_copy(js, val, req->cmd, CMD_MAX_CHARS);
      i += 2;
    } else if (jsmn_eq(js, key, "a") && val->type == JSMN_ARRAY) {
      // Argument array: copy up to MAX_ARGS string elements
      int arr_size = val->size;
      for (int k = 0; k < arr_size && k < MAX_ARGS; k++) {
        int tidx = i + 2 + k;
        if (tidx >= r)
          break;
        if (tokens[tidx].type != JSMN_STRING)
          continue;
        jsmn_copy(js, &tokens[tidx], req->args[k], ARG_MAX_CHARS);
        req->argc++;
      }
      i += 2 + arr_size;

    } else {
      // Unknown key: skip the key and its value.
      int skip = 2;
      if (val->type == JSMN_ARRAY || val->type == JSMN_OBJECT)
        skip += val->size;
      i += skip;
    }
  }

  if (!type_found)
    return 0;

  // Status query: no further fields required
  if (req->type == 'S')
    return 1;

  // Command: "c" is mandatory and must be non-empty
  if (req->type == 'X' && req->cmd[0] != '\0')
    return 1;

  return 0;
}

// ============================================================================
// SOCKET HANDLER
// ============================================================================
/*
 * Send an arbitrary buffer to a client socket.
 */
static void send_response(int fd, const char *buf, size_t len) {
  const char *p = buf;
  while (len > 0) {
    ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      hook_log_error("send failed: %s\n", strerror(errno));
      return;
    }
    if (n == 0) {
      // Shouldn't happen
      hook_log_error("send returned 0\n");
      return;
    }
    p += n;
    len -= (size_t)n;
  }
}

/*
 * Send a predefined response to a client socket.
 */
static void send_default_response(int fd, hook_response_t r) {
  const response_t *resp;
  if (r >= (int)(sizeof(default_resp_table) / sizeof(default_resp_table[0]))) {
    resp = &default_resp_table[RESP_INTERNAL_ERR];
  } else {
    resp = &default_resp_table[r];
  }
  send_response(fd, resp->msg, resp->len);
}

/*
 * Read, accumulate, parse, and dispatch a single client request.
 * Closes client_fd before returning.
 */
static void handle_client(int client_fd) {
  char buf[RECV_BUF_BYTES];
  ssize_t total = 0;
  int terminated = 0;

  // Accumulate incoming bytes across multiple recv() calls until a
  // message terminator is found, the buffer is full,
  // the client closes the connection, or an error occurs
  while (total < (ssize_t)(sizeof(buf) - 1)) {
    ssize_t n =
        recv(client_fd, buf + total, sizeof(buf) - 1 - (size_t)total, 0);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      // EAGAIN / EWOULDBLOCK
      // SO_RCVTIMEO fired, or other hard error
      goto done;
    }
    if (n == 0)
      break; // EOF

    // Scan the newly received chunk for a terminator
    for (ssize_t j = total; j < total + n; j++) {
      if (buf[j] == '\n' || buf[j] == '\0') {
        total = j; // body ends before the terminator
        terminated = 1;
        break;
      }
    }
    if (terminated)
      break;
    total += n;
  }

  if (total <= 0)
    goto done;

  buf[total] = '\0';

  hook_socket_request_t req;
  if (!parse_request(buf, (size_t)total, &req)) {
    send_default_response(client_fd, RESP_INVALID_JSON);
    goto done;
  }

  // Status query
  // Answered directly on the socket thread, no game thread needed
  if (req.type == 'S') {
    int busy = (!hook_engine_get() || hook_engine_is_server_busy());
    send_default_response(client_fd, busy ? RESP_NOT_READY : RESP_READY);
    goto done;
  }

  // Game command
  // Hand off to the game thread via the slot
  if (req.type == 'X') {
    if (!hook_engine_get() || hook_engine_is_server_busy()) {
      send_default_response(client_fd, RESP_BUSY);
      goto done;
    }

    // Reject immediately if the rate limit for this window is exhausted
    if (is_rate_limited()) {
      send_default_response(client_fd, RESP_RATE_LIMITED);
      goto done;
    }

    pthread_mutex_lock(&g_socket_slot.mutex);
    memcpy(&g_socket_slot.req, &req, sizeof(req));
    g_socket_slot.cmd_ready = 1;
    g_socket_slot.resp_ready = 0;
    pthread_cond_signal(&g_socket_slot.cmd_cond);

    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
      hook_log_error("clock_gettime failed: %s\n", strerror(errno));
      g_socket_slot.cmd_ready = 0;
      pthread_mutex_unlock(&g_socket_slot.mutex);
      send_default_response(client_fd, RESP_INTERNAL_ERR);
      goto done;
    }
    deadline.tv_sec += g_config.socket_deadline;

    int timed_out = 0;
    while (!g_socket_slot.resp_ready) {
      if (pthread_cond_timedwait(&g_socket_slot.resp_cond, &g_socket_slot.mutex,
                                 &deadline) == ETIMEDOUT) {
        timed_out = 1;
        g_socket_slot.cmd_ready = 0;
        break;
      }
    }

    if (timed_out) {
      pthread_mutex_unlock(&g_socket_slot.mutex);
      send_default_response(client_fd, RESP_TIMEOUT);
      goto done;
    }

    size_t response_len = strlen(g_socket_slot.response);
    if (response_len >= RESP_MAX_BYTES)
      response_len = RESP_MAX_BYTES - 1;
    char response_copy[RESP_MAX_BYTES + 1];
    memcpy(response_copy, g_socket_slot.response, response_len);
    pthread_mutex_unlock(&g_socket_slot.mutex);

    response_copy[response_len] = '\n';
    send_response(client_fd, response_copy, response_len + 1);
    goto done;
  }
  send_default_response(client_fd, RESP_UNKNOWN_TYPE);

done:
  close(client_fd);
}

// ============================================================================
// SOCKET RESPONSE
// ============================================================================
/*
 * Write jb's JSON body into the response slot and signal the socket thread.
 * Strips a trailing newline if present, handle_client() appends it on send.
 * Called from the game thread.
 */
void hook_socket_finish_json(json_buf_t *jb) {
  pthread_mutex_lock(&g_socket_slot.mutex);
  if (jb->overflow) {
    memcpy(g_socket_slot.response, default_resp_table[RESP_OVERFLOW].msg,
           default_resp_table[RESP_OVERFLOW].len);
  } else {
    size_t jb_len = strlen(jb->buf);
    if (jb_len > 0 && jb->buf[jb_len - 1] == '\n')
      jb_len--;
    if (jb_len == 0) {
      g_socket_slot.response[0] = '\0';
    } else {
      if (jb_len >= RESP_MAX_BYTES)
        jb_len = RESP_MAX_BYTES - 1;
      memcpy(g_socket_slot.response, jb->buf, jb_len);
      g_socket_slot.response[jb_len] = '\0';
    }
  }
  g_socket_slot.cmd_ready = 0;
  g_socket_slot.resp_ready = 1;
  pthread_cond_signal(&g_socket_slot.resp_cond);
  pthread_mutex_unlock(&g_socket_slot.mutex);
}

/*
 * Convenience wrapper:
 * Signals {"ok":true} to the socket thread.
 */
void hook_socket_finish_ok(void) {
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true}");
  hook_socket_finish_json(&jb);
}

/*
 * Convenience wrapper:
 * Signals {"ok":false,"e":<reason>} to the socket thread.
 */
void hook_socket_finish_err(const char *reason) {
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":false,\"e\":");
  jb_str(&jb, reason);
  jb_raw(&jb, "}");
  hook_socket_finish_json(&jb);
}

// ============================================================================
// SOCKET THREAD
// ============================================================================
/*
 * Socket thread entry point: binds, listens, and dispatches incoming
 * connections to handle_client(). Exits cleanly on accept() error (including
 * EBADF when server_fd is closed by hook_socket_start() or hook_socket_stop()).
 */
static void *socket_thread(void *arg) {
  (void)arg;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, g_config.socket_path, sizeof(addr.sun_path) - 1);

  unlink(g_config.socket_path);

  if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(server_fd, 4) != 0) {
    hook_log_error("Unix socket bind/listen failed: %s\n", strerror(errno));
    close(server_fd);
    server_fd = -1;
    return NULL;
  }

  hook_log_info("Unix socket listening at %s\n", g_config.socket_path);

  while (1) {
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
      if (errno == EINTR)
        continue;
      // Any other error (including EBADF) breaks the loop and
      // exits the thread cleanly
      break;
    }
    struct timeval tv = {.tv_sec = g_config.socket_deadline, .tv_usec = 0};
    if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
      hook_log_warn("SO_RCVTIMEO failed: %s\n", strerror(errno));
    if (setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
      hook_log_warn("SO_SNDTIMEO failed: %s\n", strerror(errno));

    handle_client(client_fd);
  }
  return NULL;
}

// ============================================================================
// SOCKET
// ============================================================================
/*
 * Signal-safe shutdown:
 * Close the server fd and remove the socket file.
 */
static void socket_shutdown(void) {
  if (server_fd >= 0) {
    close(server_fd);
    server_fd = -1;
  }
  unlink(g_config.socket_path);
}

/*
 * Init or restart the socket thread. If a thread is already running,
 * wakes any blocked waiters, closes server_fd, and joins before proceeding.
 * Pthread primitives are initialised once and reused across restarts.
 */
void hook_socket_start(void) {
  if (socket_thread_running) {
    if (slot_initialised) {
      pthread_mutex_lock(&g_socket_slot.mutex);
      g_socket_slot.cmd_ready = 0;
      g_socket_slot.resp_ready = 0;
      pthread_cond_broadcast(&g_socket_slot.cmd_cond);
      pthread_cond_broadcast(&g_socket_slot.resp_cond);
      pthread_mutex_unlock(&g_socket_slot.mutex);
    }
    if (server_fd >= 0) {
      close(server_fd);
      server_fd = -1;
    }
    pthread_join(socket_thread_handle, NULL);
    socket_thread_running = 0;
  }

  server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_fd < 0) {
    hook_log_error("socket() failed: %s\n", strerror(errno));
    return;
  }

  // Primitives are initialised once and reused across restarts
  if (!slot_initialised) {
    pthread_condattr_t cattr;
    if (pthread_condattr_init(&cattr) != 0 ||
        pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC) != 0) {
      hook_log_error("pthread_condattr init failed: %s\n", strerror(errno));
      close(server_fd);
      server_fd = -1;
      return;
    }

    if (pthread_mutex_init(&g_socket_slot.mutex, NULL) != 0 ||
        pthread_cond_init(&g_socket_slot.cmd_cond, &cattr) != 0 ||
        pthread_cond_init(&g_socket_slot.resp_cond, &cattr) != 0) {
      hook_log_error("pthread init failed: %s\n", strerror(errno));
      pthread_condattr_destroy(&cattr);
      close(server_fd);
      server_fd = -1;
      return;
    }
    pthread_condattr_destroy(&cattr);
    slot_initialised = 1;
  }

  g_socket_slot.cmd_ready = 0;
  g_socket_slot.resp_ready = 0;

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  int ptc = pthread_create(&socket_thread_handle, &attr, socket_thread, NULL);
  if (ptc != 0) {
    hook_log_error("pthread_create failed: %d\n", ptc);
    pthread_attr_destroy(&attr);
    close(server_fd);
    server_fd = -1;
    return;
  }
  socket_thread_running = 1;
  pthread_attr_destroy(&attr);
}

/*
 * Broadcast to any blocked waiters, then delegate fd/file teardown to
 * socket_shutdown().
 * Doesn't join the thread -> safe to call from a signal handler.
 */
void hook_socket_stop(void) {
  if (slot_initialised) {
    pthread_mutex_lock(&g_socket_slot.mutex);
    g_socket_slot.req = (hook_socket_request_t){0};
    g_socket_slot.response[0] = '\0';
    g_socket_slot.cmd_ready = 0;
    g_socket_slot.resp_ready = 0;
    pthread_cond_broadcast(&g_socket_slot.cmd_cond);
    pthread_cond_broadcast(&g_socket_slot.resp_cond);
    pthread_mutex_unlock(&g_socket_slot.mutex);
  }
  socket_shutdown();
}

/*
 * Check whether a command is pending dispatch to the game thread.
 * Returns cmd_ready under trylock.
 * Returns 0 if the mutex is contended.
 * Called from the game thread on every Tick.
 */
int hook_socket_poll(void) {
  if (pthread_mutex_trylock(&g_socket_slot.mutex) != 0)
    return 0;

  int ready = g_socket_slot.cmd_ready;
  pthread_mutex_unlock(&g_socket_slot.mutex);
  return ready;
}