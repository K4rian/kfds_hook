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
// SOCKET MACROS
// ============================================================================
#define SEND_OR_LOG(fd, msg)                                                   \
  do {                                                                         \
    if (send((fd), (msg), sizeof(msg) - 1, 0) < 0)                             \
      hook_log_error("send failed: %s\n", strerror(errno));                    \
  } while (0)

#define SEND_PTR_OR_LOG(fd, msg)                                               \
  do {                                                                         \
    if (send((fd), (msg), strlen(msg), 0) < 0)                                 \
      hook_log_error("send failed: %s\n", strerror(errno));                    \
  } while (0)

// ============================================================================
// SOCKET GLOBAL STATE
// ============================================================================
hook_socket_slot_t g_socket_slot = {0};

// ============================================================================
// SOCKET STATIC STATE
// ============================================================================
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

  // [1]="t", tokens[2]=<TYPE>
  if (!jsmn_eq(js, &tokens[1], "t"))
    return 0;
  if (tokens[2].end - tokens[2].start != 1)
    return 0;
  req->type = js[tokens[2].start];

  // [3]="c", tokens[4]=<COMMAND>
  if (r < 5 || !jsmn_eq(js, &tokens[3], "c"))
    return 0;
  jsmn_copy(js, &tokens[4], req->cmd, CMD_MAX_CHARS);

  // [5]="a", tokens[6]=<ARRAY> (optional)
  if (r >= 7 && jsmn_eq(js, &tokens[5], "a") && tokens[6].type == JSMN_ARRAY) {
    int arr_size = tokens[6].size;
    for (int k = 0; k < arr_size && k < MAX_ARGS; k++) {
      jsmn_copy(js, &tokens[7 + k], req->args[k], ARG_MAX_CHARS);
      req->argc++;
    }
  }
  return req->type != 0;
}

// ============================================================================
// SOCKET HANDLER
// ============================================================================
static void handle_client(int client_fd) {
  // Single recv is sufficient for small requests
  char buf[RECV_BUF_BYTES];
  ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
  if (n <= 0) {
    goto done;
  }
  buf[n] = '\0';

  // Strip trailing newline if present
  if (n > 0 && buf[n - 1] == '\n')
    buf[--n] = '\0';

  hook_socket_request_t req;
  if (!parse_request(buf, (size_t)n, &req)) {
    SEND_OR_LOG(client_fd, "{\"ok\":false,\"e\":\"invalid JSON\"}\n");
    goto done;
  }

  // Status query
  // Answered directly on the socket thread, no game thread needed
  if (req.type == 'S') {
    int busy =  (!hook_engine_get() || is_server_busy());
    const char *resp = busy ? "{\"ready\":false}\n" : "{\"ready\":true}\n";
    SEND_PTR_OR_LOG(client_fd, resp);
    goto done;
  }

  // Game command
  // Hand off to the game thread via the slot
  if (req.type == 'X') {
    if (!hook_engine_get() || is_server_busy()) {
      SEND_OR_LOG(client_fd, "{\"ok\":false,\"e\":\"busy\"}\n");
      goto done;
    }

    pthread_mutex_lock(&g_socket_slot.mutex);
    memcpy(&g_socket_slot.req, &req, sizeof(req));
    g_socket_slot.cmd_ready = 1;
    g_socket_slot.resp_ready = 0;
    pthread_cond_signal(&g_socket_slot.cmd_cond);

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
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

    // Copy response while still holding mutex, then release
    // RESP_MAX_BYTES + 1: the +1 is for the '\n' appended after the
    // JSON body. Without it, response_copy[len+1] writes one byte
    // past the end when len == RESP_MAX_BYTES - 1
    char response_copy[RESP_MAX_BYTES + 1];
    memcpy(response_copy, g_socket_slot.response, RESP_MAX_BYTES - 1);
    response_copy[RESP_MAX_BYTES - 1] = '\0';
    pthread_mutex_unlock(&g_socket_slot.mutex);

    if (timed_out) {
      SEND_OR_LOG(client_fd, "{\"ok\":false,\"e\":\"timeout\"}\n");
      goto done;
    }

    size_t len = strlen(response_copy);
    response_copy[len] = '\n';
    response_copy[len + 1] = '\0';
    SEND_PTR_OR_LOG(client_fd, response_copy);
    goto done;
  }
  SEND_OR_LOG(client_fd, "{\"ok\":false,\"e\":\"unknown type\"}\n");

done:
  close(client_fd);
}

// ============================================================================
// SOCKET RESPONSE
// ============================================================================
void hook_socket_finish_json(json_buf_t *jb) {
  pthread_mutex_lock(&g_socket_slot.mutex);
  if (jb->overflow)
    memcpy(g_socket_slot.response, "{\"ok\":false,\"e\":\"response overflow\"}",
           sizeof("{\"ok\":false,\"e\":\"response overflow\"}"));
  else {
    memcpy(g_socket_slot.response, jb->buf, RESP_MAX_BYTES - 1);
    g_socket_slot.response[RESP_MAX_BYTES - 1] = '\0';
  }
  g_socket_slot.cmd_ready = 0;
  g_socket_slot.resp_ready = 1;
  pthread_cond_signal(&g_socket_slot.resp_cond);
  pthread_mutex_unlock(&g_socket_slot.mutex);
}

void hook_socket_finish_ok(void) {
  json_buf_t jb;
  jb_init(&jb);
  jb_raw(&jb, "{\"ok\":true}");
  hook_socket_finish_json(&jb);
}

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
static void *socket_thread(void *arg) {
  (void)arg;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  memcpy(addr.sun_path, g_config.socket_path, sizeof(addr.sun_path) - 1);

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
    handle_client(client_fd);
  }
  return NULL;
}

// ============================================================================
// SOCKET
// ============================================================================
void hook_socket_start(void) {
  hook_socket_stop();

  server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_fd < 0) {
    hook_log_error("socket() failed: %s\n", strerror(errno));
    return;
  }

  pthread_mutex_init(&g_socket_slot.mutex, NULL);
  pthread_cond_init(&g_socket_slot.cmd_cond, NULL);
  pthread_cond_init(&g_socket_slot.resp_cond, NULL);
  slot_initialised = 1;
  g_socket_slot.cmd_ready = 0;
  g_socket_slot.resp_ready = 0;

  pthread_t t;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  pthread_create(&t, &attr, socket_thread, NULL);
  pthread_attr_destroy(&attr);
}

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
    slot_initialised = 0;
  }

  if (server_fd >= 0) {
    close(server_fd);
    server_fd = -1;
  }
  unlink(g_config.socket_path);
}

int hook_socket_poll(void) {
  if (pthread_mutex_trylock(&g_socket_slot.mutex) != 0)
    return 0;

  int ready = g_socket_slot.cmd_ready;
  pthread_mutex_unlock(&g_socket_slot.mutex);
  return ready;
}