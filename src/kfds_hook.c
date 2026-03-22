#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "hook_config.h"
#include "hook_log.h"
#include "hook_security.h"
#include "hook_socket.h"
#include "hook_trampoline.h"
#include "kfds_hook.h"

#ifdef DEBUG
  #define BUILD_VARIANT "_debug"
#else
  #define BUILD_VARIANT ""
#endif

// ============================================================================
// KFDS_HOOK STATIC STATE
// ============================================================================
static _Atomic int hook_detached = 0;
static struct sigaction old_sigint;
static struct sigaction old_sigterm;

// ============================================================================
// HEARTBEAT
// ============================================================================
/*
 * Emits a periodic log line at info level.
 * Interval is controlled by g_config.heartbeat_interval (seconds).
 * Detached, no cleanup needed on shutdown, _exit() reaps it immediately.
 */
static void *heartbeat_thread(void *arg) {
  (void)arg;
  while (1) {
    sleep((unsigned int)g_config.heartbeat_interval);
    hook_log_info("<HEARTBEAT>\n");
  }
  return NULL;
}

// ============================================================================
// KFDS_HOOK
// ============================================================================
static void hook_signal_handler(int sig);

/*
 * Loaded via LD_PRELOAD, before main()
 */
__attribute__((constructor)) static void hook_attach(void) {
  struct sigaction sa = {0};
  sa.sa_handler = hook_signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART; // avoids interrupting slow syscalls

  sigaction(SIGINT, &sa, &old_sigint);
  sigaction(SIGTERM, &sa, &old_sigterm);

  hook_load_config();
  hook_log_info("kfds_hook loaded (r%s%s)\n", HOOK_REVISION, BUILD_VARIANT);

  if (!g_config.hook_enabled) {
    hook_log_warn("hook_enabled=0, skipping hook installation\n");
    return;
  }

  // Security patch first: modifies the binary's integrity check before
  // the trampoline installs
  if (g_config.security_patch)
    hook_security_patch();

  hook_socket_start();
  hook_trampoline_install();

  // Start heartbeat thread if configured
  if (g_config.heartbeat_interval > 0) {
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, heartbeat_thread, NULL) != 0)
      hook_log_warn("heartbeat: pthread_create failed\n");
    pthread_attr_destroy(&attr);
  }

  hook_log_info("kfds_hook init complete\n");
}

__attribute__((destructor)) static void hook_detach(void) {
  if (hook_detached)
    return;
  hook_detached = 1;

  hook_socket_stop();
  hook_log_info("kfds_hook unloaded\n");
  hook_log_close();

  // Restore the original handlers
  sigaction(SIGINT, &old_sigint, NULL);
  sigaction(SIGTERM, &old_sigterm, NULL);
}

__attribute__((noreturn)) void _exit(int status) {
  hook_detach();
  void (*real__exit)(int) = dlsym(RTLD_NEXT, "_exit");
  real__exit(status);
  __builtin_unreachable();
}

static void hook_signal_handler(int sig) {
  hook_detach();
  // Chain to the original handler so the server exits normally
  if (sig == SIGINT && old_sigint.sa_handler)
    old_sigint.sa_handler(sig);
  if (sig == SIGTERM && old_sigterm.sa_handler)
    old_sigterm.sa_handler(sig);
}