#include <dlfcn.h>
#include <signal.h>

#include "hook_config.h"
#include "hook_log.h"
#include "hook_socket.h"
#include "hook_trampoline.h"
#include "kfds_hook.h"

// ============================================================================
// KFDS_HOOK STATIC STATE
// ============================================================================
static _Atomic int hook_detached = 0;
static struct sigaction old_sigint;
static struct sigaction old_sigterm;

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
  hook_log_info("kfds_hook loaded (r%s)\n", HOOK_REVISION);

  if (!g_config.hook_enabled) {
    hook_log_warn("hook_enabled=0, skipping hook installation\n");
    return;
  }

  hook_socket_start();
  hook_install_trampoline();

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