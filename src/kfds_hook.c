#include <dlfcn.h>
#include <signal.h>

#include "hook_config.h"
#include "hook_log.h"
#include "hook_trampoline.h"
#include "kfds_hook.h"

// ============================================================================
//  ENTRYPOINT
// ============================================================================
static void hook_signal_handler(int sig);

static struct sigaction g_old_sigint;
static struct sigaction g_old_sigterm;

static _Atomic int g_detached = 0;

/*
 * Loaded via LD_PRELOAD, before main()
 */
__attribute__((constructor)) static void hook_attach(void) {
  struct sigaction sa = {0};
  sa.sa_handler = hook_signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART; // avoids interrupting slow syscalls

  sigaction(SIGINT, &sa, &g_old_sigint);
  sigaction(SIGTERM, &sa, &g_old_sigterm);

  hook_load_config();
  hook_log(HOOK_LOG_LEVEL_ALL, "kfds_hook loaded (v%s)\n", HOOK_REVISION);

  // if (!g_config.hook_enabled) {
  //     hook_log(HOOK_LOG_LEVEL_ERRORS, "hook_enabled=0, skipping hook
  //     installation\n"); return;
  // }

  // TODO: socket

  hook_install_trampoline();

  // TODO: pthread

  hook_log(HOOK_LOG_LEVEL_ALL, "kfds_hook init complete\n");
}

__attribute__((destructor)) static void hook_detach(void) {
  if (g_detached)
    return;
  g_detached = 1;

  hook_log(HOOK_LOG_LEVEL_ALL, "kfds_hook unloaded\n");
  hook_log_close();

  // Restore the original handlers
  sigaction(SIGINT, &g_old_sigint, NULL);
  sigaction(SIGTERM, &g_old_sigterm, NULL);
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
  if (sig == SIGINT && g_old_sigint.sa_handler)
    g_old_sigint.sa_handler(sig);
  if (sig == SIGTERM && g_old_sigterm.sa_handler)
    g_old_sigterm.sa_handler(sig);
}