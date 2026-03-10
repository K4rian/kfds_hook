#ifndef HOOK_TRAMPOLINE_H
#define HOOK_TRAMPOLINE_H

// ============================================================================
// TRAMPOLINE
// ============================================================================
void hook_install_trampoline(void);

// ============================================================================
// HOOKED FUNCTIONS
// ============================================================================
void hooked_Tick(void *self, float delta_seconds);

#endif /* HOOK_TRAMPOLINE_H */