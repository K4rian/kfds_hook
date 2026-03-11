#ifndef HOOK_SOCKET_DEFS_H
#define HOOK_SOCKET_DEFS_H

// ============================================================================
// SOCKET SHARED DEFINES
// ============================================================================
#define RECV_BUF_BYTES 4096 // max incoming command size
#define RESP_MAX_BYTES 8192 // max outgoing response size
#define MAX_ARGS 8          // max command arguments
#define ARG_MAX_CHARS 1024  // max UTF-8 chars per argument
#define CMD_MAX_CHARS 64    // max command name length

#endif /* HOOK_SOCKET_DEFS_H */