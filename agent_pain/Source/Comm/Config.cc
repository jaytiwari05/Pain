#include <windows.h>
#include <Agent.h>
#include <Defines.h>

// Default C2 config baked at compile time.
// Override via Makefile: make PAIN_C2_HOST='"10.0.0.1"' PAIN_C2_PORT=443
// All arrays live in .text$B (DECLFN) so they survive the linker script.
// Access them at runtime with G_SYM(g_C2Host) etc. - never use the raw symbol name.

#ifndef PAIN_C2_HOST
#define PAIN_C2_HOST "127.0.0.1"
#endif

#ifndef PAIN_C2_PORT
#define PAIN_C2_PORT 8080
#endif

#ifndef PAIN_SLEEP
#define PAIN_SLEEP 5
#endif

#ifndef PAIN_JITTER
#define PAIN_JITTER 0
#endif

#ifndef PAIN_C2_SSL
#define PAIN_C2_SSL 0
#endif

#ifndef PAIN_AGENT_UUID
#define PAIN_AGENT_UUID "00000000-0000-0000-0000-000000000001"
#endif

#ifndef PAIN_USER_AGENT
#define PAIN_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#endif

DECLFN char g_C2Host[]  = PAIN_C2_HOST;
DECLFN char g_UserAgent[]  = PAIN_USER_AGENT;
DECLFN char g_AgentUUID[]  = PAIN_AGENT_UUID;
DECLFN char g_WininetDll[]  = "wininet.dll";

struct PAIN_BUILD_CFG_T {
    UINT16 Port;
    ULONG  Sleep;
    ULONG  Jitter;
    BOOL   Ssl;
};

DECLFN PAIN_BUILD_CFG_T g_BuildCfg = {
    .Port   = PAIN_C2_PORT,
    .Sleep  = PAIN_SLEEP,
    .Jitter = PAIN_JITTER,
    .Ssl    = PAIN_C2_SSL,
};
