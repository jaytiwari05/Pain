#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

// This handles the Parsing the Data that comes from C2 Server

// New: copy the incoming buffer onto the agent heap and set the cursor to the start
DECLFN void Psr_New( PPARSER psr, PVOID buf, UINT32 size )
{
    psr->Original = (PCHAR)Heap_Alloc( size );
    if ( !psr->Original ) return;

    Mem_Copy( psr->Original, buf, size );

    psr->Buffer = psr->Original;  // cursor starts at the beginning
    psr->Size   = size;
    psr->Length = size;           // all bytes are unread at this point
}

// Pad: skip 'size' bytes (advance cursor without reading the data)
// used to skip fixed-size headers like the 36-byte AgentID
DECLFN void Psr_Pad( PPARSER psr, UINT32 size )
{
    if ( psr->Length < size ) return;

    psr->Buffer += size;
    psr->Length -= size;
}

// Int32: read 4 bytes big-endian from the cursor and advance it
DECLFN INT32 Psr_Int32( PPARSER psr )
{
    if ( psr->Length < 4 ) return 0;

    BYTE* b = (BYTE*)psr->Buffer;

    INT32 val = ( (UINT32)b[0] << 24 )
              | ( (UINT32)b[1] << 16 )
              | ( (UINT32)b[2] <<  8 )
              | ( (UINT32)b[3]       );

    psr->Buffer += 4;
    psr->Length -= 4;

    return val;
}

// Bytes: read a length-prefixed blob - reads the 4-byte length then returns
// a pointer directly into the buffer (caller must not free this pointer)
DECLFN PBYTE Psr_Bytes( PPARSER psr, UINT32 *out_size )
{
    if ( psr->Length < 4 ) return nullptr;

    UINT32 size = (UINT32)Psr_Int32( psr );  // reads 4 bytes + advances cursor

    if ( psr->Length < size ) return nullptr;

    PBYTE data = (PBYTE)psr->Buffer;

    psr->Buffer += size;
    psr->Length -= size;

    if ( out_size ) *out_size = size;

    return data;
}

// Str: read a length-prefixed string - same as Bytes but returns PCHAR
DECLFN PCHAR Psr_Str( PPARSER psr, UINT32 *out_size )
{
    return (PCHAR)Psr_Bytes( psr, out_size );
}

// Destroy: free the buffer we copied in Psr_New and zero all fields
DECLFN void Psr_Destroy( PPARSER psr )
{
    if ( !psr ) return;

    if ( psr->Original ) {
        Heap_Free( psr->Original );
        psr->Original = nullptr;
        psr->Buffer   = nullptr;
        psr->Length   = 0;
    }
}
