#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

// XOR a buffer in-place with a repeating 8-byte key
// Same key bytes cycle: buf[i] ^= key_byte[ i % 8 ]
DECLFN void Crypt_Xor( PVOID buf, SIZE_T size, ULONG_PTR key )
{
    BYTE* data      = (BYTE*)buf;
    BYTE* key_ptr   = (BYTE*)&key;

    for ( SIZE_T i= 0; i < size; i++ )
    {
        data[i] ^= key_ptr[ i % sizeof(ULONG_PTR) ];
    }
}

// XOR a buffer in-place with an arbitrary-length repeating key (e.g. 16-byte auth key)
DECLFN void Crypt_XorKey( PVOID buf, SIZE_T size, PBYTE key, SIZE_T key_len )
{
    if ( !key || !key_len ) return;
    BYTE* data = (BYTE*)buf;
    for ( SIZE_T i = 0; i < size; i++ )
        data[i] ^= key[ i % key_len ];
}