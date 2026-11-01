#ifndef HASH_H
#define HASH_H

#include <stdint.h>

// namespace is used for having Hash::Str to avoid conflict
namespace Hash
{
    // String hashing for Simple ASCII strings
    constexpr uint32_t Str( const char* str )
    {
        uint32_t hash = 0x811c9dc5; // FNV [Fowler–Noll–Vo] offset basis
        uint8_t byte    = 0;

        while ( *str )
        {
            byte = (uint8_t)( *str++ );

            // make case-insensitive: uppercase the byte before hashing
            if( byte >= 'a') byte -= 0x20;

            // FNV-1a: XOR then multiply
            hash ^= byte;
            hash *= 0x01000193; // FNV prime - the multiplier that spreads bits after each XOR
        }

        return hash ;
    }

    // wide version - used for module names in PEB (wchar_t)
    constexpr uint32_t Str( const wchar_t* str )
    {
        uint32_t hash   = 0x811c9dc5; // FNV [Fowler–Noll–Vo] offset basis
        uint8_t byte    = 0;

        while ( *str )
        {
            byte    = (uint8_t)( *str++ );

            if (byte >= 'a') byte -= 0x20;

            hash ^= byte;
            hash *= 0x01000193;
        }
        
        return hash;

    }
}

#endif // HASH_H