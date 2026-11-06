#ifndef DEFINES_H
#define DEFINES_H

#include <windows.h>
#include <LdrLoad.h>

// Forces every function/data into the .text$B section (shellcode blob)
#define DECLFN __attribute__((section(".text$B")))

// Use DECLFN_CODE in a TU that also has DECLFN *data* - placing a function in .text$B
// alongside data causes a COFF section-type conflict (data vs code flags on same section).
// .text$BC is a sibling section included by the linker script; same shellcode, no conflict.
#define DECLFN_CODE __attribute__((section(".text$BC")))

// Casting helpers this avoids verbose reinterpret_cast everywhere
#define U_PTR(x)    reinterpret_cast<ULONG_PTR>(x)
#define B_PTR(x)    reinterpret_cast<BYTE*>(x)
#define A_PTR(x)    reinterpret_cast<PCHAR>(x)
#define W_PTR(x)    reinterpret_cast<PWCHAR>(x)

extern "C" ULONG_PTR StartPtr();
#define G_SYM(x)    (ULONG_PTR)( StartPtr() - ( (ULONG_PTR)&StartPtr - (ULONG_PTR)(x) ) )

// placement new - not available without <new>, so declare it manually
inline void* operator new( unsigned long long, void* ptr ) noexcept { return ptr; }

// memcpy replacement - compiler may emit a call to memcpy for __builtin_memcpy
// with variable sizes, and we have no stdlib. use a plain byte loop instead.
static inline void Mem_Copy( void* dst, const void* src, unsigned long long n )
{
    char* d = (char*)dst;
    const char* s = (const char*)src;
    while ( n-- ) *d++ = *s++;
}

static inline void Mem_Set( void* dst, unsigned char val, unsigned long long n )
{
    unsigned char* d = (unsigned char*)dst;
    while ( n-- ) *d++ = val;
}

// Resolve Imports
#define RSL_IMP(module) {                                               \
    auto* slots = (ULONG_PTR*)&(module);                               \
    ULONG count = sizeof(module) / sizeof(ULONG_PTR);                  \
    for ( ULONG i = 1; i < count; i++ ) {                              \
        if ( slots[i] )                                                \
            slots[i] = LdrLoad::_Api( slots[0], (uint32_t)slots[i] ); \
    }                                                                  \
}

#endif // DEFINES_H