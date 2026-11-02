#ifndef BOF_H
#define BOF_H

#include <windows.h>

// Read/write N bytes at an address as a typed integer (for relocation patching)
#define BOF_DEF32(x) (*(INT32*)(x))
#define BOF_DEF64(x) (*(INT64*)(x))

// Round a size up to the nearest 4KB page boundary
#define BOF_PAGE_ALIGN(x) (((ULONG_PTR)(x) + 0xFFF) & ~(ULONG_PTR)0xFFF)

// ISFCN: true when the COFF Type field's high nibble encodes DT_FCN (=2)
// Format: bits[7:4] = derived type, bits[3:0] = base type
#ifndef ISFCN
#define ISFCN(x) (((x) & 0x00F0) == 0x0020)
#endif

// AMD64 relocation types (may not be defined on all MinGW versions)
#ifndef IMAGE_REL_AMD64_ADDR64
#define IMAGE_REL_AMD64_ADDR64   0x0001   // 64-bit absolute address
#endif
#ifndef IMAGE_REL_AMD64_REL32
#define IMAGE_REL_AMD64_REL32    0x0004   // 32-bit relative (from next instruction)
#define IMAGE_REL_AMD64_REL32_1  0x0005   // REL32 with -1 addend
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009
#endif

// How we classify a symbol after parsing the COFF table
#define COFF_SYM_UNKNOWN  0x00
#define COFF_SYM_IMP      0x01  // "__imp_" prefix: external import - Win32 or Beacon API
#define COFF_SYM_FNC      0x02  // function defined in this object file
#define COFF_SYM_VAR      0x03  // variable defined in this object file

// Per-section record: where the section's raw data landed in memory
struct BOF_SECTION {
    PVOID Base;  // pointer into the allocated memory block
    ULONG Size;  // SizeOfRawData from IMAGE_SECTION_HEADER
};

// Per-symbol record: resolved address (for imports) or in-section offset (for code/data)
struct BOF_SYMBOL {
    PCHAR   Name;          // pointer into the COFF string data - NOT heap-owned, valid while buf lives
    UINT32  Hash;          // FNV-1a of Name (same algorithm as Pain's Hash::Str - case-insensitive)
    PVOID   Ptr;           // COFF_SYM_IMP: resolved Win32 or Beacon API function pointer
    ULONG   Rva;           // COFF_SYM_FNC/VAR: byte offset of symbol within its section
    INT16   SectionNumber; // 1-based section index (from IMAGE_SYMBOL.SectionNumber)
    UINT8   Type;          // COFF_SYM_IMP / COFF_SYM_FNC / COFF_SYM_VAR
};

// A fully loaded COFF ready to execute
struct BOF_MAPPED {
    PVOID        MmBase;      // base of the single RW allocation (sections + import table)
    ULONG        MmSize;      // total size of that allocation
    PVOID        EntryPoint;  // address of the 'go(char* args, int argc)' function
    BOF_SECTION* Sections;    // heap-allocated array [SecCount]
    BOF_SYMBOL*  Symbols;     // heap-allocated array [SymCount]
    ULONG        SecCount;
    ULONG        SymCount;
};

// datap: argument parser used by BeaconDataXxx
struct datap {
    PCHAR Original; // start of the buffer (reference only)
    PCHAR Buffer;   // current read cursor
    INT   Length;   // bytes remaining from cursor to end
    INT   Size;     // total buffer size
};

// fmt: incremental output builder used by BeaconFormatXxx
struct fmt {
    PCHAR Original; // start of the heap allocation
    PCHAR Buffer;   // current write cursor
    INT   Length;   // bytes remaining (Cap - written)
    INT   Size;     // total capacity
};

// ApiTable entry: maps a Beacon API function name hash to its address in Pain's .text
struct BEACON_API_ENTRY {
    UINT32 Hash;
    PVOID  Ptr;
};

// Public API

// Parse a COFF .o buffer into memory. Returns TRUE on success.
BOOL Bof_Map    ( BYTE* buf, ULONG size, BOF_MAPPED* out );

// Call the 'go' entrypoint of a mapped COFF. Returns TRUE on success.
BOOL Bof_Execute( BOF_MAPPED* mapped, BYTE* args, ULONG argc );

// Free all memory associated with a mapped COFF.
VOID Bof_Unmap  ( BOF_MAPPED* mapped );

// One-shot: Map → Execute → Unmap.
BOOL Bof_Loader ( BYTE* buf, ULONG size, BYTE* args, ULONG argc );

// Resolve an __imp_ symbol name to a function pointer.
// Called internally by Bof_Map during the symbol pass.
PVOID Bof_RslApi ( PCHAR sym_name );

// Resolve a "BeaconXxx" or "AxXxx" symbol name.
// Stub in Block 2; real implementation added in BeaconApi.cc (Block 3 / 4).
PVOID Bof_RslBeaconApi( PCHAR name );

#endif // BOF_H
