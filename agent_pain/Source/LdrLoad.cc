#include <windows.h>
#include <stdint.h>
#include <intrin.h>
#include <Native.h>
#include <Hash.h>
#include <LdrLoad.h>

namespace LdrLoad
{
    auto Module( uint32_t hash ) -> ULONG_PTR
    {
        // get PEB via gs:[60]
        PAIN_PEB* peb = NtCurrentPeb();

        //InLoadOrderModuleList is a circular doubly-linked list
        // head is the anchor - whne current loop back to head we are done
        LIST_ENTRY* head = &peb->Ldr->InLoadOrderModuleList;
        LIST_ENTRY* curr = head->Flink;

        while ( curr != head )
        {
            // curr points to InLoadOrderLinks which is the FIRST field 
            // LDR_DATA_TABLE_ENTRY so casting directly is safe
            auto* entry = (LDR_DATA_TABLE_ENTRY*)curr;

            // BaseDllName.Buffer is wchar_t* - use the wide hash version
            if ( entry->BaseDllName.Buffer )
            {
                if (Hash::Str( entry->BaseDllName.Buffer ) == hash )
                {
                    return (ULONG_PTR)entry->DllBase; // Found - return base address
                }
            }
            
            curr = curr->Flink; // move to next DLL in the list
        }

        return 0;
    }

    auto _Api( ULONG_PTR module_base, uint32_t hash ) -> ULONG_PTR
    {
        if ( !module_base ) return 0;

        // DOS header sits at the very start of every PE file
        // e_lfanew tells us where the NT headers begin
        auto* dos = (IMAGE_DOS_HEADER*)module_base;
        auto* nt = (IMAGE_NT_HEADERS*)( module_base + dos->e_lfanew );

        // DataDirectory[0] = export directory, VirtualAddress is an RVA
        DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        if ( !export_rva ) return 0; // DLL has no Exports

        auto* exp = (IMAGE_EXPORT_DIRECTORY*)( module_base + export_rva );

        // three parallel arrays - all values are RVAs, add module_base to resolve
        auto* names = (DWORD*)( module_base + exp->AddressOfNames );
        auto* ordinals = (WORD*)( module_base + exp->AddressOfNameOrdinals );
        auto* functions = (DWORD*)( module_base + exp->AddressOfFunctions );

        for ( DWORD i = 0; i < exp->NumberOfNames; i++)
        {
            // names[i] is an RVA to the ASCII function name string
            const char* name = (const char*)(module_base + names[i]);

            if ( Hash::Str ( name ) == hash)
            {
                // ordinals[i] indexes into the functions array
                return module_base + functions[ ordinals[i] ];
            }
        }

        return 0; // export not found
    }
}