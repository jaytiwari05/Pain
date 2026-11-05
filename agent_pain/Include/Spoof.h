#ifndef SPOOF_H
#define SPOOF_H

// Default to enabled; override with -DPAIN_STACK_SPOOF=0 to compile out
#ifndef PAIN_STACK_SPOOF
#define PAIN_STACK_SPOOF 1
#endif

#include <windows.h>
#include <stddef.h>

// Two-field frame descriptor: a planted return address + the frame's allocation size.
struct SpoofFrame {
    ULONG_PTR Ptr;   // planted as return address in the fake call chain
    ULONG_PTR Size;  // frame size from UNWIND_INFO (how many bytes sub rsp allocated)
};

// SpoofSetup - field offsets are hardcoded in Spoof.x64.asm.
// The layout must NEVER be changed without updating the asm.
// Compile-time asserts below verify every critical offset.
struct SpoofSetup {
    SpoofFrame  First;      // 0x00/0x08 - RtlUserThreadStart+0x21
    SpoofFrame  Second;     // 0x10/0x18 - BaseThreadInitThunk+0x14
    SpoofFrame  Gadget;     // 0x20/0x28 - jmp [rbx] gadget in kernel32
    ULONG_PTR   _pad;       // 0x30      - padding to push Ssn to 0x38
    ULONG_PTR   Ssn;        // 0x38      - syscall number (0 for plain WinAPI)
    ULONG_PTR   RealRet;    // 0x40      - real return address (written by ASM)
    ULONG_PTR   OldRbx;     // 0x48
    ULONG_PTR   OldRdi;     // 0x50
    ULONG_PTR   OldRsi;     // 0x58
    ULONG_PTR   OldR12;     // 0x60
    ULONG_PTR   OldR13;     // 0x68
    ULONG_PTR   OldR14;     // 0x70
    ULONG_PTR   OldR15;     // 0x78
    ULONG_PTR   ArgCount;    // 0x80      - total stack args (always 12)
    // Sleep-time frame sizes: same as First/Second/Gadget.Size minus the +0x20 SpoofCall
    // padding. These match what the REAL stack walker reads from UNWIND_INFO.
    ULONG_PTR   SleepFsFirst;  // 0x88
    ULONG_PTR   SleepFsSecond; // 0x90
    ULONG_PTR   SleepFsGadget; // 0x98
};

static_assert(offsetof(SpoofSetup, First.Ptr)   == 0x00, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, First.Size)  == 0x08, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, Second.Ptr)  == 0x10, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, Second.Size) == 0x18, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, Gadget.Ptr)  == 0x20, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, Gadget.Size) == 0x28, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, Ssn)         == 0x38, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, RealRet)     == 0x40, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, OldRbx)      == 0x48, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, OldRdi)      == 0x50, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, OldRsi)      == 0x58, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, OldR12)      == 0x60, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, OldR13)      == 0x68, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, OldR14)      == 0x70, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, OldR15)      == 0x78, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, ArgCount)      == 0x80, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, SleepFsFirst)  == 0x88, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, SleepFsSecond) == 0x90, "SpoofSetup offset mismatch");
static_assert(offsetof(SpoofSetup, SleepFsGadget) == 0x98, "SpoofSetup offset mismatch");

// ASM entry point (Spoof.x64.asm)
extern "C" ULONG_PTR SpoofCall( ... );

// C++ wrappers (Frame.cc)
void      Spoof_Init();
ULONG_PTR Spoof_Call(
    ULONG_PTR Fnc, ULONG_PTR Ssn,
    ULONG_PTR a1  = 0, ULONG_PTR a2  = 0, ULONG_PTR a3  = 0, ULONG_PTR a4  = 0,
    ULONG_PTR a5  = 0, ULONG_PTR a6  = 0, ULONG_PTR a7  = 0, ULONG_PTR a8  = 0,
    ULONG_PTR a9  = 0, ULONG_PTR a10 = 0, ULONG_PTR a11 = 0, ULONG_PTR a12 = 0
);

#endif // SPOOF_H
