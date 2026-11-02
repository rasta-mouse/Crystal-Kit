#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT HMODULE   WINAPI  KERNEL32$LoadLibraryW( LPCWSTR );
DECLSPEC_IMPORT HMODULE   WINAPI  KERNEL32$LoadLibraryExW( LPCWSTR, HANDLE, DWORD );
DECLSPEC_IMPORT int       WINAPIV MSVCRT$wcscmp( const wchar_t*, const wchar_t* );
DECLSPEC_IMPORT wchar_t*  WINAPIV MSVCRT$wcsstr( const wchar_t*, const wchar_t* );

extern void hookModule( HMODULE hModule, DWORD targetHash, PVOID targetHook );

DWORD __ror13_LoadLibraryExW( );

HMODULE WINAPI _LoadLibraryExW_Hook( LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags )
{
    HMODULE hModule = KERNEL32$LoadLibraryExW( lpLibFileName, hFile, dwFlags );

    /**
     * what was loaded? for postex, like invokeassembly.dll, we need to check if this was mscoreei.dll.
     * if it was, we need to hook LoadLibraryExW to catch the load for clr.dll
     */
    if ( MSVCRT$wcsstr( lpLibFileName, L"mscoreei.dll" ) != NULL ) {
        hookModule( hModule, __ror13_LoadLibraryExW( ), ( PVOID )( _LoadLibraryExW_Hook ));
    }

    return hModule;
}

HMODULE WINAPI _LoadLibraryW_Hook( LPCWSTR lpLibFileName )
{
    HMODULE hModule = KERNEL32$LoadLibraryW( lpLibFileName );

    /**
     * what was loaded? for postex, like invokeassembly.dll, we need to check if this was mscoree.dll.
     * if it was, we need to hook LoadLibraryExW to catch the loads for mscoreei.dll.
     */
    if ( MSVCRT$wcscmp( lpLibFileName, L"mscoree.dll" ) == 0 ) {
        hookModule( hModule, __ror13_LoadLibraryExW( ), ( PVOID )( _LoadLibraryExW_Hook ));
    }

    return hModule;
}
