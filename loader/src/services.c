#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA( LPCSTR );

__typeof__ ( GetModuleHandleA ) * getModuleHandle __attribute__(( section( ".text" )));
__typeof__ ( GetProcAddress   ) * getProcAddress  __attribute__(( section( ".text" )));

FARPROC resolve( DWORD mod_hash, DWORD func_hash )
{
    HANDLE hModule = findModuleByHash( mod_hash );
    return findFunctionByHash( hModule, func_hash );
}

FARPROC resolve_ext( char* mod_name, char* func_name )
{
    HANDLE hModule = KERNEL32$GetModuleHandleA( mod_name );

    if ( hModule == NULL ) {
        hModule = LoadLibraryA( mod_name );
    }
 
    return GetProcAddress( hModule, func_name );
}

FARPROC resolve_smart( char* mod_name, char* func_name )
{
    HANDLE hModule = getModuleHandle( mod_name );

    if ( hModule == NULL ) {
        hModule = LoadLibraryA( mod_name );
    }

    return getProcAddress( hModule, func_name );
}
