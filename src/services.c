#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA ( LPCSTR );

__typeof__ ( GetModuleHandle ) * get_module_handle __attribute__ ( ( section ( ".text" ) ) );
__typeof__ ( GetProcAddress )  * get_proc_address  __attribute__ ( ( section ( ".text" ) ) );

FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
    HANDLE module = findModuleByHash ( mod_hash );
    return findFunctionByHash ( module, func_hash );
}

FARPROC resolve_ext ( char * mod_name, char * func_name )
{
    HANDLE module = KERNEL32$GetModuleHandleA ( mod_name );
    
    if ( module == NULL ) {
        module = LoadLibraryA ( mod_name );
    }
 
    return GetProcAddress ( module, func_name );
}

FARPROC resolve_patch ( char * mod_name, char * func_name )
{
    HANDLE module = get_module_handle ( mod_name );
    return get_proc_address ( module, func_name );
}