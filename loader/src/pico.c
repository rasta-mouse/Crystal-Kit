#include <windows.h>
#include "bud.h"
#include "tcg.h"

PALLOCATED_MEMORY g_memory;

FARPROC WINAPI _GetProcAddress( HMODULE hModule, LPCSTR lpProcName )
{
    if ( IS_INTRESOURCE( lpProcName ) ) {
        return GetProcAddress( hModule, lpProcName );
    }

    FARPROC result = __resolve_hook( ror13hash( lpProcName ));

    if ( result != NULL ) {
        return result;
    }
    
    return GetProcAddress( hModule, lpProcName );
}

void go( IMPORTFUNCS* funcs ) {
    funcs->GetProcAddress = ( __typeof__( GetProcAddress ) * )( _GetProcAddress );
}
