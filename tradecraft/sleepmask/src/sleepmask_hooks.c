#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep( DWORD );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc( HANDLE, DWORD, SIZE_T );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc( HANDLE, DWORD, LPVOID, SIZE_T );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree( HANDLE, DWORD, LPVOID );
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$ExitThread( DWORD );

extern void maskMemory( BOOL );
extern void addHeapRecord( PVOID, SIZE_T );
extern void updateHeapRecord( PVOID, PVOID, SIZE_T );
extern void removeHeapRecord( PVOID );

VOID WINAPI _Sleep_Mask( DWORD dwMilliseconds )
{
    maskMemory( TRUE );
    KERNEL32$Sleep( dwMilliseconds );
    maskMemory( FALSE );
}

LPVOID WINAPI _HeapAlloc_Mask( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes )
{
    LPVOID ptr = KERNEL32$HeapAlloc( hHeap, dwFlags, dwBytes );

    if ( ptr != NULL ) {
        addHeapRecord( ptr, dwBytes );
    }

    return ptr;
}

LPVOID WINAPI _HeapReAlloc_Mask( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes )
{
    LPVOID new_ptr = KERNEL32$HeapReAlloc( hHeap, dwFlags, lpMem, dwBytes );

    if ( new_ptr != NULL ) {
        updateHeapRecord( lpMem, new_ptr, dwBytes );
    }

    return new_ptr;
}

BOOL WINAPI _HeapFree_Mask( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem )
{
    BOOL result = KERNEL32$HeapFree( hHeap, dwFlags, lpMem );

    if ( result ) {
        removeHeapRecord( lpMem );
    }

    return result;
}

VOID WINAPI _ExitThread_Mask( DWORD dwExitCode )
{
    maskMemory(TRUE);
    KERNEL32$ExitThread(dwExitCode);
}
