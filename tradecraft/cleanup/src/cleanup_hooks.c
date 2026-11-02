#include <windows.h>

DECLSPEC_IMPORT VOID WINAPI KERNEL32$ExitThread( DWORD );

extern void cleanupMemory( );

VOID WINAPI _ExitThread_Cleanup( DWORD dwExitCode )
{
    cleanupMemory( );
    KERNEL32$ExitThread( dwExitCode );
}
