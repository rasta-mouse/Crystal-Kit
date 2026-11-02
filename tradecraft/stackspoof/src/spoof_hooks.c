#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <combaseapi.h>
#include <windns.h>
#include "spoof.h"
#include "tcg.h"

DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$AdjustTokenPrivileges( HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD );
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$DuplicateTokenEx( HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE );
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$ImpersonateLoggedOnUser( HANDLE );
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$ImpersonateNamedPipeClient( HANDLE );
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$LogonUserA( LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE );
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$OpenProcessToken( HANDLE, DWORD, PHANDLE );
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$OpenThreadToken( HANDLE, DWORD, BOOL, PHANDLE );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$CloseHandle( HANDLE );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$ConnectNamedPipe( HANDLE, LPOVERLAPPED );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateFileMappingA( HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$CreatePipe( PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateNamedPipeA( LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$CreateProcessA( LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateRemoteThread( HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateThread( LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateToolhelp32Snapshot( DWORD, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$DisconnectNamedPipe( HANDLE );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$DuplicateHandle( HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD );
DECLSPEC_IMPORT VOID      WINAPI KERNEL32$ExitProcess( UINT );
DECLSPEC_IMPORT VOID      WINAPI KERNEL32$ExitThread( DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$GetThreadContext( HANDLE, LPCONTEXT );
DECLSPEC_IMPORT HMODULE   WINAPI KERNEL32$LoadLibraryW( LPCWSTR );
DECLSPEC_IMPORT HMODULE   WINAPI KERNEL32$LoadLibraryExW( LPCWSTR, HANDLE, DWORD );
DECLSPEC_IMPORT LPVOID    WINAPI KERNEL32$MapViewOfFile( HANDLE, DWORD, DWORD, DWORD, SIZE_T );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$OpenProcess( DWORD, BOOL, DWORD );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$OpenThread( DWORD, BOOL, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$PeekNamedPipe( HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$ReadProcessMemory( HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T * );
DECLSPEC_IMPORT DWORD     WINAPI KERNEL32$ResumeThread( HANDLE );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$SetThreadContext( HANDLE, const CONTEXT * );
DECLSPEC_IMPORT VOID      WINAPI KERNEL32$Sleep( DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$UnmapViewOfFile( LPCVOID );
DECLSPEC_IMPORT LPVOID    WINAPI KERNEL32$VirtualAlloc( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT LPVOID    WINAPI KERNEL32$VirtualAllocEx( HANDLE, LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$VirtualFree( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$VirtualProtect( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$VirtualProtectEx( HANDLE, LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT SIZE_T    WINAPI KERNEL32$VirtualQuery( LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$WaitNamedPipeA( LPCSTR, DWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$WriteProcessMemory( HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T * );
DECLSPEC_IMPORT HRESULT   WINAPI MSCOREE$CLRCreateInstance( REFCLSID clsid, REFIID riid, LPVOID* );
DECLSPEC_IMPORT HRESULT   WINAPI OLE32$CoCreateInstance( REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID * );
DECLSPEC_IMPORT HINTERNET WINAPI WININET$HttpOpenRequestA( HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR );
DECLSPEC_IMPORT BOOL      WINAPI WININET$HttpSendRequestA( HINTERNET, LPCSTR, DWORD, LPVOID, DWORD );
DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetConnectA( HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR );
DECLSPEC_IMPORT HINTERNET WINAPI WININET$InternetOpenA( LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD );
DECLSPEC_IMPORT int       WINAPI WS2_32$WSARecv( SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE );
DECLSPEC_IMPORT int       WINAPI WS2_32$WSASend( SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE );
DECLSPEC_IMPORT SOCKET    WINAPI WS2_32$WSASocketA( int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD );
DECLSPEC_IMPORT int       WINAPI WS2_32$WSAStartup( WORD, LPWSADATA );

// DECLSPEC_IMPORT int      WINAPIV MSVCRT$wcscmp( const wchar_t*, const wchar_t* );
// DECLSPEC_IMPORT wchar_t* WINAPIV MSVCRT$wcsstr( const wchar_t*, const wchar_t* );

// extern void hookModule( HMODULE hModule, DWORD targetHash, PVOID targetHook );

// DWORD __ror13_LoadLibraryExW( );

BOOL WINAPI _AdjustTokenPrivileges_Spoof( HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( ADVAPI32$AdjustTokenPrivileges );
    call.argc = 6;
    
    call.args[0] = spoofArg( TokenHandle );
    call.args[1] = spoofArg( DisableAllPrivileges );
    call.args[2] = spoofArg( NewState );
    call.args[3] = spoofArg( BufferLength );
    call.args[4] = spoofArg( PreviousState );
    call.args[5] = spoofArg( ReturnLength );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _DuplicateTokenEx_Spoof( HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( ADVAPI32$DuplicateTokenEx );
    call.argc = 6;
    
    call.args[0] = spoofArg( hExistingToken );
    call.args[1] = spoofArg( dwDesiredAccess );
    call.args[2] = spoofArg( lpTokenAttributes );
    call.args[3] = spoofArg( ImpersonationLevel );
    call.args[4] = spoofArg( TokenType );
    call.args[5] = spoofArg( phNewToken );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _ImpersonateLoggedOnUser_Spoof( HANDLE hToken )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( ADVAPI32$ImpersonateLoggedOnUser );
    call.argc = 1;
    
    call.args[0] = spoofArg( hToken );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _ImpersonateNamedPipeClient_Spoof( HANDLE hNamedPipe )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( ADVAPI32$ImpersonateNamedPipeClient );
    call.argc = 1;
    
    call.args[0] = spoofArg( hNamedPipe );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _LogonUserA_Spoof( LPCSTR lpszUsername, LPCSTR lpszDomain, LPCSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( ADVAPI32$LogonUserA );
    call.argc = 6;
    
    call.args[0] = spoofArg( lpszUsername );
    call.args[1] = spoofArg( lpszDomain );
    call.args[2] = spoofArg( lpszPassword );
    call.args[3] = spoofArg( dwLogonType );
    call.args[4] = spoofArg( dwLogonProvider );
    call.args[5] = spoofArg( phToken );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _OpenProcessToken_Spoof( HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( ADVAPI32$OpenProcessToken );
    call.argc = 3;
    
    call.args[0] = spoofArg( ProcessHandle );
    call.args[1] = spoofArg( DesiredAccess );
    call.args[2] = spoofArg( TokenHandle );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _OpenThreadToken_Spoof( HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( ADVAPI32$OpenThreadToken );
    call.argc = 4;
    
    call.args[0] = spoofArg( ThreadHandle );
    call.args[1] = spoofArg( DesiredAccess );
    call.args[2] = spoofArg( OpenAsSelf );
    call.args[3] = spoofArg( TokenHandle );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _CloseHandle_Spoof( HANDLE hObject )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$CloseHandle );
    call.argc = 1;
    
    call.args[0] = spoofArg( hObject );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _ConnectNamedPipe_Spoof( HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$ConnectNamedPipe );
    call.argc = 2;
    
    call.args[0] = spoofArg( hNamedPipe );
    call.args[1] = spoofArg( lpOverlapped );

    return ( BOOL )( spoofCall ( &call ));
}

HANDLE WINAPI _CreateFileMappingA_Spoof( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$CreateFileMappingA );
    call.argc = 6;

    call.args[0] = spoofArg( hFile );
    call.args[1] = spoofArg( lpFileMappingAttributes );
    call.args[2] = spoofArg( flProtect );
    call.args[3] = spoofArg( dwMaximumSizeHigh );
    call.args[4] = spoofArg( dwMaximumSizeLow );
    call.args[5] = spoofArg( lpName );

    return ( HANDLE )( spoofCall ( &call ));
}

BOOL WINAPI _CreatePipe_Spoof( PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize)
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$CreatePipe );
    call.argc = 4;

    call.args[0] = spoofArg( hReadPipe );
    call.args[1] = spoofArg( hWritePipe );
    call.args[2] = spoofArg( lpPipeAttributes );
    call.args[3] = spoofArg( nSize );

    return ( BOOL )( spoofCall ( &call ));
}

HANDLE WINAPI _CreateNamedPipeA_Spoof( LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$CreateNamedPipeA );
    call.argc = 8;

    call.args[0] = spoofArg( lpName );
    call.args[1] = spoofArg( dwOpenMode );
    call.args[2] = spoofArg( dwPipeMode );
    call.args[3] = spoofArg( nMaxInstances );
    call.args[4] = spoofArg( nOutBufferSize );
    call.args[5] = spoofArg( nInBufferSize );
    call.args[6] = spoofArg( nDefaultTimeOut );
    call.args[7] = spoofArg( lpSecurityAttributes );

    return ( HANDLE )( spoofCall ( &call ));
}

BOOL WINAPI _CreateProcessA_Spoof( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$CreateProcessA );
    call.argc = 10;

    call.args[0] = spoofArg( lpApplicationName );
    call.args[1] = spoofArg( lpCommandLine );
    call.args[2] = spoofArg( lpProcessAttributes );
    call.args[3] = spoofArg( lpThreadAttributes );
    call.args[4] = spoofArg( bInheritHandles );
    call.args[5] = spoofArg( dwCreationFlags );
    call.args[6] = spoofArg( lpEnvironment );
    call.args[7] = spoofArg( lpCurrentDirectory );
    call.args[8] = spoofArg( lpStartupInfo );
    call.args[9] = spoofArg( lpProcessInformation );

    return ( BOOL )( spoofCall ( &call ));
}

HANDLE WINAPI _CreateRemoteThread_Spoof( HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$CreateRemoteThread );
    call.argc = 7;

    call.args[0] = spoofArg( hProcess );
    call.args[1] = spoofArg( lpThreadAttributes );
    call.args[2] = spoofArg( dwStackSize );
    call.args[3] = spoofArg( lpStartAddress );
    call.args[4] = spoofArg( lpParameter );
    call.args[5] = spoofArg( dwCreationFlags );
    call.args[6] = spoofArg( lpThreadId );

    return ( HANDLE )( spoofCall ( &call ));
}

HANDLE WINAPI _CreateThread_Spoof( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$CreateThread );
    call.argc = 6;
    
    call.args[0] = spoofArg( lpThreadAttributes );
    call.args[1] = spoofArg( dwStackSize );
    call.args[2] = spoofArg( lpStartAddress );
    call.args[3] = spoofArg( lpParameter );
    call.args[4] = spoofArg( dwCreationFlags );
    call.args[5] = spoofArg( lpThreadId );

    return ( HANDLE )( spoofCall ( &call ));
}

HANDLE WINAPI _CreateToolhelp32Snapshot_Spoof( DWORD dwFlags, DWORD th32ProcessID )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$CreateToolhelp32Snapshot );
    call.argc = 2;
    
    call.args[0] = spoofArg( dwFlags );
    call.args[1] = spoofArg( th32ProcessID );

    return ( HANDLE )( spoofCall ( &call ));
}

BOOL WINAPI _DisconnectNamedPipe_Spoof( HANDLE hNamedPipe )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$DisconnectNamedPipe );
    call.argc = 1;
    
    call.args[0] = spoofArg( hNamedPipe );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _DuplicateHandle_Spoof( HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$DuplicateHandle );
    call.argc = 7;
    
    call.args[0] = spoofArg( hSourceProcessHandle );
    call.args[1] = spoofArg( hSourceHandle );
    call.args[2] = spoofArg( hTargetProcessHandle );
    call.args[3] = spoofArg( lpTargetHandle );
    call.args[4] = spoofArg( dwDesiredAccess );
    call.args[5] = spoofArg( bInheritHandle );
    call.args[6] = spoofArg( dwOptions );

    return ( BOOL )( spoofCall ( &call ));
}

VOID WINAPI _ExitProcess_Spoof( UINT uExitCode )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$ExitProcess );
    call.argc = 1;
    
    call.args[0]  = spoofArg( uExitCode );

    spoofCall( &call );
}

VOID WINAPI _ExitThread_Spoof( DWORD dwExitCode )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$ExitThread );
    call.argc = 1;
    
    call.args[0]  = spoofArg( dwExitCode );

    spoofCall( &call );
}

FARPROC _GetProcAddress_Spoof( HMODULE hModule, LPCSTR  lpProcName )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( GetProcAddress );
    call.argc = 2;
    
    call.args[0] = spoofArg( hModule );
    call.args[1] = spoofArg( lpProcName );

    return ( FARPROC )( spoofCall ( &call ));
}

BOOL WINAPI _GetThreadContext_Spoof( HANDLE hThread, LPCONTEXT lpContext )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$GetThreadContext );
    call.argc = 2;
    
    call.args[0] = spoofArg( hThread );
    call.args[1] = spoofArg( lpContext );

    return ( BOOL )( spoofCall ( &call ));
}

HMODULE WINAPI _LoadLibraryA_Spoof( LPCSTR lpLibFileName )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( LoadLibraryA );
    call.argc = 1;
    
    call.args[0] = spoofArg( lpLibFileName );

    return ( HMODULE )( spoofCall ( &call ));
}

HMODULE WINAPI _LoadLibraryExW_Spoof( LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$LoadLibraryExW );
    call.argc = 3;
    
    call.args[0] = spoofArg( lpLibFileName );
    call.args[1] = spoofArg( hFile );
    call.args[2] = spoofArg( dwFlags );

    return ( HMODULE )( spoofCall( &call ));
}

HMODULE WINAPI _LoadLibraryW_Spoof( LPCWSTR lpLibFileName )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$LoadLibraryW );
    call.argc = 1;
    
    call.args[0] = spoofArg( lpLibFileName );

    return ( HMODULE )( spoofCall ( &call ));
}

LPVOID WINAPI _MapViewOfFile_Spoof( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$MapViewOfFile );
    call.argc = 5;
    
    call.args[0] = spoofArg( hFileMappingObject );
    call.args[1] = spoofArg( dwDesiredAccess );
    call.args[2] = spoofArg( dwFileOffsetHigh );
    call.args[3] = spoofArg( dwFileOffsetLow );
    call.args[4] = spoofArg( dwNumberOfBytesToMap );

    return ( LPVOID )( spoofCall ( &call ));
}

HANDLE WINAPI _OpenProcess_Spoof( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$OpenProcess );
    call.argc = 3;
    
    call.args[0] = spoofArg( dwDesiredAccess );
    call.args[1] = spoofArg( bInheritHandle );
    call.args[2] = spoofArg( dwProcessId );

    return ( HANDLE )( spoofCall ( &call ));
}

HANDLE WINAPI _OpenThread_Spoof( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$OpenThread );
    call.argc = 3;
    
    call.args[0] = spoofArg( dwDesiredAccess );
    call.args[1] = spoofArg( bInheritHandle );
    call.args[2] = spoofArg( dwThreadId );

    return ( HANDLE )( spoofCall ( &call ));
}

BOOL WINAPI _PeekNamedPipe_Spoof( HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$PeekNamedPipe );
    call.argc = 6;
    
    call.args[0] = spoofArg( hNamedPipe );
    call.args[1] = spoofArg( lpBuffer );
    call.args[2] = spoofArg( nBufferSize );
    call.args[3] = spoofArg( lpBytesRead );
    call.args[4] = spoofArg( lpTotalBytesAvail );
    call.args[5] = spoofArg( lpBytesLeftThisMessage );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _ReadProcessMemory_Spoof( HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$ReadProcessMemory );
    call.argc = 5;
    
    call.args[0] = spoofArg( hProcess );
    call.args[1] = spoofArg( lpBaseAddress );
    call.args[2] = spoofArg( lpBuffer );
    call.args[3] = spoofArg( nSize );
    call.args[4] = spoofArg( lpNumberOfBytesRead );

    return ( BOOL )( spoofCall ( &call ));
}

DWORD WINAPI _ResumeThread_Spoof( HANDLE hThread )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$ResumeThread );
    call.argc = 1;
    
    call.args[0] = spoofArg( hThread );

    return ( DWORD )( spoofCall ( &call ));
}

BOOL WINAPI _SetThreadContext_Spoof( HANDLE hThread, const CONTEXT * lpContext )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$SetThreadContext );
    call.argc = 2;
    
    call.args[0] = spoofArg( hThread );
    call.args[1] = spoofArg( lpContext );

    return ( BOOL )( spoofCall ( &call ));
}

VOID WINAPI _Sleep_Spoof( DWORD dwMilliseconds )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$Sleep );
    call.argc = 1;
    
    call.args[0] = spoofArg( dwMilliseconds );

    spoofCall( &call );
}

BOOL WINAPI _UnmapViewOfFile_Spoof( LPCVOID lpBaseAddress )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$UnmapViewOfFile );
    call.argc = 1;
    
    call.args[0] = spoofArg( lpBaseAddress );

    return ( BOOL )( spoofCall ( &call ));
}

LPVOID WINAPI _VirtualAlloc_Spoof( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$VirtualAlloc );
    call.argc = 4;
    
    call.args[0] = spoofArg( lpAddress );
    call.args[1] = spoofArg( dwSize );
    call.args[2] = spoofArg( flAllocationType );
    call.args[3] = spoofArg( flProtect );

    return ( LPVOID )( spoofCall ( &call ));
}

LPVOID WINAPI _VirtualAllocEx_Spoof( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$VirtualAllocEx );
    call.argc = 5;
    
    call.args[0] = spoofArg( hProcess );
    call.args[1] = spoofArg( lpAddress );
    call.args[2] = spoofArg( dwSize );
    call.args[3] = spoofArg( flAllocationType );
    call.args[4] = spoofArg( flProtect );

    return ( LPVOID )( spoofCall ( &call ));
}

BOOL WINAPI _VirtualFree_Spoof( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$VirtualFree );
    call.argc = 3;
    
    call.args[0] = spoofArg( lpAddress );
    call.args[1] = spoofArg( dwSize );
    call.args[2] = spoofArg( dwFreeType );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _VirtualProtect_Spoof( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$VirtualProtect );
    call.argc = 4;
    
    call.args[0] = spoofArg( lpAddress );
    call.args[1] = spoofArg( dwSize );
    call.args[2] = spoofArg( flNewProtect );
    call.args[3] = spoofArg( lpflOldProtect );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _VirtualProtectEx_Spoof( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$VirtualProtectEx );
    call.argc = 5;
    
    call.args[0] = spoofArg( hProcess );
    call.args[1] = spoofArg( lpAddress );
    call.args[2] = spoofArg( dwSize );
    call.args[3] = spoofArg( flNewProtect );
    call.args[4] = spoofArg( lpflOldProtect );

    return ( BOOL )( spoofCall ( &call ));
}

SIZE_T WINAPI _VirtualQuery_Spoof( LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$VirtualQuery );
    call.argc = 3;
    
    call.args[0] = spoofArg( lpAddress );
    call.args[1] = spoofArg( lpBuffer );
    call.args[2] = spoofArg( dwLength );

    return ( SIZE_T )( spoofCall ( &call ));
}

BOOL WINAPI _WaitNamedPipeA_Spoof( LPCSTR lpNamedPipeName, DWORD nTimeOut )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$WaitNamedPipeA );
    call.argc = 2;
    
    call.args[0] = spoofArg( lpNamedPipeName );
    call.args[1] = spoofArg( nTimeOut );

    return ( BOOL )( spoofCall ( &call ));
}

BOOL WINAPI _WriteProcessMemory_Spoof( HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( KERNEL32$WriteProcessMemory );
    call.argc = 5;
    
    call.args[0] = spoofArg( hProcess );
    call.args[1] = spoofArg( lpBaseAddress );
    call.args[2] = spoofArg( lpBuffer );
    call.args[3] = spoofArg( nSize );
    call.args[4] = spoofArg( lpNumberOfBytesWritten );

    return ( BOOL )( spoofCall ( &call ));
}

HRESULT WINAPI _CLRCreateInstance_Spoof( REFCLSID clsid, REFIID riid, LPVOID* ppInterface )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( MSCOREE$CLRCreateInstance );
    call.argc = 3;
    
    call.args[0] = spoofArg( clsid );
    call.args[1] = spoofArg( riid );
    call.args[2] = spoofArg( ppInterface );

    return ( HRESULT )( spoofCall ( &call ));
}

HRESULT WINAPI _CoCreateInstance_Spoof( REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID * ppv )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( OLE32$CoCreateInstance );
    call.argc = 5;
    
    call.args[0] = spoofArg( rclsid );
    call.args[1] = spoofArg( pUnkOuter );
    call.args[2] = spoofArg( dwClsContext );
    call.args[3] = spoofArg( riid );
    call.args[4] = spoofArg( ppv );

    return ( HRESULT )( spoofCall ( &call ));
}

HINTERNET WINAPI _HttpOpenRequestA_Spoof( HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( WININET$HttpOpenRequestA );
    call.argc = 8;

    call.args[0] = spoofArg( hConnect );
    call.args[1] = spoofArg( lpszVerb );
    call.args[2] = spoofArg( lpszObjectName );
    call.args[3] = spoofArg( lpszVersion );
    call.args[4] = spoofArg( lpszReferrer );
    call.args[5] = spoofArg( lplpszAcceptTypes );
    call.args[6] = spoofArg( dwFlags );
    call.args[7] = spoofArg( dwContext );

    return ( HINTERNET )( spoofCall ( &call ));
}

BOOL WINAPI _HttpSendRequestA_Spoof( HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( WININET$HttpSendRequestA );
    call.argc = 5;

    call.args[0] = spoofArg( hRequest );
    call.args[1] = spoofArg( lpszHeaders );
    call.args[2] = spoofArg( dwHeadersLength );
    call.args[3] = spoofArg( lpOptional );
    call.args[4] = spoofArg( dwOptionalLength );

    return ( BOOL )( spoofCall ( &call ));
}

HINTERNET WINAPI _InternetConnectA_Spoof( HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( WININET$InternetConnectA );
    call.argc = 8;

    call.args[0] = spoofArg( hInternet );
    call.args[1] = spoofArg( lpszServerName );
    call.args[2] = spoofArg( nServerPort );
    call.args[3] = spoofArg( lpszUserName );
    call.args[4] = spoofArg( lpszPassword );
    call.args[5] = spoofArg( dwService );
    call.args[6] = spoofArg( dwFlags );
    call.args[7] = spoofArg( dwContext );

    return ( HINTERNET )( spoofCall ( &call ));
}

HINTERNET WINAPI _InternetOpenA_Spoof( LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( WININET$InternetOpenA );
    call.argc = 5;

    call.args[0] = spoofArg( lpszAgent );
    call.args[1] = spoofArg( dwAccessType );
    call.args[2] = spoofArg( lpszProxy );
    call.args[3] = spoofArg( lpszProxyBypass );
    call.args[4] = spoofArg( dwFlags );

    return ( HINTERNET )( spoofCall ( &call ));
}

int WINAPI _WSARecv_Spoof( SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( WS2_32$WSARecv );
    call.argc = 7;

    call.args[0] = spoofArg( s );
    call.args[1] = spoofArg( lpBuffers );
    call.args[2] = spoofArg( dwBufferCount );
    call.args[3] = spoofArg( lpNumberOfBytesRecvd );
    call.args[4] = spoofArg( lpFlags );
    call.args[5] = spoofArg( lpOverlapped );
    call.args[6] = spoofArg( lpCompletionRoutine );

    return ( int )( spoofCall ( &call ));
}

int WINAPI _WSASend_Spoof( SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( WS2_32$WSASend );
    call.argc = 7;

    call.args[0] = spoofArg( s );
    call.args[1] = spoofArg( lpBuffers );
    call.args[2] = spoofArg( dwBufferCount );
    call.args[3] = spoofArg( lpNumberOfBytesSent );
    call.args[4] = spoofArg( dwFlags );
    call.args[5] = spoofArg( lpOverlapped );
    call.args[6] = spoofArg( lpCompletionRoutine );

    return ( int )( spoofCall ( &call ));
}

SOCKET WINAPI _WSASocketA_Spoof( int af, int type, int protocol, LPWSAPROTOCOL_INFOA lpProtocolInfo, GROUP g, DWORD dwFlags )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID )( WS2_32$WSASocketA );
    call.argc = 6;

    call.args[0] = spoofArg( af );
    call.args[1] = spoofArg( type );
    call.args[2] = spoofArg( protocol );
    call.args[3] = spoofArg( lpProtocolInfo );
    call.args[4] = spoofArg( g );
    call.args[5] = spoofArg( dwFlags );

    return ( SOCKET )( spoofCall ( &call ));
}

int WINAPI _WSAStartup_Spoof( WORD wVersionRequested, LPWSADATA lpWSAData )
{
    FUNCTION_CALL call = { 0 };
    
    call.ptr  = ( PVOID )( WS2_32$WSAStartup );
    call.argc = 2;

    call.args[0] = spoofArg( wVersionRequested );
    call.args[1] = spoofArg( lpWSAData );
    
    return ( int )( spoofCall ( &call ));
}
