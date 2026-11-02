#include <windows.h>
#include "bud.h"
#include "tcg.h"

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);

#define memcpy(dst, src, len) __movsb( ( u_char* )( dst ), ( u_char* )( src ), len )

extern PALLOCATED_MEMORY g_memory;

const char xorkey[128] = { 1 };

void applyMask( char* data, DWORD len )
{
    for ( DWORD i = 0; i < len; i++ ) {
        data[i] ^= xorkey[i % sizeof(xorkey)];
    }
}

BOOL isWriteable( DWORD protection )
{
    if ( protection == PAGE_EXECUTE_READWRITE ||
         protection == PAGE_EXECUTE_WRITECOPY ||
         protection == PAGE_READWRITE         ||
         protection == PAGE_WRITECOPY ) {
            return TRUE;
    }

    return FALSE;
}

void maskSection( PALLOCATED_MEMORY_SECTION section, BOOL mask )
{
    if ( mask == TRUE && isWriteable( section->currentProtect ) == FALSE )
    {
        DWORD old_protect = 0;
        if ( KERNEL32$VirtualProtect( section->baseAddress, section->virtualSize, PAGE_READWRITE, &old_protect ))
        {
            section->currentProtect  = PAGE_READWRITE;
            section->previousProtect = old_protect;
        }
    }

    if ( isWriteable( section->currentProtect )) {
        applyMask( section->baseAddress, section->virtualSize );
    }

    if ( mask == FALSE && section->currentProtect != section->previousProtect )
    {
        DWORD old_protect = 0;
        if ( KERNEL32$VirtualProtect( section->baseAddress, section->virtualSize, section->previousProtect, &old_protect ))
        {
            section->currentProtect  = section->previousProtect;
            section->previousProtect = old_protect;
        }
    }
}

void maskRegion( PALLOCATED_MEMORY_REGION region, BOOL mask )
{
    for ( int i = 0; i < BUD_MAX_SECTIONS; i++ )
    {
        if ( region->sections[i].baseAddress == NULL || region->sections[i].virtualSize == 0 ) {
            continue;
        }

        maskSection( &region->sections[i], mask );
    }
}

void maskHeap( PHEAP_RECORD record )
{
    /* these are already rw */
    applyMask( record->ptr, record->size );
}

void maskMemory( BOOL mask )
{
    /* mask each region */
    for ( int i = 0; i < BUD_MAX_REGIONS; i++ )
    {
        if ( g_memory->memoryRegions[i].allocationBase == NULL || g_memory->memoryRegions[i].regionSize == 0 ) {
            continue;
        }

        maskRegion( &g_memory->memoryRegions[i], mask );
    }

    /* mask each heap record */
    for ( int i = 0; i < BUD_MAX_HEAP_RECORDS; i++ )
    {
        if ( g_memory->heapRecords[i].ptr == NULL || g_memory->heapRecords[i].size == 0 ) {
            continue;
        }

        maskHeap( &g_memory->heapRecords[i] );
    }
}

void addHeapRecord( PVOID ptr, SIZE_T size )
{
    /* loop over records */
    for ( int i = 0; i < BUD_MAX_HEAP_RECORDS; i++ )
    {
        /* find an empty slot */
        if ( g_memory->heapRecords[i].ptr == NULL )
        {
            g_memory->heapRecords[i].ptr  = ptr;
            g_memory->heapRecords[i].size = size;

            break;
        }
    }
}

void updateHeapRecord( PVOID old_ptr, PVOID new_ptr, SIZE_T new_size )
{
    /* loop over records */
    for ( int i = 0; i < BUD_MAX_HEAP_RECORDS; i++ )
    {
        /* find correct ptr */
        if ( g_memory->heapRecords[i].ptr == old_ptr )
        {
            /* update values */
            g_memory->heapRecords[i].ptr  = new_ptr;
            g_memory->heapRecords[i].size = new_size;
            
            break;
        }
    }
}

void removeHeapRecord( PVOID ptr )
{
    /* loop over records */
    for ( int i = 0; i < BUD_MAX_HEAP_RECORDS; i++ )
    {
        /* find correct ptr */
        if ( g_memory->heapRecords[i].ptr == ptr )
        {
            /* just 0 the values */
            g_memory->heapRecords[i].ptr  = NULL;
            g_memory->heapRecords[i].size = 0;
            
            break;
        }
    }
}

void setupMemory( PALLOCATED_MEMORY memory )
{   
    if ( memory != NULL ) {
        g_memory = memory;
    }   
}
