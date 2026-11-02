#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualProtect( LPVOID, SIZE_T, DWORD, PDWORD );

void hookModule( HMODULE hModule, DWORD targetHash, PVOID targetHook )
{
    /* parse the module */
    DLLDATA dll_data;
    ParseDLL(( char* )( hModule ), &dll_data );

    /* get the import directory */
    IMAGE_DATA_DIRECTORY     imports_directory = dll_data.OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR* import_descriptor = ( IMAGE_IMPORT_DESCRIPTOR* )( imports_directory.VirtualAddress + ( DWORD_PTR )( hModule ));

    /* walk every imported module */
    while ( import_descriptor->Name != 0 )
    {
        IMAGE_THUNK_DATA* orig_first_thunk = ( IMAGE_THUNK_DATA* )(( DWORD_PTR )( hModule ) + import_descriptor->OriginalFirstThunk );
        IMAGE_THUNK_DATA* first_thunk      = ( IMAGE_THUNK_DATA* )(( DWORD_PTR )( hModule ) + import_descriptor->FirstThunk );

        /* walk every imported function */
        while ( orig_first_thunk->u1.AddressOfData != 0 )
        {
            IMAGE_IMPORT_BY_NAME* func_name = ( IMAGE_IMPORT_BY_NAME* )(( DWORD_PTR )( hModule ) + orig_first_thunk->u1.AddressOfData );
            DWORD                 func_hash = ror13hash (( const char* )( func_name->Name ));

            /* is this the target hash? */
            if ( func_hash == targetHash )
            {
                /* yep, hook it */
                DWORD prev_protect = 0;

                if ( KERNEL32$VirtualProtect(( LPVOID )( &first_thunk->u1.Function ), sizeof(PVOID), PAGE_READWRITE, &prev_protect ))
                {
                    first_thunk->u1.Function = ( DWORD_PTR )( targetHook );
                    KERNEL32$VirtualProtect(( LPVOID )( &first_thunk->u1.Function ), sizeof(PVOID), prev_protect, &prev_protect );
                }

                /* we're done */
                break;
            }

            ++orig_first_thunk;
            ++first_thunk;
        }

        import_descriptor++;
    }
}
