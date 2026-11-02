#define spoofArg(x) ( ULONG_PTR ) ( x )

typedef struct {
    PVOID     ptr;
    DWORD     ssn;
    int       argc;
    ULONG_PTR args[10];
} FUNCTION_CALL;

ULONG_PTR spoofCall( FUNCTION_CALL * call );
