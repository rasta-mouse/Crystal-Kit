typedef struct {
    PVOID  BaseAddress;
    SIZE_T Size;
    DWORD  CurrentProtect;
    DWORD  PreviousProtect;
} MEMORY_SECTION;

typedef struct {
    PVOID          BaseAddress;
    SIZE_T         Size;
    MEMORY_SECTION Sections [ 20 ];
} MEMORY_REGION;

typedef struct {
    MEMORY_REGION Pico;
    MEMORY_REGION Dll;
} MEMORY_LAYOUT;