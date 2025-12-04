x64:
    # this returns a loader with hooks
    run "loader.spec"

    # add dfr resolution
    dfr "resolve" "ror13" "KERNEL32, NTDLL"
    dfr "resolve_ext" "strings"

    # this returns a pico without hooks
    run "pico.spec"
        .pico_hooks  # add the hooks
        export
        link "pico"  # link pico to loader

    # export pic
    export

pico_hooks.x64:
    addhook "WININET$InternetOpenA"       "_InternetOpenA"
    addhook "WININET$InternetConnectA"    "_InternetConnectA"
    addhook "KERNEL32$CloseHandle"        "_CloseHandle"
    addhook "KERNEL32$CreateFileMappingA" "_CreateFileMappingA"
    addhook "KERNEL32$CreateProcessA"     "_CreateProcessA"
    addhook "KERNEL32$CreateRemoteThread" "_CreateRemoteThread"
    addhook "KERNEL32$CreateThread"       "_CreateThread"
    addhook "KERNEL32$DuplicateHandle"    "_DuplicateHandle"
    addhook "KERNEL32$ExitThread"         "_ExitThread"
    addhook "KERNEL32$GetThreadContext"   "_GetThreadContext"
    addhook "KERNEL32$LoadLibraryA"       "_LoadLibraryA"
    addhook "KERNEL32$MapViewOfFile"      "_MapViewOfFile"
    addhook "KERNEL32$OpenProcess"        "_OpenProcess"
    addhook "KERNEL32$OpenThread"         "_OpenThread"
    addhook "KERNEL32$ReadProcessMemory"  "_ReadProcessMemory"
    addhook "KERNEL32$ResumeThread"       "_ResumeThread"
    addhook "KERNEL32$SetThreadContext"   "_SetThreadContext"
    addhook "KERNEL32$Sleep"              "_Sleep"
    addhook "KERNEL32$UnmapViewOfFile"    "_UnmapViewOfFile"
    addhook "KERNEL32$VirtualAlloc"       "_VirtualAlloc"
    addhook "KERNEL32$VirtualAllocEx"     "_VirtualAllocEx"
    addhook "KERNEL32$VirtualFree"        "_VirtualFree"
    addhook "KERNEL32$VirtualProtect"     "_VirtualProtect"
    addhook "KERNEL32$VirtualProtectEx"   "_VirtualProtectEx"
    addhook "KERNEL32$VirtualQuery"       "_VirtualQuery"
    addhook "KERNEL32$WriteProcessMemory" "_WriteProcessMemory"
    addhook "OLE32$CoCreateInstance"      "_CoCreateInstance"