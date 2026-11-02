setup.x64:
    echo "no setup"

hooks.x64:
    load "bin/hooker.x64.o"
        merge

    load "bin/hooker_hooks.x64.o"
        merge
    
    addhook "KERNEL32$LoadLibraryW"
    attach  "KERNEL32$LoadLibraryW" "_LoadLibraryW_Hook"

    addhook "KERNEL32$LoadLibraryExW"
    attach  "KERNEL32$LoadLibraryExW" "_LoadLibraryExW_Hook"
