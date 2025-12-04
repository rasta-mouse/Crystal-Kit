x64:
    load "bin/loader.x64.o"
        make pic +gofirst +optimize

    # merge services
    load "bin/services.x64.o"
        merge

    mergelib "libtcg.x64.zip"

    # merge hooks into the loader
    load "bin/hooks.x64.o"
        merge

    # merge call stack spoofing into the loader
    load "bin/spoof.x64.o"
        merge

    # link the stack spoofing assembly
    load "bin/draugr.x64.bin"
        linkfunc "draugr_stub"

    # hook functions that the loader uses
    .loader_hooks

    # mask & link the dll
    generate $MASK 128
    push $DLL
        xor $MASK
        preplen
        link "dll"

    # link the mask key
    push $MASK
        preplen
        link "mask"

loader_hooks.x64:
    attach "KERNEL32$LoadLibraryA"    "_LoadLibraryA"
    attach "KERNEL32$VirtualAlloc"    "_VirtualAlloc"
    attach "KERNEL32$VirtualProtect"  "_VirtualProtect"
    attach "KERNEL32$VirtualFree"     "_VirtualFree"

    preserve "KERNEL32$LoadLibraryA"  "init_frame_info"