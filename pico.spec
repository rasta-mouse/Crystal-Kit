x64:
    load "bin/pico.x64.o"
        make object +disco

    mergelib "libtcg.x64.zip"
    
    # merge the hook functions
    load "bin/hooks.x64.o"
        merge

    # merge the call stack spoofing
    load "bin/spoof.x64.o"
        merge

    # merge the asm stub
    load "bin/draugr.x64.bin"
        linkfunc "draugr_stub"

    # merge mask
    load "bin/mask.x64.o"
        merge

    # generate and patch in a random key
    generate $KEY 128
    patch "xorkey" $KEY

    # merge cfg code
    load "bin/cfg.x64.o"
        merge
            
    # merge cleanup
    load "bin/cleanup.x64.o"
        merge

    # export setup_hooks and setup_memory
    exportfunc "setup_hooks"  "__tag_setup_hooks"
    exportfunc "setup_memory" "__tag_setup_memory"