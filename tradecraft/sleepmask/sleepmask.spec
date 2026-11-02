setup.x64:
    load "bin/sleepmask_setup.x64.o"
        merge

    redirect "setupHooks" "setupHooksMask"

hooks.x64:
    load "bin/sleepmask.x64.o"
        merge

    load "bin/sleepmask_hooks.x64.o"
        merge

    generate $KEY 128
    patch "xorkey" $KEY
    
    exportfunc "setupMemory" "__tag_setupMemory"

    addhook  "KERNEL32$ExitThread"
    addhook  "KERNEL32$HeapAlloc"
    addhook  "KERNEL32$HeapFree"
    addhook  "KERNEL32$HeapReAlloc"
    addhook  "KERNEL32$Sleep"
    
    attach  "KERNEL32$ExitThread"  "_ExitThread_Mask"
    attach  "KERNEL32$HeapAlloc"   "_HeapAlloc_Mask"
    attach  "KERNEL32$HeapFree"    "_HeapFree_Mask"
    attach  "KERNEL32$HeapReAlloc" "_HeapReAlloc_Mask"
    attach  "KERNEL32$Sleep"       "_Sleep_Mask"
