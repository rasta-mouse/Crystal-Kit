setup.x64:
    load "bin/cleanup_setup.x64.o"
        merge

    redirect "setupHooks" "setupHooksCleanup"

hooks.x64:
    load "bin/cleanup.x64.o"
        merge

    load "bin/cleanup_hooks.x64.o"
        merge

    load "bin/cfg.x64.o"
        merge

    exportfunc "setupCleanup" "__tag_setupCleanup"

    addhook "KERNEL32$ExitThread"

    .attach

attach.x64:
    attach  "KERNEL32$ExitThread" "_ExitThread_Cleanup"
