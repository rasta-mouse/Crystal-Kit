x64:
    # this returns a loader with hooks
    run "loader.spec"

    # patch smart inject pointers
    patch "get_module_handle" $GMH
    patch "get_proc_address"  $GPA

    # add dfr resolution
    dfr "resolve_patch" "strings"

    # this returns a pico without hooks
    run "pico.spec"
        .pico_hooks  # add the hooks
        export
        link "pico"  # link pico to loader

    # export pic
    export

pico_hooks.x64:
    addhook "KERNEL32$LoadLibraryW"  "_LoadLibraryW"
    addhook "KERNEL32$ExitThread"    "_ExitThread"