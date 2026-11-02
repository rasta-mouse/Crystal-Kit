name       "Crystal Kit Smart Loader"
describe   "A UDRL for Cobalt Strike Beacons that are spawned by another Beacon. Takes GMH & GPA function pointers from the parent."
author     "@_RastaMouse"
license    "MIT"
reference  "https://rastamouse.me/crystal-kit/" 
defraw     "$DLL" "Beacon DLL"

initpic.x64:
    make pic +gofirst +disco +mutate +blockparty +shatter +optimize

    load "bin/services.x64.o"
        merge

    patch "getModuleHandle" $GMH
    patch "getProcAddress"  $GPA

    dfr "resolve_smart" "strings"

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
