name       "Crystal Kit BOF Cocktails"
describe   "Applies evasion tradecraft to postex BOFs."
author     "@_RastaMouse"
license    "MIT"
reference  "https://rastamouse.me/bof-cocktails-in-cobalt-strike/" 
defraw     "$OBJECT" "Postex BOF"

x64:
    push $OBJECT
        make coff +disco +mutate +blockparty +shatter +optimize
    
        foreach %hooks: call %_ "hooks"
        
        mergelib "libtcg.x64.zip"

        export
