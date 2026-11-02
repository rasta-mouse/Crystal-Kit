#
# lznt1 data encoding module
#

# 'init' is called by loader.spec and is our opportunity to merge in code
# and set any global values we need to set.
init.x86:
	# merge in code for lznt1 recovery
	load "bin/recover.x86.o"
		merge

	# layer our lznt1 recovery function over recover
	redirect "_recover" "_lznt1_recover"

init.x64:
	load "bin/recover.x64.o"
		merge

	redirect "recover" "lznt1_recover"

# 'apply' is called by loader.spec and is our opportunity to encode the data
apply.x86:
	encode "lznt1" "length, in_length"

apply.x64:
	encode "lznt1" "length, in_length"
