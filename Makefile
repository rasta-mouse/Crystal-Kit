all:
	cd loader && make $@
	cd transforms && make $@
	cd tradecraft && make $@

clean:
	cd loader && make $@
	cd transforms && make $@
	cd tradecraft && make $@
