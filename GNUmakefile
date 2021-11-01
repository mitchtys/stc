.DEFAULT: all
CARGO:=cargo
STC:=stc

all: debug release

.PHONY: debug
debug:
	$(CARGO) build

.PHONY: release
release:
	$(CARGO) build --release

.PHONY: clean
clean:
	-cargo clean
	-rm -fr target

.PHONY: update
update:
	cargo update

# The sledgehammer of "hold my beer hope this works" in local dev
.PHONY: wtf
wtf: clean update
	touch build.rs

.PHONY: watch
watch:
	$(CARGO) watch -c -x check -x fmt -x test -x "clippy -- -D warnings" -x build -x "build --release"
