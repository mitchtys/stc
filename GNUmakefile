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
	-rm -fr target

.PHONY: watch
watch:
	$(CARGO) watch -c -x check -x fmt -x test -x "clippy -- -D warnings" -x build -x "build --release"
