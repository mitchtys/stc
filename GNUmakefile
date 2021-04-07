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

# Below here be dragons, if ye not be programming in rust, this tis not for thee!
#
# Feel free to run it though, just not that useful of a target for most people
# and it presumes a valid build env/SHELL that sets signals for exit codes
# sanely/according to posix. And that entr is installed.
ENTR:=entr
CARGO:=cargo
CI_CMDS:=$(CARGO) test && $(CARGO) fmt && $(CARGO) build && $(CARGO) build --release
.PHONY: ci
ci:
	while :; do \
	  (printf "build.rs\nCargo.toml\n" && find src -name "*.rs" -type f) | $(ENTR) -ad -- /bin/sh -c "$(CI_CMDS)"; \
    if [ $$? -gt 128 ]; then \
        break; \
    fi; \
    sleep 1; \
	  clear; \
	done

.PHONY: watch
watch:
	$(CARGO) watch -c -x check -x test -x fmt -x build -x "build --release"
