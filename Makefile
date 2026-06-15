SHELL  := /bin/bash
# IMPORTANT: build with the CX project's V fork — github.com/cx-home/v — not
# stock V. The `code` module's HTTP/SSE engine uses picoev extensions
# (cx_set_sse_on_close / cx_hold_fd) that live only in the fork, and -prod needs
# the fork's macOS GC fix. Point `make` at it:  make V=/path/to/cx-home-v/v test
V ?= v
PREFIX ?= $(HOME)/.local/bin

# The cx module's regex engine (cx/regex_re2.v) binds the RE2 C++ library
# through a small shim (deps/re2_shim/). Building also needs:
#   • a C++ compiler
#   • RE2 development headers + library — macOS: `brew install re2`;
#     Debian/Ubuntu: `apt install libre2-dev`
# The re2-shim target compiles the shim into target/libcx_re2_shim.a, which
# cx/regex_re2.v links via `#flag -L @VMODROOT/target -lcx_re2_shim`.

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Darwin)
  RE2_INC := -I/opt/homebrew/include
else
  RE2_INC := -I/usr/include
endif
RE2_SHIM_LIB := target/libcx_re2_shim.a

.PHONY: install uninstall test re2-shim

re2-shim: $(RE2_SHIM_LIB)

$(RE2_SHIM_LIB): deps/re2_shim/re2_shim.cc deps/re2_shim/re2_shim.h
	@mkdir -p target
	c++ -std=c++17 -O2 -fPIC $(RE2_INC) -Ideps/re2_shim -c deps/re2_shim/re2_shim.cc -o target/cx_re2_shim.o
	ar rcs $(RE2_SHIM_LIB) target/cx_re2_shim.o

# cmd/main.v + the tests import BOTH `cx` (this package root) and `code` (the
# eval/stdlib module in code/). We stage a temporary _modules/ with a symlink
# per module so VMODULES resolves both regardless of the shell's VMODULES.
MODSETUP = mkdir -p _modules && ln -sfn $$(pwd) _modules/cx && ln -sfn $$(pwd)/code _modules/code

# NOTE: not `-prod`. `-prod` turns V warnings into errors, and the cmd/ LSP
# files carry benign unused-import warnings (same class as cx-home/cx-private#13);
# `-prod` with a stock-V Boehm GC can also segfault on macOS. The CLI is a thin
# dispatch layer over the (in cx-home/cx, -prod) libcx, so -O2 C opt suffices.
# CX_VERSION derives from the shipped VERSION file (single source of truth, same
# as the main repo) so cx-v's `cx --version` / C-ABI report the real release
# version rather than the dev fallback.
CX_VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0-dev)

install: re2-shim
	@mkdir -p $(PREFIX) && $(MODSETUP)
	@VMODULES=$$(pwd)/_modules $(V) -cflags "-O2" -d cx_version=$(CX_VERSION) -o $(PREFIX)/cx cmd/; STATUS=$$?; rm -rf _modules; \
	  [ $$STATUS -eq 0 ] && echo "installed: $(PREFIX)/cx — make sure $(PREFIX) is on your PATH"; exit $$STATUS

uninstall:
	rm -f $(PREFIX)/cx
	@echo "removed: $(PREFIX)/cx"

test: re2-shim
	@$(MODSETUP)
	@VMODULES=$$(pwd)/_modules $(V) test tests/; STATUS=$$?; rm -rf _modules; exit $$STATUS
