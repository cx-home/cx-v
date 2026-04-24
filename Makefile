SHELL  := /bin/bash
V      := v
TARGET := target

# ── Platform detection ────────────────────────────────────────────────────────

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Darwin)
  LIB_EXT  := dylib
  LIB_NAME := libcx.dylib
  STRIP    := strip
else
  LIB_EXT  := so
  LIB_NAME := libcx.so
  STRIP    := strip --strip-unneeded
endif

LIB  := $(TARGET)/$(LIB_NAME)
CLI  := $(TARGET)/cx

# Production C flags: size-optimized, all debug overhead removed.
# -Os    : optimize for size (smaller than -O3 for this codebase)
# -DNDEBUG -DNO_DEBUGGING : remove assertions and V debug helpers
# -fwrapv: defined integer overflow semantics (matches -prod behaviour)
PROD_CFLAGS := -Os -DNDEBUG -DNO_DEBUGGING -fwrapv

CONFORMANCE_CORE := ../conformance/core.txt
CONFORMANCE_EXT  := ../conformance/extended.txt
CONFORMANCE_XML  := ../conformance/xml.txt
CONFORMANCE_MD   := ../conformance/md.txt

.PHONY: all build lib lib-dev cli conform conform-core conform-ext conform-xml conform-md clean

# ── Targets ───────────────────────────────────────────────────────────────────

all: build

build: lib cli

$(TARGET):
	mkdir -p $(TARGET)

# Shared library — production build: size-optimised, stripped
lib: $(TARGET)
	$(V) -cflags "$(PROD_CFLAGS)" -shared -o $(LIB) cx/
	$(STRIP) $(LIB)

# Unoptimised build for local development (faster compile, debuggable)
lib-dev: $(TARGET)
	$(V) -shared -o $(LIB) cx/

# CLI binary — production
cli: $(TARGET)
	$(V) -cflags "$(PROD_CFLAGS)" -o $(CLI) cmd/
	$(STRIP) $(CLI)

# ── Conformance ───────────────────────────────────────────────────────────────

conform: conform-core conform-ext conform-xml conform-md

conform-core:
	@echo "── core.txt ──────────────────────────────────────────────────────────"
	$(V) run tests/conformance_run.v $(CONFORMANCE_CORE)

conform-ext:
	@echo "── extended.txt ──────────────────────────────────────────────────────"
	$(V) run tests/conformance_run.v $(CONFORMANCE_EXT)

conform-xml:
	@echo "── xml.txt ───────────────────────────────────────────────────────────"
	$(V) run tests/conformance_run.v $(CONFORMANCE_XML)

conform-md:
	@echo "── md.txt ────────────────────────────────────────────────────────────"
	$(V) run tests/conformance_run.v $(CONFORMANCE_MD)

conform-all:
	@echo "── all suites ────────────────────────────────────────────────────────"
	$(V) run tests/conformance_run.v

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -rf $(TARGET)
