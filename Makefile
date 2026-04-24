SHELL  := /bin/bash
V      := v
PREFIX ?= $(HOME)/.local/bin

.PHONY: install uninstall test

install:
	@mkdir -p $(PREFIX)
	$(V) -prod -o $(PREFIX)/cx cmd/main.v
	@echo "installed: $(PREFIX)/cx"
	@echo "make sure $(PREFIX) is on your PATH"

uninstall:
	rm -f $(PREFIX)/cx
	@echo "removed: $(PREFIX)/cx"

# v test needs to resolve `import cx` to this repo.
# We create a temporary _modules/cx symlink pointing here so VMODULES
# works regardless of what the shell has set for VMODULES.
test:
	@mkdir -p _modules && ln -sfn $$(pwd) _modules/cx
	@VMODULES=$$(pwd)/_modules $(V) test tests/; STATUS=$$?; rm -rf _modules; exit $$STATUS
