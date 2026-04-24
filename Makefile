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

test:
	$(V) test tests/
