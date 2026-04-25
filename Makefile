.PHONY: docs install-pkgsite help

PORT ?= 3030
URL  := http://127.0.0.1:$(PORT)
PKGSITE_BIN ?= $(shell go env GOPATH)/bin/pkgsite

help:
	@echo "Targets:"
	@echo "  docs             Launch pkgsite on port $(PORT)"
	@echo "  install-pkgsite  Install pkgsite"

docs:
	@{ [ -x "$(PKGSITE_BIN)" ] || command -v "$(PKGSITE_BIN)" >/dev/null 2>&1; } || { \
		echo "pkgsite not found at $(PKGSITE_BIN). Run: make install-pkgsite (or pass PKGSITE_BIN=/path/to/pkgsite)"; \
		exit 1; \
	}
	@echo
	@echo "  Docs: $(URL)"
	@echo
	@$(PKGSITE_BIN) -http 127.0.0.1:$(PORT)

install-pkgsite:
	go install golang.org/x/pkgsite/cmd/pkgsite@latest