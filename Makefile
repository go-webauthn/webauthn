.PHONY: docs install-pkgsite help

PORT ?= 3030
URL  := http://127.0.0.1:$(PORT)
PKGSITE_BIN ?= $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)/pkgsite

help:
	@echo "Targets:"
	@echo "  docs             Launch pkgsite on port $(PORT)"
	@echo "  install-pkgsite  Install pkgsite"

docs:
	@bin="$(PKGSITE_BIN)"; \
	case "$$bin" in \
		*/*) [ -x "$$bin" ] || bin="$$(command -v pkgsite 2>/dev/null)" ;; \
		*)   bin="$$(command -v "$$bin" 2>/dev/null)" ;; \
	esac; \
	if [ -z "$$bin" ] || [ ! -x "$$bin" ]; then \
		echo "pkgsite not found (tried $(PKGSITE_BIN) and PATH). Run: make install-pkgsite (or pass PKGSITE_BIN=/path/to/pkgsite)"; \
		exit 1; \
	fi; \
	exec "$$bin" -http 127.0.0.1:$(PORT)

install-pkgsite:
	go install golang.org/x/pkgsite/cmd/pkgsite@latest