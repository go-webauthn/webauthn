.PHONY: docs install-pkgsite help

PORT ?= 3030
URL  := http://127.0.0.1:$(PORT)

help:
	@echo "Targets:"
	@echo "  docs             Launch pkgsite on port $(PORT)"
	@echo "  install-pkgsite  Install pkgsite"

docs:
	@command -v pkgsite >/dev/null 2>&1 || { \
		echo "pkgsite not found. Run: make install-pkgsite"; \
		exit 1; \
	}
	@echo
	@echo "  Docs: $(URL)"
	@echo
	@pkgsite -http 127.0.0.1:$(PORT)

install-pkgsite:
	go install golang.org/x/pkgsite/cmd/pkgsite@latest