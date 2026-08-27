.PHONY: docs fuzz help install-pkgsite

PORT     ?= 3030
FUZZTIME ?= 30s
URL  := http://127.0.0.1:$(PORT)
PKGSITE_BIN ?= $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)/pkgsite

help:
	@echo "Targets:"
	@echo "  docs             Launch pkgsite on port $(PORT)"
	@echo "  fuzz             Run every fuzz target for FUZZTIME each (currently $(FUZZTIME))"
	@echo "  install-pkgsite  Install pkgsite"

release:
	conventional-changelog -i CHANGELOG.md -o CHANGELOG.md -p angular -r 2

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

# The targets are discovered from the test binaries rather than listed, so a fuzz target added to any package is run
# without this having to be edited. Discovery failing is fatal, as a package which does not build would otherwise be
# reported as a package with no fuzz targets; a package which builds and has none is not an error. The test binary
# timeout is disabled because it would otherwise expire before a FUZZTIME longer than its default, reporting a panic
# in place of the result.
#
# The seed corpus of every target already runs as part of `go test ./...`; this is the search.
fuzz:
	@pkgs=$$(go list ./...) || exit 1; \
	for pkg in $$pkgs; do \
		listed=$$(go test -list '^Fuzz' "$$pkg") || exit 1; \
		for target in $$(printf '%s\n' "$$listed" | grep '^Fuzz' || true); do \
			echo "==> $$target ($$pkg)"; \
			go test -run '^$$' -fuzz "^$$target$$" -fuzztime '$(FUZZTIME)' -timeout 0 "$$pkg" || exit 1; \
		done; \
	done
