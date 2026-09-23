GO ?= go
GOLANGCI_LINT ?= golangci-lint

.PHONY: all
all: build test vet

.PHONY: build
build:
	$(GO) build ./...

.PHONY: test
test:
	$(GO) test ./...

# Tests with version 5 key support enabled (see README, build tags).
.PHONY: test-v5
test-v5:
	$(GO) test -tags v5 ./...

.PHONY: vet
vet:
	$(GO) vet ./...

# Checks that all first-party files are gofmt-formatted.
.PHONY: fmt
fmt:
	@out="$$(gofmt -l . 2>/dev/null || true)"; if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

# Rewrites all first-party files with gofmt.
.PHONY: fmt-fix
fmt-fix:
	@go list -f '{{.Dir}}' ./... | while read -r d; do d="$${d#$$(pwd)/}"; gofmt -w "$$d"; done

.PHONY: lint
lint:
	@if command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then \
		$(GOLANGCI_LINT) run ./...; \
	else \
		echo "golangci-lint not found; running go vet instead"; \
		$(GO) vet ./...; \
	fi

.PHONY: cover
cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

.PHONY: clean
clean:
	rm -f coverage.out
