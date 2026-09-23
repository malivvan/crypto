# Makefile for github.com/malivvan/crypto/ssh

GO ?= go

.PHONY: help fmt lint lint-fix test tidy release fetch-tags

## help: display available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -E 's/^## ([a-zA-Z_-]+): (.*)/\1: \2/'

## fmt: format the code with gofmt
fmt:
	gofmt -w .

## lint: run the linters
lint:
	golangci-lint run

## lint-fix: run the linters and apply automatic fixes
lint-fix:
	golangci-lint run --fix

## test: run the test suite (pass extra arguments via ARGS)
test:
	$(GO) test -race ./... $(ARGS)

## tidy: run go mod tidy
tidy:
	$(GO) mod tidy

## release: create and push a new tag following semver
release:
	@test "$$(git symbolic-ref --short HEAD)" = "master" || { echo "Not on master branch"; exit 1; }
	@test "$$(git status --porcelain=2 | wc -l)" = "0" || { echo "Git is dirty"; exit 1; }
	@gh run list --workflow go.yml --commit $$(git rev-parse HEAD) --status success --json conclusion -q ".[0].conclusion" | grep -q success || { echo "Test build for this commit failed or not present"; exit 1; }
	@$(MAKE) fetch-tags
	@NEXT="$$(svu next --always || $(GO) run github.com/caarlos0/svu/v3@latest next --always)"; \
	echo "Releasing $$NEXT..."; \
	git commit --allow-empty -m "$$NEXT" && \
	git tag --annotate --sign -m "$$NEXT" "$$NEXT" $(ARGS) && \
	git push origin master --follow-tags

## fetch-tags: fetch tags from the remote
fetch-tags:
	git fetch --tags
