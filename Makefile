# Farrier build entry points.
#
# Everything a contributor or CI runs lives here, so that "what does CI do" is answerable by reading one
# file rather than by reading five workflow YAMLs. The workflows in .github/workflows call these targets
# rather than duplicating the commands.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DIST    := dist

# -s -w strip the symbol table and DWARF; the agent ships to other people's servers and there is no
# reason for it to be larger than it needs to be. The version is stamped rather than compiled in from a
# constant so that a build from a tag and a build from a branch are distinguishable in a heartbeat.
LDFLAGS := -s -w \
	-X github.com/pascalgross/farrier/internal/buildinfo.Version=$(VERSION) \
	-X github.com/pascalgross/farrier/internal/buildinfo.Commit=$(COMMIT)

GO_PACKAGES := ./...

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: $(DIST)/farrier-agent $(DIST)/farrier-server $(DIST)/farrier helpers ## Build every binary

$(DIST):
	mkdir -p $(DIST)

$(DIST)/farrier-agent: $(DIST)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/farrier-agent

$(DIST)/farrier-server: $(DIST)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/farrier-server

$(DIST)/farrier: $(DIST)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/farrier

.PHONY: helpers
helpers: $(DIST) ## Build the three root helpers
	@for h in apply-updates restart-unit reboot-host; do \
	  CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/$$h ./helpers/$$h; \
	done

.PHONY: test
test: ## Run unit tests
	go test -race -count=1 $(GO_PACKAGES)

# The module the signing-backend tests drive. libsofthsm2, not softhsm2: the tests build their own
# token through the module's own C_InitToken, C_InitPIN and C_GenerateKeyPair, so the tools package is
# not needed.
.PHONY: test-pkcs11
test-pkcs11: ## Run the PKCS#11 backend against a real module, in the build that ships
	# Twice, deliberately. `make test` runs with cgo because -race requires it, so the path the
	# released binary actually takes — purego's own dlopen, with no cgo — is otherwise never
	# exercised by anything.
	go test -race -count=1 -v ./internal/signing/backend/pkcs11/
	CGO_ENABLED=0 go test -count=1 ./internal/signing/backend/pkcs11/

.PHONY: cover
cover: ## Run unit tests with a coverage profile
	go test -race -count=1 -coverprofile=coverage.txt -covermode=atomic $(GO_PACKAGES)

.PHONY: guarantee
guarantee: guarantee-tests guarantee-fuzz ## Run the tests that enforce docs/SECURITY.md section 1

# Split so that the guarantee workflow can call the two halves as two named steps — which is what puts
# the right failure message at the top of a red run — without restating the commands. The required
# check and `make guarantee` must be the same thing; a workflow that copied the commands could be
# weakened by an edit here that nobody noticed, or strengthened here and never run in CI.
.PHONY: guarantee-tests
guarantee-tests: ## The catalogue is the expected set, and nothing reaches a shell
	# ./... rather than ./internal/...: three guarantee-named tests live under helpers/ and were
	# silently outside the required check, which nothing about their names said.
	go test -count=1 -run '^(TestGuarantee|TestClassPredicates)' -v ./...

.PHONY: guarantee-fuzz
guarantee-fuzz: ## Fuzz the parameter decoders and the canonical encoder, as CI does
	go test -count=1 -run '^$$' -fuzz 'FuzzGuarantee' -fuzztime 60s ./internal/intent/
	go test -count=1 -run '^$$' -fuzz 'FuzzNormalize' -fuzztime 60s ./internal/canonical/

.PHONY: fuzz
fuzz: ## Fuzz both guarantee targets for longer than CI does
	go test -run '^$$' -fuzz 'FuzzGuarantee' -fuzztime 10m ./internal/intent/
	go test -run '^$$' -fuzz 'FuzzNormalize' -fuzztime 10m ./internal/canonical/

.PHONY: site
site: ## Render the documentation site into public/
	go run ./tools/docsite -root . -out public

.PHONY: lint
lint: vet doccheck golangci ## Run every Go linter

.PHONY: vet
vet: ## go vet
	go vet $(GO_PACKAGES)

.PHONY: doccheck
doccheck: ## Enforce a doc comment on every type and function, exported or not
	go run ./tools/doccheck ./cmd ./internal ./helpers ./tools

# The linter version, used by the golangci target and by CI. Pinned rather than @latest: a new linter
# release must be something somebody adopts deliberately, not something that turns every open pull
# request red overnight on a tree nobody touched.
GOLANGCI_VERSION := v2.13.1

.PHONY: golangci-install
golangci-install: ## Install the pinned golangci-lint
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

.PHONY: golangci
golangci: ## golangci-lint, if it is installed
	@if command -v golangci-lint >/dev/null 2>&1; then \
	  golangci-lint run; \
	else \
	  echo "golangci-lint not installed; see https://golangci-lint.run/welcome/install/"; \
	  exit 1; \
	fi

.PHONY: fmt
fmt: ## Format Go source
	gofmt -w $(shell git ls-files '*.go')

.PHONY: fmt-check
fmt-check: ## Fail if any Go source is unformatted
	@unformatted="$$(gofmt -l $$(git ls-files '*.go'))"; \
	if [ -n "$$unformatted" ]; then \
	  echo "these files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: web
web: ## Build the Angular application into the location farrier-server embeds
	cd web && pnpm install --frozen-lockfile && pnpm run build
	find internal/server/assets -mindepth 1 -maxdepth 1 \
	  ! -name .gitignore ! -name PLACEHOLDER.md -exec rm -rf {} +
	cp -r web/dist/. internal/server/assets/

.PHONY: web-lint
web-lint: ## Lint the web application, including the doc-comment rule on private members
	cd web && pnpm install --frozen-lockfile && pnpm exec eslint .

# Every systemd unit the package ships. systemd silently ignores a directive it does not understand, so
# a typo in one of these is a hardening line that is simply absent on every host — which is why the deb
# target verifies them and CI verifies them again with the binaries in place.
UNITS := packaging/farrier-agent.service \
	packaging/farrier-apply-updates.socket packaging/farrier-apply-updates@.service \
	packaging/farrier-restart-unit.socket packaging/farrier-restart-unit@.service \
	packaging/farrier-reboot-host.socket packaging/farrier-reboot-host@.service

.PHONY: units
units: ## Check every packaged systemd unit with systemd-analyze
	systemd-analyze verify $(UNITS)

ARCH ?= $(shell go env GOARCH)
# nfpm insists on a semver version, and `git describe` yields v0.1.0-3-gabc1234 between tags.
DEB_VERSION ?= $(patsubst v%,%,$(VERSION))

# Debian's version ordering has no notion of a prerelease, so nfpm's semver schema encodes the hyphen
# as a tilde — 0.1.0-rc1 becomes 0.1.0~rc1, which sorts *before* 0.1.0 exactly as a prerelease should.
# Anything that needs to name the resulting file has to do the same substitution, and forgetting is a
# glob that silently matches nothing.
DEB_FILE_VERSION = $(subst -,~,$(DEB_VERSION))

.PHONY: deb-path
deb-path: ## Print the .deb path `make deb` would produce, for scripts that need to name it
	@echo "$(DIST)/packages/farrier-agent_$(DEB_FILE_VERSION)_$(ARCH).deb"

.PHONY: deb
deb: build ## Build the farrier-agent .deb
	@command -v nfpm >/dev/null 2>&1 || { echo "nfpm not installed; see https://nfpm.goreleaser.com/install/"; exit 1; }
	@command -v systemd-analyze >/dev/null 2>&1 && systemd-analyze verify $(UNITS) >/dev/null 2>&1 || true
	mkdir -p $(DIST)/packages
	cd packaging && \
	  VERSION="$(DEB_VERSION)" ARCH="$(ARCH)" \
	  nfpm package --packager deb --target "../$(DIST)/packages"

.PHONY: clean
clean: ## Remove build output
	rm -rf $(DIST) coverage.txt

.PHONY: ci
ci: fmt-check vet doccheck test guarantee ## What CI runs, minus the pieces that need extra tooling
