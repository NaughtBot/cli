.PHONY: build test coverage clean sk-provider pkcs11-provider lint format release ensure-attested-key-zk-static-lib install

# ── VERSION resolution ─────────────────────────────────────
# Supports: make release VERSION=1.2.3 | VERSION=patch | VERSION=minor | VERSION=major
ifdef VERSION
  ifneq ($(filter v%,$(VERSION)),)
    $(error VERSION must not start with 'v' — the prefix is added automatically. Usage: make release VERSION=1.2.3)
  endif
  ifneq ($(filter patch minor major,$(VERSION)),)
    _LATEST_TAG := $(shell git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0)
    _LATEST_VER := $(patsubst v%,%,$(_LATEST_TAG))
    _VER_PARTS  := $(subst ., ,$(_LATEST_VER))
    _CUR_MAJOR  := $(or $(word 1,$(_VER_PARTS)),0)
    _CUR_MINOR  := $(or $(word 2,$(_VER_PARTS)),0)
    _CUR_PATCH  := $(or $(word 3,$(_VER_PARTS)),0)
    ifeq ($(VERSION),patch)
      override VERSION := $(_CUR_MAJOR).$(_CUR_MINOR).$(shell echo $$(($(_CUR_PATCH) + 1)))
    else ifeq ($(VERSION),minor)
      override VERSION := $(_CUR_MAJOR).$(shell echo $$(($(_CUR_MINOR) + 1))).0
    else ifeq ($(VERSION),major)
      override VERSION := $(shell echo $$(($(_CUR_MAJOR) + 1))).0.0
    endif
  endif
  ifeq ($(shell echo '$(VERSION)' | grep -cE '^[0-9]+\.[0-9]+\.[0-9]+$$'),0)
    $(error Invalid VERSION '$(VERSION)'. Must be semver X.Y.Z (e.g. 1.2.3) or bump keyword (patch|minor|major))
  endif
endif
# ────────────────────────────────────────────────────────────

# Opt in to development-only attestation bypass support with `make DEV=1 ...`.
# Default binaries keep attestation enforcement enabled.
DEV ?= 0
GO_LDFLAGS =
ifeq ($(DEV),1)
GO_LDFLAGS += -X github.com/naughtbot/cli/internal/shared/transport.AllowSkipAttestation=true
endif

# Build the CLI binary and all components
build: sk-provider pkcs11-provider age-plugin-nb
	go build -ldflags="$(GO_LDFLAGS)" -o nb ./cmd/nb

# Build the age plugin binary
age-plugin-nb:
	go build -ldflags="$(GO_LDFLAGS)" -o age-plugin-nb ./cmd/age-plugin-nb

# Build the sk-provider shared library
sk-provider:
	$(MAKE) -C sk-provider

# Build the pkcs11-provider shared library
pkcs11-provider:
	$(MAKE) -C pkcs11-provider

ensure-attested-key-zk-static-lib:
	@if [ -f ../attested-key-zk/build/libattested_key_zk.a ] && \
	    [ -f ../attested-key-zk/include/attested_key_zk/approval_proof_v1_zk.h ]; then \
		echo "==> attested-key-zk static lib already built, skipping"; \
	else \
		$(MAKE) -C ../attested-key-zk static-lib; \
	fi

# Run tests
test: ensure-attested-key-zk-static-lib
	go test ./...

# Run tests with coverage
coverage: ensure-attested-key-zk-static-lib
	go test -coverprofile=coverage.out.tmp ./...
	grep -v -E '/gen/|/gen\.go:' coverage.out.tmp > coverage.out
	rm -f coverage.out.tmp
	@echo "Per-package coverage:"
	@go tool cover -func=coverage.out | awk '/^total:/{next} { f=$$1; sub(/:.*/, "", f); n=split(f,a,"/"); f=a[1]; for(i=2;i<n;i++) f=f"/"a[i]; pct=$$NF; sub(/%/,"",pct); s[f]+=pct+0; c[f]++ } END { for(p in s) printf "  %-60s %.1f%%\n", p, s[p]/c[p] }' | sort
	@echo ""
	@go tool cover -func=coverage.out | tail -1

# Lint
lint:
	go vet ./...
	$(MAKE) -C sk-provider lint
	$(MAKE) -C pkcs11-provider lint

# Format (excludes generated code and sub-provider directories)
format:
	gofmt -w $(shell find . -name '*.go' ! -path '*/gen/*' ! -name 'gen.go' ! -name '*_gen.go' ! -name '*.gen.go' ! -path '*/sk-provider/*' ! -path '*/pkcs11-provider/*')
	$(MAKE) -C sk-provider format
	$(MAKE) -C pkcs11-provider format

# Release: tag and push (CI builds binaries and creates GitHub Release)
# Usage: make release VERSION=0.2.0
release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=1.2.3 (or patch|minor|major))
endif
	@echo "Releasing v$(VERSION)$(if $(_LATEST_VER), (was v$(_LATEST_VER)),)"
	git tag v$(VERSION)
	git push origin v$(VERSION)

# Clean build artifacts
clean:
	rm -f nb age-plugin-nb
	$(MAKE) -C sk-provider clean
	$(MAKE) -C pkcs11-provider clean

install: build
	cp nb /usr/local/bin/nb
	cp age-plugin-nb /usr/local/bin/age-plugin-nb
	$(MAKE) -C sk-provider install
	$(MAKE) -C pkcs11-provider install
