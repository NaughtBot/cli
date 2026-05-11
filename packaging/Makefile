.PHONY: all build-arm64 sign pkg pkg-sign notarize release tarballs clean

# Version from git tag (consolidated nb-cli/* tags for all platforms)
VERSION := $(shell git describe --tags --match 'nb-cli/*' --always --dirty 2>/dev/null | sed 's|^nb-cli/||' || echo "0.0.1")
PKG_IDENTIFIER := com.naughtbot.cli
PKG_NAME := NaughtBot-CLI-$(VERSION)-arm64.pkg

# Directories
BUILD_DIR := build
ARM64_DIR := $(BUILD_DIR)/arm64
PKG_ROOT := $(BUILD_DIR)/pkg-root
CLI_DIR := ..
COMPONENTS_DIR := components

# Code signing identities (set via environment variables)
APPLE_DEVELOPER_ID_APP ?=
APPLE_DEVELOPER_ID_INSTALLER ?=
APPLE_ID ?=
APPLE_APP_PASSWORD ?=
APPLE_TEAM_ID ?=

all: build-arm64

# =============================================================================
# Complete Bundle Build (for .pkg / Cask)
# =============================================================================

# Build ARM64 binaries for complete bundle
build-arm64: $(ARM64_DIR)/nb $(ARM64_DIR)/libnb-sk.dylib $(ARM64_DIR)/libnb-pkcs11.dylib $(ARM64_DIR)/age-plugin-nb

$(ARM64_DIR)/nb:
	@echo "Building nb CLI for arm64..."
	@mkdir -p $(ARM64_DIR)
	cd $(CLI_DIR) && GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w -X github.com/naughtbot/cli/internal/shared/version.Version=$(VERSION)" -o packaging/$(ARM64_DIR)/nb ./cmd/nb

$(ARM64_DIR)/libnb-sk.dylib:
	@echo "Building sk-provider for arm64..."
	@mkdir -p $(ARM64_DIR)
	cd $(CLI_DIR)/sk-provider && CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -buildmode=c-shared -ldflags="-s -w -X main.version=$(VERSION)" -o ../packaging/$(ARM64_DIR)/libnb-sk.dylib .
	@rm -f $(ARM64_DIR)/libnb-sk.h

$(ARM64_DIR)/libnb-pkcs11.dylib:
	@echo "Building pkcs11-provider for arm64..."
	@mkdir -p $(ARM64_DIR)
	cd $(CLI_DIR)/pkcs11-provider && CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -buildmode=c-shared -ldflags="-s -w -X main.version=$(VERSION)" -o ../packaging/$(ARM64_DIR)/libnb-pkcs11.dylib .
	@rm -f $(ARM64_DIR)/libnb-pkcs11.h

$(ARM64_DIR)/age-plugin-nb:
	@echo "Building age-plugin-nb for arm64..."
	@mkdir -p $(ARM64_DIR)
	cd $(CLI_DIR) && GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w -X github.com/naughtbot/cli/internal/shared/version.Version=$(VERSION)" -o packaging/$(ARM64_DIR)/age-plugin-nb ./cmd/age-plugin-nb

# Sign binaries with Developer ID Application certificate
sign: build-arm64
ifndef APPLE_DEVELOPER_ID_APP
	$(error APPLE_DEVELOPER_ID_APP is not set. Set it to your "Developer ID Application: ..." certificate name)
endif
	@echo "Signing binaries..."
	codesign --sign "$(APPLE_DEVELOPER_ID_APP)" \
		--options runtime \
		--timestamp \
		--force \
		$(ARM64_DIR)/nb
	codesign --sign "$(APPLE_DEVELOPER_ID_APP)" \
		--options runtime \
		--timestamp \
		--force \
		$(ARM64_DIR)/libnb-sk.dylib
	codesign --sign "$(APPLE_DEVELOPER_ID_APP)" \
		--options runtime \
		--timestamp \
		--force \
		$(ARM64_DIR)/libnb-pkcs11.dylib
	codesign --sign "$(APPLE_DEVELOPER_ID_APP)" \
		--options runtime \
		--timestamp \
		--force \
		$(ARM64_DIR)/age-plugin-nb
	@echo "Verifying signatures..."
	codesign --verify --verbose $(ARM64_DIR)/nb
	codesign --verify --verbose $(ARM64_DIR)/libnb-sk.dylib
	codesign --verify --verbose $(ARM64_DIR)/libnb-pkcs11.dylib
	codesign --verify --verbose $(ARM64_DIR)/age-plugin-nb

# Create package root structure
$(PKG_ROOT): build-arm64
	@echo "Creating package root..."
	@rm -rf $(PKG_ROOT)
	@mkdir -p $(PKG_ROOT)/usr/local/bin
	@mkdir -p $(PKG_ROOT)/usr/local/lib
	cp $(ARM64_DIR)/nb $(PKG_ROOT)/usr/local/bin/
	cp $(ARM64_DIR)/age-plugin-nb $(PKG_ROOT)/usr/local/bin/
	cp $(ARM64_DIR)/libnb-sk.dylib $(PKG_ROOT)/usr/local/lib/
	cp $(ARM64_DIR)/libnb-pkcs11.dylib $(PKG_ROOT)/usr/local/lib/

# Create unsigned .pkg
pkg: $(PKG_ROOT)
	@echo "Creating component package..."
	@mkdir -p $(BUILD_DIR)
	pkgbuild --root $(PKG_ROOT) \
		--identifier $(PKG_IDENTIFIER) \
		--version $(VERSION) \
		--scripts scripts \
		--install-location / \
		$(BUILD_DIR)/nb-cli-component.pkg
	@echo "Creating product archive..."
	productbuild --distribution distribution.xml \
		--package-path $(BUILD_DIR) \
		--resources resources \
		$(BUILD_DIR)/$(PKG_NAME).unsigned.pkg
	@echo "Created: $(BUILD_DIR)/$(PKG_NAME).unsigned.pkg"

# Sign .pkg with Developer ID Installer certificate
pkg-sign: pkg
ifndef APPLE_DEVELOPER_ID_INSTALLER
	$(error APPLE_DEVELOPER_ID_INSTALLER is not set. Set it to your "Developer ID Installer: ..." certificate name)
endif
	@echo "Signing package..."
	productsign --sign "$(APPLE_DEVELOPER_ID_INSTALLER)" \
		$(BUILD_DIR)/$(PKG_NAME).unsigned.pkg \
		$(BUILD_DIR)/$(PKG_NAME)
	@rm -f $(BUILD_DIR)/$(PKG_NAME).unsigned.pkg
	@echo "Verifying package signature..."
	pkgutil --check-signature $(BUILD_DIR)/$(PKG_NAME)
	@echo "Created: $(BUILD_DIR)/$(PKG_NAME)"

# Notarize and staple
notarize: pkg-sign
ifndef APPLE_ID
	$(error APPLE_ID is not set)
endif
ifndef APPLE_APP_PASSWORD
	$(error APPLE_APP_PASSWORD is not set. Create an app-specific password at appleid.apple.com)
endif
ifndef APPLE_TEAM_ID
	$(error APPLE_TEAM_ID is not set)
endif
	@echo "Submitting for notarization..."
	xcrun notarytool submit $(BUILD_DIR)/$(PKG_NAME) \
		--apple-id "$(APPLE_ID)" \
		--password "$(APPLE_APP_PASSWORD)" \
		--team-id "$(APPLE_TEAM_ID)" \
		--wait
	@echo "Stapling notarization ticket..."
	xcrun stapler staple $(BUILD_DIR)/$(PKG_NAME)
	@echo "Verifying notarization..."
	spctl --assess --type install --verbose $(BUILD_DIR)/$(PKG_NAME)
	@echo "Notarized package ready: $(BUILD_DIR)/$(PKG_NAME)"

# Full release build (build, sign, package, notarize)
release: sign pkg-sign notarize

# Build unsigned package (for testing)
pkg-unsigned: $(PKG_ROOT)
	@echo "Creating unsigned package (for testing)..."
	@mkdir -p $(BUILD_DIR)
	pkgbuild --root $(PKG_ROOT) \
		--identifier $(PKG_IDENTIFIER) \
		--version $(VERSION) \
		--scripts scripts \
		--install-location / \
		$(BUILD_DIR)/nb-cli-component.pkg
	productbuild --distribution distribution.xml \
		--package-path $(BUILD_DIR) \
		--resources resources \
		$(BUILD_DIR)/$(PKG_NAME)
	@echo "Created unsigned package: $(BUILD_DIR)/$(PKG_NAME)"

# =============================================================================
# Component Tarballs (for Homebrew Formula)
# =============================================================================

tarballs: sign
	@echo "Creating darwin-arm64 component tarballs..."
	@mkdir -p $(BUILD_DIR)/tarballs
	# nb tarball
	@mkdir -p $(BUILD_DIR)/nb-$(VERSION)-darwin-arm64
	cp $(ARM64_DIR)/nb $(BUILD_DIR)/nb-$(VERSION)-darwin-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-$(VERSION)-darwin-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-$(VERSION)-darwin-arm64.tar.gz nb-$(VERSION)-darwin-arm64
	@rm -rf $(BUILD_DIR)/nb-$(VERSION)-darwin-arm64
	# nb-sk-provider tarball
	@mkdir -p $(BUILD_DIR)/nb-sk-provider-$(VERSION)-darwin-arm64
	cp $(ARM64_DIR)/libnb-sk.dylib $(BUILD_DIR)/nb-sk-provider-$(VERSION)-darwin-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-sk-provider-$(VERSION)-darwin-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-sk-provider-$(VERSION)-darwin-arm64.tar.gz nb-sk-provider-$(VERSION)-darwin-arm64
	@rm -rf $(BUILD_DIR)/nb-sk-provider-$(VERSION)-darwin-arm64
	# nb-pkcs11 tarball
	@mkdir -p $(BUILD_DIR)/nb-pkcs11-$(VERSION)-darwin-arm64
	cp $(ARM64_DIR)/libnb-pkcs11.dylib $(BUILD_DIR)/nb-pkcs11-$(VERSION)-darwin-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-pkcs11-$(VERSION)-darwin-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-pkcs11-$(VERSION)-darwin-arm64.tar.gz nb-pkcs11-$(VERSION)-darwin-arm64
	@rm -rf $(BUILD_DIR)/nb-pkcs11-$(VERSION)-darwin-arm64
	# nb-age-plugin tarball
	@mkdir -p $(BUILD_DIR)/nb-age-plugin-$(VERSION)-darwin-arm64
	cp $(ARM64_DIR)/age-plugin-nb $(BUILD_DIR)/nb-age-plugin-$(VERSION)-darwin-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-age-plugin-$(VERSION)-darwin-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-age-plugin-$(VERSION)-darwin-arm64.tar.gz nb-age-plugin-$(VERSION)-darwin-arm64
	@rm -rf $(BUILD_DIR)/nb-age-plugin-$(VERSION)-darwin-arm64
	@echo "Created component tarballs in $(BUILD_DIR)/tarballs/"

# =============================================================================
# Utility targets
# =============================================================================

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f $(ARM64_DIR)/*.dylib $(ARM64_DIR)/*.h
	$(MAKE) -C $(COMPONENTS_DIR)/nb clean
	$(MAKE) -C $(COMPONENTS_DIR)/sk-provider clean
	$(MAKE) -C $(COMPONENTS_DIR)/pkcs11 clean
	$(MAKE) -C $(COMPONENTS_DIR)/age-plugin clean
	$(MAKE) -C $(COMPONENTS_DIR)/complete clean

# Show current version
version:
	@echo $(VERSION)

# Help
help:
	@echo "NaughtBot CLI Packaging"
	@echo ""
	@echo "Complete Bundle Targets (for macOS .pkg / Cask):"
	@echo "  build-arm64        Build ARM64 binaries"
	@echo "  sign               Sign binaries (requires APPLE_DEVELOPER_ID_APP)"
	@echo "  pkg                Create unsigned .pkg"
	@echo "  pkg-unsigned       Create unsigned .pkg for testing"
	@echo "  pkg-sign           Create signed .pkg (requires APPLE_DEVELOPER_ID_INSTALLER)"
	@echo "  notarize           Notarize and staple (requires APPLE_ID, APPLE_APP_PASSWORD, APPLE_TEAM_ID)"
	@echo "  release            Full release: sign + pkg-sign + notarize"
	@echo ""
	@echo "Component Tarball Targets (for Homebrew Formula):"
	@echo "  tarballs           Create separate tarballs for each component"
	@echo ""
	@echo "Utility Targets:"
	@echo "  clean              Remove build artifacts"
	@echo "  version            Show current version"
	@echo ""
	@echo "Environment variables for signing:"
	@echo "  APPLE_DEVELOPER_ID_APP       Developer ID Application certificate name"
	@echo "  APPLE_DEVELOPER_ID_INSTALLER Developer ID Installer certificate name"
	@echo "  APPLE_ID                     Apple ID email"
	@echo "  APPLE_APP_PASSWORD           App-specific password"
	@echo "  APPLE_TEAM_ID                Team ID"
