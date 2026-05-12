.PHONY: all clean version help
.PHONY: build-amd64 build-arm64
.PHONY: tarballs-amd64 tarballs-arm64
.PHONY: deb-amd64 deb-arm64 rpm-amd64 rpm-arm64
.PHONY: packages-amd64 packages-arm64

# Version from git tag (consolidated nb-cli/* tags for all platforms)
VERSION := $(shell git describe --tags --match 'nb-cli/*' --always --dirty 2>/dev/null | sed 's|^nb-cli/||' || echo "0.0.1")

# RPM-safe version: fpm converts dashes to underscores in --version,
# but NOT in --depends, so we must do it ourselves for consistency.
RPM_VERSION := $(subst -,_,$(VERSION))

# Directories
BUILD_DIR := build
CLI_DIR := ../..

all: build-amd64 build-arm64

# =============================================================================
# Build Targets
# =============================================================================

build-amd64:
	@echo "Building all components for linux/amd64..."
	@mkdir -p $(BUILD_DIR)/amd64
	# nb CLI
	cd $(CLI_DIR) && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w -X github.com/naughtbot/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/linux/$(BUILD_DIR)/amd64/nb ./cmd/nb
	# age-plugin-nb
	cd $(CLI_DIR) && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w -X github.com/naughtbot/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/linux/$(BUILD_DIR)/amd64/age-plugin-nb ./cmd/age-plugin-nb
	# sk-provider
	cd $(CLI_DIR)/sk-provider && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/linux/$(BUILD_DIR)/amd64/libnb-sk.so .
	@rm -f $(BUILD_DIR)/amd64/libnb-sk.h
	# pkcs11-provider
	cd $(CLI_DIR)/pkcs11-provider && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/linux/$(BUILD_DIR)/amd64/libnb-pkcs11.so .
	@rm -f $(BUILD_DIR)/amd64/libnb-pkcs11.h

build-arm64:
	@echo "Building all components for linux/arm64..."
	@mkdir -p $(BUILD_DIR)/arm64
	# nb CLI (requires cross-compiler for CGo/BBS+ FFI)
	cd $(CLI_DIR) && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build \
		-ldflags="-s -w -X github.com/naughtbot/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/linux/$(BUILD_DIR)/arm64/nb ./cmd/nb
	# age-plugin-nb (requires cross-compiler for CGo/BBS+ FFI)
	cd $(CLI_DIR) && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build \
		-ldflags="-s -w -X github.com/naughtbot/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/linux/$(BUILD_DIR)/arm64/age-plugin-nb ./cmd/age-plugin-nb
	# sk-provider (requires cross-compiler)
	cd $(CLI_DIR)/sk-provider && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/linux/$(BUILD_DIR)/arm64/libnb-sk.so .
	@rm -f $(BUILD_DIR)/arm64/libnb-sk.h
	# pkcs11-provider (requires cross-compiler)
	cd $(CLI_DIR)/pkcs11-provider && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/linux/$(BUILD_DIR)/arm64/libnb-pkcs11.so .
	@rm -f $(BUILD_DIR)/arm64/libnb-pkcs11.h

# =============================================================================
# Component Tarballs (for Homebrew Formula)
# =============================================================================

tarballs-amd64: build-amd64
	@echo "Creating amd64 component tarballs..."
	@mkdir -p $(BUILD_DIR)/tarballs
	# nb tarball
	@mkdir -p $(BUILD_DIR)/nb-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/amd64/nb $(BUILD_DIR)/nb-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-$(VERSION)-linux-amd64.tar.gz nb-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/nb-$(VERSION)-linux-amd64
	# nb-sk-provider tarball
	@mkdir -p $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/amd64/libnb-sk.so $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-sk-provider-$(VERSION)-linux-amd64.tar.gz nb-sk-provider-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-amd64
	# nb-pkcs11 tarball
	@mkdir -p $(BUILD_DIR)/nb-pkcs11-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/amd64/libnb-pkcs11.so $(BUILD_DIR)/nb-pkcs11-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-pkcs11-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-pkcs11-$(VERSION)-linux-amd64.tar.gz nb-pkcs11-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/nb-pkcs11-$(VERSION)-linux-amd64
	# nb-age-plugin tarball
	@mkdir -p $(BUILD_DIR)/nb-age-plugin-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/amd64/age-plugin-nb $(BUILD_DIR)/nb-age-plugin-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-age-plugin-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-age-plugin-$(VERSION)-linux-amd64.tar.gz nb-age-plugin-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/nb-age-plugin-$(VERSION)-linux-amd64
	@echo "Created component tarballs in $(BUILD_DIR)/tarballs/"

tarballs-arm64: build-arm64
	@echo "Creating arm64 component tarballs..."
	@mkdir -p $(BUILD_DIR)/tarballs
	# nb tarball
	@mkdir -p $(BUILD_DIR)/nb-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/arm64/nb $(BUILD_DIR)/nb-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-$(VERSION)-linux-arm64.tar.gz nb-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/nb-$(VERSION)-linux-arm64
	# nb-sk-provider tarball
	@mkdir -p $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/arm64/libnb-sk.so $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-sk-provider-$(VERSION)-linux-arm64.tar.gz nb-sk-provider-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-arm64
	# nb-pkcs11 tarball
	@mkdir -p $(BUILD_DIR)/nb-pkcs11-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/arm64/libnb-pkcs11.so $(BUILD_DIR)/nb-pkcs11-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-pkcs11-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-pkcs11-$(VERSION)-linux-arm64.tar.gz nb-pkcs11-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/nb-pkcs11-$(VERSION)-linux-arm64
	# nb-age-plugin tarball
	@mkdir -p $(BUILD_DIR)/nb-age-plugin-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/arm64/age-plugin-nb $(BUILD_DIR)/nb-age-plugin-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-age-plugin-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/nb-age-plugin-$(VERSION)-linux-arm64.tar.gz nb-age-plugin-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/nb-age-plugin-$(VERSION)-linux-arm64
	@echo "Created component tarballs in $(BUILD_DIR)/tarballs/"

# =============================================================================
# Component deb/rpm Packages (with dependencies)
# =============================================================================

deb-amd64: build-amd64
	@echo "Creating amd64 deb packages..."
	# nb (CLI binary)
	fpm -s dir -t deb --architecture amd64 \
		--name nb \
		--version $(VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "NaughtBot CLI for hardware-backed signing" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends libc6 \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/nb=/usr/local/bin/nb
	# nb-sk-provider
	fpm -s dir -t deb --architecture amd64 \
		--name nb-sk-provider \
		--version $(VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "SSH SecurityKey provider for NaughtBot (software keys)" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(VERSION)" \
		--depends libc6 \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/libnb-sk.so=/usr/local/lib/libnb-sk.so
	# nb-pkcs11
	fpm -s dir -t deb --architecture amd64 \
		--name nb-pkcs11 \
		--version $(VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "PKCS#11 provider for NaughtBot (hardware keys)" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(VERSION)" \
		--depends libc6 \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/libnb-pkcs11.so=/usr/local/lib/libnb-pkcs11.so
	# nb-age-plugin
	fpm -s dir -t deb --architecture amd64 \
		--name nb-age-plugin \
		--version $(VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "Age encryption plugin for NaughtBot" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(VERSION)" \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/age-plugin-nb=/usr/local/bin/age-plugin-nb
	@echo "Created deb packages in $(BUILD_DIR)/"

deb-arm64: build-arm64
	@echo "Creating arm64 deb packages..."
	# nb (CLI binary)
	fpm -s dir -t deb --architecture arm64 \
		--name nb \
		--version $(VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "NaughtBot CLI for hardware-backed signing" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends libc6 \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/nb=/usr/local/bin/nb
	# nb-sk-provider
	fpm -s dir -t deb --architecture arm64 \
		--name nb-sk-provider \
		--version $(VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "SSH SecurityKey provider for NaughtBot (software keys)" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(VERSION)" \
		--depends libc6 \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/libnb-sk.so=/usr/local/lib/libnb-sk.so
	# nb-pkcs11
	fpm -s dir -t deb --architecture arm64 \
		--name nb-pkcs11 \
		--version $(VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "PKCS#11 provider for NaughtBot (hardware keys)" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(VERSION)" \
		--depends libc6 \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/libnb-pkcs11.so=/usr/local/lib/libnb-pkcs11.so
	# nb-age-plugin
	fpm -s dir -t deb --architecture arm64 \
		--name nb-age-plugin \
		--version $(VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "Age encryption plugin for NaughtBot" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(VERSION)" \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/age-plugin-nb=/usr/local/bin/age-plugin-nb
	@echo "Created deb packages in $(BUILD_DIR)/"

rpm-amd64: build-amd64
	@echo "Creating x86_64 rpm packages..."
	# nb (CLI binary)
	fpm -s dir -t rpm --architecture x86_64 \
		--name nb \
		--version $(RPM_VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "NaughtBot CLI for hardware-backed signing" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends glibc \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/nb=/usr/local/bin/nb
	# nb-sk-provider
	fpm -s dir -t rpm --architecture x86_64 \
		--name nb-sk-provider \
		--version $(RPM_VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "SSH SecurityKey provider for NaughtBot (software keys)" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(RPM_VERSION)" \
		--depends glibc \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/libnb-sk.so=/usr/local/lib/libnb-sk.so
	# nb-pkcs11
	fpm -s dir -t rpm --architecture x86_64 \
		--name nb-pkcs11 \
		--version $(RPM_VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "PKCS#11 provider for NaughtBot (hardware keys)" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(RPM_VERSION)" \
		--depends glibc \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/libnb-pkcs11.so=/usr/local/lib/libnb-pkcs11.so
	# nb-age-plugin
	fpm -s dir -t rpm --architecture x86_64 \
		--name nb-age-plugin \
		--version $(RPM_VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "Age encryption plugin for NaughtBot" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(RPM_VERSION)" \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/age-plugin-nb=/usr/local/bin/age-plugin-nb
	@echo "Created rpm packages in $(BUILD_DIR)/"

rpm-arm64: build-arm64
	@echo "Creating aarch64 rpm packages..."
	# nb (CLI binary)
	fpm -s dir -t rpm --architecture aarch64 \
		--name nb \
		--version $(RPM_VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "NaughtBot CLI for hardware-backed signing" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends glibc \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/nb=/usr/local/bin/nb
	# nb-sk-provider
	fpm -s dir -t rpm --architecture aarch64 \
		--name nb-sk-provider \
		--version $(RPM_VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "SSH SecurityKey provider for NaughtBot (software keys)" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(RPM_VERSION)" \
		--depends glibc \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/libnb-sk.so=/usr/local/lib/libnb-sk.so
	# nb-pkcs11
	fpm -s dir -t rpm --architecture aarch64 \
		--name nb-pkcs11 \
		--version $(RPM_VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "PKCS#11 provider for NaughtBot (hardware keys)" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(RPM_VERSION)" \
		--depends glibc \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/libnb-pkcs11.so=/usr/local/lib/libnb-pkcs11.so
	# nb-age-plugin
	fpm -s dir -t rpm --architecture aarch64 \
		--name nb-age-plugin \
		--version $(RPM_VERSION) \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "Age encryption plugin for NaughtBot" \
		--url "https://github.com/naughtbot/cli" \
		--license "MIT" \
		--depends "nb = $(RPM_VERSION)" \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/age-plugin-nb=/usr/local/bin/age-plugin-nb
	@echo "Created rpm packages in $(BUILD_DIR)/"

# =============================================================================
# Combined Targets
# =============================================================================

packages-amd64: tarballs-amd64 deb-amd64 rpm-amd64
packages-arm64: tarballs-arm64 deb-arm64 rpm-arm64

# =============================================================================
# Utility Targets
# =============================================================================

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

version:
	@echo $(VERSION)

help:
	@echo "NaughtBot CLI Linux Packaging"
	@echo ""
	@echo "Build Targets:"
	@echo "  build-amd64        Build all components for x86_64"
	@echo "  build-arm64        Build all components for arm64"
	@echo ""
	@echo "Package Targets:"
	@echo "  tarballs-amd64     Create amd64 component tarballs"
	@echo "  tarballs-arm64     Create arm64 component tarballs"
	@echo "  deb-amd64          Create amd64 component debs"
	@echo "  deb-arm64          Create arm64 component debs"
	@echo "  rpm-amd64          Create x86_64 component rpms"
	@echo "  rpm-arm64          Create aarch64 component rpms"
	@echo "  packages-amd64     Create all amd64 packages"
	@echo "  packages-arm64     Create all arm64 packages"
	@echo ""
	@echo "Utility Targets:"
	@echo "  clean              Remove build artifacts"
	@echo "  version            Show current version"
	@echo ""
	@echo "Dependencies:"
	@echo "  sudo apt install gcc-aarch64-linux-gnu  # For arm64 cross-compilation"
	@echo "  sudo gem install fpm                    # For deb/rpm packages"
