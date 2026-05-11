.PHONY: all deb-amd64 deb-arm64 rpm-amd64 rpm-arm64 packages-amd64 packages-arm64 clean

# Version from git tag
VERSION := $(shell git describe --tags --match 'cli/*' --always --dirty 2>/dev/null | sed 's|^cli/||' || echo "0.0.1")

# Directories
BUILD_DIR := build

# This is a meta-package that only declares dependencies on the other packages.
# It doesn't contain any files itself - it just pulls in all the other components.

all: packages-amd64 packages-arm64

# === Debian meta-packages ===

deb-amd64:
	@echo "Creating nb amd64 deb meta-package..."
	@mkdir -p $(BUILD_DIR)
	fpm -s empty -t deb \
		--name nb \
		--version $(VERSION) \
		--architecture amd64 \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "Complete NaughtBot CLI suite (meta-package)" \
		--url "https://github.com/nb/nb" \
		--license "MIT" \
		--depends "nb-cli = $(VERSION)" \
		--depends "nb-sk-provider = $(VERSION)" \
		--depends "nb-pkcs11 = $(VERSION)" \
		--depends "nb-age-plugin = $(VERSION)" \
		--package $(BUILD_DIR)/
	@echo "Created: $(BUILD_DIR)/nb_$(VERSION)_amd64.deb"

deb-arm64:
	@echo "Creating nb arm64 deb meta-package..."
	@mkdir -p $(BUILD_DIR)
	fpm -s empty -t deb \
		--name nb \
		--version $(VERSION) \
		--architecture arm64 \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "Complete NaughtBot CLI suite (meta-package)" \
		--url "https://github.com/nb/nb" \
		--license "MIT" \
		--depends "nb-cli = $(VERSION)" \
		--depends "nb-sk-provider = $(VERSION)" \
		--depends "nb-pkcs11 = $(VERSION)" \
		--depends "nb-age-plugin = $(VERSION)" \
		--package $(BUILD_DIR)/
	@echo "Created: $(BUILD_DIR)/nb_$(VERSION)_arm64.deb"

# === RPM meta-packages ===

rpm-amd64:
	@echo "Creating nb x86_64 rpm meta-package..."
	@mkdir -p $(BUILD_DIR)
	fpm -s empty -t rpm \
		--name nb \
		--version $(VERSION) \
		--architecture x86_64 \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "Complete NaughtBot CLI suite (meta-package)" \
		--url "https://github.com/nb/nb" \
		--license "MIT" \
		--depends "nb-cli = $(VERSION)" \
		--depends "nb-sk-provider = $(VERSION)" \
		--depends "nb-pkcs11 = $(VERSION)" \
		--depends "nb-age-plugin = $(VERSION)" \
		--package $(BUILD_DIR)/
	@echo "Created: $(BUILD_DIR)/nb-$(VERSION)-1.x86_64.rpm"

rpm-arm64:
	@echo "Creating nb aarch64 rpm meta-package..."
	@mkdir -p $(BUILD_DIR)
	fpm -s empty -t rpm \
		--name nb \
		--version $(VERSION) \
		--architecture aarch64 \
		--maintainer "NaughtBot <hello@naughtbot.com>" \
		--description "Complete NaughtBot CLI suite (meta-package)" \
		--url "https://github.com/nb/nb" \
		--license "MIT" \
		--depends "nb-cli = $(VERSION)" \
		--depends "nb-sk-provider = $(VERSION)" \
		--depends "nb-pkcs11 = $(VERSION)" \
		--depends "nb-age-plugin = $(VERSION)" \
		--package $(BUILD_DIR)/
	@echo "Created: $(BUILD_DIR)/nb-$(VERSION)-1.aarch64.rpm"

# === Combined targets ===

packages-amd64: deb-amd64 rpm-amd64
packages-arm64: deb-arm64 rpm-arm64

clean:
	rm -rf $(BUILD_DIR)

version:
	@echo $(VERSION)
