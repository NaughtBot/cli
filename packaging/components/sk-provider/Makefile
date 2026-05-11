.PHONY: all build-darwin-arm64 build-linux-amd64 build-linux-arm64 tarball-darwin-arm64 tarball-linux-amd64 tarball-linux-arm64 clean

# Version from git tag
VERSION := $(shell git describe --tags --match 'nb-cli/*' --always --dirty 2>/dev/null | sed 's|^nb-cli/||' || echo "0.0.1")

# Directories
BUILD_DIR := build
CLI_DIR := ../../..

all: build-darwin-arm64

# === Build targets ===

build-darwin-arm64:
	@echo "Building sk-provider for darwin/arm64..."
	@mkdir -p $(BUILD_DIR)/darwin-arm64
	cd $(CLI_DIR)/sk-provider && CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/components/sk-provider/$(BUILD_DIR)/darwin-arm64/libnb-sk.dylib .
	@rm -f $(BUILD_DIR)/darwin-arm64/libnb-sk.h

build-linux-amd64:
	@echo "Building sk-provider for linux/amd64..."
	@mkdir -p $(BUILD_DIR)/linux-amd64
	cd $(CLI_DIR)/sk-provider && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/components/sk-provider/$(BUILD_DIR)/linux-amd64/libnb-sk.so .
	@rm -f $(BUILD_DIR)/linux-amd64/libnb-sk.h

build-linux-arm64:
	@echo "Building sk-provider for linux/arm64..."
	@mkdir -p $(BUILD_DIR)/linux-arm64
	cd $(CLI_DIR)/sk-provider && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/components/sk-provider/$(BUILD_DIR)/linux-arm64/libnb-sk.so .
	@rm -f $(BUILD_DIR)/linux-arm64/libnb-sk.h

# === Tarball targets ===

tarball-darwin-arm64: build-darwin-arm64
	@echo "Creating nb-sk-provider darwin-arm64 tarball..."
	@mkdir -p $(BUILD_DIR)/nb-sk-provider-$(VERSION)-darwin-arm64
	cp $(BUILD_DIR)/darwin-arm64/libnb-sk.dylib $(BUILD_DIR)/nb-sk-provider-$(VERSION)-darwin-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-sk-provider-$(VERSION)-darwin-arm64/
	cd $(BUILD_DIR) && tar -czvf nb-sk-provider-$(VERSION)-darwin-arm64.tar.gz nb-sk-provider-$(VERSION)-darwin-arm64
	@rm -rf $(BUILD_DIR)/nb-sk-provider-$(VERSION)-darwin-arm64
	@echo "Created: $(BUILD_DIR)/nb-sk-provider-$(VERSION)-darwin-arm64.tar.gz"

tarball-linux-amd64: build-linux-amd64
	@echo "Creating nb-sk-provider linux-amd64 tarball..."
	@mkdir -p $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/linux-amd64/libnb-sk.so $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf nb-sk-provider-$(VERSION)-linux-amd64.tar.gz nb-sk-provider-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-amd64
	@echo "Created: $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-amd64.tar.gz"

tarball-linux-arm64: build-linux-arm64
	@echo "Creating nb-sk-provider linux-arm64 tarball..."
	@mkdir -p $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/linux-arm64/libnb-sk.so $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf nb-sk-provider-$(VERSION)-linux-arm64.tar.gz nb-sk-provider-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-arm64
	@echo "Created: $(BUILD_DIR)/nb-sk-provider-$(VERSION)-linux-arm64.tar.gz"

clean:
	rm -rf $(BUILD_DIR)

version:
	@echo $(VERSION)
