# Ghidra Skill - Build System
#
# Usage:
#   make build        - Download Ghidra (if needed) and build the plugin
#   make plugin       - Build just the plugin (requires Ghidra already downloaded)
#   make download     - Download and extract Ghidra
#   make test         - Run all tests (Go + Java)
#   make test-go      - Run Go tests only
#   make test-java    - Run Java tests only
#   make test-cover   - Run Go tests with coverage report
#   make clean        - Remove build artifacts
#   make distclean    - Remove build artifacts and downloaded Ghidra

GHIDRA_DIR := .ghidra
GHIDRA_REPO := NationalSecurityAgency/ghidra
PLUGIN_DIR := ghidra-plugin
DIST_DIR := $(PLUGIN_DIR)/dist

# Detect OS for download tool and archive handling
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    DOWNLOAD_CMD = curl -fSL -o
else
    DOWNLOAD_CMD = wget -O
endif

.PHONY: all build plugin download clean distclean check-ghidra info test test-go test-java test-cover

all: build

# Main build target - ensures Ghidra is downloaded, then builds plugin
build: download plugin

# Download and extract Ghidra if not present
download: $(GHIDRA_DIR)/.extracted

$(GHIDRA_DIR)/.extracted:
	@echo "==> Fetching latest Ghidra release info..."
	@mkdir -p $(GHIDRA_DIR)
	@RELEASE_INFO=$$(curl -fsSL "https://api.github.com/repos/$(GHIDRA_REPO)/releases/latest"); \
	DOWNLOAD_URL=$$(echo "$$RELEASE_INFO" | grep -o '"browser_download_url": "[^"]*\.zip"' | head -1 | cut -d'"' -f4); \
	FILENAME=$$(basename "$$DOWNLOAD_URL"); \
	SHA256=$$(echo "$$RELEASE_INFO" | grep -o 'SHA-256: `[^`]*`' | cut -d'`' -f2); \
	VERSION=$$(echo "$$RELEASE_INFO" | grep -o '"tag_name": "[^"]*"' | cut -d'"' -f4); \
	echo "==> Latest version: $$VERSION"; \
	echo "==> Downloading $$FILENAME..."; \
	$(DOWNLOAD_CMD) "$(GHIDRA_DIR)/$$FILENAME" "$$DOWNLOAD_URL"; \
	echo "==> Verifying SHA-256 checksum..."; \
	if [ "$(UNAME_S)" = "Darwin" ]; then \
		ACTUAL_SHA=$$(shasum -a 256 "$(GHIDRA_DIR)/$$FILENAME" | cut -d' ' -f1); \
	else \
		ACTUAL_SHA=$$(sha256sum "$(GHIDRA_DIR)/$$FILENAME" | cut -d' ' -f1); \
	fi; \
	if [ "$$ACTUAL_SHA" != "$$SHA256" ]; then \
		echo "ERROR: SHA-256 mismatch!"; \
		echo "  Expected: $$SHA256"; \
		echo "  Actual:   $$ACTUAL_SHA"; \
		rm -f "$(GHIDRA_DIR)/$$FILENAME"; \
		exit 1; \
	fi; \
	echo "==> Checksum verified"; \
	echo "==> Extracting..."; \
	unzip -q -o "$(GHIDRA_DIR)/$$FILENAME" -d "$(GHIDRA_DIR)"; \
	rm "$(GHIDRA_DIR)/$$FILENAME"; \
	touch $(GHIDRA_DIR)/.extracted
	@echo "==> Ghidra downloaded and extracted to $(GHIDRA_DIR)/"

# Build the Ghidra plugin
plugin: check-ghidra
	@echo "==> Building Ghidra HTTP plugin..."
	@GHIDRA_INSTALL=$$(cd $(GHIDRA_DIR) && find . -maxdepth 1 -type d -name 'ghidra_*' | head -1 | sed 's|^\./||'); \
	if [ -z "$$GHIDRA_INSTALL" ]; then \
		echo "ERROR: Could not find Ghidra installation in $(GHIDRA_DIR)/"; \
		exit 1; \
	fi; \
	GHIDRA_ABS_PATH="$$(pwd)/$(GHIDRA_DIR)/$$GHIDRA_INSTALL"; \
	echo "==> Using Ghidra at: $$GHIDRA_ABS_PATH"; \
	cd $(PLUGIN_DIR) && GHIDRA_INSTALL_DIR="$$GHIDRA_ABS_PATH" gradle buildExtension
	@echo "==> Build complete! Extension is in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/*.zip 2>/dev/null || true

# Check that Ghidra is downloaded
check-ghidra:
	@if [ ! -f "$(GHIDRA_DIR)/.extracted" ]; then \
		echo "ERROR: Ghidra not found. Run 'make download' first."; \
		exit 1; \
	fi

# Show info about the current setup
info:
	@echo "Ghidra directory: $(GHIDRA_DIR)"
	@if [ -f "$(GHIDRA_DIR)/.extracted" ]; then \
		GHIDRA_INSTALL=$$(find $(GHIDRA_DIR) -maxdepth 1 -type d -name 'ghidra_*' | head -1); \
		echo "Ghidra installed: $$GHIDRA_INSTALL"; \
	else \
		echo "Ghidra installed: No (run 'make download')"; \
	fi
	@echo "Plugin directory: $(PLUGIN_DIR)"
	@if [ -d "$(DIST_DIR)" ]; then \
		echo "Built extensions:"; \
		ls -la $(DIST_DIR)/*.zip 2>/dev/null || echo "  (none)"; \
	fi

# Clean build artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(PLUGIN_DIR)/build $(PLUGIN_DIR)/.gradle $(DIST_DIR)
	@echo "==> Done"

# Clean everything including downloaded Ghidra
distclean: clean
	@echo "==> Removing downloaded Ghidra..."
	rm -rf $(GHIDRA_DIR)
	@echo "==> Done"

# Run all tests
test: test-go test-java

# Run Go tests
test-go:
	@echo "==> Running Go tests..."
	go test ./... -v
	@echo "==> Done"

# Run Go tests with coverage
test-cover:
	@echo "==> Running Go tests with coverage..."
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "==> Coverage report: coverage.html"
	@go tool cover -func=coverage.out | tail -1

# Run Java tests (requires Ghidra to be downloaded)
test-java: check-ghidra
	@echo "==> Running Java tests..."
	@GHIDRA_INSTALL=$$(cd $(GHIDRA_DIR) && find . -maxdepth 1 -type d -name 'ghidra_*' | head -1 | sed 's|^\./||'); \
	GHIDRA_ABS_PATH="$$(pwd)/$(GHIDRA_DIR)/$$GHIDRA_INSTALL"; \
	cd $(PLUGIN_DIR) && GHIDRA_INSTALL_DIR="$$GHIDRA_ABS_PATH" gradle test
	@echo "==> Done"
