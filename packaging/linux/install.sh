#!/bin/bash
set -e

# NaughtBot Linux Installer

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default installation directories
if [ "$(id -u)" -eq 0 ]; then
    # Running as root - install system-wide
    BIN_DIR="/usr/local/bin"
    LIB_DIR="/usr/local/lib"
else
    # Running as user - install to home directory
    BIN_DIR="${HOME}/.local/bin"
    LIB_DIR="${HOME}/.local/lib"
fi

echo "NaughtBot Installer"
echo "=================="
echo ""
echo "Installing to:"
echo "  Binary: ${BIN_DIR}/nb"
echo "  Binary: ${BIN_DIR}/age-plugin-nb"
echo "  Library: ${LIB_DIR}/libnb-sk.so"
echo ""

# Create directories
mkdir -p "${BIN_DIR}"
mkdir -p "${LIB_DIR}"

# Install files
cp "${SCRIPT_DIR}/nb" "${BIN_DIR}/nb"
chmod 755 "${BIN_DIR}/nb"

cp "${SCRIPT_DIR}/age-plugin-nb" "${BIN_DIR}/age-plugin-nb"
chmod 755 "${BIN_DIR}/age-plugin-nb"

cp "${SCRIPT_DIR}/libnb-sk.so" "${LIB_DIR}/libnb-sk.so"
chmod 755 "${LIB_DIR}/libnb-sk.so"

echo "Installation complete!"
echo ""

# Check if bin directory is in PATH
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
    echo "NOTE: ${BIN_DIR} is not in your PATH."
    echo "Add this to your shell profile (~/.bashrc or ~/.zshrc):"
    echo ""
    echo "  export PATH=\"${BIN_DIR}:\$PATH\""
    echo ""
fi

echo "Next steps:"
echo ""
echo "1. Login to NaughtBot:"
echo "   nb login"
echo ""
echo "2. For SSH SecurityKeyProvider, add to ~/.ssh/config:"
echo "   SecurityKeyProvider ${LIB_DIR}/libnb-sk.so"
echo ""
echo "   Or set environment variable:"
echo "   export SSH_SK_PROVIDER=${LIB_DIR}/libnb-sk.so"
echo ""
echo "3. For GPG signing, configure git:"
echo "   git config --global gpg.program \"nb gpg\""
echo ""
echo "4. For age encryption/decryption:"
echo "   nb age keygen"
echo "   age -r \$(nb age recipient) -o secret.age file.txt"
echo "   age -d -i <(nb age identity) secret.age"
echo ""
echo "See README.txt for more details."
