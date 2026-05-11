OOBSign CLI for Linux
======================

OOBSign routes signing and authorization requests to your iOS device for
biometric approval. Private keys never leave the iOS Secure Enclave.

Contents
--------
- oobsign              CLI tool for login, GPG signing, and more
- age-plugin-oobsign   age encryption plugin for iOS key decryption
- liboobsign-sk.so     SSH SecurityKeyProvider shared library
- install.sh            Installation script
- README.txt            This file

Installation
------------
Run the install script:

    ./install.sh

This installs to ~/.local/bin and ~/.local/lib by default.
Run with sudo for system-wide installation to /usr/local.

Quick Start
-----------
1. Login to OOBSign (requires iOS app):

    oobsign login

2. Verify your enrolled keys:

    oobsign login --keys

SSH Setup
---------
Add to ~/.ssh/config:

    SecurityKeyProvider ~/.local/lib/liboobsign-sk.so

Or set environment variable:

    export SSH_SK_PROVIDER=~/.local/lib/liboobsign-sk.so

GPG Signing
-----------
Configure git to use OOBSign for signing:

    git config --global gpg.program "oobsign gpg"
    git config --global commit.gpgsign true

age Encryption
--------------
Generate an age key on your iOS device:

    oobsign age keygen

Get your recipient address for sharing:

    oobsign age recipient

Encrypt files (standard age command):

    age -r age1oobsign1... -o secret.age secret.txt

Decrypt files (requires iOS approval):

    age -d -i <(oobsign age identity) secret.age

Requirements
------------
- Linux x86_64 or arm64
- For SSH: OpenSSH 8.2+ with SecurityKeyProvider support
- For credential storage: pass, kwallet, or secretservice (D-Bus)

More Information
----------------
https://github.com/oobsign/oobsign
