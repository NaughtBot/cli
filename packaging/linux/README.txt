NaughtBot CLI for Linux
======================

NaughtBot routes signing and authorization requests to your iOS device for
biometric approval. Private keys never leave the iOS Secure Enclave.

Contents
--------
- nb              CLI tool for login, GPG signing, and more
- age-plugin-nb   age encryption plugin for iOS key decryption
- libnb-sk.so     SSH SecurityKeyProvider shared library
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
1. Login to NaughtBot (requires iOS app):

    nb login

2. Verify your enrolled keys:

    nb login --keys

SSH Setup
---------
Add to ~/.ssh/config:

    SecurityKeyProvider ~/.local/lib/libnb-sk.so

Or set environment variable:

    export SSH_SK_PROVIDER=~/.local/lib/libnb-sk.so

GPG Signing
-----------
Configure git to use NaughtBot for signing:

    git config --global gpg.program "nb gpg"
    git config --global commit.gpgsign true

age Encryption
--------------
Generate an age key on your iOS device:

    nb age keygen

Get your recipient address for sharing:

    nb age recipient

Encrypt files (standard age command):

    age -r age1nb1... -o secret.age secret.txt

Decrypt files (requires iOS approval):

    age -d -i <(nb age identity) secret.age

Requirements
------------
- Linux x86_64 or arm64
- For SSH: OpenSSH 8.2+ with SecurityKeyProvider support
- For credential storage: pass, kwallet, or secretservice (D-Bus)

More Information
----------------
https://github.com/nb/nb
