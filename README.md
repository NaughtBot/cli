# NaughtBot CLI

Command-line tool for SSH, GPG, and age signing. Routes signing requests to
your phone for biometric approval with hardware-backed cryptographic keys.

## Status

The WS3.2 Go module rename + dependency rewire is complete. The
[WS3.3 rebrand sweep](https://github.com/NaughtBot/cli/issues/3) (in
progress) renames the legacy `oobsign` / `AckAgent` identifiers to
`nb` / `NaughtBot` across binary names, packaging identifiers,
user-visible strings, env var prefixes, age recipient HRPs, and
keychain service IDs. The CLI's HTTP wiring against the regenerated
`github.com/naughtbot/api/auth` and `github.com/naughtbot/api/mailbox`
clients (plus the deletion of `internal/protocol/gen.go` in favour of
the generated `github.com/naughtbot/e2ee-payloads/go` envelope payload
types) is gated behind the `legacy_api` build tag while that work
lands in a follow-up. Test fixtures (WS3.4), integration suites,
packaging, and CI land in WS3.5–WS3.7.

Master tracker: [NaughtBot/workspace#3](https://github.com/NaughtBot/workspace/issues/3).

## Install

Homebrew (macOS, Linux):

```sh
brew install naughtbot/tap/nb
```

The Homebrew tap is hosted at
[naughtbot/homebrew-tap](https://github.com/naughtbot/homebrew-tap).

Debian / RPM packages and signed Apple `.pkg` artefacts are built by
the release workflow under [naughtbot/cli](https://github.com/naughtbot/cli).

## Binaries

- `nb` — main CLI (login, age, gpg, ssh).
- `age-plugin-nb` — age plugin that delegates decryption to your phone.
- `libnb-sk.{dylib,so}` — OpenSSH SecurityKey provider shared library.
- `libnb-pkcs11.{dylib,so}` — PKCS#11 module shared library.

## Quick start

```sh
nb login                     # pair this desktop with your phone
nb age recipient             # print your age recipient (age1nb1...)
nb gpg --list-keys           # list enrolled GPG keys
nb ssh --generate-key -n id  # enrol a new SSH SecurityKey
```

## Configuration

- Config directory defaults to `~/.config/nb/` on Linux,
  `~/Library/Application Support/com.naughtbot.nb/` on macOS, and
  `%AppData%\NaughtBot\nb\` on Windows.
- Override the location with `NB_CONFIG_DIR=/path/to/dir`.
- Select an alternate profile with `NB_PROFILE=<name>` or `--profile`.
- Set log verbosity with `NB_LOG_LEVEL=debug|info|warn|error`.

## Building from source

Requirements:

- Go 1.26.0+ with `CGO_ENABLED=1` for the shared-library providers.
- A C++17 compiler (`clang++` or `g++`) and OpenSSL development
  headers for the bundled attested-key-zk verifier.

```sh
make build              # builds nb, age-plugin-nb, and both provider .dylib/.so files
go test ./...           # unit tests
```

## Documentation

Full documentation, brand assets, and release notes will land alongside
WS3.6 (CI, AGENTS.md, packaging).
