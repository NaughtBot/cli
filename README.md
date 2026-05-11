# NaughtBot CLI

Command-line tool for SSH, GPG, and age signing. Routes signing requests to
your phone for biometric approval with hardware-backed cryptographic keys.

## Status

> The CLI does not have a publishable build yet. WS3.2 (Go module rename +
> dependency rewire) and WS3.3 (rebrand sweep) have landed; the HTTP wiring
> against the regenerated `github.com/naughtbot/api/auth` and
> `github.com/naughtbot/api/mailbox` clients, plus deletion of
> `internal/protocol/gen.go` in favour of the generated
> `github.com/naughtbot/e2ee-payloads/go` envelope payload types, is gated
> behind the `legacy_api` build tag pending the WS3.3a follow-up. In the
> default build, the QR-code login flow (`nb login`) returns
> `login: not yet rewired to NaughtBot/api/auth (WS3.3)`. Test fixtures
> (WS3.4), integration suites (WS3.5), packaging release workflow / CI
> (WS3.6), and the proper `AGENTS.md` (WS3.7) follow.

Master tracker: [NaughtBot/workspace#3](https://github.com/NaughtBot/workspace/issues/3).

## Binaries

- `nb` — main CLI (login, age, gpg, ssh).
- `age-plugin-nb` — age plugin that delegates decryption to your phone.
- `libnb-sk.{dylib,so}` — OpenSSH SecurityKey provider shared library.
- `libnb-pkcs11.{dylib,so}` — PKCS#11 module shared library.

## Building from source

Requirements:

- Go 1.26.0+ with `CGO_ENABLED=1` for the shared-library providers.
- A C++17 compiler (`clang++` or `g++`) and OpenSSL development
  headers for the bundled attested-key-zk verifier.

```sh
make build              # builds nb, age-plugin-nb, and both provider .dylib/.so files
go test ./...           # unit tests
```

## Configuration (when login is wired)

- Config directory defaults to `~/.config/nb/` on Linux,
  `~/Library/Application Support/com.naughtbot.nb/` on macOS, and
  `%AppData%\NaughtBot\nb\` on Windows.
- Override the location with `NB_CONFIG_DIR=/path/to/dir`.
- Select an alternate profile with `NB_PROFILE=<name>` or `--profile`.
- Set log verbosity with `NB_LOG_LEVEL=debug|info|warn|error`.

## Distribution (when WS3.6 lands)

The release workflow will publish:

- Homebrew formula at
  [naughtbot/homebrew-tap](https://github.com/naughtbot/homebrew-tap)
  installable via `brew install naughtbot/tap/nb`.
- Signed Apple `.pkg` artefacts.
- Debian / RPM packages.

Until then, install by building from source.

## Documentation

Full documentation, install instructions, brand assets, and release notes
will land alongside WS3.6 (CI, packaging) and WS3.7 (proper `AGENTS.md`).
