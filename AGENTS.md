# NaughtBot CLI — AGENTS.md

> **WIP — see [NaughtBot/workspace#3](https://github.com/NaughtBot/workspace/issues/3).**

This repository was bootstrapped by importing the legacy `oobsign-cli`
source tree (see [NaughtBot/cli#1](https://github.com/NaughtBot/cli/issues/1)).
The WS3.2 Go module rename and dependency rewire and WS3.3 rebrand
sweep are complete. WS3.3a deleted `internal/protocol/gen.go` and
rewired consumers onto generated types from `github.com/naughtbot/api`
and `github.com/naughtbot/e2ee-payloads/go`; the network call sites
that previously targeted the legacy `/api/v1/exchanges` surface return
`client.ErrNotImplemented` / `transport.ErrRelayNotImplemented` until
the mailbox-DPoP rewire lands as a follow-up to NaughtBot/cli#12.
WS3.4–WS3.7 follow with test fixtures, integration suites, packaging,
CI, and the proper AGENTS.md content.

See the detailed plan at
[`workspace/plans/2026-05-11-0208Z-cli-extraction.md`](https://github.com/NaughtBot/workspace/blob/main/plans/2026-05-11-0208Z-cli-extraction.md).

## Module / Go version

- Module path: `github.com/naughtbot/cli`.
- Go: 1.26.0.
- Cross-repo deps (no `replace` directives): `github.com/naughtbot/api`,
  `github.com/naughtbot/attested-key-zk/bindings/go`,
  `github.com/naughtbot/e2ee-payloads/go`.

## Build / test

```sh
go build ./...                    # full tree
go build -buildmode=c-shared ./sk-provider     # libnb-sk
go build -buildmode=c-shared ./pkcs11-provider # libnb-pkcs11
go test ./...
```

Some test packages depend on the JSON test-vector fixtures that
WS3.4 will copy into `cli/testdata/`. Until then, the relevant
`*_vectors_test.go` files fail with file-not-found at
`/Users/<...>/cli/../data/`.

## Layout

- `cmd/nb/` — main CLI binary.
- `cmd/age-plugin-nb/` — age plugin binary.
- `cmd/gentestvectors/` — vector-fixture generator (developer tool).
- `sk-provider/`, `pkcs11-provider/` — c-shared library entry points
  (`libnb-sk`, `libnb-pkcs11`).
- `internal/age/`, `internal/gpg/`, `internal/ssh/` — per-surface
  signing logic.
- `internal/approval/` — vendored approval-proof verifier (Longfellow
  glue + `attested-key-zk`).
- `internal/shared/{client,transport,config,sync,multidevice,...}` —
  shared HTTP client, transport layer, config persistence.
- `crypto/`, `data/fixtures/` — crypto primitives + bundled fixtures.
- `packaging/` — `.pkg`, `.deb`, `.rpm`, Homebrew packaging Makefiles.

## Cross-repo contract

- OpenAPI specs in `NaughtBot/api` are the source of truth. Generated
  Go clients (`auth`, `blob`, `mailbox`) come from
  `github.com/naughtbot/api`. Envelope payload types come from
  `github.com/naughtbot/e2ee-payloads/go`.
- Do NOT hand-write Go structs that mirror either set of schemas;
  pin the generated module instead.
- Releases run from `gh workflow run release` (workflow lands in
  WS3.6); never invoke local release scripts manually.
