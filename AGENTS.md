# Repository Guidelines — NaughtBot CLI

`naughtbot/cli` is the NaughtBot desktop CLI repo. It ships the user-facing
`nb` binary plus the supporting plugins and shared libraries that route SSH /
GPG / age / PKCS#11 signing and decryption requests to your phone for
biometric approval. It is the desktop counterpart to the iOS app in
`NaughtBot/mobile` and speaks the same envelope formats published by
`NaughtBot/e2ee-payloads`.

The CLI is a greenfield rebrand: no legacy pre-NaughtBot identifiers
should appear in production source, package names, or generated code. Use
the legacy source trees that this repo replaced only as comparison material
when triaging cross-repo behaviour; the current `cli/`, `mobile/`, `core/`,
and `e2ee-payloads/` contracts are the source of truth.

## Module / Go version

- Module path: `github.com/naughtbot/cli` (single Go module rooted at the
  repo root).
- Go: 1.26.0 (see `go.mod`).
- Cross-repo Go dependencies (no `replace` directives — always pinned by
  semver tag):
  - `github.com/naughtbot/api` — generated server-stub-paired clients for
    backend HTTP. Single root module with sub-packages `auth`, `blob`,
    `mailbox` (imported as `github.com/naughtbot/api/auth` etc., **not**
    `/go/auth`).
  - `github.com/naughtbot/e2ee-payloads/go` — generated envelope payload
    types (`ssh_auth`, `ssh_sign`, `gpg_sign`, `gpg_decrypt`, `age_unwrap`,
    `pkcs11_sign`, `pkcs11_derive`, `enroll`).
  - `github.com/naughtbot/attested-key-zk/bindings/go` — Go bindings to the
    AKZK approval-proof verifier static lib.

## Project Structure & Module Organization

- `cmd/nb/` — primary user-facing CLI binary (cobra + viper). Top-level
  subcommands: `login`, `age`, `gpg`, `ssh`, `keys`, `profile`.
- `cmd/age-plugin-nb/` — `age-plugin-nb` binary. Standard age plugin that
  delegates X25519 unwrap to a paired phone via the `age_unwrap` envelope.
- `cmd/gentestvectors/` — developer-only generator that emits the JSON test
  vector fixtures under `testdata/`.
- `sk-provider/` — c-shared OpenSSH `SecurityKey` provider (`libnb-sk.dylib`
  / `libnb-sk.so`), loaded by OpenSSH via `SSH_SK_PROVIDER`.
- `pkcs11-provider/` — c-shared PKCS#11 module (`libnb-pkcs11.dylib` /
  `libnb-pkcs11.so`), loaded by GPG / SSH / openssl as a PKCS#11 token.
- `internal/` — shared packages, all non-importable from outside this repo:
  - `shared/config`, `shared/client`, `shared/transport`, `shared/log`,
    `shared/sync`, `shared/multidevice`, `shared/version`,
    `shared/testdata` (the resolver that anchors `*_vectors_test.go` reads
    on repo-root `testdata/<name>`).
  - `age/`, `gpg/`, `ssh/` — per-surface signing / decrypt logic.
  - `approval/` — AKZK approval-proof verifier glue.
  - `audit/`, `ptr/` — small support packages.
- `crypto/` — crypto primitives, attestation parsers, and the
  `*_vectors_test.go` loaders.
- `testdata/` — JSON test vectors copied in WS3.4 from `mobile/` and
  `core/` test fixtures. Read at runtime via
  `internal/shared/testdata.Path`. Driven by `cmd/gentestvectors/`. Treat
  as generated output; regenerate, don't hand-edit.
- `data/fixtures/` — additional vector JSONs (BBS pseudonym, relay auth)
  that pre-date the shared testdata resolver and are read directly by a
  few test files.
- `tests/integration/{ssh,gpg,age,pkcs11,shared}/` — planned home for
  `//go:build integration` end-to-end suites that wire a real `nb` binary
  against a local `core/` docker-compose stack plus a paired phone
  fixture. The directory is not yet present; the integration suites land
  in WS3.5 (tracked under `NaughtBot/workspace#3`). Until then, end-to-end
  validation is manual.
- `packaging/` — release packaging: macOS `.pkg` via `pkgbuild` /
  `productbuild` (with notarization) plus the per-component Homebrew
  tarballs; Linux `.deb` / `.rpm` via `fpm` (`packaging/linux/`); Homebrew
  formula bumps.

Treat `*/gen/`, `testdata/`, `data/fixtures/`, `packaging/build/`, and
`packaging/*/build/` as generated output; do not hand-edit.

## Build, Test, and Development Commands

The repo has a top-level `Makefile` that wraps the common flows, but plain
`go` commands also work from the repo root.

- `go build ./...` — compile every Go package in pure-Go mode. This does
  **not** emit the c-shared providers (`libnb-sk.{dylib,so}`,
  `libnb-pkcs11.{dylib,so}`), which require `-buildmode=c-shared` and
  `CGO_ENABLED=1`.
- `make build` — convenience target that drops `nb`, `age-plugin-nb`,
  `libnb-sk.{dylib,so}`, and `libnb-pkcs11.{dylib,so}` into the repo
  root. Internally invokes the `sk-provider/` and `pkcs11-provider/`
  sub-Makefiles for the c-shared artefacts. Note that `make build` does
  **not** depend on `ensure-attested-key-zk-static-lib` — only `make
  test` does. In a fresh workspace where the sibling AKZK static lib has
  not been built yet, run `make ensure-attested-key-zk-static-lib`
  first (or `make test` once) before `make build`, otherwise the
  c-shared providers fail with missing header / library errors.
- `go test ./...` — run all unit tests. Anything tagged `integration` is
  excluded (and the directory does not exist yet — see below).
- `go test -tags=integration ./tests/integration/...` — once the WS3.5
  integration tree lands, run the end-to-end suites. These require a
  running `core/` docker-compose stack and a paired phone fixture; they
  are skipped by default.
- `make -C packaging all` (alias for `build-arm64`) — build the macOS
  arm64 binaries plus the c-shared providers for the `.pkg` payload.
  Other useful targets: `pkg` / `pkg-unsigned` (build the `.pkg`),
  `pkg-sign`, `notarize`, `release`, `tarballs`. The Linux equivalents
  live under `packaging/linux/` (`make -C packaging/linux`). There is no
  top-level `make -C packaging build` target.
- `go vet ./...` — vet pass. Wired into `make lint`, which also runs the
  sub-Makefile lints for the c-shared providers.
- `golangci-lint run` — only if `.golangci.yml` is present in the repo
  root; CI gates on it once configured.

The `sk-provider/` and `pkcs11-provider/` sub-Makefiles produce the
c-shared libraries with `CGO_ENABLED=1`. A C++17 toolchain plus the
`attested-key-zk` static lib is required (`make
ensure-attested-key-zk-static-lib` in the top-level Makefile builds it from
the sibling AKZK checkout in lane / workspace layouts).

## Cross-repo contract

- **OpenAPI is the source of truth.** Backend HTTP wire types come from
  `github.com/naughtbot/api`; envelope payload wire types come from
  `github.com/naughtbot/e2ee-payloads/go`. Pin both modules by semver tag.
  Do **not** hand-write Go structs that mirror either set of schemas. If a
  needed type is missing, the fix is a new OpenAPI release in the relevant
  source repo, not a local mirror struct.
- The `github.com/naughtbot/api` module is a single root Go module with
  sub-packages `auth`, `blob`, `mailbox`. Imports are
  `github.com/naughtbot/api/auth`, **not** `github.com/naughtbot/api/go/auth`.
- No `replace` directives. The lane workspace ships sibling repo checkouts,
  but the CLI must build against the published modules.
- The AKZK Go bindings depend on a C++ static lib built from the sibling
  `attested-key-zk` checkout. The top-level Makefile's
  `ensure-attested-key-zk-static-lib` target handles this in lane and
  workspace layouts.

## Non-obvious crypto invariants

These mirror `NaughtBot/mobile`'s
`memories/signing-types-protocol-notes.md`. Wire compatibility with the
phone is non-negotiable — getting one of these wrong makes the verifier
silently reject every response.

- **ECDSA vs EdDSA preimage handling in GPG sign.** P-256 ECDSA signs over
  the *preimage* (the signer hashes internally). Ed25519 signs over the
  *precomputed 32-byte SHA-256 digest*. Dispatch on key algorithm; feeding
  raw preimage to the EdDSA path produces a signature over the wrong
  bytes.
- **age uses a zero nonce.** age v1 X25519 wrap encrypts the 16-byte file
  key with ChaCha20-Poly1305 using a zero nonce. This is safe because the
  HKDF salt for the wrap key already includes the ephemeral public key, so
  every wrap derives a fresh key. Do not "fix" this to a random nonce.
- **PKCS#11 sign uses the auth key; PKCS#11 derive uses the encryption
  key.** The provider publishes the device's **auth** public key as
  `CKA_EC_POINT`, so `C_Sign` must dispatch to
  `signWithAuthKey(digest:context:)`. ECDH derive must dispatch to the
  **encryption** key, **not** the sync key — the sync-key path triggers a
  biometric prompt and breaks non-interactive derive flows.
- **GPG decrypt subkey resolution order.** First match wins:
  1. `payload.iosKeyId` — the host-side payload may name the exact
     subkey UUID to use.
  2. `transaction.signingPublicKeyHex` — match by hex of the subkey
     public, when attached.
  3. Scan-and-match by **8-byte V4 key-ID suffix** of the public key
     fingerprint. Multiple matches → tie-break by **newest `createdAt`**.
  GPG PKESK packets only ship the 8-byte key-ID, so the fallback path
  matters.
- **HKDF info strings stay byte-identical to mobile.** Do not normalise,
  abbreviate, or version-bump these in place — a new version means a new
  string and a coordinated CLI + phone release.
  - E2EE envelope keys: `"signer-request-v1"`, `"signer-response-v1"`,
    `"signer-wrap-v1"`.
  - age v1 X25519: `"age-encryption.org/v1/X25519"` (full string,
    including the slash and `v1`).
- **Wire algorithm strings for enrollment** are lowercase, hyphenated:
  `"ecdsa"` (NIST P-256 signing), `"ed25519"` (Curve25519 EdDSA),
  `"ecdh-p256"` (NIST P-256 ECDH), `"x25519"` (Curve25519 ECDH). The CLI
  and verifier match on these as plain strings. Do not switch to camelCase
  or constant-case forms.
- **SSH-SK signing preimage.** The OpenSSH-SK preimage that the phone
  signs is
  `SHA256(application) || flags || counter (u32 BE) || SHA256(data)`. The
  `flags` value is carried in the `ssh_sign` payload; the `counter` value
  is **not** yet carried in `e2ee-payloads/go v0.1.0`'s
  `MailboxSshAuthResponseSuccessV1` schema, so `sk-provider/ssh_ops.go`
  currently relays `counter = 0` and OpenSSH verification only succeeds
  when the approver also signs with counter 0. Adding a counter field to
  the SSH response payloads is upstream `e2ee-payloads` work tracked
  outside `NaughtBot/cli#12`. When that schema bump lands, consume
  `counter` from the generated type rather than hardcoding constants —
  hardcoded zero counters give up SSH-SK clone-detection.

## Testing Guidelines

Run the narrowest target first, then broaden if the change crosses a
package boundary.

- Per-package: `go test ./internal/<pkg>/...` or `go test ./crypto/...`.
- Unit tests under `crypto/` read JSON test vectors from repo-root
  `testdata/<name>`, resolved by `internal/shared/testdata.Path`. Some
  legacy fixtures (BBS pseudonym, relay auth) still live under
  `data/fixtures/` and are read directly by their tests. After a wire
  change, regenerate the shared `testdata/` JSON by **redirecting**
  `cmd/gentestvectors` output to the target fixture (the binary writes
  to stdout); for example
  `go run ./cmd/gentestvectors > testdata/<fixture>.json`. Running
  `go run ./cmd/gentestvectors` without a redirection leaves the
  checked-in fixtures unchanged. Add new fixtures under `testdata/`,
  not a sibling location.
- Bug fixes must include a regression test next to the changed code.
- Cross-surface changes (anything that touches the envelope payload types,
  HTTP client wiring, or the c-shared providers) must validate the
  integration suites once they land in WS3.5:
  `go test -tags=integration ./tests/integration/...`. Until then,
  manually exercise the affected surface against a local `core/` stack
  and a paired phone fixture.
- When a change updates the cross-repo modules
  (`github.com/naughtbot/api`, `github.com/naughtbot/e2ee-payloads/go`),
  run `go build ./...` plus the integration suite against the matching
  `core/` and `mobile/` versions.

## Release Flow

**Never run a release manually.** All releases (binary builds, signed
macOS `.pkg`, Linux `.deb` / `.rpm`, Homebrew formula bump) go through the
GitHub Actions `release` workflow. The workflow consumes a tagged commit on
`main` and publishes the resulting artifacts plus the Homebrew tap update.

Trigger via `gh workflow run release -F version=X.Y.Z` (workflow lands in
WS3.6 — currently tracked at NaughtBot/cli#8). Local Makefile targets such
as `make release VERSION=...` and the scripts in `packaging/*/scripts/`
exist for emergency human use only — agents must not invoke them. Releases
must be reproducible from a tagged commit on `main`.

## Commit & Pull Request Guidelines

- Conventional commits: `feat(cli): add ...`, `fix(gpg): handle ...`,
  `chore(deps): bump ...`, `docs(cli): ...`, `test(ssh): ...`.
- Bug fixes include a regression test next to the changed code.
- No `replace` directives in `go.mod`. Cross-repo deps are published Go
  modules pinned by semver tag.
- After opening or updating a PR, use the `wait-for-bot-reviews` skill to
  wait for Copilot / Codex bot reviews, then review the comments for
  validity and address & resolve as appropriate.
- No backwards-compatibility shims unless explicitly requested; this is a
  greenfield extraction.

## Migration history

This repo was extracted and rebranded under
[NaughtBot/workspace#3](https://github.com/NaughtBot/workspace/issues/3).
The detailed extraction plan lives in
[`workspace/plans/2026-05-11-0208Z-cli-extraction.md`](https://github.com/NaughtBot/workspace/blob/main/plans/2026-05-11-0208Z-cli-extraction.md).
Treat the pre-rebrand source trees as comparison material only; the
current `cli/`, `mobile/`, `core/`, and `e2ee-payloads/` contracts are the
source of truth.
