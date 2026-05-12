# NaughtBot CLI

`nb` is the NaughtBot desktop CLI. It plugs into the standard SSH, GPG, age,
and PKCS#11 surfaces on your laptop and routes the cryptographic operations
to your phone, which signs or decrypts under a hardware-backed key after a
biometric approval. The private keys never leave the device; the laptop only
ever sees signatures and unwrapped session keys.

## Binaries

This repo ships four executables / shared libraries:

- `nb` — the main CLI. Subcommands: `login`, `age`, `gpg`, `ssh`, `keys`,
  `profile`.
- `age-plugin-nb` — an [age](https://age-encryption.org/) plugin that
  delegates X25519 unwrap to your phone. The recipient strings the plugin
  emits are `age1nb1…` (encryption); the identity strings consumed via
  `age -i` are `AGE-PLUGIN-NB-1…`. `age` and `rage` invoke the plugin
  automatically when they see either form.
- `libnb-sk.{dylib,so}` — an OpenSSH `SecurityKey` provider shared library.
  Load it from `ssh(1)` via the `SecurityKeyProvider` config option (`-o
  SecurityKeyProvider=/path/to/libnb-sk.dylib` or a `SecurityKeyProvider`
  entry in `~/.ssh/config`), and from `ssh-keygen(1)` / `ssh-add(1)` via
  `SSH_SK_PROVIDER=/path/to/libnb-sk.dylib`. Then use it like any other
  `ed25519-sk` / `ecdsa-sk` key.
- `libnb-pkcs11.{dylib,so}` — a PKCS#11 module that exposes your enrolled
  signing keys to anything that speaks PKCS#11 (GPG smartcard mode, OpenSSL,
  enterprise VPN clients, etc.).

## Install

> The release workflow is still in flight under
> [NaughtBot/cli#8](https://github.com/NaughtBot/cli/issues/8); pre-built
> binaries, the macOS `.pkg`, the Linux `.deb` / `.rpm`, and the Homebrew tap
> will all be published from that workflow once it lands. Until then, install
> from source.

### From source

Requires Go 1.26+ with `CGO_ENABLED=1` for the shared-library providers and
a C++17 compiler for the bundled
[`attested-key-zk`](https://github.com/NaughtBot/attested-key-zk) verifier.

```sh
go install github.com/naughtbot/cli/cmd/nb@latest
go install github.com/naughtbot/cli/cmd/age-plugin-nb@latest
```

To build the shared-library providers (`libnb-sk`, `libnb-pkcs11`) plus
everything above into the working tree, you need a sibling
[`attested-key-zk`](https://github.com/NaughtBot/attested-key-zk) checkout
alongside the `cli` checkout (the `make ensure-attested-key-zk-static-lib`
target shells out to `make -C ../attested-key-zk static-lib`):

```sh
git clone https://github.com/NaughtBot/cli
git clone https://github.com/NaughtBot/attested-key-zk
cd cli
# Build the AKZK static lib first so the c-shared providers can link
# against it. `make test` and the top-level Makefile rule both invoke
# this; `make build` does not depend on it.
make ensure-attested-key-zk-static-lib
make build
```

After `make build` the `nb` and `age-plugin-nb` binaries land in the repo
root; the c-shared providers land under their sub-Makefile dirs
(`sk-provider/libnb-sk.dylib`, `pkcs11-provider/libnb-pkcs11.dylib` on
macOS; build the `linux` sub-Makefile target for the `.so` equivalents).

### Pre-built (when WS3.6 lands)

The pending release workflow will publish:

- macOS `.pkg` via Homebrew tap: `brew install naughtbot/tap/nb`.
- Linux `.deb` and `.rpm` packages from the GitHub Releases page.
- Standalone tarballs for each component (`nb`, `nb-sk-provider`,
  `nb-pkcs11`, `nb-age-plugin`) for manual install or container layering.

## Quick usage

Pair the CLI to your phone, then enroll a key per surface (SSH, GPG, age)
and use it from the matching standard tool.

> **Status — phone-backed request flows are stubbed.** Beyond `nb login`,
> the request paths that talk to your phone (enrollment, signing,
> decrypt, key sync) currently terminate at
> `client.ErrNotImplemented` / `transport.ErrRelayNotImplemented`
> because the relay transport and approver-key fetch have not been
> rewired against `github.com/naughtbot/api` yet (mailbox-DPoP follow-up
> to [NaughtBot/cli#12](https://github.com/NaughtBot/cli/issues/12)).
> The snippets below describe the intended UX once that re-wire lands.
> Local-only operations (`nb keys`, `nb profile *`, `nb login --logout`)
> are usable today.

### Pair

```sh
nb login                     # (stubbed) scan the QR code with the NaughtBot app
nb keys --sync               # (stubbed) pull enrolled signing keys from your phone
nb keys                      # show enrolled keys grouped by purpose (local-only)
```

`nb login` itself currently returns
`login: not yet rewired to NaughtBot/api/auth pairing surface`; the
`--logout` sub-mode is local-only and still works. `nb keys --sync`
hits the stubbed relay transport. `nb keys` (no flag) is local-only and
reads the profile state in place.

### age

```sh
nb age keygen                # generate an X25519 age key on your phone
nb age recipient             # print the age1nb1… recipient (share this)
nb age identity              # print the age plugin identity (for -i)

# Encrypt — anyone with the recipient can do this, no phone needed:
age -r "$(nb age recipient)" -o secret.age secret.txt

# Decrypt — your phone prompts for biometric approval:
age -d -i <(nb age identity) -o secret.txt secret.age
```

### GPG

```sh
nb gpg --generate-key --name "Alice" --email "alice@example.com"
nb gpg --list-keys

# Sign — git uses this shape with -bsau FINGERPRINT:
echo "test" | nb gpg -bsau FINGERPRINT

# Encrypt + decrypt:
echo "hello" | nb gpg -e -r FINGERPRINT --armor > msg.asc
nb gpg --decrypt msg.asc
```

`nb gpg` is wire-compatible with the GPG command-line surface that `git`
and other tooling drive, so it can be set as `gpg.program` in `~/.gitconfig`
to sign commits and tags under hardware-backed keys.

### SSH

```sh
nb ssh --generate-key -n laptop -o ~/.ssh/id_nb         # ECDSA P-256, default
nb ssh --generate-key -n laptop-ed25519 -t ed25519 -o ~/.ssh/id_nb_ed25519
nb ssh --list-keys

# Then use the key like any other SSH key. The OpenSSH `ssh` client
# selects the SK provider via the `SecurityKeyProvider` config option —
# either inline:
ssh -o SecurityKeyProvider=/usr/local/lib/libnb-sk.dylib -i ~/.ssh/id_nb user@host

# …or in `~/.ssh/config`:
#
#   Host my-host
#     SecurityKeyProvider /usr/local/lib/libnb-sk.dylib
#     IdentityFile        ~/.ssh/id_nb
#
# (`ssh-keygen(1)` and `ssh-add(1)` honour the `SSH_SK_PROVIDER`
# environment variable instead; `ssh(1)` itself does not.)
```

### Profiles

`nb` supports multiple profiles (work, personal, etc.):

```sh
nb profile list
nb profile use work
nb --profile personal age recipient
```

Profiles isolate enrolled keys, pairing state, and config. Override the
config directory with `NB_CONFIG_DIR=/path/to/dir`, select a non-active
profile with `NB_PROFILE=<name>` or `--profile <name>`, and set log
verbosity with `NB_LOG_LEVEL=debug|info|warn|error`.

Default config locations (all driven by the `AppID = "com.naughtbot.nb"`
constant in `internal/shared/config/types.go`):

- Linux: `$XDG_CONFIG_HOME/com.naughtbot.nb/` or
  `~/.config/com.naughtbot.nb/`.
- macOS: `~/Library/Application Support/com.naughtbot.nb/`.
- Windows: `%APPDATA%\com.naughtbot.nb\`.

Run `nb <command> --help` for the full flag list on any subcommand.

## Migration history

The full extraction history for this repo, including the per-step PR list
and the staged rebrand, lives under
[NaughtBot/workspace#3](https://github.com/NaughtBot/workspace/issues/3) and
the detailed plan at
[`workspace/plans/2026-05-11-0208Z-cli-extraction.md`](https://github.com/NaughtBot/workspace/blob/main/plans/2026-05-11-0208Z-cli-extraction.md).

For contributor-facing build, test, and architecture rules, see
[`AGENTS.md`](./AGENTS.md).

## License

MIT — see [LICENSE](./LICENSE). Third-party notices are collected in
[NOTICES](./NOTICES).
