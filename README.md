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

Requires Go 1.26+ with `CGO_ENABLED=1` (the providers and the bundled
approval-proof verifier all use cgo), a C++17 compiler, and a sibling
[`attested-key-zk`](https://github.com/NaughtBot/attested-key-zk) checkout
alongside the `cli` checkout. `nb` and `age-plugin-nb` both pull in the
AKZK static lib transitively, so the AKZK sibling is required even for
the `go install` quick path:

```sh
git clone https://github.com/NaughtBot/cli
git clone https://github.com/NaughtBot/attested-key-zk
cd cli
# Build the AKZK static lib first so cgo links cleanly. `make test` and
# the top-level Makefile rule both invoke this; `make build` and
# `go install` do not.
make ensure-attested-key-zk-static-lib

# Either go install (binaries only, dropped under $GOBIN):
go install github.com/naughtbot/cli/cmd/nb@latest
go install github.com/naughtbot/cli/cmd/age-plugin-nb@latest

# …or make build (binaries + c-shared providers in the working tree):
make build           # darwin default — produces .dylib providers
# On Linux, build the providers' linux sub-target separately:
make -C sk-provider linux
make -C pkcs11-provider linux
```

After `make build` the `nb` and `age-plugin-nb` binaries land in the repo
root; the c-shared providers land under their sub-Makefile dirs
(`sk-provider/libnb-sk.dylib`, `pkcs11-provider/libnb-pkcs11.dylib` on
macOS; `*.so` after the `linux` sub-target on Linux).

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
nb age keygen                # (stubbed) generate an X25519 age key on your phone
nb age recipient             # local: print the age1nb1… recipient for share
nb age identity              # local: print the AGE-PLUGIN-NB-1… identity for -i

# Encrypt — anyone with the recipient can do this, no phone needed:
age -r "$(nb age recipient)" -o secret.age secret.txt

# Decrypt — once the relay rewire lands, your phone prompts for
# biometric approval. Today, age-plugin-nb's unwrap call hits the
# stubbed relay transport and returns ErrRelayNotImplemented.
age -d -i <(nb age identity) -o secret.txt secret.age
```

### GPG

```sh
nb gpg --generate-key --name "Alice" --email "alice@example.com"   # stubbed
nb gpg --list-keys                                                  # local
nb gpg --export FINGERPRINT                                         # local

# Sign — git uses this shape with -bsau FINGERPRINT.
# Today the sign path hits the stubbed relay transport; once the
# rewire lands the phone prompts and the signature is streamed back.
echo "test" | nb gpg -bsau FINGERPRINT

# Encrypt + decrypt — same status: stubbed today, phone-backed when
# the relay transport is rewired.
echo "hello" | nb gpg -e -r FINGERPRINT --armor > msg.asc
nb gpg --decrypt msg.asc
```

`nb gpg` is wire-compatible with the GPG command-line surface that `git`
and other tooling drive. Git's `gpg.program` config must name a single
executable rather than a command + subcommand, so wrap `nb gpg` in a tiny
script (e.g. `~/bin/nb-gpg`) and point `gpg.program` at the wrapper:

```sh
cat > ~/bin/nb-gpg <<'WRAPPER'
#!/bin/sh
exec nb gpg "$@"
WRAPPER
chmod +x ~/bin/nb-gpg
git config --global gpg.program "$HOME/bin/nb-gpg"
```

### SSH

```sh
# Key generation is stubbed today — it requires the rewired relay
# transport to ask the phone to mint a hardware-backed key. Once the
# rewire lands these emit the public key plus a key-handle blob.
nb ssh --generate-key -n laptop -o ~/.ssh/id_nb         # ECDSA P-256, default
nb ssh --generate-key -n laptop-ed25519 -t ed25519 -o ~/.ssh/id_nb_ed25519
nb ssh --list-keys                                       # local

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
profile in the `nb` binary with `NB_PROFILE=<name>` or `--profile <name>`,
and set log verbosity with `NB_LOG_LEVEL=debug|info|warn|error`.

The profile override is currently honoured only by `nb` itself. The
plugin binaries (`age-plugin-nb`) and the c-shared providers
(`libnb-pkcs11`, `libnb-sk`) load config directly and always read the
active profile from the config file. To exercise a non-active profile
through the plugin / PKCS#11 / SSH-SK paths, run `nb profile use <name>`
first to switch the active profile on disk.

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
