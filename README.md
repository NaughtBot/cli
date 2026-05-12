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
  delegates X25519 unwrap to your phone. Used transparently by the standard
  `age` and `rage` tools when you decrypt to an `age1nb1…` identity.
- `libnb-sk.{dylib,so}` — an OpenSSH `SecurityKey` provider shared library.
  Set `SSH_SK_PROVIDER=/path/to/libnb-sk.dylib` and use it like any other
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
everything above into the working tree:

```sh
git clone https://github.com/NaughtBot/cli && cd cli
make build
```

### Pre-built (when WS3.6 lands)

The pending release workflow will publish:

- macOS `.pkg` via Homebrew tap: `brew install naughtbot/tap/nb`.
- Linux `.deb` and `.rpm` packages from the GitHub Releases page.
- Standalone tarballs for each component (`nb`, `nb-sk-provider`,
  `nb-pkcs11`, `nb-age-plugin`) for manual install or container layering.

## Quick usage

Pair the CLI to your phone, then enroll a key per surface (SSH, GPG, age)
and use it from the matching standard tool.

### Pair

```sh
nb login                     # scan the QR code with the NaughtBot app
nb keys --sync               # pull enrolled signing keys down from your phone
nb keys                      # show enrolled keys grouped by purpose
```

> **Note — pairing is temporarily disabled.** `nb login` is being rewired
> against the new `github.com/naughtbot/api/auth` pairing surface and
> currently returns `login: not yet rewired to NaughtBot/api/auth pairing
> surface` (tracked under [NaughtBot/cli#12](https://github.com/NaughtBot/cli/issues/12)
> follow-ups). The `nb login --logout` sub-mode still works because it is
> a local-only operation. Existing profiles can still log out and re-pair
> once the new flow lands.

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

# Then use the key like any other SSH key. With the libnb-sk provider
# loaded, the phone signs each authentication challenge:
SSH_SK_PROVIDER=/usr/local/lib/libnb-sk.dylib ssh -i ~/.ssh/id_nb user@host
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

Default config locations:

- Linux: `~/.config/nb/`.
- macOS: `~/Library/Application Support/com.naughtbot.nb/`.
- Windows: `%AppData%\NaughtBot\nb\`.

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
