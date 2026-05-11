# NaughtBot CLI

> **Status: WIP — does not build yet.**
>
> This repository was bootstrapped by importing the legacy `oobsign-cli` source
> tree from the internal monorepo. The Go module path, imports, generated
> protocol types, and user-visible branding still reference the old layout and
> will not compile until subsequent PRs land.
>
> Tracking:
>
> - Master tracker: [NaughtBot/workspace#3](https://github.com/NaughtBot/workspace/issues/3)
> - Bootstrap issue: [NaughtBot/cli#1](https://github.com/NaughtBot/cli/issues/1)
> - Detailed plan: [`workspace/plans/2026-05-11-0208Z-cli-extraction.md`](https://github.com/NaughtBot/workspace/blob/main/plans/2026-05-11-0208Z-cli-extraction.md)
>
> Go module rename + dependency rewire lands in WS3.2; full rebrand sweep
> (binary names, identifiers, user-visible strings, `internal/protocol/gen.go`
> removal) lands in WS3.3. Test fixtures, integration suites, packaging, CI,
> and a proper `AGENTS.md` follow in WS3.4–WS3.7.

---

Command-line tool for SSH, GPG, and age signing. Routes signing requests to
your phone for biometric approval with hardware-backed cryptographic keys.

Public-facing documentation, install instructions, and brand-aligned content
will be filled in once the rebrand sweep (WS3.3) lands.
