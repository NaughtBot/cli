# NaughtBot CLI — AGENTS.md

> **WIP — see [NaughtBot/workspace#3](https://github.com/NaughtBot/workspace/issues/3).**

This repository was bootstrapped by importing the legacy `oobsign-cli` source
tree (see [NaughtBot/cli#1](https://github.com/NaughtBot/cli/issues/1)). The
tree does not build yet: the Go module path, several `replace` directives, and
the `internal/protocol/gen.go` symbols still reference the legacy monorepo.
Build, lint, and test commands will be wired up by the WS3.2 – WS3.6 PRs that
follow this one. See the detailed plan at
[`workspace/plans/2026-05-11-0208Z-cli-extraction.md`](https://github.com/NaughtBot/workspace/blob/main/plans/2026-05-11-0208Z-cli-extraction.md).
Until that work lands, treat the source tree as reference material only — do
not run `go build` and do not start additional rebrand / cleanup work without
coordinating with the master tracker.
