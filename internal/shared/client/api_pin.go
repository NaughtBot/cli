package client

// Blank-import the generated `github.com/naughtbot/api` client packages so
// `go mod tidy` keeps the module pinned in this repo's go.mod while the
// mailbox-DPoP / auth-pairing rewire is in progress. Per the cross-repo
// AGENTS.md contract, the generated `auth`, `blob`, and `mailbox` clients
// are the source of truth for the HTTP surfaces this package will rewire to
// in WS3.x — keeping the dependency pinned guards against silent drift even
// while the local types in this package are still hand-written stubs.
//
// TODO(WS3.x): delete these blank imports as each network surface lands on
// the real generated client (the imports will then be load-bearing).

import (
	_ "github.com/naughtbot/api/auth"
	_ "github.com/naughtbot/api/blob"
	_ "github.com/naughtbot/api/mailbox"
)
