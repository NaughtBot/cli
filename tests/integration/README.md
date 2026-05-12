# Integration Tests

End-to-end tests that exercise the NaughtBot CLI's hardware-backed signing
flows (ssh, gpg, age, pkcs11) against the iOS approver app.

> **WS3.5 status:** The Go suites build cleanly under `-tags=integration`
> but do not run end-to-end yet. The legacy `OOBSignE2E` Xcode scheme and
> the `OOBSignUITests` XCUITest bundle have not been re-created against
> the NaughtBot iOS app target. Until that approval-UI follow-up lands,
> the harness scripts (`setup.sh`, `run-test.sh`, `run-parallel.sh`,
> `teardown.sh`, `status.sh`) are present for reference but cannot drive
> a full run. They reference `mobile/ios/apps/NaughtBot/` resolved through
> the sibling workspace checkout (override with `WORKSPACE_ROOT`).
>
> The `login` suite has not been moved over yet; the legacy login flow is
> tied to the OOBSign-era XCUITest harness and will be re-introduced once
> the NaughtBot approver app has an equivalent E2E test bundle.

The legacy harness shared the same `docker-compose.yml` stack as the rest
of the monorepo. In the new layout the stack lives in the sibling `core/`
checkout (see `nb_workspace_root` in `lib/common.sh`).

---

## NaughtBot E2E

### Quick start

```bash
cd tests/integration

# One-time bootstrap: build CLI + sidecar binaries, bring up docker with
# the nb-e2e-testing profile, reset a simulator, and xcodebuild
# build-for-testing the NaughtBot scheme under LocalDev.
./setup.sh --build --clean-start

# Run a suite. --e2e sets RUN_NB_E2E=1 so the suite actually executes
# (suites skip by default outside the harness). The `login` suite has not
# been re-introduced after the cli extraction — see "WS3.5 status" above.
./run-test.sh ssh    --e2e
./run-test.sh gpg    --e2e
./run-test.sh age    --e2e
./run-test.sh pkcs11 --e2e

# Check stack health at any time.
./status.sh

# Tear everything down.
./teardown.sh --all
```

### Scripts

| Script            | Purpose                                                               |
|-------------------|-----------------------------------------------------------------------|
| `setup.sh`        | Build CLI, start docker stack, reset sim, build NaughtBot            |
| `setup.sh --parallel N` | Create N slots (sims + dirs) and run login on each concurrently |
| `run-test.sh`     | Run a single suite, stream device logs, dump failure context          |
| `run-test.sh --slot N` | Same, against slot N's simulator/config                          |
| `run-parallel.sh` | Round-robin dispatch suites across all slots, concurrent across slots |
| `status.sh`       | Health check; `--quick` exits 0/1 only                                |
| `teardown.sh`     | Stop docker + log streams; `--all` also wipes tmp state + slot sims   |

### Layout

```
tests/integration/
  setup.sh run-test.sh teardown.sh status.sh
  lib/
    common.sh     log_{info,warn,error,step,ok,banner}, wait_for_*, require_command
    env.sh        slot-aware data_dir/config_dir, write/load env.sh, health checks
  shared/         github.com/naughtbot/cli/tests/integration/shared
    e2e.go        file-IPC (qr_url.txt, approval_{complete,error}.txt, ...)
    helpers.go    SetupTestEnv, TestEnv, WaitForQRURL, IsLoggedIn, ...
    simulator.go  RunFullE2ELogin, RunApprovalUITest, SimctlOpenURL, ...
    logging.go    LogEnvDump, LogStep, DumpCoordinationDir, TeeToLog
  login/          (Phase 2) nb login --localdev + E2EFullFlowUITests
  ssh/ gpg/ age/ pkcs11/   (Phase 3) non-login suites via E2EApprovalUITests
```

### State & coordination dirs

Single-slot defaults (phase 1):

| Path                                   | Role                                 |
|----------------------------------------|--------------------------------------|
| `/tmp/nb-e2e/`                    | XCUITest ↔ Go file IPC               |
| `/tmp/nb-e2e/env.sh`              | setup.sh → run-test.sh env snapshot  |
| `/tmp/nb-e2e-config-<ts>-<pid>/`  | NB_CONFIG_DIR (CLI profile etc) |
| `/tmp/nb-e2e-derived-data/`       | DerivedData for xcodebuild           |
| `/tmp/nb-<suite>-sim-log`         | Per-suite device log stream          |
| `/tmp/nb-e2e/last-test-output.txt`| Aggregate tee'd output               |

Parallel slots use `/tmp/nb-e2e-slot-N/` and
`/tmp/nb-e2e-config-slot-N/` instead (see Parallel mode below).

### Parallel mode

For shorter wall-clock time, run multiple suites on separate simulators
concurrently:

```bash
cd tests/integration

# Bootstrap 3 isolated slots (creates 3 fresh simulators named
# NaughtBot-E2E-0..2, runs login on each in parallel, writes per-slot env.sh).
./setup.sh --parallel 3 --clean-start --build

# Dispatch the default five suites (login ssh age gpg pkcs11) across the slots.
# Suites are assigned round-robin; suites on the same slot run sequentially,
# different slots run concurrently.
./run-parallel.sh

# Run a subset instead.
./run-parallel.sh --suites ssh,gpg

# Full cleanup — also deletes the NaughtBot-E2E-* simulators + slot state.
./teardown.sh --all
```

Slot layout after `./setup.sh --parallel N`:

| Path                                | Role                                   |
|-------------------------------------|----------------------------------------|
| `/tmp/nb-e2e-meta/parallel-count` | Recorded slot count                 |
| `/tmp/nb-e2e-slot-<N>/`        | Slot N coordination dir (E2E_DATA_DIR) |
| `/tmp/nb-e2e-slot-<N>/env.sh`  | Slot N env snapshot (NB_E2E_SLOT) |
| `/tmp/nb-e2e-config-slot-<N>/` | Slot N CLI config dir                  |
| `/tmp/nb-parallel-<suite>-slot<N>-<ts>.log` | Per-suite run log         |
| `/tmp/nb-parallel-slot<N>-<ts>.log` | Per-slot aggregate runner log     |
| `/tmp/nb-<suite>-slot<N>-sim-log` | Per-suite device log stream         |

Notes:
- The docker backend stack is shared across slots; only the simulators and
  coordination/config directories are per-slot.
- `./run-test.sh <suite> --e2e --slot <N>` runs one suite on a specific slot
  (useful for re-running a failing suite in isolation).
- Single-slot mode (no `--parallel` flag) is the default; nothing changes
  when you don't opt in.

### File-IPC contract

| File                    | Writer    | Reader    | Contents                       |
|-------------------------|-----------|-----------|--------------------------------|
| `qr_url.txt`            | Go        | XCUITest  | QR login URL                   |
| `relay_url.txt`         | Go        | XCUITest  | Relay URL                      |
| `login_url.txt`         | Go        | XCUITest  | Login URL                      |
| `blob_url.txt`          | Go        | XCUITest  | Blob URL                       |
| `approval_request.txt`  | Go        | XCUITest  | Expected request type          |
| `approval_complete.txt` | XCUITest  | Go        | `"success"` on pass            |
| `approval_error.txt`    | XCUITest  | Go        | Error message on failure       |
| `callback_debug.txt`    | XCUITest  | Go        | Push/response callback trace   |
| `sekey_debug.txt`       | XCUITest  | Go        | Secure Enclave / key-op trace  |

### iOS target

`mobile/ios/apps/NaughtBot/project.yml` defines:

- `LocalDev` build configuration (inherits Debug, points `OOBSIGN_*_URL` at
  the docker compose services on `127.0.0.1`).
- `NaughtBotUITests` XCUITest bundle with `com.nb.NaughtBotUITests`.
- `NaughtBot` scheme that test-builds `NaughtBotUITests` under `LocalDev`.

Run `xcodegen generate --spec mobile/ios/apps/NaughtBot/project.yml` after editing.

### App launch-environment hooks

Honoured only when `RUN_INTEGRATION_TESTS=1`:

| Env var                    | Effect                                                  |
|----------------------------|---------------------------------------------------------|
| `FORCE_CLEAN_STATE=1`      | Wipes AuthAccount data on launch                        |
| `FORCE_SOFTWARE_KEY=1`     | Falls back from Secure Enclave to software keys         |
| `FORCE_SOFTWARE_ATTESTATION=1` | Bypasses AppAttest on the device                    |
| `TEST_RELAY_URL`           | Override relay URL                                      |
| `TEST_LOGIN_URL`           | Override login URL                                      |
| `TEST_BLOB_URL`            | Override blob URL                                       |
| `E2E_AUTO_CREATE_ACCOUNT=1`| On first appearance of auth view, create test account   |
| `E2E_AUTO_CONFIRM_SAS=1`   | On SAS device-login detail view, auto-tap confirm       |
| `E2E_AUTO_APPROVE=1`       | On other pending-request detail views, auto-tap approve |

Universal-link delivery uses `xcrun simctl openurl` on the host. The XCUITest
writes `open_url_request.txt`; the Go harness's `ServeOpenURLRequests`
goroutine dispatches simctl and acknowledges via `open_url_delivered.txt`.

### Docker

`docker compose --profile nb-e2e-testing up` brings up the default dev
stack plus `nb-ssh-server` (openssh-server on `localhost:2222`) for the
ssh suite.

### Requirements

- macOS with Xcode 16+ and an iOS Simulator (iPhone 17 or Pro)
- Docker + docker compose
- Go 1.24+
- `xcodegen`, `jq`, `curl`, `make` on `PATH`

---

## NaughtBot iOS Local-Dev Flow

```bash
cd tests/integration

# Rebuild docker-compose services, wipe the simulator, launch NaughtBot,
# and run the real captcha flow against the example page.
./run-naughtbot-ios-local-dev.sh
```

This path is separate from the NaughtBot harness. It launches the
`ios/naughtbot` app with integration-only automation flags, targets the
local `docker-compose.yml` stack, and runs Playwright against the
`naughtbot-example` page on `http://127.0.0.1:8084`. The Playwright/browser
side hands the captcha QR URL to the simulator app through a localhost
bridge, which avoids iOS pasteboard and custom-scheme confirmation prompts.
