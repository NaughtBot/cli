#!/usr/bin/env bash
#
# run-test.sh — run a single NaughtBot E2E suite after ./setup.sh has bootstrapped
# the stack.
#
# Usage:
#   ./run-test.sh <suite> [--e2e] [--slot N] [--timeout T] [-- <go-test flags>]
#
# Where <suite> is one of: login, ssh, gpg, age, pkcs11.
#
# --e2e        sets RUN_NB_E2E=1 so suites that skip unless told explicitly
#              (all of them today) will run their full flow.
# --slot N     selects slot N's env.sh (/tmp/nb-e2e-slot-N/env.sh) and
#              streams device logs to /tmp/nb-<suite>-slot<N>-sim-log.
#              Default (no flag) uses the single-slot /tmp/nb-e2e/env.sh.
# --timeout T  passed to `go test -timeout T`. Default: unset (go default 10m).
# -- <flags>   anything after a bare `--` is forwarded verbatim to `go test`.
#
# The script:
#   1. sources /tmp/nb-e2e/env.sh (or slot N variant);
#   2. starts a simulator log stream scoped to com.naughtbot.ios;
#   3. invokes `go test ./tests/integration/<suite>/...`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=./lib/env.sh
source "$SCRIPT_DIR/lib/env.sh"

if [[ $# -lt 1 ]]; then
    log_error "usage: run-test.sh <suite> [--e2e] [--slot N] [-- <go-test flags>]"
    exit 2
fi

SUITE="$1"; shift
RUN_E2E=0
SLOT=""
GO_TEST_TIMEOUT=""
GO_TEST_EXTRA=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --e2e)
            RUN_E2E=1; shift;;
        --slot)
            SLOT="$2"
            export NB_E2E_SLOT="$2"
            shift 2;;
        --timeout)
            GO_TEST_TIMEOUT="$2"; shift 2;;
        --)
            shift
            GO_TEST_EXTRA=("$@")
            break;;
        *)
            log_warn "ignoring unknown flag: $1"
            shift;;
    esac
done

case "$SUITE" in
    ssh|gpg|age|pkcs11) ;;
    login)
        log_error "suite 'login' is not present in this repo (the legacy XCUITest"
        log_error "harness has not been re-introduced against the NaughtBot iOS"
        log_error "approver yet). See tests/integration/README.md for context."
        exit 2;;
    *)
        log_error "unknown suite: $SUITE (expected: ssh | gpg | age | pkcs11)"
        exit 2;;
esac

if [[ -n "$SLOT" ]]; then
    load_slot_env_state "$SLOT"
else
    load_env_file
fi

REPO_ROOT="$(nb_cli_root)"
SUITE_DIR="$REPO_ROOT/tests/integration/$SUITE"

if [[ ! -d "$SUITE_DIR" ]]; then
    log_error "suite directory does not exist: $SUITE_DIR"
    log_error "a typo like './run-test.sh ssh2 --e2e' must not produce a silent pass"
    exit 2
fi

if [[ -n "$SLOT" ]]; then
    SIM_LOG_FILE="${SIM_LOG_FILE:-/tmp/nb-$SUITE-slot${SLOT}-sim-log}"
else
    SIM_LOG_FILE="${SIM_LOG_FILE:-/tmp/nb-$SUITE-sim-log}"
fi
LOG_STREAM_PID=""

cleanup() {
    if [[ -n "$LOG_STREAM_PID" ]]; then
        kill "$LOG_STREAM_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

start_device_logs() {
    : > "$SIM_LOG_FILE"
    xcrun simctl spawn "$SIMULATOR_ID" log stream \
        --style compact \
        --level debug \
        --predicate 'subsystem == "com.naughtbot.ios"' \
        >"$SIM_LOG_FILE" 2>&1 &
    LOG_STREAM_PID="$!"
    log_info "streaming device logs → $SIM_LOG_FILE (pid $LOG_STREAM_PID)"
}

run_suite() {
    log_banner "NaughtBot E2E suite: $SUITE${SLOT:+ (slot $SLOT)}" \
        "Simulator:    $SIMULATOR_ID" \
        "CLI:          $NB_CLI" \
        "Config dir:   $NB_CONFIG_DIR" \
        "E2E data dir: $E2E_DATA_DIR" \
        "Sim log:      $SIM_LOG_FILE" \
        "Go args:      ${GO_TEST_EXTRA[*]:-<none>}"

    # Per-suite state lives inside the coordination dir so previous runs do
    # not leak `approval_complete.txt` / `approval_error.txt` between tests.
    rm -f "$E2E_DATA_DIR/approval_complete.txt" "$E2E_DATA_DIR/approval_error.txt" \
        "$E2E_DATA_DIR/qr_url.txt" "$E2E_DATA_DIR/approval_request.txt" \
        "$E2E_DATA_DIR/callback_debug.txt" "$E2E_DATA_DIR/sekey_debug.txt"

    export SIMULATOR_ID NB_CLI NB_CLI_PATH AGE_PLUGIN SK_DYLIB PKCS11_DYLIB
    export NB_CONFIG_DIR E2E_DATA_DIR NB_APP_PATH DERIVED_DATA_PATH
    export TEST_LOGIN_URL TEST_RELAY_URL TEST_BLOB_URL TEST_SSH_HOST TEST_SSH_PORT
    if [[ "$RUN_E2E" == "1" ]]; then
        export RUN_NB_E2E=1
    fi

    # PKCS#11 loads libnb-pkcs11.dylib in-process via dlopen. The
    # dylib embeds its own Go runtime with an independent env snapshot, so
    # SKIP_VERIFY_ATTESTATION must be present in the test process's initial
    # environment — setting it later from TestMain (os.Setenv or C.setenv)
    # does not propagate into the dylib runtime. Paired with the DEV=1
    # build that bakes AllowSkipAttestation="true" via ldflags.
    if [[ "$SUITE" == "pkcs11" ]]; then
        export SKIP_VERIFY_ATTESTATION=true
    fi

    local -a go_test_cmd=(go test -v -count=1 -tags=integration)
    if [[ -n "$GO_TEST_TIMEOUT" ]]; then
        go_test_cmd+=(-timeout "$GO_TEST_TIMEOUT")
    fi
    (
        cd "$SUITE_DIR"
        "${go_test_cmd[@]}" "${GO_TEST_EXTRA[@]+"${GO_TEST_EXTRA[@]}"}" ./...
    )
}

dump_failure_context() {
    log_error "suite $SUITE failed — dumping context"
    log_warn "---- device log (last 200 lines) ----"
    tail -n 200 "$SIM_LOG_FILE" 2>/dev/null || true
    log_warn "---- coordination dir $E2E_DATA_DIR ----"
    ls -la "$E2E_DATA_DIR" 2>/dev/null || true
    for f in "$E2E_DATA_DIR"/*.txt; do
        [[ -e "$f" ]] || continue
        log_warn "---- $(basename "$f") ----"
        head -n 200 "$f" || true
    done
    log_warn "---- NB_CONFIG_DIR $NB_CONFIG_DIR ----"
    if [[ -d "$NB_CONFIG_DIR" ]]; then
        (cd "$NB_CONFIG_DIR" && find . -maxdepth 3 -print) || true
    fi
}

main() {
    start_device_logs
    if run_suite; then
        if [[ "$SUITE" == "login" && "$RUN_E2E" == "1" ]]; then
            mark_env_login_complete "${SLOT:-}"
        fi
        log_ok "suite $SUITE passed"
    else
        local ec=$?
        log_error "suite $SUITE failed (exit $ec)"
        dump_failure_context
        exit "$ec"
    fi
}

main "$@"
