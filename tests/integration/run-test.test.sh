#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_TMP="$(mktemp -d)"
BIN_DIR="$TEST_TMP/bin"
SIM_LOG_FILE="$TEST_TMP/sim.log"

cleanup() {
    rm -rf "$TEST_TMP"
    rm -rf /tmp/nb-e2e-slot-run-test-regression-fail-$$
    rm -rf /tmp/nb-e2e-slot-run-test-regression-success-$$
}
trap cleanup EXIT

mkdir -p "$BIN_DIR"

write_go_stub() {
    local exit_code="$1"
    cat >"$BIN_DIR/go" <<EOF
#!/usr/bin/env bash
exit $exit_code
EOF
    chmod +x "$BIN_DIR/go"
}

cat >"$BIN_DIR/xcrun" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "simctl" && "${2:-}" == "spawn" ]]; then
    echo "stub simulator log"
    exit 0
fi
exit 1
EOF
chmod +x "$BIN_DIR/xcrun"

write_env_file() {
    local slot="$1"
    local state_dir="/tmp/nb-e2e-slot-$slot"
    local env_file="$state_dir/env.sh"
    local config_dir="$TEST_TMP/config-$slot"
    local data_dir="$TEST_TMP/data-$slot"

    mkdir -p "$state_dir" "$config_dir" "$data_dir"

    cat >"$env_file" <<EOF
export SIMULATOR_ID=test-sim
export NB_CLI=$TEST_TMP/nb-cli
export NB_CLI_PATH=$TEST_TMP/nb-cli-canonical
export AGE_PLUGIN=$TEST_TMP/age-plugin
export SK_DYLIB=$TEST_TMP/sk.dylib
export PKCS11_DYLIB=$TEST_TMP/pkcs11.dylib
export NB_CONFIG_DIR=$config_dir
export E2E_DATA_DIR=$data_dir
export NB_APP_PATH=$TEST_TMP/NaughtBot.app
export DERIVED_DATA_PATH=$TEST_TMP/DerivedData
export TEST_LOGIN_URL=http://127.0.0.1:4456
export TEST_RELAY_URL=http://127.0.0.1:8080
export TEST_BLOB_URL=http://127.0.0.1:8082
export TEST_SSH_HOST=127.0.0.1
export TEST_SSH_PORT=2222
export NB_E2E_LOGIN_DONE=0
EOF
}

FAIL_SLOT="run-test-regression-fail-$$"
FAIL_OUTPUT_FILE="$TEST_TMP/output-fail.txt"
FAIL_STATE_DIR="/tmp/nb-e2e-slot-$FAIL_SLOT"
FAIL_ENV_FILE="$FAIL_STATE_DIR/env.sh"
FAIL_DATA_DIR="$TEST_TMP/data-$FAIL_SLOT"

write_go_stub 17
write_env_file "$FAIL_SLOT"
PATH="$BIN_DIR:$PATH" \
SIM_LOG_FILE="$SIM_LOG_FILE" \
    bash "$REPO_ROOT/tests/integration/run-test.sh" ssh --slot "$FAIL_SLOT" \
    >"$FAIL_OUTPUT_FILE" 2>&1 || ec=$?

ec="${ec:-0}"
if [[ "$ec" -ne 17 ]]; then
    echo "expected exit code 17, got $ec"
    cat "$FAIL_OUTPUT_FILE"
    exit 1
fi

if ! grep -q "suite ssh failed — dumping context" "$FAIL_OUTPUT_FILE"; then
    echo "expected failure context dump in output"
    cat "$FAIL_OUTPUT_FILE"
    exit 1
fi

if ! grep -q -- "---- coordination dir $FAIL_DATA_DIR ----" "$FAIL_OUTPUT_FILE"; then
    echo "expected coordination directory dump in output"
    cat "$FAIL_OUTPUT_FILE"
    exit 1
fi

if ! grep -q 'export NB_E2E_LOGIN_DONE=0' "$FAIL_ENV_FILE"; then
    echo "expected failed ssh run to leave NB_E2E_LOGIN_DONE unchanged"
    cat "$FAIL_ENV_FILE"
    exit 1
fi

SUCCESS_SLOT="run-test-regression-success-$$"
SUCCESS_OUTPUT_FILE="$TEST_TMP/output-success.txt"
SUCCESS_STATE_DIR="/tmp/nb-e2e-slot-$SUCCESS_SLOT"
SUCCESS_ENV_FILE="$SUCCESS_STATE_DIR/env.sh"

write_go_stub 0
write_env_file "$SUCCESS_SLOT"
PATH="$BIN_DIR:$PATH" \
SIM_LOG_FILE="$SIM_LOG_FILE" \
    bash "$REPO_ROOT/tests/integration/run-test.sh" ssh --e2e --slot "$SUCCESS_SLOT" \
    >"$SUCCESS_OUTPUT_FILE" 2>&1

if ! grep -q "suite ssh passed" "$SUCCESS_OUTPUT_FILE"; then
    echo "expected success output"
    cat "$SUCCESS_OUTPUT_FILE"
    exit 1
fi

if ! grep -q 'export NB_E2E_LOGIN_DONE=0' "$SUCCESS_ENV_FILE"; then
    echo "expected successful ssh run to leave NB_E2E_LOGIN_DONE unchanged (only the login suite advances this flag)"
    cat "$SUCCESS_ENV_FILE"
    exit 1
fi

echo "run-test.sh regression tests passed"
