#!/usr/bin/env bash
#
# setup.sh — one-shot bootstrap for the NaughtBot E2E harness.
#
# Responsibilities:
#   1. Build the NaughtBot CLI + sidecar binaries (age-plugin, sk dylib, pkcs11 dylib).
#   2. Start the docker-compose stack with the `nb-e2e-testing` profile.
#   3. Wait for gateway / identity / blob / relay / ssh-server to be healthy.
#   4. Pick an iOS Simulator, reset it, and xcodegen + xcodebuild-build-for-testing
#      the NaughtBot scheme under LocalDev.
#   5. Snapshot all state into env.sh so run-test.sh can source it.
#
# Flags:
#   --build / --no-build     (default --build) — skip if binaries are current.
#   --clean-start            — teardown + wipe temp dirs before bringing the
#                              stack up (equivalent to `teardown.sh --all` then
#                              re-run).
#   --sim-name <name>        — simulator name (default "iPhone 17" w/ Pro fallback).
#   --parallel N             — create N isolated slots (each with its own
#                              simulator + coordination/config dir), run login
#                              on each slot, and record the slot count for
#                              run-parallel.sh. Default (no flag) is the
#                              original single-slot flow.
#
# Conventions follow tests/integration/run-naughtbot-ios-local-dev.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=./lib/env.sh
source "$SCRIPT_DIR/lib/env.sh"

REPO_ROOT="$(nb_cli_root)"
WORKSPACE_ROOT="$(nb_workspace_root)"

DO_BUILD=1
DO_CLEAN_START=0
SIMULATOR_NAME="${SIMULATOR_NAME:-iPhone 17}"
FALLBACK_SIMULATOR_NAME="${FALLBACK_SIMULATOR_NAME:-iPhone 17 Pro}"
PARALLEL_SLOTS=0

DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-/tmp/nb-e2e-derived-data}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)
            DO_BUILD=1; shift;;
        --no-build)
            DO_BUILD=0; shift;;
        --clean-start)
            DO_CLEAN_START=1; shift;;
        --sim-name)
            SIMULATOR_NAME="$2"; shift 2;;
        --parallel)
            PARALLEL_SLOTS="$2"
            if ! [[ "$PARALLEL_SLOTS" =~ ^[0-9]+$ ]] || (( PARALLEL_SLOTS < 1 )); then
                log_error "--parallel requires a positive integer (got: $PARALLEL_SLOTS)"
                exit 2
            fi
            shift 2;;
        -h|--help)
            sed -n '2,35p' "$0"
            exit 0;;
        *)
            log_warn "ignoring unknown flag: $1"
            shift;;
    esac
done

E2E_DATA_DIR="$(nb_e2e_data_dir)"
NB_CONFIG_DIR="$(nb_e2e_config_dir)"

require_command docker
require_command xcrun
require_command xcodebuild
require_command xcodegen
require_command jq
require_command curl
require_command make

clean_start() {
    log_step "clean-start: tearing down docker compose state"
    (
        cd "$WORKSPACE_ROOT/core"
        docker compose --profile nb-e2e-testing down -v --remove-orphans >/dev/null 2>&1 || true
    )
    log_step "clean-start: shutting down iOS simulators"
    xcrun simctl shutdown all >/dev/null 2>&1 || true
    log_step "clean-start: deleting prior parallel-slot simulators (NB-E2E-*)"
    xcrun simctl list devices -j 2>/dev/null \
        | jq -r '.devices | to_entries[] | .value[]
            | select(.name | startswith("NB-E2E-")) | .udid' \
        | while IFS= read -r udid; do
            [[ -n "$udid" ]] || continue
            xcrun simctl delete "$udid" >/dev/null 2>&1 || true
        done
    log_step "clean-start: wiping coordination + config dirs"
    rm -rf \
        /tmp/nb-e2e \
        /tmp/nb-e2e-slot-* \
        /tmp/nb-e2e-config-* \
        /tmp/nb-e2e-meta \
        "$DERIVED_DATA_PATH" || true
    mkdir -p "$E2E_DATA_DIR"
}

build_cli() {
    log_step "building nb CLI + sidecars (DEV=1)"
    (
        cd "$REPO_ROOT"
        make build DEV=1
        # age-plugin-nb is not part of `make build` — build it here so
        # the age suite has a usable plugin alongside the CLI.
        CGO_ENABLED=1 go build \
            -ldflags="-X github.com/naughtbot/cli/internal/shared/transport.AllowSkipAttestation=true" \
            -o age-plugin-nb ./cmd/age-plugin-nb
    )
    local cli="$REPO_ROOT/nb"
    if [[ ! -x "$cli" ]]; then
        log_error "nb CLI not found after build: $cli"
        exit 1
    fi
    local size
    size="$(stat -f%z "$cli" 2>/dev/null || stat -c%s "$cli")"
    log_info "built nb CLI: $cli ($size bytes)"
    NB_CLI="$cli"
    AGE_PLUGIN="$REPO_ROOT/age-plugin-nb"
    SK_DYLIB="$REPO_ROOT/sk-provider/libnb-sk.dylib"
    PKCS11_DYLIB="$REPO_ROOT/pkcs11-provider/libnb-pkcs11.dylib"
}

start_stack() {
    log_step "starting docker compose with profile nb-e2e-testing"
    (
        cd "$WORKSPACE_ROOT/core"
        docker compose --profile nb-e2e-testing up --build -d
    )
    log_step "waiting for backend services to be healthy"
    wait_for_url "http://127.0.0.1:4455/.well-known/openid-configuration" "Gateway OIDC" 180
    wait_for_url "$(identity_management_url)/health" "Identity management endpoint" 180
    wait_for_url "$(blob_management_url)/health" "Blob management endpoint" 180
    wait_for_url "$(relay_management_url)/health" "Relay management endpoint" 180
    wait_for_tcp_port "127.0.0.1" "2222" "SSH test server" 60
}

resolve_simulator() {
    log_step "resolving iOS simulator ($SIMULATOR_NAME / $FALLBACK_SIMULATOR_NAME)"
    local candidate
    candidate="$(xcrun simctl list devices available -j | jq -r --arg name "$SIMULATOR_NAME" '
        .devices | to_entries[] | .value[]
        | select(.name == $name and .isAvailable == true) | .udid' | head -n 1)"
    if [[ -z "$candidate" ]]; then
        log_warn "primary simulator '$SIMULATOR_NAME' not found; trying fallback"
        candidate="$(xcrun simctl list devices available -j | jq -r --arg name "$FALLBACK_SIMULATOR_NAME" '
            .devices | to_entries[] | .value[]
            | select(.name == $name and .isAvailable == true) | .udid' | head -n 1)"
    fi
    if [[ -z "$candidate" ]]; then
        log_error "no usable iOS simulator found"
        exit 1
    fi
    SIMULATOR_ID="$candidate"
    log_info "using simulator $SIMULATOR_ID"
}

reset_and_boot_simulator() {
    log_step "resetting + booting simulator $SIMULATOR_ID"
    xcrun simctl shutdown "$SIMULATOR_ID" >/dev/null 2>&1 || true
    xcrun simctl erase "$SIMULATOR_ID"
    xcrun simctl boot "$SIMULATOR_ID" >/dev/null 2>&1 || true
    xcrun simctl bootstatus "$SIMULATOR_ID" -b
}

regenerate_xcodeproj() {
    log_step "regenerating NaughtBot.xcodeproj via xcodegen"
    (
        cd "$WORKSPACE_ROOT/mobile/ios/apps/NaughtBot"
        xcodegen generate --spec project.yml
    )
}

build_ios_test_bundle() {
    log_step "xcodebuild build-for-testing (NaughtBot / LocalDev)"
    rm -rf "$DERIVED_DATA_PATH"
    local -a cmd=(
        xcodebuild
        build-for-testing
        -project "$WORKSPACE_ROOT/mobile/ios/apps/NaughtBot/NaughtBot.xcodeproj"
        -scheme "NaughtBot"
        -configuration "LocalDev"
        -destination "platform=iOS Simulator,id=$SIMULATOR_ID"
        -derivedDataPath "$DERIVED_DATA_PATH"
    )
    if command -v xcbeautify >/dev/null 2>&1; then
        (set -o pipefail; "${cmd[@]}" 2>&1 | xcbeautify)
    else
        "${cmd[@]}"
    fi
    local app_path="$DERIVED_DATA_PATH/Build/Products/LocalDev-iphonesimulator/NaughtBot.app"
    if [[ ! -d "$app_path" ]]; then
        log_error "built app not found at $app_path"
        exit 1
    fi
    xcrun simctl install "$SIMULATOR_ID" "$app_path"
    NB_APP_PATH="$app_path"
}

snapshot_env() {
    mkdir -p "$NB_CONFIG_DIR"
    write_env_file \
        "SIMULATOR_ID=$SIMULATOR_ID" \
        "SIMULATOR_NAME=$SIMULATOR_NAME" \
        "NB_CLI=$NB_CLI" \
        "NB_CLI_PATH=$NB_CLI" \
        "AGE_PLUGIN=$AGE_PLUGIN" \
        "SK_DYLIB=$SK_DYLIB" \
        "PKCS11_DYLIB=$PKCS11_DYLIB" \
        "NB_APP_PATH=$NB_APP_PATH" \
        "DERIVED_DATA_PATH=$DERIVED_DATA_PATH" \
        "NB_CONFIG_DIR=$NB_CONFIG_DIR" \
        "E2E_DATA_DIR=$E2E_DATA_DIR" \
        "TEST_LOGIN_URL=http://127.0.0.1:4455" \
        "TEST_RELAY_URL=http://127.0.0.1:8080" \
        "TEST_BLOB_URL=http://127.0.0.1:8082" \
        "IDENTITY_MANAGEMENT_URL=$(identity_management_url)" \
        "RELAY_MANAGEMENT_URL=$(relay_management_url)" \
        "BLOB_MANAGEMENT_URL=$(blob_management_url)" \
        "TEST_SSH_HOST=127.0.0.1" \
        "TEST_SSH_PORT=2222" \
        "NB_E2E_SLOT=${NB_E2E_SLOT:-}"
}

print_summary() {
    log_banner "NaughtBot E2E setup complete" \
        "Simulator:         $SIMULATOR_ID ($SIMULATOR_NAME)" \
        "CLI:               $NB_CLI" \
        "App:               $NB_APP_PATH" \
        "Login URL:         http://127.0.0.1:4455" \
        "Relay URL:         http://127.0.0.1:8080" \
        "Blob URL:          http://127.0.0.1:8082" \
        "SSH server:        127.0.0.1:2222" \
        "Coordination dir:  $E2E_DATA_DIR" \
        "CLI config dir:    $NB_CONFIG_DIR" \
        "Env snapshot:      $(nb_e2e_env_file)" \
        "" \
        "Next: ./run-test.sh <suite> --e2e    (suites: login ssh gpg age pkcs11)"
}

# --------------------------------------------------------------------------
# Parallel (--parallel N) path
# --------------------------------------------------------------------------
# Each slot gets a dedicated simulator, coordination dir, and CLI config dir.
# The docker stack is shared; the login suite is expected to create distinct
# accounts per slot (each slot runs TestLoginFlow in its own config root).

parallel_resolve_device_type_and_runtime() {
    local sim_name="$SIMULATOR_NAME"
    PARALLEL_DEVICE_TYPE="$(xcrun simctl list devicetypes -j \
        | jq -r --arg n "$sim_name" '.devicetypes[] | select(.name == $n) | .identifier' | head -n 1)"
    PARALLEL_RUNTIME="$(xcrun simctl list runtimes -j \
        | jq -r '[.runtimes[] | select(.isAvailable == true and (.platform == "iOS" or (.identifier | contains("iOS")))) | .identifier] | .[-1]')"
    if [[ -z "$PARALLEL_DEVICE_TYPE" || "$PARALLEL_DEVICE_TYPE" == "null" ]]; then
        log_warn "device type '$sim_name' not found, trying fallback '$FALLBACK_SIMULATOR_NAME'"
        sim_name="$FALLBACK_SIMULATOR_NAME"
        PARALLEL_DEVICE_TYPE="$(xcrun simctl list devicetypes -j \
            | jq -r --arg n "$sim_name" '.devicetypes[] | select(.name == $n) | .identifier' | head -n 1)"
    fi
    if [[ -z "$PARALLEL_DEVICE_TYPE" || "$PARALLEL_DEVICE_TYPE" == "null" ]]; then
        log_error "no usable iPhone device type for parallel slot creation"
        exit 1
    fi
    if [[ -z "$PARALLEL_RUNTIME" || "$PARALLEL_RUNTIME" == "null" ]]; then
        log_error "no available iOS runtime found"
        exit 1
    fi
    PARALLEL_DEVICE_NAME="$sim_name"
    log_info "parallel mode using device type: $PARALLEL_DEVICE_TYPE ($PARALLEL_DEVICE_NAME)"
    log_info "parallel mode using runtime:    $PARALLEL_RUNTIME"
}

parallel_create_slots() {
    SLOT_SIM_IDS=()
    local slot name existing udid
    for slot in $(seq 0 $((PARALLEL_SLOTS - 1))); do
        name="NB-E2E-$slot"
        # Delete any lingering sim with the same name (e.g. from a prior setup
        # that didn't run teardown --all). Keep this idempotent.
        while IFS= read -r udid; do
            [[ -n "$udid" ]] || continue
            log_info "  slot $slot: deleting existing simulator $name ($udid)"
            xcrun simctl delete "$udid" >/dev/null 2>&1 || true
        done < <(xcrun simctl list devices -j 2>/dev/null \
            | jq -r --arg n "$name" '.devices | to_entries[] | .value[] | select(.name == $n) | .udid')

        log_info "  slot $slot: creating simulator $name"
        local sim_id
        sim_id="$(xcrun simctl create "$name" "$PARALLEL_DEVICE_TYPE" "$PARALLEL_RUNTIME")"
        SLOT_SIM_IDS+=("$sim_id")
        log_info "  slot $slot: created $sim_id"

        xcrun simctl boot "$sim_id" >/dev/null 2>&1 || true
    done

    for slot in $(seq 0 $((PARALLEL_SLOTS - 1))); do
        local sim_id="${SLOT_SIM_IDS[$slot]}"
        xcrun simctl bootstatus "$sim_id" -b >/dev/null 2>&1 || true
        log_info "  slot $slot: simulator booted ($sim_id)"
    done
}

parallel_build_and_install() {
    # Build the test bundle once against slot 0's simulator, then install the
    # resulting .app onto every slot's simulator. Reusing a single DerivedData
    # tree across slots is safe because run-test.sh passes SKIP_TEST_BUILD=1
    # during the parallel path via test-without-building.
    local sim_id_0="${SLOT_SIM_IDS[0]}"
    log_step "xcodebuild build-for-testing (NaughtBot / LocalDev) against slot 0 sim"
    rm -rf "$DERIVED_DATA_PATH"
    local -a cmd=(
        xcodebuild
        build-for-testing
        -project "$WORKSPACE_ROOT/mobile/ios/apps/NaughtBot/NaughtBot.xcodeproj"
        -scheme "NaughtBot"
        -configuration "LocalDev"
        -destination "platform=iOS Simulator,id=$sim_id_0"
        -derivedDataPath "$DERIVED_DATA_PATH"
    )
    if command -v xcbeautify >/dev/null 2>&1; then
        (set -o pipefail; "${cmd[@]}" 2>&1 | xcbeautify)
    else
        "${cmd[@]}"
    fi
    local app_path="$DERIVED_DATA_PATH/Build/Products/LocalDev-iphonesimulator/NaughtBot.app"
    if [[ ! -d "$app_path" ]]; then
        log_error "built app not found at $app_path"
        exit 1
    fi
    NB_APP_PATH="$app_path"

    local slot sim_id
    for slot in $(seq 0 $((PARALLEL_SLOTS - 1))); do
        sim_id="${SLOT_SIM_IDS[$slot]}"
        xcrun simctl install "$sim_id" "$app_path"
        log_info "  slot $slot: installed app on $sim_id"
    done
}

parallel_write_slot_envs() {
    local slot sim_id slot_data slot_cfg
    for slot in $(seq 0 $((PARALLEL_SLOTS - 1))); do
        sim_id="${SLOT_SIM_IDS[$slot]}"
        slot_data="$(slot_state_dir "$slot")"
        slot_cfg="$(slot_config_dir "$slot")"
        mkdir -p "$slot_data" "$slot_cfg"
        write_slot_env_state "$slot" \
            "SIMULATOR_ID=$sim_id" \
            "SIMULATOR_NAME=$PARALLEL_DEVICE_NAME" \
            "NB_CLI=$NB_CLI" \
            "NB_CLI_PATH=$NB_CLI" \
            "AGE_PLUGIN=$AGE_PLUGIN" \
            "SK_DYLIB=$SK_DYLIB" \
            "PKCS11_DYLIB=$PKCS11_DYLIB" \
            "NB_APP_PATH=$NB_APP_PATH" \
            "DERIVED_DATA_PATH=$DERIVED_DATA_PATH" \
            "NB_CONFIG_DIR=$slot_cfg" \
            "E2E_DATA_DIR=$slot_data" \
            "TEST_LOGIN_URL=http://127.0.0.1:4455" \
            "TEST_RELAY_URL=http://127.0.0.1:8080" \
            "TEST_BLOB_URL=http://127.0.0.1:8082" \
            "IDENTITY_MANAGEMENT_URL=$(identity_management_url)" \
            "RELAY_MANAGEMENT_URL=$(relay_management_url)" \
            "BLOB_MANAGEMENT_URL=$(blob_management_url)" \
            "TEST_SSH_HOST=127.0.0.1" \
            "TEST_SSH_PORT=2222" \
            "NB_E2E_SLOT=$slot" \
            "NB_E2E_LOGIN_DONE=0"
    done
    write_parallel_count "$PARALLEL_SLOTS"
}

parallel_run_logins() {
    log_step "running login suite on each slot concurrently"
    local slot pid
    local -a LOGIN_PIDS=()
    local -a LOGIN_LOGS=()
    for slot in $(seq 0 $((PARALLEL_SLOTS - 1))); do
        local log_file="/tmp/nb-parallel-login-slot${slot}-$(date +%Y%m%d-%H%M%S).log"
        LOGIN_LOGS[$slot]="$log_file"
        log_info "  slot $slot: starting login → $log_file"
        (
            "$SCRIPT_DIR/run-test.sh" login --e2e --slot "$slot"
        ) >"$log_file" 2>&1 &
        LOGIN_PIDS[$slot]=$!
    done

    local any_failed=0
    for slot in $(seq 0 $((PARALLEL_SLOTS - 1))); do
        pid="${LOGIN_PIDS[$slot]}"
        if wait "$pid"; then
            log_ok "  slot $slot: login PASSED"
            mark_env_login_complete "$slot"
        else
            log_error "  slot $slot: login FAILED (see ${LOGIN_LOGS[$slot]})"
            any_failed=1
        fi
    done
    if (( any_failed )); then
        log_error "one or more slot logins failed; aborting setup"
        for slot in $(seq 0 $((PARALLEL_SLOTS - 1))); do
            log_warn "  slot $slot log: ${LOGIN_LOGS[$slot]}"
        done
        exit 1
    fi
}

parallel_print_summary() {
    local -a lines=()
    lines+=("Slots:             $PARALLEL_SLOTS")
    lines+=("CLI:               $NB_CLI")
    lines+=("App:               $NB_APP_PATH")
    local slot
    for slot in $(seq 0 $((PARALLEL_SLOTS - 1))); do
        lines+=("Slot $slot sim:         ${SLOT_SIM_IDS[$slot]}")
        lines+=("Slot $slot data dir:    $(slot_state_dir "$slot")")
        lines+=("Slot $slot config dir:  $(slot_config_dir "$slot")")
    done
    lines+=("Parallel-count file: $NB_E2E_META_DIR/parallel-count")
    lines+=("")
    lines+=("Next: ./run-parallel.sh                      (all five suites)")
    lines+=("      ./run-parallel.sh --suites ssh,gpg     (subset)")
    lines+=("      ./run-test.sh gpg --e2e --slot 0       (single slot)")
    log_banner "NaughtBot E2E parallel setup complete" "${lines[@]}"
}

run_parallel_setup() {
    parallel_resolve_device_type_and_runtime
    parallel_create_slots
    parallel_build_and_install
    parallel_write_slot_envs
    parallel_run_logins
    parallel_print_summary
}

main() {
    if (( PARALLEL_SLOTS > 0 )); then
        log_banner "NaughtBot E2E setup (parallel, N=$PARALLEL_SLOTS)"
    else
        log_banner "NaughtBot E2E setup"
    fi

    if [[ "$DO_CLEAN_START" == "1" ]]; then
        clean_start
    else
        mkdir -p "$E2E_DATA_DIR"
    fi

    if [[ "$DO_BUILD" == "1" ]]; then
        build_cli
    else
        log_warn "--no-build: reusing existing cli artefacts"
        NB_CLI="$REPO_ROOT/nb"
        AGE_PLUGIN="$REPO_ROOT/age-plugin-nb"
        SK_DYLIB="$REPO_ROOT/sk-provider/libnb-sk.dylib"
        PKCS11_DYLIB="$REPO_ROOT/pkcs11-provider/libnb-pkcs11.dylib"
        if [[ ! -x "$NB_CLI" ]]; then
            log_error "--no-build requested but nb CLI missing at $NB_CLI"
            exit 1
        fi
    fi

    start_stack
    regenerate_xcodeproj

    if (( PARALLEL_SLOTS > 0 )); then
        run_parallel_setup
        return
    fi

    # Single-slot path (default, unchanged behavior).
    resolve_simulator
    reset_and_boot_simulator
    build_ios_test_bundle
    snapshot_env
    print_summary
}

main "$@"
