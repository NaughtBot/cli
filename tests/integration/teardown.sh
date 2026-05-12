#!/usr/bin/env bash
#
# teardown.sh — cleanup for the NaughtBot E2E harness.
#
# Usage:
#   ./teardown.sh              # stop docker stack + log streams
#   ./teardown.sh --all        # also wipe tmp dirs, derived data, sim state
#
# Safe to run repeatedly; every action is idempotent.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=./lib/env.sh
source "$SCRIPT_DIR/lib/env.sh"

FULL=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --all|--full) FULL=1; shift;;
        -h|--help)
            sed -n '2,14p' "$0"
            exit 0;;
        *) log_warn "ignoring unknown flag: $1"; shift;;
    esac
done

REPO_ROOT="$(nb_cli_root)"
WORKSPACE_ROOT="$(nb_workspace_root)"

stop_docker_stack() {
    # Only tear down the services we explicitly added under the
    # nb-e2e-testing profile. Shared services (gateway/relay/identity/
    # blob) are profile-less and are relied on by other local-dev stacks;
    # running `docker compose --profile nb-e2e-testing down` would stop
    # them too. See design spec "Docker compose profile" section.
    log_step "stopping nb-e2e-testing-only services (nb-ssh-server)"
    (
        cd "$WORKSPACE_ROOT/core"
        docker compose --profile nb-e2e-testing stop nb-ssh-server >/dev/null 2>&1 || true
        if [[ "$FULL" == "1" ]]; then
            docker compose --profile nb-e2e-testing rm -f -v nb-ssh-server >/dev/null 2>&1 || true
        else
            docker compose --profile nb-e2e-testing rm -f nb-ssh-server >/dev/null 2>&1 || true
        fi
    )
}

kill_log_streams() {
    log_step "killing lingering simctl log stream processes"
    pkill -f 'simctl spawn .* log stream.*com.naughtbot.ios' >/dev/null 2>&1 || true
}

shutdown_simulators() {
    log_step "shutting down iOS simulators"
    xcrun simctl shutdown all >/dev/null 2>&1 || true
}

delete_slot_simulators() {
    # In parallel mode setup.sh creates simulators named NB-E2E-<N>.
    # Delete them so a later setup starts clean (names are reused).
    if ! command -v xcrun >/dev/null 2>&1; then
        return 0
    fi
    log_step "deleting parallel-slot simulators (NB-E2E-*)"
    local udid
    while IFS= read -r udid; do
        [[ -n "$udid" ]] || continue
        log_info "  deleting simulator $udid"
        xcrun simctl delete "$udid" >/dev/null 2>&1 || true
    done < <(xcrun simctl list devices -j 2>/dev/null \
        | jq -r '.devices | to_entries[] | .value[]
            | select(.name | startswith("NB-E2E-")) | .udid' 2>/dev/null)
}

wipe_tmp_state() {
    log_step "wiping /tmp/nb-e2e* and derived data"
    rm -rf \
        /tmp/nb-e2e \
        /tmp/nb-e2e-slot-* \
        /tmp/nb-e2e-config-* \
        /tmp/nb-e2e-meta \
        /tmp/nb-e2e-derived-data \
        /tmp/nb-*-sim-log \
        /tmp/nb-parallel-*.log || true
}

main() {
    log_banner "NaughtBot E2E teardown" "mode: $( [[ $FULL == 1 ]] && echo full || echo soft )"
    stop_docker_stack
    kill_log_streams
    if [[ "$FULL" == "1" ]]; then
        shutdown_simulators
        delete_slot_simulators
        wipe_tmp_state
    fi
    log_ok "teardown complete"
}

main "$@"
