#!/usr/bin/env bash
#
# status.sh — quick health check for the NaughtBot E2E harness.
#
# Usage:
#   ./status.sh          # human-readable status report
#   ./status.sh --quick  # no output, exit 0 iff stack is healthy
#
# Checks:
#   - env.sh exists
#   - docker backend (gateway/identity/blob/relay) responds
#   - ssh server accepts TCP on 2222
#   - the recorded simulator UDID is booted

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=./lib/env.sh
source "$SCRIPT_DIR/lib/env.sh"

QUIET=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick|-q) QUIET=1; shift;;
        -h|--help)
            sed -n '2,13p' "$0"
            exit 0;;
        *) shift;;
    esac
done

qlog_info() { [[ "$QUIET" == "1" ]] || log_info "$@"; }
qlog_warn() { [[ "$QUIET" == "1" ]] || log_warn "$@"; }
qlog_ok()   { [[ "$QUIET" == "1" ]] || log_ok   "$@"; }

failed=0
sim_ids=()

# Discover state. After `./setup.sh --parallel N`, env state lives only in
# /tmp/nb-e2e-slot-<N>/env.sh (no single-slot env.sh). Fall back to the
# parallel slots so status.sh reports something useful for both layouts.
single_env_file="$(nb_e2e_env_file)"
parallel_count="$(read_parallel_count || true)"
parallel_slots=()
while IFS= read -r slot; do
    [[ -n "$slot" ]] || continue
    parallel_slots+=("$slot")
done < <(list_slots)

if [[ -f "$single_env_file" ]]; then
    # shellcheck disable=SC1090
    source "$single_env_file"
    qlog_info "env snapshot: $single_env_file"
    [[ -n "${SIMULATOR_ID:-}" ]] && sim_ids+=("$SIMULATOR_ID")
elif (( ${#parallel_slots[@]} > 0 )); then
    qlog_info "parallel-count: ${parallel_count:-?}, slots: ${parallel_slots[*]}"
    for slot in "${parallel_slots[@]}"; do
        slot_file="$(slot_env_file "$slot")"
        if [[ ! -f "$slot_file" ]]; then
            qlog_warn "slot $slot env snapshot missing at $slot_file"
            failed=1
            continue
        fi
        # shellcheck disable=SC1090
        ( source "$slot_file"; printf 'SIMULATOR_ID=%s\n' "${SIMULATOR_ID:-}" ) \
            | while IFS='=' read -r k v; do
                [[ "$k" == "SIMULATOR_ID" && -n "$v" ]] && printf '%s\n' "$v"
            done > "/tmp/.nb-status-slot-$slot-sim.$$"
        sim_id="$(cat "/tmp/.nb-status-slot-$slot-sim.$$")"
        rm -f "/tmp/.nb-status-slot-$slot-sim.$$"
        if [[ -n "$sim_id" ]]; then
            sim_ids+=("$sim_id")
            qlog_info "  slot $slot sim: $sim_id"
        else
            qlog_warn "  slot $slot env.sh present but no SIMULATOR_ID"
            failed=1
        fi
    done
else
    qlog_warn "no env snapshot (run ./setup.sh or ./setup.sh --parallel N)"
    failed=1
fi

if is_stack_healthy; then
    qlog_ok "backend stack healthy (gateway/identity/blob/relay)"
else
    qlog_warn "backend stack unhealthy or not running"
    failed=1
fi

if (echo >"/dev/tcp/127.0.0.1/2222") >/dev/null 2>&1; then
    qlog_ok "ssh server accepting TCP on 127.0.0.1:2222"
else
    qlog_warn "ssh server not listening on 127.0.0.1:2222"
    failed=1
fi

if (( ${#sim_ids[@]} == 0 )); then
    qlog_warn "no simulator UDID recorded"
    failed=1
else
    for sim_id in "${sim_ids[@]}"; do
        if is_simulator_booted "$sim_id"; then
            qlog_ok "simulator $sim_id is booted"
        else
            qlog_warn "simulator $sim_id is not booted"
            failed=1
        fi
    done
fi

exit "$failed"
