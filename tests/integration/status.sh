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

env_file="$(nb_e2e_env_file)"
if [[ -f "$env_file" ]]; then
    # shellcheck disable=SC1090
    source "$env_file"
    qlog_info "env snapshot: $env_file"
else
    qlog_warn "no env snapshot (run ./setup.sh)"
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

if [[ -n "${SIMULATOR_ID:-}" ]]; then
    if is_simulator_booted "$SIMULATOR_ID"; then
        qlog_ok "simulator $SIMULATOR_ID is booted"
    else
        qlog_warn "simulator $SIMULATOR_ID is not booted"
        failed=1
    fi
else
    qlog_warn "no simulator UDID recorded"
    failed=1
fi

exit "$failed"
