#!/usr/bin/env bash
#
# run-parallel.sh — dispatch NaughtBot E2E suites across parallel slots.
#
# Requires prior `./setup.sh --parallel N`, which creates N slot directories
# (/tmp/nb-e2e-slot-0..N-1/) and records the count in
# /tmp/nb-e2e-meta/parallel-count.
#
# Usage:
#   ./run-parallel.sh                                    # all default suites
#   ./run-parallel.sh --suites ssh,age,gpg,pkcs11        # explicit list
#   ./run-parallel.sh --suites ssh,gpg                   # subset
#   ./run-parallel.sh --timeout 15m                      # per-suite timeout
#   ./run-parallel.sh --verbose                          # stream child output
#
# Suites are assigned to slots in round-robin order. Suites assigned to the
# same slot run sequentially on that slot; suites on different slots run
# concurrently. The final summary banner prints PASS/FAIL per suite and the
# slot each ran on.
#
# Each suite invocation writes to:
#   /tmp/nb-parallel-<suite>-slot<N>-<timestamp>.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=./lib/env.sh
source "$SCRIPT_DIR/lib/env.sh"

DEFAULT_SUITES="ssh,age,gpg,pkcs11"
SUITES_ARG="$DEFAULT_SUITES"
TIMEOUT="10m"
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --suites)
            SUITES_ARG="$2"; shift 2;;
        --timeout)
            TIMEOUT="$2"; shift 2;;
        --verbose|-v)
            VERBOSE=1; shift;;
        -h|--help)
            sed -n '2,24p' "$0"
            exit 0;;
        *)
            log_error "unknown flag: $1"
            exit 2;;
    esac
done

# -------------------------------------------------------------------------
# Discover available slots.
# -------------------------------------------------------------------------
PARALLEL_COUNT="$(read_parallel_count || true)"
if [[ -z "$PARALLEL_COUNT" ]]; then
    log_error "no parallel-count recorded — run: ./setup.sh --parallel N"
    exit 2
fi

SLOTS=()
while IFS= read -r slot; do
    [[ -n "$slot" ]] || continue
    SLOTS+=("$slot")
done < <(list_slots)

if (( ${#SLOTS[@]} == 0 )); then
    log_error "no slot directories found despite parallel-count=$PARALLEL_COUNT"
    log_error "re-run: ./setup.sh --parallel $PARALLEL_COUNT --clean-start"
    exit 2
fi

SUITES_LIST="${SUITES_ARG//,/ }"

# Reject `login` upfront: the login suite has not been moved to nb/cli yet,
# so the parallel runner has nothing to dispatch for it. Letting it through
# would surface as a confusing per-slot "suite directory does not exist".
for s in $SUITES_LIST; do
    if [[ "$s" == "login" ]]; then
        log_error "suite 'login' is not present in this repo (the legacy XCUITest"
        log_error "harness has not been re-introduced against the NaughtBot iOS"
        log_error "approver yet). See tests/integration/README.md for context."
        exit 2
    fi
done

# Each slot must have an env.sh from `./setup.sh --parallel N`. The legacy
# harness additionally required NB_E2E_LOGIN_DONE=1 from the login suite;
# that gate is suspended until the login suite is reintroduced.
for slot in "${SLOTS[@]}"; do
    if ! load_slot_env_state "$slot" >/dev/null 2>&1; then
        log_error "slot $slot env.sh missing; run ./setup.sh --parallel $PARALLEL_COUNT --clean-start"
        exit 2
    fi
done

NUM_SLOTS=${#SLOTS[@]}
log_banner "NaughtBot E2E parallel runner" \
    "Slots:    $NUM_SLOTS (${SLOTS[*]})" \
    "Suites:   $SUITES_LIST" \
    "Timeout:  $TIMEOUT per suite" \
    "Verbose:  $( (( VERBOSE )) && echo yes || echo no )"

# -------------------------------------------------------------------------
# Round-robin assign suites to slots.
# SLOT_SUITES[i] is a space-separated list of suites for slot SLOTS[i].
# -------------------------------------------------------------------------
SLOT_SUITES=()
for i in "${!SLOTS[@]}"; do
    SLOT_SUITES[$i]=""
done

idx=0
for suite in $SUITES_LIST; do
    si=$(( idx % NUM_SLOTS ))
    SLOT_SUITES[$si]="${SLOT_SUITES[$si]} $suite"
    idx=$(( idx + 1 ))
done

log_info "Assignments:"
for i in "${!SLOTS[@]}"; do
    slot="${SLOTS[$i]}"
    suites="${SLOT_SUITES[$i]# }"
    if [[ -n "$suites" ]]; then
        log_info "  slot $slot: $suites"
    fi
done

# -------------------------------------------------------------------------
# Launch one background job per slot. Inside the job, suites run sequentially.
# Each suite's output goes to its own log; the job's aggregate output goes to
# /tmp/nb-parallel-slot<N>-<ts>.log so we can tail it on failure.
# -------------------------------------------------------------------------
TS="$(date +%Y%m%d-%H%M%S)"
SLOT_JOB_PIDS=()
SLOT_JOB_LOGS=()
# macOS bash 3.2 lacks associative arrays; fake them via dynamic variable names.
# SUITE_LOG_FILE__<suite> and SUITE_SLOT__<suite> and SUITE_RESULT__<suite>.
_suite_var() { printf '%s__%s' "$1" "$2"; }
_set_kv() { printf -v "$(_suite_var "$1" "$2")" '%s' "$3"; }
_get_kv() { local __n; __n="$(_suite_var "$1" "$2")"; printf '%s' "${!__n-}"; }

for i in "${!SLOTS[@]}"; do
    slot="${SLOTS[$i]}"
    suites="${SLOT_SUITES[$i]# }"
    [[ -n "$suites" ]] || continue

    slot_log="/tmp/nb-parallel-slot${slot}-${TS}.log"
    SLOT_JOB_LOGS[$i]="$slot_log"

    # Capture per-suite log paths upfront so wait-side can reference them.
    for suite in $suites; do
        _set_kv SUITE_LOG_FILE "$suite" "/tmp/nb-parallel-${suite}-slot${slot}-${TS}.log"
        _set_kv SUITE_SLOT "$suite" "$slot"
    done

    (
        slot_exit=0
        for suite in $suites; do
            suite_log="/tmp/nb-parallel-${suite}-slot${slot}-${TS}.log"
            echo "===== [$(date +%H:%M:%S)] slot $slot: $suite starting (log $suite_log) ====="
            if "$SCRIPT_DIR/run-test.sh" "$suite" --e2e --slot "$slot" --timeout "$TIMEOUT" \
                    >"$suite_log" 2>&1; then
                echo "===== [$(date +%H:%M:%S)] slot $slot: $suite PASSED ====="
                echo "PARALLEL-RESULT: $suite:$slot:PASSED"
            else
                ec=$?
                echo "===== [$(date +%H:%M:%S)] slot $slot: $suite FAILED (exit $ec) ====="
                echo "PARALLEL-RESULT: $suite:$slot:FAILED"
                slot_exit=1
            fi
        done
        exit $slot_exit
    ) >"$slot_log" 2>&1 &

    pid=$!
    SLOT_JOB_PIDS[$i]="$pid"
    log_info "  launched slot $slot (pid $pid) → $slot_log"

    if (( VERBOSE )); then
        # Mirror the slot job's aggregate log to stdout in the background.
        ( tail -f "$slot_log" 2>/dev/null | sed -e "s/^/[slot $slot] /" ) &
    fi
done

log_info ""
log_info "waiting for slot jobs..."

# -------------------------------------------------------------------------
# Wait for all slot jobs. Parse PARALLEL-RESULT lines from each slot log to
# reconstruct per-suite results (this survives partial failures where the
# slot exits non-zero but some suites passed).
# -------------------------------------------------------------------------
for i in "${!SLOTS[@]}"; do
    pid="${SLOT_JOB_PIDS[$i]:-}"
    [[ -n "$pid" ]] || continue
    slot="${SLOTS[$i]}"
    slot_log="${SLOT_JOB_LOGS[$i]}"

    if wait "$pid"; then
        log_ok "slot $slot job exited 0"
    else
        log_error "slot $slot job exited non-zero"
    fi

    # Parse PARALLEL-RESULT lines from the slot's aggregate log.
    if [[ -f "$slot_log" ]]; then
        while IFS= read -r line; do
            # Expected form: PARALLEL-RESULT: suite:slot:STATUS
            entry="${line#PARALLEL-RESULT: }"
            IFS=':' read -r r_suite r_slot r_status <<<"$entry"
            [[ -n "$r_suite" && -n "$r_status" ]] || continue
            _set_kv SUITE_RESULT "$r_suite" "$r_status"
        done < <(grep '^PARALLEL-RESULT: ' "$slot_log" 2>/dev/null || true)
    fi
done

# Any suite without a result was never reached. Mark UNKNOWN.
for suite in $SUITES_LIST; do
    if [[ -z "$(_get_kv SUITE_RESULT "$suite")" ]]; then
        _set_kv SUITE_RESULT "$suite" "UNKNOWN"
    fi
done

# -------------------------------------------------------------------------
# Summary.
# -------------------------------------------------------------------------
passed=0
failed=0
summary_lines=()
for suite in $SUITES_LIST; do
    status="$(_get_kv SUITE_RESULT "$suite")"
    slot="$(_get_kv SUITE_SLOT "$suite")"
    [[ -n "$slot" ]] || slot="?"
    log_path="$(_get_kv SUITE_LOG_FILE "$suite")"
    [[ -n "$log_path" ]] || log_path="<none>"
    summary_lines+=("$(printf '  %-7s  slot %-3s  %s' "$suite" "$slot" "$status")")
    case "$status" in
        PASSED) passed=$(( passed + 1 ));;
        *)      failed=$(( failed + 1 ));;
    esac
done

header=(
    "Total:  $(( passed + failed ))"
    "Passed: $passed"
    "Failed: $failed"
    ""
    "Results:"
    "${summary_lines[@]}"
    ""
    "Logs:"
)
for suite in $SUITES_LIST; do
    log_path="$(_get_kv SUITE_LOG_FILE "$suite")"
    [[ -n "$log_path" ]] || log_path="<none>"
    header+=("  $suite: $log_path")
done

if (( failed == 0 )); then
    log_banner "NaughtBot E2E parallel: ALL GREEN" "${header[@]}"
    exit 0
else
    log_banner "NaughtBot E2E parallel: FAILURES ($failed)" "${header[@]}"
    # Dump last 40 lines of each failing suite's log so the terminal has a clue.
    for suite in $SUITES_LIST; do
        status="$(_get_kv SUITE_RESULT "$suite")"
        if [[ "$status" != "PASSED" ]]; then
            log_path="$(_get_kv SUITE_LOG_FILE "$suite")"
            log_warn "---- last 40 lines: $suite (${log_path:-<missing>}) ----"
            if [[ -n "$log_path" && -f "$log_path" ]]; then
                tail -n 40 "$log_path" || true
            fi
        fi
    done
    exit 1
fi
