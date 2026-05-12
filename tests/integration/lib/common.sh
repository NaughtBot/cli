# lib/common.sh — shared helpers for the NaughtBot E2E harness.
#
# Source this file from any harness script:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=./lib/common.sh
#   source "$SCRIPT_DIR/lib/common.sh"
#
# Provides:
#   - Colored log_{info,warn,error,step} helpers, tee'd to /tmp/nb-e2e/last-test-output.txt
#   - require_command <cmd>              : exit 1 if a required binary is missing
#   - wait_for_url / wait_for_http_response / wait_for_status_code / wait_for_tcp_port
#   - nb_cli_root                  : absolute path to the monorepo root
#
# This file intentionally does not enable `set -e`; callers decide.

if [[ -z "${_NB_COMMON_SH_LOADED:-}" ]]; then
    _NB_COMMON_SH_LOADED=1

    # -----------------------------------------------------------------------
    # Colours — honour NO_COLOR per https://no-color.org/ and disable when
    # stdout is not a TTY so log files stay clean.
    # -----------------------------------------------------------------------
    if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
        _C_RESET=$'\033[0m'
        _C_INFO=$'\033[0;36m'   # cyan
        _C_WARN=$'\033[0;33m'   # yellow
        _C_ERROR=$'\033[0;31m'  # red
        _C_STEP=$'\033[1;35m'   # bold magenta
        _C_OK=$'\033[0;32m'     # green
    else
        _C_RESET=""
        _C_INFO=""
        _C_WARN=""
        _C_ERROR=""
        _C_STEP=""
        _C_OK=""
    fi

    _NB_COMMON_LOG_SINK="${NB_E2E_LOG_SINK:-/tmp/nb-e2e/last-test-output.txt}"
    mkdir -p "$(dirname "$_NB_COMMON_LOG_SINK")" 2>/dev/null || true

    _nb_log_write() {
        local plain="$1"
        if [[ -n "$_NB_COMMON_LOG_SINK" ]]; then
            # Gate the append on the sink's parent directory still existing.
            # Bash emits "No such file or directory" to stderr from the
            # redirection itself (before printf runs), so `2>/dev/null` on
            # the inner command cannot suppress it. Teardown wipes the
            # /tmp/nb-e2e tree and the farewell log line would then
            # produce a spurious error, so skip silently in that case.
            if [[ -d "$(dirname "$_NB_COMMON_LOG_SINK")" ]]; then
                printf '%s\n' "$plain" >>"$_NB_COMMON_LOG_SINK" 2>/dev/null || true
            fi
        fi
    }

    _nb_ts() {
        date +"%Y-%m-%dT%H:%M:%S%z"
    }

    log_info() {
        local msg="$*"
        local ts
        ts="$(_nb_ts)"
        printf '%s [%sINFO%s] %s\n' "$ts" "$_C_INFO" "$_C_RESET" "$msg"
        _nb_log_write "$ts [INFO] $msg"
    }

    log_warn() {
        local msg="$*"
        local ts
        ts="$(_nb_ts)"
        printf '%s [%sWARN%s] %s\n' "$ts" "$_C_WARN" "$_C_RESET" "$msg" >&2
        _nb_log_write "$ts [WARN] $msg"
    }

    log_error() {
        local msg="$*"
        local ts
        ts="$(_nb_ts)"
        printf '%s [%sERROR%s] %s\n' "$ts" "$_C_ERROR" "$_C_RESET" "$msg" >&2
        _nb_log_write "$ts [ERROR] $msg"
    }

    log_step() {
        local msg="$*"
        local ts
        ts="$(_nb_ts)"
        printf '%s [%sSTEP%s] %s\n' "$ts" "$_C_STEP" "$_C_RESET" "$msg"
        _nb_log_write "$ts [STEP] $msg"
    }

    log_ok() {
        local msg="$*"
        local ts
        ts="$(_nb_ts)"
        printf '%s [%sOK%s] %s\n' "$ts" "$_C_OK" "$_C_RESET" "$msg"
        _nb_log_write "$ts [OK] $msg"
    }

    log_banner() {
        local title="$1"
        shift || true
        local width=76
        local sep
        sep="$(printf '%*s' "$width" '' | tr ' ' '=')"
        printf '\n%s%s%s\n' "$_C_STEP" "$sep" "$_C_RESET"
        printf '%s== %s%s\n' "$_C_STEP" "$title" "$_C_RESET"
        for line in "$@"; do
            printf '%s== %s%s\n' "$_C_STEP" "$line" "$_C_RESET"
        done
        printf '%s%s%s\n\n' "$_C_STEP" "$sep" "$_C_RESET"
        if [[ -d "$(dirname "$_NB_COMMON_LOG_SINK")" ]]; then
            {
                echo "=== $title ==="
                for line in "$@"; do
                    echo "== $line"
                done
            } >>"$_NB_COMMON_LOG_SINK" 2>/dev/null || true
        fi
    }

    require_command() {
        if ! command -v "$1" >/dev/null 2>&1; then
            log_error "Required command not found on PATH: $1"
            exit 1
        fi
    }

    nb_cli_root() {
        # lib/common.sh lives at <repo>/tests/integration/lib/common.sh.
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        (cd "$script_dir/../../.." && pwd)
    }

    # nb_workspace_root resolves the parent NaughtBot workspace checkout that
    # contains the sibling cli/, mobile/, core/, e2ee-payloads/, ... repos.
    # The harness needs this to locate the mobile iOS app target and the
    # core/docker-compose.yml stack. Override with WORKSPACE_ROOT when running
    # from a non-canonical layout (e.g. an isolated lane worktree).
    nb_workspace_root() {
        if [[ -n "${WORKSPACE_ROOT:-}" ]]; then
            (cd "$WORKSPACE_ROOT" && pwd)
            return
        fi
        local cli_root
        cli_root="$(nb_cli_root)"
        (cd "$cli_root/.." && pwd)
    }

    # -----------------------------------------------------------------------
    # Wait helpers — all write progress at INFO, failures at ERROR.
    # -----------------------------------------------------------------------

    wait_for_url() {
        local url="$1"
        local label="$2"
        local timeout="${3:-180}"
        local started_at
        started_at="$(date +%s)"
        while true; do
            if curl -fsS "$url" >/dev/null 2>&1; then
                log_info "$label is ready at $url"
                return 0
            fi
            if (( "$(date +%s)" - started_at >= timeout )); then
                log_error "$label did not become ready within ${timeout}s ($url)"
                return 1
            fi
            sleep 2
        done
    }

    # wait_for_http_response polls a URL until the response status is 2xx or
    # 3xx. Anything else (4xx, 5xx, 000/connection refused) is treated as
    # "not ready". For services that legitimately answer with a 4xx on the
    # probe path (e.g. `/` on the relay returning 404 because there is no
    # such route), use wait_for_http_any_response_allow with an explicit
    # allowlist instead.
    wait_for_http_response() {
        local url="$1"
        local label="$2"
        local timeout="${3:-180}"
        local started_at
        started_at="$(date +%s)"
        while true; do
            local status_code
            status_code="$(curl -sS -o /dev/null -w '%{http_code}' "$url" || true)"
            if [[ "$status_code" =~ ^[23][0-9][0-9]$ ]]; then
                log_info "$label is responding at $url (HTTP $status_code)"
                return 0
            fi
            if (( "$(date +%s)" - started_at >= timeout )); then
                log_error "$label did not return a 2xx/3xx within ${timeout}s ($url, last status $status_code)"
                return 1
            fi
            sleep 2
        done
    }

    # wait_for_http_any_response_allow polls a URL until the response status
    # matches one of the explicit allowlist values supplied as the trailing
    # arguments. Use this for endpoints that have no health route and answer
    # the probe path with a non-success status (e.g. relay `/` returns 404).
    #
    # Usage: wait_for_http_any_response_allow <url> <label> <timeout> <code> [<code>...]
    wait_for_http_any_response_allow() {
        local url="$1"
        local label="$2"
        local timeout="$3"
        shift 3
        local allowed=("$@")
        if (( ${#allowed[@]} == 0 )); then
            log_error "wait_for_http_any_response_allow: no allowed status codes supplied for $label ($url)"
            return 2
        fi
        local started_at
        started_at="$(date +%s)"
        while true; do
            local status_code
            status_code="$(curl -sS -o /dev/null -w '%{http_code}' "$url" || true)"
            local code
            for code in "${allowed[@]}"; do
                if [[ "$status_code" == "$code" ]]; then
                    log_info "$label is responding at $url (HTTP $status_code, in allowlist)"
                    return 0
                fi
            done
            if (( "$(date +%s)" - started_at >= timeout )); then
                log_error "$label did not return one of [${allowed[*]}] within ${timeout}s ($url, last status $status_code)"
                return 1
            fi
            sleep 2
        done
    }

    wait_for_status_code() {
        local url="$1"
        local expected_status="$2"
        local label="$3"
        local timeout="${4:-120}"
        local started_at
        started_at="$(date +%s)"
        while true; do
            local status_code
            status_code="$(curl -sS -o /dev/null -w '%{http_code}' "$url" || true)"
            if [[ "$status_code" == "$expected_status" ]]; then
                log_info "$label is ready at $url (HTTP $status_code)"
                return 0
            fi
            if (( "$(date +%s)" - started_at >= timeout )); then
                log_error "$label did not reach HTTP $expected_status within ${timeout}s ($url)"
                return 1
            fi
            sleep 1
        done
    }

    wait_for_tcp_port() {
        local host="$1"
        local port="$2"
        local label="$3"
        local timeout="${4:-120}"
        local started_at
        started_at="$(date +%s)"
        while true; do
            if (echo >"/dev/tcp/$host/$port") >/dev/null 2>&1; then
                log_info "$label is accepting TCP at $host:$port"
                return 0
            fi
            if (( "$(date +%s)" - started_at >= timeout )); then
                log_error "$label did not accept TCP within ${timeout}s ($host:$port)"
                return 1
            fi
            sleep 1
        done
    }

    wait_for_file() {
        local path="$1"
        local label="$2"
        local timeout="${3:-60}"
        local started_at
        started_at="$(date +%s)"
        while true; do
            if [[ -f "$path" ]]; then
                log_info "$label is ready at $path"
                return 0
            fi
            if (( "$(date +%s)" - started_at >= timeout )); then
                log_error "$label did not appear within ${timeout}s ($path)"
                return 1
            fi
            sleep 1
        done
    }
fi
