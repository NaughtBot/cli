#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_TMP="$(mktemp -d)"
BIN_DIR="$TEST_TMP/bin"
CURL_LOG="$TEST_TMP/curl.log"

cleanup() {
    rm -rf "$TEST_TMP"
}
trap cleanup EXIT

mkdir -p "$BIN_DIR"

cat >"$BIN_DIR/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

log_file="${CURL_LOG:?}"
url="${!#}"
printf '%s\n' "$url" >>"$log_file"

case "$url" in
    "http://127.0.0.1:4455/.well-known/openid-configuration"|\
    "http://127.0.0.1:9091/health"|\
    "http://127.0.0.1:9092/health"|\
    "http://127.0.0.1:9093/health")
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
EOF
chmod +x "$BIN_DIR/curl"

# shellcheck source=./lib/common.sh
source "$REPO_ROOT/tests/integration/lib/common.sh"
# shellcheck source=./lib/env.sh
source "$REPO_ROOT/tests/integration/lib/env.sh"

PATH="$BIN_DIR:$PATH" CURL_LOG="$CURL_LOG" is_stack_healthy

for url in \
    "http://127.0.0.1:4455/.well-known/openid-configuration" \
    "http://127.0.0.1:9091/health" \
    "http://127.0.0.1:9092/health" \
    "http://127.0.0.1:9093/health"
do
    if ! grep -qx "$url" "$CURL_LOG"; then
        echo "missing expected probe: $url"
        cat "$CURL_LOG"
        exit 1
    fi
done

if grep -q "/api/auth/challenge" "$CURL_LOG"; then
    echo "unexpected public challenge probe"
    cat "$CURL_LOG"
    exit 1
fi

if grep -q "http://127.0.0.1:8080/$" "$CURL_LOG"; then
    echo "unexpected relay public probe"
    cat "$CURL_LOG"
    exit 1
fi

if grep -q "http://127.0.0.1:8082/$" "$CURL_LOG"; then
    echo "unexpected blob public probe"
    cat "$CURL_LOG"
    exit 1
fi

echo "env.sh management probe regression test passed"
