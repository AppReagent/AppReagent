#!/bin/bash
set -euo pipefail

AREA="$(cd "$(dirname "$0")/.." && pwd)/area"
USE_CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)/tests/use-cases"
DATA_DIR="/tmp/area-test-$$"
SOCK="$DATA_DIR/area.sock"
SERVER_PID=""

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
GRAY='\033[90m'
RESET='\033[0m'

die() { echo -e "${RED}FAIL${RESET} $1" >&2; cleanup; exit 1; }
pass() { echo -e "${GREEN}PASS${RESET} $1"; }
fail() { echo -e "${RED}FAIL${RESET} $1"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "${GRAY}$1${RESET}"; }

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

start_server() {
    mkdir -p "$DATA_DIR/chats/default"
    local ROOT="$(cd "$(dirname "$0")/.." && pwd)"
    if [ -f "$ROOT/config.json" ]; then
        cp "$ROOT/config.json" "$DATA_DIR/config.json"
    elif [ -f /opt/area/config.json ]; then
        cp /opt/area/config.json "$DATA_DIR/config.json"
    elif [ -f "$ROOT/config.example.json" ]; then
        cp "$ROOT/config.example.json" "$DATA_DIR/config.json"
    fi
    cp "$ROOT/ddl.sql" "$DATA_DIR/" 2>/dev/null || true
    cp -r "$ROOT/prompts" "$DATA_DIR/" 2>/dev/null || true
    cp "$ROOT/ca-certificate.crt" "$DATA_DIR/" 2>/dev/null || true
    cp "$ROOT/constitution.md" "$DATA_DIR/" 2>/dev/null || true

    export AREA_DATA_DIR="$DATA_DIR"
    cd "$DATA_DIR"
    AREA_DATA_DIR="$DATA_DIR" "$AREA" server >"$DATA_DIR/server.log" 2>&1 &
    SERVER_PID=$!

    for i in $(seq 1 30); do
        [ -S "$SOCK" ] && break
        sleep 0.2
    done
    [ -S "$SOCK" ] || die "Server failed to start. Log:\n$(cat "$DATA_DIR/server.log")"
    info "server started (pid=$SERVER_PID)"
}

# Send a prompt to the agent, capture output
ask() {
    local prompt="$1"
    local chat_id="${2:-default}"
    echo "$prompt" | "$AREA" chat "$chat_id" 2>/dev/null
}

assert_contains() {
    local output="$1" pattern="$2" msg="${3:-contains '$2'}"
    if echo "$output" | grep -qi "$pattern"; then
        pass "$msg"
    else
        fail "$msg"
        echo -e "  ${GRAY}output: ${output:0:200}${RESET}"
    fi
}

assert_not_contains() {
    local output="$1" pattern="$2" msg="${3:-does not contain '$2'}"
    if echo "$output" | grep -qi "$pattern"; then
        fail "$msg"
        echo -e "  ${GRAY}output: ${output:0:200}${RESET}"
    else
        pass "$msg"
    fi
}

assert_file_exists() {
    local path="$1" msg="${2:-file exists: $1}"
    if [ -f "$path" ]; then
        pass "$msg"
    else
        fail "$msg"
    fi
}

assert_file_contains() {
    local path="$1" pattern="$2" msg="${3:-file contains '$2'}"
    if grep -q "$pattern" "$path" 2>/dev/null; then
        pass "$msg"
    else
        fail "$msg"
    fi
}

# Run a single use case (sources test.sh in current shell)
run_case() {
    local name="$1"
    local dir="$USE_CASE_DIR/$name"
    echo -e "\n${YELLOW}=== $name ===${RESET}"
    source "$dir/test.sh"
}

# Run a use case in a background subshell, write results to a temp file
run_case_bg() {
    local name="$1"
    local outfile="$DATA_DIR/result-$name.txt"
    bash -c '
        AREA="'"$AREA"'"
        DATA_DIR="'"$DATA_DIR"'"
        SOCK="'"$SOCK"'"
        AREA_DATA_DIR="'"$DATA_DIR"'"
        USE_CASE_DIR="'"$USE_CASE_DIR"'"
        RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; GRAY="\033[90m"; RESET="\033[0m"
        FAILURES=0
        pass() { echo -e "${GREEN}PASS${RESET} $1"; }
        fail() { echo -e "${RED}FAIL${RESET} $1"; FAILURES=$((FAILURES + 1)); }
        info() { echo -e "${GRAY}$1${RESET}"; }
        ask() { echo "$1" | "$AREA" chat "${2:-'"$name"'}" 2>/dev/null; }
        assert_contains() {
            if echo "$1" | grep -qi "$2"; then pass "${3:-contains}"; else fail "${3:-contains}"; echo -e "  ${GRAY}output: ${1:0:200}${RESET}"; fi
        }
        assert_not_contains() {
            if echo "$1" | grep -qi "$2"; then fail "${3:-not contains}"; echo -e "  ${GRAY}output: ${1:0:200}${RESET}"; else pass "${3:-not contains}"; fi
        }
        assert_file_exists() { if [ -f "$1" ]; then pass "${2:-exists}"; else fail "${2:-exists}"; fi; }
        assert_file_contains() { if grep -q "$2" "$1" 2>/dev/null; then pass "${3:-contains}"; else fail "${3:-contains}"; fi; }
        cd "$DATA_DIR"
        source "$USE_CASE_DIR/'"$name"'/test.sh"
        echo "RESULT:$FAILURES"
    ' > "$outfile" 2>&1 &
    echo $!
}

# ---- Main ----

FAILURES=0

if [ $# -eq 0 ]; then
    echo "Usage: $0 <use-case> | all | fast | parallel"
    echo ""
    echo "  all       — run all use cases sequentially"
    echo "  fast      — run only fast (non-scan) use cases"
    echo "  parallel  — run scan tests in parallel, fast tests sequentially"
    echo ""
    echo "Available use cases:"
    for d in "$USE_CASE_DIR"/*/; do
        [ -f "$d/test.sh" ] && echo "  $(basename "$d")"
    done
    exit 0
fi

TARGET="$1"

if [ "$TARGET" = "fast" ]; then
    start_server
    for d in "$USE_CASE_DIR"/*/; do
        [ -f "$d/test.sh" ] || continue
        name="$(basename "$d")"
        # Skip scan tests (they hit real LLM endpoints and are slow)
        case "$name" in scan-*) continue ;; esac
        export AREA DATA_DIR SOCK
        run_case "$name"
    done
elif [ "$TARGET" = "parallel" ]; then
    start_server
    export AREA DATA_DIR SOCK

    # Run fast tests first (sequential)
    for d in "$USE_CASE_DIR"/*/; do
        [ -f "$d/test.sh" ] || continue
        name="$(basename "$d")"
        case "$name" in scan-*) continue ;; esac
        run_case "$name"
    done

    # Run scan tests in parallel (each in its own chat session)
    declare -A PIDS
    for d in "$USE_CASE_DIR"/*/; do
        [ -f "$d/test.sh" ] || continue
        name="$(basename "$d")"
        case "$name" in scan-*) ;; *) continue ;; esac
        echo -e "\n${YELLOW}=== $name (background) ===${RESET}"
        pid=$(run_case_bg "$name")
        PIDS["$name"]=$pid
    done

    # Wait for all parallel tests by polling for RESULT: lines
    info "waiting for scan tests to complete..."
    for name in "${!PIDS[@]}"; do
        outfile="$DATA_DIR/result-$name.txt"
        # Poll until the result file contains RESULT:
        for i in $(seq 1 600); do  # 10 min max
            if grep -q "^RESULT:" "$outfile" 2>/dev/null; then break; fi
            sleep 1
        done
        echo -e "\n${YELLOW}=== $name (result) ===${RESET}"
        if [ -f "$outfile" ]; then
            grep -v "^RESULT:" "$outfile" || true
            result_line=$(grep "^RESULT:" "$outfile" || echo "RESULT:1")
            count="${result_line#RESULT:}"
            FAILURES=$((FAILURES + count))
        else
            fail "$name: no output file"
        fi
    done
elif [ "$TARGET" = "all" ]; then
    start_server
    for d in "$USE_CASE_DIR"/*/; do
        [ -f "$d/test.sh" ] || continue
        name="$(basename "$d")"
        echo -e "\n${YELLOW}=== $name ===${RESET}"
        export AREA DATA_DIR SOCK
        source "$d/test.sh"
    done
else
    CASE_DIR="$USE_CASE_DIR/$TARGET"
    [ -f "$CASE_DIR/test.sh" ] || die "Use case not found: $TARGET"
    start_server
    echo -e "${YELLOW}=== $TARGET ===${RESET}"
    export AREA DATA_DIR SOCK
    source "$CASE_DIR/test.sh"
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}All assertions passed${RESET}"
else
    echo -e "${RED}$FAILURES assertion(s) failed${RESET}"
    exit 1
fi
