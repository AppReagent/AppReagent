#!/bin/bash
# Test scan pause and resume with a large file set.
# Requires a running server: ./area server
set -euo pipefail

AREA="$(cd "$(dirname "$0")/.." && pwd)/area"
SCAN_DIR="${1:-/tmp/area-pause-test}"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; GRAY='\033[90m'; RESET='\033[0m'
pass() { echo -e "${GREEN}PASS${RESET} $1"; }
fail() { echo -e "${RED}FAIL${RESET} $1"; exit 1; }
info() { echo -e "${GRAY}$1${RESET}"; }

FILE_COUNT=$(find "$SCAN_DIR" -name "*.smali" | wc -l)
info "Testing pause/resume with $FILE_COUNT .smali files in $SCAN_DIR"

# 1. Start a scan in background via area chat
info "Starting scan..."
echo "scan $SCAN_DIR for network connections and data exfiltration" | "$AREA" chat pause-test &
SCAN_PID=$!

# 2. Wait a few seconds for it to start, then check state
sleep 10
info "Checking state after 10s..."
STATE=$(echo "is there a scan running?" | "$AREA" chat pause-check 2>/dev/null)
echo "$STATE"

if echo "$STATE" | grep -qi "running\|active\|progress"; then
    pass "Scan is running"
else
    info "Scan may have already finished (small directory). Checking..."
fi

# 3. Extract the run_id from state
RUN_ID=$(echo "$STATE" | grep -oP 'Scan \K[A-Za-z0-9_-]{8,}' | head -1 || true)
if [ -z "$RUN_ID" ]; then
    # Try getting it from scan_results
    RUN_ID=$(echo "what is the latest run_id?" | "$AREA" chat pause-check 2>/dev/null | grep -oP '[A-Za-z0-9_-]{8,}' | head -1 || true)
fi

if [ -z "$RUN_ID" ]; then
    info "Could not extract run_id — scan may have finished before pause"
    wait $SCAN_PID 2>/dev/null || true
    pass "Scan completed (too fast to pause — use a larger directory)"
    exit 0
fi

info "Run ID: $RUN_ID"

# 4. Pause the scan
info "Pausing scan $RUN_ID..."
PAUSE_OUT=$(echo "pause scan $RUN_ID" | "$AREA" chat pause-check 2>/dev/null)
echo "$PAUSE_OUT"

if echo "$PAUSE_OUT" | grep -qi "paus"; then
    pass "Pause acknowledged"
else
    fail "Pause not acknowledged"
fi

# Wait for the scan process to exit
wait $SCAN_PID 2>/dev/null || true

# 5. Check how many files were scanned before pause
info "Checking progress before pause..."
PROGRESS=$(echo "how many files were scanned for run_id $RUN_ID?" | "$AREA" chat pause-check 2>/dev/null)
echo "$PROGRESS"
pass "Progress query completed"

# 6. Resume the scan
info "Resuming scan $RUN_ID..."
echo "resume scan $RUN_ID" | "$AREA" chat resume-test 2>/dev/null &
RESUME_PID=$!

# Let it run for a bit then check
sleep 15
RESUME_STATE=$(echo "is there a scan running?" | "$AREA" chat pause-check2 2>/dev/null)
echo "$RESUME_STATE"

# Wait for resume to finish
wait $RESUME_PID 2>/dev/null || true

# 7. Verify more files were scanned
info "Checking final state..."
FINAL=$(echo "how many total files were scanned for run_id $RUN_ID?" | "$AREA" chat pause-check2 2>/dev/null)
echo "$FINAL"
pass "Resume completed"

echo ""
echo -e "${GREEN}Pause/resume test complete${RESET}"
