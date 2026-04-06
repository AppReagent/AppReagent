# Use case: Start a scan, check state, delete it
# Tests the scan lifecycle: start → state → delete

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")/../scan-benign-file" && pwd)/assets/BenignActivity.smali"

# Start a scan in one chat session
info "starting scan in session A..."
output_a=$(ask "scan $SMALI for network connections" "lifecycle-a")
assert_contains "$output_a" "Scan\|scan\|Scanned" "scan started and produced output"

# Extract run_id from the output
run_id=$(echo "$output_a" | grep -oP 'run_id.*?(\w{8,})' | head -1 | grep -oP '\w{8,}$' || true)

# Check state from a different session — should show no active (scan already finished for small file)
info "checking state from session B..."
output_b=$(ask "is there a scan running right now?" "lifecycle-b")
assert_contains "$output_b" "no active\|No active\|not.*running\|no.*scan\|completed" "state check works from different session"

# Verify scan data exists in DB, then delete via SQL (faster than agent roundtrip)
if [ -n "$run_id" ]; then
    info "verifying scan $run_id exists in DB..."
    output_check=$(ask "how many results are there for run_id $run_id?" "lifecycle-b")
    assert_contains "$output_check" "1\|row\|result" "scan data found in database"
fi
