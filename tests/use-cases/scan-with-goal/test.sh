# Use case: Scan with a specific goal question
# Expected: Agent scans and answers the goal question about network connections

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/NetworkHelper.smali"

info "scanning with goal: does this open network connections?"
output=$(ask "does this file open any network connections? scan $SMALI")

# Should find the HTTP connection
assert_contains "$output" "relevant\|network\|HTTP\|URL\|connection\|socket" "found network-related behavior"
assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"
