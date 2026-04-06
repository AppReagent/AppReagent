# Use case: Verify call graph is built during scans
# Expected: After scanning, method_calls table has edges and agent can query them

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/SmsExfil.smali"

# Scan the file to build call graph
info "scanning file to build call graph..."
scan_output=$(ask "scan $SMALI" "callgraph-test")
assert_contains "$scan_output" "1 scanned\|Scanned: 1\|complete" "scan completed"

# Query the call graph via SQL to verify edges were stored
info "querying call graph edges..."
edges_output=$(ask "run this exact SQL and show me the results: SELECT caller_class, caller_method, callee_class, callee_method, invoke_type FROM method_calls ORDER BY caller_method, callee_method LIMIT 20" "callgraph-test")

# Should have edges from the scanned file
assert_contains "$edges_output" "SmsManager\|sendTextMessage\|getDefault\|SmsExfil\|method_calls" "call graph contains expected method calls"

# Ask about callees of a specific method
info "querying callees of exfiltrateViaSms..."
callees_output=$(ask "what methods does exfiltrateViaSms call? use the method_calls table" "callgraph-test")
assert_contains "$callees_output" "stealContacts\|sendStolenData" "found expected callees"
