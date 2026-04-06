# Use case: Verify agent handles SQL queries that come back wrapped in markdown
# Expected: Agent successfully queries and returns results without getting stuck

info "asking agent to count scan results..."
output=$(ask "how many rows are in the scan_results table?")

# Should get a numeric answer, not an error loop
assert_not_contains "$output" "syntax error" "no SQL syntax errors"
assert_not_contains "$output" "max iterations" "did not hit max iterations"

# Should have some answer
if [ -n "$output" ]; then
    pass "got a response from agent"
else
    fail "empty response from agent"
fi
