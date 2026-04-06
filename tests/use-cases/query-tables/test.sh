# Use case: Ask the agent what tables exist in the database
# Expected: Agent uses SQL tool and mentions scan_results and llm_calls

info "asking agent about database tables..."
output=$(ask "what tables are in the database?")

assert_contains "$output" "scan_results" "mentions scan_results table"
assert_contains "$output" "llm_calls" "mentions llm_calls table"
assert_not_contains "$output" "\[error\]" "no error messages"
