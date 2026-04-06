# Use case: Ask agent to generate a run ID
# Expected: Agent calls GENERATE_RUN_ID tool and returns an ID

info "asking agent to generate a run ID..."
output=$(ask "please generate a new run id for a scan")

assert_contains "$output" "run" "mentions run in response"
assert_not_contains "$output" "\[error\]" "no error messages"
