# Use case: Ask the agent if any scans are running
# Expected: Agent uses STATE tool and reports no active scans

info "asking agent about scan state..."
output=$(ask "is there a scan running right now?")

assert_contains "$output" "no active\|No active\|not.*running\|no.*scan" "reports no active scans"
assert_not_contains "$output" "\[error\]" "no error messages"
