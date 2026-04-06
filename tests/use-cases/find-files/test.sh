# Use case: Ask agent to find files by rough name
# Expected: Agent calls FIND_FILES and returns matching paths

info "asking agent to find SmsExfil test file..."
output=$(ask "find me the SmsExfil smali file, I don't remember the exact path")

assert_contains "$output" "SmsExfil" "found the SmsExfil file"
assert_contains "$output" "smali" "mentions smali"
assert_not_contains "$output" "\[error\]" "no error messages"
