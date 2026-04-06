# Use case: /clear command wipes agent context
# Expected: After /clear, agent does not remember prior conversation

CHAT_ID="clear-ctx-test"

info "sending initial message to establish context..."
output=$(ask "remember that the secret word is pineapple" "$CHAT_ID")

info "sending /clear to wipe context..."
echo "/clear" | ./area chat "$CHAT_ID"

info "verifying context was actually cleared..."
output=$(ask "what was the secret word I told you earlier?" "$CHAT_ID")

assert_not_contains "$output" "pineapple" "agent should not remember the secret word after /clear"
