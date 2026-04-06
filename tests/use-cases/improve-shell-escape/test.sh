# Use case: IMPROVE tool handles special characters safely
# Verifies that shell metacharacters in user input don't cause injection.
# This tests the escaping in ImproveTool's gitCommit and exec() calls.

# Send a task containing shell metacharacters — should not crash or execute injected commands
output=$(ask "evaluate the corpus with goal: test'; echo INJECTED; echo '" "improve-escape")

# The agent should respond without crashing — we don't care about the exact result,
# just that it didn't execute the injected command or error out from bad quoting
assert_not_contains "$output" "INJECTED" "shell injection did not execute"
assert_not_contains "$output" "syntax error" "no shell syntax errors"
assert_not_contains "$output" "unexpected EOF" "no shell quoting errors"

# The agent should still route to IMPROVE or respond meaningfully
assert_contains "$output" "score\|corpus\|evaluation\|improve\|error\|Error\|OBSERVATION" "agent responded to improve request"
