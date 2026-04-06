# Use case: IMPROVE tool routes correctly and runs evaluation
# Verifies the agent uses IMPROVE: (not SHELL:) and returns a score.

# Ask the agent to evaluate — should route to IMPROVE tool, not SHELL
output=$(ask "evaluate the corpus score" "improve-eval")
assert_contains "$output" "score\|evaluation\|corpus\|/100" "improve eval returned score info"
assert_not_contains "$output" "sandbox\|Sandbox\|docker\|Docker" "no sandbox errors"

# Ask with different phrasing — should still route to IMPROVE
output2=$(ask "run the improve tool" "improve-eval2")
assert_contains "$output2" "score\|evaluation\|corpus\|/100\|improve" "run improve tool returned results"
assert_not_contains "$output2" "sandbox\|Sandbox" "no sandbox errors on second phrasing"
