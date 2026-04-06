# Use case: Scan a file, then run RAG-augmented analysis
# Tests: SCAN produces results → ANALYZE retrieves and analyzes them

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../use-cases/scan-suspicious-file" && pwd)/assets/SmsExfil.smali"

# Step 1: Run a scan to populate results
info "scanning suspicious file for analysis..."
output_scan=$(ask "scan $SMALI" "analyze-test")
assert_contains "$output_scan" "Scan\|scan\|relevant" "scan produced results"

# Step 2: Ask the agent to analyze the latest scan
info "running analysis on latest scan..."
output_analyze=$(ask "analyze the latest scan results" "analyze-test")

# The agent should use the ANALYZE tool
assert_contains "$output_analyze" "nalysis\|threat\|risk\|confidence\|findings\|pattern" "analysis produced meaningful output"

# Step 3: Verify analysis references the scanned content
assert_contains "$output_analyze" "SMS\|sms\|exfil\|message\|threat\|risk" "analysis references scan findings"
