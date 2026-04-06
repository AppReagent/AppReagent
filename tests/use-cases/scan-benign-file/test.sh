# Use case: Scan a clearly benign smali file
# Expected: File is classified as not relevant with low relevance score

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/BenignActivity.smali"

info "scanning benign file: $SMALI"
output=$("$AREA" scan "$SMALI" 2>&1)
# Check the summary line (last few lines)
summary=$(echo "$output" | grep -i "complete:")

assert_contains "$summary" "0 relevant\|Relevant: 0" "zero relevant in summary"
assert_contains "$output" "not_relevant\|irrelevant\|Not relevant" "classified as not relevant"
assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"

# Check JSONL was written
JSONL=$(ls scan-outputs/*.jsonl 2>/dev/null | tail -1)
if [ -n "$JSONL" ]; then
    assert_file_contains "$JSONL" '"type":"file_result"' "JSONL has file_result"
    assert_file_contains "$JSONL" '"type":"metadata"' "JSONL has metadata"
    assert_file_contains "$JSONL" '"type":"llm_call"' "JSONL has llm_call entries"
    pass "JSONL output file created"
else
    fail "no JSONL output file found"
fi
