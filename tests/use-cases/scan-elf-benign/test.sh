# Use case: Scan a benign ELF binary (simple hello world)
# Expected: Classified as not relevant with low risk

ELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/hello"

info "scanning benign ELF: $ELF"
output=$("$AREA" scan "$ELF" 2>&1)

assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"
assert_contains "$output" "not_relevant\|irrelevant\|Not relevant\|0 relevant\|Relevant: 0" "classified as not relevant"

# Check JSONL was written
JSONL=$(ls scan-outputs/*.jsonl 2>/dev/null | tail -1)
if [ -n "$JSONL" ]; then
    assert_file_contains "$JSONL" '"type":"file_result"' "JSONL has file_result"
    assert_file_contains "$JSONL" '"type":"llm_call"' "JSONL has llm_call entries"
    pass "JSONL output file created for ELF scan"
else
    fail "no JSONL output file found"
fi
