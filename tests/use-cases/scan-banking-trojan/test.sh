# Use case: Scan a banking trojan with overlay attacks, SMS interception, and C2
# Expected: Classified as relevant with banking trojan indicators

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/OverlayAttack.smali"

info "scanning banking trojan file: $SMALI"
output=$("$AREA" scan "$SMALI" 2>&1)

# Should detect as relevant
if echo "$output" | grep -qi "relevant"; then
    pass "classified as relevant"
else
    fail "not detected as relevant"
    echo "  output: $output"
fi

assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"

# Check JSONL for banking trojan indicators
JSONL=$(ls scan-outputs/*.jsonl 2>/dev/null | tail -1)
if [ -n "$JSONL" ]; then
    if grep -q '"file_result"' "$JSONL"; then
        result_line=$(grep '"file_result"' "$JSONL")
        if echo "$result_line" | grep -qi "banking\|overlay\|accessibility\|phishing\|credential\|c2"; then
            pass "findings mention banking trojan indicators"
        else
            fail "findings do not mention banking trojan indicators"
            echo "  result: ${result_line:0:300}"
        fi
    fi
fi
