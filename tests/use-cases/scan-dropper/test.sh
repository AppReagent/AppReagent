# Use case: Scan a dropper/loader that downloads, decrypts, and executes a DEX payload
# Expected: Classified as relevant with dropper threat category

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/PayloadLoader.smali"

info "scanning dropper file: $SMALI"
output=$("$AREA" scan "$SMALI" 2>&1)

# Should detect as relevant
if echo "$output" | grep -qi "relevant"; then
    pass "classified as relevant"
else
    fail "not detected as relevant"
    echo "  output: $output"
fi

assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"

# Check JSONL for dropper indicators
JSONL=$(ls scan-outputs/*.jsonl 2>/dev/null | tail -1)
if [ -n "$JSONL" ]; then
    if grep -q '"file_result"' "$JSONL"; then
        result_line=$(grep '"file_result"' "$JSONL")
        if echo "$result_line" | grep -qi "dropper\|DexClassLoader\|payload\|download"; then
            pass "findings mention dropper/payload indicators"
        else
            fail "findings do not mention dropper/payload indicators"
            echo "  result: ${result_line:0:300}"
        fi
    fi
fi
