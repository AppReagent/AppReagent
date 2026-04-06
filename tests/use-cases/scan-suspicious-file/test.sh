# Use case: Scan a clearly malicious smali file (SMS exfiltration)
# Expected: File is classified as relevant (has malware indicators)

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/SmsExfil.smali"

info "scanning suspicious file: $SMALI"
output=$("$AREA" scan "$SMALI" 2>&1)

# Should detect as relevant (has suspicious behavior)
if echo "$output" | grep -qi "relevant"; then
    pass "classified as relevant"
else
    fail "not detected as relevant"
    echo "  output: $output"
fi

assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"

# Check JSONL result
JSONL=$(ls scan-outputs/*.jsonl 2>/dev/null | tail -1)
if [ -n "$JSONL" ]; then
    # The findings should mention SMS or exfiltration
    if grep -q '"file_result"' "$JSONL"; then
        result_line=$(grep '"file_result"' "$JSONL")
        if echo "$result_line" | grep -qi "sms\|exfil\|relevant"; then
            pass "findings mention SMS/exfiltration indicators"
        else
            fail "findings do not mention SMS/exfiltration"
            echo "  result: ${result_line:0:300}"
        fi
    fi
fi
