# Use case: Scan malware with persistence mechanisms (BOOT_COMPLETED, AlarmManager, device admin)
# Expected: Classified as relevant with persistence indicators

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/BootPersistence.smali"

info "scanning persistence file: $SMALI"
output=$("$AREA" scan "$SMALI" 2>&1)

# Should detect as relevant
if echo "$output" | grep -qi "relevant"; then
    pass "classified as relevant"
else
    fail "not detected as relevant"
    echo "  output: $output"
fi

assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"

# Check JSONL for persistence indicators
JSONL=$(ls scan-outputs/*.jsonl 2>/dev/null | tail -1)
if [ -n "$JSONL" ]; then
    if grep -q '"file_result"' "$JSONL"; then
        result_line=$(grep '"file_result"' "$JSONL")
        if echo "$result_line" | grep -qi "persist\|boot\|alarm\|device.admin\|service"; then
            pass "findings mention persistence indicators"
        else
            fail "findings do not mention persistence indicators"
            echo "  result: ${result_line:0:300}"
        fi
    fi
fi
