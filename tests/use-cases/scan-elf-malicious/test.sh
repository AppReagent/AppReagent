# Use case: Scan a malicious ELF binary (reverse shell with socket+execve)
# Expected: Classified as relevant with high risk

ELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/revshell"

info "scanning malicious ELF: $ELF"
output=$("$AREA" scan "$ELF" 2>&1)

assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"

# Should detect as relevant (has socket, connect, execve, dup2 — classic reverse shell)
if echo "$output" | grep -qi "relevant"; then
    pass "classified as relevant"
else
    fail "not detected as relevant"
    echo "  output: $output"
fi

# Check JSONL result
JSONL=$(ls scan-outputs/*.jsonl 2>/dev/null | tail -1)
if [ -n "$JSONL" ]; then
    if grep -q '"file_result"' "$JSONL"; then
        result_line=$(grep '"file_result"' "$JSONL")
        if echo "$result_line" | grep -qi "socket\|execve\|c2\|shell\|reverse\|relevant"; then
            pass "findings mention network/execution indicators"
        else
            fail "findings do not mention expected indicators"
            echo "  result: ${result_line:0:300}"
        fi
    fi
    pass "JSONL output file created for ELF scan"
else
    fail "no JSONL output file found"
fi
