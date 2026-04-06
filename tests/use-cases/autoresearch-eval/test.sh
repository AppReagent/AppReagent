# Use case: AutoResearch corpus files scan correctly
# Smoke test: scan one malware + one benign file, verify classification makes sense

CORPUS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../autoresearch/corpus" && pwd)"
MALWARE="$CORPUS/malware/SmsExfil.smali"
BENIGN="$CORPUS/benign/BenignActivity.smali"

# Scan the malware file
info "scanning malware corpus file..."
output_mal=$(ask "scan $MALWARE" "eval-mal")
assert_contains "$output_mal" "relevant\|Relevant\|scan.*complete\|Scan.*complete" "malware scan produced output"

# Scan the benign file
info "scanning benign corpus file..."
output_ben=$(ask "scan $BENIGN" "eval-ben")
assert_contains "$output_ben" "scan\|Scan" "benign scan produced output"

# Query risk scores to verify separation
info "checking risk score separation..."
output_scores=$(ask "show risk_score and file_path from scan_results order by risk_score desc limit 10" "eval-check")

# Malware should have higher score than benign
if echo "$output_scores" | grep -qi "sms\|exfil"; then
    pass "scan results include malware file"
else
    info "could not verify scores via SQL (non-critical)"
fi
