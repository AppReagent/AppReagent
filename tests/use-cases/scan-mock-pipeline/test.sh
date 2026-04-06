# Use case: Full scan pipeline with mock LLM responses (no real LLM calls)
# Tests the complete scan → triage → deep_analysis → synthesis pipeline
# using MockBackend with routed responses for each node.

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMALI="$TEST_DIR/assets/SmsExfil.smali"
MOCK_RESPONSES="$TEST_DIR/assets/mock_responses.json"

# Copy test asset (reuse from scan-suspicious-file)
if [ ! -f "$SMALI" ]; then
    cp "$(dirname "$TEST_DIR")/scan-suspicious-file/assets/SmsExfil.smali" "$SMALI"
fi

# Copy mock responses to DATA_DIR so the mock backend can find it
cp "$MOCK_RESPONSES" "$DATA_DIR/mock_responses.json"

# Patch config.json to use mock endpoints at each tier, pointing to the responses file
python3 -c "
import json, sys
with open('$DATA_DIR/config.json') as f:
    cfg = json.load(f)
cfg['ai_endpoints'] = [
    {'id': 'mock-t0', 'provider': 'mock', 'url': '$DATA_DIR/mock_responses.json', 'model': 'auto', 'tier': 0, 'max_concurrent': 3, 'context_window': 131072},
    {'id': 'mock-t1', 'provider': 'mock', 'url': '$DATA_DIR/mock_responses.json', 'model': 'auto', 'tier': 1, 'max_concurrent': 3, 'context_window': 131072},
    {'id': 'mock-t2', 'provider': 'mock', 'url': '$DATA_DIR/mock_responses.json', 'model': 'auto', 'tier': 2, 'max_concurrent': 3, 'context_window': 131072},
]
# Remove embedding config to avoid external calls
cfg.pop('embedding', None)
with open('$DATA_DIR/config.json', 'w') as f:
    json.dump(cfg, f, indent=2)
"

# Run the scan directly (not via agent/server — avoids DB dependency for agent chat)
info "scanning SmsExfil.smali with mock LLM pipeline"
output=$("$AREA" scan "$SMALI" 2>&1)

# Verify the full pipeline executed
assert_contains "$output" "relevant" "classified as relevant"
assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"
assert_contains "$output" "1 relevant\|Relevant: 1" "one file is relevant"

# Check JSONL output was written
JSONL=$(ls "$DATA_DIR/scan-outputs/"*.jsonl 2>/dev/null | tail -1)
if [ -n "$JSONL" ]; then
    assert_file_contains "$JSONL" '"type":"file_result"' "JSONL has file_result"
    assert_file_contains "$JSONL" '"type":"metadata"' "JSONL has metadata"
    assert_file_contains "$JSONL" '"type":"llm_call"' "JSONL has llm_call entries"

    # Verify the mock responses flowed through correctly
    assert_file_contains "$JSONL" 'SmsManager' "findings mention SmsManager"
    assert_file_contains "$JSONL" 'exfiltration\|C2\|malware' "findings mention malware indicators"

    # Verify synthesis produced a risk score
    if grep -q '"type":"scan_synthesis"' "$JSONL"; then
        assert_file_contains "$JSONL" 'relevance_score' "synthesis has relevance_score"
        pass "synthesis node executed"
    else
        fail "no synthesis output in JSONL"
    fi

    pass "JSONL output file created with mock pipeline results"
else
    fail "no JSONL output file found"
fi
