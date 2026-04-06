# Use case: Search for cross-references after a scan
# Expected: XREFS tool finds references to target classes/methods in scan data

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/SmsExfil.smali"

info "scanning file first to populate data..."
output=$(ask "scan $SMALI")
assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"

info "searching for cross-references to SmsManager..."
output=$(ask "find all cross-references to SmsManager")

# Should find references in call graph or findings
assert_contains "$output" "SmsManager\|sendTextMessage\|SMS\|sms" "found SMS-related references"
