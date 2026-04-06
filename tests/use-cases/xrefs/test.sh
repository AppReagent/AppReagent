# Use case: Find cross-references to classes and methods
# Expected: XREFS finds references to HttpURLConnection, SmsManager, etc.

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/MalwareService.smali"

info "finding cross-references to HttpURLConnection..."
output=$(ask "find all references to HttpURLConnection in $SMALI")
assert_contains "$output" "HttpURLConnection\|openConnection\|exfiltrateData" "found HTTP references"

info "finding cross-references to SmsManager..."
output=$(ask "find all references to SmsManager in $SMALI")
assert_contains "$output" "SmsManager\|sendTextMessage\|sendSMS" "found SMS references"
