# Use case: Search code for specific patterns using GREP
# Expected: GREP finds network calls, SMS, crypto operations in smali code

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/MalwareService.smali"

info "searching for network calls in code..."
output=$(ask "find all network calls in $SMALI")
assert_contains "$output" "HttpURLConnection\|openConnection\|URL\|network" "found network-related code"

info "searching for SMS operations..."
output=$(ask "find SMS sending code in $SMALI")
assert_contains "$output" "SmsManager\|sendTextMessage\|SMS\|sms" "found SMS operations"

info "searching for crypto operations..."
output=$(ask "find encryption or crypto code in $SMALI")
assert_contains "$output" "Cipher\|AES\|encrypt\|SecretKeySpec\|crypto" "found crypto operations"
