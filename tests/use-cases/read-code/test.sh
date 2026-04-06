# Use case: Read source code files and extract specific methods
# Expected: READ shows file contents with line numbers

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/MalwareService.smali"

info "reading full file..."
output=$(ask "show me the contents of $SMALI")
assert_contains "$output" "MalwareService\|exfiltrateData\|sendSMS\|encryptData" "shows file content"

info "reading specific method..."
output=$(ask "show me the sendSMS method in $SMALI")
assert_contains "$output" "sendTextMessage\|SmsManager\|sendSMS" "shows the sendSMS method"
