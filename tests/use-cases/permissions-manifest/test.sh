# Use case: Analyze AndroidManifest.xml for permissions and components
# Expected: PERMISSIONS tool identifies dangerous permissions and suspicious combinations

MANIFEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/AndroidManifest.xml"

info "analyzing manifest permissions..."
output=$(ask "analyze the permissions in $MANIFEST")

# Should identify dangerous permissions
assert_contains "$output" "READ_SMS\|SEND_SMS\|SMS" "found SMS permissions"
assert_contains "$output" "CAMERA\|camera" "found camera permission"
assert_contains "$output" "INTERNET\|internet" "found internet permission"

# Should flag suspicious combinations
assert_contains "$output" "suspicious\|exfiltration\|surveillance\|combination" "flagged suspicious permission combinations"

# Should identify exported components
assert_contains "$output" "BootReceiver\|SmsReceiver\|exported" "identified exported receivers"
