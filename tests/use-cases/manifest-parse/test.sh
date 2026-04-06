# Use case: Parse AndroidManifest.xml for permissions and components
# Expected: MANIFEST shows permissions, activities, services, receivers

MANIFEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets"

info "analyzing manifest..."
output=$(ask "analyze the manifest at $MANIFEST_DIR/AndroidManifest.xml")
assert_contains "$output" "INTERNET\|READ_CONTACTS\|SEND_SMS\|permission" "found permissions"
assert_contains "$output" "MalwareService\|BootReceiver\|MainActivity" "found components"
