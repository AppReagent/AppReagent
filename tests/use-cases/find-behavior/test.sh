# Use case: Scan a file, then use FIND to search for specific behaviors
# Expected: FIND surfaces methods matching behavioral queries

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/FileReader.smali"

info "scanning file for behavioral data..."
output=$(ask "scan $SMALI")
assert_contains "$output" "1 scanned\|Scanned: 1" "one file was scanned"

info "searching for filesystem reading behavior..."
output=$(ask "find methods that read from the filesystem")

# Should find the readExternalFile method
assert_contains "$output" "readExternalFile\|FileInputStream\|file\|filesystem" "found filesystem reading behavior"

info "searching for network behavior..."
output=$(ask "find methods that make network connections or HTTP requests")

# Should find the sendToServer method
assert_contains "$output" "sendToServer\|HTTP\|URL\|network\|connection" "found network behavior"
