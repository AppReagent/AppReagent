# Use case: Search for similar methods using vector embeddings
# Expected: After scanning a file, SIMILAR: queries return relevant matches

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/SmsExfil.smali"

# First, scan the file to populate embeddings
info "scanning file to populate embeddings..."
scan_output=$(ask "scan $SMALI" "similar-test")

# Verify scan completed
assert_contains "$scan_output" "1 scanned\|Scanned: 1\|complete" "scan completed"

# Now search for similar methods
info "searching for similar methods..."
similar_output=$(ask "find methods similar to SMS sending" "similar-test")

# The agent should use the SIMILAR tool or return embedding results
# It might use SQL as fallback if embeddings aren't configured, which is also acceptable
assert_contains "$similar_output" "sms\|SMS\|similar\|method\|embedding\|scan_results" "response references SMS or search results"
