# Use case: Extract hardcoded strings from code files
# Expected: STRINGS pulls out URLs, keys, and other string literals

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/MalwareService.smali"

info "extracting strings from smali file..."
output=$(ask "extract all hardcoded strings from $SMALI")
assert_contains "$output" "evil-c2.example.com\|s3cr3t_k3y\|https\|content://" "found hardcoded strings"

info "searching for URL strings..."
output=$(ask "find URL strings in $SMALI")
assert_contains "$output" "https://evil-c2.example.com\|http\|URL\|url" "found URL strings"
