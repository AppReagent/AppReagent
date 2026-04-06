# Use case: List all classes in a decompiled app directory
# Expected: CLASSES shows class hierarchy, methods, fields grouped by package

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets"

info "listing all classes in the app..."
output=$(ask "show me all the classes in $APP_DIR")
assert_contains "$output" "MalwareService\|NetworkHelper\|DataCollector\|class" "found app classes"

info "filtering classes..."
output=$(ask "show classes related to network in $APP_DIR")
assert_contains "$output" "NetworkHelper\|network\|Network" "found network-related classes"
