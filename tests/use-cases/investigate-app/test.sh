# Use case: Multi-step investigation of a suspicious app
# Expected: Agent chains tools together to answer RE questions

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets"
SMALI="$APP_DIR/MalwareService.smali"

info "asking the agent to investigate the app..."
output=$(ask "investigate $APP_DIR — what does this app do and is it suspicious? check the classes, decompile key methods, look at strings")
assert_contains "$output" "network\|HTTP\|URL\|exfiltrat\|SMS\|encrypt\|suspicious\|malicious\|malware\|C2\|command" "agent identified suspicious behavior through investigation"
