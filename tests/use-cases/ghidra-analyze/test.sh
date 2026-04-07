# Use case: Ghidra deep binary analysis
# Expected: Agent uses GHIDRA tool to decompile and analyze an ELF binary

REVSHELL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/revshell"
HELLO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/hello"

info "requesting Ghidra decompilation of reverse shell..."
output=$(ask "use ghidra to decompile the main function in $REVSHELL")

# Should show decompiled C code with malicious indicators
assert_contains "$output" "main\|decompil" "showed decompiled main function"
assert_contains "$output" "socket\|connect\|c2\|exec\|shell\|establish\|anti_debug" "identified malicious patterns in decompiled code"

info "requesting Ghidra overview of benign binary..."
output=$(ask "use ghidra to get an overview of $HELLO")

# Should show function listing and metadata
assert_contains "$output" "main\|function\|ELF\|x86" "showed binary overview"
