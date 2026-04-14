# Use case: Ghidra exact-address disassembly
# Expected: Agent can disassemble code at a specific address and report the target instruction

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HELLO="$ROOT/tests/use-cases/scan-elf-benign/assets/hello"

info "requesting Ghidra disassembly at an exact code address..."
output=$(ask "use ghidra to disassemble the code at 0x4018ab in $HELLO and tell me what instruction is at that exact address")

assert_contains "$output" "4018ab" "reported the requested address"
assert_contains "$output" "endbr64\|main" "showed instruction-level disassembly around the target address"
