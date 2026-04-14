# Use case: Ghidra import caller evidence
# Expected: Ghidra import output surfaces imported APIs together with caller counts

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SRC="$ROOT/tests/use-cases/ghidra-import-callers/assets/dynamic_imports.c"
BIN="$DATA_DIR/ghidra-import-callers-bin"

info "building a small dynamically linked ELF..."
cc -O0 -g -o "$BIN" "$SRC"

info "requesting Ghidra imports for dynamic sample..."
output=$("$AREA" ghidra "$BIN" imports)

assert_contains "$output" "puts" "reported puts import"
assert_contains "$output" "getpid" "reported getpid import"
assert_contains "$output" "callers:" "reported caller counts for imports"
