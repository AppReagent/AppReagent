#!/bin/bash
set -euo pipefail

BUILD_DIR="${BUILD_DIR:-/tmp/area-build}"

if [ ! -f "$BUILD_DIR/compile_commands.json" ]; then
    cmake -B "$BUILD_DIR" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >/dev/null 2>&1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FILTERED="$BUILD_DIR/compile_commands_iwyu.json"

python3 -c "
import json, sys, os
entries = json.load(open('$BUILD_DIR/compile_commands.json'))
only = set(os.path.abspath(f) for f in sys.argv[1:]) if len(sys.argv) > 1 else set()
filtered = []
for e in entries:
    if '_deps' in e['file']:
        continue
    if '/src/' not in e['file']:
        continue
    if only and e['file'] not in only:
        continue
    filtered.append(e)
json.dump(filtered, open('$FILTERED', 'w'), indent=2)
print(f'{len(filtered)} source files to check', file=sys.stderr)
" "$@"

if python3 -c "import json; exit(0 if json.load(open('$FILTERED')) else 1)"; then :; else
    echo "include-what-you-use: no matching source files"
    exit 0
fi

OUTPUT=$(iwyu_tool -j"$(nproc)" -p "$FILTERED" -- \
    -Xiwyu --no_fwd_decls \
    -Xiwyu --max_line_length=120 \
    -Xiwyu --mapping_file="$SCRIPT_DIR/iwyu.imp" 2>&1 || true)

ISSUES=$(echo "$OUTPUT" | grep -E 'should (add|remove) these lines' || true)

if [ -n "$ISSUES" ]; then
    echo "$OUTPUT" | grep -E '(should add|should remove|^#include|^- #include|has correct|^---$)'
    echo ""
    echo "ERROR: include-what-you-use found issues."
    exit 1
else
    echo "include-what-you-use: all clean"
fi
