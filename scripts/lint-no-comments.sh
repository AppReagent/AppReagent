#!/bin/bash
# Check that source files contain no comments.
# Tests are exempt. Comments in source are a prompt injection vector —
# an attacker could embed instructions that alter agent behavior.

set -euo pipefail

ROOT="${1:-.}"
violations=0

while IFS= read -r file; do
    # Strip strings to avoid false positives on URLs, paths, etc.
    # Then look for // or /* style comments.
    awk '
    {
        line = $0
        # Remove contents of double-quoted strings
        gsub(/"([^"\\]|\\.)*"/, "\"\"", line)
        # Remove contents of single-quoted chars
        gsub(/'\''[^'\''\\]*'\''/, "'\'''\''", line)

        if (line ~ /^} *\/\/ *namespace( [a-z:]{1,40})?$/) next

        if (line ~ /\/\//) {
            printf "%s:%d: %s\n", FILENAME, NR, $0
            found++
        } else if (line ~ /\/\*/) {
            printf "%s:%d: %s\n", FILENAME, NR, $0
            found++
        }
    }
    END { exit (found > 0 ? 1 : 0) }
    ' "$file" && true
    if [ $? -ne 0 ]; then
        violations=1
    fi
done < <(find "$ROOT/src" "$ROOT/include" -type f \( -name '*.cpp' -o -name '*.h' \) | sort)

if [ "$violations" -ne 0 ]; then
    echo ""
    echo "ERROR: Source files must not contain comments (prompt injection risk)."
    echo "       Tests (tests/) are exempt."
    exit 1
fi
