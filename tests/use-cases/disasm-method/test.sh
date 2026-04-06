# Use case: View disassembly of a specific method
# Expected: DISASM tool shows method source code and call targets

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/SmsExfil.smali"

info "listing methods in file..."
output=$(ask "show me the methods in $SMALI")

# Should list methods
assert_contains "$output" "sendStolenData\|stealContacts\|exfiltrate" "listed methods in file"

info "viewing specific method code..."
output=$(ask "show me the code of the sendStolenData method in $SMALI")

# Should show the method body with SMS sending
assert_contains "$output" "SmsManager\|sendTextMessage\|invoke" "showed method code with SMS calls"
