# Use case: Decompile smali bytecode into readable pseudo-Java
# Expected: DECOMPILE shows Java-like code with method calls, field access, constructors

SMALI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets/MalwareService.smali"

info "decompiling full file..."
output=$(ask "decompile the code in $SMALI")
assert_contains "$output" "new URL\|URL.*openConnection\|HttpURLConnection\|setRequestMethod\|POST\|exfiltrateData\|void" "shows Java-like method calls"

info "decompiling specific method..."
output=$(ask "decompile just the exfiltrateData method in $SMALI")
assert_contains "$output" "exfiltrateData\|URL\|HttpURLConnection\|getOutputStream\|write" "shows exfiltrateData as pseudo-Java"

info "decompiling another method..."
output=$(ask "decompile the encryptData method in $SMALI")
assert_contains "$output" "Cipher\|SecretKeySpec\|AES\|doFinal\|encryptData" "shows crypto operations in pseudo-Java"
