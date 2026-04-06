#!/bin/bash
# E2E test: scan a mixed directory (smali + ELF) for obfuscation techniques

ASSETS="$(dirname "$0")/assets"
ELF_AVAILABLE=false

# Build an obfuscated ELF binary if gcc is available
if command -v gcc &>/dev/null; then
    cat > /tmp/area_obf_test_$$.c << 'CEOF'
#include <string.h>
#include <stdlib.h>

/* XOR-encoded string — classic obfuscation */
static unsigned char encoded[] = {0x2a, 0x27, 0x2e, 0x2e, 0x29, 0x66, 0x35, 0x29, 0x34, 0x2e, 0x24, 0x00};

void decode_string(unsigned char* s, int len) {
    for (int i = 0; i < len; i++) {
        s[i] ^= 0x42;
    }
}

/* Anti-debugging: check for ptrace */
int check_debugger(void) {
    volatile int x = 0;
    x = x + 1;
    return x;
}

int main(void) {
    unsigned char* buf = (unsigned char*)malloc(100);
    memcpy(buf, encoded, sizeof(encoded));
    decode_string(buf, sizeof(encoded) - 1);
    check_debugger();
    free(buf);
    return 0;
}
CEOF
    if gcc -O0 -o "$ASSETS/obfuscated_binary" /tmp/area_obf_test_$$.c 2>/dev/null; then
        ELF_AVAILABLE=true
        info "Built ELF test binary"
    fi
    rm -f /tmp/area_obf_test_$$.c
fi

# Scan the mixed asset directory for obfuscation
output=$(ask "scan $ASSETS for obfuscation techniques")

# Should detect obfuscation in smali
assert_contains "$output" "obfuscat\|xor\|reflection\|cipher\|encod" \
    "Should detect obfuscation patterns"

assert_contains "$output" "relevant\|score" \
    "Should produce risk assessment"

# If ELF was available, verify it was included in the scan
if [ "$ELF_AVAILABLE" = true ]; then
    assert_contains "$output" "obfuscated_binary\|elf\|binary\|native\|decode" \
        "Should analyze ELF binary"
fi

# Clean up generated binary
rm -f "$ASSETS/obfuscated_binary"
