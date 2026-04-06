# Use case: Reverse engineer investigating an app with natural-language questions
# Tests that the agent chains tools and answers RE-style investigation questions
# about network activity, ransomware, and cryptocurrency

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/assets"

# Question 1: What network calls does the app make?
info "asking about network calls..."
output=$(ask "what network calls does the app in $APP_DIR make?")
assert_contains "$output" "HttpURLConnection\|openConnection\|URL\|network\|HTTP\|http" "found network call references"
assert_contains "$output" "c2\|malapp\|pool\|minexmr\|command\|collect" "found suspicious server URLs"

# Question 2: Any ransomware activity?
info "asking about ransomware activity..."
output=$(ask "does the app in $APP_DIR have any ransomware activity?")
assert_contains "$output" "Cipher\|encrypt\|AES\|ransom\|locked" "found encryption/ransom indicators"
assert_contains "$output" "bitcoin\|btc\|BTC\|payment\|bc1\|0.5" "found ransom payment references"

# Question 3: Cryptocurrency related stuff?
info "asking about cryptocurrency..."
output=$(ask "does $APP_DIR have any cryptocurrency related stuff in it?")
assert_contains "$output" "min\|stratum\|pool\|monero\|xmr\|crypto\|coin" "found crypto mining references"
assert_contains "$output" "wallet\|address\|hash\|SHA\|sha\|44AFF" "found wallet or hash references"
