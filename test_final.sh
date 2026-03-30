#!/bin/bash
source /tmp/payloads.sh
BASE="http://localhost:8000"
KEY="devkey"
PASS=0
FAIL=0

check() {
  local label="$1" expected="$2" got="$3"
  # removing all spaces from got and expected for robust matching
  local clean_got=$(echo "$got" | tr -d ' \n\r')
  local clean_expected=$(echo "$expected" | tr -d ' \n\r')
  if echo "$clean_got" | grep -q "$clean_expected"; then
    echo "  ✅ PASS — $label"
    PASS=$((PASS+1))
  else
    echo "  ❌ FAIL — $label"
    echo "       Expected: $clean_expected"
    echo "       Got:      $clean_got"
    FAIL=$((FAIL+1))
  fi
}

echo "── [1] Health Check ──────────────────────────"
R=$(curl -s "$BASE/health")
check "health" '"status":"ok"' "$R"

echo "── [2] Security ──────────────────────────────"
S=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/analyze" -H "Content-Type: application/json" -d '{"type":"url","data":"http://test.com"}')
check "No API key -> 401" "401" "$S"

echo "── [3] URL Detection ─────────────────────────"
R=$(curl -s -X POST "$BASE/analyze" -H "Content-Type: application/json" -H "X-API-Key: $KEY" -d '{"type":"url","data":"http://free-prize-winner.tk/login?user=admin@bank.com&verify=1%20%20"}')
check "URL -> url_model" '"model_used":"url_model"' "$R"

echo "── [4] Network Detection ─────────────────────"
R=$(curl -s -X POST "$BASE/analyze" -H "Content-Type: application/json" -H "X-API-Key: $KEY" -d "$NET_PAYLOAD")
check "Network Attack -> net_model" '"model_used":"net_model"' "$R"
check "Network Attack -> threat" '"is_threat":true' "$R"
check "Network Attack -> category" '"threat_category":"Attack"' "$R"

echo "── [5] CB Detection ──────────────────────────"
R=$(curl -s -X POST "$BASE/analyze" -H "Content-Type: application/json" -H "X-API-Key: $KEY" -d "$CB_PAYLOAD")
check "CB -> cb_model" '"model_used":"cb_model"' "$R"
check "CB -> threat" '"is_threat":true' "$R"
check "CB -> category" '"threat_category":"Cyberbullying"' "$R"

echo "── [6] Batch ─────────────────────────────────"
R=$(curl -s -X POST "$BASE/batch" -H "Content-Type: application/json" -H "X-API-Key: $KEY" -d "[$CB_PAYLOAD, $NET_PAYLOAD]")
check "Batch -> array response" '"model_used":"cb_model"' "$R"

echo "═══════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════"
exit $FAIL
