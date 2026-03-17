#!/bin/bash
# Quick test for ai-front.suyeqaaq.workers.dev

WORKER_URL="https://ai-front.suyeqaaq.workers.dev"

echo "🚀 Testing Worker at: $WORKER_URL"
echo ""

# Test 1: Health
echo "1️⃣ Health Check..."
curl -s "$WORKER_URL/health" | jq .
echo ""

# Test 2: Get JWT Token
echo "2️⃣ Getting JWT Token..."
RESPONSE=$(curl -s -X POST "$WORKER_URL/v1/auth/attest" \
  -H "Content-Type: application/json" \
  -d '{"platform":"ios","attestation":{}}')

echo "$RESPONSE" | jq .
TOKEN=$(echo "$RESPONSE" | jq -r '.token // empty')

if [ -z "$TOKEN" ]; then
  echo "❌ Failed to get token"
  exit 1
fi

echo ""
echo "✅ Got Token: ${TOKEN:0:50}..."
echo ""

# Test 3: Parse Text
echo "3️⃣ Testing Parse Text..."
curl -s -X POST "$WORKER_URL/v1/reminder/parse-text" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "明天下午三点开会",
    "timezone": "Asia/Shanghai",
    "locale": "zh-CN"
  }' | jq .

echo ""
echo "✨ Test Complete!"
