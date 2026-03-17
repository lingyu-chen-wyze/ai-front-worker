#!/bin/bash
# Test script for ai-front-worker endpoints
# Usage: ./test.sh https://your-worker.dev

if [ -z "$1" ]; then
  echo "Usage: $0 <worker-url>"
  echo "Example: $0 https://ai-front-worker.your-account.workers.dev"
  exit 1
fi

WORKER_URL="$1"

echo "🔍 Testing ai-front-worker at: $WORKER_URL"
echo ""

# Test 1: Health Check
echo "1️⃣ Testing /health endpoint..."
HEALTH=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$WORKER_URL/health")
HTTP_CODE=$(echo "$HEALTH" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$HEALTH" | grep -v "HTTP_CODE")

if [ "$HTTP_CODE" == "200" ]; then
  echo "✅ Health check passed"
  echo "   Response: $BODY"
else
  echo "❌ Health check failed (HTTP $HTTP_CODE)"
  echo "   Response: $BODY"
  exit 1
fi
echo ""

# Test 2: Attestation
echo "2️⃣ Testing /v1/auth/attest endpoint..."
ATTEST=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -X POST "$WORKER_URL/v1/auth/attest" \
  -H "Content-Type: application/json" \
  -d '{"platform":"ios","attestation":{}}')

HTTP_CODE=$(echo "$ATTEST" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$ATTEST" | grep -v "HTTP_CODE")

if [ "$HTTP_CODE" == "200" ]; then
  echo "✅ Attestation passed"
  TOKEN=$(echo "$BODY" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
  INSTALL_ID=$(echo "$BODY" | grep -o '"installId":"[^"]*"' | cut -d'"' -f4)
  echo "   InstallId: $INSTALL_ID"
  echo "   Token: ${TOKEN:0:30}..."
else
  echo "❌ Attestation failed (HTTP $HTTP_CODE)"
  echo "   Response: $BODY"
  exit 1
fi
echo ""

# Test 3: Parse Text with JWT
echo "3️⃣ Testing /v1/reminder/parse-text with JWT..."
PARSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -X POST "$WORKER_URL/v1/reminder/parse-text" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "明天下午三点开会",
    "timezone": "Asia/Shanghai",
    "locale": "zh-CN"
  }')

HTTP_CODE=$(echo "$PARSE" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$PARSE" | grep -v "HTTP_CODE")

if [ "$HTTP_CODE" == "200" ]; then
  echo "✅ Parse text passed"
  echo "   Response: $BODY"
  
  # Check rate limit headers would be in verbose output
  HEADERS=$(curl -s -I \
    -X POST "$WORKER_URL/v1/reminder/parse-text" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"text":"test","timezone":"UTC","locale":"en"}' 2>&1)
  
  LIMIT=$(echo "$HEADERS" | grep -i "x-ratelimit-limit" | cut -d: -f2 | tr -d ' \r')
  REMAINING=$(echo "$HEADERS" | grep -i "x-ratelimit-remaining" | cut -d: -f2 | tr -d ' \r')
  
  if [ ! -z "$LIMIT" ]; then
    echo "   Rate Limit: $REMAINING/$LIMIT remaining"
  fi
else
  echo "❌ Parse text failed (HTTP $HTTP_CODE)"
  echo "   Response: $BODY"
  exit 1
fi
echo ""

# Test 4: Invalid JWT
echo "4️⃣ Testing invalid JWT..."
INVALID=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -X POST "$WORKER_URL/v1/reminder/parse-text" \
  -H "Authorization: Bearer invalid.token.here" \
  -H "Content-Type: application/json" \
  -d '{"text":"test","timezone":"UTC","locale":"en"}')

HTTP_CODE=$(echo "$INVALID" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$INVALID" | grep -v "HTTP_CODE")

if [ "$HTTP_CODE" == "401" ]; then
  ERROR=$(echo "$BODY" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
  echo "✅ Invalid JWT correctly rejected"
  echo "   Error: $ERROR"
else
  echo "⚠️  Expected 401 for invalid JWT, got $HTTP_CODE"
  echo "   Response: $BODY"
fi
echo ""

# Test 5: Missing Authorization
echo "5️⃣ Testing missing authorization..."
NO_AUTH=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -X POST "$WORKER_URL/v1/reminder/parse-text" \
  -H "Content-Type: application/json" \
  -d '{"text":"test","timezone":"UTC","locale":"en"}')

HTTP_CODE=$(echo "$NO_AUTH" | grep "HTTP_CODE" | cut -d: -f2)

if [ "$HTTP_CODE" == "401" ]; then
  echo "✅ Missing auth correctly rejected"
else
  echo "⚠️  Expected 401 for missing auth, got $HTTP_CODE"
fi
echo ""

echo "✨ All tests completed!"
echo ""
echo "📊 Summary:"
echo "   Worker URL: $WORKER_URL"
echo "   Install ID: $INSTALL_ID"
echo "   JWT Token: ${TOKEN:0:50}..."
echo ""
echo "💡 To test rate limiting (50 requests/day), run:"
echo "   for i in {1..51}; do"
echo "     curl -X POST $WORKER_URL/v1/reminder/parse-text \\"
echo "       -H \"Authorization: Bearer $TOKEN\" \\"
echo "       -H \"Content-Type: application/json\" \\"
echo "       -d '{\"text\":\"test $i\",\"timezone\":\"UTC\",\"locale\":\"en\"}'"
echo "   done"
