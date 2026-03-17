#!/bin/bash

# Voice Parse API Test Script
# Usage: ./voice-test.sh <audio-file>

WORKER_URL="https://ai-front.suyeqaaq.workers.dev"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== JustRemind Voice Parse API Test ===${NC}\n"

# Step 1: Get JWT token via attestation
echo -e "${BLUE}[1/2] Getting JWT token...${NC}"

# For testing, you need a real device's attestation data
# This is a placeholder - replace with actual attestation from iOS app
TOKEN_RESPONSE=$(curl -s -X POST "${WORKER_URL}/v1/auth/attest" \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "ios",
    "attestation": {
      "keyId": "YOUR_KEY_ID",
      "attestationObject": "YOUR_ATTESTATION_OBJECT",
      "challenge": "'$(date +%s)000'"
    }
  }')

echo "Token response: $TOKEN_RESPONSE"

# Extract token (you'll need jq installed, or parse manually)
# TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.token')

# For testing, use a pre-obtained token:
echo -e "${RED}Note: Replace TOKEN with actual JWT from your iOS app${NC}\n"
TOKEN="YOUR_JWT_TOKEN_HERE"

# Step 2: Upload audio and parse
if [ -z "$1" ]; then
  echo -e "${RED}Error: Please provide audio file path${NC}"
  echo "Usage: ./voice-test.sh <audio-file.m4a>"
  exit 1
fi

AUDIO_FILE="$1"

if [ ! -f "$AUDIO_FILE" ]; then
  echo -e "${RED}Error: Audio file not found: $AUDIO_FILE${NC}"
  exit 1
fi

echo -e "${BLUE}[2/2] Uploading audio: $AUDIO_FILE${NC}"

curl -X POST "${WORKER_URL}/v1/voice/parse" \
  -H "Authorization: Bearer ${TOKEN}" \
  -F "audio=@${AUDIO_FILE}" \
  -F "timezone=America/Los_Angeles" \
  -F "now_ts=$(date +%s)000" \
  -F "context={\"source\":\"test-script\",\"version\":\"1.0\"}" \
  | jq '.' || cat

echo -e "\n${GREEN}Done!${NC}"
