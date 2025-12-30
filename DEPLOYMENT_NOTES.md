# Deployment Notes - JWT Authentication Migration

## Summary of Changes

This update migrates from long-term API key authentication to attestation-based JWT authentication with daily quota limits.

## Breaking Changes

### ❌ Removed
- `APP_API_KEY` environment variable (no longer used)
- Global daily rate limit (500/day across all users)
- `x-install-id` header fallback to IP address

### ✅ Added
- `JWT_SECRET` environment variable (REQUIRED)
- `/v1/auth/attest` endpoint for device attestation
- JWT-based authentication for `/v1/reminder/parse-text`
- Per-device daily quota (50/day) using JWT `installId`

## Migration Checklist

### 1. Environment Variables

```bash
# Add new required variable
wrangler secret put JWT_SECRET

# Existing (keep these)
# - GEMINI_API_KEY

# Remove from your config (no longer used)
# - APP_API_KEY
```

**JWT_SECRET Requirements:**
- Minimum 32 characters recommended
- Use strong random string
- Keep secure, never commit to git

Generate example:
```bash
openssl rand -base64 32
```

### 2. KV Namespace

Ensure your KV binding is named exactly `KV`:

```toml
# wrangler.toml
[[kv_namespaces]]
binding = "KV"
id = "your-kv-namespace-id"
```

Or in Dashboard: Settings → Variables → KV Namespace Bindings → Name: `KV`

### 3. Client App Changes

**Old Flow (deprecated):**
```javascript
fetch('/v1/reminder/parse-text', {
  headers: {
    'Authorization': 'Bearer <APP_API_KEY>'
  }
})
```

**New Flow (required):**
```javascript
// Step 1: Attest device and get JWT
const attestResponse = await fetch('/v1/auth/attest', {
  method: 'POST',
  body: JSON.stringify({
    platform: 'ios', // or 'android'
    attestation: attestationData
  })
});
const { token } = await attestResponse.json();

// Step 2: Use JWT for parse-text
fetch('/v1/reminder/parse-text', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
})
```

### 4. Token Management

- **Token Lifetime:** 15 minutes
- **No Refresh Tokens:** Re-attest when you receive `401 TOKEN_EXPIRED`
- **Storage:** Store JWT securely in app (Keychain/KeyStore)

Example error handling:
```javascript
if (response.status === 401) {
  const error = await response.json();
  if (error.error === 'TOKEN_EXPIRED') {
    // Get new token via /v1/auth/attest
    token = await getNewToken();
    // Retry original request
  }
}
```

## New Features

### Per-Device Quota Tracking

- **Limit:** 50 requests/day per device
- **Identifier:** `installId` from JWT `sub` claim
- **Reset:** Daily at 00:00 UTC
- **Headers in response:**
  - `X-RateLimit-Limit: 50`
  - `X-RateLimit-Remaining: <remaining>`

**429 Response Example:**
```json
{
  "ok": false,
  "error": "RATE_LIMIT_EXCEEDED",
  "limit": 50,
  "used": 50
}
```

### JWT Payload

```json
{
  "iss": "justremind",
  "sub": "uuid-of-device",  // installId
  "iat": 1703606400,         // issued at
  "exp": 1703607300          // expires (iat + 900)
}
```

## Error Codes Reference

### `/v1/auth/attest`

| Code | HTTP | Description |
|------|------|-------------|
| `INVALID_PLATFORM` | 400 | Platform must be "ios" or "android" |
| `MISSING_ATTESTATION` | 400 | Attestation data required |
| `ATTESTATION_FAILED` | 401 | Attestation verification failed |
| `SERVER_MISSING_JWT_SECRET` | 500 | JWT_SECRET not configured |

### `/v1/reminder/parse-text`

| Code | HTTP | Description |
|------|------|-------------|
| `UNAUTHORIZED` | 401 | Missing or invalid Bearer token |
| `BAD_TOKEN` | 401 | Malformed JWT (wrong format) |
| `BAD_SIGNATURE` | 401 | Invalid JWT signature |
| `TOKEN_EXPIRED` | 401 | JWT expired (>15 minutes) |
| `RATE_LIMIT_EXCEEDED` | 429 | Daily quota exceeded (50/day) |
| `SERVER_MISSING_JWT_SECRET` | 500 | JWT_SECRET not configured |
| `SERVER_MISSING_GEMINI_API_KEY` | 500 | GEMINI_API_KEY not configured |

## Testing

### 1. Test Health Endpoint
```bash
curl https://your-worker.dev/health
```

### 2. Test Attestation (Placeholder)
```bash
curl -X POST https://your-worker.dev/v1/auth/attest \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "ios",
    "attestation": {}
  }'
```

Expected response:
```json
{
  "ok": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "installId": "550e8400-e29b-41d4-a716-446655440000",
  "expiresInSec": 900
}
```

### 3. Test Parse with JWT
```bash
# First get token from step 2, then:
curl -X POST https://your-worker.dev/v1/reminder/parse-text \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "明天下午三点开会",
    "timezone": "Asia/Shanghai",
    "locale": "zh-CN"
  }'
```

### 4. Test Rate Limiting

Run the parse request 51 times with the same token to trigger rate limit:
```bash
for i in {1..51}; do
  echo "Request $i"
  curl -X POST https://your-worker.dev/v1/reminder/parse-text \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"text":"test","timezone":"UTC","locale":"en"}' \
    -w "\nHTTP: %{http_code}\n"
done
```

Expected: First 50 succeed (200), 51st returns 429.

## TODO: Implement Real Attestation

The current `verifyAttestation()` function is a **placeholder** that generates random UUIDs. You must implement:

### iOS App Attest

1. Client generates key and attestation
2. Send attestation object to `/v1/auth/attest`
3. Worker verifies with Apple servers
4. Validate app ID, challenge, public key

Resources:
- [Apple App Attest Documentation](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server)

### Android Play Integrity

1. Client requests integrity token
2. Send token to `/v1/auth/attest`
3. Worker verifies with Google Play servers
4. Check device/app integrity verdicts

Resources:
- [Play Integrity API Documentation](https://developer.android.com/google/play/integrity)

## Rollback Plan

If you need to rollback to the old API key auth:

1. Re-add `APP_API_KEY` environment variable
2. Restore from git: `git checkout HEAD~1 worker.js`
3. Redeploy

Note: This migration is recommended for production security. API keys should not be embedded in mobile apps.

## Support

For issues or questions:
1. Check error codes above
2. Review Cloudflare Worker logs
3. Verify environment variables are set correctly
4. Ensure KV binding name is exactly `KV`
