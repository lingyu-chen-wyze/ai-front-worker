# ai-front-worker

Cloudflare Worker for JustRemind app - handles attestation-based authentication and AI-powered reminder parsing.

## Features

- **JWT-based Authentication**: Secure token-based auth with HS256 signing
- **Device Attestation**: Placeholder for iOS App Attest & Android Play Integrity
- **Daily Quota Management**: 50 requests/day per device using Cloudflare KV
- **AI Reminder Parsing**: Gemini-powered natural language reminder extraction

## API Endpoints

### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "ok": true,
  "service": "ai-front",
  "ts": 1703606400000
}
```

### `POST /v1/auth/attest`
Verify device attestation and issue JWT token.

**Request:**
```json
{
  "platform": "ios",  // or "android"
  "attestation": { ... }  // Platform-specific attestation data
}
```

**Success Response (200):**
```json
{
  "ok": true,
  "token": "eyJhbGc...",
  "installId": "uuid-v4",
  "expiresInSec": 900
}
```

**Error Responses:**
- `400` - Invalid platform or missing attestation
- `401` - Attestation verification failed
- `500` - Missing JWT_SECRET environment variable

### `POST /v1/reminder/parse-text`
Parse natural language text into structured reminder data.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request:**
```json
{
  "text": "明天下午三点开会",
  "timezone": "Asia/Shanghai",
  "locale": "zh-CN",
  "now": "2025-12-26T10:00:00Z",
  "model": "gemini-2.0-flash",
  "maxOutputTokens": 256
}
```

**Success Response (200):**
```json
{
  "ok": true,
  "title": "开会",
  "dueAt": "2025-12-27T15:00:00+08:00",
  "timezone": "Asia/Shanghai",
  "rawText": "明天下午三点开会",
  "timeExpression": "明天下午三点",
  "resolution": "relative",
  "confidence": 0.95,
  "needsConfirm": false,
  "error": null
}
```

**Rate Limit Headers:**
```
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 42
```

**Error Responses:**
- `400` - Invalid JSON or missing text
- `401` - Invalid, expired, or missing JWT
  - `TOKEN_EXPIRED` - Token has expired (15min TTL)
  - `BAD_TOKEN` - Malformed token
  - `BAD_SIGNATURE` - Invalid signature
- `413` - Text too long (>200 chars)
- `429` - Rate limit exceeded (50/day per device)
- `500` - Missing required environment variables
- `502` - Gemini API error

## Environment Variables

Required environment variables in Cloudflare Worker settings:

| Variable | Description | Example |
|----------|-------------|---------|
| `JWT_SECRET` | Secret key for HS256 JWT signing | `your-secret-key-min-32-chars` |
| `GEMINI_API_KEY` | Google Gemini API key | `AIza...` |

**Note:** `APP_API_KEY` is NO LONGER USED (removed in this version).

## KV Namespace Binding

Configure in `wrangler.toml` or Worker settings:

```toml
[[kv_namespaces]]
binding = "KV"
id = "your-kv-namespace-id"
```

**KV Key Format:**
- Quota tracking: `quota:<installId>:<YYYY-MM-DD>`
- TTL: 86400 seconds (24 hours)

## Deployment

### Using Wrangler CLI

1. Install dependencies:
```bash
npm install -g wrangler
```

2. Login to Cloudflare:
```bash
wrangler login
```

3. Create KV namespace:
```bash
wrangler kv:namespace create "KV"
```

4. Set secrets:
```bash
wrangler secret put JWT_SECRET
wrangler secret put GEMINI_API_KEY
```

5. Deploy:
```bash
wrangler deploy
```

### Using Cloudflare Dashboard

1. Go to Workers & Pages
2. Create new Worker
3. Copy `worker.js` content
4. Add environment variables:
   - `JWT_SECRET`
   - `GEMINI_API_KEY`
5. Bind KV namespace named `KV`
6. Deploy

## Security Notes

### Attestation (TODO)

Currently `verifyAttestation()` is a placeholder that generates UUIDs. You need to implement:

**iOS (App Attest):**
- Verify attestation statement with Apple's servers
- Validate challenge and app ID
- Extract and verify key ID

**Android (Play Integrity):**
- Verify integrity token with Google Play
- Check device and app integrity signals
- Validate nonce and package name

### JWT Best Practices

- Token expires in 15 minutes
- No refresh tokens (client re-attests on expiry)
- HS256 signing (ensure `JWT_SECRET` is strong)
- Tokens are stateless (no server-side revocation)

## Rate Limiting

- **Per-device limit:** 50 requests/day (based on `installId` from JWT)
- **Key format:** `quota:<installId>:<YYYY-MM-DD>` (UTC)
- **Storage:** Cloudflare KV with 24-hour TTL
- **429 response includes:** `limit`, `used` count

**Note:** KV operations are eventually consistent. Under extreme concurrency, slight over-quota may occur.

## Client Integration

### 1. Attestation Flow

```javascript
// iOS/Android: Generate attestation
const attestation = await generateAttestation();

// Call attest endpoint
const response = await fetch('https://your-worker.dev/v1/auth/attest', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    platform: 'ios', // or 'android'
    attestation: attestation
  })
});

const { token, installId, expiresInSec } = await response.json();
// Store token securely
```

### 2. Parse Text with JWT

```javascript
const response = await fetch('https://your-worker.dev/v1/reminder/parse-text', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    text: '明天下午三点开会',
    timezone: 'Asia/Shanghai',
    locale: 'zh-CN',
    now: new Date().toISOString()
  })
});

if (response.status === 401) {
  const error = await response.json();
  if (error.error === 'TOKEN_EXPIRED') {
    // Re-attest and get new token
  }
}
```

## Development

### Local Testing

```bash
wrangler dev
```

### Test Health Endpoint

```bash
curl https://your-worker.dev/health
```

### Test Attestation (with placeholder)

```bash
curl -X POST https://your-worker.dev/v1/auth/attest \
  -H "Content-Type: application/json" \
  -d '{"platform":"ios","attestation":{}}'
```

### Test Parse (with JWT)

```bash
curl -X POST https://your-worker.dev/v1/reminder/parse-text \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "明天下午三点开会",
    "timezone": "Asia/Shanghai",
    "locale": "zh-CN"
  }'
```

## License

MIT
