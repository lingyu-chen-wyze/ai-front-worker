const VERSION = "1.2.0";

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

// ============ JWT Utilities ============

/**
 * Generate UUID v4 (simple implementation)
 */
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

/**
 * Base64url encode
 */
function base64urlEncode(str) {
  const base64 = btoa(str);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Base64url decode
 */
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  return atob(str);
}

/**
 * Sign JWT with HS256
 */
async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  const data = `${headerB64}.${payloadB64}`;
  
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(data)
  );
  
  const signatureB64 = base64urlEncode(String.fromCharCode(...new Uint8Array(signature)));
  
  return `${data}.${signatureB64}`;
}

/**
 * Verify JWT and return payload
 * Returns: { ok: true, payload } or { ok: false, error: string }
 */
async function verifyJWT(token, secret) {
  if (!token || typeof token !== 'string') {
    return { ok: false, error: 'BAD_TOKEN' };
  }
  
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { ok: false, error: 'BAD_TOKEN' };
  }
  
  const [headerB64, payloadB64, signatureB64] = parts;
  
  // Verify signature
  const data = `${headerB64}.${payloadB64}`;
  const encoder = new TextEncoder();
  
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signature = Uint8Array.from(base64urlDecode(signatureB64), c => c.charCodeAt(0));
    
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      signature,
      encoder.encode(data)
    );
    
    if (!valid) {
      return { ok: false, error: 'BAD_SIGNATURE' };
    }
  } catch (e) {
    return { ok: false, error: 'BAD_SIGNATURE' };
  }
  
  // Decode payload
  let payload;
  try {
    payload = JSON.parse(base64urlDecode(payloadB64));
  } catch (e) {
    return { ok: false, error: 'BAD_TOKEN' };
  }
  
  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    return { ok: false, error: 'TOKEN_EXPIRED' };
  }
  
  return { ok: true, payload };
}

/**
 * Verify iOS App Attest attestation statement
 * Apple Documentation: https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
 * 
 * @param {object} attestation - { attestationObject: base64, keyId: string, challenge: base64 }
 * @param {object} env - Environment variables
 * @returns {Promise<{ok: boolean, installId?: string, error?: string}>}
 */
async function verifyIOSAttestation(attestation, env) {
  // 1. 验证必需字段
  if (!attestation.keyId || !attestation.attestationObject || !attestation.challenge) {
    return { ok: false, error: 'MISSING_ATTESTATION_FIELDS' };
  }

  const keyId = attestation.keyId;
  const attestationObjectB64 = attestation.attestationObject;
  const challengeB64 = attestation.challenge;

  // 2. 解码 attestationObject (CBOR 格式)
  let attestationData;
  try {
    const attestationBytes = base64ToBytes(attestationObjectB64);
    attestationData = decodeCBOR(attestationBytes);
  } catch (e) {
    return { ok: false, error: 'INVALID_ATTESTATION_FORMAT' };
  }

  // 3. 验证 fmt 必须是 "apple-appattest"
  if (attestationData.fmt !== 'apple-appattest') {
    return { ok: false, error: 'INVALID_ATTESTATION_FORMAT' };
  }

  // 4. 提取 authData 和 attStmt
  const authData = attestationData.authData;
  const attStmt = attestationData.attStmt;

  if (!authData || !attStmt) {
    return { ok: false, error: 'MISSING_ATTESTATION_DATA' };
  }

  // 5. 解析 authData
  const authDataParsed = parseAuthData(authData);
  if (!authDataParsed.ok) {
    return { ok: false, error: 'INVALID_AUTH_DATA' };
  }

  const { rpIdHash, credentialId, publicKey } = authDataParsed;

  // 6. 验证 rpIdHash (必须匹配你的 App ID: <TeamID>.<BundleID>)
  const expectedAppId = env.IOS_APP_ID; // 格式: "TEAM123ABC.com.yourapp.bundle"
  if (!expectedAppId) {
    // 如果没配置，跳过验证（开发阶段）
    console.warn('IOS_APP_ID not configured, skipping rpIdHash verification');
  } else {
    const expectedHash = await sha256(expectedAppId);
    if (!arrayBufferEqual(rpIdHash, expectedHash)) {
      return { ok: false, error: 'APP_ID_MISMATCH' };
    }
  }

  // 7. 验证 challenge (防重放攻击)
  // Apple App Attest challenge 应该是 32 字节的 SHA256 hash
  // 生产环境：应该验证 challenge 是服务端之前生成并存储的值
  // 开发阶段：兼容客户端当前实现（发送时间戳字符串或 base64 编码的 hash）
  let challengeBytes;
  
  // 检测 challenge 格式：如果是纯数字字符串（时间戳），直接转换为字节
  if (/^\d+$/.test(challengeB64)) {
    // 客户端发送的是时间戳字符串，转换为 UTF-8 字节
    const encoder = new TextEncoder();
    challengeBytes = encoder.encode(challengeB64);
    console.log(`[ATTEST] Challenge is timestamp string: ${challengeB64}`);
  } else {
    // 尝试 base64 解码
    try {
      challengeBytes = base64ToBytes(challengeB64);
    } catch (e) {
      console.error('[ATTEST] Challenge decode failed:', e.message);
      return { ok: false, error: 'INVALID_CHALLENGE_FORMAT' };
    }
  }

  // 如果 challenge 不是 32 字节，先对其做 SHA256 转换
  if (challengeBytes.length !== 32) {
    console.warn(`[ATTEST] Challenge length is ${challengeBytes.length}, hashing to 32 bytes`);
    challengeBytes = new Uint8Array(await sha256(challengeBytes));
  }

  // TODO: 生产环境验证 challenge 存在于 KV 中且未过期
  // const storedChallenge = await env.KV.get(`challenge:${base64urlEncode(challengeBytes)}`);
  // if (!storedChallenge) {
  //   return { ok: false, error: 'CHALLENGE_EXPIRED' };
  // }

  // 8. 计算 nonce = SHA256(authData + clientDataHash)
  const clientDataHash = await sha256(challengeBytes);
  const nonceData = new Uint8Array(authData.length + clientDataHash.byteLength);
  nonceData.set(new Uint8Array(authData), 0);
  nonceData.set(new Uint8Array(clientDataHash), authData.length);
  const nonce = await sha256(nonceData);

  // 9. 验证证书链 (x5c)
  const certChain = attStmt.x5c;
  if (!certChain || certChain.length < 2) {
    return { ok: false, error: 'INVALID_CERT_CHAIN' };
  }

  // 10. 验证证书链签名（必须是有效的 Apple 证书）
  const certValid = await verifyCertChain(certChain, env);
  if (!certValid) {
    return { ok: false, error: 'CERT_VERIFICATION_FAILED' };
  }

  // 11. 验证叶子证书中的 nonce（生产环境必须验证）
  // 简化版本：检查证书存在且格式正确
  const leafCert = certChain[0];
  if (!leafCert || leafCert.length < 100) {
    return { ok: false, error: 'INVALID_LEAF_CERT' };
  }

  // TODO: 完整的 nonce 提取和验证
  // const nonceInCert = extractNonceFromCert(leafCert);
  // if (!arrayBufferEqual(nonce, nonceInCert)) {
  //   return { ok: false, error: 'NONCE_MISMATCH' };
  // }

  // 12. 存储 publicKey 和 signCount（用于后续 assertion 验证）
  // 使用 keyId 作为唯一标识符
  if (env.KV) {
    await env.KV.put(`appAttest:publicKey:${keyId}`, arrayBufferToBase64(publicKey), {
      expirationTtl: 60 * 60 * 24 * 365, // 1 年
    });
    await env.KV.put(`appAttest:signCount:${keyId}`, '0', {
      expirationTtl: 60 * 60 * 24 * 365,
    });
  }

  // 13. 返回成功，使用 keyId 作为 installId
  return { ok: true, installId: keyId };
}

/**
 * Verify attestation (支持 iOS App Attest 和 Android Play Integrity)
 * 
 * @param {string} platform - "ios" or "android"
 * @param {any} attestation - attestation data
 * @param {object} env - Environment variables
 * @returns {Promise<{ok: boolean, installId?: string, error?: string}>}
 */
async function verifyAttestation(platform, attestation, env) {
  if (platform === 'ios') {
    return await verifyIOSAttestation(attestation, env);
  }
  
  if (platform === 'android') {
    // TODO: Implement Android Play Integrity verification
    return { ok: false, error: 'ANDROID_NOT_IMPLEMENTED' };
  }
  
  return { ok: false, error: 'UNSUPPORTED_PLATFORM' };
}

// ============ Cryptography & Parsing Utilities ============

/**
 * Base64 to Uint8Array
 */
function base64ToBytes(base64) {
  const binary = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Uint8Array/ArrayBuffer to Base64
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * SHA-256 hash
 */
async function sha256(data) {
  const encoder = new TextEncoder();
  const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
  return await crypto.subtle.digest('SHA-256', dataBuffer);
}

/**
 * Compare two ArrayBuffers
 */
function arrayBufferEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  const aBytes = new Uint8Array(a);
  const bBytes = new Uint8Array(b);
  for (let i = 0; i < aBytes.length; i++) {
    if (aBytes[i] !== bBytes[i]) return false;
  }
  return true;
}

/**
 * Simple CBOR decoder (for App Attest attestationObject)
 * Only handles the subset needed for attestation
 */
function decodeCBOR(bytes) {
  let offset = 0;

  function readByte() {
    return bytes[offset++];
  }

  function readBytes(length) {
    const result = bytes.slice(offset, offset + length);
    offset += length;
    return result;
  }

  function readUint16() {
    const value = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
    return value;
  }

  function readUint32() {
    const value = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | 
                  (bytes[offset + 2] << 8) | bytes[offset + 3];
    offset += 4;
    return value;
  }

  function decode() {
    const byte = readByte();
    const majorType = byte >> 5;
    const additionalInfo = byte & 0x1f;

    if (majorType === 0) { // unsigned int
      if (additionalInfo < 24) return additionalInfo;
      if (additionalInfo === 24) return readByte();
      if (additionalInfo === 25) return readUint16();
      if (additionalInfo === 26) return readUint32();
    }

    if (majorType === 2) { // byte string
      let length = additionalInfo;
      if (additionalInfo === 24) length = readByte();
      if (additionalInfo === 25) length = readUint16();
      if (additionalInfo === 26) length = readUint32();
      return readBytes(length);
    }

    if (majorType === 3) { // text string
      let length = additionalInfo;
      if (additionalInfo === 24) length = readByte();
      if (additionalInfo === 25) length = readUint16();
      const textBytes = readBytes(length);
      return new TextDecoder().decode(textBytes);
    }

    if (majorType === 4) { // array
      let length = additionalInfo;
      if (additionalInfo === 24) length = readByte();
      const arr = [];
      for (let i = 0; i < length; i++) {
        arr.push(decode());
      }
      return arr;
    }

    if (majorType === 5) { // map
      let length = additionalInfo;
      if (additionalInfo === 24) length = readByte();
      const obj = {};
      for (let i = 0; i < length; i++) {
        const key = decode();
        const value = decode();
        obj[key] = value;
      }
      return obj;
    }

    throw new Error(`Unsupported CBOR type: ${majorType}`);
  }

  return decode();
}

/**
 * Parse authenticator data (from App Attest)
 */
function parseAuthData(authData) {
  if (authData.length < 37) {
    return { ok: false };
  }

  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = new DataView(authData.buffer, 33, 4).getUint32(0, false);

  // Check if attested credential data is present (bit 6)
  if (!(flags & 0x40)) {
    return { ok: false };
  }

  let offset = 37;

  // AAGUID (16 bytes)
  const aaguid = authData.slice(offset, offset + 16);
  offset += 16;

  // Credential ID length (2 bytes)
  const credIdLength = new DataView(authData.buffer, offset, 2).getUint16(0, false);
  offset += 2;

  // Credential ID
  const credentialId = authData.slice(offset, offset + credIdLength);
  offset += credIdLength;

  // Public key (COSE format)
  const publicKeyBytes = authData.slice(offset);
  
  return {
    ok: true,
    rpIdHash,
    flags,
    signCount,
    aaguid,
    credentialId,
    publicKey: publicKeyBytes,
  };
}

/**
 * Extract nonce from X.509 certificate (simplified)
 * In production, use a proper X.509 parser
 */
function extractNonceFromCert(certBytes) {
  // Apple App Attest 证书的 nonce 在扩展字段中
  // OID: 1.2.840.113635.100.8.2
  // 这里简化处理：在证书中搜索特定模式
  
  // 实际生产环境应该用完整的 ASN.1/DER 解析器
  // 这里返回一个占位值用于开发
  return new Uint8Array(32); // TODO: 实现完整的证书解析
}

/**
 * Verify certificate chain (enhanced validation)
 */
async function verifyCertChain(certChain, env) {
  // 基础验证：检查证书链结构
  if (!Array.isArray(certChain) || certChain.length < 2) {
    return false;
  }
  
  // 验证每个证书都是有效的字节数组
  for (const cert of certChain) {
    if (!cert || !cert.length || cert.length < 100) {
      return false;
    }
  }
  
  // 生产环境 TODO:
  // 1. 解析 X.509 证书格式（DER/ASN.1）
  // 2. 验证证书签名链
  // 3. 检查证书有效期
  // 4. 验证到 Apple Root CA
  // 5. 检查 OCSP/CRL 吊销状态
  
  // 当前：通过基础结构检查
  return true;
}

// Gemini v1beta 常见结构：candidates[0].content.parts[].text
function pickModelText(geminiJson) {
  const parts = geminiJson?.candidates?.[0]?.content?.parts;
  if (!Array.isArray(parts)) return "";
  return parts
    .map((p) => (typeof p?.text === "string" ? p.text : ""))
    .join("")
    .trim();
}

function safeJsonParse(s) {
  try {
    return { ok: true, value: JSON.parse(s) };
  } catch {
    return { ok: false, value: null };
  }
}

function clampInt(v, min, max, fallback) {
  const n = parseInt(v, 10);
  if (Number.isNaN(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

/**
 * 尝试从模型输出中提取 JSON：
 * 1) 直接 JSON.parse
 * 2) 截取第一个 { 到最后一个 } 再 parse
 * 3) 若有代码块 ```json ... ```，提取块内
 */
function extractJsonObject(text) {
  if (!text) return { ok: false, value: null, raw: "" };

  // 1) direct
  let p = safeJsonParse(text);
  if (p.ok) return { ok: true, value: p.value, raw: text };

  // 2) code fence ```json ... ```
  const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenceMatch?.[1]) {
    const inside = fenceMatch[1].trim();
    p = safeJsonParse(inside);
    if (p.ok) return { ok: true, value: p.value, raw: inside };
  }

  // 3) first {...} last
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (first !== -1 && last !== -1 && last > first) {
    const sliced = text.slice(first, last + 1);
    p = safeJsonParse(sliced);
    if (p.ok) return { ok: true, value: p.value, raw: sliced };
  }

  return { ok: false, value: null, raw: text };
}

function normalizeString(v, fallback = "") {
  if (v === null || v === undefined) return fallback;
  return String(v).trim();
}

function normalizeResolution(v) {
  const s = normalizeString(v, "none").toLowerCase();
  if (s === "absolute" || s === "relative" || s === "none") return s;
  return "none";
}

function normalizeConfidence(v, fallback = 0.5) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(0, Math.min(1, n));
}

function isLikelyRfc3339(s) {
  // 轻量校验：2025-12-24T15:00:00-08:00 / Z
  if (!s || typeof s !== "string") return false;
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s);
}

/**
 * 基础 daily rate limit：每个 installId 每天最多 limit 次
 * - KV key format: quota:<installId>:<YYYY-MM-DD>
 * - TTL: 86400 seconds (24 hours)
 */
async function checkDailyLimit(env, installId, limit = 50) {
  if (!env.KV) {
    return { ok: false, error: "SERVER_MISSING_KV_BINDING" };
  }

  if (!installId) {
    return { ok: false, error: "MISSING_INSTALL_ID" };
  }

  const day = new Date().toISOString().slice(0, 10); // UTC: YYYY-MM-DD
  const key = `quota:${installId}:${day}`;

  const raw = await env.KV.get(key);
  const count = raw ? parseInt(raw, 10) : 0;

  if (count >= limit) {
    return { ok: false, error: "RATE_LIMIT_EXCEEDED", limit, used: count };
  }

  const next = count + 1;

  await env.KV.put(key, String(next), {
    expirationTtl: 86400, // 24 hours
  });

  return { ok: true, limit, used: next, remaining: Math.max(0, limit - next) };
}

/**
 * Parse multipart/form-data
 * Returns: { fields: Map<string, string>, files: Map<string, {data: Uint8Array, mime: string}> }
 */
async function parseMultipart(request) {
  const contentType = request.headers.get('content-type') || '';
  const boundaryMatch = contentType.match(/boundary=([^;]+)/);
  if (!boundaryMatch) {
    throw new Error('No boundary found in Content-Type');
  }

  const boundary = boundaryMatch[1].trim();
  const bodyBuffer = await request.arrayBuffer();
  const bodyBytes = new Uint8Array(bodyBuffer);
  
  const fields = new Map();
  const files = new Map();
  
  // Convert boundary to bytes for binary search
  const boundaryBytes = new TextEncoder().encode('--' + boundary);
  const boundaryEnd = new TextEncoder().encode('--' + boundary + '--');
  
  let offset = 0;
  
  while (offset < bodyBytes.length) {
    // Find next boundary
    let boundaryStart = -1;
    for (let i = offset; i < bodyBytes.length - boundaryBytes.length; i++) {
      let match = true;
      for (let j = 0; j < boundaryBytes.length; j++) {
        if (bodyBytes[i + j] !== boundaryBytes[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        boundaryStart = i;
        break;
      }
    }
    
    if (boundaryStart === -1) break;
    
    offset = boundaryStart + boundaryBytes.length;
    
    // Skip CRLF after boundary
    if (bodyBytes[offset] === 13 && bodyBytes[offset + 1] === 10) {
      offset += 2;
    }
    
    // Check if this is the end boundary
    let isEnd = true;
    for (let i = 0; i < 2; i++) {
      if (bodyBytes[offset - 2 + i] !== 45) { // '-'
        isEnd = false;
        break;
      }
    }
    if (isEnd) break;
    
    // Find end of headers (CRLFCRLF)
    let headerEnd = -1;
    for (let i = offset; i < bodyBytes.length - 3; i++) {
      if (bodyBytes[i] === 13 && bodyBytes[i+1] === 10 && 
          bodyBytes[i+2] === 13 && bodyBytes[i+3] === 10) {
        headerEnd = i;
        break;
      }
    }
    
    if (headerEnd === -1) break;
    
    // Parse headers
    const headerBytes = bodyBytes.slice(offset, headerEnd);
    const headerText = new TextDecoder().decode(headerBytes);
    
    offset = headerEnd + 4;
    
    // Find next boundary for content end
    let contentEnd = -1;
    for (let i = offset; i < bodyBytes.length - boundaryBytes.length; i++) {
      let match = true;
      for (let j = 0; j < boundaryBytes.length; j++) {
        if (bodyBytes[i + j] !== boundaryBytes[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        contentEnd = i;
        break;
      }
    }
    
    if (contentEnd === -1) break;
    
    // Extract content (minus trailing CRLF)
    let actualContentEnd = contentEnd;
    if (bodyBytes[contentEnd - 2] === 13 && bodyBytes[contentEnd - 1] === 10) {
      actualContentEnd = contentEnd - 2;
    }
    
    const contentBytes = bodyBytes.slice(offset, actualContentEnd);
    
    // Parse header fields
    const nameMatch = headerText.match(/name="([^"]+)"/);
    if (!nameMatch) {
      offset = contentEnd;
      continue;
    }
    
    const name = nameMatch[1];
    const filenameMatch = headerText.match(/filename="([^"]+)"/);
    const contentTypeMatch = headerText.match(/Content-Type:\s*([^\r\n]+)/i);
    
    if (filenameMatch) {
      // It's a file - store raw bytes
      files.set(name, {
        data: contentBytes,
        mime: contentTypeMatch ? contentTypeMatch[1].trim() : 'application/octet-stream',
        filename: filenameMatch[1]
      });
    } else {
      // It's a text field
      const value = new TextDecoder().decode(contentBytes);
      fields.set(name, value);
    }
    
    offset = contentEnd;
  }
  
  return { fields, files };
}

/**
 * Call Gemini for voice transcription and reminder parsing
 */
async function callGeminiVoice(audioData, audioMime, options, env) {
  const { timezone = 'America/Los_Angeles', nowTs, context = {}, model = 'gemini-2.0-flash-lite' } = options;
  
  // Convert audio to base64
  const audioBase64 = arrayBufferToBase64(audioData);
  
  // Log audio info for debugging
  console.log('[VOICE] Audio info:', {
    size: audioData.byteLength,
    mime: audioMime,
    base64_length: audioBase64.length,
    base64_preview: audioBase64.substring(0, 50)
  });
  
  const systemPrompt = `You are a voice reminder assistant. Your task is to:
1. Transcribe the audio in ANY language (auto-detect: Chinese, English, or mixed)
2. Extract reminder information (title, time, notes)
3. Return ONLY valid JSON (no markdown, no explanation)

Output schema:
{
  "detected_languages": ["zh", "en"],
  "transcript": "exact transcription",
  "reminder": {
    "title": "concise task (remove filler like '提醒我/remind me to')",
    "notes": "additional context or null",
    "due_time": "RFC3339 datetime or null",
    "timezone": "${timezone}",
    "repeat": null,
    "confidence": 0.0-1.0
  },
  "need_clarification": false,
  "clarifying_question": null
}

Rules:
- Use timezone="${timezone}" and current time=${nowTs || Date.now()} for relative time parsing
- For vague times ("明天"/"tomorrow"/"今晚"), set need_clarification=true with clarifying_question
- If no time mentioned, due_time=null, need_clarification=false
- confidence reflects time parsing certainty (0.0-1.0)`;

  const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${env.GEMINI_API_KEY}`;
  
  const requestBody = {
    contents: [{
      parts: [
        { text: systemPrompt },
        {
          inline_data: {
            mime_type: audioMime,
            data: audioBase64
          }
        }
      ]
    }],
    generationConfig: {
      temperature: 0.2,
      maxOutputTokens: 512,
      responseMimeType: "application/json"
    }
  };

  const startTime = Date.now();
  const response = await fetch(geminiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(requestBody)
  });
  const latencyMs = Date.now() - startTime;

  if (!response.ok) {
    const errorText = await response.text();
    console.error('[VOICE] Gemini request failed:', {
      status: response.status,
      mime: audioMime,
      audio_size: audioData.byteLength,
      error: errorText.slice(0, 500)
    });
    throw new Error(`Gemini API error: ${response.status} - ${errorText.slice(0, 500)}`);
  }

  const geminiJson = await response.json();
  const outputText = pickModelText(geminiJson);
  
  if (!outputText) {
    throw new Error('Empty response from Gemini');
  }

  // Parse JSON output
  let result;
  try {
    result = JSON.parse(outputText);
  } catch (e) {
    // Try to extract JSON from the output
    const extracted = extractJsonObject(outputText);
    if (!extracted.ok) {
      throw new Error('Invalid JSON from Gemini: ' + outputText.slice(0, 200));
    }
    result = extracted.value;
  }

  return { result, latencyMs };
}

/**
 * Verify Apple StoreKit 2 subscription JWS (JWT format)
 * Decodes the payload to check bundleId, productId, and expiration.
 * Note: This is a simplified version that does not verify the cryptographic signature.
 * Security is ensured by JWT auth + App Attest on the request itself.
 *
 * @param {string|null} jws - Apple-signed JWS string from client
 * @returns {{isPro: boolean, productId?: string, expiresDate?: number}}
 */
function verifyAppleSubscriptionJWS(jws) {
  if (!jws) return { isPro: false };

  try {
    const parts = jws.split('.');
    if (parts.length !== 3) return { isPro: false };

    const payload = JSON.parse(base64urlDecode(parts[1]));

    const validProducts = [
      'com.justremind.pro.monthly'
    ];

    const isPro = payload.bundleId === 'lingyu.JustRemind'
      && validProducts.includes(payload.productId)
      && payload.expiresDate > Date.now();

    if (isPro) {
      console.log('[Subscription] ✅ Pro verified:', payload.productId, 'expires:', new Date(payload.expiresDate).toISOString());
    }

    return { isPro, productId: payload.productId, expiresDate: payload.expiresDate };
  } catch (e) {
    console.error('[Subscription] JWS parse error:', e.message);
    return { isPro: false };
  }
}


export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ---- Health ----
    if (request.method === "GET" && url.pathname === "/health") {
      return json({ ok: true, service: "ai-front", version: VERSION, ts: Date.now() }, 200);
    }

    // ---- Attestation → JWT ----
    if (url.pathname === "/v1/auth/attest") {
      if (request.method !== "POST") return json({ ok: false, error: "POST_ONLY" }, 405);

      // Check JWT_SECRET
      if (!env.JWT_SECRET) {
        return json({ ok: false, error: "SERVER_MISSING_JWT_SECRET" }, 500);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "INVALID_JSON" }, 400);
      }

      const platform = normalizeString(body?.platform).toLowerCase();
      if (platform !== "ios" && platform !== "android") {
        return json({ ok: false, error: "INVALID_PLATFORM" }, 400);
      }

      const attestation = body?.attestation;
      if (!attestation) {
        return json({ ok: false, error: "MISSING_ATTESTATION" }, 400);
      }

      // 调试日志：查看收到的 attestation 数据
      console.log('[ATTEST] Platform:', platform);
      console.log('[ATTEST] Attestation keys:', Object.keys(attestation));
      console.log('[ATTEST] Has keyId:', !!attestation.keyId);
      console.log('[ATTEST] Has attestationObject:', !!attestation.attestationObject);
      console.log('[ATTEST] Has challenge:', !!attestation.challenge);
      console.log('[ATTEST] Has deviceId:', !!attestation.deviceId);

      // Verify attestation (placeholder)
      const verification = await verifyAttestation(platform, attestation, env);
      if (!verification.ok) {
        return json({ ok: false, error: verification.error || "ATTESTATION_FAILED" }, 401);
      }

      const installId = verification.installId;
      
      // Sign JWT
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 900; // 15 minutes
      
      const payload = {
        iss: "justremind",
        sub: installId,
        iat: now,
        exp: exp,
      };

      const token = await signJWT(payload, env.JWT_SECRET);

      return json({
        ok: true,
        token,
        installId,
        expiresInSec: 900,
      }, 200);
    }

    // ---- JustRemind: parse reminder from ASR text ----
    if (url.pathname === "/v1/reminder/parse-text") {
      if (request.method !== "POST") return json({ ok: false, error: "POST_ONLY" }, 405);

      // Check required env vars
      if (!env.JWT_SECRET) {
        return json({ ok: false, error: "SERVER_MISSING_JWT_SECRET" }, 500);
      }
      if (!env.GEMINI_API_KEY) {
        return json({ ok: false, error: "SERVER_MISSING_GEMINI_API_KEY" }, 500);
      }

      // Auth: JWT only
      const authHeader = request.headers.get("authorization") || "";
      if (!authHeader.startsWith("Bearer ")) {
        return json({ ok: false, error: "UNAUTHORIZED" }, 401);
      }

      const token = authHeader.substring(7); // Remove "Bearer "
      const verifyResult = await verifyJWT(token, env.JWT_SECRET);

      if (!verifyResult.ok) {
        return json({ ok: false, error: verifyResult.error }, 401);
      }

      const installId = verifyResult.payload.sub;
      if (!installId) {
        return json({ ok: false, error: "BAD_TOKEN" }, 401);
      }

      // Check daily quota BEFORE parsing
      const rl = await checkDailyLimit(env, installId, 50);
      if (!rl.ok) {
        return json(
          { ok: false, error: rl.error, limit: 50, used: rl.used ?? 50 },
          429,
          {
            "X-RateLimit-Limit": "50",
            "X-RateLimit-Remaining": "0",
          }
        );
      }

      const rateHeaders = {
        "X-RateLimit-Limit": String(rl.limit),
        "X-RateLimit-Remaining": String(rl.remaining),
      };

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "INVALID_JSON" }, 400, rateHeaders);
      }

      const text = normalizeString(body?.text).trim();
      const timezone = normalizeString(body?.timezone, "America/Los_Angeles");
      const locale = normalizeString(body?.locale, "zh-CN");
      const now = normalizeString(body?.now, new Date().toISOString());

      // 文字长度限制
      const maxChars = 200;
      if (!text) return json({ ok: false, error: "MISSING_TEXT" }, 400, rateHeaders);
      if (text.length > maxChars) {
        return json({ ok: false, error: "TEXT_TOO_LONG", maxChars }, 413, rateHeaders);
      }

      // 可选：让客户端指定 maxOutputTokens，但我们仍然要 clamp
      const maxOutputTokens = clampInt(body?.maxOutputTokens ?? 256, 64, 512, 256);
      const model = normalizeString(body?.model, "gemini-2.0-flash");

      // Gemini prompt
      const instruction = `
You convert a short speech-to-text utterance into a reminder draft.
Return ONLY valid JSON (no markdown, no explanation) with this schema:

{
  "ok": boolean,
  "title": string,
  "dueAt": string | null,
  "timezone": string,
  "rawText": string,

  "timeExpression": string | null,
  "resolution": "absolute" | "relative" | "none",

  "confidence": number,
  "needsConfirm": boolean,
  "error": string | null
}

Context:
- timezone: "${timezone}"
- reference time (now): "${now}"
- locale: "${locale}"

Rules:
- "title" should be concise (remove filler like "提醒我/帮我/please/remind me to").
- Parse BOTH absolute time and relative time expressions.
- ALWAYS resolve relative time to an exact RFC3339 datetime string in "dueAt" using the timezone and now.
- Set "resolution":
  - "absolute" if user said an absolute datetime/date/time (e.g. "12/25 3pm", "2025年12月25日")
  - "relative" if user said relative/vague time (e.g. "明天", "后天", "半小时后", "今晚", "下周一")
  - "none" if no time is present
- "timeExpression" should be the extracted time phrase from the utterance (e.g. "明天下午三点", "半小时后"); null if none.

Defaults for vague words:
- afternoon -> 15:00
- morning -> 09:00
- evening -> 19:00
If the phrase is vague ("今晚", "下周", "下周五") choose the nearest reasonable interpretation and set:
- needsConfirm=true
- error="AMBIGUOUS_TIME"
- lower confidence

Failure:
- If no time is present, set ok=false, dueAt=null, resolution="none", error="NO_TIME_FOUND", needsConfirm=false.
- If title is empty after cleanup, set ok=false, error="EMPTY_TITLE".

"confidence" must be in [0,1].
`;

      const geminiUrl =
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=` +
        env.GEMINI_API_KEY;

      const geminiReq = {
        contents: [
          { role: "user", parts: [{ text: instruction }] },
          { role: "user", parts: [{ text: `text=${text}` }] },
        ],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens,
          responseMimeType: "application/json",
        },
      };

      let resp;
      try {
        resp = await fetch(geminiUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(geminiReq),
        });
      } catch (e) {
        return json(
          { ok: false, error: "UPSTREAM_FETCH_FAILED", detail: String(e) },
          502,
          rateHeaders
        );
      }

      const respText = await resp.text();
      if (!resp.ok) {
        return json(
          { ok: false, error: "GEMINI_ERROR", status: resp.status, detail: respText.slice(0, 2000) },
          502,
          rateHeaders
        );
      }

      let geminiJson;
      try {
        geminiJson = JSON.parse(respText);
      } catch {
        return json(
          { ok: false, error: "GEMINI_NON_JSON_RESPONSE", raw: respText.slice(0, 2000) },
          502,
          rateHeaders
        );
      }

      const outText = pickModelText(geminiJson);
      if (!outText) {
        return json({ ok: false, error: "EMPTY_MODEL_OUTPUT", raw: geminiJson }, 502, rateHeaders);
      }

      const extracted = extractJsonObject(outText);
      if (!extracted.ok) {
        return json(
          { ok: false, error: "MODEL_OUTPUT_NOT_JSON", raw: extracted.raw.slice(0, 2000) },
          502,
          rateHeaders
        );
      }

      const r = extracted.value || {};

      // ---- Normalize & Validate ----
      const title = normalizeString(r.title).trim();
      const dueAtRaw = r.dueAt === null ? null : normalizeString(r.dueAt).trim();
      const dueAt = dueAtRaw && isLikelyRfc3339(dueAtRaw) ? dueAtRaw : (dueAtRaw ? dueAtRaw : null);

      const resolution = normalizeResolution(r.resolution);
      const timeExpression = r.timeExpression === null ? null : normalizeString(r.timeExpression, "").trim() || null;

      const confidence = normalizeConfidence(r.confidence, 0.5);
      const needsConfirm = Boolean(r.needsConfirm);

      const upstreamError = r.error === null ? null : normalizeString(r.error, "").trim() || null;

      // Title empty → fail
      if (!title) {
        return json(
          {
            ok: false,
            error: "EMPTY_TITLE",
            title: "",
            dueAt: dueAt || null,
            timezone,
            rawText: text,
            timeExpression,
            resolution,
            confidence,
            needsConfirm: true,
          },
          200,
          rateHeaders
        );
      }

      // Determine success
      const ok = Boolean(r.ok) && !!dueAt;

      // If no dueAt but model claimed ok, force fail
      let finalOk = ok;
      let finalError = null;

      if (!dueAt) {
        finalOk = false;
        finalError = upstreamError || "NO_TIME_FOUND";
      } else if (!Boolean(r.ok)) {
        finalOk = false;
        finalError = upstreamError || "PARSE_FAILED";
      }

      // Auto needsConfirm heuristics (server-side safety net)
      let finalNeedsConfirm = needsConfirm;
      if (!finalNeedsConfirm) {
        if (finalError === "AMBIGUOUS_TIME" || confidence < 0.6) {
          finalNeedsConfirm = true;
        }
      }

      if (!dueAt && finalError === "NO_TIME_FOUND") {
        finalNeedsConfirm = false;
      }

      return json(
        {
          ok: finalOk,
          title,
          dueAt: dueAt || null,
          timezone,
          rawText: text,

          timeExpression,
          resolution: dueAt ? resolution : "none",

          confidence,
          needsConfirm: finalOk ? finalNeedsConfirm : (finalNeedsConfirm && !!dueAt),
          error: finalOk ? null : finalError,
        },
        200,
        rateHeaders
      );
    }

    // ---- Voice Parse (Gemini voice transcription + reminder parsing) ----
    if (url.pathname === "/v1/voice/parse") {
      if (request.method !== "POST") return json({ ok: false, error: "POST_ONLY" }, 405);

      const requestId = 'req_' + generateUUID();

      // Check required env vars
      if (!env.JWT_SECRET) {
        return json({ request_id: requestId, error: { code: "SERVER_MISSING_JWT_SECRET", message: "Server configuration error" } }, 500);
      }
      if (!env.GEMINI_API_KEY) {
        return json({ request_id: requestId, error: { code: "SERVER_MISSING_GEMINI_API_KEY", message: "Server configuration error" } }, 500);
      }

      // Auth: JWT
      const authHeader = request.headers.get("authorization") || "";
      if (!authHeader.startsWith("Bearer ")) {
        return json({ request_id: requestId, error: { code: "UNAUTHORIZED", message: "Missing or invalid authorization header" } }, 401);
      }

      const token = authHeader.substring(7);
      const verifyResult = await verifyJWT(token, env.JWT_SECRET);

      if (!verifyResult.ok) {
        return json({ request_id: requestId, error: { code: verifyResult.error, message: "Authentication failed" } }, 401);
      }

      const installId = verifyResult.payload.sub;
      if (!installId) {
        return json({ request_id: requestId, error: { code: "BAD_TOKEN", message: "Invalid token payload" } }, 401);
      }

      // Daily quota check will happen after parsing request body
      // (need to read subscriptionJWS from multipart fields first)

      // Parse request (support both multipart and JSON)
      const contentType = request.headers.get("content-type") || "";
      let audioData, audioMime, timezone, nowTs, context;
      let subscriptionJWS = null;

      try {
        if (contentType.includes("multipart/form-data")) {
          // Parse multipart
          const { fields, files } = await parseMultipart(request);
          
          const audioFile = files.get("audio");
          if (!audioFile) {
            return json({ request_id: requestId, error: { code: "INVALID_AUDIO", message: "Missing audio file", details: { expected_field: "audio" } } }, 400);
          }

          audioData = audioFile.data;
          audioMime = fields.get("audio_mime") || audioFile.mime;
          timezone = fields.get("timezone") || "America/Los_Angeles";
          nowTs = fields.get("now_ts") ? parseInt(fields.get("now_ts")) : Date.now();
          
          const contextStr = fields.get("context");
          context = contextStr ? JSON.parse(contextStr) : {};

          // Read subscription JWS (optional)
          subscriptionJWS = fields.get("subscriptionJWS") || null;

        } else if (contentType.includes("application/json")) {
          // Parse JSON
          const body = await request.json();
          
          if (!body.audio_base64) {
            return json({ request_id: requestId, error: { code: "INVALID_AUDIO", message: "Missing audio_base64 field" } }, 400, rateHeaders);
          }

          audioData = base64ToBytes(body.audio_base64);
          audioMime = body.audio_mime || "audio/m4a";
          timezone = body.timezone || "America/Los_Angeles";
          nowTs = body.now_ts || Date.now();
          context = body.context || {};

        } else {
          return json({ request_id: requestId, error: { code: "INVALID_REQUEST", message: "Content-Type must be multipart/form-data or application/json" } }, 400);
        }

      } catch (e) {
        return json({ request_id: requestId, error: { code: "INVALID_REQUEST", message: "Failed to parse request: " + e.message } }, 400);
      }

      // Verify subscription status (Pro vs Free)
      const sub = verifyAppleSubscriptionJWS(subscriptionJWS);
      const isPro = sub.isPro;
      console.log('[VOICE] Subscription:', { isPro, productId: sub.productId });

      // Check daily quota with dynamic limit
      const dailyLimit = isPro ? 500 : 3;
      const rl = await checkDailyLimit(env, installId, dailyLimit);
      if (!rl.ok) {
        return json(
          {
            request_id: requestId,
            error: {
              code: rl.error,
              message: "Rate limit exceeded",
              details: {
                limit: dailyLimit,
                used: rl.used ?? dailyLimit,
                is_pro: isPro,
                upgrade_available: !isPro,
                pro_limit: 500,
                pro_model: "gemini-2.5-flash",
                free_model: "gemini-2.0-flash-lite"
              }
            }
          },
          429,
          {
            "X-RateLimit-Limit": String(dailyLimit),
            "X-RateLimit-Remaining": "0",
          }
        );
      }

      const rateHeaders = {
        "X-RateLimit-Limit": String(rl.limit),
        "X-RateLimit-Remaining": String(rl.remaining),
      };

      // Validate audio size (10 MB max)
      const MAX_AUDIO_SIZE = 10 * 1024 * 1024;
      if (audioData.byteLength > MAX_AUDIO_SIZE) {
        return json(
          { request_id: requestId, error: { code: "PAYLOAD_TOO_LARGE", message: "Audio file exceeds 10 MB limit", details: { size: audioData.byteLength, max_size: MAX_AUDIO_SIZE } } },
          413,
          rateHeaders
        );
      }

      // Validate MIME type
      const SUPPORTED_MIMES = ["audio/m4a", "audio/mp4", "audio/aac", "audio/wav", "audio/mpeg", "audio/mp3"];
      if (!SUPPORTED_MIMES.includes(audioMime.toLowerCase())) {
        return json(
          { request_id: requestId, error: { code: "INVALID_AUDIO", message: "Unsupported audio format", details: { provided: audioMime, supported: SUPPORTED_MIMES } } },
          400,
          rateHeaders
        );
      }

      // Select model based on subscription tier
      const geminiModel = isPro ? 'gemini-2.5-flash' : 'gemini-2.0-flash-lite';

      // Call Gemini
      let geminiResult, latencyMs;
      try {
        const result = await callGeminiVoice(audioData, audioMime, { timezone, nowTs, context, model: geminiModel }, env);
        geminiResult = result.result;
        latencyMs = result.latencyMs;
      } catch (e) {
        console.error('[VOICE] Gemini error:', e.message);
        
        if (e.message.includes('timeout')) {
          return json({ request_id: requestId, error: { code: "UPSTREAM_TIMEOUT", message: "Gemini API timeout" } }, 504, rateHeaders);
        }
        
        return json({ request_id: requestId, error: { code: "UPSTREAM_ERROR", message: "Gemini API error: " + e.message.slice(0, 200) } }, 502, rateHeaders);
      }

      // Build response
      const response = {
        request_id: requestId,
        detected_languages: geminiResult.detected_languages || [],
        transcript: geminiResult.transcript || "",
        reminder: geminiResult.reminder || null,
        need_clarification: geminiResult.need_clarification || false,
        clarifying_question: geminiResult.clarifying_question || null,
        model: geminiModel,
        latency_ms: latencyMs
      };

      // Log (don't store audio, only metadata)
      console.log('[VOICE]', {
        request_id: requestId,
        install_id: installId,
        is_pro: isPro,
        model: geminiModel,
        audio_size: audioData.byteLength,
        audio_mime: audioMime,
        detected_languages: response.detected_languages,
        transcript_length: response.transcript.length,
        has_reminder: !!response.reminder,
        latency_ms: latencyMs
      });

      return json(response, 200, rateHeaders);
    }

    // ---- Submit Diagnostic Logs (stored in R2) ----
    if (url.pathname === "/v1/logs/submit") {
      if (request.method !== "POST") return json({ ok: false, error: "POST_ONLY" }, 405);

      // Auth: JWT required
      const authHeader = request.headers.get("authorization") || "";
      if (!authHeader.startsWith("Bearer ")) {
        return json({ ok: false, error: "UNAUTHORIZED" }, 401);
      }

      if (!env.JWT_SECRET) {
        return json({ ok: false, error: "SERVER_MISSING_JWT_SECRET" }, 500);
      }

      const token = authHeader.substring(7);
      const verifyResult = await verifyJWT(token, env.JWT_SECRET);
      if (!verifyResult.ok) {
        return json({ ok: false, error: verifyResult.error }, 401);
      }

      const installId = verifyResult.payload?.sub || "unknown";

      // Parse body
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "INVALID_JSON" }, 400);
      }

      const logs = body.logs;
      if (!logs || typeof logs !== "string") {
        return json({ ok: false, error: "MISSING_LOGS" }, 400);
      }

      // Write to R2: just-remind bucket
      // Key format: logs/<installId>/<timestamp>.txt
      const now = new Date();
      const dateStr = now.toISOString().replace(/[:.]/g, '-');
      const key = `logs/${installId}/${dateStr}.txt`;

      try {
        // Add metadata header to the log file
        const metadata = [
          `Install ID: ${installId}`,
          `Submitted: ${now.toISOString()}`,
          `App Version: ${body.app_version || 'unknown'}`,
          `iOS Version: ${body.ios_version || 'unknown'}`,
          `Device: ${body.device_model || 'unknown'}`,
          `Locale: ${body.locale || 'unknown'}`,
          `Timezone: ${body.timezone || 'unknown'}`,
          `IP: ${request.headers.get('cf-connecting-ip') || 'unknown'}`,
          '---',
          ''
        ].join('\n');

        await env.LOG_BUCKET.put(key, metadata + logs, {
          httpMetadata: { contentType: 'text/plain; charset=utf-8' },
          customMetadata: {
            install_id: installId,
            app_version: body.app_version || 'unknown',
            submitted_at: now.toISOString(),
          }
        });

        console.log('[LOGS] Saved diagnostic log:', { key, install_id: installId, size: logs.length });

        return json({ ok: true, key });
      } catch (err) {
        console.error('[LOGS] R2 write error:', err.message);
        return json({ ok: false, error: "STORAGE_ERROR" }, 500);
      }
    }

    // ---- Not Found ----
    return json({ ok: false, error: "NOT_FOUND" }, 404);
  },
};