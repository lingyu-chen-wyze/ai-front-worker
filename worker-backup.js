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
 * - KV 非原子自增：极端并发会有少量误差，但对“基础护栏”足够
 * - dayKey 使用 UTC 日期（YYYY-MM-DD）
 */
async function checkDailyLimit(env, installId, limit = 50) {
  if (!env.KV) {
    return { ok: false, error: "SERVER_MISSING_KV_BINDING" };
  }

  if (!installId) {
    return { ok: false, error: "MISSING_INSTALL_ID" };
  }

  const day = new Date().toISOString().slice(0, 10); // UTC: YYYY-MM-DD
  const key = `rl:${installId}:${day}`;

  const raw = await env.KV.get(key);
  const count = raw ? parseInt(raw, 10) : 0;

  if (count >= limit) {
    return { ok: false, error: "RATE_LIMIT_EXCEEDED", limit, used: count };
  }

  const next = count + 1;

  await env.KV.put(key, String(next), {
    expirationTtl: 60 * 60 * 24, // 24h（基础做法）
  });

  return { ok: true, limit, used: next, remaining: Math.max(0, limit - next) };
}

async function checkGlobalDailyLimit(env, limit = 500) {
  if (!env.KV) {
    return { ok: false, error: "SERVER_MISSING_KV_BINDING" };
  }

  const day = new Date().toISOString().slice(0, 10); // UTC day
  const key = `global:${day}`;

  const raw = await env.KV.get(key);
  const count = raw ? parseInt(raw, 10) : 0;

  if (count >= limit) {
    return { ok: false, error: "GLOBAL_RATE_LIMIT_EXCEEDED", used: count, limit };
  }

  const next = count + 1;

  await env.KV.put(key, String(next), {
    expirationTtl: 60 * 60 * 24, // 24h
  });

  return {
    ok: true,
    used: next,
    remaining: Math.max(0, limit - next),
    limit,
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ---- Health ----
    if (request.method === "GET" && url.pathname === "/health") {
      return json({ ok: true, service: "ai-front", ts: Date.now() }, 200);
    }

    // ---- JustRemind: parse reminder from ASR text ----
    if (url.pathname === "/v1/reminder/parse-text") {
      if (request.method !== "POST") return json({ ok: false, error: "POST_ONLY" }, 405);

      // Auth: Authorization: Bearer <APP_API_KEY> (Dev only)
      const auth = request.headers.get("authorization") || "";
      if (!env.APP_API_KEY) return json({ ok: false, error: "SERVER_MISSING_APP_API_KEY" }, 500);
      if (auth !== `Bearer ${env.APP_API_KEY}`) return json({ ok: false, error: "UNAUTHORIZED" }, 401);

      if (!env.GEMINI_API_KEY) return json({ ok: false, error: "SERVER_MISSING_GEMINI_API_KEY" }, 500);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "INVALID_JSON" }, 400);
      }

      const text = normalizeString(body?.text).trim();
      const timezone = normalizeString(body?.timezone, "America/Los_Angeles");
      const locale = normalizeString(body?.locale, "zh-CN");
      // 建议由客户端传 now（更稳定），不传就用服务器时间
      const now = normalizeString(body?.now, new Date().toISOString());

      // 文字长度限制（语音长度请在客户端控制 6~10 秒）
      const maxChars = 200;
      if (!text) return json({ ok: false, error: "MISSING_TEXT" }, 400);
      if (text.length > maxChars) {
        return json({ ok: false, error: "TEXT_TOO_LONG", maxChars }, 413);
      }

      // ---- Global hard limit: 500/day ----
      const global = await checkGlobalDailyLimit(env, 500);

      if (!global.ok) {
        return json(
          {
            ok: false,
            error: global.error,
            limit: global.limit,
            used: global.used,
          },
          429,
          {
            "X-Global-RateLimit-Limit": String(global.limit),
            "X-Global-RateLimit-Remaining": "0",
          }
        );
      }

      // ---- Basic daily rate limit (50/day) ----
      // 优先用 installId；没传就用 IP 兜底（方便你 curl 自测）
      const installIdHeader = request.headers.get("x-install-id");
      const ipFallback =
        request.headers.get("cf-connecting-ip") ||
        request.headers.get("x-forwarded-for") ||
        "unknown";
      const installId = (installIdHeader && installIdHeader.trim()) ? installIdHeader.trim() : `ip:${ipFallback}`;

      const rl = await checkDailyLimit(env, installId, 50);
      if (!rl.ok) {
        return json(
          { ok: false, error: rl.error, limit: 50, used: rl.used ?? 50 },
          429,
          {
            "X-RateLimit-Limit": "50",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": new Date(Date.now() + 60 * 60 * 24 * 1000).toISOString(),
          }
        );
      }

      const rateHeaders = {
        "X-RateLimit-Limit": String(rl.limit),
        "X-RateLimit-Remaining": String(rl.remaining),
      };

      // 可选：让客户端指定 maxOutputTokens，但我们仍然要 clamp
      const maxOutputTokens = clampInt(body?.maxOutputTokens ?? 256, 64, 512, 256);

      // 你可以固定用 flash，便宜快
      const model = normalizeString(body?.model, "gemini-2.0-flash");

      // 新 schema：统一输出 dueAt（绝对时间），同时给 timeExpression/resolution/needsConfirm
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

    // ---- Not Found ----
    return json({ ok: false, error: "NOT_FOUND" }, 404);
  },
};