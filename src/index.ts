import { renderAdminHtml } from "./adminHtml";
import { lookupRoom, ROOMS_JSON_STRING, RoomMeta, TOTAL_ROOMS } from "./rooms";

export interface Env {
  ELE_KV: KVNamespace;
  CACHE_TTL_SECONDS?: string;
  CLIENT_MISS_LIMIT?: string;
  CLIENT_MISS_WINDOW_SECONDS?: string;
  REQUIRE_APP_SIGNATURE?: string;
  APP_SIGN_SECRET?: string;
  ALLOWED_ADMIN_EMAIL?: string;
  DISABLE_ZERO_TRUST_CHECK?: string;
}

interface SessionState {
  openid: string;
  jsessionid: string;
  alive: boolean;
  updatedAt: number;
  lastHeartbeatAt: number;
  lastCheckedAt: number;
  lastError: string;
}

interface ElectricityPayload {
  schoolid: string;
  roomid: string;
  campusName: string;
  buildingName: string;
  floorName: string;
  roomName: string;
  meterType: string;
  balanceText: string;
  balanceValue: number | null;
  unit: string;
  accountStatus: string;
  queriedAt: number;
  fromCache: boolean;
}

interface MissBucket {
  count: number;
  resetAt: number;
}

class UpstreamBusyError extends Error {}
class UpstreamAuthExpiredError extends Error {}
class UpstreamQueryError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string
  ) {
    super(message);
  }
}

const KV_SESSION_KEY = "session_state";
const MCARD_BASE = "https://mcard.buct.edu.cn";
const FACTORY_CODE = "E005";
const INVALID_OPENID = "DCFDE1134D316C1242D25B6EAB6B41A3";
const WX_USER_AGENT =
  "Mozilla/5.0 (Linux; Android 14; wv) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Version/4.0 Chrome/138.0.7204.180 Mobile Safari/537.36 " +
  "wxwork/5.0.13 MicroMessenger/7.0.1";

const MAX_UPSTREAM_CONCURRENCY = 5;
const SIGNATURE_MAX_SKEW_SECONDS = 300;
const HEX_32_RE = /^[0-9A-F]{32}$/;
const CLIENT_ID_RE = /^[A-Za-z0-9_-]{4,64}$/;

let inFlightUpstream = 0;
const isolateMissMap = new Map<string, MissBucket>();
const inFlightRoomQueries = new Map<string, Promise<ElectricityPayload>>();
let isolateLastCheckedAt = 0;
let isolateLastHeartbeatAt = 0;

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function maskHex32(val: string): string {
  const clean = (val || "").trim();
  if (clean.length < 12) return clean ? "***" : "";
  return `${clean.slice(0, 6)}...${clean.slice(-4)}`;
}

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Client-Id, X-Timestamp, X-Sign",
  };
}

function jsonResponse(
  body: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...corsHeaders(),
      ...extraHeaders,
    },
  });
}

function parseJwtEmail(jwtToken: string): { email: string; expired: boolean } {
  try {
    const parts = jwtToken.split(".");
    if (parts.length !== 3) return { email: "", expired: false };
    const normalized = parts[1].replaceAll("-", "+").replaceAll("_", "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const payload = JSON.parse(atob(padded)) as { email?: string; exp?: number };
    const expired = typeof payload.exp === "number" && payload.exp < nowSeconds();
    return {
      email: typeof payload.email === "string" ? payload.email.trim() : "",
      expired,
    };
  } catch {
    return { email: "", expired: false };
  }
}

function authenticateAdmin(
  request: Request,
  env: Env
): { ok: true; email: string } | { ok: false; status: number; error: string } {
  if (env.DISABLE_ZERO_TRUST_CHECK === "true") {
    return { ok: true, email: "local-dev@localhost" };
  }

  const jwt = (request.headers.get("Cf-Access-Jwt-Assertion") || "").trim();
  if (!jwt) {
    return {
      ok: false,
      status: 403,
      error: "拒绝访问：未检测到 Cloudflare Zero Trust Access 认证凭据",
    };
  }

  const parsed = parseJwtEmail(jwt);
  if (parsed.expired) {
    return {
      ok: false,
      status: 401,
      error: "Zero Trust 会话已过期，请刷新页面重新登录",
    };
  }

  const headerEmail = (request.headers.get("Cf-Access-Authenticated-User-Email") || "").trim();
  const effectiveEmail = headerEmail || parsed.email;

  const allowedRaw = (env.ALLOWED_ADMIN_EMAIL || "").trim();
  if (allowedRaw) {
    const allowedSet = new Set(
      allowedRaw
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    );
    if (!effectiveEmail || !allowedSet.has(effectiveEmail.toLowerCase())) {
      return {
        ok: false,
        status: 403,
        error: "拒绝访问：当前账号不在管理员邮箱白名单中",
      };
    }
  }

  return { ok: true, email: effectiveEmail || "Zero Trust 用户" };
}

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function verifyClientSignature(
  request: Request,
  roomid: string,
  env: Env
): Promise<{ ok: true; clientId: string } | { ok: false; status: number; error: string }> {
  const requireSig = (env.REQUIRE_APP_SIGNATURE || "false").toLowerCase() === "true";
  const rawClientId = (request.headers.get("X-Client-Id") || "").trim();

  if (rawClientId && !CLIENT_ID_RE.test(rawClientId)) {
    return {
      ok: false,
      status: 400,
      error: "请求头 X-Client-Id 格式无效（仅允许 4~64 位字母数字及 _-）",
    };
  }

  if (!requireSig) {
    return { ok: true, clientId: rawClientId || "anonymous" };
  }

  const secret = (env.APP_SIGN_SECRET || "").trim();
  if (!secret) {
    return {
      ok: false,
      status: 500,
      error: "服务端未配置 APP_SIGN_SECRET",
    };
  }

  if (!rawClientId) {
    return { ok: false, status: 401, error: "缺少请求头 X-Client-Id" };
  }

  const tsRaw = (request.headers.get("X-Timestamp") || "").trim();
  const signRaw = (request.headers.get("X-Sign") || "").trim().toLowerCase();
  const ts = Number(tsRaw);
  if (!Number.isInteger(ts) || Math.abs(nowSeconds() - ts) > SIGNATURE_MAX_SKEW_SECONDS) {
    return { ok: false, status: 401, error: "请求时间戳无效或已过期" };
  }
  if (!/^[0-9a-f]{64}$/.test(signRaw)) {
    return { ok: false, status: 401, error: "请求签名格式无效" };
  }

  const expected = await sha256Hex(`${rawClientId}:${roomid}:${ts}:${secret}`);
  if (!timingSafeEqualStr(expected, signRaw)) {
    return { ok: false, status: 401, error: "请求签名校验失败" };
  }

  return { ok: true, clientId: rawClientId };
}

async function readSessionState(env: Env): Promise<SessionState | null> {
  const raw = await env.ELE_KV.get<SessionState>(KV_SESSION_KEY, "json");
  if (!raw || !raw.openid || !raw.jsessionid) {
    return null;
  }
  return raw;
}

async function writeSessionState(env: Env, state: SessionState): Promise<void> {
  await env.ELE_KV.put(KV_SESSION_KEY, JSON.stringify(state));
}

async function withUpstreamSlot<T>(fn: () => Promise<T>): Promise<T> {
  if (inFlightUpstream >= MAX_UPSTREAM_CONCURRENCY) {
    throw new UpstreamBusyError("上游查询并发已满，请稍后重试");
  }
  inFlightUpstream++;
  try {
    return await fn();
  } finally {
    inFlightUpstream--;
  }
}

interface McardResponse {
  success?: boolean;
  message?: string;
  resultData?: Record<string, unknown>;
}

async function callMcard(
  path: string,
  payload: Record<string, unknown>,
  openid: string,
  jsessionid: string
): Promise<{ noauth: boolean; status: number; data: McardResponse | null }> {
  const cleanSid = jsessionid.replace(/^JSESSIONID=/i, "").trim();
  const targetUrl = `${MCARD_BASE}${path}?openid=${encodeURIComponent(openid.trim())}&connect_redirect=1`;

  return withUpstreamSlot(async () => {
    const resp = await fetch(targetUrl, {
      method: "POST",
      redirect: "manual",
      headers: {
        "Content-Type": "application/json",
        Cookie: `JSESSIONID=${cleanSid}`,
        "User-Agent": WX_USER_AGENT,
        "X-Requested-With": "XMLHttpRequest",
      },
      body: JSON.stringify(payload),
    });

    const noauthHeader = (resp.headers.get("Noauthentication") || "").toLowerCase() === "true";
    let parsed: McardResponse | null = null;
    try {
      parsed = (await resp.json()) as McardResponse;
    } catch {
      parsed = null;
    }

    const msg = parsed?.message || "";
    const noauthBody =
      parsed?.success === false &&
      (msg.includes("openid无效") || msg.includes("请使用微信客户端"));

    return {
      noauth: noauthHeader || noauthBody || resp.status === 302,
      status: resp.status,
      data: parsed,
    };
  });
}

async function runHeartbeatCheck(
  env: Env,
  forceWriteKv: boolean
): Promise<{ alive: boolean; message: string; state: SessionState | null }> {
  const state = await readSessionState(env);
  if (!state) {
    return { alive: false, message: "KV 中尚未配置会话凭证", state: null };
  }

  const now = nowSeconds();
  isolateLastCheckedAt = now;

  try {
    const res = await callMcard(
      "/channel/getXiaoQuList",
      { factorycode: FACTORY_CODE },
      state.openid,
      state.jsessionid
    );

    if (res.data?.success === true) {
      isolateLastHeartbeatAt = now;
      const flippedToAlive = !state.alive;
      if (flippedToAlive || forceWriteKv) {
        const next: SessionState = {
          ...state,
          alive: true,
          lastHeartbeatAt: now,
          lastCheckedAt: now,
          lastError: "",
        };
        await writeSessionState(env, next);
        return { alive: true, message: "会话活跃，心跳保活成功", state: next };
      }
      return { alive: true, message: "会话活跃（KV 状态未变化，免写跳过）", state };
    }

    const errMsg = res.data?.message || `上游验活失败 (HTTP ${res.status})`;
    const flippedToDead = state.alive;
    if (res.noauth && (flippedToDead || forceWriteKv)) {
      const next: SessionState = {
        ...state,
        alive: false,
        lastCheckedAt: now,
        lastError: errMsg,
      };
      await writeSessionState(env, next);
      return { alive: false, message: errMsg, state: next };
    }
    return { alive: state.alive && !res.noauth, message: errMsg, state };
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    console.error("[Heartbeat] Upstream error:", errMsg);
    return { alive: state.alive, message: `网络异常: ${errMsg}`, state };
  }
}

async function checkAndConsumeMissQuota(
  origin: string,
  clientId: string,
  limit: number,
  windowSeconds: number,
  ctx: ExecutionContext
): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds: number }> {
  const now = nowSeconds();

  // Opportunistic cleanup for in-isolate map
  if (isolateMissMap.size > 1000) {
    for (const [k, v] of isolateMissMap) {
      if (v.resetAt <= now) isolateMissMap.delete(k);
    }
  }

  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(
    `${origin}/__cache/v1/miss-limit/${encodeURIComponent(clientId)}`,
    { method: "GET" }
  );

  let activeCount = 0;
  let activeResetAt = now + windowSeconds;

  const iso = isolateMissMap.get(clientId);
  if (iso && iso.resetAt > now) {
    activeCount = iso.count;
    activeResetAt = iso.resetAt;
  }

  try {
    const cachedResp = await cache.match(cacheReq);
    if (cachedResp) {
      const cached = (await cachedResp.json()) as MissBucket;
      if (cached && cached.resetAt > now && cached.count > activeCount) {
        activeCount = cached.count;
        activeResetAt = cached.resetAt;
      }
    }
  } catch {
    // Cache read failure gracefully falls back to in-isolate counter
  }

  if (activeCount >= limit) {
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.max(1, activeResetAt - now),
    };
  }

  const nextBucket: MissBucket = {
    count: activeCount + 1,
    resetAt: activeResetAt,
  };
  isolateMissMap.set(clientId, nextBucket);

  const ttl = Math.max(1, nextBucket.resetAt - now);
  const putResp = new Response(JSON.stringify(nextBucket), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": `public, max-age=${ttl}`,
    },
  });
  ctx.waitUntil(cache.put(cacheReq, putResp));

  return {
    allowed: true,
    remaining: Math.max(0, limit - nextBucket.count),
    retryAfterSeconds: 0,
  };
}

function parseBalanceValue(balanceText: string): { value: number | null; unit: string } {
  const numMatch = balanceText.match(/[-+]?\d+(?:\.\d+)?/);
  const value = numMatch ? Number(numMatch[0]) : null;
  let unit = "";
  if (balanceText.includes("元")) unit = "元";
  else if (/kWh/i.test(balanceText)) unit = "kWh";
  return {
    value: value !== null && Number.isFinite(value) ? value : null,
    unit,
  };
}

async function fetchUpstreamElectricity(
  roomMeta: RoomMeta,
  env: Env,
  state: SessionState
): Promise<ElectricityPayload> {
  const inflightKey = `${roomMeta.schoolid}\u0000${roomMeta.roomid}`;
  const existing = inFlightRoomQueries.get(inflightKey);
  if (existing) {
    return existing;
  }

  const task = (async () => {
    const res = await callMcard(
      "/channel/queryResEle",
      {
        schoolid: roomMeta.schoolid,
        roomid: roomMeta.roomid,
        factorycode: FACTORY_CODE,
      },
      state.openid,
      state.jsessionid
    );

    if (res.noauth) {
      if (state.alive) {
        await writeSessionState(env, {
          ...state,
          alive: false,
          lastCheckedAt: nowSeconds(),
          lastError: res.data?.message || "上游会话已过期",
        });
      }
      throw new UpstreamAuthExpiredError("上游认证会话已过期，等待管理员刷新");
    }

    if (!res.data?.success) {
      throw new UpstreamQueryError(
        502,
        res.data?.message || "电表不在线或上游查询失败"
      );
    }

    const rd = res.data.resultData || {};
    const balanceText = String(rd.elebalance || "").trim();
    const parsed = parseBalanceValue(balanceText);

    return {
      schoolid: roomMeta.schoolid,
      roomid: roomMeta.roomid,
      campusName: roomMeta.campusName,
      buildingName: roomMeta.buildingName,
      floorName: roomMeta.floorName,
      roomName: roomMeta.roomName,
      meterType: roomMeta.meterType,
      balanceText,
      balanceValue: parsed.value,
      unit: parsed.unit,
      accountStatus: rd.AccountStatus != null ? String(rd.AccountStatus) : "",
      queriedAt: nowSeconds(),
      fromCache: false,
    };
  })();

  inFlightRoomQueries.set(inflightKey, task);
  try {
    return await task;
  } finally {
    inFlightRoomQueries.delete(inflightKey);
  }
}

async function handlePublicElectricity(
  request: Request,
  url: URL,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  const schoolid = (url.searchParams.get("schoolid") || "").trim();
  const roomid = (url.searchParams.get("roomid") || "").trim();
  if (!schoolid || !roomid) {
    return jsonResponse({ error: "缺少必要参数 schoolid 或 roomid" }, 400);
  }

  const roomMeta = lookupRoom(schoolid, roomid);
  if (!roomMeta) {
    return jsonResponse({ error: "非法的校区或房间 ID" }, 400);
  }

  const sigCheck = await verifyClientSignature(request, roomid, env);
  if (!sigCheck.ok) {
    return jsonResponse({ error: sigCheck.error }, sigCheck.status);
  }

  const cache = (caches as unknown as { default: Cache }).default;
  const cacheUrl = `${url.origin}/__cache/v1/electricity?schoolid=${encodeURIComponent(schoolid)}&roomid=${encodeURIComponent(roomid)}`;
  const cacheReq = new Request(cacheUrl, { method: "GET" });

  try {
    const cachedResp = await cache.match(cacheReq);
    if (cachedResp) {
      const cachedData = (await cachedResp.json()) as ElectricityPayload;
      return jsonResponse({ ...cachedData, fromCache: true }, 200);
    }
  } catch {
    // Ignore edge cache read error and proceed to upstream
  }

  const state = await readSessionState(env);
  if (!state || !state.alive) {
    return jsonResponse(
      { error: "电费查询网关凭证维护中，请稍后重试" },
      503
    );
  }

  const missLimit = parsePositiveInt(env.CLIENT_MISS_LIMIT, 3);
  const missWindow = parsePositiveInt(env.CLIENT_MISS_WINDOW_SECONDS, 600);
  const quota = await checkAndConsumeMissQuota(
    url.origin,
    sigCheck.clientId,
    missLimit,
    missWindow,
    ctx
  );
  if (!quota.allowed) {
    return jsonResponse(
      {
        error: `该设备未命中缓存的查询过于频繁（每 ${Math.ceil(missWindow / 60)} 分钟最多 ${missLimit} 次新房间查询），请稍后再试`,
        retryAfterSeconds: quota.retryAfterSeconds,
      },
      429,
      { "Retry-After": String(quota.retryAfterSeconds) }
    );
  }

  try {
    const payload = await fetchUpstreamElectricity(roomMeta, env, state);
    const cacheTtl = parsePositiveInt(env.CACHE_TTL_SECONDS, 900);
    const cachePutResp = new Response(JSON.stringify(payload), {
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": `public, max-age=${cacheTtl}`,
      },
    });
    ctx.waitUntil(cache.put(cacheReq, cachePutResp));
    return jsonResponse(payload, 200);
  } catch (err) {
    if (err instanceof UpstreamBusyError) {
      return jsonResponse({ error: err.message }, 503);
    }
    if (err instanceof UpstreamAuthExpiredError) {
      return jsonResponse({ error: err.message }, 503);
    }
    if (err instanceof UpstreamQueryError) {
      return jsonResponse({ error: err.message }, err.statusCode);
    }
    const msg = err instanceof Error ? err.message : String(err);
    return jsonResponse({ error: `上游请求失败: ${msg}` }, 502);
  }
}

async function handleAdminUpdateSession(request: Request, env: Env): Promise<Response> {
  let body: { openid?: string; jsessionid?: string };
  try {
    body = (await request.json()) as { openid?: string; jsessionid?: string };
  } catch {
    return jsonResponse({ error: "请求体必须为合法 JSON" }, 400);
  }

  const openid = (body.openid || "").trim().toUpperCase();
  const jsessionid = (body.jsessionid || "")
    .replace(/^JSESSIONID=/i, "")
    .trim()
    .toUpperCase();

  if (!HEX_32_RE.test(openid) || openid === INVALID_OPENID) {
    return jsonResponse({ error: "openid 格式无效（需为 32 位十六进制字符串）" }, 400);
  }
  if (!HEX_32_RE.test(jsessionid)) {
    return jsonResponse({ error: "JSESSIONID 格式无效（需为 32 位十六进制字符串）" }, 400);
  }

  try {
    const check = await callMcard(
      "/channel/getXiaoQuList",
      { factorycode: FACTORY_CODE },
      openid,
      jsessionid
    );
    if (!check.data?.success) {
      return jsonResponse(
        { error: `上游验活失败: ${check.data?.message || `HTTP ${check.status}`}` },
        400
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return jsonResponse({ error: `上游验活网络异常: ${msg}` }, 502);
  }

  const now = nowSeconds();
  isolateLastCheckedAt = now;
  isolateLastHeartbeatAt = now;

  const nextState: SessionState = {
    openid,
    jsessionid,
    alive: true,
    updatedAt: now,
    lastHeartbeatAt: now,
    lastCheckedAt: now,
    lastError: "",
  };
  await writeSessionState(env, nextState);

  return jsonResponse({
    success: true,
    message: "验活通过，新凭证已写入 KV 并激活保活",
    openidMasked: maskHex32(openid),
    jsessionidMasked: maskHex32(jsessionid),
  });
}

async function handleAdminTestQuery(url: URL, env: Env): Promise<Response> {
  const schoolid = (url.searchParams.get("schoolid") || "").trim();
  const roomid = (url.searchParams.get("roomid") || "").trim();
  if (!schoolid || !roomid) {
    return jsonResponse({ error: "缺少 schoolid 或 roomid 参数" }, 400);
  }
  const roomMeta = lookupRoom(schoolid, roomid);
  if (!roomMeta) {
    return jsonResponse({ error: "房间不在白名单中" }, 400);
  }
  const state = await readSessionState(env);
  if (!state || !state.openid || !state.jsessionid) {
    return jsonResponse({ error: "KV 中尚未配置凭证" }, 503);
  }

  try {
    const payload = await fetchUpstreamElectricity(roomMeta, env, state);
    return jsonResponse(payload, 200);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return jsonResponse({ error: msg }, 502);
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Never expose internal cache key paths externally
    if (path.startsWith("/__cache/")) {
      return jsonResponse({ error: "Not Found" }, 404);
    }

    // ---------- Public API routes ----------
    if (request.method === "GET" && path === "/v1/health") {
      const state = await readSessionState(env);
      return jsonResponse({
        ok: true,
        alive: Boolean(state?.alive),
        updatedAt: state?.updatedAt || 0,
        lastHeartbeatAt: Math.max(state?.lastHeartbeatAt || 0, isolateLastHeartbeatAt),
        totalRooms: TOTAL_ROOMS,
      });
    }

    if (request.method === "GET" && path === "/v1/rooms") {
      return new Response(ROOMS_JSON_STRING, {
        status: 200,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "public, max-age=86400",
          ...corsHeaders(),
        },
      });
    }

    if (request.method === "GET" && path === "/v1/electricity") {
      return handlePublicElectricity(request, url, env, ctx);
    }

    // ---------- Zero Trust protected Admin routes ----------
    if (path === "/admin" || path === "/admin/" || path.startsWith("/admin/")) {
      const auth = authenticateAdmin(request, env);
      if (!auth.ok) {
        if (path.startsWith("/admin/api/")) {
          return jsonResponse({ error: auth.error }, auth.status);
        }
        return new Response(auth.error, {
          status: auth.status,
          headers: { "Content-Type": "text/plain; charset=utf-8" },
        });
      }

      if (request.method === "GET" && (path === "/admin" || path === "/admin/")) {
        return new Response(renderAdminHtml(auth.email), {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
          },
        });
      }

      if (request.method === "GET" && path === "/admin/api/status") {
        const state = await readSessionState(env);
        return jsonResponse({
          alive: Boolean(state?.alive),
          openidMasked: state ? maskHex32(state.openid) : "",
          jsessionidMasked: state ? maskHex32(state.jsessionid) : "",
          updatedAt: state?.updatedAt || 0,
          lastHeartbeatAt: Math.max(state?.lastHeartbeatAt || 0, isolateLastHeartbeatAt),
          lastCheckedAt: Math.max(state?.lastCheckedAt || 0, isolateLastCheckedAt),
          lastError: state?.lastError || "",
          totalRooms: TOTAL_ROOMS,
          adminEmail: auth.email,
        });
      }

      if (request.method === "POST" && path === "/admin/api/session") {
        return handleAdminUpdateSession(request, env);
      }

      if (request.method === "POST" && path === "/admin/api/heartbeat") {
        const res = await runHeartbeatCheck(env, true);
        return jsonResponse({
          alive: res.alive,
          message: res.message,
          checkedAt: nowSeconds(),
        });
      }

      if (request.method === "GET" && path === "/admin/api/test-query") {
        return handleAdminTestQuery(url, env);
      }

      return jsonResponse({ error: "Not Found" }, 404);
    }

    return jsonResponse({ error: "Not Found" }, 404);
  },

  async scheduled(
    _controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext
  ): Promise<void> {
    ctx.waitUntil(
      runHeartbeatCheck(env, false).then((res) => {
        console.log(`[Cron] alive=${res.alive}, message=${res.message}`);
      })
    );
  },
};
