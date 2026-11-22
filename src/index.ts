import { renderAdminHtml } from "./adminHtml";
import {
  authenticateAdminHeaders,
  corsHeaders,
  createUpstreamGateway,
  ElectricityPayload,
  FACTORY_CODE,
  maskHex32,
  MissBucket,
  normalizeSessionCredentials,
  nowSeconds,
  parsePositiveInt,
  SessionState,
  UpstreamAuthExpiredError,
  UpstreamBusyError,
  UpstreamQueryError,
  verifyClientSignatureHeaders,
} from "./core";
import { lookupRoom, ROOMS_JSON_STRING, TOTAL_ROOMS } from "./rooms";

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

const KV_SESSION_KEY = "session_state";

const upstream = createUpstreamGateway();
const isolateMissMap = new Map<string, MissBucket>();
let isolateLastCheckedAt = 0;
let isolateLastHeartbeatAt = 0;

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
    const res = await upstream.callMcard(
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
    // Edge Cache read failure falls back to in-isolate counter
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

  const sigCheck = await verifyClientSignatureHeaders(
    (name) => request.headers.get(name) ?? undefined,
    roomid,
    {
      requireSignature: env.REQUIRE_APP_SIGNATURE,
      appSignSecret: env.APP_SIGN_SECRET,
    }
  );
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
    return jsonResponse({ error: "电费查询网关凭证维护中，请稍后重试" }, 503);
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
    const payload = await upstream.fetchElectricity(roomMeta, state, async (errMsg) => {
      await writeSessionState(env, {
        ...state,
        alive: false,
        lastCheckedAt: nowSeconds(),
        lastError: errMsg,
      });
    });

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
    if (err instanceof UpstreamBusyError || err instanceof UpstreamAuthExpiredError) {
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

  const normalized = normalizeSessionCredentials(body.openid, body.jsessionid);
  if (!normalized.ok) {
    return jsonResponse({ error: normalized.error }, 400);
  }

  try {
    const check = await upstream.callMcard(
      "/channel/getXiaoQuList",
      { factorycode: FACTORY_CODE },
      normalized.openid,
      normalized.jsessionid
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
    openid: normalized.openid,
    jsessionid: normalized.jsessionid,
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
    openidMasked: maskHex32(normalized.openid),
    jsessionidMasked: maskHex32(normalized.jsessionid),
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
    const payload = await upstream.fetchElectricity(roomMeta, state, async (errMsg) => {
      await writeSessionState(env, {
        ...state,
        alive: false,
        lastCheckedAt: nowSeconds(),
        lastError: errMsg,
      });
    });
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

    if (path.startsWith("/__cache/")) {
      return jsonResponse({ error: "Not Found" }, 404);
    }

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

    if (path === "/admin" || path === "/admin/" || path.startsWith("/admin/")) {
      const auth = authenticateAdminHeaders(
        (name) => request.headers.get(name) ?? undefined,
        {
          disableZeroTrustCheck: env.DISABLE_ZERO_TRUST_CHECK,
          allowedAdminEmail: env.ALLOWED_ADMIN_EMAIL,
        }
      );
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
