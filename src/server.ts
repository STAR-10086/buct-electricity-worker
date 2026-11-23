import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import http, { IncomingMessage, ServerResponse } from "node:http";
import { dirname } from "node:path";
import { renderAdminHtml } from "./adminHtml";
import {
  authenticateAdminRequest,
  buildBanErrorMessage,
  checkBannedStudent,
  corsHeaders,
  createEmptyUsageState,
  createUpstreamGateway,
  ElectricityPayload,
  FACTORY_CODE,
  HeaderGetter,
  maskHex32,
  MissBucket,
  normalizeSessionCredentials,
  normalizeUsageState,
  nowSeconds,
  parsePositiveInt,
  recordStudentQuery,
  SessionState,
  STUDENT_ID_RE,
  summarizeUsageState,
  UpstreamAuthExpiredError,
  UpstreamBusyError,
  UpstreamQueryError,
  UsageState,
  verifyClientSignatureHeaders,
} from "./core";
import { lookupRoom, ROOMS_JSON_STRING, TOTAL_ROOMS } from "./rooms";

const PORT = parsePositiveInt(process.env.PORT, 8080);
const HOST = process.env.HOST || "0.0.0.0";
const SESSION_FILE = process.env.SESSION_FILE || "/data/session_state.json";
const USAGE_FILE = process.env.USAGE_FILE || "/data/usage_state.json";

const CACHE_TTL_SECONDS = parsePositiveInt(process.env.CACHE_TTL_SECONDS, 900);
const CLIENT_MISS_LIMIT = parsePositiveInt(process.env.CLIENT_MISS_LIMIT, 3);
const CLIENT_MISS_WINDOW_SECONDS = parsePositiveInt(process.env.CLIENT_MISS_WINDOW_SECONDS, 600);
const HEARTBEAT_INTERVAL_SECONDS = parsePositiveInt(process.env.HEARTBEAT_INTERVAL_SECONDS, 480);

const REQUIRE_APP_SIGNATURE = process.env.REQUIRE_APP_SIGNATURE || "false";
const REQUIRE_STUDENT_ID = process.env.REQUIRE_STUDENT_ID || "false";
const APP_SIGN_SECRET = process.env.APP_SIGN_SECRET || "";
const ALLOWED_ADMIN_EMAIL = process.env.ALLOWED_ADMIN_EMAIL || "";
const ALLOWED_ADMIN_HOST = process.env.ALLOWED_ADMIN_HOST || "";
const CF_ACCESS_TEAM_DOMAIN = process.env.CF_ACCESS_TEAM_DOMAIN || "";
const CF_ACCESS_AUD = process.env.CF_ACCESS_AUD || "";
const DISABLE_ZERO_TRUST_CHECK = process.env.DISABLE_ZERO_TRUST_CHECK || "false";

const MAX_ADMIN_BODY_BYTES = 64 * 1024;

const upstream = createUpstreamGateway();
const eleCache = new Map<string, { payload: ElectricityPayload; expiresAt: number }>();
const clientMissMap = new Map<string, MissBucket>();

let sessionState: SessionState | null = null;
let usageState: UsageState = createEmptyUsageState();
let usageSaveTimer: ReturnType<typeof setTimeout> | null = null;
let usageDirty = false;
let memLastCheckedAt = 0;
let memLastHeartbeatAt = 0;

function loadSessionFromDisk(): void {
  try {
    mkdirSync(dirname(SESSION_FILE), { recursive: true });
    if (!existsSync(SESSION_FILE)) return;
    const raw = JSON.parse(readFileSync(SESSION_FILE, "utf8")) as SessionState;
    if (raw && raw.openid && raw.jsessionid) {
      sessionState = raw;
      memLastCheckedAt = raw.lastCheckedAt || 0;
      memLastHeartbeatAt = raw.lastHeartbeatAt || 0;
      console.log(`[Init] Loaded persisted session from ${SESSION_FILE} (alive=${raw.alive})`);
    }
  } catch (err) {
    console.error(`[Init] Failed to read ${SESSION_FILE}:`, err);
  }
}

function saveSessionToDisk(next: SessionState): void {
  sessionState = next;
  mkdirSync(dirname(SESSION_FILE), { recursive: true });
  const tmpFile = `${SESSION_FILE}.tmp`;
  writeFileSync(tmpFile, JSON.stringify(next, null, 2), "utf8");
  renameSync(tmpFile, SESSION_FILE);
}

function loadUsageFromDisk(): void {
  try {
    mkdirSync(dirname(USAGE_FILE), { recursive: true });
    if (!existsSync(USAGE_FILE)) return;
    const raw = JSON.parse(readFileSync(USAGE_FILE, "utf8")) as unknown;
    usageState = normalizeUsageState(raw);
    console.log(
      `[Init] Loaded usage state from ${USAGE_FILE} (users=${Object.keys(usageState.users).length}, banned=${Object.keys(usageState.banned).length})`
    );
  } catch (err) {
    console.error(`[Init] Failed to read ${USAGE_FILE}:`, err);
  }
}

function saveUsageImmediate(): void {
  if (usageSaveTimer) {
    clearTimeout(usageSaveTimer);
    usageSaveTimer = null;
  }
  usageDirty = false;
  mkdirSync(dirname(USAGE_FILE), { recursive: true });
  const tmpFile = `${USAGE_FILE}.tmp`;
  writeFileSync(tmpFile, JSON.stringify(usageState, null, 2), "utf8");
  renameSync(tmpFile, USAGE_FILE);
}

function scheduleUsageSave(): void {
  usageDirty = true;
  if (usageSaveTimer) return;
  usageSaveTimer = setTimeout(() => {
    usageSaveTimer = null;
    if (!usageDirty) return;
    try {
      saveUsageImmediate();
    } catch (err) {
      console.error(`[Usage] Failed to save ${USAGE_FILE}:`, err);
    }
  }, 5000);
}

function makeHeaderGetter(req: IncomingMessage): HeaderGetter {
  return (name: string): string | undefined => {
    const val = req.headers[name.toLowerCase()];
    return Array.isArray(val) ? val[0] : val;
  };
}

function sendJson(
  res: ServerResponse,
  body: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {}
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...corsHeaders(),
    ...extraHeaders,
  });
  res.end(payload);
}

function sendText(
  res: ServerResponse,
  body: string,
  status = 200,
  contentType = "text/plain; charset=utf-8"
): void {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
  });
  res.end(body);
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_ADMIN_BODY_BYTES) {
        reject(new Error("请求体过大"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve(JSON.parse(text) as Record<string, unknown>);
      } catch {
        reject(new Error("请求体必须为合法 JSON"));
      }
    });
    req.on("error", (err) => reject(err));
  });
}

function checkAndConsumeMissQuota(
  clientId: string,
  studentId: string
): {
  allowed: boolean;
  retryAfterSeconds: number;
} {
  const now = nowSeconds();
  if (clientMissMap.size > 4000) {
    for (const [k, v] of clientMissMap) {
      if (v.resetAt <= now) clientMissMap.delete(k);
    }
  }

  const keys = studentId ? [`client:${clientId}`, `student:${studentId}`] : [`client:${clientId}`];

  for (const key of keys) {
    const existing = clientMissMap.get(key);
    if (existing && existing.resetAt > now && existing.count >= CLIENT_MISS_LIMIT) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, existing.resetAt - now),
      };
    }
  }

  for (const key of keys) {
    const existing = clientMissMap.get(key);
    if (!existing || existing.resetAt <= now) {
      clientMissMap.set(key, { count: 1, resetAt: now + CLIENT_MISS_WINDOW_SECONDS });
    } else {
      existing.count += 1;
    }
  }
  return { allowed: true, retryAfterSeconds: 0 };
}

async function runHeartbeatCheck(
  forceSave: boolean
): Promise<{ alive: boolean; message: string }> {
  const state = sessionState;
  if (!state || !state.openid || !state.jsessionid) {
    return { alive: false, message: "尚未配置会话凭证" };
  }

  const now = nowSeconds();
  memLastCheckedAt = now;

  try {
    const res = await upstream.callMcard(
      "/channel/getXiaoQuList",
      { factorycode: FACTORY_CODE },
      state.openid,
      state.jsessionid
    );

    if (res.data?.success === true) {
      memLastHeartbeatAt = now;
      if (!state.alive || forceSave) {
        saveSessionToDisk({
          ...state,
          alive: true,
          lastHeartbeatAt: now,
          lastCheckedAt: now,
          lastError: "",
        });
        return { alive: true, message: "会话活跃，心跳保活成功" };
      }
      return { alive: true, message: "会话活跃（状态未变）" };
    }

    const errMsg = res.data?.message || `上游验活失败 (HTTP ${res.status})`;
    if (res.noauth && (state.alive || forceSave)) {
      saveSessionToDisk({
        ...state,
        alive: false,
        lastCheckedAt: now,
        lastError: errMsg,
      });
      return { alive: false, message: errMsg };
    }
    return { alive: state.alive && !res.noauth, message: errMsg };
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    console.error("[Heartbeat] Upstream error:", errMsg);
    return { alive: state.alive, message: `网络异常: ${errMsg}` };
  }
}

async function handlePublicElectricity(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL
): Promise<void> {
  const schoolid = (url.searchParams.get("schoolid") || "").trim();
  const roomid = (url.searchParams.get("roomid") || "").trim();
  if (!schoolid || !roomid) {
    sendJson(res, { error: "缺少必要参数 schoolid 或 roomid" }, 400);
    return;
  }

  const roomMeta = lookupRoom(schoolid, roomid);
  if (!roomMeta) {
    sendJson(res, { error: "非法的校区或房间 ID" }, 400);
    return;
  }

  const sigCheck = await verifyClientSignatureHeaders(makeHeaderGetter(req), roomid, {
    requireSignature: REQUIRE_APP_SIGNATURE,
    requireStudentId: REQUIRE_STUDENT_ID,
    appSignSecret: APP_SIGN_SECRET,
  });
  if (!sigCheck.ok) {
    sendJson(res, { error: sigCheck.error }, sigCheck.status);
    return;
  }

  const ban = checkBannedStudent(usageState, sigCheck.studentId);
  if (ban) {
    sendJson(res, { error: buildBanErrorMessage(ban), banned: true }, 403);
    return;
  }

  const now = nowSeconds();
  if (eleCache.size > 2000) {
    for (const [k, v] of eleCache) {
      if (v.expiresAt <= now) eleCache.delete(k);
    }
  }

  const cacheKey = `${schoolid}\u0000${roomid}`;
  const cached = eleCache.get(cacheKey);
  if (cached && cached.expiresAt > now) {
    if (recordStudentQuery(usageState, sigCheck.studentId, roomMeta, false)) {
      scheduleUsageSave();
    }
    sendJson(res, { ...cached.payload, fromCache: true }, 200);
    return;
  }

  const state = sessionState;
  if (!state || !state.alive) {
    sendJson(res, { error: "电费查询网关凭证维护中，请稍后重试" }, 503);
    return;
  }

  const quota = checkAndConsumeMissQuota(sigCheck.clientId, sigCheck.studentId);
  if (!quota.allowed) {
    sendJson(
      res,
      {
        error: `未命中缓存的新房间查询过于频繁（每 ${Math.ceil(CLIENT_MISS_WINDOW_SECONDS / 60)} 分钟最多 ${CLIENT_MISS_LIMIT} 次），请稍后再试`,
        retryAfterSeconds: quota.retryAfterSeconds,
      },
      429,
      { "Retry-After": String(quota.retryAfterSeconds) }
    );
    return;
  }

  try {
    const payload = await upstream.fetchElectricity(roomMeta, state, async (errMsg) => {
      saveSessionToDisk({
        ...state,
        alive: false,
        lastCheckedAt: nowSeconds(),
        lastError: errMsg,
      });
    });

    eleCache.set(cacheKey, {
      payload,
      expiresAt: nowSeconds() + CACHE_TTL_SECONDS,
    });
    if (recordStudentQuery(usageState, sigCheck.studentId, roomMeta, true)) {
      scheduleUsageSave();
    }
    sendJson(res, payload, 200);
  } catch (err) {
    if (err instanceof UpstreamBusyError || err instanceof UpstreamAuthExpiredError) {
      sendJson(res, { error: err.message }, 503);
      return;
    }
    if (err instanceof UpstreamQueryError) {
      sendJson(res, { error: err.message }, err.statusCode);
      return;
    }
    const msg = err instanceof Error ? err.message : String(err);
    sendJson(res, { error: `上游请求失败: ${msg}` }, 502);
  }
}

async function handleAdminUpdateSession(
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  let body: Record<string, unknown>;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "请求体解析失败";
    sendJson(res, { error: msg }, 400);
    return;
  }

  const normalized = normalizeSessionCredentials(
    typeof body.openid === "string" ? body.openid : undefined,
    typeof body.jsessionid === "string" ? body.jsessionid : undefined
  );
  if (!normalized.ok) {
    sendJson(res, { error: normalized.error }, 400);
    return;
  }

  try {
    const check = await upstream.callMcard(
      "/channel/getXiaoQuList",
      { factorycode: FACTORY_CODE },
      normalized.openid,
      normalized.jsessionid
    );
    if (!check.data?.success) {
      sendJson(
        res,
        { error: `上游验活失败: ${check.data?.message || `HTTP ${check.status}`}` },
        400
      );
      return;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    sendJson(res, { error: `上游验活网络异常: ${msg}` }, 502);
    return;
  }

  const now = nowSeconds();
  memLastCheckedAt = now;
  memLastHeartbeatAt = now;

  saveSessionToDisk({
    openid: normalized.openid,
    jsessionid: normalized.jsessionid,
    alive: true,
    updatedAt: now,
    lastHeartbeatAt: now,
    lastCheckedAt: now,
    lastError: "",
  });

  sendJson(res, {
    success: true,
    message: "验活通过，新凭证已保存并激活保活",
    openidMasked: maskHex32(normalized.openid),
    jsessionidMasked: maskHex32(normalized.jsessionid),
  });
}

async function handleAdminTestQuery(url: URL, res: ServerResponse): Promise<void> {
  const schoolid = (url.searchParams.get("schoolid") || "").trim();
  const roomid = (url.searchParams.get("roomid") || "").trim();
  if (!schoolid || !roomid) {
    sendJson(res, { error: "缺少 schoolid 或 roomid 参数" }, 400);
    return;
  }
  const roomMeta = lookupRoom(schoolid, roomid);
  if (!roomMeta) {
    sendJson(res, { error: "房间不在白名单中" }, 400);
    return;
  }
  const state = sessionState;
  if (!state || !state.openid || !state.jsessionid) {
    sendJson(res, { error: "尚未配置会话凭证" }, 503);
    return;
  }

  try {
    const payload = await upstream.fetchElectricity(roomMeta, state, async (errMsg) => {
      saveSessionToDisk({
        ...state,
        alive: false,
        lastCheckedAt: nowSeconds(),
        lastError: errMsg,
      });
    });
    sendJson(res, payload, 200);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    sendJson(res, { error: msg }, 502);
  }
}

async function routeRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = (req.method || "GET").toUpperCase();
  if (method === "OPTIONS") {
    res.writeHead(204, corsHeaders());
    res.end();
    return;
  }

  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  const path = url.pathname;

  if (method === "GET" && path === "/v1/health") {
    sendJson(res, {
      ok: true,
      alive: Boolean(sessionState?.alive),
      updatedAt: sessionState?.updatedAt || 0,
      lastHeartbeatAt: Math.max(sessionState?.lastHeartbeatAt || 0, memLastHeartbeatAt),
      totalRooms: TOTAL_ROOMS,
    });
    return;
  }

  if (method === "GET" && path === "/v1/rooms") {
    res.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "public, max-age=86400",
      ...corsHeaders(),
    });
    res.end(ROOMS_JSON_STRING);
    return;
  }

  if (method === "GET" && path === "/v1/electricity") {
    await handlePublicElectricity(req, res, url);
    return;
  }

  if (path === "/admin" || path === "/admin/" || path.startsWith("/admin/")) {
    const auth = await authenticateAdminRequest(
      makeHeaderGetter(req),
      req.headers.host || url.host,
      {
        allowedAdminHost: ALLOWED_ADMIN_HOST,
        disableZeroTrustCheck: DISABLE_ZERO_TRUST_CHECK,
        cfAccessTeamDomain: CF_ACCESS_TEAM_DOMAIN,
        cfAccessAud: CF_ACCESS_AUD,
        allowedAdminEmail: ALLOWED_ADMIN_EMAIL,
      }
    );
    if (!auth.ok) {
      if (path.startsWith("/admin/api/")) {
        sendJson(res, { error: auth.error }, auth.status);
      } else {
        sendText(res, auth.error, auth.status);
      }
      return;
    }

    if (method === "GET" && (path === "/admin" || path === "/admin/")) {
      sendText(res, renderAdminHtml(auth.email), 200, "text/html; charset=utf-8");
      return;
    }

    if (method === "GET" && path === "/admin/api/status") {
      sendJson(res, {
        alive: Boolean(sessionState?.alive),
        openidMasked: sessionState ? maskHex32(sessionState.openid) : "",
        jsessionidMasked: sessionState ? maskHex32(sessionState.jsessionid) : "",
        updatedAt: sessionState?.updatedAt || 0,
        lastHeartbeatAt: Math.max(sessionState?.lastHeartbeatAt || 0, memLastHeartbeatAt),
        lastCheckedAt: Math.max(sessionState?.lastCheckedAt || 0, memLastCheckedAt),
        lastError: sessionState?.lastError || "",
        totalRooms: TOTAL_ROOMS,
        adminEmail: auth.email,
      });
      return;
    }

    if (method === "POST" && path === "/admin/api/session") {
      await handleAdminUpdateSession(req, res);
      return;
    }

    if (method === "POST" && path === "/admin/api/heartbeat") {
      const hb = await runHeartbeatCheck(true);
      sendJson(res, {
        alive: hb.alive,
        message: hb.message,
        checkedAt: nowSeconds(),
      });
      return;
    }

    if (method === "GET" && path === "/admin/api/test-query") {
      await handleAdminTestQuery(url, res);
      return;
    }

    if (method === "GET" && path === "/admin/api/users") {
      const q = url.searchParams.get("q") || "";
      sendJson(res, summarizeUsageState(usageState, q));
      return;
    }

    if (method === "POST" && path === "/admin/api/ban") {
      let body: Record<string, unknown>;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "请求体解析失败";
        sendJson(res, { error: msg }, 400);
        return;
      }
      const sid = typeof body.studentId === "string" ? body.studentId.trim() : "";
      const reason = typeof body.reason === "string" ? body.reason.trim().slice(0, 120) : "";
      if (!STUDENT_ID_RE.test(sid)) {
        sendJson(res, { error: "学号格式无效（仅允许 6~20 位字母或数字）" }, 400);
        return;
      }
      usageState.banned[sid] = {
        studentId: sid,
        reason: reason || "异常高频查询",
        bannedAt: nowSeconds(),
      };
      saveUsageImmediate();
      sendJson(res, { success: true, message: `已拉黑学号 ${sid}`, studentId: sid });
      return;
    }

    if (method === "POST" && path === "/admin/api/unban") {
      let body: Record<string, unknown>;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        const msg = err instanceof Error ? err.message : "请求体解析失败";
        sendJson(res, { error: msg }, 400);
        return;
      }
      const sid = typeof body.studentId === "string" ? body.studentId.trim() : "";
      if (!STUDENT_ID_RE.test(sid)) {
        sendJson(res, { error: "学号格式无效" }, 400);
        return;
      }
      delete usageState.banned[sid];
      saveUsageImmediate();
      sendJson(res, { success: true, message: `已解除拉黑 ${sid}`, studentId: sid });
      return;
    }

    sendJson(res, { error: "Not Found" }, 404);
    return;
  }

  sendJson(res, { error: "Not Found" }, 404);
}

loadSessionFromDisk();
loadUsageFromDisk();

const server = http.createServer((req, res) => {
  routeRequest(req, res).catch((err) => {
    console.error("[HTTP] Unhandled error:", err);
    if (!res.headersSent) {
      sendJson(res, { error: "Internal Server Error" }, 500);
    }
  });
});

const heartbeatTimer = setInterval(() => {
  runHeartbeatCheck(false)
    .then((res) => {
      console.log(`[Heartbeat] alive=${res.alive}, message=${res.message}`);
    })
    .catch((err) => {
      console.error("[Heartbeat] Unexpected error:", err);
    });
}, HEARTBEAT_INTERVAL_SECONDS * 1000);

// Initial non-blocking check right after startup if credentials were restored from disk
if (sessionState) {
  setTimeout(() => {
    runHeartbeatCheck(false)
      .then((res) => console.log(`[BootCheck] alive=${res.alive}, message=${res.message}`))
      .catch((err) => console.error("[BootCheck] Error:", err));
  }, 2000);
}

server.listen(PORT, HOST, () => {
  console.log(
    `[Server] BUCT electricity gateway listening on http://${HOST}:${PORT} (rooms=${TOTAL_ROOMS}, heartbeat=${HEARTBEAT_INTERVAL_SECONDS}s)`
  );
});

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    console.log(`[Server] Received ${sig}, shutting down...`);
    clearInterval(heartbeatTimer);
    if (usageDirty) {
      try {
        saveUsageImmediate();
      } catch (err) {
        console.error("[Usage] Failed to flush on shutdown:", err);
      }
    }
    server.close(() => process.exit(0));
  });
}
