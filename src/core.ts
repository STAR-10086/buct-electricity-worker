import { RoomMeta } from "./rooms";

export interface SessionState {
  openid: string;
  jsessionid: string;
  alive: boolean;
  updatedAt: number;
  lastHeartbeatAt: number;
  lastCheckedAt: number;
  lastError: string;
}

export interface ElectricityPayload {
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

export interface MissBucket {
  count: number;
  resetAt: number;
}

export interface StudentUsageRecord {
  studentId: string;
  totalQueries: number;
  cacheMissQueries: number;
  firstSeenAt: number;
  lastSeenAt: number;
  lastRoomId: string;
  lastRoomLabel: string;
  recentRooms: string[];
}

export interface BanRecord {
  studentId: string;
  reason: string;
  bannedAt: number;
}

export interface UsageState {
  users: Record<string, StudentUsageRecord>;
  banned: Record<string, BanRecord>;
}

export interface McardResponse {
  success?: boolean;
  message?: string;
  resultData?: Record<string, unknown>;
}

export interface McardCallResult {
  noauth: boolean;
  status: number;
  data: McardResponse | null;
}

export class UpstreamBusyError extends Error {}
export class UpstreamAuthExpiredError extends Error {}
export class UpstreamQueryError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string
  ) {
    super(message);
  }
}

export const MCARD_BASE = "https://mcard.buct.edu.cn";
export const FACTORY_CODE = "E005";
export const INVALID_OPENID = "DCFDE1134D316C1242D25B6EAB6B41A3";
export const WX_USER_AGENT =
  "Mozilla/5.0 (Linux; Android 14; wv) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Version/4.0 Chrome/138.0.7204.180 Mobile Safari/537.36 " +
  "wxwork/5.0.13 MicroMessenger/7.0.1";

export const MAX_UPSTREAM_CONCURRENCY = 5;
export const SIGNATURE_MAX_SKEW_SECONDS = 300;
export const HEX_32_RE = /^[0-9A-F]{32}$/;
export const CLIENT_ID_RE = /^[A-Za-z0-9_-]{4,64}$/;
export const STUDENT_ID_RE = /^[A-Za-z0-9]{6,20}$/;

const JWKS_CACHE_TTL_SECONDS = 3600;
const JWKS_REFRESH_COOLDOWN_SECONDS = 30;

interface CachedJwks {
  keysByKid: Map<string, CryptoKey>;
  fetchedAt: number;
}

const jwksCache = new Map<string, CachedJwks>();
const inflightJwksFetches = new Map<string, Promise<CachedJwks>>();

export type HeaderGetter = (name: string) => string | undefined;

export function parsePositiveInt(raw: string | undefined, fallback: number): number {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function maskHex32(val: string): string {
  const clean = (val || "").trim();
  if (clean.length < 12) return clean ? "***" : "";
  return `${clean.slice(0, 6)}...${clean.slice(-4)}`;
}

export function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Client-Id, X-Student-Id, X-Timestamp, X-Sign",
  };
}

function base64UrlToBytes(b64url: string): Uint8Array<ArrayBuffer> {
  const normalized = b64url.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function normalizeHostname(rawHost: string): string {
  const trimmed = rawHost.trim().toLowerCase();
  if (!trimmed) return "";
  if (trimmed.startsWith("[")) {
    const endIdx = trimmed.indexOf("]");
    return endIdx !== -1 ? trimmed.slice(0, endIdx + 1) : trimmed;
  }
  return trimmed.split(":")[0].trim();
}

function normalizeTeamOrigin(raw: string): string {
  const trimmed = raw.trim().replace(/\/+$/, "");
  if (!trimmed) return "";
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const u = new URL(withScheme);
    if (u.protocol !== "https:") return "";
    return u.origin.toLowerCase();
  } catch {
    return "";
  }
}

async function fetchJwks(teamOrigin: string): Promise<CachedJwks> {
  const existing = inflightJwksFetches.get(teamOrigin);
  if (existing) return existing;

  const task = (async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const resp = await fetch(`${teamOrigin}/cdn-cgi/access/certs`, {
        method: "GET",
        signal: controller.signal,
        headers: { Accept: "application/json" },
      });
      if (!resp.ok) {
        throw new Error(`拉取 Cloudflare Access 公钥失败 (HTTP ${resp.status})`);
      }
      const data = (await resp.json()) as {
        keys?: Array<{
          kid?: string;
          kty?: string;
          alg?: string;
          n?: string;
          e?: string;
          use?: string;
        }>;
      };
      const keysByKid = new Map<string, CryptoKey>();
      for (const k of data.keys || []) {
        if (!k.kid || k.kty !== "RSA" || !k.n || !k.e) continue;
        if (k.alg && k.alg !== "RS256") continue;
        const cryptoKey = await crypto.subtle.importKey(
          "jwk",
          { kty: k.kty, n: k.n, e: k.e, alg: "RS256", ext: true },
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          false,
          ["verify"]
        );
        keysByKid.set(k.kid, cryptoKey);
      }
      if (keysByKid.size === 0) {
        throw new Error("Cloudflare Access certs 未包含有效 RS256 公钥");
      }
      const entry: CachedJwks = { keysByKid, fetchedAt: nowSeconds() };
      jwksCache.set(teamOrigin, entry);
      return entry;
    } finally {
      clearTimeout(timer);
    }
  })();

  inflightJwksFetches.set(teamOrigin, task);
  try {
    return await task;
  } finally {
    inflightJwksFetches.delete(teamOrigin);
  }
}

async function getVerificationKey(teamOrigin: string, kid: string): Promise<CryptoKey | null> {
  const now = nowSeconds();
  let cached = jwksCache.get(teamOrigin);
  if (!cached || now - cached.fetchedAt > JWKS_CACHE_TTL_SECONDS) {
    cached = await fetchJwks(teamOrigin);
  }
  let key = cached.keysByKid.get(kid);
  if (!key && now - cached.fetchedAt > JWKS_REFRESH_COOLDOWN_SECONDS) {
    cached = await fetchJwks(teamOrigin);
    key = cached.keysByKid.get(kid);
  }
  return key ?? null;
}

export interface AdminAuthConfig {
  allowedAdminHost?: string;
  disableZeroTrustCheck?: string;
  cfAccessTeamDomain?: string;
  cfAccessAud?: string;
  allowedAdminEmail?: string;
}

export async function authenticateAdminRequest(
  getHeader: HeaderGetter,
  requestHost: string,
  config: AdminAuthConfig
): Promise<{ ok: true; email: string } | { ok: false; status: number; error: string }> {
  const allowedHostsRaw = (config.allowedAdminHost || "").trim();
  if (allowedHostsRaw) {
    const reqHost = normalizeHostname(requestHost);
    const allowedHosts = new Set(
      allowedHostsRaw
        .split(",")
        .map((h) => normalizeHostname(h))
        .filter(Boolean)
    );
    if (!reqHost || !allowedHosts.has(reqHost)) {
      return { ok: false, status: 404, error: "Not Found" };
    }
  }

  if (config.disableZeroTrustCheck === "true") {
    return { ok: true, email: "local-dev@localhost" };
  }

  const jwt = (getHeader("Cf-Access-Jwt-Assertion") || "").trim();
  if (!jwt) {
    return {
      ok: false,
      status: 403,
      error: "拒绝访问：未检测到 Cloudflare Zero Trust Access 认证凭据",
    };
  }

  const teamOrigin = normalizeTeamOrigin(config.cfAccessTeamDomain || "");
  if (!teamOrigin) {
    return {
      ok: false,
      status: 500,
      error: "服务端未配置 CF_ACCESS_TEAM_DOMAIN，拒绝未验签访问",
    };
  }

  const parts = jwt.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    return { ok: false, status: 401, error: "Zero Trust JWT 格式无效" };
  }

  let header: { alg?: string; kid?: string };
  let payload: {
    iss?: string;
    aud?: string | string[];
    exp?: number;
    nbf?: number;
    email?: string;
  };
  let sigBytes: Uint8Array<ArrayBuffer>;
  try {
    const dec = new TextDecoder();
    header = JSON.parse(dec.decode(base64UrlToBytes(parts[0]))) as typeof header;
    payload = JSON.parse(dec.decode(base64UrlToBytes(parts[1]))) as typeof payload;
    sigBytes = base64UrlToBytes(parts[2]);
  } catch {
    return { ok: false, status: 401, error: "Zero Trust JWT 解码失败" };
  }

  if (header.alg !== "RS256" || typeof header.kid !== "string" || !header.kid) {
    return { ok: false, status: 401, error: "Zero Trust JWT 算法或 kid 无效" };
  }

  let verifyKey: CryptoKey | null;
  try {
    verifyKey = await getVerificationKey(teamOrigin, header.kid);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, status: 502, error: `Zero Trust 公钥获取失败: ${msg}` };
  }

  if (!verifyKey) {
    return { ok: false, status: 401, error: "Zero Trust JWT 签名密钥未匹配" };
  }

  const signedData = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const sigValid = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    verifyKey,
    sigBytes,
    signedData
  );
  if (!sigValid) {
    return { ok: false, status: 401, error: "Zero Trust JWT 签名验证失败" };
  }

  const now = nowSeconds();
  const payloadIss = (payload.iss || "").trim().replace(/\/+$/, "").toLowerCase();
  if (payloadIss !== teamOrigin) {
    return { ok: false, status: 401, error: "Zero Trust JWT 签发者 (iss) 不匹配" };
  }

  if (typeof payload.exp !== "number" || payload.exp <= now) {
    return { ok: false, status: 401, error: "Zero Trust 会话已过期，请刷新页面重新登录" };
  }

  if (typeof payload.nbf === "number" && payload.nbf > now + 60) {
    return { ok: false, status: 401, error: "Zero Trust JWT 尚未生效" };
  }

  const expectedAud = (config.cfAccessAud || "").trim();
  if (expectedAud) {
    const audList = Array.isArray(payload.aud)
      ? payload.aud
      : typeof payload.aud === "string"
        ? [payload.aud]
        : [];
    if (!audList.includes(expectedAud)) {
      return { ok: false, status: 401, error: "Zero Trust JWT 受众 (aud) 不匹配" };
    }
  }

  const signedEmail = typeof payload.email === "string" ? payload.email.trim() : "";
  const allowedRaw = (config.allowedAdminEmail || "").trim();
  if (allowedRaw) {
    const allowedSet = new Set(
      allowedRaw
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    );
    if (!signedEmail || !allowedSet.has(signedEmail.toLowerCase())) {
      return {
        ok: false,
        status: 403,
        error: "拒绝访问：当前账号不在管理员邮箱白名单中",
      };
    }
  }

  return { ok: true, email: signedEmail || "Zero Trust 用户" };
}

export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export async function verifyClientSignatureHeaders(
  getHeader: HeaderGetter,
  roomid: string,
  config: { requireSignature?: string; requireStudentId?: string; appSignSecret?: string }
): Promise<
  | { ok: true; clientId: string; studentId: string }
  | { ok: false; status: number; error: string }
> {
  const requireSig = (config.requireSignature || "false").toLowerCase() === "true";
  const requireStudentId =
    requireSig || (config.requireStudentId || "false").toLowerCase() === "true";
  const rawClientId = (getHeader("X-Client-Id") || "").trim();
  const rawStudentId = (getHeader("X-Student-Id") || "").trim();

  if (rawClientId && !CLIENT_ID_RE.test(rawClientId)) {
    return {
      ok: false,
      status: 400,
      error: "请求头 X-Client-Id 格式无效（仅允许 4~64 位字母数字及 _-）",
    };
  }

  if (rawStudentId && !STUDENT_ID_RE.test(rawStudentId)) {
    return {
      ok: false,
      status: 400,
      error: "请求头 X-Student-Id 格式无效（仅允许 6~20 位字母或数字）",
    };
  }

  if (!requireSig) {
    if (requireStudentId && !rawStudentId) {
      return { ok: false, status: 401, error: "缺少请求头 X-Student-Id" };
    }
    return { ok: true, clientId: rawClientId || "anonymous", studentId: rawStudentId };
  }

  const secret = (config.appSignSecret || "").trim();
  if (!secret) {
    return {
      ok: false,
      status: 500,
      error: "服务端未配置 APP_SIGN_SECRET",
    };
  }

  if (!rawStudentId) {
    return { ok: false, status: 401, error: "缺少请求头 X-Student-Id" };
  }
  if (!rawClientId) {
    return { ok: false, status: 401, error: "缺少请求头 X-Client-Id" };
  }

  const tsRaw = (getHeader("X-Timestamp") || "").trim();
  const signRaw = (getHeader("X-Sign") || "").trim().toLowerCase();
  const ts = Number(tsRaw);
  if (!Number.isInteger(ts) || Math.abs(nowSeconds() - ts) > SIGNATURE_MAX_SKEW_SECONDS) {
    return { ok: false, status: 401, error: "请求时间戳无效或已过期" };
  }
  if (!/^[0-9a-f]{64}$/.test(signRaw)) {
    return { ok: false, status: 401, error: "请求签名格式无效" };
  }

  const expected = await sha256Hex(`${rawStudentId}:${rawClientId}:${roomid}:${ts}:${secret}`);
  if (!timingSafeEqualStr(expected, signRaw)) {
    return { ok: false, status: 401, error: "请求签名校验失败" };
  }

  return { ok: true, clientId: rawClientId, studentId: rawStudentId };
}

export function createEmptyUsageState(): UsageState {
  return { users: {}, banned: {} };
}

export function normalizeUsageState(raw: unknown): UsageState {
  if (!raw || typeof raw !== "object") return createEmptyUsageState();
  const obj = raw as { users?: unknown; banned?: unknown };
  const users: Record<string, StudentUsageRecord> = {};
  const banned: Record<string, BanRecord> = {};

  if (obj.users && typeof obj.users === "object") {
    for (const [k, v] of Object.entries(obj.users as Record<string, unknown>)) {
      if (!STUDENT_ID_RE.test(k) || !v || typeof v !== "object") continue;
      const rec = v as Partial<StudentUsageRecord>;
      users[k] = {
        studentId: k,
        totalQueries: typeof rec.totalQueries === "number" ? rec.totalQueries : 0,
        cacheMissQueries: typeof rec.cacheMissQueries === "number" ? rec.cacheMissQueries : 0,
        firstSeenAt: typeof rec.firstSeenAt === "number" ? rec.firstSeenAt : 0,
        lastSeenAt: typeof rec.lastSeenAt === "number" ? rec.lastSeenAt : 0,
        lastRoomId: typeof rec.lastRoomId === "string" ? rec.lastRoomId : "",
        lastRoomLabel: typeof rec.lastRoomLabel === "string" ? rec.lastRoomLabel : "",
        recentRooms: Array.isArray(rec.recentRooms)
          ? rec.recentRooms.filter((r): r is string => typeof r === "string").slice(0, 15)
          : [],
      };
    }
  }

  if (obj.banned && typeof obj.banned === "object") {
    for (const [k, v] of Object.entries(obj.banned as Record<string, unknown>)) {
      if (!STUDENT_ID_RE.test(k) || !v || typeof v !== "object") continue;
      const b = v as Partial<BanRecord>;
      banned[k] = {
        studentId: k,
        reason: typeof b.reason === "string" ? b.reason : "",
        bannedAt: typeof b.bannedAt === "number" ? b.bannedAt : 0,
      };
    }
  }

  return { users, banned };
}

export function checkBannedStudent(state: UsageState, studentId: string): BanRecord | null {
  if (!studentId) return null;
  return state.banned[studentId] || null;
}

export function buildBanErrorMessage(ban: BanRecord): string {
  const reason = ban.reason.trim() || "异常高频查询";
  return `当前学号因异常查询已被暂停宿舍电费查询权限（原因：${reason}），如有疑问请联系开发者`;
}

export function recordStudentQuery(
  state: UsageState,
  studentId: string,
  roomMeta: RoomMeta,
  isCacheMiss: boolean
): boolean {
  if (!studentId) return false;
  const now = nowSeconds();
  const meterSuffix = roomMeta.meterType ? ` (${roomMeta.meterType})` : "";
  const roomLabel = `${roomMeta.campusName} · ${roomMeta.buildingName} ${roomMeta.roomName}${meterSuffix}`;
  const existing = state.users[studentId];

  if (!existing) {
    state.users[studentId] = {
      studentId,
      totalQueries: 1,
      cacheMissQueries: isCacheMiss ? 1 : 0,
      firstSeenAt: now,
      lastSeenAt: now,
      lastRoomId: roomMeta.roomid,
      lastRoomLabel: roomLabel,
      recentRooms: [roomMeta.roomid],
    };
    return true;
  }

  existing.totalQueries += 1;
  if (isCacheMiss) {
    existing.cacheMissQueries += 1;
  }
  existing.lastSeenAt = now;
  existing.lastRoomId = roomMeta.roomid;
  existing.lastRoomLabel = roomLabel;
  existing.recentRooms = [
    roomMeta.roomid,
    ...existing.recentRooms.filter((r) => r !== roomMeta.roomid),
  ].slice(0, 15);
  return true;
}

export function summarizeUsageState(state: UsageState, searchQuery = "") {
  const q = searchQuery.trim().toLowerCase();
  const userList = Object.values(state.users)
    .filter((u) => !q || u.studentId.toLowerCase().includes(q) || u.lastRoomLabel.toLowerCase().includes(q))
    .map((u) => {
      const ban = state.banned[u.studentId] || null;
      return {
        ...u,
        distinctRoomCount: u.recentRooms.length,
        isBanned: Boolean(ban),
        banReason: ban?.reason || "",
        bannedAt: ban?.bannedAt || 0,
      };
    })
    .sort((a, b) =>
      b.cacheMissQueries - a.cacheMissQueries ||
      b.totalQueries - a.totalQueries ||
      b.lastSeenAt - a.lastSeenAt
    );

  // Include banned students who might not yet have a usage record
  for (const ban of Object.values(state.banned)) {
    if (!state.users[ban.studentId]) {
      if (!q || ban.studentId.toLowerCase().includes(q) || ban.reason.toLowerCase().includes(q)) {
        userList.unshift({
          studentId: ban.studentId,
          totalQueries: 0,
          cacheMissQueries: 0,
          firstSeenAt: 0,
          lastSeenAt: 0,
          lastRoomId: "",
          lastRoomLabel: "无查询记录（手动预拉黑）",
          recentRooms: [],
          distinctRoomCount: 0,
          isBanned: true,
          banReason: ban.reason,
          bannedAt: ban.bannedAt,
        });
      }
    }
  }

  const bannedList = Object.values(state.banned).sort((a, b) => b.bannedAt - a.bannedAt);

  return {
    totalUsers: Object.keys(state.users).length,
    totalBanned: bannedList.length,
    users: userList,
    banned: bannedList,
  };
}

export function normalizeSessionCredentials(
  openidRaw: string | undefined,
  jsessionidRaw: string | undefined
): { ok: true; openid: string; jsessionid: string } | { ok: false; error: string } {
  const openid = (openidRaw || "").trim().toUpperCase();
  const jsessionid = (jsessionidRaw || "")
    .replace(/^JSESSIONID=/i, "")
    .trim()
    .toUpperCase();

  if (!HEX_32_RE.test(openid) || openid === INVALID_OPENID) {
    return { ok: false, error: "openid 格式无效（需为 32 位十六进制字符串）" };
  }
  if (!HEX_32_RE.test(jsessionid)) {
    return { ok: false, error: "JSESSIONID 格式无效（需为 32 位十六进制字符串）" };
  }
  return { ok: true, openid, jsessionid };
}

export function parseBalanceValue(balanceText: string): { value: number | null; unit: string } {
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

export interface UpstreamGateway {
  callMcard(
    path: string,
    payload: Record<string, unknown>,
    openid: string,
    jsessionid: string
  ): Promise<McardCallResult>;
  fetchElectricity(
    roomMeta: RoomMeta,
    state: SessionState,
    onAuthExpired: (errMsg: string) => Promise<void>
  ): Promise<ElectricityPayload>;
}

export function createUpstreamGateway(): UpstreamGateway {
  let inFlightUpstream = 0;
  const inFlightRoomQueries = new Map<string, Promise<ElectricityPayload>>();

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

  async function callMcard(
    path: string,
    payload: Record<string, unknown>,
    openid: string,
    jsessionid: string
  ): Promise<McardCallResult> {
    const cleanSid = jsessionid.replace(/^JSESSIONID=/i, "").trim();
    const targetUrl = `${MCARD_BASE}${path}?openid=${encodeURIComponent(openid.trim())}&connect_redirect=1`;

    return withUpstreamSlot(async () => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12000);
      try {
        const resp = await globalThis.fetch(targetUrl, {
          method: "POST",
          redirect: "manual",
          signal: controller.signal,
          headers: {
            "Content-Type": "application/json",
            Cookie: `JSESSIONID=${cleanSid}`,
            "User-Agent": WX_USER_AGENT,
            "X-Requested-With": "XMLHttpRequest",
          },
          body: JSON.stringify(payload),
        });

        const noauthHeader =
          (resp.headers.get("Noauthentication") || "").toLowerCase() === "true";
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
      } finally {
        clearTimeout(timer);
      }
    });
  }

  async function fetchElectricity(
    roomMeta: RoomMeta,
    state: SessionState,
    onAuthExpired: (errMsg: string) => Promise<void>
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
        const msg = res.data?.message || `上游会话已过期 (HTTP ${res.status})`;
        if (state.alive) {
          await onAuthExpired(msg);
        }
        throw new UpstreamAuthExpiredError("上游认证会话已过期，等待管理员刷新");
      }

      if (!res.data?.success) {
        throw new UpstreamQueryError(
          502,
          res.data?.message || `电表不在线或上游查询失败 (HTTP ${res.status})`
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

  return { callMcard, fetchElectricity };
}
