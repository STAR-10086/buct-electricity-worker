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
    "Access-Control-Allow-Headers": "Content-Type, X-Client-Id, X-Timestamp, X-Sign",
  };
}

export function parseJwtEmail(jwtToken: string): { email: string; expired: boolean } {
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

export function authenticateAdminHeaders(
  getHeader: HeaderGetter,
  config: { disableZeroTrustCheck?: string; allowedAdminEmail?: string }
): { ok: true; email: string } | { ok: false; status: number; error: string } {
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

  const parsed = parseJwtEmail(jwt);
  if (parsed.expired) {
    return {
      ok: false,
      status: 401,
      error: "Zero Trust 会话已过期，请刷新页面重新登录",
    };
  }

  const headerEmail = (getHeader("Cf-Access-Authenticated-User-Email") || "").trim();
  const effectiveEmail = headerEmail || parsed.email;

  const allowedRaw = (config.allowedAdminEmail || "").trim();
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
  config: { requireSignature?: string; appSignSecret?: string }
): Promise<{ ok: true; clientId: string } | { ok: false; status: number; error: string }> {
  const requireSig = (config.requireSignature || "false").toLowerCase() === "true";
  const rawClientId = (getHeader("X-Client-Id") || "").trim();

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

  const secret = (config.appSignSecret || "").trim();
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

  const tsRaw = (getHeader("X-Timestamp") || "").trim();
  const signRaw = (getHeader("X-Sign") || "").trim().toLowerCase();
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
