function escapeHtml(raw: string): string {
  return raw
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * Renders the Zero Trust protected single-page admin console.
 */
export function renderAdminHtml(adminEmail: string): string {
  const safeEmail = escapeHtml(adminEmail || "Zero Trust 已验证用户");
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>BUCT 电费网关 · 管理台</title>
  <style>
    :root {
      --bg: #0b1120;
      --card: #131c31;
      --card-inner: #0a101d;
      --border: #24324d;
      --text: #f1f5f9;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --ok: #22c55e;
      --err: #ef4444;
      --warn: #f59e0b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 24px 16px 48px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
    }
    .container {
      max-width: 760px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
    }
    h1 { font-size: 20px; margin: 0 0 6px 0; }
    h2 { font-size: 15px; margin: 0 0 12px 0; color: var(--accent); }
    .sub { font-size: 13px; color: var(--muted); }
    .header-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      flex-wrap: wrap;
    }
    .identity-pill {
      font-size: 12px;
      padding: 4px 10px;
      border-radius: 999px;
      background: rgba(56, 189, 248, 0.12);
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.25);
    }
    label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
    input[type="text"] {
      width: 100%;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--card-inner);
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 13px;
      margin-bottom: 12px;
      outline: none;
    }
    input[type="text"]:focus { border-color: var(--accent); }
    .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
    button {
      padding: 9px 15px;
      border-radius: 8px;
      border: none;
      background: var(--accent);
      color: #082f49;
      font-weight: 600;
      cursor: pointer;
      font-size: 13px;
    }
    button:disabled { opacity: 0.55; cursor: not-allowed; }
    button.secondary { background: #24324d; color: var(--text); }
    .dropzone {
      border: 2px dashed var(--border);
      border-radius: 12px;
      padding: 26px 16px;
      text-align: center;
      cursor: pointer;
      transition: border-color 0.2s, background 0.2s;
      margin-bottom: 14px;
      background: rgba(10, 16, 29, 0.45);
    }
    .dropzone.dragover {
      border-color: var(--accent);
      background: rgba(56, 189, 248, 0.08);
    }
    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
    }
    .badge.ok { background: rgba(34, 197, 94, 0.16); color: var(--ok); }
    .badge.err { background: rgba(239, 68, 68, 0.16); color: var(--err); }
    .badge.warn { background: rgba(245, 158, 11, 0.16); color: var(--warn); }
    .kv-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 10px;
      margin-top: 12px;
    }
    .kv-item {
      background: var(--card-inner);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px 12px;
    }
    .kv-label { font-size: 11px; color: var(--muted); }
    .kv-val {
      font-size: 13px;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      margin-top: 2px;
      word-break: break-all;
    }
    pre {
      background: var(--card-inner);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      font-size: 12px;
      overflow-x: auto;
      margin: 12px 0 0 0;
      white-space: pre-wrap;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="header-row">
        <div>
          <h1>BUCT 电费查询网关 · 管理台</h1>
          <div class="sub">Zero Trust 鉴权保护 · 仅管理员自用 · 支持拖入 ProxyPin HAR 解析或手填凭证</div>
        </div>
        <div class="identity-pill" id="adminEmailPill">${safeEmail}</div>
      </div>
    </div>

    <div class="card">
      <div class="header-row" style="align-items: center; margin-bottom: 8px;">
        <h2 style="margin: 0;">1. 上游会话与 Cron 保活状态</h2>
        <div class="row">
          <button class="secondary" onclick="fetchStatus()">刷新状态</button>
          <button onclick="triggerHeartbeat()">立即验活心跳</button>
        </div>
      </div>
      <div id="statusSummary" class="sub">正在加载状态...</div>
      <div class="kv-grid" id="statusGrid"></div>
    </div>

    <div class="card">
      <h2>2. 更新会话凭证（HAR 自动提取 / 手填 JSESSIONID）</h2>
      <div class="dropzone" id="dropzone" onclick="document.getElementById('harInput').click()">
        <div style="font-size: 14px; font-weight: 600; margin-bottom: 4px;">点击选择或将 ProxyPin .har 文件拖入此处</div>
        <div class="sub">纯浏览器本地解析 mcard.buct.edu.cn（按时间升序自动提取最新 openid 与 Set-Cookie）</div>
        <input type="file" id="harInput" accept=".har,.json" style="display:none" onchange="handleFile(this.files[0])" />
      </div>

      <label>OpenID（32 位十六进制，本机自动记住，日常无需重复填写）</label>
      <input type="text" id="openidInput" placeholder="输入或从 HAR 提取 32 位十六进制 OpenID" />

      <label>JSESSIONID（32 位十六进制，可留空仅解析或抓包粘贴新值）</label>
      <input type="text" id="jsessionidInput" placeholder="输入或从 HAR 提取 32 位 JSESSIONID（不含 JSESSIONID= 前缀也可）" />

      <div class="row">
        <button onclick="applySession()">验活并写入 KV</button>
        <button class="secondary" onclick="clearSavedOpenid()">清除本机记住的 OpenID</button>
      </div>
      <pre id="parseLog" style="display:none;"></pre>
    </div>

    <div class="card">
      <h2>3. 管理员在线查电费测试（不计入客户端限流）</h2>
      <div class="row" style="align-items: flex-end;">
        <div style="width: 160px;">
          <label>校区 ID (schoolid)</label>
          <input type="text" id="testSchoolId" value="1503634598" style="margin-bottom: 0;" />
        </div>
        <div style="flex: 1; min-width: 220px;">
          <label>房间 ID (roomid)</label>
          <input type="text" id="testRoomId" value="CCPS.BUCT.B0601.F01.R0102" style="margin-bottom: 0;" />
        </div>
        <button class="secondary" onclick="testQuery()">测试查询</button>
      </div>
      <pre id="testOutput" style="display:none;"></pre>
    </div>
  </div>

  <script>
    var INVALID_OPENID = "DCFDE1134D316C1242D25B6EAB6B41A3";
    var LS_OPENID_KEY = "buct_ele_admin_openid";

    var openidEl = document.getElementById("openidInput");
    var sidEl = document.getElementById("jsessionidInput");
    var savedOpenid = localStorage.getItem(LS_OPENID_KEY) || "";
    if (savedOpenid) {
      openidEl.value = savedOpenid;
    }

    var dz = document.getElementById("dropzone");
    dz.addEventListener("dragover", function (e) {
      e.preventDefault();
      dz.classList.add("dragover");
    });
    dz.addEventListener("dragleave", function () {
      dz.classList.remove("dragover");
    });
    dz.addEventListener("drop", function (e) {
      e.preventDefault();
      dz.classList.remove("dragover");
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleFile(e.dataTransfer.files[0]);
      }
    });

    function showPre(elId, text) {
      var el = document.getElementById(elId);
      el.style.display = "block";
      el.textContent = text;
    }

    function fmtTime(sec) {
      if (!sec) return "无";
      return new Date(sec * 1000).toLocaleString("zh-CN", { hour12: false });
    }

    async function apiFetch(url, options) {
      var opts = options || {};
      opts.credentials = "same-origin";
      opts.redirect = "manual";
      var resp;
      try {
        resp = await fetch(url, opts);
      } catch (err) {
        throw new Error("请求失败（若 Zero Trust 登录过期，请刷新整页重新认证）: " + err.message);
      }
      if (resp.type === "opaqueredirect" || resp.status === 302) {
        throw new Error("Zero Trust 会话已过期，请刷新当前页面重新登录");
      }
      var text = await resp.text();
      var data;
      try {
        data = JSON.parse(text);
      } catch (_) {
        throw new Error("服务端返回非 JSON（HTTP " + resp.status + "），请尝试刷新页面重新认证");
      }
      if (!resp.ok) {
        throw new Error(data.error || data.detail || ("HTTP " + resp.status));
      }
      return data;
    }

    function renderStatus(data) {
      var summary = document.getElementById("statusSummary");
      var grid = document.getElementById("statusGrid");
      summary.innerHTML = "";
      grid.innerHTML = "";

      var badge = document.createElement("span");
      badge.className = "badge " + (data.alive ? "ok" : (data.openidMasked ? "err" : "warn"));
      badge.textContent = data.alive ? "在线保活中" : (data.openidMasked ? "会话已失效 / 离线" : "尚未配置会话");
      summary.appendChild(badge);

      if (data.lastError) {
        var errSpan = document.createElement("span");
        errSpan.style.color = "var(--err)";
        errSpan.style.marginLeft = "10px";
        errSpan.textContent = "最近错误: " + data.lastError;
        summary.appendChild(errSpan);
      }

      var items = [
        ["OpenID（脱敏）", data.openidMasked || "未配置"],
        ["JSESSIONID（脱敏）", data.jsessionidMasked || "未配置"],
        ["凭证更新时间", fmtTime(data.updatedAt)],
        ["最近心跳成功", fmtTime(data.lastHeartbeatAt)],
        ["最近心跳检查", fmtTime(data.lastCheckedAt)],
        ["静态白名单房间数", String(data.totalRooms || 0)]
      ];

      for (var i = 0; i < items.length; i++) {
        var box = document.createElement("div");
        box.className = "kv-item";
        var lbl = document.createElement("div");
        lbl.className = "kv-label";
        lbl.textContent = items[i][0];
        var val = document.createElement("div");
        val.className = "kv-val";
        val.textContent = items[i][1];
        box.appendChild(lbl);
        box.appendChild(val);
        grid.appendChild(box);
      }
    }

    async function fetchStatus() {
      try {
        var data = await apiFetch("/admin/api/status");
        renderStatus(data);
      } catch (err) {
        var summary = document.getElementById("statusSummary");
        summary.textContent = "加载状态失败: " + err.message;
      }
    }

    async function triggerHeartbeat() {
      try {
        var data = await apiFetch("/admin/api/heartbeat", { method: "POST" });
        showPre("parseLog", (data.alive ? "心跳验活成功: " : "心跳验活失败: ") + data.message);
        await fetchStatus();
      } catch (err) {
        showPre("parseLog", "心跳请求异常: " + err.message);
      }
    }

    async function handleFile(file) {
      if (!file) return;
      try {
        var raw = await file.text();
        var har = JSON.parse(raw);
        var entries = ((har.log && har.log.entries) || [])
          .filter(function (e) {
            return e && e.request && e.request.url && e.request.url.indexOf("mcard.buct.edu.cn") !== -1;
          })
          .sort(function (a, b) {
            return String(a.startedDateTime || "").localeCompare(String(b.startedDateTime || ""));
          });

        if (entries.length === 0) {
          showPre("parseLog", "未在 " + file.name + " 中找到 mcard.buct.edu.cn 请求记录。");
          return;
        }

        var foundOpenid = "";
        var foundJsessionid = "";
        var timeline = [];

        for (var i = 0; i < entries.length; i++) {
          var e = entries[i];
          var url = e.request.url || "";
          var ts = e.startedDateTime || "";

          var urlMatch = url.match(/[?&]openid=([0-9A-Fa-f]{32})/);
          if (urlMatch && urlMatch[1].toUpperCase() !== INVALID_OPENID) {
            foundOpenid = urlMatch[1].toUpperCase();
          }

          var postText = (e.request.postData && e.request.postData.text) || "";
          var bodyMatch = postText.match(/"openid"\\s*:\\s*"([0-9A-Fa-f]{32})"/);
          if (bodyMatch && bodyMatch[1].toUpperCase() !== INVALID_OPENID) {
            foundOpenid = bodyMatch[1].toUpperCase();
          }

          var reqHeaders = e.request.headers || [];
          for (var j = 0; j < reqHeaders.length; j++) {
            var rh = reqHeaders[j];
            if (rh.name && rh.name.toLowerCase() === "cookie" && rh.value) {
              var rm = rh.value.match(/JSESSIONID=([0-9A-Fa-f]{32})/i);
              if (rm) {
                foundJsessionid = rm[1].toUpperCase();
                timeline.push("[" + ts + "] Req Cookie -> " + foundJsessionid);
              }
            }
          }

          var respHeaders = (e.response && e.response.headers) || [];
          for (var k = 0; k < respHeaders.length; k++) {
            var sh = respHeaders[k];
            if (sh.name && sh.name.toLowerCase() === "set-cookie" && sh.value) {
              var sm = sh.value.match(/JSESSIONID=([0-9A-Fa-f]{32})/i);
              if (sm) {
                foundJsessionid = sm[1].toUpperCase();
                timeline.push("[" + ts + "] Resp Set-Cookie -> " + foundJsessionid);
              }
            }
          }
        }

        if (foundOpenid) {
          openidEl.value = foundOpenid;
          localStorage.setItem(LS_OPENID_KEY, foundOpenid);
        }
        if (foundJsessionid) {
          sidEl.value = foundJsessionid;
        }

        showPre(
          "parseLog",
          "已解析 " + file.name + "（匹配 " + entries.length + " 条 mcard 请求）：\\n" +
          "OpenID     = " + (foundOpenid || "未找到（保留现有输入框）") + "\\n" +
          "JSESSIONID = " + (foundJsessionid || "未找到") + "\\n\\n" +
          "会话轨迹（按时间升序）：\\n" + timeline.join("\\n")
        );
      } catch (err) {
        showPre("parseLog", "解析 HAR 失败: " + err.message);
      }
    }

    async function applySession() {
      var openid = openidEl.value.trim().toUpperCase();
      var jsessionid = sidEl.value.replace(/JSESSIONID=/i, "").trim().toUpperCase();
      if (!openid || !jsessionid) {
        showPre("parseLog", "请填写完整的 32 位 OpenID 与 JSESSIONID，或先拖入 HAR 文件解析。");
        return;
      }
      localStorage.setItem(LS_OPENID_KEY, openid);
      showPre("parseLog", "正在向学校服务器验活并写入 KV...");
      try {
        var data = await apiFetch("/admin/api/session", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ openid: openid, jsessionid: jsessionid })
        });
        showPre("parseLog", data.message || "更新成功");
        await fetchStatus();
      } catch (err) {
        showPre("parseLog", "更新失败: " + err.message);
      }
    }

    function clearSavedOpenid() {
      localStorage.removeItem(LS_OPENID_KEY);
      openidEl.value = "";
      showPre("parseLog", "已清除本机记住的 OpenID。");
    }

    async function testQuery() {
      var sid = encodeURIComponent(document.getElementById("testSchoolId").value.trim());
      var rid = encodeURIComponent(document.getElementById("testRoomId").value.trim());
      showPre("testOutput", "查询中...");
      try {
        var data = await apiFetch("/admin/api/test-query?schoolid=" + sid + "&roomid=" + rid);
        showPre("testOutput", JSON.stringify(data, null, 2));
      } catch (err) {
        showPre("testOutput", "查询失败: " + err.message);
      }
    }

    fetchStatus();
  </script>
</body>
</html>`;
}
