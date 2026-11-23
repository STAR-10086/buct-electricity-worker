# buct-electricity-worker

北京化工大学（BUCT）宿舍电费只读查询网关，同时支持 **VPS Docker（Node.js 22 零运行时依赖）** 与 **Cloudflare Workers** 两种运行方式，管理员后台受 **Cloudflare Zero Trust Access** 保护。

> **重要说明**：实测学校校园卡上游（`mcard.buct.edu.cn` 前置 Caddy 网关）会对 Cloudflare Workers 出口 IP 段（AS13335）返回 **`HTTP 418`** 拦截，而公网普通 VPS / 家宽 IP 均可正常 `HTTP 200` 访问。因此推荐直接运行本仓库内置的 **VPS Docker 版本**，前端依然挂在 Cloudflare DNS / Cloudflare Tunnel + Zero Trust 下，Zero Trust 策略与 `/admin` 控制台完全复用！

---

## 核心特性

1. **只读代理与全校房间白名单**：
   - 内置昌平、东区、西区共 3 校区、33 栋楼、190 层、10,028 条合法房间/电表字典（`src/rooms.json`）。
   - 非法 `(schoolid, roomid)` 直接在网关返回 `400`，不向上游发起请求。
2. **缓存优先 + 8 分钟自动心跳保活**：
   - 电费查询结果默认缓存 **15 分钟**（`CACHE_TTL_SECONDS = 900`），缓存命中直接返回，不消耗限流配额、不请求学校接口。
   - 内置后台定时任务（`480s` / 8 分钟一次）自动调用 `/channel/getXiaoQuList` 刷新学校 Tomcat `JSESSIONID` 空闲计时器；会话状态持久化到 `/data/session_state.json`。
3. **适配校园网同出口 IP 的多端精准限流与学号防滥用黑名单**：
   - **不做粗暴 IP 封锁**（避免北化校园网共用 NAT 出口 IP 导致全校误伤）。
   - 同时按设备 `X-Client-Id` 与学号 `X-Student-Id` 对**未命中缓存的回源查询**限流：默认每 **10 分钟**最多 **3 次**新房间回源查询（已缓存房间可无限次刷新）。
   - 开启签名鉴权（`REQUIRE_APP_SIGNATURE = "true"`）时强校验 `X-Student-Id`、`X-Client-Id`、`X-Timestamp` 与 `X-Sign = SHA-256(studentId:clientId:roomid:timestamp:APP_SIGN_SECRET)`。
   - 服务端记录每个学号的总查询次数、回源次数与最近查询房间，并在 `/admin` 管理台提供一键拉黑 / 解封开关（持久化至 `/data/usage_state.json`，拉黑后直接拦截返回 `403`）。
   - 内置上游并发上限（最多同时 5 个回源请求）与同房间请求合并（singleflight）。
4. **Zero Trust 管理员控制台（`/admin`）**：
   - 无硬编码密码或静态 Token，管理员路由受 Cloudflare Zero Trust Access 保护：服务端通过 `CF_ACCESS_TEAM_DOMAIN/cdn-cgi/access/certs` 拉取 Cloudflare 官方 JWKS 公钥，使用 `RS256` 严格校验 `Cf-Access-Jwt-Assertion` 数字签名、`iss`、`exp`、可选 `CF_ACCESS_AUD` 及已签名 JWT 内的 `email` 白名单（`ALLOWED_ADMIN_EMAIL`），并支持通过 `ALLOWED_ADMIN_HOST` 将管理台隔离到独立域名（未配置域名命中直接返回 `404`），彻底杜绝在 Cloudflare for SaaS / 多域名场景下伪造 `Cf-Access-*` 请求头绕过鉴权。
   - 内置单页控制台，支持**直接拖入 ProxyPin `.har` 文件在浏览器本地解析最新 `openid` 与 `Set-Cookie: JSESSIONID`**，或**直接手填更新**，提交前自动向学校接口验活。

---

## VPS Docker 部署指南（推荐，绕过学校对 Cloudflare Workers IP 的 418 拦截）

### 第 1 步：在 VPS 上拉取代码并启动容器

```bash
git clone https://github.com/STAR-10086/buct-electricity-worker.git
cd buct-electricity-worker

# 创建 .env：务必配置 CF_ACCESS_TEAM_DOMAIN 以开启 Zero Trust RS256 公钥验签
cat > .env << 'EOF'
CF_ACCESS_TEAM_DOMAIN=your-team.cloudflareaccess.com
ALLOWED_ADMIN_EMAIL=your-email@example.com
# 如使用 SaaS 优选域名对外服务、独立橙色云朵域名进后台，建议绑定管理台域名（不匹配直接 404）
ALLOWED_ADMIN_HOST=admin.example.com
# 可选：填 Zero Trust Application 中的 AUD 标签进一步绑定指定应用
CF_ACCESS_AUD=
REQUIRE_APP_SIGNATURE=false
APP_SIGN_SECRET=
EOF

docker compose up -d --build
```

启动后验证本机监听（默认仅监听 `127.0.0.1:8080`，防止外网直接绕过 Cloudflare Zero Trust 访问 IP）：

```bash
curl http://127.0.0.1:8080/v1/health
```

### 第 2 步：从 Cloudflare Workers 解绑 `ele.buct.one`

如果你此前把 `ele.buct.one` 绑在了 Cloudflare Workers Custom Domains 上：
1. 进入 Cloudflare Dashboard → **Workers & Pages → `buct-electricity-worker` → Settings → Domains & Routes**。
2. 删除 `ele.buct.one` 的 Custom Domain 绑定（Cloudflare 会自动清理原来的 Worker 路由与占位 DNS 记录）。

### 第 3 步：将 `ele.buct.one` 指向 VPS 的 `127.0.0.1:8080`

任选以下两种方式之一（推荐方式 A）：

- **方式 A（推荐）：Cloudflare Tunnel（无需在 VPS 开 80/443，也不用配 SSL 证书）**
  1. 在 Cloudflare **Zero Trust → Networks → Tunnels** 创建或复用现有 Tunnel，并在 VPS 上运行 `cloudflared`。
  2. 为该 Tunnel 添加一条 **Public Hostname**：
     - Subdomain：`ele`
     - Domain：`buct.one`
     - Service：`HTTP` → `127.0.0.1:8080`（如果 `cloudflared` 也跑在同一个 Docker 网络里，可填 `http://buct-electricity:8080` 并把两容器连入同一 Docker network）。

- **方式 B：Nginx / Caddy 反代 + Cloudflare 橙色云朵代理**
  1. 在 Cloudflare **DNS → Records** 添加一条 `ele` 指向你 VPS 公网 IP 的 `A` 记录，务必保持 **Proxied（橙色云朵）开启**（否则 `Cf-Access-*` 头与 Zero Trust 不会生效）。
  2. 在 VPS 现有的 Caddy 或 Nginx 中反代 `ele.buct.one` 到 `http://127.0.0.1:8080`。

### 第 4 步：确认 Zero Trust 策略与后台域名隔离

- 在 **Cloudflare Zero Trust → Access → Applications** 中保护管理台域名（路径填 `admin*`）；流量经过 Cloudflare 边缘节点进入 VPS 之前会触发 Zero Trust 登录，VPS 服务端再通过 `CF_ACCESS_TEAM_DOMAIN` 校验 `Cf-Access-Jwt-Assertion` 的 RS256 签名及 `ALLOWED_ADMIN_EMAIL`。
- 若对外查电费域名使用了 **Cloudflare for SaaS 优选**（CNAME 到未直接绑定 Zero Trust 的域名），强烈建议通过 `ALLOWED_ADMIN_HOST` 仅允许专属橙色云朵管理域名访问 `/admin*`，公开优选域名访问 `/admin*` 将直接返回 `404`。
- `/v1/*` 不在 Zero Trust 路径范围内，供客户端直接请求。

### 第 5 步：初始化凭证

1. 浏览器访问 `https://ele.buct.one/admin`，通过 Cloudflare Zero Trust 邮箱验证登录。
2. 拖入在企业微信「校园卡服务」抓包导出的 ProxyPin `.har` 文件（或手动填写 `openid` 与 `JSESSIONID`），点击 **「验活并写入 KV」**。
3. 会话状态会保存在宿主机的 `./data/session_state.json`，容器重启不会丢失；后台每 8 分钟自动向 `mcard.buct.edu.cn` 发送一次保活心跳。

---

## API 说明

### 公开接口（供客户端调用）

- `GET /v1/health`：查看网关是否存活及基础元信息（不含任何个人凭据）。
- `GET /v1/rooms`：获取全校校区、楼栋、楼层与房间 `roomid` 字典（带 24 小时浏览器/边缘缓存）。
- `GET /v1/electricity?schoolid=<校区ID>&roomid=<房间ID>`：查询指定房间当前电费余额/剩余度数。
  - 推荐请求头：
    - `X-Client-Id: <客户端随机生成的 UUIDv4>`
    - `X-Student-Id: <当前登录用户学号（经 App 弹窗同意共享）>`
  - 若开启签名模式（`REQUIRE_APP_SIGNATURE = "true"`），上述两头与下面两头均为**必填**：
    - `X-Timestamp: <当前秒级 Unix 时间戳>`
    - `X-Sign: <小写十六进制 SHA-256(studentId + ":" + clientId + ":" + roomid + ":" + timestamp + ":" + APP_SIGN_SECRET)>`

### 管理员接口（仅通过 Cloudflare Zero Trust 后可访问）

- `GET /admin`：管理员单页控制台（HAR 解析、凭证更新、状态监控、测试查询、学号查询统计与拉黑管理）。
- `GET /admin/api/status`：查看当前 `openid` / `JSESSIONID` 脱敏状态与最近心跳时间。
- `POST /admin/api/session`：提交 `{ "openid": "<32位HEX>", "jsessionid": "<32位HEX>" }`，验活成功后持久化。
- `POST /admin/api/heartbeat`：手动立即执行一次心跳验活。
- `GET /admin/api/test-query?schoolid=...&roomid=...`：管理员在线测试电费查询（不计入客户端限流）。
- `GET /admin/api/users?q=`：查询学号维度的查询次数统计与黑名单列表。
- `POST /admin/api/ban`：提交 `{ "studentId": "...", "reason": "..." }` 拉黑指定学号。
- `POST /admin/api/unban`：提交 `{ "studentId": "..." }` 解除指定学号拉黑。

---

## 备选：Cloudflare Workers 部署说明（仅作架构参考）

> 注意：因校方 `mcard.buct.edu.cn` 网关当前对 Cloudflare Workers 出口 IP 返回 `HTTP 418`，Workers 方案目前仅作代码保留（`src/index.ts` + `wrangler.toml`）；如未来校方解除拦截或换用自建出站代理，可按以下方式部署：

1. 在 Cloudflare **Storage & Databases → KV** 创建 `ELE_KV`，在构建命令中通过私有变量 `ELE_KV_ID` 替换占位符：`sed -i "s/REPLACE_WITH_YOUR_KV_NAMESPACE_ID/$ELE_KV_ID/g" wrangler.toml`。
2. `wrangler.toml` 已配置 `workers_dev = false` 与 `crons = ["*/8 * * * *"]`，并通过环境变量 `ALLOWED_ADMIN_EMAIL` 校验 Zero Trust 登录邮箱。

---

## 安全与隐私提示

- **请勿向任何公开仓库提交你个人的 `openid`、`JSESSIONID`、`.env`、`data/` 或抓包 `.har` 文件**；所有会话凭据仅应保存在 VPS 本地 `./data/session_state.json`。
- `.gitignore` 已默认忽略本地临时调研文档、`buct_electricity_rooms.json`、`node_modules/`、`dist/`、`.env`、`data/` 与 `.dev.vars`。
