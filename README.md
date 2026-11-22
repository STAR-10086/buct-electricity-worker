# buct-electricity-worker

北京化工大学（BUCT）宿舍电费只读查询网关，运行在 **Cloudflare Workers + KV + Cron Triggers** 上，管理员后台通过 **Cloudflare Zero Trust Access** 保护。

---

## 核心特性

1. **只读代理与全校房间白名单**：
   - 内置昌平、东区、西区共 3 校区、33 栋楼、190 层、10,028 条合法房间/电表字典（`src/rooms.json`）。
   - 非法 `(schoolid, roomid)` 直接在边缘返回 `400`，不向上游发起请求。
2. **边缘缓存优先 + 零 KV 写心跳保活**：
   - 电费查询结果使用 Cloudflare Edge Cache（`caches.default`）默认缓存 **15 分钟**（`CACHE_TTL_SECONDS = 900`），缓存命中直接返回，不消耗限流配额、不请求学校接口。
   - 定时任务（`*/8 * * * *`）每 8 分钟调用一次 `/channel/getXiaoQuList` 维持学校 Tomcat `JSESSIONID` 活跃；仅当会话状态在 `alive` 与失效间翻转时才写入 `ELE_KV`，正常情况下每日 KV 写入接近 0 次。
3. **适配校园网同出口 IP 的多端精准限流**：
   - **不做粗暴 IP 封锁**（避免北化校园网共用 NAT 出口 IP 导致全校误伤）。
   - 改为按设备 `X-Client-Id` 对**未命中缓存的回源查询**限流：默认每 **10 分钟**最多 **3 次**新房间回源查询（已缓存房间可无限次刷新）。
   - 支持可选轻签名校验（`REQUIRE_APP_SIGNATURE = "true"` 时验证 `X-Timestamp` 与 `X-Sign = SHA-256(clientId:roomid:timestamp:APP_SIGN_SECRET)`）。
   - 单 Worker 实例内置上游并发上限（最多同时 5 个回源请求）与同房间请求合并（singleflight）。
4. **Zero Trust 管理员控制台（`/admin`）**：
   - 无硬编码密码或静态 Token，管理员路由受 Cloudflare Zero Trust Access 保护（Worker 内同时校验 `Cf-Access-Jwt-Assertion` 与可选邮箱白名单 `ALLOWED_ADMIN_EMAIL`）。
   - 内置单页控制台，支持**直接拖入 ProxyPin `.har` 文件在浏览器本地解析最新 `openid` 与 `Set-Cookie: JSESSIONID`**，或**直接手填更新**，提交前自动向学校接口验活。

---

## API 说明

### 公开接口（供客户端调用）

- `GET /v1/health`：查看网关是否存活及基础元信息（不含任何个人凭据）。
- `GET /v1/rooms`：获取全校校区、楼栋、楼层与房间 `roomid` 字典（带 24 小时浏览器/边缘缓存）。
- `GET /v1/electricity?schoolid=<校区ID>&roomid=<房间ID>`：查询指定房间当前电费余额/剩余度数。
  - 推荐请求头：`X-Client-Id: <客户端随机生成的 UUIDv4>`
  - 若开启签名模式（`REQUIRE_APP_SIGNATURE = "true"`），还需附带：
    - `X-Timestamp: <当前秒级 Unix 时间戳>`
    - `X-Sign: <小写十六进制 SHA-256(clientId + ":" + roomid + ":" + timestamp + ":" + APP_SIGN_SECRET)>`

### 管理员接口（仅通过 Cloudflare Zero Trust 后可访问）

- `GET /admin`：管理员单页控制台（HAR 解析、凭证更新、状态监控、测试查询）。
- `GET /admin/api/status`：查看当前 `openid` / `JSESSIONID` 脱敏状态与最近心跳时间。
- `POST /admin/api/session`：提交 `{ "openid": "<32位HEX>", "jsessionid": "<32位HEX>" }`，验活成功后写入 `ELE_KV`。
- `POST /admin/api/heartbeat`：手动立即执行一次心跳验活。
- `GET /admin/api/test-query?schoolid=...&roomid=...`：管理员在线测试电费查询（不计入客户端限流）。

---

## Cloudflare 部署与 Zero Trust 配置指南

### 第 1 步：创建 Cloudflare KV 命名空间

1. 登录 Cloudflare Dashboard → **Storage & Databases → KV**（或 Workers & Pages → KV）。
2. 点击 **Create a namespace**，名称填 `ELE_KV`，创建后记录下它的 **Namespace ID**。
3. 修改本仓库 `wrangler.toml` 中的：
   ```toml
   [[kv_namespaces]]
   binding = "ELE_KV"
   id = "填入你刚刚创建的_KV_NAMESPACE_ID"
   ```

### 第 2 步：接入 Cloudflare Workers（推荐 Git 原生集成）

1. 在 Cloudflare Dashboard → **Workers & Pages → Create → Continue with GitHub**，选择本仓库 `buct-electricity-worker`。
2. 构建配置保持默认（或安装依赖后部署 `npx wrangler deploy`）；如果已在 `wrangler.toml` 填好 KV ID，Cloudflare 会自动完成 KV 与 Cron Trigger（`*/8 * * * *`）绑定；也可以在 Worker 的 **Settings → Bindings** 手动确认变量名 `ELE_KV` 已绑定。
   - *备选*：如果你更倾向用 GitHub Actions 自动部署，可在 GitHub 仓库 **Settings → Secrets and variables → Actions** 中添加 `CLOUDFLARE_API_TOKEN` 与 `CLOUDFLARE_ACCOUNT_ID`，`.github/workflows/deploy.yml` 会自动执行部署。

### 第 3 步：绑定自定义域名（关闭默认 `workers.dev`）

1. 本项目已在 `wrangler.toml` 设置 `workers_dev = false`，防止绕过自定义域名上的 Zero Trust 策略。
2. 进入 Worker → **Settings → Domains & Routes → Add → Custom domain**，绑定例如 `ele.buct.one`。

### 第 4 步：配置环境变量（建议）

在 Worker → **Settings → Variables and Secrets** 中添加：

- `ALLOWED_ADMIN_EMAIL`（纯文本或 Secret）：填入你允许登录 `/admin` 的邮箱（例如 `your-email@example.com`，支持逗号分隔多个），作为 Zero Trust 之外的第二道邮箱白名单校验。
- `REQUIRE_APP_SIGNATURE`（可选，测试阶段默认 `"false"`）：正式上线 App 对接后可改为 `"true"`。
- `APP_SIGN_SECRET`（Secret，开启签名时必填）：与客户端约定的签名盐值。

### 第 5 步：配置 Cloudflare Zero Trust Access 保护 `/admin*`

1. 进入 Cloudflare **Zero Trust** 控制台 → **Access → Applications → Add an application → Self-hosted**。
2. 配置应用作用域：
   - **Application domain**：子域填 `ele`、域选 `buct.one`、Path 填 `admin*`（或配置两条路径覆盖 `/admin` 与 `/admin/*`；推荐在 Path 填 `admin*` 即可同时拦截 `/admin`、`/admin/` 与 `/admin/api/*`）。
3. 添加 **Policy（放行策略）**：
   - Policy name：`Admin Only`
   - Action：`Allow`
   - Include 规则选择 `Emails`，填入你自己的邮箱（或配置 GitHub OAuth / One-time PIN 邮箱验证码登录）。
4. 保持 `/v1/*` 不在任何 Access Application 保护范围内，以便所有用户无需登录 Zero Trust 即可正常查电费。

### 第 6 步：初始化凭证

1. 在浏览器访问 `https://ele.buct.one/admin`，通过 Zero Trust 登录验证。
2. 在页面中**拖入从企业微信「校园卡服务」抓取的 ProxyPin `.har` 文件**（或直接填写抓包获得的 `openid` 与 `JSESSIONID`），点击 **「验活并写入 KV」**。
3. 之后 Worker 的 `*/8 * * * *` 定时任务会每 8 分钟自动刷新学校服务器会话，可在管理台或 `GET /v1/health` 随时查看存活状态。

---

## 安全与隐私提示

- **请勿向任何公开仓库提交你个人的 `openid`、`JSESSIONID` 或抓包 `.har` 文件**；所有会话凭据仅应保存在 Cloudflare KV 与本机。
- `.gitignore` 已默认忽略本地临时调研文档、`buct_electricity_rooms.json`、`node_modules/` 与 `.dev.vars`。
