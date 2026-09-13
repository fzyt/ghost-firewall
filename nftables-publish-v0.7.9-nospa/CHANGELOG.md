# Changelog

所有重要更改均记录在此文件中。

## [v0.7.9.1] - 2026-09-13

### 安全加固（11 项审查全部修复）

#### High 修复
- **上传大小限制**：`app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024`
  - 在 `before_request` 早期主动检查 `Content-Length` header（不依赖 Werkzeug 惰性读 body），超限直接返回 413 `PAYLOAD_TOO_LARGE`
  - 证书 < 10KB、反代规则配置几百字节；16MB 富余足够
- **IPv6 客户端拒绝**：`before_request` 早期判断 `':' in request.remote_addr` → 403 `IPV6_NOT_ALLOWED`
  - 管理界面只支持 IPv4
  - defense-in-depth：服务当前监听 `0.0.0.0:5443`，IPv6 客户端本就连不上；代码层加固是给将来启用 IPv6 监听兜底

#### Medium 修复
- **`_failed_logins` 内存泄漏防御**：
  - `_MAX_FAILED_LOGINS_IPS = 50000` IP 数硬上限（防恶意创建大量 IP 条目撑爆内存）
  - `_gc_failed_logins()` 每 100 次请求触发一次全局 GC，清理过期 IP 条目
- **`/api/auth/change-password` 加限流**：
  - 复用 `_check_rate_limit`（5 次失败锁 15 分钟）
  - 旧密码错误也记录失败 → `_record_login_failure(client_ip)`
  - 修改密码成功 → `_clear_login_failures(client_ip)`
  - 防暴力枚举旧密码
- **CSP 响应头**：内网单页应用适配
  ```
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;
  connect-src 'self'; frame-ancestors 'none'; base-uri 'self'
  ```
- **`save_config` 异常不要吞错**：
  - fcntl 锁失败记录 `WARNING` 后回退到无锁模式
  - 真正写失败必须 `raise`，让上层调用方能感知保存失败

#### 其他校验加固
- **`_sanitize_target_address` 加强校验**（反代规则 target_address 字段）：
  - IPv4：每段严格 0-255，否则 `IPv4 段数或越界`
  - port：必须数字，且 1-65535
  - host：不能为空
  - domain：复用 `_sanitize_domain` 严格校验（a-z 0-9 - .）

#### 测试
- 综合测试 70/70 全过（无回归）
- v0.7.9.1 专项验证全部通过：
  - CSP header ✅
  - change-password 限流：前 5 次 401，第 6-7 次 429 ✅
  - MAX_CONTENT_LENGTH：17MB upload → 413 `PAYLOAD_TOO_LARGE` ✅
  - `_sanitize_target_address`：IPv4 越界 / port 越界 / port 非数字 / 缺端口 / 非法 domain 都正确拒绝 ✅
  - IPv6：服务监听 `0.0.0.0:5443`，IPv6 客户端连不上 ✅

#### ⚠️ 状态
- 未完整验证版本 — 由 AI agent 自动完成，未经生产环境手动验证
- 建议先在测试环境部署验证，确认无误后再升级生产

---

## [v0.7.9] - 2026-09-13

### 安全加固（首版认证 + HTTPS + 限流 + dry-run + 风险检测）

#### 主要改动
- **认证系统**：PBKDF2-HMAC-SHA256 (200000 轮) + Flask session + 全局 `before_request` 拦截
- **限流**：5 次登录失败锁 IP 15 分钟（IP-based 内存 dict）
- **HTTPS**：自签证书自动生成 + HTTP:5000 → HTTPS:5443 重定向
- **反代证书自动接管**：扫 `/etc/nginx/ssl/` 优先用反代证书，自签 fallback
- **SSL 启动失败**：`sys.exit(1)` 拒绝明文 HTTP（避免密码明文传输）
- **安全响应头**：HSTS + X-Content-Type-Options + Referrer-Policy
- **Cookie**：HttpOnly + SameSite=Lax（CSRF 防护）

#### dry-run preview-changes
- `POST /api/rules/preview-changes`：模拟配置变更，不写文件、不应用 nft
- 风险检测 3 条规则：SSH 端口移除 / trusted_ip4 移除自己 IP / access_mode 变化
- 完整 diff 摘要 + 新规则文本

#### Bug 修复
- 部署路径：`app.py` 应在 `backend/` 子目录（之前错位导致 `/` 和 `/app.js` 返回 404）
- 反代 rule_id 重复：同 domain 已存在时 update 而非 append
- 黑名单 set flags：`blacklist4/6 flags` 是 dynamic 不支持 timeout，自动改永久写入
- nft timeout 语法：`timeout 18000s`（无空格+紧跟 s）兼容 OpenWrt nft 1.1.1
- 限制规则 / 黑名单 apply 时 nft set 不存在的错误处理
- `template_engine.py`：支持 list → nftables 集合语法 `{ a, b, c }`

#### 安全修复
- **Host Header 注入**：重定向 URL 用 `router_ip4` 配置，不用 `HTTP_HOST`

#### 前端
- 429 RATE_LIMITED 拦截
- diffModal Alpine state + saveConfig 改造（先 preview-changes → 弹 modal → 确认才 POST）
- HTTP 不安全警告 banner（指向 :5443）
- diff modal（风险警告 + diff 摘要 + 新增/删除行样例 + 完整新规则折叠）

#### ⚠️ 状态
- 未完整验证版本 — 由 AI agent 自动完成

---

## [v0.7.7] - 2026-03-22

### 修复
- **反向代理**：修复非标准端口反代时移动端登录失败的问题
  - `proxy_set_header Host $host;` → `proxy_set_header Host $http_host;`
  - `$http_host` 包含完整端口号，解决 DSM 移动端登录校验 Host 端口失败返回空响应的问题

## [v0.7.6] - 2026-03-22

### 修复

- 修复反向代理群晖 DSM 登录后提示"登录信息过期"的问题

### 变更详情

**Nginx 反代配置新增：**

- `proxy_set_header Host $http_host;` — 传递完整 Host 头（含端口号），解决手机端登录校验失败问题
- `proxy_set_header X-Forwarded-Host $host;` — 传递原始 Host
- `proxy_set_header X-Forwarded-Port $server_port;` — 传递原始端口
- `proxy_cookie_domain ~^(\d+\.\d+\.\d+\.\d+) $host;` — Cookie 域重写，将群晖 IP 的 Cookie 域改为反代域名
- `proxy_buffering off;` — 关闭代理缓冲
- `proxy_request_buffering off;` — 关闭请求缓冲

**超时调整：**

- `proxy_send_timeout` 和 `proxy_read_timeout` 从 60s 调整为 300s
