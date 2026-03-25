# Changelog

所有重要更改均记录在此文件中。

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
