# Changelog

所有重要更改均记录在此文件中。

## [v0.8.0] - 2026-10-05

单端口认证网关（多进程架构）。**这一版的重点不是新功能，是把安全边界重新划清。**

### 架构：面板与认证彻底分离

```
进程 A  app.py           面板    5443   仅 LAN，公网不可达
nginx   系统自带          网关    自定义高位端口（默认 8443）
进程 B  auth_gateway.py  认证API  127.0.0.1:<auth_api_port>
```

- **面板不再有任何公网入口**。原先面板监听 `0.0.0.0` 且借用反代私钥（连带触发 HSTS
  `includeSubDomains` 锁死子域，即审查记录里的待定项 N-5），现在一并消失
- **认证服务只绑 `127.0.0.1`**，启动时检查 `AUTH_BIND_HOST`，非回环地址直接退出。
  nftables 侧不为该端口生成任何放行规则
- **认证崩了 = 网关 502 = 公网入口全断，但 LAN 上一切正常**，面板仍能打开修问题。
  这正是原设计稿最担心的「保险丝装在电表箱里」自锁问题

### 新增：单端口认证网关

- 所有服务收敛到**一个端口**，靠 URL 路径前缀区分（`/nas/`、`/dsm/`、`/photos/`）
- `auth_request` 子请求做认证，未认证 401 → 302 跳登录页
- **`public_access` 语义由「放行哪个端口」改为「限制来源」**：
  - `true` → 所有来源可达，但必须先过认证
  - `false` → nginx `allow <lan_subnet>; deny all;`，仅内网可达、不进认证
  - 认证层管「有没有 token」管不了「从哪来」，来源限制必须在 nginx 落地才有效
- **公网暴露面从「N 个反代端口」收敛成 1 个**。`tcp_services` 白名单里，
  网关开启时只放行 `gateway_port` 一个端口
- **网关端口完全可配置**（含家宽常用的非 443 高位端口），不写死
- 首次进入需验证，之后带 token 访问；滑动窗口默认 1800 秒（30 分钟），后台可改
- 新增 `access_log`（此前项目生成的 nginx conf **一条访问记录都没有**），
  记 `$uri` 而非 `$request_uri`，避免把查询串里的敏感参数写进日志

### 新增：认证安全基线

| 项 | 做法 |
|---|---|
| fail-closed | `/auth/verify` 结构上只有两处返回 200（内网豁免 / 校验通过），其余路径含**所有异常**一律 401。测试注入 `load_gateway_config` 与 `parse_token` 抛异常验证过 |
| 限流落盘 | 面板原有 `_failed_logins` 是内存 dict，**进程重启即清零 → 等重启即可绕过**。本进程计数落盘 + `fcntl` 锁 |
| token 密钥域分离 | 从 SECRET 文件派生独立子密钥，不复用 Flask `SECRET_KEY` |
| 续期换 jti | 每次续期重新签发，杜绝旧 token 重放 |
| 幂等时间比较 | 签名比对统一走 `hmac.compare_digest` |
| CSRF | 登录端点校验 `Origin`/`Referer`，跨站直接 403 |
| 抗枚举 | 登录失败响应体对「密码错」与「未设密码」完全一致 |
| 弱哈希拒绝 | PBKDF2 迭代数 < 100000 的存量哈希直接判失败，而不是降级接受 |
| Bearer 支持 | `/auth/verify` 同时认 cookie 与 `Authorization: Bearer`，供脚本使用 |
| 审计落盘 | 登录/登出/续期/拒绝全部写 JSONL，含来源 IP、设备标识、指纹、UA |

### 新增：日志页重构（设备指纹并入 + log_size 可调 + 远程转发）

在 `.224` 真机实测后重写。四条都是实测出来的，不是设想。

**① 认证审计并入系统日志时间线（此前完全看不到）**

`app.py` 从来没读过 `/var/log/nftables-web-auth.log`。认证服务一直在采集
设备指纹并落盘，面板却一条都显示不出来 —— 数据在采，但没有出口。
现在 `/api/system/logs` 同时读 `logread` 和该 JSONL，按时间倒序合并成一条时间线，
认证事件来源标记为 `nftables-web-auth`，日志表内联展示设备标识与浏览器指纹。

**② 缓冲区水位可视化（此前显示的「共 N 条」是假的）**

原实现固定 `logread -l 5000`，但 `log_size` 默认只有 128KB，环形缓冲写满后
`logread` 实际只返回约 1500 行（.224 实测 1582 行 / 136841 字节 ≈ 86 字节/行）。
UI 照常显示「共 N 条」，让人误以为是全量。现在返回并展示水位、已用字节、
平均行长和容量估算，缓冲 ≥70% 转琥珀色、≥90% 转红色。

**③ 时间戳统一为 ISO + 解析器放宽**

原时间戳直接透传 syslog 文本（`Tue Oct  6 18:52:41 2026`），排序和筛选都别扭，
现在统一为 `2026-10-06T18:52:41` 并带 `epoch`。
正则同时放宽三处，每处都是为了**不让日志被静默丢弃**：星期几与年份可选
（busybox `syslogd -L` 落文件的格式就没有星期）、facility 用 `[\w.-]+` 贪婪匹配
（`my.app-name_v2.info` 原本整行解析失败）、程序名与 pid 整段可选
（`kernel.crit <message>` 这类无 `prog:` 结构的行原本整行丢掉）。
无法解析的行数作为 `unparsed` 如实返回并在页面上标出，不再藏。

**④ `log_size` 可调 + 保存幂等 + 清空副作用如实上报**

- `log_size` 此前全项目从未被代码碰过。现在可在「日志开关」页调整，
  UI 给出预计容量与占物理内存比例，超过 10% 出警示
- **`log_size` 只在 logd 启动时读取**，改完必须重启 `/etc/init.d/log` 才生效；
  而**重启会清空内存环形缓冲**（.224 实测 1580 行 → 1 行）。
  这个副作用以前完全没有提示，现在保存前 confirm、返回 `restarted`/`buffer_cleared`、
  toast 用琥珀色警示
- **保存改为幂等**：比对现值，配置没变就不重启、不清空。
  旧实现每次保存转发配置都无条件重启 log —— 也就是说**保存一次转发配置
  就清空一次历史日志**，用户一直不知道

### 新增：认证事件转发到远程日志服务器

- `auth_gateway` 对 `login_ok` / `login_fail` / `logout` / `lockout` 双发 syslog
  （`logger -t nftables-web-auth`），使认证审计能随 logd 转发到远程日志服务器
- **`verify_denied` / `token_refreshed` 刻意排除**：前者每个未认证请求都触发，
  全 WAN 打过来会把远程日志刷爆，真正该看的几条反而被埋掉
  （这两类在本地 JSONL 里仍是全的）
- **日志注入防护**：UA / URI 全部由客户端可控，写进 syslog 等于给了伪造远程日志的能力。
  非可打印字符一律剥除，长度截断。实测用带换行的 UA 打过来，
  远程日志里只出现一条干净的 `login_fail`，注入内容消失
- 实测链路：`.224` → `do` 的 Log Center `:514/udp`，
  5 次登录失败本地生成 4 条（1 次被限流正确挡下），
  本地 JSONL / logread / do 三方对账 **4/4 一致**，无转发丢失

### 新增：日志导出（CSV / JSON）

导出**当前筛选结果**，所见即所得。所有字段加引号并翻倍内部引号
（日志消息里逗号和引号都很常见，如 `DHCPACK` 那类），CSV 前置 BOM
（否则 Excel 按本地代码页解码，中文全乱码）。

### 新增：部署模式（为 Linux 适配铺路）

- 新增 `deploy_mode`：`openwrt`（默认，行为与 0.7.9.1 完全一致）/ `linux_gateway`
- `linux_gateway` 模式下 `flush ruleset` 换成 `flush table inet fw4` ——
  **只重建本项目自己的表，不清空宿主机全局 ruleset**（否则会连带清掉 Docker 等规则）
- ⚠️ 这一版**只做了地基**。Linux 部署的完整适配（接口名、端口敲死在 NAT 下的失效、
  WAN IP 获取、systemd、包管理器）留待后续，见文末待办

### 修复

- **面板 CSP 补 `'unsafe-eval'`（P0，面板在浏览器里完全不可用）**。Alpine.js 不预编译
  `x-data` / `@click` / `x-show` 表达式，而是运行时用 `new Function()` 现场编译。
  原 CSP 为 `script-src 'self' 'unsafe-inline'`，缺 `unsafe-eval` 时浏览器直接抛
  `Refused to evaluate a string as JavaScript`，Alpine 整个起不来 → 所有 `x-show`
  失效 → 模态框遮罩常驻 → 连登录按钮都点不动。curl 级验收查不到这一层，
  必须真实浏览器才能发现。认证门户是自写原生 JS 不需要 eval，那两页保持 `'self'`
- **`diffModal` 与登录遮罩游离在 `x-data` 容器外（P0）**。两者父级是 `BODY` 而非
  `x-data` 根，Alpine 不初始化它们 → `x-show` 永远不生效。此前被 `x-cloak` 掩盖，
  cloak 一失效就暴露：登录成功后遮罩不消失、diffModal 永久盖屏。已移进容器
- **`x-show` 保护的控件内部仍对 null 求值（P1）**。`x-show` 只管显隐，Alpine 初始化
  时照样对内层 `x-model` 求值。`presetEditing`（5 处）与 `rpEditingRule`（10 处）
  初始为 null → 每次开页面必抛 `Cannot read properties of null`。改用
  `<template x-if>` 包裹，不满足就不渲染
- **`checkAuth()` 读错一层导致登录死循环（P1）**。后端 `/api/auth/status` 返回
  `{success, data:{...}}`（与其它端点一致的双层结构），`api.request` 只剥最外层，
  直接读 `data.authenticated` 恒为 undefined → `password_set` 读成 false →
  误判 `loginMode='setup'`。已设密码的面板首次打开显示「首次使用，请设置管理员密码」，
  提交后后端 400「密码已设置，请用 /login 登录」，**死循环且无法自愈**。
  改为兼容双层/扁平两种风格
- **`x-init` 无视 `x-show`（P1）**。Alpine 的 `x-init` 不管 `x-show` 是否为 true 都执行，
  页面一加载就调 `/api/rules/preview` → 401 → 派发 `auth-expired` →
  `handleAuthExpired()` 清空 `config`/`rp` 并提示「会话已过期」——用户还没输密码
  就被告知会话过期。守卫放在方法内（同时覆盖 x-init 与「刷新预览」两个入口），
  并在 `loadAllData()` 里补一次，登录后仍自动加载
- **认证端点默认开放，收敛为白名单（P1，公网攻击面）**。网关配置里写的是
  `location /auth/`，这是**前缀匹配**，会把认证服务下所有 `/auth/*` 一并暴露到公网，
  其中包括：
  - `/auth/verify` —— 只应由 `location = /_auth` 以 `auth_request` 子请求方式内部调用
    （该 location 自带 `internal;`，本不该有任何外部入口）。外部可达等于给了
    攻击者一个可以反复重放的 token 校验入口
  - `/auth/health` —— 探活端点，外部可达泄露服务存在与内部状态
  认证服务以后每加一个 `/auth/*` 端点都会被这个前缀匹配默认带出去，属于典型的
  「默认开放」。改为**逐个精确列举**公网必需的 5 个端点（`/auth/login`、
  `/auth/logout`、`/auth/status`、`/auth/portal`、`/auth/static/`），其余
  `/auth/*` 一律 `return 404`。实测 `/auth/verify`、`/auth/health`、
  `/auth/config` 均由 200 变 404，功能无损（门户 13/13 仍全过）

  另外核对了认证服务是否有设置类信息外泄：9 个端点的返回字段只有
  `authenticated / code / device_id / expires_in / fp / message / ok / remaining /
  services / user / via`，全为会话与服务列表，没有任何端点把配置或密钥序列化给客户端
- **DDNS 配置全部字段被写坏，DDNS 起不来（P1）**。`_uci_set()` 用**双引号**包裹值
  （`uci set key="250"`），而 uci 会把双引号当成值的一部分存进文件，于是
  `uci get` 读回来是 `"250"`。ddns-scripts 里的 `$((ddns_loglines + 1))` 直接报
  `arithmetic syntax error`，点「重启服务」恒 500；密码里的三重双引号也被转义成
  一串反斜杠。2026-10-06 在 .224 上逐条实测确认正确写法是**值完全不加引号** ——
  uci 自己按第一个 `=` 分割并处理转义，含空格 / 单引号 / 等号 / 分号 / 反斜杠 /
  三重双引号都能原样保留。加引号反而出错。修复后 DDNS 重启 500 → 200
- **PPPoE 在单网卡机器上会导致整机失联（P0）**。`update_uci_wan_config()` 原本以
  `wan_device = 'eth0'` 兜底，而 `eth0` 恰恰是 br-lan 的唯一从属端口（设备检测本就是
  为把它排除掉）—— 兜底等于把 WAN 强行绑到 LAN 的网卡上，桥塌掉即失联。
  2026-10-06 实测：x86 单网卡 OpenWrt 上点「PPPoE 拨号 → 保存网络配置 → 重启网络」，
  设备当场 ARP FAILED，且无带外恢复入口。改为**检测不到独立 WAN 网卡就拒绝**，
  返回 400 + `INVALID_NETWORK` 并说明原因；PPPoE 账号为空也一并拒绝
- **空值无保护（P2）**。`getRpDefaultCert()` 在证书列表为空时返回 undefined，
  HTML 直接 `.domain`；`handleAuthExpired()` 重置的 `this.rp` 不含 `dnsProviders`，
  HTML 直接 `.dnsProviders.find`。均已加保护
- **启动恢复规则的优先级**。规则文件 `99-custom-rules.nft` 丢失时原先落到 `.backup`
  —— 那是「首次 apply 之前」的快照，可能比当前配置旧数周。实测因此踩中：backup 里的
  trusted 白名单没有后来才加进去的管理机 IP，启动恢复把管理员自己的 SSH 和面板
  一起关在门外。改为规则文件缺失时**优先按当前配置重新生成**，backup 降为第三优先级
- **删除 HTTP 5000 跳转器**（死代码）。10-01 那轮把 `lan_allowed_ports` 从 5000
  改成 5443 之后，5000 就被防火墙 `policy drop` 拦住、从未可达，
  但代码里还留着并误导文档。对外只保留 HTTPS 5443 一个入口
- `HTTPS_PORT` 从文件中部提到顶部：`validate_config()` 要用它做
  「网关端口不能占用面板端口」的交叉校验
- 新增 `_safe_cidr()`。原先用 `_safe_ip()` 校验网段，而它只认单个 IP，
  `192.168.100.0/24` 会被判非法并**静默回落到 `192.168.0.0/16`** ——
  那会把「仅内网可达」的放行范围悄悄放大
- 网关端口白名单：无 public 服务时不再放行网关端口
- **`setup.sh` 装 `nginx-full` 而非 `nginx-ssl`**。认证网关每个公网请求都要经
  `auth_request` 子请求核对 token，而 `nginx-ssl` 不含该模块：装它不报错，
  但一开网关就整片 500。装完新增 `check_nginx_modules()` 当场校验 `nginx -V`，
  缺 `auth_request` 直接 `die`（不是 warn+skip），缺 `realip` 仅告警（只影响
  日志里客户端 IP 的还原）
- **`setup.sh` 改为校验真正在跑的那份 nginx 配置**。OpenWrt 实际运行的是
  `/var/lib/nginx/uci.conf`（procd 从 template 生成），它并不被
  `/etc/nginx/nginx.conf` include，原来的 `nginx -t` 校验的是一份没人跑的配置，
  真出语法错也照样「通过」
- **`setup.sh` 新增 80/443 占用提示**。网关默认 8443 不会撞，但用户把公网端口
  自定义成 443 时 nginx 会因 bind 失败进入崩溃循环。不自动停 uhttpd（停了会
  失去 LuCI），只在安装阶段讲清楚该怎么处理

### 验证

| 项 | 结果 |
|---|---|
| 认证网关功能测试 | **40/40 通过**（含 fail-closed 异常注入、限流落盘、吊销、滑动续期、CSRF、门户） |
| 真 HTTP 端到端 | 起真实进程 curl 验证：cookie/Bearer/篡改/登出失效/续期行为全部符合预期 |
| 前端逻辑测试 | **29/29 通过**（Node + DOM 桩，无 npm 依赖） |
| 页面/静态资源/CSP | **22/22 通过**（两页 CSP 均 `script-src 'self'`） |
| 端口与超时守卫 | 8 个 case 全部正确（冲突、越界、非法模式均被拦，合法组合通过） |
| nft 规则集语法 | 两种 deploy_mode 均过 **nft v1.0.6** 真实校验（542/543 行，0 语法错误） |
| **零回归** | openwrt 模式下生成规则与 10-01 版本**逐字节一致**（仅多一行说明注释） |
| 语法编译 | app.py / template_engine.py / auth_gateway.py / setup.sh / 2 个 init 脚本 全通过 |
| `check_nginx_modules()` | stub nginx 四用例：缺 `auth_request`→die(1)、模块齐全→ok(0)、缺 `realip`→warn+ok(0)、无 nginx→die(1) |
| 端口占用检测 | 在 `.224` 真实 `netstat` 输出上验证，正确识别 80/443 占用，对 8080/8443/9999 无误报 |
| **真机 30 项验收** | **30/30 通过**（`192.168.100.224`，含 fail-closed：杀进程 B → 公网 500、内网仍 200） |

### ⚠️ 状态

- **已在真机验证**：`192.168.100.224`（OpenWrt 24.10.0 x86_64）部署 v0.8.0，
  30/30 项验收通过，含 fail-closed 实测（杀掉进程 B → 公网 500、内网仍 200）
- `auth_request` 模块**已实测存在**，但代价是必须换包：OpenWrt 自带的
  `nginx-ssl` **不含**该模块，换 `nginx-full 1.26.3` 后才具备
  （`nginx -V` 可见 `--with-http_auth_request_module`）。`setup.sh` 已改为
  安装 `nginx-full` 并在装完当场校验，缺模块直接中止
- 前端（登录页 / 门户页 / 设备指纹采集）已实现并通过 29/29 逻辑测试
- 灰度开关 `gateway_enabled` 默认**关闭**，不影响现有访问

### 待办

1. ~~日志页重构 + 指纹并入~~ **已完成**（见上「日志页重构」与「认证事件转发」两节）；
   `log_size` 调大、远程转发到 do 的 Log Center 均已真机跑通
2. Linux 部署完整适配（见上）—— 6 项原始需求里**唯一还没开工**的一项
3. 真实公网穿透验证（当前靠 `X-Test-IP` 模拟来源，判定逻辑已验，公网行为未验）
4. 「端口转发绕过认证」检测已有基础实现，但需在新网关模型下重新验证
5. N-5（面板借反代私钥的 HSTS 副作用）随面板退出公网而自然消解，可关闭该待定项

---

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
