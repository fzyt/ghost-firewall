# Changelog

所有重要更改均记录在此文件中。

## [v0.8.8] - 2026-10-30

**一键部署脚本**（`tools/deploy.sh`）+ **全新安装路径的三个修正**。

### 新增：一键部署（`tools/deploy.sh`）

开发机执行，SSH 驱动设备，九个阶段：连通+身份确认 → 判定路径 → 备份 →
传输 → 权限与密钥 → 语法预检 → 重启服务 → 应用（可选）→ 自检。
任何一步失败**自动回滚**（备份目录里带一份 `restore.sh`）。

```bash
./tools/deploy.sh --host <ip>              # 升级（只换代码）
./tools/deploy.sh --host <ip> --apply      # 升级并应用规则集
./tools/deploy.sh --host <ip> --dry-run    # 只打印计划
```

两条路径自动判定：设备上已装过 → **升级**（只换代码）；没装过 → **全新安装**
（复用 `setup.sh`）。设计上的硬规矩：

- **只覆盖，不删除。** 配置 / 口令 / 密钥 / 限流表一个都不碰
  （老 `redeploy.sh` 的 `rm -rf $APP` 会把「谁能进这台路由器」的凭据一起删掉）
- **换代码 ≠ 生效。** 规则集与 nginx 网关配置都是面板运行时生成的，
  部署代码不会让它们变 —— 要生效得显式 `--apply`
- **令牌密钥不能变。** `nftables-web-secret` 变了 = 所有设备的网关令牌作废
  ⇒ 用户全部要重新登录。脚本部署前后比对 md5，不一致就大声报
- **不重启路由器**，只重启本项目的两个服务
- 自检 19 项：两个进程的 uid（面板 root / 网关 nftweb）、三个端口、
  三个 HTTP 200、四个关键文件的权限、**网关的 gid == 配置文件的组 gid**、
  版本号、以及「规则集 md5 与 crontab 条数没被改动」

### 修复：全新安装路径的三个问题

这三个都**只在全新安装（设备被重置）时才会暴露**，升级路径上看不见：

1. **配置写成 0600，网关读不到。** `setup.sh` 写配置用的是 `chmod 600`，
   但网关（uid 1000 nftweb）是独立进程，要读这份配置。网关读不到时
   **不报错**，只是静默回退到默认值（`load_gateway_config` 读失败返回空 dict）
   ⇒ 现象是「配置写着 A、网关按 B 跑」，现场极难查。
   改成 0640 root:nftweb，并让 init 脚本把 `nftables-web-config.json`
   纳入组可读名单（**不能**纳入 `nftables-web-session-secret` —— 那是面板的
   会话签名密钥）。
2. **`setup.sh` 的版本号写死成 `0.7.9.1`** —— 装的是 v0.8.8 的代码，
   屏幕上写的是 v0.7.9.1。改成从同级的 `VERSION` 文件读。
3. **`frontend/` 之前没被当成运行时件。** 面板的 UI 是从 `../frontend` 提供的
   （`app.py`: `send_from_directory('../frontend', 'index.html')`），
   不是 `backend/static/`（后者是网关自己的登录页和门户）。部署脚本两个都传。

### 验证

- **真机**（`.233` OpenWrt 25.12.5）：升级路径连跑 3 次，19 项自检全绿，
  结果**逐次一致**（规则集 md5 `74f244b4…` 不变、crontab 仍 3 条、
  令牌密钥 md5 `f0e71a76…` 不变 ⇒ 用户不用重登网关）
- **回滚**：第一版脚本的端口断言写错了（`netstat` 里一个端口有 IPv4+IPv6
  **两行**，我写成等值比较 `== 1`）⇒ 自检抓到自己 ⇒ **自动回滚成功**，
  回滚后面板/网关/认证 API 全 200、网关仍是 nftweb 降权、规则集 md5 未变。
  失败回滚这条路径是真跑过的，不是演练

## [v0.8.7] - 2026-10-29

**Shannon 渗透测试 P0 修复批次**（8443 网关，5 轮测试 / 119 条 finding /
93 个独立问题；本条覆盖 11 条 P0，P1/P2 另计）。

| 编号 | 问题 | 修复 |
|---|---|---|
| P0-1 | 滑动续期在 auth_request 子请求里签新令牌 + 吊销旧 jti，但子请求响应头到不了浏览器 ⇒ 用户每 15 分钟被踢回登录页 | 续期搬到 `/auth/status`（普通 proxy_pass，Set-Cookie 能到浏览器）；`auth_request` 路径退回**纯校验、无副作用**。**补**：续期前必须校验世代号，否则旧令牌能靠 `/auth/status` 换到新世代令牌，绕过「改密码作废全部会话」 |
| P0-2 | 登录页 `next` 参数开放重定向（`//evil.com`、`\t` 等控制字符） | `safeNext()` **第一条**就挡控制字符；表单补 `method="post"` |
| P0-3 | 面板 Flask SECRET_KEY 与网关令牌密钥**共用同一个文件**，而该文件对降权后的网关进程可读 | 拆成两个文件、权限相反：`nftables-web-secret`（0640 root:nftweb，网关令牌密钥，**已存在则原样保留**）与 `nftables-web-session-secret`（0600 root:root，面板会话密钥）。网关攻陷也签不出面板 session |
| P0-4 | `POST /api/config` 能写 `auth_token_epoch` ⇒ 改密码「作废全部会话」可被绕过 | `auth_token_epoch` 进 `READONLY_CONFIG_KEYS` |
| P0-5 | 锁定触发时清空 fails ⇒ `remaining` 被算成 5（错报还剩 5 次）；限流表读写无锁 | 锁定返 **429 + `remaining=0`**；读端加 `flock(LOCK_SH)`（写端本就有 `LOCK_EX`）⇒ 不会读到 truncate 后的半截 JSON |
| P0-6 | PBKDF2 校验失败路径不迭代 ⇒ 响应时间可区分「用户存在/不存在」 | dummy 路径用 `max(存储 iters, MIN, 200000)` |
| P0-7 | 共享配置 `0644` world-readable | `save_config` 落 **0640**（含 `.backup`）。选 0640 而非 0600：网关是独立进程读同一份配置，目录 `2755 root:nftweb` |
| P0-8 | `linux_gateway` 模式只 flush `table inet fw4`，`table ip nat` 里的端口转发规则**永久残留**（用户在面板删了转发，内核里还在跑） | 前导块改为「先建空表再 flush fw4；把本项目自己那两条 nat 链 delete 后由模板重建」。**不用 `flush table ip nat`** —— 那是宿主机标准 NAT 表，flush 会连 Docker 的规则一起清掉（实测） |
| P0-9 | DDNS `ipv6_source` 可注入（`../../etc/hostname` 路径穿越、`x;id` 分号注入） | 白名单 `router` / `rule_<N>` + **删现有 service 之前**预校验 + 用 `fullmatch` 推导 idx |
| P0-10 | `crontab -l` 失败时仍用空列表继续写 ⇒ **整个 root crontab 被覆盖**（实测 3 条变 1 条，acme 续期与证书续期脚本双双被抹） | 两处（`_upsert_cron_for` / `install_china_ips`）**fail-closed** |
| P0-11 | 反代 test 端点回显原始异常 + 响应时间可区分 ⇒ 内网端口扫描 oracle | 错误归一化 + 不可达时等满最小时间 + 每次探测记审计 |

### 验证

- **回归**：全量 Python + 前端 + 变异脚本；变异锚点随代码搬家同步更新。
  修复后最终结果 **✅ 2104 · ❌ 0**，源码指纹一致（变异已还原干净）
- **回归自检**：首轮全量回归跑出 **4 处失效测试** —— 3 条断言写死了**修复前**的旧契约
  （`/auth/verify` 续期、只读键一律不落盘、限流表旧锚点），1 条变异**根本没跑过**
  （锚点未命中 = 跳过 ≠ 通过）。全部已修，并补上拦住漏网变异的新断言
- **变异覆盖**：新增 `tests/mutation_check_p0_fixes.py` —— 把 25 处 P0 修复逐一改回
  修复前的样子，验证测试是否真的会红；**25 / 25 全部被捕获**
  （脚本区分「断言变红」与「测试崩了」，后者不算数）
- **真机语义**：`tests/nft_semantic_check.sh` —— 在隔离 netns 里验 nft 语义
  （`flush table X` 表不存在时报错 / ruleset 是合并语义 / 同事务 delete+重建可行 /
  `flush table ip nat` 会误伤 Docker / `nft -f` 整文件一个事务无空档窗口）。
  **正测 10/10，负测（原版规则集）11 项红**
- **原子性**：反复 apply 期间实测「违规连接成功 0 次、长连接中断 0 次」，
  并用「独立一次 nft 调用制造真实空档」做正控制，证明检测有效
- **独立审查**：DeepSeek（deepseek-v4-pro）24 轮带工具独立审查 ⇒ 结论**可接受**，
  无必须修项；6 条建议已落实 5 条（第 6 条「改用 `destroy chain`」会抬高最低
  nft 版本要求，待定）

> 本次只覆盖 8443 网关侧；面板侧（5443）另有 49 条问题未纳入本批次。

## [v0.8.6] - 2026-10-28

泛域名体系落地：**泛域名证书**（签发 / SAN / 定时续期）+ **host 分发**
（服务按自己的对外域名分发到根路径，认证一步不丢）。

### 泛域名证书

| 能力 | 说明 |
|---|---|
| 签发 | 面板直接申请 `base` + `*.base`（DNS-01），acme.sh 走多路径探测，OpenWrt 裁剪版缺 dnsapi 插件时给**人话报错**而不是 acme.sh 原始报错 |
| 覆盖范围 | 证书列表返回真实 **SAN**（从证书里读，不信用户填的标签），卡片显示「覆盖：SAN（含泛域名）」 |
| 自动续期 | `auto_renew` + `renew_days` → 落盘 `/opt/nftables-web/renew-certs.sh` + crontab `*/30`；`python3 app.py --renew-certs` 可手动触发 |
| setup.sh | 补装 6 个 DNS 插件（`dns_ali` / `dns_tencent` / `dns_cf` / `dns_huaweicloud` / `dns_porkbun` / `dns_gd`）到 `~/.acme.sh/dnsapi/` |

### host 分发（本次主线）

反代规则新增 **`host`** 字段（对外域名，如 `siyuan.fzyto.top`）。
填了就会**额外**开一个 `server_name` 入口，服务挂到该域名的**根路径**：

```
server {
    server_name siyuan.fzyto.top;
    location / { proxy_pass http://192.168.100.218:6807/; auth_request /_auth; ... }
}
```

**为什么必须做**：路径前缀分发（`/siy/`）下，上游写死的根绝对路径
（`/api/xxx`）会逃出 location → 接口全 404；而 WebSocket 因上游在运行时
按 `location.host` 拼 URL，**静态 `sub_filter` 根本匹配不到** ——
子路径反代的天花板不是补丁能补的。挂在域名根路径上，这两个问题天然不存在。

**认证一步不丢**：host 入口同样走 `auth_request /_auth` + 401 跳登录，
和路径入口完全一致。

**跨子域共用一次登录**：浏览器按 host 存 cookie，门户在 `fzyto.top` 登录
拿到的令牌送到 `siyuan.fzyto.top` 时不会被带上 —— 表现是「每换一个域名
就要重登一次」。解法是把 cookie 的 `Domain` 抬到父域（`.fzyto.top`）：

- `base_domain` 由面板**从默认证书的 SAN 自动推导**（`*.fzyto.top` → `fzyto.top`），
  用户不必手填（手填十有八九填错，浏览器就是满屏证书告警）；
- `cookie_domain` 默认 `.` + `base_domain`，可单独覆盖；
- ⚠️ **IP 主机名必须退回 host-only**：浏览器对「IP + Domain 属性」的 cookie 是
  **整条拒收**（RFC 6265 §5.3），硬带 Domain 会让「密码正确却登不进去」，
  比不带 Domain 更难查。所以 `Domain` 按**当前请求主机**动态决定。

**「键存在 = 已做过决定」**：`base_domain` / `cookie_domain` 的语义与其它开关
不同 —— 键不存在 = 还没问过用户（可以从证书自动推导）；键存在但值为空 =
用户**明确清空**了（绝不能再自动改回来）。若把它们放进 `RP_DEFAULT_SETTINGS`
当普通开关处理，「自动推导」就永远不触发，「用户清空」也会被悄悄覆盖。

**派生值必须落盘，不能只活在面板内存里**（真机踩出来的）：认证服务
（`auth_gateway.py`）是**另一个进程**，只读同一份 JSON，不会去解析证书。
如果这两个值只在面板的接口层现算，接口返回看着一切正常，但认证服务读到
的是空的 → 下发的 cookie **没有 Domain 属性** → 浏览器按 host 各自存 →
**跨子域每换一个域名就要重登一次**，而且面板上完全看不出来。
现在 `_save_rp_config()` 在写盘前先把派生值物化。

**两侧语义必须一致**：面板 `app.py._rp_cookie_domain()` 与认证服务
`auth_gateway._cookie_domain()` 用同一套判据（键存在就用、键不存在就推导）。
两边不一致 = 「面板说共享、认证服务不共享」。

### 顺带修掉的既有缺陷

- `getRpCertDaysClass` 前端**根本没实现**，但证书卡片两处在调 →
  「剩余天数」「状态」两行颜色一直绑不上（补实现：灰/红/黄/绿四档）
- `loadReverseProxy()` 判断顺序错：「只有一个证书就自动设默认」写在
  `settings` 赋值**之前** → 每次新开面板进反代页都误触发 `set-default` →
  `_deploy_all_rules` 重生成整份 nginx 配置 → **冲掉手工补丁**
  （实测把 33 条 `sub_filter` 冲成 7 条）。已把该块移到赋值之后

### 回归

`tests/run_all.sh` 全量通过（断言 ✅1991 · ❌0，源码指纹一致）；
新增 `tests/test_host_dispatch.py`。重构把网关 nginx 生成拆成三个函数后，
**5 个变异脚本共 22 条锚点因缩进变化失效**（锚点未命中 = 那条变异根本没跑，
是「悄悄少验」），已逐条对齐并复核命中数。

真机（OpenWrt `.233`）验证：门户登录一次 → 点服务卡片 → 直接进
`https://siyuan.fzyto.top:8443/`，不再重复登录；思源完整加载，
WebSocket 连通，42 个请求 **0 个 4xx/5xx**。

## [v0.8.5] - 2026-10-21

一次「保存配置」把整棵反代配置清空 —— 2026-10-21 `.1` 主路由真机事故的定案与修复。
同批带上网关「根绝对路径改写」功能与协议相对 URL 预检。

### P0-1  点一次「保存配置」，反代规则与证书被静默清成 0

`.1`（主路由）上，13:41 建好的 2 条反代规则 + 13:42 传的 1 张阿里云证书
（`fzyto.top`，DigiCert），在 14:06:22 的一次「保存配置」之后变成 **0 条 0 张**。
用户侧表现是「我操作一下，所有内容就没了，包括证书」。

全链路日志佐证（`.1` 面板访问日志逐行可查）：

| 时刻 | 客户端 | 动作 | 磁盘 `reverse_proxy` |
|---|---|---|---|
| 13:20:31 | .110 | `GET /api/config` | **0 规则 0 证书**（这就是那份快照） |
| 13:41:37 | .105 | `POST /api/reverse-proxy/rules` | 1 条 |
| 13:42:01 | .105 | `PUT rp_001` + `POST /rules` | 2 条 |
| 13:42:38 | .105 | `certificates/upload` + `set-default` | 2 条 + 1 张证书 |
| **14:06:22** | **.110** | **`POST /api/config`**（带 13:20 的旧快照） | **→ 0 条 0 张** ❌ |
| 14:11:49 | .110 | `GET /api/config` | （下一次 GET 已在 POST 之后） |

交叉验证不依赖推断：`save_config` 落盘前会先 `shutil.copy` 一份 `.backup`，
14:12 现场主文件是 0 规则 0 证书、`.backup` 是 2 规则 1 证书 ——
那段时间里唯一的写者就是那一次 `POST /api/config`。

根因链（四环，缺一不可）：

1. **前端把整份 config 当 blob 带着走** —— `GET /api/config` 返回
   `dict(config, ...)`，`reverse_proxy` 全量在里面；`loadConfig()` 原样
   `this.config = data`。
2. **反代页改了数据但从不回写这份 blob** —— `loadReverseProxy()` 只动
   `this.rp.rules` / `this.rp.certificates`。硬证据：
   `grep reverse_proxy frontend/` **命中 0 处** —— 前端根本不认识这个词，
   它只是作为 `this.config` 里一个**不透明附带物**被动跟着整份配置回传。
3. **配置页把整份快照原样 POST 回去** —— `pendingConfig = { ...this.config }`。
4. **后端无条件整份覆盖** —— `new_cfg = dict(old_cfg); new_cfg.update(incoming)`，
   前端快照里的 `reverse_proxy`（旧）直接盖掉磁盘上最新的那份。

后端四道护栏一道都没拦住：`READONLY_CONFIG_KEYS`（5 键）与
`GATEWAY_OWNED_CONFIG_KEYS`（6 键）**都不含 `reverse_proxy`**；
`_detect_risks` 只看会进 nft 规则的字段；`preview-changes` 算的是 nft 规则 diff，
用户看不到「你正在抹掉 2 条反代规则和 1 张证书」。

⇒ **必然复现，不是偶发事故**：只要「反代页改动 → 不刷新页面 → 配置页点保存」
这个顺序发生一次，反代数据就回滚到快照时刻的状态。

**修法（主防线在后端，不指望前端「别带」）**

- `RP_OWNED_CONFIG_KEYS = frozenset({'reverse_proxy'})`：
  `/api/config` **无条件**剔除 `reverse_proxy`，响应回报 `ignored_rp_fields`。
  安全性依据：`index.html` 里没有 `config.reverse_proxy` 的任何绑定，
  配置页本来就不编辑反代数据。
- 新增 `config_rev` 版本闸：`GET` 带回内容哈希，`POST` 必须带回来，
  对不上直接 **409 `CONFIG_STALE`** 拒收。三个设计决定：
  - **只算 `/api/config` 拥有的字段** —— `reverse_proxy` 不参与，
    否则反代页改一条规则就让配置页莫名 409（而那份数据本来就不会被写）；
  - **不带 `config_rev` 的调用不拦**（curl / 第三方脚本 / 旧版前端），
    主防线是无条件剔除，版本闸只是纵深防御，不该变成破坏性变更；
  - **保存成功后必须把新版本号带回前端**，否则连点两次保存第二次就撞 409。
- `preview-changes` 同样剔除 ⇒ 预览 = 实际会保存的内容。
- 前端识别 `CONFIG_STALE`：说清原因、问用户要不要重新加载；
  用户选择**不**重载时不偷换版本号 ⇒ 下次保存仍会被拒。

### P0-2  上传证书 / 设为默认证书，从不生效

`rp_upload_cert` 与 `rp_set_default_cert` 只落盘，**不调 `_deploy_all_rules`、
不 reload nginx**；而同文件的 `reupload` 会部署。

`.1` 实测：13:42 传了阿里云证书并设为默认，8443 一直用自签证书
（`/etc/nginx/ssl/nftables-web/fullchain.pem`），而面板显示
「默认证书 = cert_001」—— 两边对不上。`nginx/reload` 只重载旧 conf、
不重新生成，所以也救不了。

修法：两个端点落盘后都调 `_deploy_all_rules`，沿用 `reupload` 的既有约定
（**先落盘、再部署**，部署失败只改文案、不改成功状态 —— 证书文件已经原子
写进磁盘，落盘与否不造成反复失败；硬套规则 CRUD 的「先部署后落盘」反而会让
「网关已启用但 0 条规则」这种状态下连证书都设不了）。响应新增 `nginx_reloaded`。

### P1-1  损坏的配置被直接删掉

`load_config()` 的损坏兜底是 `shutil.copy` + `os.remove` —— 原文件没了，
只剩一份同样损坏的副本。两个后果叠加：
① 一次瞬时损坏 + 一次保存，`DEFAULT_CONFIG`（**里面没有 `reverse_proxy` 键**）
被写回磁盘 ⇒ 反代子树从磁盘上彻底消失，全程只有一条 `[WARNING]`；
② `_config_lost_after_setup()` 不认 `.corrupted.*` ⇒ 移走后被判定为
「全新安装」⇒ 守卫从此永远满足，一次损坏被固化成永久配置。

修法：改成 `os.replace` **改名移走**为 `.broken.<ts>`（原子 rename，
不出现「副本写了一半」的窗口），并让 `_config_lost_after_setup()` 认得
`.broken.*` / `.corrupted.*`。

### P1-2  `_migrate_rp_rules` 白名单漏 `created_at`

它是**字段白名单**，没列出的键无声丢弃，而它被 `load_config()` 和
`_deploy_all_rules()` 各调一次 ⇒ 每一次 load→save 都会抹掉这个时间戳。
（`rewrite_root_paths` 当初也是这样丢过一次，注释里还留着那次事故的记录。）

### feat-1  网关「根绝对路径改写」

上游页面里写死的**根绝对路径**（`href="/x"` / `src="/x"` / `action="/x"`）
被浏览器按 absolute-path 语义解析时会**丢掉本路径前缀**（RFC 3986 §5.2.2）
⇒ 样式表、脚本、页面链接全跑到别的服务去 → 404，页面变成没样式的裸文本。

- 后端 `_generate_gateway_nginx_conf` 按规则生成 `sub_filter`，
  只改写「属性值紧跟」这一种形态，不动 JS 里普通的字符串
- 新增 `_nginx_regex_literal` / `_nginx_dquote` / `_nginx_host_literal`
  三个辅助函数做字面量转义
- 前端反代页新增「根绝对路径改写」开关（默认关）
- **已知边界**：协议相对 URL（`href="//cdn.example.com/x.css"`）会被改坏 ——
  nginx 的 `sub_filter` 只支持字面量，没法把 `//` 排除掉
  ⇒ 新增 `POST /api/reverse-proxy/detect-protocol-relative` 预检，
  开关前先探一下

### fix-1  回归断言总数不可复现

`test_auth_gateway.py` 里 PBKDF2 闸门大小来自启动探针
`_probe_pbkdf2_parallelism()` —— 它要真跑一遍 PBKDF2 才能判断本机并发有没有
收益，结果**随机器负载浮动**。于是 `_size` 在 1 与 >1 之间来回跳，
if/else 两个分支打印的 ✅ 条数不一样 ⇒ 回归的「断言总数」不可复现
（实测 1609 与 1608 来回跳）。else 分支改成一条**确定性**的断言。

### 测试

| 文件 | 内容 |
|---|---|
| `tests/test_config_ownership.py` | 43 条断言，含 **.1 事故原样复现** |
| `tests/test_config_ownership_frontend.js` | 23 条，把 `confirmSaveConfig` **在沙箱里真的求值一遍**（不是只 grep 源码） |
| `tests/mutation_check_config_ownership.py` | 11 处变异，**捕获 11** |
| `tests/test_gateway_path_rewrite.py` | 73 条 |
| `tests/test_gateway_path_rewrite_frontend.js` | 30 条 |
| `tests/mutation_check_gateway_path_rewrite.py` | 25 处变异，**捕获 25** |

全量回归（`bash tests/run_all.sh`，唯一权威入口）：
**断言 ✅ 1675 · ❌ 0**；22 个变异脚本全通、锚点未命中 0、漏过 0；
源码指纹开始/结束 sha256 对账一致（变异已还原干净）。

## [v0.8.4] - 2026-10-13

首次在真实 WAN 侧路径上做端到端实测（.224 OpenWrt 测试机 + netns 模拟外网
源），逮到一个此前从未被测到的 P0：**端口敲门从来没有成功过**。

### P0-4  敲门限流 burst=1，四步序列的第二步起永远超限落链尾

P1-6 把敲门限流从规则级 `limit rate 1/minute burst 1`（整条规则一个全局桶，
任何人一分钟发 2 个包就能把全世界的合法敲门挤掉）改成挂在 set 元素上的
按源分桶。方向是对的，但 **burst 忘了跟着改**。

限流挂在 set 元素上之后，桶是跟地址走、**跨规则共享**的：四步敲门写的是同一个
`@knock_rate4`，所以第一步就把该源地址的桶用光了，第 2~4 步全部超限不匹配，
只剩链尾 `[KNOCK-WAN4-UNMATCHED]` 兜底丢弃。而 `knock1_done4` 等中间态只有
8 秒超时，所以无论等多久重试都不可能走完 —— **敲门的完成路径不存在**。
IPv6 的 `knock_rate6` 是同一份写法，同样中招。

表现对用户是：第一下有反应（`[KNOCK4-OK-S1]`），之后永远连不上，
且没有任何报错指向真实原因。

`.224` 真机定位过程（netns 造一个 198.51.100.0/24 的模拟外网，绑到真接口
`simwan0` 上，源地址非 RFC1918，能走通完整的 input_wan 链路）：

| 对照组 | 限流写法 | 四步序列 |
|---|---|---|
| 线上原样 | 元素级 `1/minute burst 1` | 第 1 步通过，第 2 步落链尾 |
| 每步之间清空 `knock_rate4` | 同上 | 4/4 走通 |
| 影子表 · 同一条链 | 元素级 `1/minute burst 1` | 走不通 |
| 影子表 · 同一条链 | 规则级限流 | 走通 |

唯一变量就是限流挂在哪，根因坐实。改成 `limit rate 1/second burst 4 packets`
（burst 必须 >= 序列长度）：一轮 4 连敲瞬时放行，之后每秒补 1 个令牌，
既满足正常敲门和敲错后重试，又保住每源每秒 1 包的洪泛压制 ——
影子表连打 12 包实测放行 6 丢 6，限流依旧生效。IPv6 一并改，共 8 处。

修复后同一台机器、同一套测试：敲门四步全通 → 进 `allowed4` → 端口转发
端到端拿到 LAN 后端的真实 HTTP 200，18/18 断言全绿。

顺带修了两处**把缺陷固化成了「正确行为」**的测试：`test_review_fixes.py` 里
「v4/v6 敲门按源分桶」两条断言原文写死 `limit rate 1/minute`，等于给错误的
burst 值背书；现改为断言真正的不变量（按源分桶 **且** burst >= 序列长度）。

新增 FIX-16 回归断言，并给变异套件补 3 条变异。写断言时踩到一个老坑：
nft 规则是多行 `\` 续行结构，只把首行注释掉、后面几行还在文件里，
文本仍在但规则已死 —— 于是加了一个 nft 感知的剥注释函数，
会识别「续行被注释掉」并丢弃其后所有孤儿碎片。

同批实测确认正常（无缺陷）：反伪造拦截、`[I4-ALVN-T-1]` 端口转发端到端、
`allowed4` 门禁拒绝非白名单源、`input_wan` 放行。`lan_allowed_ports`
在 `access_mode=lan` 下不生成放行规则是设计如此（LAN 模式本就全放行），
不是死配置。

## [v0.8.3] - 2026-10-12

功能性审查发现的 10 个缺陷修复，外加 1 处看门狗恢复链路缺陷。**规则链相关问题不在本版范围**（P0-1 见文末）。

### P0-2  ACME 路径漏掉私钥权限加固（上一版引入的回归）

v0.8.2 把 nginx worker 降到了 `nobody`，但私钥仍是 `600 root`。
上传和重传两条路径都会 `chmod(key, 0o600)` 之后调 `_harden_key_for_nginx_worker()`，
**ACME 两条路径不会** —— acme.sh 自己写出 `privkey.pem` 600 root，项目这边根本不 chmod。

后果：手动传的证书能用，ACME 申请的证书一续期就 TLS 握手失败。而面板这侧
`expires_at` 正常、UI 照样显示「● 有效」，排障方向会被完全带偏到「是不是
nginx 配置错了」。

- `_acme_issue()` 与 `_acme_renew()` 各补一次 `_harden_key_for_nginx_worker()`
- 顺手修了 `_harden_key_for_nginx_worker` 的 docstring：原来写「三条路径
  （上传/ACME续期/自签）」，但第三条其实是 reupload 不是 ACME —— **注释自己
  撒谎，恰好掩盖了 ACME 的缺口**。改成如实列出五条

### P0-3  证书续期按钮永远不显示

后端写 `"source": "auto"`，前端判 `cert.source === 'acme'`。两边对不上，
ACME 证书的「续期」按钮从来不会出现。

改前端（`cert.source === 'auto'`）而不是改后端：后端 `auto` 已经落进存量
配置，`/renew` 的 `!= "auto"` 守卫也按 `auto` 写的，动后端会同时打断两者。

### P1-1  反代 CRUD 漏交叉校验，可构造免认证 DNAT 直达

`rp_create_rule` / `rp_update_rule` / `rp_delete_rule` 都不调 `validate_config`，
所以完全绕过了「端口转发目标不能是已启用的反代服务」这条交叉校验。
于是可以先建一条端口转发，再建一条指向同一后端的反代 —— DNAT 走 nftables，
根本不经过 nginx 的认证层，一条完全免登录的公网入口就成立了。

- 把交叉校验抽成唯一入口 `_rp_forward_conflicts(cfg)`，`validate_config` 与
  反代 CRUD 共用。两份逻辑迟早分叉，PUT 就是这么漏的
- `rp_create_rule` 在 append 后、部署前校验，冲突时 `rp["rules"].pop()` 撤销
- `rp_update_rule` 在 mutate 后、部署前校验，冲突时 `rule.update(original)` 还原
- 新增 `tools/check-api-coverage.py`：比对前后端接口覆盖度

### P1-2  `/auth/static/` 下的 HTML 拿不到 CSP

`location /auth/static/` 排在 `location /auth/` 之前，所以 `login.html` 和
`portal.html` 可以直接从静态路径取到（真机实测返回 200），**不带 CSP** ——
等于多了一条绕过 CSP 的路。

- `auth_gateway.py` 新增 `CSP_LOGIN_HTML` / `CSP_PORTAL_HTML` 常量
- `static_files` 对 `.html` 按文件名选对应 CSP；门户页与登录页改用常量，
  不再各自内联第二份（两份 form-action 不同的策略迟早分叉）
- 真机复验：`.224` 上 `/auth/static/login.html` 与 `portal.html` 经网关 8443
  均已带上 CSP，且两个取值正确区分（登录页 `form-action 'self'`、门户页
  `form-action 'none'` + `img-src data:`）

### P1-3  网关配置先落盘后部署

`/api/gateway/config` 里 `save_config()` 排在 `_deploy_gateway_nginx()` 前面。
nginx 部署失败时磁盘上已经是新配置、生效的却是旧配置，两者从此不一致；
提示还写着「配置已保存但网关部署失败」，用户下次动别的字段时又会基于这份
落盘配置重新生成，把问题静默放大。

改为**先部署、后落盘**，失败时明确返回「网关部署失败，配置未保存」。

### P2-1  手动更新 IPv6 不写 DDNS 中转文件

`/tmp/ddns-ipv6-*` 只有 cron 脚本会写。手动点「更新 IPv6」只改了内核 set，
中转文件始终是空的 —— 阿里云 DDNS 与通用 DDNS（`ip_script=/bin/cat
/tmp/ddns-ipv6-N`）读到的还是旧值，**IPv6 记录静默停在过期地址上，没有任何报错**。

`update_ipv6()` 现在同样写 `/tmp/ddns-ipv6-0` 与 `/tmp/ddns-ipv6-{idx}`，
且写失败只告警不阻断（IO 错误不该让整个接口 500）。

### P2-2  上传证书不校验证书与私钥配对

原来只做域名正则 + 三字段非空就落盘。传错私钥（换证书时两个文件选反，
非常容易）的话 nginx 拿着不匹配的 key 做 TLS 握手，而面板 `expires_at`
正常、UI 显示「● 有效」，排障方向同样被带偏。

- 新增 `_cert_key_pair_ok()`：比较两边公钥（`openssl x509 -pubkey` vs
  `openssl pkey -pubout`）。用 `pkey` 而非 `rsa`，ECDSA 私钥也能过
- openssl 不可用时**放行**：校验不了 ≠ 校验失败，环境问题不该拦住用户存证书
- `rp_upload_cert` / `rp_reupload_cert` 改为**先写 `.tmp` 校验、通过才
  `os.replace` 覆盖** —— 传错私钥时原来能用的证书必须保住

### P2-3  `/api/rules/save` 是一条绕过全部安全机制的旁路

这条是新写的 `tools/check-api-coverage.py` 报出来的：后端 75 条路由里，
它是唯一一条「有路由、前端零调用」**且**绕过 v0.8.x 全部加固的。

原实现 `build_rules()` + 直接写盘，同时绕过：

- `_config_corrupted_response()` —— 配置损坏时 `load_config()` 返回硬编码
  `DEFAULT_CONFIG`（内含他人网段），原实现拿它直接落盘，等于把陌生网段写进
  真实防火墙，还回报 `success: true`
- `_FW_APPLY_LOCK` —— 与看门狗的 `nft -f` 交叉执行
- `_apply_ruleset()` 的语法校验与失败回滚

`app.py:2082` 的注释早就写明「避免出现某条路径跳过了校验和回滚」——
这条路径当时就是那个例外。

改为转发给 `/api/rules/apply`（保留端点，不打断可能存在的 curl / 脚本调用方）。
**是否直接从路由表删掉更干净，留给你定。**

### P1  forward 链缺黑名单 —— 拉黑对已转发端口无效

黑名单 drop 只写在 `input` 链（第 173-174 行）。但 DNAT 把目标改成内网主机后
会重新路由，目标不是本机就**只走 `forward` hook，`input` hook 根本不触发** ——
所以拉黑一个 IP 之后，它照常能用端口转发。

在 `.224` 上用 `ip route get` 实测确认了路由分流：

```
ip route get 192.168.100.50  →  192.168.100.50 dev br-lan   ← 转发（forward hook）
ip route get 127.0.0.1       →  local 127.0.0.1 dev lo       ← 本机（input hook）
```

`input_wan` 里**不需要**加：黑名单 drop 在 `input` 链内排第 10 位，
`jump input_wan` 排第 46 位，定向到路由器本机的 WAN 流量早就被拦住了。

实际利用面窄：`forward` 的放行条件是 `ip saddr @allowed4`，没敲过门的黑名单 IP
进不了 allowed4，确实转发不了。真正的缺口是「敲门成功后又被拉黑」——
`nftables.conf:369` 敲门成功 `add @allowed4`（5h 超时），而 `372-373` 拉黑时
只加黑名单、不清 allowed4，那个 IP 在剩余 5 小时里照常转发。

改动（`backend/templates/nftables.conf`，forward 链）：

```
ip saddr @blacklist4 log prefix "[BLACKLIST4-FWD] " drop
ip6 saddr @blacklist6 log prefix "[BLACKLIST6-FWD] " drop
ct state { established, related } accept
```

- **必须排在 established 之前**，否则已建立连接的后续报文会先命中 established
  直接放行，黑名单就只能挡新连接 —— 和 `input` 链当初把黑名单从 established
  之后挪到之前是同一个道理
- 日志前缀用 `-FWD` 与 `input` 链区分，日志里能看出是「访问路由器被拦」还是
  「转发被拦」
- 固定语句，不依赖任何配置开关（`blacklist4`/`blacklist6` 在模板里无条件定义），
  面板黑名单功能维护的就是这两个集合，前后端不用各改一处

验证：`.224` 真机 `nft -c -f`（只检查不下发）过 baseline / trusted /
dns_lan_resolver / 带端口转发的完整配置四个场景，全部 rc=0；渲染顺序断言确认
黑名单落在链体第 1、2 位。回归 `test_review_fixes` 142→147，
`mutation_check` 19→21 且 21/21 全捕获（新增两种退化：挪到 established 之后、
整条删掉）。

**注意：规则模板改动需点「应用规则」才下发到内核，不会自动生效。**

### P0  配置损坏守卫只挂 1 个端点，且不挡持久化

#### 问题

`_config_corrupted_response()`（配置损坏就拒绝下发）**全库只有 `/api/rules/apply`
一个调用点**。实测同一份损坏配置下的行为：

| 端点 | 修复前 | 修复后 |
|---|---|---|
| `/api/rules/apply` | 500 拒绝下发 | 500 拒绝下发 |
| **`/api/network/restart`** | **200 照常下发** | 500 拒绝，且**不重启网络** |
| **`/api/gateway/config`** | **200 下发 + 写回磁盘** | 500 拒绝，不落盘 |
| **`/api/reverse-proxy/rules` POST** | **200 照常下发** | 500 拒绝 |
| `/api/reverse-proxy/rules/<id>` PUT/DELETE | 404（规则随配置一起消失，够不着下发） | 同左 |

`/api/network/restart` 原实现是 `build_rules` → `open(RULES_PATH,'w')` →
`nft -f`，四样全缺：不查损坏、不持 `_FW_APPLY_LOCK`、`open(...,'w')` 是
truncate+write 非原子、没有 `nft -c` 预检也没有 `.lastgood` 备份。

#### 真正严重的是持久化，不是下发

`/api/gateway/config` 会 `save_config(new_cfg)`。实测这条链：

```
① 改一次网关端口 → HTTP 200，磁盘配置已变成 trusted_ip4=192.168.100.2
② 再点「应用规则」→ HTTP 200 规则已应用，守卫是否还拦: False
③ 再点「重启网络」→ 200，正常下发
```

落盘之后 `_config_lost_after_setup()` 判定为「全新安装」，守卫**从此永远满足**。
一次瞬时损坏被固化成永久配置，接口全程返回 200，之后不会再有任何告警。

拿 `.224` 的真实配置对比 `DEFAULT_CONFIG`，39 个字段里 **19 个**会被换成出厂值：

```
knock1/2/3/4   10376 / 23224 / 32760 / 13550  →  1 / 2 / 3 / 4   （敲门口令全废）
reverse_proxy  "测试NAS" /nas → 127.0.0.1:15000  →  null        （反代服务整个没了）
lan_allowed_ports  [22, 5443]  →  ""                                （内网管理端口白名单清空）
forward_rules   []  →  [{... "target_ip": "192.168.4.226"}]         （凭空多出一条公网转发）
lan_subnet4 / lan_broadcast4 / ula_prefix6 / wan_prefix6 / trusted_ip4 全部指向陌生网段
```

缓解因素：损坏现场会以 `.corrupted.<时间戳>` 留存，用户真实配置可从中恢复
（2026-10-12 `.224` 配置丢失就是这么恢复的）。但前提是知道去哪儿找。

#### 改法

- **守卫下沉到 `_apply_ruleset`**（取锁之前判断，纯内存检查不占锁）——
  覆盖 `/api/rules/apply`、`/api/gateway/config`、反代增删改、看门狗自愈。
  看门狗自己本来就查 `_config_corrupted()` 并退到 `.backup` / basic lockdown，
  所以下沉不会误伤自愈能力
- **`save_config` 也拦**：新增 `ConfigCorruptedError` + 统一的
  `@app.errorhandler`。守卫放在函数**最前面**——函数体第一件事是
  `shutil.copy(CONFIG_PATH, CONFIG_PATH + '.backup')`，而 `load_config()` 检出损坏时
  会把原件移走，此时 `.backup` 是唯一完好的恢复材料，先复制等于用损坏文件覆盖它。
  选抛异常 + errorhandler 而不是逐个调用点加 try/except：`save_config` 有 8 个
  调用点，手写迟早漏一个，而漏掉的那个就是「静默写回出厂配置」的那条路。
  留 `_force=False` 参数给将来的恢复路径（当前 `restore_config` 走 `os.replace`，
  不经过这里）
- **`restart_network` 改走 `_apply_ruleset`**，顺带白捡原子写、`nft -c` 预检、
  `.lastgood` 备份、加锁。顺序也从「先写文件再重启网络」改成
  「先重启网络再下发」（重启会重载 fw4 冲掉规则），并且**守卫前置到重启之前**——
  否则会出现「网络已断才发现规则装不回来」的窗口

#### 验证

- 6 个端点逐一实测：修复前 3 个下发、修复后 0 个下发
- 持久化实测：修复后配置文件不被重写、规则文件不写、无 `nft` 调用
- **正常路径实测**（配置完好时 4 个端点）：全部 200、照常下发、照常落盘、
  `/api/network/restart` 照常重启网络 —— 确认守卫没有误伤
- 损坏配置下 `/api/network/restart` 确认**没有重启网络**
- `test_functional_fixes.py` 52→67 条断言，`mutation_check_functional.py`
  23→31 条变异且 31/31 全捕获（新增 6 条：`_apply_ruleset` 守卫去掉、
  `save_config` 守卫去掉、守卫挪到备份之后、`restart_network` 改回自己写盘、
  守卫挪到重启之后、errorhandler 去掉）

### P0  删掉最后一个反代服务，网关整个挂掉

网关开着但一个反代服务都没有时，生成的 nginx 配置**加载不了**：

```
[emerg] unknown "auth_user" variable
nginx: configuration file /etc/nginx/uci.conf test failed
```

原因不直观。access_log 的 `log_format` 里引用了 `$auth_user` / `$auth_device`，
而真正给这两个变量赋值的 `auth_request_set` 只写在「每个反代服务」的 location 里。
服务数为 0 时那个循环一次都不执行 —— 变量被引用、却从头到尾没人定义，
nginx 直接拒绝加载**整份**配置。

后果不是「网关少了点什么」，是整个网关连 portal 页、登录页一起消失。
而触发路径是个再普通不过的操作：**删掉最后一个反代服务**。
`_deploy_gateway_nginx` 的 `nginx -t` 预检会把它挡下来并回滚，
用户看到的就是「最后一个反代服务删不掉」。

改法：`server` 块里显式给出两个变量的空默认值，位置在 `server_tokens off;` 之后、
服务循环之前。服务 location 里的 `auth_request_set` 会在认证子请求返回后覆盖成
真实值，不影响鉴权与审计。

`.224` 真机复验：修复前 `nginx -t` 报 `[emerg] unknown "auth_user" variable`，
修复后同一份生成物 `test is successful`。

### P0  全新安装打开网关开关直接崩

`DEFAULT_CONFIG` 里**根本没有 `reverse_proxy` 这个键**。全新安装（或配置文件缺失
回落到默认配置）时 `config.get("reverse_proxy")` 就是 `None`，而
`_generate_gateway_nginx_conf` 紧接着就 `rp.get("certificates")`：

```
AttributeError: 'NoneType' object has no attribute 'get'    （app.py:4943，.224 真机复现）
```

`app.py` 里的 `_get_rp_config()` 本来会做这个规范化，但生成函数是绕开它自己读
config 的，所以得自己兜住。改成 `if not isinstance(rp, dict): rp = {}`，
位置必须在取证书**之前** —— 只包住 `settings` 那一步的话兜底形同虚设。

两个 bug 同源：都是「反代服务数为 0」这条路径从来没被走过。

#### 验证

- `.224` 真机：0 服务生成物 `nginx -t` 从 failed 转 successful；缺 `reverse_proxy`
  段时正常生成 3790 字符，不再 AttributeError。真配置已还原（md5 与备份一致）
- `test_functional_fixes.py` 67→75 条断言，`mutation_check_functional.py` 31→35 条
  变异且 35/35 全捕获
- **断言本身也踩过一次坑**：最初用 `'set $auth_device' in src` 判定，
  结果 `auth_request_set $auth_device` 本身就含这个子串 ——
  把 `set` 删掉测试照样全绿。改成 `(?<![A-Za-z0-9_])set\s+\$(\w+)` 才算真的在测。
  顺带修了 `log_format` 多行续行导致 `$auth_device` 根本没被扫到的问题

### P1  12 条死接口：7 条补界面，5 条在工具里说清为什么不做

`tools/check-api-coverage.py` 报出 12 条「后端有路由、前端零调用」。逐条看过之后
**只有 7 条是真缺界面**，其余 5 条本来就不该有界面：

| 端点 | 为什么不补 UI |
|---|---|
| `/api/firewall/china-ips-script` | 脚本下载端点，给外部 crontab 取用 |
| `/api/scripts/update-ipv6.sh` | 同上 |
| `/api/knock-info` | 供 LAN 内客户端脚本读敲门端口，刻意无面板入口 |
| `/api/rules/save` | 已废弃，保留是为了不打断可能存在的 curl 调用方 |
| `/:file` | 前端静态路由，不是 API |

工具原本把这 5 类和真缺口混在同一张清单里报出来。**假阳性比漏报更糟** ——
一份天天误报的清单，用久了就没人看了。新增 `INTENTIONAL_NO_UI` 登记与
独立的【D】类输出，B 类现在为 0。

补上的 7 条界面：

1. **修改密码** —— 侧边栏页脚。此前面板**根本没有改密码入口**，密码只能用
   ssh 手改文件。要求输入两次新密码，不一致时在本地拦下，不浪费旧密码校验额度
2. **规则集健康 + 看门狗状态卡** —— 加在「防火墙状态」页。v0.8.x 加了一整套
   下发失败回滚与看门狗自愈，界面上却一个字都没有：规则没装上、或者被 flush 了
   还没到重试时间，用户只能靠「还能不能上网」反推。现在直接摊开内核真实状态，
   含看门狗的上次自检结果、已恢复次数、冷却与阈值
3. **证书重新上传** —— 本轮刚加固的证书/私钥配对校验，此前**只有 curl 能触发**。
   拆成两个隐藏 file input（先证书后私钥），避免把顺序选反
4. **WAN 公网 IPv6 展示 + 安装定时更新** —— DDNS 的值取自这个地址，此前界面上
   一个字都没说，用户看到「DDNS 不生效」没法判断是地址没取到还是没装定时任务
5. **阿里云记录连通性测试** —— 每条记录一个测试按钮，用该记录自己的 RR/Type/Value。
   AAAA 记录传 `ipv6_source` 不传 `value`，让后端自己去读 `/tmp/ddns-ipv6-N` ——
   顺带把「IPv6 来源文件是空的」这个静默失效点也测到
6. **反代 nginx 配置预览** —— 部署失败时 `nginx -t` 只报行号，没有上下文很难定位

### P1  弹窗被放到了 Alpine 组件根外，整页按钮点不动

这个是**真实浏览器实测逮到的**，curl 打接口完全测不出来。

新增的两个弹窗被写在了 `x-data="app()"` 组件根**之外**。`x-show` 依赖 Alpine
求值，元素在组件根外时 `nginxPreview` 是 `undefined`，指令根本不生效，
遮罩层保持默认的 `display: block` —— 于是它盖住整页，**所有按钮都点不动**。
面板直接变成一块砖。

`tests/e2e_buttons.js probe` 第一步就报：

```
page.click: Timeout 30000ms exceeded
  - <div class="p-4 border-t text-xs text-gray-500">…</div>
    from <div x-show="nginxPreview.show" class="fixed inset-0 z-[200] …">
    subtree intercepts pointer events
```

已加回归断言：按 `<div>` 深度判断每个弹窗/文件输入框是否落在组件根内
（根外的元素深度恒为 0），并检查全文 div 标签配平。

### P1  `x-show` 挡不住 null 解引用，页面刷出 270 条 TypeError

和上一条**同一类根因**：Alpine 指令的语义被想当然地理解了。`x-show` 只是把
`display` 设成 `none`，**内层的 `x-text` 照样求值**。

健康卡的看门狗区当时是 `x-show="rulesHealth.watchdog"`，而 `watchdog` 初值是
`null`（接口还没回来）。于是页面刚打开就刷：

```
[30×] Cannot read properties of null (reading 'last_result')
[30×] Cannot read properties of null (reading 'interval')
[30×] Cannot read properties of null (reading 'consecutive_fails')
[60×] Cannot read properties of null (reading 'enabled')
...  共 270 条
```

阿里云测试的结果行 `x-show="aliyunTest.result && ..."` 是同一个坑：
`x-show` 的条件写了非空判断，同一元素上的 `x-text` 却直接
`aliyunTest.result.message`。

两处都改成 `<template x-if>` —— `x-if` 才是真把子树摘掉，表达式根本不会求值。

**这一条 curl 完全测不出来**：`/api/rules/health` 返回完全正常，
坏的是「数据还没到时模板已经渲染」这一段。只有真在浏览器里打开页面、
让控制台跑一遍才会暴露。

修完之后浏览器复测：页面级错误从 **300 条降到 30 条**，剩下的全是
`/api/network/wan-ipv6` 的 404（`.224` 没有公网 IPv6，属预期情况，
前端已按「无地址」处理）。

顺带修了 `tests/e2e_buttons.js` 的一处缺口：它的弹窗清理只认
`diffModal / presetModalOpen / rpEditingRule`，**新增模态必须登记进去** ——
不然测试器自己点开弹窗后不关，后面每个按钮都被遮罩挡住，
整页报 `Timeout exceeded`，看着像满屏产品 bug。已补上 `pwModal` 与
`nginxPreview`，并写进注释说明为什么漏了会这样。

### P1  网关只放行 IPv6 回环，漏了 IPv4

`public_access=false` 的服务生成的 nginx 片段里写了 `allow ::1;` 却没写
`allow 127.0.0.1;` —— 于是从路由器本机用 IPv4 回环访问自己的网关会被
`deny all` 挡成 403，而同样语义的 `curl https://[::1]:8443/dsm/` 却能通。
同一个「本机」两种结果，纯属遗漏。

安全上没有风险：`127.0.0.1` 只有路由器自己发起的连接才是这个源地址，
公网侧根本无法伪造（WAN 入向本来就有反伪造 drop）。已补，并加了「不是把
`::1` 换成 `127.0.0.1`」的反向断言。

### P1  名单增量操作不持 `_FW_APPLY_LOCK`

`_FW_APPLY_LOCK` 当初引入就是为了防「增量 nft 操作与看门狗的 `nft -f` 交叉执行」，
代码注释里写得很明白 —— 但全库只有 `_apply_ruleset()` 与
`_recover_ruleset_if_unhealthy()` 两处真的拿了。名单的 add / delete / flush /
presets-apply 全在锁外裸跑 `subprocess.run`。

交叉执行的坏结果，第二种更要命：

- add 落在 `nft -f` 的 `flush ruleset` 之后 → 内核元素被冲掉。而
  `_mutate_lists()` 是在内核成功之后才落盘的，磁盘记着这个 IP、内核里没有 ——
  用户看到「已封禁」，实际已经放行
- add 撞上重建中途、set 还不存在的窗口 → nft 报错回 400，但那是几百毫秒的
  瞬时状态，不是用户能理解的失败原因

抽出统一入口 `_nft_set_write()`，五处写操作全部走它。以后再新增名单操作
不会再漏加锁 —— 漏一次就是一次静默的放行。

### P1  看门狗把空规则文件误判成「恢复成功」，`.lastgood` 永远轮不到

`_try_apply_rules_file()` 的第二道检查是「表还在吗」（`_ruleset_is_empty()`）。
这个判据挡不住**语法合法但内容为空**的文件 —— `nft -f` 返回 0，而现网本来就有
`inet fw4` 表，「表还在吗」根本看不出区别，于是返回 True。

后果在调用方：

```python
for _p in (RULES_PATH, RULES_PATH + '.lastgood'):
    if os.path.exists(_p) and _try_apply_rules_file(_p):
        reloaded = True
        break          # ← 空文件在这里就 break 掉了
```

一次假成功就 break，**`.lastgood` 永远轮不到**，接着走 basic lockdown ——
而 basic lockdown 是降级，会丢掉端口转发。规则文件被清空这种场景
（手工编辑、磁盘写满、脚本截断）恰好就是最需要 `.lastgood` 的一次。

第二道检查改用严判据 `_ruleset_is_functional()`：表在、input 链挂 hook、
且带 drop/reject 策略才算生效。空文件在任何一种「需要恢复」的前提下都过不了。

对 `_apply_basic_lockdown()` 无影响 —— 它生成的正是
`type filter hook input priority 0; policy drop`，严判据同样成立。

`.224` 真机演练（用必然失败或必然 no-op 的文件，全程不动现网）：

| 场景 | 结果 |
|---|---|
| 语法错误的规则文件 | 正确拒绝，现网 12 链 163 条规则零改动 |
| `RULES_PATH` / `.lastgood` / `.backup` 三个恢复源 | `nft -c` 全部 rc=0 |
| 健康规则集 + 空文件 | 判成功（正确 —— 规则集确实可用） |
| **不健康规则集 + 空文件** | **判失败 → 会继续试 `.lastgood`** |
| nft 不可用时做健康检查 | fail-closed（判不健康，触发恢复） |
| 不存在的路径 | 正确拒绝 |
| 演练收尾指纹 | 与基线完全一致 |

### 测试：看门狗这批断言从来没做过变异验证

四个既有变异脚本（`mutation_check` / `_security` / `_privilege` / `_functional`）
分别对着 `test_review_fixes` / `test_security_fixes` / `test_privilege_drop` /
`test_functional_fixes`，**没有一个覆盖 `test_fw_recovery.py`** ——
那 58 条断言从来没被证明过「在缺陷重现时会失败」。

新增 `tests/mutation_check_fw_recovery.py`（11 条变异）。首轮跑出 **5 条未被捕获**，
暴露的全是断言本身的洞，逐条补上：

- `nft -f` 非零退出码、`subprocess` 三类异常（`FileNotFoundError` /
  `TimeoutExpired` / `OSError`）—— 原先完全没有断言覆盖，把它们整个删掉测试照样全绿
- 健康判据的严格性：只测了「完整健康」和「缺 policy」两种输入，
  **缺 `hook input` 的样例同时缺了 policy**，被下一条检查兜住，
  于是「删掉 hook input 检查」这个变异抓不到。补一个「换了别的 hook、
  policy drop 还在」的独立样例
- 重试循环的 `break`：原先只测了「第一个失败」，补了「第一个成功就必须停手」，
  否则拿旧 `.lastgood` 盖掉刚恢复好的新规则这种退化也测不出来

断言 58→69 条，变异 11/11 全捕获。

### 面板全 API 烟测（`.224`）

27 个只读端点逐一实测，**全部行为正确**：

- `/api/knock-info` 从本机回环打返回 403 `LAN_ONLY` —— 设计如此（只给 LAN 内
  客户端脚本用）。从真实内网地址（192.168.100.249）匿名打返回 200，
  读出的 4 个端口与内核规则完全一致；其他端点匿名仍是 401
- `/api/network/wan-ipv6` 404 —— `.224` 只有 `fe80::`，环境限制
- `/api/aliyun-ddns/records` 400 —— DDNS 域名未配置
- 带路径参数的端点：`nginx/preview/rp_001` 返回真实 location 片段，
  不存在的 id 与不存在的证书一律 404

### 顺带修掉的工具 bug

`tools/check-api-coverage.py` 初版只抓 `api.get/post/...`，漏了 multipart
上传走的裸 `fetch(...)`，把整条证书上传链路误判成死接口；改用正则抓第一个实参
又会在拼接 URL 的闭合引号处截断。这两处都会产出「后端有路由但前端从不调用」
的**假结论** —— 假阳性比漏报更糟，它会让人去删一个其实在用的接口。改成正经解析
实参（跟踪引号与嵌套）后【A】前端调了但后端没有、【C】方法不匹配均为空。

修正后工具报出的另外 10 条真死接口（前端零调用，且无表单/location 等其他入口）：

```
/api/knock-info                 /api/network/wan-ipv6
/api/aliyun-ddns/test           /api/network/install-ipv6-cron
/api/firewall/china-ips-script  /api/scripts/update-ipv6.sh
/api/rules/health               /api/auth/change-password
/api/reverse-proxy/nginx/preview/:id
/api/reverse-proxy/certificates/:id/reupload
```

其中 **`/api/reverse-proxy/certificates/:id/reupload` 本轮刚加了配对校验，
但前端没有任何入口** —— 也就是说那个修复目前只有 curl 能触发。
是否补一个「重新上传」按钮，也留给你定。

### 测试

新增 `tests/test_functional_fixes.py`（131 条断言）+ `tests/mutation_check_functional.py`
（56 条变异）+ `tests/mutation_check_fw_recovery.py`（11 条变异）。
所有变异 100% 被捕获。

全量回归（本版改动后）：单测 131 + 147 + 51 + 47 + 68 + 69 + 前端 29 全部通过，
变异 56 + 21 + 10 + 19 + 11 共 117 条全部捕获。

跑测试时发现并修掉九处**测试自身的弱点**（不是代码 bug）：

1. 断言匹配到了解释性注释里的字面量（`save_config()`、「配置已保存但网关部署
   失败」）—— 已加 `strip_comments()`，位置判断前先剥注释
2. FIX-6 断言只找 `/tmp/ddns-ipv6-*` 这个串，旁边的 `print("[WARN] 写 …失败")`
   里有同样的串，于是「删掉真正的写入、留着警告」也能通过 —— 改成盯 `open()` 调用本身
3. `test_privilege_drop.py` 的 PD-11 按参数名 `(key_path|NFTABLES_WEB_KEY)` 统计
   加固调用点，**把两条 ACME 路径排除在统计之外** —— 这正是 P0-2 能长期存在的
   原因：断言号称「补权限与 chmod 一一对应」，却对 ACME 完全失明。改成数全部
   调用点（5 处）并新增「chmod 之后紧跟加固」的顺序断言，对应补 N8/N9/N10 三条变异
4. FIX-10 的断言用 `'set $auth_device' in src` 判定有没有默认值 ——
   `auth_request_set $auth_device` 本身就含这个子串，**把真正的 `set` 删掉测试照样
   全绿**。第一版就是这样漏过去的，是变异验证抓出来的。改成
   `(?<![A-Za-z0-9_])set\s+\$(\w+)`，顺带发现 `log_format` 是多行续行、
   只扫首行的话 `$auth_device` 根本没被检查到
5. `test_fw_recovery.py` 的健康判据只喂了「完整健康」和「缺 policy」两种输入 ——
   「缺 `hook input`」那个样例同时缺了 policy，被下一条检查兜住，于是
   **删掉 `hook input` 检查这个变异完全抓不到**。补一个「换成 forward hook、
   `policy drop` 还在」的独立样例；另补 `nft -f` 非零退出码、`subprocess` 三类异常、
   重试循环 `break` 的三组输入
6. FIX-12 前端断言写成「函数里出现过 `e.data`」—— 模板串 `${e.data.succeeded_count}`
   里也有 e.data，把它改成 null 断言照样通过。改成盯绑定本身
   `const failed = e.data && e.data.failed`
7. FIX-13 断言用「全文出现过『修改密码』」判断侧边栏入口 —— 弹窗那段的分隔注释里
   也有同样四个字，把真正的按钮删掉测试照样绿。改成先切出侧边栏范围再找
8. FIX-13 对工具源码的断言没剥注释 —— 把登记项注释掉，字符串本身还在文件里。
   同一个坑今天已经踩到第五次：注释、子串、多行续行、模板串、Python 注释
9. 这一轮整体缺一类断言：**Alpine 指令语义**（组件根位置、`x-show` 与 `x-if`
   的区别）。加了两条：按 `<div>` 深度确认弹窗在 `x-data="app()"` 根内；
   扫出「同一元素上既有 `x-show` 又解引用可能为 null 的对象」这个反模式

### 回归（改动前后各跑一遍）

```
单元  test_review_fixes 147 · test_privilege_drop 51 · test_auth_gateway 68
      test_security_fixes 47 · test_fw_recovery 69 · test_log_parser
      test_functional_fixes 131 · 前端 test_frontend.js 29       —— 全绿
变异  mutation_check 21/21 · mutation_check_security 10/10
      mutation_check_privilege 19/19 · mutation_check_functional 56/56
      mutation_check_fw_recovery 11/11                            —— 全捕获
```

### 不在本版范围

- **P0-1**：开启「境外 IP 拦截」但集合为空时，`china_ipv4 drop` 在 `input_wan`
  链内排第 2 条，敲门在第 25 条、白名单放行在第 30 条 —— 空集合会让 WAN IPv4
  全断，且语法合法所以不回滚。**规则链问题按要求本轮不改**
- 面板 9 条低危 finding + 3 个网关低危 finding
- 证书链路的真机验证见下

### 真机验证进度（.224，OpenWrt 测试机）

已在本机部署实测通过的：

- **证书链路全通过** —— 配对上传 → `640 root:nogroup` → worker `nobody(65534)`
  fork 降权后**真读到私钥**；传错私钥/垃圾文件 → 400 且原文件字节未变、无 `.tmp`
  残留；重传三种情形全部保住原文件；ACME 场景 `600 root:root` → 加固后
  `640 root:nogroup`
- **反代 nginx 配置生成 9 场景** —— 基线/单服务/多服务/WebSocket/非公网/网关关闭，
  全部用服务真实参数 `nginx -t -c /etc/nginx/uci.conf` rc=0
- **认证网关** —— 登录成功、`/auth/verify` 对伪造 token 正确返回 **401**、
  错密码前 5 次 401、第 6 次起 429 限流生效
- **P1-2 的 CSP** —— `/auth/static/login.html` 与 `portal.html` 经网关 8443 均已带上，
  两个取值正确区分（登录页 `form-action 'self'` / 门户页 `form-action 'none'`）；
  白名单外文件（`../app.py`、`secret.txt`）一律 404
- **本版两个 P0** —— 0 服务生成物 `nginx -t` 转 successful；缺 `reverse_proxy`
  段时不再 AttributeError
- **看门狗恢复链路演练** —— 用必然失败或必然 no-op 的规则文件，全程不动现网：
  语法错误正确拒绝、三个恢复源文件 `nft -c` 全过、**不健康规则集 + 空文件正确
  判失败**（修复前会误报成功）、nft 不可用时 fail-closed；
  收尾规则集指纹（12 链 / 163 条）与基线完全一致
- **面板 27 个只读端点** —— 全部行为正确，含带路径参数的
  `nginx/preview/<id>` 与 `certificates/<id>/download`

- **规则生成顺序（直接读内核，不重新渲染不下发）** —— 14 条断言全通过：
  `forward` 链 `BLACKLIST4-FWD`/`BLACKLIST6-FWD` 落在第 2、3 条、`established`
  accept 在第 4 条；`input` 链黑名单第 11 条、`established` 第 13 条；
  `jump input_wan` 在黑名单之后（第 29 条）；敲门端口集合 4 个与配置一致；
  5 个关键集合全部已定义

仍未验证：

- 真实 NAS/DSM 门户后端（目前仍接 `/tmp/fake_services.py`）
- 真实 WAN 敲门限流（`.224` 无物理 WAN 口且内核不支持任何虚拟网卡类型，
  结构上做不到，需 Proxmox 侧加虚拟网卡）
- **看门狗「整体 flush 后自愈」的完整演练** —— 做这一项必须真的删掉
  `inet fw4` 表，而那张表同时承载 OpenWrt 自己的 LAN 放行（含 SSH），
  看门狗只会恢复我们的自定义规则、恢复不了 OpenWrt 基线，
  可能永久失去这台测试机。已改用「必然失败 / 必然 no-op 的规则文件」
  演练看门狗的**决策逻辑**（这部分已全覆盖），自愈本身靠 69 条单测 + 11 条变异保证

## [v0.8.2] - 2026-10-12

认证网关**降权运行**。这是本项目第一次把「公网可达的代码」移出 root 权限域。

### 问题

`auth_gateway.py` 是**唯一直接处理公网请求的进程**：面板只在 LAN、认证 API
只在回环，但 nginx 的 `auth_request` 会把公网流量送进这里。

它此前由 init 脚本以 root 启动，而它**根本不需要 root** —— 只读配置、
做 PBKDF2、绑 `127.0.0.1:8444`（>1024 不需特权）、调 `logger`（任意用户可调）。

后果不是「服务被攻破」，而是**整台机器沦陷**：任何一处 RCE 都可以
`nft flush ruleset` 关掉防火墙、`kill` 掉看门狗进程让规则集永远不再自愈、
读 SSH 私钥与 `/etc/shadow`。看门狗挡不住这个 —— 它和被保护对象在同一个
root 权限域，攻击者拿到 root 的第一件事就是把它关掉。

### 根因

降权不能靠外部工具：OpenWrt 没有 `useradd` / `adduser` / `su` / `setpriv`
（busybox 未编译这些 applet），`chroot` 也是 BusyBox 版且**没有 `--userspec`**，
只能切根目录不能降权。所以降权只能在 Python 进程内用 `os.setuid()` 完成。

### 改法

- `auth_gateway.py` 新增 `_drop_privileges()`，**模块级执行**（与既有的
  `_assert_loopback_bind()` 同一模式：导入即生效，gunicorn / waitress 加载也逃不掉）
- init 脚本幂等建 `nftweb` 用户（直接追加 `/etc/passwd`+`/etc/group`，
  与 dnsmasq / logd / ubus 同样的做法），预建数据文件并改属主
- `/etc/nftables` 设 setgid：日后 `app.py` 以 root 重建密码/密钥文件时，
  组仍归 `nftweb`，网关读得到 —— 少了这一步，「用户改密码 → 文件被重建 →
  属主变 root → 登录全断」会在某个随机时刻炸开

### 安全设计要点（每条都有对应测试）

- **失败即退出**：降权失败绝不「打印警告然后继续以 root 跑」——
  那比不写更糟，读代码的人会以为已经降权了
- **两道独立防线**：①`except` 里 `raise SystemExit(1)` ②降权后复核
  `geteuid`/`getuid`/`getgid`。只拆①，②仍然独立拦住 —— 变异验证里
  专门区分了这两种情况，避免把「变异太弱」误判成「测试没用」
- **`initgroups` 不可省**：只 `setuid` 不清组权限 = 假降权
- **顺序不可反**：`setgid` 必须在 `setuid` 之前，uid 一旦非 0 就再也改不了 gid
- **`AUTH_DROP_UID=0` 直接拒绝启动**：那等于没有降权
- init 脚本在进程起来后**再核一次 `/proc/<pid>/status` 的 uid**，为 0 就杀掉并报错

### 真机实测（.224，OpenWrt 24.10，Python 3.11.14）

```
进程身份    Uid: 1000 1000 1000 1000 / Gid: 1000 1000 1000 1000 / Groups: 1000
文件可读    password / secret / config.json  → OK（登录不断）
文件不可读  /etc/shadow、dropbear 私钥、/root 下任何东西 → Permission denied
反向验证    nft flush ruleset        → Operation not permitted (you must be root)
            nft add rule ... accept  → Operation not permitted
            kill -9 1                → Operation not permitted
端到端      网关登录成功 {"success":true,"user":"kirito"}，审计日志正常落盘
```

`cp nftables-web-secret → /tmp` 仍然成功，这是**必须保留**的能力 ——
网关要靠这个密钥签 token，砍掉它等于砍掉认证。

### 顺带修掉的两个问题

- `_drop_privileges()` 未配置环境变量时整体跳过，开发机与单元测试不受影响
- 发现 `/etc/nftables.d/` 下的规则文件本来就是 644 且含无密钥 —— 未改动，
  仅记录在此以免后续误以为与本次改动有关

---

## [v0.8.2-rc1] 2026-10-12 · nginx worker 同样降权

与上面的网关降权同属一类，但入口在 HTTP 层而不是应用层。

### 问题

`/etc/nginx/uci.conf` 里是显式的 `user root;`，worker 进程以 root 运行。
master 需要 root（读私钥、bind 低端口），但**真正处理公网流量的是 worker**。
nginx 侧任何一处漏洞（请求走私、模块缺陷、配置误伤）落地就是 root。

### 改法

新增 `tools/nginx-priv-drop.sh`：master 保留 root，worker 降到 `nobody`。
配套在 `app.py` 加 `_harden_key_for_nginx_worker()`，在**每一次私钥写入之后**
补组读权限 —— 见下面「私钥权限为什么必须跟着每次写入走」。

### 实测踩到的三个坑（都已写成回归测试）

1. **`nginx -t` 验的不是服务实际加载的配置。** 裸 `nginx -t` 读
   `/etc/nginx/nginx.conf`，而 init 脚本起的是 `nginx -c /etc/nginx/uci.conf`。
   两份文件不同，于是拿到一个**假绿灯**，真正的原因根本不在被验的那份里，
   `restart` 之后网关直接起不来。→ 脚本改为 `nginx -t -c "$CONF"`。

2. **nginx 的 `user` 指令内部是 `getpwnam()` + `getgrnam()`，两个都要查，
   而且用同一个名字。** OpenWrt 的 `/etc/passwd` 里有 `nobody`，
   `/etc/group` 里却只有 `nogroup` 没有 `nobody` —— 只查用户会漏掉这一半，
   nginx 报 `getgrnam("nobody") failed` 拒绝启动。→ 脚本检测并自动补建组。

3. **`user` 指令只在 master 启动时生效，`reload` 不改 worker 身份。**
   实测 reload 之后 worker 仍然是 uid=0。→ 指令有变更时走
   `/etc/init.d/nginx stop && start`。

另外复核那段原本写成「遍历进程、发现 worker 还是 uid=0 就报错」，
**但 nginx 一个进程都没有时循环体一次都不进，BAD 保持 0，脚本会谎报「完成」**。
已补进程数量下限判断。

### 私钥权限为什么必须跟着每次写入走

`app.py` 在三处（上传 `:5669`、ACME 续期 `:5773`、自签生成 `:6252`）
都会 `os.chmod(key, 0o600)`。那是对的 —— 私钥本就不该被别人读到。
但 worker 现在以 `nobody` 运行，必须能读私钥才能做 TLS 握手，于是：

> 只改一次 nginx 的 user → 下一次换证书，worker 立刻读不到私钥，
> 而 nginx 的表现只是「TLS 握手失败」，没有任何提示说明是权限问题。

规则：**谁把权限打回 600，谁就负责补成 worker 可读。**
`640 root:nobody` 对「其他用户」依然完全关闭，实际暴露面和 600 等价。

### 真机实测（.224）

```
master pid=6965 uid=0                      ← 保留 root，正确
worker pid=7172 uid=65534                  ← 已降权
worker pid=7173 uid=65534
privkey.pem  root:nogroup 640              ← worker 的 gid 65534 读得到
端到端      网关 200 / 登录 200 / 面板 200 / 防火墙 257 行
```

### 关于 chroot：评估后决定不做

评估过给认证网关加 chroot 做二层隔离，**结论是不做**，理由是数据不支持：

- 磁盘只剩 **19.6M**，Python stdlib + site-packages 是 **52M**
- 放进去只能走「硬链接约 3 万 inode」或「bind mount 等于把 52M 全搬进去」
  两条路，前者在 2 核机器上很慢，后者让「最小化」名存实亡
- 还要在主机上留 5 个 mount，崩溃即残留
- 而它相对已拿到的非 root 权限，边际收益很小：实测 `nftweb` 本来就
  读不到 `/etc/shadow`、SSH 私钥、`/root`，也动不了 `nft`、杀不了进程

风险收益不成比例，不做。

### 仍未覆盖

- **证书链路**（上传 / ACME / 续期 / 设默认 / 删除保护）真机零验证
- **WAN 侧规则在任何机器上都未执行过**：`.224` 无物理 WAN 口，且内核不支持
  任何虚拟网卡类型（veth / dummy / macvlan / ipvlan 均 `Not supported`），
  结构上不具备验证条件。需在有真 WAN 口的设备上验收
- 面板 9 条 finding + 网关 3 条低危仍按原划界暂缓

## [v0.8.1] - 2026-10-11

反代模块收敛为**认证网关单轨**，并重做管理界面。
v0.8.0 里一条规则同时生成「独立站点 conf」和「网关 location」两套暴露面，
但 `path_prefix` 既没有写入路径也没有 UI —— 实际只有无认证的独立站点在跑。
这一版砍掉独立站点，所有服务统一挂在网关的一个端口下。

### 后端：字段校验统一到唯一入口

`PUT /api/reverse-proxy/rules/<id>` 的 `target_protocol` 和 `listen_port` **零校验**。
实测传 `"http;}\n server { listen 9999; #"` 能注入出第二个 server 块并落盘；
`listen_port` 传 `''` / `True` / `443.5` / `[443]` 会拼出任意文件名。

根因是 POST 和 PUT 各抄了一份校验，PUT 那边漏了。现在统一为 `_validate_rp_service`，
POST/PUT 共用 —— 两份校验迟早会再次分叉。

### 后端：修掉一批审核缺陷

- 证书删除保护检查 `rules[].ssl_cert_id`（该字段已随单轨移除）→ 恒空 →
  删掉网关默认证书不被拦。改查 `settings.default_cert_id`
- `_deploy_gateway_nginx._undo` 先 `rmtree` 快照再 `copytree` 恢复 → 恢复必然失败，
  且失败前已把整个 `conf.d` 删光，用户自己的站点配置全丢
- nginx reload 三处裸调 `/etc/init.d/nginx`，普通 Linux 直接 `FileNotFoundError`
  → 统一走 `_nginx_reload`，`NGINX_INIT_PATH` 抽成常量
- `client_max_body_size` 只允许大写 `K/M/G`，照 nginx 文档填最常见的 `10m` 反被拒
  → 大小写都收、输出归一

### 后端：规则结构简化

规则简化为 `{id, name, enabled, path_prefix, target_address, target_protocol,
public_access, client_max_body_size, websocket_enabled, icon}`，
删除 `domain` / `listen_port` / `ssl_cert_id`。

删除 `_generate_nginx_conf` / `_write_nginx_conf_file` / `_remove_nginx_conf_file` /
`_remove_nginx_conf_by_domain_port`（约 250 行）。新增 `_migrate_rp_rules`：
旧规则自动派生 `path_prefix`（`nas.test` → `/nas`），挂在 `load_config` 上。

### 前端：界面重做

- 反代表单换字段，新增网关配置卡（总开关/端口/会话超时/绝对有效期/内网免登录/状态行）
- 修 6 个缺陷：编辑服务会变追加（`delete _editIndex` 写在判断之前，条件恒假）、
  新增按钮种子字段全是旧的、卡片不显示路径前缀和目标地址、
  卡片无任何操作按钮（`editRpRule`/`deleteRpRule`/`testRpRule` 从未被 HTML 引用）、
  `cancelRpEdit` 未定义导致点「取消」抛异常、WebSocket 说明里的损坏字符

### 验证

- 后端回归 142 + 68，变异验证 19/19 捕获
- 面板 e2e 24/24（连跑 3 次稳定）、网关 e2e 16/16、视觉 22/22
- 真机 OpenWrt：nginx -t 通过；`/nas/` 走 auth_request + 跳登录，
  `/dsm/` 走内网 allow/deny，60MB 上传被 413 拦下

### 已知未覆盖

- 证书链路（上传 / ACME / 续期 / 设默认 / 删除保护）在真机一次都没跑过，
  测试机用的是自签证书，证书库为空
- 门户后端是假服务（`/tmp/fake_services.py`），未对接真实群晖/DSM
- `.224` 无物理 WAN 口，敲门限流按源分桶虽有真实流量规则但未经真实 WAN 验证
- 反代保存仍会连带调用 `_apply_ruleset` 重刷防火墙，与「应用规则」按钮解耦待做

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

### 安全修复：Shannon 渗透测试实测确认的公网认证口缺陷

2026-10-07 用 Shannon v3.2.0 对认证网关（公网唯一入口）与管理面板各跑一轮，
逐条独立复现验证后修复。**本节只列公网认证口（进程 B）的 4 处**，
管理面板那 9 条按用户判断属 LAN 面，暂缓。

**① [critical] `0.0.0.0/0` / `::/0` 被当成合法网段 → 全员免认证**

`_safe_cidr` 只校验「是不是合法 CIDR」，`0.0.0.0/0` 完全合法。
`.224` 上实测完整链路：

```
POST /api/config {"lan_subnet4":"0.0.0.0/0","lan_subnet6":"::/0"}
→ {"success":true,"risks":[]}          ← 连风险提示都没有
→ 8.8.8.8 / 1.1.1.1 / 203.0.113.5 全部 /auth/verify → 200 + X-Auth-Via: lan-bypass
```

填错一个网段就让公网网关对**全互联网免认证**。双层修复：
`validate_config` 直接拒绝并给出中文原因（`0.0.0.0/0` → 400 INVALID_CONFIG，
不落盘），认证服务侧也忽略 `/0` 作为纵深防御（配置可能被手改或被备份恢复）。

**② [high] 回环绑定检查只在 `if __name__ == "__main__":` 里**

一旦模块被 WSGI 方式加载（gunicorn / uWSGI / waitress / `flask run`），
`__main__` 不成立，这道检查就**静默消失**。而绑 `0.0.0.0` 意味着认证系统
多一个可从公网直接触达的入口，是本项目安全模型里最不能破的一条。
改为 `_assert_loopback_bind()` 在**模块加载时**执行，导入即校验。

**③ [high] `client_ip()` 无条件采信 `X-Real-IP` / `X-Forwarded-For`**

和 ② 串成一条完整攻击链：能碰到认证端口 → 声明任意源 IP → 冒充内网
→ `is_lan_source` 放行 → 所有 `public_access=true` 的服务直通。
改为**只有 `request.remote_addr` 是回环时才采信代理头**（真实 nginx 走的就是
这条路径，实测未误伤）；非回环来源只认真实对端，判不出内网就落到「要认证」。

**④ [high] `is_lan_source` 在没有可用网段时回落 `is_private`**

回落意味着「对所有 RFC1918 地址免认证」——咖啡厅 / 酒店 / 公司 / 邻居
Wi-Fi 的访客源 IP 就是私网段，能直连公网网关端口并被放行。
改为**没有可用网段就一律要求认证**（fail-closed）。
副作用：从未配过网段的存量用户会突然需要登录，这是有意为之。

**⑤ [medium] PBKDF2 短路时序预言机**

哈希未配置/损坏时直接 `return False`，耗时不到 1ms；正常路径要跑几万到
几十万轮迭代。攻击者只发一个 `{"password":"x"}` 就能靠响应耗时区分
「部署没配密码」和「配了密码」，等于一个免认证的状态枚举口。
改为异常路径也真跑一次 PBKDF2（迭代数取下限，避免畸形配置触发天文数字
的迭代把请求线程拖死）。

**验证**：认证网关 40/40 → **64/64**；8 个人为变异**全部被测试捕获**
（`0.0.0.0/0` 放行 / 回落 is_private / 无条件信任头 / 移除 PBKDF2 dummy /
星期必填 / `Origin:null` 放行 / 续期不吊销 / 缺省改回 True）；
`.224` 真机复测 `/0` 返回 400 且不落盘；浏览器回归 面板 42/42 + 门户 13/13。

测试侧同时修掉两个自身缺陷：
- 时序测试原先用 `open(PWD).read()` 拿到的是 JSON 文本而非哈希串，
  `split("$")` 后 algo 对不上直接抛错 —— **两条路径都走 except，等于拿自己
  跟自己比**，测不出任何东西
- 配置读写散落 7 处手工失效 mtime 缓存，漏了一处；而同一时钟刻度内两次写入
  得到完全相同的 mtime，缓存 key 不变就读到陈旧配置，表现为「代码是对的但
  测试说功能坏了」。改成集中 `set_cfg()` helper

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
