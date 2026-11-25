# Ghost Firewall (nftables-web-v2)

> 基于 OpenWrt 的防火墙 Web 管理面板

**版本：** v0.19.19

> 仓库主页（功能速览 / 截图 / 安全设计）见 [根 README](../README.md)。

Ghost Firewall 是一个运行在 OpenWrt 上的轻量防火墙管理工具，通过 Web 界面管理 nftables 规则，提供端口敲门、端口转发、DDNS、反向代理等功能。

## 访问入口

| 入口 | 地址 | 暴露面 | 用途 |
|------|------|--------|------|
| 管理面板 | `https://<路由器IP>:5443` | **仅局域网** | nftables 规则、反代配置、DDNS、日志 |
| 认证网关 | `https://<域名或公网IP>:<自定义端口>/` | 可映射公网 | 单端口访问所有服务，公网需认证 |
| 认证服务 | `127.0.0.1:8444` | **本机专属** | 网关的认证后端，公网不可达 |

> v0.8.0 起面板不再有任何公网入口。原先的 HTTP 5000 跳转器已删除
> （它自 0.7.9.1 起就被防火墙 `policy drop` 拦住、从未可达，属于死代码）。
>
> **防火墙控制入口**（2026-11-04）：面板的反代管理页有「添加防火墙控制入口」按钮，
> 一键加一条 `/fw/` 规则，把**管理面板自己**经网关暴露出来 ——
> 登录 8443 的门户后就能点进防火墙控制台。
> 该规则**仅内网可访问**（`public_access=false`，网关侧按 LAN 网段放行），
> 「面板无公网入口」的设计不变；
> 规则自带的「启用这条服务」就是那个开关 —— 关掉后门户卡片同步消失。
>
> 预设规则会**自动填好**三个字段（手工填漏了就是「页面能开、数据全 404」）：
> 上游协议 `https`（面板自己走 TLS）、
> API 路径改写 `/api/`、根绝对路径改写（面板的 API、字体、背景图都是根绝对路径）。
>
> ⚠️ 门户登录态与面板登录态是**两套**（网关 token vs 面板 session），
> `/fw/` 只是把面板反向代理到网关的同一个端口下，**没有打通两套会话** ⇒
> 点开卡片后仍需在面板这一层输一次密码。要「登录一次直接进控制台」
> 需另做 SSO（本轮未做）。
>
> **登录页背景**（2026-11-04）：门户、面板、**网关登录页**三处都从
> 「原版月白」与「TRAE 原版」两档里**每次打开随机**挑一个；
> URL 加 `?pfstyle=moonstone` / `?pfstyle=trae` 可钉死某一档。
> 面板登录遮罩的不透明度已从 88% 调到 58%（登录页能看见背景了）。
>
> **两条安全默认值**（2026-11-05）：
>
> - `auth_lan_bypass`（LAN 内免登录）的**缺省值改成 False** ——
>   原来面板默认开、网关默认关，两边不一致；
>   现在统一为「关」（要放行由管理员显式打开）。
>   ⚠️ 只改缺省值：配置里已经写了这个键的机器行为不变。
> - `POST /api/config` **强制要求 `config_rev`** ——
>   不带版本号的调用一律 409 `CONFIG_REV_REQUIRED`。
>   带版本号但对不上是 409 `CONFIG_STALE`（语义不同：一个是「没带」，一个是「过期了」）。
>   ⇒ **用脚本改配置要先 `GET /api/config` 取一份最新快照，带上 `config_rev` 再提交。**

## 功能一览

| 模块 | 说明 |
|------|------|
| **认证网关** | 单端口汇聚所有服务，按路径前缀区分，公网访问需认证（v0.8.0+） |
| **网络接口** | PPPoE 拨号、路由器网关 IP 管理 |
| **端口敲门** | 自定义 4 端口敲门序列，白名单 IP，超时设置 |
| **端口转发** | TCP/UDP 转发，IPv4/IPv6 双栈支持 |
| **反代管理** | Nginx 反向代理，SSL 证书（手动上传 + ACME 自动申请），多 DNS 服务商（v0.7.0+）；**路径改写新建时自动探测，不用手填** |
| **访问控制** | LAN 模式 / 信任 IP 模式 |
| **日志管理** | 各类日志开关 + 环形缓冲大小（`log_size`）+ 远程日志转发（logd） |
| **系统日志** | 系统日志与认证审计合并在一条时间线，带设备指纹；级别/来源组合筛选，导出 CSV/JSON |
| **国外 IP 拦截** | 自动拦截境外 IP |
| **DNS 局域网解析** | 允许 LAN 设备通过路由器查询内网 DNS 服务器（如 adguardhome） |
| **DDNS** | 通用 DDNS + 阿里云 DDNS，多 DNS 服务商，IPv6 来源选择 |
| **防火墙状态** | nftables 规则实时查看 |
| **名单管理** | IP 黑白名单 |

### 反代的路径改写：新建时自动探测，不用手填

反代表单里**没有**「上游 API 路径前缀」输入框，也没有「根绝对路径改写」勾选框 ——
**新建规则时由后端自动探测上游后决定**（2026-11-24 起）。

理由是这两个字段填错的后果是「**页面能开、数据接口全 404**」，
症状极具迷惑性（用户会以为是自己部署坏了）；而上游的接口清单与首页正文
**探得到** ⇒ 机器比人更清楚该填什么。

自动探测的判定口径：

| 字段 | 怎么定的 |
|------|----------|
| API 路径前缀 | 读上游自己的 `openapi.json`，取**命中条数最多**的那一段（不按名字排 —— 字母序里 `/admin/` 会排到 `/api/` 前面，选错 ⇒ 接口全 404） |
| 根绝对路径改写 | 首页正文里有根绝对路径（`href="/`、`src="/`、`action="/`）**且没有**协议相对 URL（`href="//cdn…"`）时才开 |

⚠️ 协议相对 URL 也要排除：nginx 的 `sub_filter` 只支持**字面量**，
没法把 `//` 排除掉 ⇒ `href="//cdn/x.css"` 也会被 `href="/` 命中 ⇒ 开了就会改坏它们。

⚠️ **只对 LAN 网段内的目标探测**（与其它诊断端点同一条 SSRF 边界）。
探测失败时**保留原值不动** —— 失败不等于结论是「不需要」。

⚠️ **编辑已有规则不会重新探测**（要重新探测只能删了重建）：① 面板每次保存
都会把所有规则逐条 PUT，加探测等于每次保存多发 N 次网络请求；
② 内置 `/fw` 规则的路径前缀是**预设值**（面板自己的 API、字体、背景图
都是根绝对路径），重探可能把设好的开关改掉。

两个诊断端点 `/api/reverse-proxy/detect-api-prefix` 与
`/api/reverse-proxy/detect-protocol-relative` 保留为排查入口，返回结构不变。

## 安装

要求 OpenWrt 系统（opkg 或 apk 包管理器），通过一键脚本安装：

```bash
wget -O /tmp/setup.sh https://raw.githubusercontent.com/fzyt/ghost-firewall/main/nftables-publish-v0.7.9-nospa/setup/setup.sh
sh /tmp/setup.sh
```

脚本自动安装所有依赖（python3、flask、nftables-json、nginx 等）。安装后访问
`https://路由器IP:5443`，首次启动会自动生成随机端口敲门序列。

> `ddns-scripts-namecheap` 在部分 OpenWrt 版本中不存在，不影响其他功能。

覆盖安装加 `--force` 参数：

```bash
sh /tmp/setup.sh --force
```

## 升级部署（开发机执行）

`setup.sh` 面向**全新安装**。已有设备上的**版本升级**用 `tools/deploy.sh`：

```bash
./tools/deploy.sh --host 192.168.100.233              # 升级（只换代码）
./tools/deploy.sh --host 192.168.100.233 --apply      # 升级并应用规则集
./tools/deploy.sh --host 192.168.100.233 --dry-run    # 只打印计划
```

九个阶段：连通+身份确认 → 判定路径 → 备份 → 传输 → 权限与密钥 → 语法预检
→ 重启服务 → 应用（可选）→ 自检。任何一步失败**自动回滚**。

几条刻意的设计：

- **只覆盖，不删除。** 配置、口令、密钥、限流表一个都不碰。老的
  `redeploy.sh` 里的 `rm -rf $APP` 会把「谁能进这台路由器」的凭据一起删掉。
- **换代码 ≠ 生效。** 规则集（`/etc/nftables.d/99-custom-rules.nft`）和 nginx
  网关配置都是面板**运行时**生成的，部署代码不会让它们变 —— 想生效要么在面板里
  点「应用」，要么部署时加 `--apply`。
- **令牌密钥不能变。** `/etc/nftables/nftables-web-secret` 变了 = 所有设备的
  网关令牌全部作废 = 用户全部要重新登录。脚本部署前后比对 md5，不一致会大声报。
- **不重启路由器**，只重启本项目的两个服务。
- 自检会验：两个进程的 uid（面板 root / 网关 nftweb）、三个端口、
  三个 HTTP 200、四个关键文件的权限、**网关的 gid == 配置文件的组 gid**
  （读不到配置时网关会**静默退回默认值**，不报错）、版本号、
  以及「规则集 md5 与 crontab 条数没被改动」。

设备上每次部署都会留一份备份（含一份 `restore.sh`），备份目录
`/root/nftables-web-backups/<时间戳>/`，默认保留最近 5 份。手工回滚：

```bash
ssh root@192.168.100.233 'sh /root/nftables-web-backups/<时间戳>/restore.sh'
```

### 装依赖失败：报「no such package」多半不是包不存在

弱网下 apk 把索引文件 `packages.adb` 拉到一半断线：

```
WARNING: fetching .../packages.adb: unexpected end of file
ERROR: unable to select packages:
  python3-flask (no such package):
```

注意它报的**不是网络错误，而是「这个包不存在」** —— 一个纯网络问题被伪装成了
「仓库里没这个包」，而且这个误报会一直持续到索引被重下为止。
`setup.sh` 现在会自动 `apk update` 刷新索引后重试（最多 3 次），
但如果机器到官方源实在不通，可以把源换到国内镜像（OpenWrt 25.x 的源配置在
`/etc/apk/repositories.d/distfeeds.list`）：

```bash
# 以南京大学镜像为例，把每条 downloads.openwrt.org 换成 mirror.nju.edu.cn
sed -i 's#https://downloads.openwrt.org/releases#https://mirror.nju.edu.cn/openwrt/releases#' \
    /etc/apk/repositories.d/distfeeds.list
apk update
```

实测 8 条索引全部可达、单条下载都在 0.35 秒内（官方源 3.2 秒且经常断）。
换了源之后**不需要**重装设备，重跑 `./tools/deploy.sh --host <ip> --yes` 即可续装。

> 注意：`/etc/apk/repositories`（旧布局）是空的，OpenWrt 25.x 读的是
> `/etc/apk/repositories.d/distfeeds.list`。

## 项目结构

```
nftables-publish-v0.7.9-nospa/
├── setup/
│   ├── setup.sh                  # 一键安装脚本（全新设备）
│   └── knock-*.sh|.py|.ps1       # 端口敲门客户端（LAN / WAN）
├── tools/
│   ├── deploy.sh                 # 升级部署脚本（开发机执行，SSH 驱动设备）
│   └── verify-fixes.sh           # 真机复验（拷到设备上跑）
└── backend/
    ├── app.py                    # 进程 A：管理面板（5443，仅 LAN）
    ├── auth_gateway.py           # 进程 B：认证 API（127.0.0.1）
    ├── template_engine.py        # 模板引擎
    ├── nftables-web.init         # 面板 init 脚本
    ├── nftables-web-auth.init    # 认证服务 init 脚本
    ├── templates/
    │   └── nftables.conf         # nftables 规则模板
    └── static/                   # 登录页 / 服务门户的前端（零依赖零构建）
        ├── base.css              # 设计令牌 + 布局 + 服务卡片
        ├── gate.css              # 「光之门」转场动画
        ├── login.html/.js        # 登录页
        ├── portal.html/.js       # 服务门户（背景每次打开在「原版月白」与「TRAE 原版」之间随机；URL 加 ?pfstyle= 可钉死某一档）
        └── pixelfield.js         # 像素场背景引擎（光带扫过方块场 / 方向随机换向 + 速度随机起伏 / 规整量化点阵 + 硬边二值 / TRAE 原版复刻：7px 晶格 + 5px 实心方块 + 按块随机绿白 / 月白·TRAE 合档：方块用原方案 + 流动用 TRAE 域扭曲 / TRAE·原版方块：TRAE 原版为底 + 方块换成原方案：12px 晶格小点 + 月白银白 + 余晖渐隐）
frontend/
├── index.html                    # 面板前端（背景：像素场 + 环境光 + 细网格三层）
├── app.js                        # 面板逻辑
├── pixelbg.js                    # 面板背景选档与挂载（原版月白 / TRAE 原版 每次打开随机）
├── styles.css                    # 样式
└── assets/                       # 静态资源
```

> 面板的**跟随鼠标动效**（追光 / 磁性按钮 / 倾斜卡片）已于 2026-11-08 移除 ——
> 原 `frontend/fx.js` 整个引擎连同引用一并删除，页面不再挂 `pointermove`
> 监听、也不再跑任何 rAF 循环。
> 光源与卡片柔光**保留但固定不动**（CSS 变量的缺省值接管）。
> ⚠ 另注：网关/门户侧的 `backend/static/fx.js`（背景变体引擎）更早就在
> v0.18.0 删掉了，与面板这个 fx.js **是两回事**。

> 面板与门户的像素场引擎是**同一份**源码（`backend/static/pixelfield.js`）：
> 面板的静态服务在 `frontend/` 找不到时会**回退**到 `backend/static/` 取，
> 但只放行白名单里的文件（见 `backend/app.py` 的 `SHARED_STATIC_FILES`）。
> 刻意不在 `frontend/` 留拷贝 —— 2700 行源码两份拷贝必然漂移。

## 已知限制

- **ddns-scripts-namecheap**：OpenWrt 25.x 仓库中暂无此包，Namecheap DDNS 功能暂不可用
- **OpenWrt 25.x**：包管理器从 opkg 切换到 apk，setup.sh 已做兼容处理。另有几处
  25.x 生态特有的坑也已处理（详见 `setup/SETUP.md` 的「已知问题」）：
  ① `wget-ssl` 与它自己的依赖 `libopenssl3` 的鸡生蛋（会让 apk 的下载器中途坏掉，
  之后什么都下不来）—— setup.sh 会用 curl 顶替 wget 自愈。⚠️ 判"wget 坏了"必须看
  **输出特征**（`Error relocating` / `symbol not found`），**不能**拿
  `wget --version` 的退出码：25.x 原装的 wget 是指向 `uclient-fetch` 的软链，
  而 uclient-fetch 不支持 `--version`（退出码 1），会被误判成坏掉；
  ② 25.x 仓库没有 blinker 包（但 Flask 3.x 必须它）—— 改为随包携带，不用 pip
  （pip 兜底前有磁盘闸，overlay 装不下就直接报错，不会把根文件系统撑爆）；
  ③ apk 的下载缓存在 overlay 上 —— 统一用 `apk add --no-cache`
- **Linux 部署**：已预留 `deploy_mode=linux_gateway`（只重建自有表，不清空宿主机
  ruleset），但接口名、端口敲门（NAT 源 IP 下失效）、WAN IP 获取等完整适配尚未实现。
  ⚠️ 该模式**声称拥有 `table ip nat` 里的两条小写链**（`prerouting` /
  `postrouting`）—— 应用规则时它们会被整条删除再重建，这是为了清掉用户早已
  删除、却仍留在内核里继续生效的端口转发规则（P0-8）。Docker / iptables-nft 用的是
  **大写**链名（`PREROUTING` / `DOCKER` / `POSTROUTING`），大小写敏感，不会被碰到。
  但 nftables 官方示例里的经典 NAT 用例同样是**小写** `postrouting` —— 如果宿主机
  管理员手写的 ruleset 或其它 nft 原生工具也在 `table ip nat` 里用了小写链名，
  首次应用规则时那些规则会被一起删掉。宿主机上有自定义 nft 规则时请先确认。
  ⚠️ 前导块用的是「先建空链脚手架、再 `delete chain`」两步（`delete` 遇到不存在的
  链会报错，所以必须先 create 出空链）。**不要**图省事改成 `destroy chain` ——
  `destroy` 命令要 **nft ≥ 1.1.x** 才认识（实测 nft 1.0.6 完全不认识，会把
  `destroy` 当成对象名报语法错误；1.1.3 / 1.1.7 才解析通过），改了就把
  linux_gateway 的最低 nft 版本要求整个抬上去。详见
  `报告/nft-destroy命令可行性调研-20261108.md`。
- **单网卡机器不能开 PPPoE**（已做拦截，见 CHANGELOG）。像 Proxmox 虚拟机这种只有
  一张物理网卡的设备，`eth0` 已经是 br-lan 的唯一从属端口，再把 WAN 绑上去会让
  桥塌掉、整机失联。面板会检测不到独立 WAN 网卡并拒绝保存（返回
  `INVALID_NETWORK`），而不是猜一个网卡名写进配置。要用 PPPoE 得先在 OpenWrt
  里划出第二张网卡专供 WAN
- **日志缓冲有上限，写满就覆盖**：`log_size` 默认 128KB，`.224` 实测约 1500 行。
  日志页顶部水位条显示当前占用，缓冲 ≥90% 转红。历史日志要长期留存必须配远程转发
- **保存日志配置会清空本机历史日志**：`log_size` 和转发配置都由 logd 在启动时读取，
  改完必须重启 `/etc/init.d/log`，而重启会清空内存环形缓冲（实测 1580 行 → 1 行）。
  面板现在会先 confirm 再保存，且配置没变时**不重启、不清空**
- **认证事件只转发低频安全事件**：`login_ok` / `login_fail` / `logout` / `lockout`
  会进 syslog 随 logd 转发；`verify_denied` 每个未认证请求都触发，全 WAN 打过来会
  把远程日志刷爆，刻意只留在本机 JSONL
- **真实公网未穿透验证**：公网分支目前靠 `X-Test-IP` 头模拟来源判定，判定逻辑
  已验证正确，但真实运营商网络、封端口、真实公网 IP 下的行为未验
- **nginx 必须 `nginx-full`**：认证网关依赖 `auth_request` 模块，OpenWrt 的
  `nginx-ssl` 不含该模块（装完不报错，一开网关整片 500）。已在
  `192.168.100.224`（OpenWrt 24.10.0）实测：`nginx-full 1.26.3` 具备
  `auth_request` / `realip`，`setup.sh` 装完会当场校验
- **overlay 至少要留 80~90MB**：全新安装实测（`.232`，OpenWrt 25.12.5 x86_64，
  overlay 共 86.4MB）—— 装完依赖 + 项目代码后**已用 56MB**、剩 27MB。
  这是 `apk add --no-cache`（不落包缓存）与「不装 python3-pip」（52MB，
  改用随包 blinker）这两条设计换来的。装的时候别顺手在同一个 overlay 上放别的东西，
  否则会在装到一半时把盘撑满 —— 表现为「apk 装不动、log 写不进去、一堆莫名其妙的失败」。
  想留备份的话，备份目录可以指到 tmpfs（`/tmp` 是 tmpfs，不占 overlay）

### 浏览器实测

面板前端是 Alpine.js SPA，**必须有真实浏览器才能验证它能不能用**——curl 级别
的验收完全查不出 Alpine 启动失败、元素被遮罩挡住、登录流程死循环这类问题。
`tests/run-e2e.sh` 提供三种模式：

```bash
bash tests/run-e2e.sh setup     # 装 playwright-core + Chromium（装仓库外）
bash tests/run-e2e.sh probe     # 14 页逐页枚举，与静态清单对账
bash tests/run-e2e.sh click     # 逐个点击，捕获 JS 异常与 4xx/5xx
bash tests/run-e2e.sh portal    # 认证门户全链路
python3 tests/button_audit.py   # 静态全量抽取所有可交互元素（零依赖）
```

点击权限分三档，**默认只点无副作用的按钮**：`--destructive` 才点删除/清空/应用规则；
`--allow-network` 才点重启网络/切 PPPoE。最后这档会直接把网络搞挂，开之前务必确认
有一条带外恢复通道。
