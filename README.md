# Ghost Firewall

> 跑在 OpenWrt 上的 **nftables 防火墙 Web 管理面板**
> 规则管理 · 端口敲门 · 端口转发 · DDNS · **带认证的反向代理网关**

[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](./LICENSE)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-24.10%20%7C%2025.x-00c875.svg)](https://openwrt.org/)
[![Python](https://img.shields.io/badge/python-3.x-3776ab.svg)](https://www.python.org/)
[![Frontend](https://img.shields.io/badge/frontend-Alpine.js%20%2B%20Tailwind-2b8a76.svg)](./nftables-publish-v0.7.9-nospa/frontend/assets/alpine.js)
[![Version](https://img.shields.io/badge/version-v0.8.8-orange.svg)](./nftables-publish-v0.7.9-nospa/VERSION)

Ghost Firewall（原内部代号 **nftables-web-v2**）是部署在 OpenWrt 路由器上的轻量防火墙控制台。
它把 nftables 规则的日常操作搬到一个自签证书的 HTTPS 面板里，同时把「把内网服务暴露到公网」
这件事收敛成一个 **必须先认证的单端口网关**。

**一句话：给家用 / 家庭实验室路由器用的、零构建、默认不裸露公网的防火墙控制面板。**

- **零构建** —— 纯 Python 标准库后端 + 原生前端，`git clone` 下来就能跑，没有 npm / webpack / 依赖树
- **零 CDN** —— Alpine.js 与 Tailwind 全部随包分发，前端不连任何外部域名，因此 CSP 可以开得很死
- **默认不裸奔** —— v0.8.0 起管理面板 **只在局域网可达**，公网入口只有一个需要认证的网关

---

## 三个入口，三种暴露面

| 入口 | 地址 | 暴露面 | 用途 |
|------|------|--------|------|
| **管理面板** | `https://<路由器IP>:5443` | **仅局域网** | nftables 规则、反代配置、DDNS、日志 |
| **认证网关** | `https://<域名或公网IP>:<自定义端口>/` | 可映射公网 | 单端口汇聚所有内网服务，公网访问需认证 |
| **认证服务** | `127.0.0.1:8444` | **本机专属** | 网关的认证后端，公网不可达 |

设计上刻意分成三个进程 / 三个暴露面：面板管规则，网关管对外，认证后端只在环回口上。
公网上能看到的东西只有一个 nginx 入口，它必须先过认证。

---

## 功能一览

| 模块 | 说明 |
|------|------|
| **认证网关** | 单端口汇聚所有服务，按路径前缀区分，公网访问需认证 |
| **端口敲门** | 自定义 4 端口敲门序列，敲对才把来源 IP 加进白名单 |
| **端口转发** | TCP / UDP 转发，IPv4 / IPv6 双栈 |
| **反代管理** | Nginx 反向代理，SSL 证书（手动上传 + ACME 自动申请），多 DNS 服务商 |
| **DDNS** | 通用 DDNS + 阿里云 DDNS，多 DNS 服务商，支持 IPv6 来源地址选择 |
| **访问控制** | LAN 模式 / 信任 IP 模式 |
| **名单管理** | IP 黑白名单 |
| **国外 IP 拦截** | 自动拦截境外 IP |
| **DNS 局域网解析** | 允许 LAN 设备通过路由器查询内网 DNS 服务器 |
| **防火墙状态** | nftables 规则实时查看 |
| **日志管理** | 各类日志开关 + 环形缓冲上限 + 远程日志转发（logd） |
| **系统日志** | 系统日志与认证审计合并为一条时间线，带设备指纹，可按级别 / 来源筛选，导出 CSV / JSON |
| **网络接口** | PPPoE 拨号、路由器网关 IP 管理 |

更细的说明、踩坑记录和真机验证结论见
**[项目本体 README](./nftables-publish-v0.7.9-nospa/README.md)**。

---

## 快速开始

要求 OpenWrt 系统（24.10 的 opkg 或 25.x 的 apk 包管理器），一条命令安装：

```bash
wget -O /tmp/setup.sh \
  https://raw.githubusercontent.com/fzyt/ghost-firewall/main/nftables-publish-v0.7.9-nospa/setup/setup.sh
sh /tmp/setup.sh
```

脚本会自动探测包管理器、装齐依赖（python3 / flask / nftables-json / nginx-full 等）、
生成自签证书、落地配置并注册开机自启。装完访问 `https://<路由器IP>:5443` 即可。

覆盖安装（重跑一遍）加 `--force`：

```bash
sh /tmp/setup.sh --force
```

### 装之前值得知道的三件事

1. **overlay 至少留 80~90MB。** 实测全新安装（OpenWrt 25.12.5 x86_64，overlay 共 86.4MB）
   装完依赖 + 项目代码后已用 56MB、剩 27MB。这条是靠 `apk add --no-cache`（不落包缓存）
   和「不装 python3-pip」（52MB，改为随包携带 blinker）换来的。
2. **nginx 必须是 `nginx-full`。** 认证网关依赖 `auth_request` 模块，
   OpenWrt 的 `nginx-ssl` 不含该模块 —— 装完不报错，一开网关整片 500。
3. **弱网下 apk 的报错会骗人。** 索引文件拉到一半断线时，apk 报的是
   `python3-flask (no such package)` —— 一个纯网络问题被伪装成「仓库里没这个包」。
   `setup.sh` 会自动 `apk update` 刷新索引后重试（最多 3 次）。

---

## 安全设计

这个项目处理的是「谁能进你家路由器」，所以安全相关的取舍写得很死：

- **面板口令**用 PBKDF2-HMAC-SHA256 / 200000 轮哈希（标准库 `hashlib` 实现，不引第三方依赖）
- **认证服务只监听 `127.0.0.1`**，公网侧只有 nginx 一个入口
- **关键文件权限**：配置 `640 root:nftweb`、会话密钥 `600 root:root`，
  且网关进程的 **gid 必须等于配置文件的组 gid** —— 读不到配置时网关会**静默退回默认值而不报错**，
  部署自检会专门验这一条
- **令牌密钥不可变**：部署脚本在替换前后比对 md5，不一致会大声报错 ——
  密钥变了 = 所有设备的网关令牌全部作废 = 用户全部要重新登录
- **只覆盖，不删除**：升级部署不碰配置、口令、密钥、限流表；
  规则集与 nginx 网关配置由面板**运行时**生成，「换代码 ≠ 生效」
- **失败自动回滚**：部署分九个阶段，任一步失败自动回滚，不重启路由器
- **严格 CSP**：前端不连任何外部域名

---

## 仓库结构

> 项目本体放在 `nftables-publish-v0.7.9-nospa/` 子目录里 —— 那是发布打包时用的目录名，
> 历史上为兼容发布流程保留了下来。

```
.
├── README.md                     # 本文件（GitHub 主页展示）
├── LICENSE                       # GPL-3.0
├── nftables-publish-v0.7.9-nospa/ # 项目本体
│   ├── setup/
│   │   ├── setup.sh              # 一键安装脚本（全新设备）
│   │   ├── SETUP.md              # 装机细节与 OpenWrt 25.x 已知问题
│   │   ├── vendor/               # 随包分发的 acme.sh 等第三方组件
│   │   └── knock-*.sh|.py|.ps1   # 端口敲门客户端（LAN / WAN）
│   ├── backend/
│   │   ├── app.py                # 进程 A：管理面板（5443，仅 LAN）
│   │   ├── auth_gateway.py       # 进程 B：认证 API（127.0.0.1）
│   │   ├── template_engine.py    # 规则模板引擎
│   │   └── nftables-web*.init    # 两个服务的 init 脚本
│   ├── frontend/
│   │   ├── index.html            # 面板前端（Alpine.js SPA）
│   │   ├── app.js                # 面板逻辑
│   │   ├── styles.css
│   │   └── assets/               # 本地化的 alpine.js / tailwind.js / 字体
│   ├── tools/
│   │   ├── deploy.sh             # 升级部署脚本（开发机执行，SSH 驱动设备）
│   │   └── verify-fixes.sh       # 真机复验
│   └── tests/                    # 43 个测试文件 + 34 个变异脚本
├── 04-文档/                      # 常见问题解决指南
├── 报告/                         # 安全审查报告、问题清单、真机测试记录
└── *.md                          # 设计文档与历史审查 / 验收报告
```

---

## 文档

| 文档 | 内容 |
|------|------|
| [项目本体 README](./nftables-publish-v0.7.9-nospa/README.md) | 功能详解、装机、升级部署、已知限制、浏览器实测方法 |
| [装机细节 SETUP.md](./nftables-publish-v0.7.9-nospa/setup/SETUP.md) | 安装过程说明与 OpenWrt 25.x 的坑 |
| [常见问题解决指南](./04-文档/常见问题解决指南.md) | FAQ |
| [设计-统一认证门户](./设计-统一认证门户.md) | 认证网关的设计方案 |
| [审查报告](./审查报告-2026-10-01.md) / [审查与修复记录](./审查与修复记录-2026-10-01.md) | 代码审查结论与修复情况 |
| [真机测试报告](./真机测试报告-2026-10-01.md) / [真机验收报告](./真机验收报告-2026-10-06.md) | 真机验证结论 |
| [问题清单](./报告/问题清单-20261029.md) | 全部已知问题与处置状态 |
| [CHANGELOG](./nftables-publish-v0.7.9-nospa/CHANGELOG.md) | 逐版本变更 |

---

## 开发与测试

```bash
cd nftables-publish-v0.7.9-nospa

# 全量回归（行为级测试 + 34 个变异脚本，零外部依赖）
bash tests/run_all.sh

# 真浏览器 e2e（playwright-core + Chromium，装在仓库外）
bash tests/run_e2e.sh setup     # 装浏览器
bash tests/run_e2e.sh probe     # 14 页逐页枚举
bash tests/run_e2e.sh click     # 逐个点击，捕获 JS 异常与 4xx/5xx
bash tests/run_e2e.sh portal    # 认证门户全链路
```

点击权限分三档，**默认只点无副作用的按钮**：`--destructive` 才点删除 / 清空 / 应用规则；
`--allow-network` 才点重启网络 / 切 PPPoE。最后这档会直接把网络搞挂，
开之前务必确认有一条带外恢复通道。

---

## License

[GPL-3.0-or-later](./LICENSE)。源码中的 SPDX 标识为 `GPL-3.0-or-later`；
随包分发的第三方组件（acme.sh 等）各自遵循其原许可，详见
[`setup/vendor/README.md`](./nftables-publish-v0.7.9-nospa/setup/vendor/README.md)。

---

## English

**Ghost Firewall** is a lightweight web control panel for nftables that runs on OpenWrt routers.

- **Zero build step** — Python standard library backend + native frontend. No npm, no bundler, no dependency tree.
- **Zero CDN** — Alpine.js and Tailwind are vendored locally, so the Content-Security-Policy can be strict.
- **Not exposed by default** — since v0.8.0 the admin panel is LAN-only; the single public entry point is an
  authenticated reverse-proxy gateway.
- **Features** — firewall rules, port knocking, port forwarding, DDNS, Nginx reverse proxy with
  ACME-managed certificates, IP allow/deny lists, geo-blocking, log management and export.
- **Install** — one command on OpenWrt (24.10 / opkg or 25.x / apk):

```bash
wget -O /tmp/setup.sh \
  https://raw.githubusercontent.com/fzyt/ghost-firewall/main/nftables-publish-v0.7.9-nospa/setup/setup.sh
sh /tmp/setup.sh
```

License: GPL-3.0-or-later.
