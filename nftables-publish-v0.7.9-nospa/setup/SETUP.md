# nftables-web-v2 安装指南

> 本文档是 nftables-web-v2 在 OpenWrt 上的唯一权威安装参考。

---

## 目录

- [系统要求](#系统要求)
- [依赖说明](#依赖说明)
- [安装方式](#安装方式)
- [安装流程](#安装流程)
- [服务管理](#服务管理)
- [文件结构](#文件结构)
- [已知问题](#已知问题)

---

## 系统要求

| 项目 | 要求 |
|------|------|
| OpenWrt 版本 | 23.05+（opkg）或 25.x（apk） |
| CPU 架构 | x86_64、aarch64、arm* |
| 磁盘空间 | ≥ 50MB |
| 运行环境 | root 权限 |

---

## 依赖说明

### 必要依赖

| 包名 | opkg | apk | 说明 |
|------|------|-----|------|
| nftables | nftables | nftables-json | 防火墙核心 |
| **libopenssl3** | libssl libcrypto | **libopenssl3** | **OpenSSL 共享库**。apk 上必须**先于** `wget-ssl` 安装 —— 它提供 `libssl.so.3`，而 `wget-ssl` 依赖它、`wget-ssl` 又要靠 wget 下载自己的依赖（鸡生蛋） |
| python3 | python3 | python3 | 运行环境 |
| python3-light | python3-light | python3-light | 精简版 |
| python3-requests | python3-requests | python3-requests | HTTP 库 |
| python3-flask | python3-flask | python3-flask | Web 框架 |
| nginx-full | nginx-full | nginx-full | 反向代理 + SSL + `auth_request`（**认证网关硬依赖**） |
| curl | curl | curl | HTTP 工具。**apk 上它链的是 mbedTLS 而不是 OpenSSL**，所以在 libssl.so.3 缺失时它照样能下 https —— 安装期的 wget 顶替就靠它 |
| openssl-util | openssl-util | openssl-util | SSL 工具 |
| socat | socat | socat | 端口转发 |
| ca-certificates | ca-certificates | ca-certificates | CA 证书 |
| wget-ssl | wget-ssl | wget-ssl | 下载工具。**apk 上必须最后装**（它的 postinst 会替换 /usr/bin/wget） |
| blinker | `pip3 install blinker` | `pip3 install blinker` | Flask 依赖。**25.x 仓库里没有这个包**，本项目改为**随包携带**（`setup/vendor/blinker/`），不需要 pip |

> ⚠️ **必须用 `nginx-full`，不能用 `nginx-ssl`。** v0.8.0 的单端口认证网关
> 每个公网请求都要经 `auth_request` 子请求向认证服务核对 token，而 OpenWrt 的
> `nginx-ssl` **不含**该模块 —— 装它不会报错，但一开网关就整片 500。
> `setup.sh` 装完会当场校验 `nginx -V` 是否带 `http_auth_request_module`，
> 缺了直接中止安装并提示重装，不会 warn+skip 放过去。

### 可选依赖

> 以下为 DDNS 功能相关依赖，按需安装。

| 包名 | opkg | apk | 说明 |
|------|------|-----|------|
| acme-acmesh | acme-acmesh | acme-acmesh | Let's Encrypt 证书 |
| ddns-scripts | ddns-scripts | ddns-scripts | DDNS 框架 |
| ddns-scripts-cloudflare | ddns-scripts-cloudflare | ddns-scripts-cloudflare | Cloudflare DDNS |
| ddns-scripts-dnspod | ddns-scripts-dnspod | ddns-scripts-dnspod | DNSPod DDNS |
| ddns-scripts-noip | ddns-scripts-noip | ddns-scripts-noip | No-IP DDNS |
| ddns-scripts-nsupdate | ddns-scripts-nsupdate | ddns-scripts-nsupdate | NSUpdate DDNS |
| ddns-scripts-godaddy | ddns-scripts-godaddy | ddns-scripts-godaddy | GoDaddy DDNS |
| ddns-scripts-namecheap | ddns-scripts-namecheap | ❌ 不可用 | Namecheap DDNS |

---

## 安装方式

### 方式一：一键安装（从 GitHub 下载）

```bash
# 默认安装最新版本
sh setup/setup.sh

# 指定版本
sh setup/setup.sh --version v0.7.7

# 强制覆盖已安装版本
sh setup/setup.sh --force

# 跳过 nginx 配置
sh setup/setup.sh --skip-nginx
```

### 方式二：本地安装

```bash
# 从本地目录安装（如当前目录）
sh setup/setup.sh --local ./
```

---

## 安装流程

setup.sh 自动完成以下步骤：

1. **环境检查**
   - 检查 root 权限
   - 检查 OpenWrt 系统版本
   - 检查磁盘空间（≥50MB）

2. **安装必要依赖**
   - 根据系统类型（opkg / apk）安装对应包
   - blinker 通过 pip3 安装（apk 需先安装 python3-pip）

3. **下载项目代码**
   - 从 GitHub archive 下载指定版本
   - 部署到 `/opt/nftables-web-v2/`
   - 网络不稳定时有自动重试机制

4. **配置 nginx 反向代理**
   - 生成 nginx 配置文件
   - 启用 SSL 支持
   - 如需跳过，使用 `--skip-nginx` 参数

5. **初始化配置文件**
   - 创建 `/etc/nftables/nftables-web-config.json`
   - 写入默认配置项

6. **注册并启动服务**
   - 安装 OpenWrt init 脚本 `/etc/init.d/nftables-web`
   - 启用开机自启
   - 启动服务

7. **配置 nftables 基础规则**
   - 写入 `/etc/nftables.conf`
   - 应用 nftables 规则

---

## 服务管理

```bash
# 启动服务
/etc/init.d/nftables-web start

# 停止服务
/etc/init.d/nftables-web stop

# 重启服务
/etc/init.d/nftables-web restart

# 查看服务状态
/etc/init.d/nftables-web status

# 开机自启（已默认启用）
/etc/init.d/nftables-web enable
```

---

## 文件结构

```
/opt/nftables-web-v2/          # 项目安装目录
├── app/                       # 应用代码
├── static/                    # 静态文件
├── templates/                 # 模板文件
├── requirements.txt           # Python 依赖
└── ...

/etc/nftables/
└── nftables-web-config.json   # 配置文件

/etc/nftables.conf             # nftables 主配置
/etc/init.d/nftables-web       # OpenWrt init 脚本

/var/log/nftables-web-setup.log  # 安装日志
```

---

## 端口和路径

| 用途 | 地址/路径 |
|------|----------|
| 管理界面 | https://`<路由器IP>`:5443 （仅局域网可达） |
| 配置文件 | `/etc/nftables/nftables-web-config.json` |
| 安装目录 | `/opt/nftables-web-v2/` |
| nftables 配置 | `/etc/nftables.conf` |
| 安装日志 | `/var/log/nftables-web-setup.log` |

---

## 已知问题

| 问题 | 说明 | 解决方案 |
|------|------|----------|
| OpenWrt 25.x 包管理器 | 25.x 使用 apk 替代 opkg | setup.sh 已自动兼容，无需手动处理 |
| **25.x 的 `wget-ssl` 鸡生蛋** | `wget-ssl` 依赖 `libssl.so.3`（`libopenssl3`），而 `libopenssl3` 要靠 wget 下载。apk 在同一事务里把 wget 换成坏的那个后，就再也下不来任何包 | setup.sh 会**自愈**：检测到 wget 不可用就用 curl 顶替（curl 链 mbedTLS，不依赖 libssl.so.3），装完再把 wget 换回原版 |
| **⚠️ 别拿 `wget --version` 的退出码判 wget 好坏** | 25.x 原装的 `/usr/bin/wget` 是指向 `/bin/uclient-fetch` 的软链，而 **uclient-fetch 不支持 `--version`**（输出 `wget: unrecognized option: version`，退出码 1）。拿退出码当判据会把**好用的**下载器误判成坏掉 | setup.sh 改成按**输出特征**判坏：真坏掉（wget-ssl 缺 `libssl.so.3`）的输出含 `Error relocating` / `symbol not found`；`unrecognized option` 不算坏 |
| **顶替 wget 的 shim 不能只认 curl** | 全新机上 curl 还没装，shim 只认 curl 就必然 `exit 127` | setup.sh 的 shim **运行时**选后端：优先 `/usr/bin/curl`，退回 `/bin/uclient-fetch`（后者不支持 `-O -`，走 stdout 时不传 `-O`；也没有 `--fail`/`--retry`，但 HTTP 错误码自身返回非 0） |
| **25.x 仓库没有 blinker** | `python3-flask` 的依赖里也没有它，但 Flask 3.x 的代码会 `import blinker` | blinker **随包携带**（`setup/vendor/blinker/`，32KB 纯 Python），不需要 `python3-pip`（那要 52MB）。装不上时 pip 兜底前有**磁盘闸**：剩 <80MB 直接报错，不会把根文件系统撑爆 |
| **apk 缓存写在 overlay 上** | `/var/cache/apk` 不是 tmpfs，下载的包会**再存一份** | setup.sh 用 `apk add --no-cache` |
| **25.x busybox 没有 wget applet** | OpenWrt 用 `uclient-fetch` 替代，所以「换回 busybox wget」这条路走不通 | 只能用 curl（链 mbedTLS）或 `uclient-fetch` |
| **dropbear 没有 sftp-server** | `scp` 默认走 SFTP ⇒ `ash: /usr/libexec/sftp-server: not found` | 用 `tar czf - ... \| ssh host 'tar xzf -'` 传文件 |
| 磁盘空间偏紧 | OpenWrt 常见 overlay 只有 80~90MB；python3 + nginx-full 就占 ~55MB | 装完通常剩 ~28MB；**不要**再装 python3-pip 之类的大包 |
| ddns-scripts-namecheap | 在 apk 下不可用 | 使用 opkg 的 OpenWrt 23.05，或跳过该 DDNS provider |
| itsdangerous 版本过旧 | Flask 会产生 warning | 不影响运行，可忽略 |
| GitHub 下载失败 | 网络不稳定时可能发生 | setup.sh 内置重试机制，建议在网络较好时安装 |

> **25.x 排障提示**：如果安装卡在「安装依赖」并且日志里出现
> ```
> ERROR: wget: exited with error 127
> ERROR: unable to select packages: XXX (no such package)
> ```
> 那**不是**「仓库里没有这个包」，而是**apk 的下载器自己坏了**
> （wget-ssl 把 wget 换成了缺 libssl.so.3 的版本）。
> 照 `repair_downloader()` 的注释手工做一次即可。

---

> 如有其他问题，请提交 Issue：https://github.com/你的用户名/nftables-web-v2/issues
