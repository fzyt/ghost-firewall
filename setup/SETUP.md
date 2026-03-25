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
| python3 | python3 | python3 | 运行环境 |
| python3-light | python3-light | python3-light | 精简版 |
| python3-requests | python3-requests | python3-requests | HTTP 库 |
| python3-flask | python3-flask | python3-flask | Web 框架 |
| nginx-ssl | nginx-ssl | nginx-ssl | 反向代理 + SSL |
| curl | curl | curl | HTTP 工具 |
| openssl-util | openssl-util | openssl-util | SSL 工具 |
| socat | socat | socat | 端口转发 |
| ca-certificates | ca-certificates | ca-certificates | CA 证书 |
| wget-ssl | wget-ssl | wget-ssl | 下载工具 |
| blinker | `pip3 install blinker` | `pip3 install blinker` | Flask 依赖（apk 需额外安装 python3-pip） |

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
| 管理界面 | http://`<路由器IP>`:5000 |
| 配置文件 | `/etc/nftables/nftables-web-config.json` |
| 安装目录 | `/opt/nftables-web-v2/` |
| nftables 配置 | `/etc/nftables.conf` |
| 安装日志 | `/var/log/nftables-web-setup.log` |

---

## 已知问题

| 问题 | 说明 | 解决方案 |
|------|------|----------|
| OpenWrt 25.x 包管理器 | 25.x 使用 apk 替代 opkg | setup.sh 已自动兼容，无需手动处理 |
| ddns-scripts-namecheap | 在 apk 下不可用 | 使用 opkg 的 OpenWrt 23.05，或跳过该 DDNS provider |
| itsdangerous 版本过旧 | Flask 会产生 warning | 不影响运行，可忽略 |
| GitHub 下载失败 | 网络不稳定时可能发生 | setup.sh 内置重试机制，建议在网络较好时安装 |

---

> 如有其他问题，请提交 Issue：https://github.com/你的用户名/nftables-web-v2/issues
