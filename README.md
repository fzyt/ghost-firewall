# Ghost Firewall (nftables-web-v2)

> 基于 OpenWrt 的防火墙 Web 管理面板

**版本：** v0.7.7

Ghost Firewall 是一个运行在 OpenWrt 上的轻量防火墙管理工具，通过 Web 界面管理 nftables 规则，提供端口敲门、端口转发、DDNS、反向代理等功能。

## 功能一览

| 模块 | 说明 |
|------|------|
| **网络接口** | PPPoE 拨号、路由器网关 IP 管理 |
| **端口敲门** | 自定义 4 端口敲门序列，白名单 IP，超时设置 |
| **端口转发** | TCP/UDP 转发，IPv4/IPv6 双栈支持 |
| **反代管理** | Nginx 反向代理，SSL 证书（手动上传 + ACME 自动申请），多 DNS 服务商（v0.7.0+） |
| **访问控制** | LAN 模式 / 信任 IP 模式 |
| **日志管理** | 各类日志开关 + 远程日志转发（logd） |
| **系统日志** | 实时查看 nftables 日志 |
| **国外 IP 拦截** | 自动拦截境外 IP |
| **DDNS** | 通用 DDNS + 阿里云 DDNS，多 DNS 服务商，IPv6 来源选择 |
| **防火墙状态** | nftables 规则实时查看 |
| **名单管理** | IP 黑白名单 |

## 安装

要求 OpenWrt 系统，通过一键脚本安装：

```bash
chmod +x setup.sh
./setup.sh
```

安装完成后通过浏览器访问管理面板即可使用，各功能页面内有详细说明。

## 项目结构

```
nftables-web-v2/
├── setup.sh                # 一键安装脚本
├── backend/
│   ├── app.py              # 后端主程序
│   ├── template_engine.py  # 模板引擎
│   ├── nftables-web.init   # OpenWrt init 服务脚本
│   └── templates/
│       └── nftables.conf   # nftables 规则模板
└── frontend/
    ├── index.html          # 前端入口
    ├── app.js              # 前端逻辑
    ├── styles.css          # 样式
    └── assets/             # 静态资源（JS 库、截图等）
```
