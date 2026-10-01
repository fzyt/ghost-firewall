# knock-wan-termux — Termux / Android 公网端口敲门客户端

> 适用于 [nftables-web-v2](../README.md) 的 **WAN** 端口敲门场景。
> 在 Android Termux 终端里，从公网（4G/5G/酒店 WiFi 等）敲门家里的路由器。

---

## ⚠️ WAN 链必读

`chain knock_wan_v4` 比 LAN 严格得多：

| 规则 | 含义 | 对客户端的影响 |
|------|------|---------------|
| `limit rate 1/minute burst 1 packets` | 同 IP 同端口两次放行必须间隔 60s | 4 步敲门默认 **100% 失败**（4 包在 4 秒内全被 burst 拒绝） |
| `add @error_ips4 timeout 30s` | 失败/重复会进 30s 惩罚窗口 | 这 30 秒内本机任何敲门包都被丢弃 |
| `jump add_to_blacklist4` | 错误累计 → 永久封禁 | 本机公网 IP 进 blacklist，**之后所有敲门都失败** |

所以脚本**默认走 fast 模式（1s/步）**，但**前提是你必须先在路由器放宽限速**：

```nftables
# 把 knock_wan_v4 链里的
limit rate 1/minute burst 1 packets
# 改成
limit rate 4/minute burst 4 packets
# 或者直接删掉 limit（最宽松）
```

否则脚本只在命令行提示「100% 失败」但仍会发出 4 个包，等于浪费 4 次公网包 + 计入 4 次 error。

> **结论**：先改路由器限速，再敲。

---

## 它是什么

`knock-wan-termux.sh` 是给 Android Termux 用的 WAN 敲门客户端。**它做两件事**：
1. 顺序向 4 个 UDP 端口各发 1 包，间隔 ~1s（不超 8s set timeout）。
2. 让这 4 个 UDP 包的 payload 看起来像正常互联网流量（"数据伪装"）。

> UDP 是无连接协议，路由器 nftables `chain knock_wan_v4` 只看 `udp dport`，不查 payload。
> 所以 payload 改不改都能敲门；伪装的目的只是**让抓包/审计更难一眼看出"敲门"**。

---

## 安装

```bash
# Termux 里
pkg update && pkg install python curl

# 把脚本推到手机（任选一种）
# 方式 A：scp
scp setup/knock-wan-termux.sh setup/knock-wan-termux.py \
    kirito@<termux-ip>:~/bin/
ssh kirito@<termux-ip> 'chmod +x ~/bin/knock-wan-termux.sh ~/bin/knock-wan-termux.py'

# 方式 B：termux 上直接 vim 写
# 方式 C：通过 Syncthing / KDE Connect 等同步工具
```

Termux 不需要 root —— 客户端 UDP `sendto` 不需要特权。

---

## 用法

### 方式 A：编辑顶部「🔧 快速配置区」（推荐）

打开 `knock-wan-termux.sh`，改这几行：

```bash
KNOCK_MODE="wan"                          # lan | wan（默认 wan）
KNOCK_HOST=""                             # 例: "1.2.3.4"（路由器 WAN IP 或 DDNS A 记录）
KNOCK_DOMAIN=""                           # 或填域名，例: "router.example.com"
KNOCK_API=""                              # 或从后端拉，例: "http://router.example.com:5000/api/config"
KNOCK_PORTS="1234,5678,9012,3456"         # 4 个端口，逗号分隔
KNOCK_MIMIC="tls"                         # WAN 推荐 tls|stun|ntp
KNOCK_NOISE=2                             # 每步之间几个噪音包
KNOCK_INTERVAL=1.0                        # 步间基准（秒）
KNOCK_JITTER=0.3                          # 步间随机抖动（秒）
KNOCK_NOISE_PORTS="53,123,443,3478,51820" # 噪音目标端口（WAN 会自动剔除重叠的敲门端口）
KNOCK_PRINT_PUBLIC_IP=1                   # 启动时打印本机公网 IP 1=是 0=否
```

保存后直接执行：

```bash
./knock-wan-termux.sh
```

### 方式 B：命令行参数覆盖（不改脚本）

```bash
# 公网域名（DDNS 友好）
knock-wan-termux.sh -h router.example.com

# 显式 4 端口
knock-wan-termux.sh -h 1.2.3.4 -p 1234,5678,9012,3456

# 从 nftables-web 后端自动拉配置（需要 Web 可达，且后端有 GET /api/config）
knock-wan-termux.sh --api http://router.example.com:5000/api/config

# 用 NTP 风格 payload（payload 看起来像 NTP 客户端探活）
knock-wan-termux.sh -h 1.2.3.4 --mimic ntp

# TLS ClientHello + 噪音包（在敲门间隙额外往 53/123/443/3478/51820 撒包）
knock-wan-termux.sh -h 1.2.3.4 --mimic tls --noise 2

# 步间抖动 0.5s ± 0.4s，避免每次敲门时间戳完全相同
knock-wan-termux.sh -h 1.2.3.4 --mimic stun -i 0.5 -j 0.4

# 切到 LAN 模式（同一脚本也能用，无 rate limit）
knock-wan-termux.sh --mode lan -h 192.168.4.1

# 启动时不打印本机公网 IP（节省一次外网请求）
knock-wan-termux.sh -h 1.2.3.4 --no-publicip

# 仅试运行（不真发包，只看会发什么）
knock-wan-termux.sh -h 1.2.3.4 --mimic dns --dry-run
```

命令行参数优先级高于顶部配置。

---

## 数据伪装模式（`--mimic`）

| 模式 | payload | 长度 | 看起来像 |
|------|---------|------|----------|
| `none` | `b"k"` | 1B | 原版固定 marker（最小） |
| `random` | 随机字节 | 8~32B | 普通 UDP 探活 |
| `ntp` | NTPv4 client request | 48B | NTP 时间同步请求（0x23 = client mode） |
| `dns` | 最小 DNS 查询 | 32B | `ping.home.arpa. IN AAAA` |
| `tls` | TLS 1.2 ClientHello | ~95B | HTTPS 握手开始（SNI: www.microsoft.com） |
| `stun` | STUN Binding Request | 20B | WebRTC/VoIP NAT 穿透探测 |
| `wireguard` | WG handshake init 第 1 字节 | 38B | WireGuard VPN 握手 |
| `noise` | 同 random | 8~32B | 同 random（语义别名） |

> WAN 场景推荐 `tls` / `stun` / `ntp`：长度固定、特征明显但常见，最像"普通互联网行为"。

---

## 噪音包（`--noise N`）

在 **每步真实敲门包之间**额外发 `N` 个 UDP 包到非敲门端口（默认轮询 `53,123,443,3478,51820`，即 DNS/NTP/HTTPS/STUN/WireGuard 公共端口）。

**WAN 自动剔除**：如果你的 `KNOCK_PORTS` 里包含了噪音目标端口（比如把敲门端口设成 123），脚本会自动剔除重叠项，不会让噪音包误触发 `add @error_ips4`。如果全部重叠，噪音自动禁用并打 WARN。

噪音 payload 与 `--mimic` 模式一致（除 `wireguard` 用 `random` 避免看起来有 5 个并发的 WG init）。

噪音只发到**非敲门端口**，不会触发路由器 `chain knock_wan_v4` 的状态机，**也不会被 limit rate 1/minute 影响**。

`--noise 0`（默认）= 不发噪音，最干净的"4 步静默敲门"。
`--noise 2` ~ `--noise 5` 适合对付"4 个独立 UDP 包 + 完全无其他活动 = 明显扫描"这种粗粒度检测。

---

## 步间 jitter（`-j/--jitter`）

默认 1s 间隔、jitter 0.3s（即每步间隔 0.7~1.3s 随机）。
理论上只要 `interval ± jitter < 8s` 就能进门（因为 `set knock1_done4 { timeout 8s }`）。

但因为路由器 `limit rate 1/minute burst 1` 的存在，**4 步间隔必须 ≥60s 才能正常进门**（fast 模式必然失败，需要你先改路由器限速）。

---

## 公网 IP 自检（`--publicip` / `--no-publicip`）

WAN 模式默认开启，启动时会通过 `curl https://ifconfig.co` 查本机公网出口 IP（失败 fallback `api.ipify.org`），打印给你看，方便你在路由器上检查：

```bash
# 路由器 SSH：
nft list set inet fw4 error_ips4     # 30s 惩罚窗口
nft list set inet fw4 blacklist4     # 永久封禁

# 解封本机公网 IP X.X.X.X：
nft delete element inet fw4 blacklist4 { X.X.X.X }
nft flush set inet fw4 error_ips4    # 清空整个 30s 窗口（慎用）
```

脚本不做 TCP verify（不做敲门后回连测试），只查 IP 给你做决策。

---

## 验证（路由器 SSH）

敲门后到路由器上跑：
```bash
nft list set inet fw4 allowed4
```
应该看到你的客户端**公网** IP（带 `expires` 过期时间，~5h）。

如果看不到：
- 先看路由器日志：`logread | grep -E 'KNOCK4-OK-S|WAN-KNOCK4|KNOCK-ERR'`
- 最常见原因：
  1. **路由器限速没放宽**（4 步被 burst 拒绝）
  2. **本机公网 IP 在 error_ips4 / blacklist4**（自检后看到 IP，去路由器上对照）
  3. **步间超过 8s**（脚本默认 1s，正常不会）
  4. **DDNS 域名解析到旧 IP**（用 `--api` 拉最新，或手动指定 IP）

---

## 退出码

| code | 含义 |
|------|------|
| 0 | 4 步全部发出（UDP 无连接，发送成功即认为完成） |
| 1 | 参数错误 / 找不到 python / API 拉取失败 |
| 2 | 部分 UDP 包 sendto 失败（一般是 ICMP 阻断，不影响主体） |

---

## 已知限制 / 设计取舍

1. **fast 模式依赖路由器放宽限速**。这是项目模板 `chain knock_wan_v4` 的固有约束，不是 bug。如果不放手速，4 步敲门 100% 失败。
2. **payload 伪装 ≠ 流量伪装**。审计/抓包者仍能基于"包大小 + 时间间隔 + 目标端口 + 总包数"识别敲门模式。本工具只把最浅的一层（payload 字符串）伪装掉；深度伪装需要发到不同的 target / 走代理 / 与真实流量并发。
3. **噪音包可能违反网络礼仪**。往路由器公网 IP 的 53/443/123 撒包，如果路由器开了 fail2ban / port-scan 检测器，可能反向触发封锁。**噪音已经自动剔除重叠的敲门端口**，但其他端口仍可能被反扫。
4. **DNS / NTP / STUN payload 是骨架级**，不含完整协议状态机。够骗 tcpdump grep，不够骗完整协议解析器。
5. **公网 IP 自检依赖外网**。如果手机没数据/WiFi，脚本会打印"无法获取，请检查网络"，但不影响后续敲门发送。
6. **不做敲门后 verify**（按用户要求）。敲门后想知道是否成功，到路由器 SSH 看 `allowed4`。
