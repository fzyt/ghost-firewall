#!/bin/bash
# knock-wan-termux.sh — nftables-web-v2 WAN 端口敲门客户端（Termux / Android 适配版）
#
# nftables 模板里 chain knock_wan_v4 已实现 WAN 端 4 步敲门流程：
#   knock1 (8s 内) -> knock2 (8s 内) -> knock3 (8s 内) -> knock4 -> 加入 @allowed4
# 白名单默认持续 5 小时（whitelist_timeout 配置）。
#
# 场景：
#   你从公网（4G/5G/酒店/咖啡厅 WiFi 等）敲门家里的路由器。
#   路由器 WAN 链 knock_wan_v4 有严格的状态机：
#     - limit rate 1/minute burst 1 packets：同 IP 同端口两次放行必须间隔 60s
#     - 失败/重发会进入 @error_ips4（30s 惩罚窗口，期间敲门直接进黑名单）
#     - 多次失败 → add_to_blacklist4 永久封禁
#   因此本脚本默认走 "fast 模式"（1s/步）：**你需要先把路由器 WAN 链的
#   limit rate 1/minute 改成 limit rate 4/minute burst 4（或干脆去掉 limit），
#   否则 4 步敲门 100% 失败**。
#
# 与 setup/knock-lan.sh 的区别：
#   1. 内核用 Python socket（termux 默认就有 python3，比 /dev/udp 更稳）
#   2. 支持多种"数据伪装"模式（payload / mimic 协议 / 噪音包）
#   3. 步间 jitter（1s ± 0~0.3s），让连续敲门不那么机械化
#   4. 可以从路由器 web 后端自动拉配置（无需事先拷贝 JSON 到手机）
#   5. --mode lan|wan 切换（默认 wan）。lan 走原项目 8s 规则，wan 走 fast 1s
#   6. WAN 模式自动剔除「噪音目标端口 == 敲门端口」的情况，避免触发 error_ips
#   7. 启动时打印本机公网出口 IP（可选），提醒「如果已进黑名单先在路由器解封」
#
# 用法：
#   ① 直接执行（用脚本顶部「快速配置区」的默认配置）
#       knock-wan-termux.sh
#
#   ② 命令行参数覆盖（不改脚本也能用）
#       knock-wan-termux.sh -h router.example.com                     # 公网域名（DDNS）
#       knock-wan-termux.sh -h 1.2.3.4 -p 1234,5678,9012,3456         # 显式 4 个端口
#       knock-wan-termux.sh --api http://router.example.com:5000/api/config  # 从后端拉
#       knock-wan-termux.sh --mimic ntp -i 0.5                         # 用 NTP 风格 payload，0.5s 步间
#       knock-wan-termux.sh --mimic tls --noise 2                      # TLS ClientHello + 2 个噪音包
#       knock-wan-termux.sh --mode lan                                 # 切到 LAN 模式（无 rate limit）
#       knock-wan-termux.sh --mode wan --publicip                      # WAN + 启动时打印公网 IP
#
#   ③ 编辑脚本头部「🔧 快速配置区」，改完保存直接执行
#       KNOCK_HOST=""             # 例: "1.2.3.4"（路由器 WAN IP / DDNS）
#       KNOCK_DOMAIN=""           # 例: "router.example.com"
#       KNOCK_API=""              # 例: "http://router.example.com:5000/api/config"
#       KNOCK_PORTS="1234,5678,9012,3456"
#       KNOCK_MIMIC="ntp"         # none|random|ntp|dns|tls|stun|wireguard
#       KNOCK_NOISE=2
#       KNOCK_INTERVAL=1.0
#       KNOCK_JITTER=0.3
#
# 数据伪装模式（--mimic）：
#   none       默认，沿用原版 payload（一个字节 'k'）
#   random     8~32 字节随机 payload（伪装成普通 UDP 探活）
#   noise      纯随机，不冒充任何协议（实际等价 random，但语义不同）
#   ntp        构造一个 48 字节的 NTP client request（LI=0,VN=4,Mode=3）
#   dns        构造一个最小 DNS 查询（ping.home.arpa. IN AAAA）
#   tls        构造一个最小 TLS 1.2 ClientHello（握手开始）
#   stun       构造一个 STUN Binding Request（带 magic cookie）
#   wireguard  构造一个 WireGuard handshake initiation 第 1 个字节（type=1）
#
# 噪音包（--noise N）：在 4 步敲门之间额外向 **其他端口** 发 N 个 UDP 包。
# 噪音端口轮询 53/123/443/3478/51820（真实公共 UDP 服务端口），payload 与主模式匹配。
# WAN 模式下脚本自动剔除"噪音端口 == 敲门端口"的情况，避免被路由器计入 @error_ips。
# 这样总流量看起来像普通 NAT 探测，而不是孤立 4 包敲击。
#
# 验证方法（路由器 SSH）：
#   nft list set inet fw4 allowed4
# 应能看到你的客户端公网 IP（带 expires 过期时间）
# 如果看不到，检查：
#   1. 路由器 knock_wan_v4 是否放行了限速（必须改 limit）
#   2. 本机公网 IP 是否在 @error_ips4（30s 观察期）或 blacklist（永久封禁）
#      nft list set inet fw4 error_ips4
#      nft list set inet fw4 blacklist4
#
# 退出码：
#   0  - 4 步全部发出（UDP 无连接）
#   1  - 参数错误 / 配置拉取失败 / Python 不存在
#   2  - 部分 UDP 包发送失败（不影响敲门主体）

set -e

# ===========================================================================
# 🔧 快速配置区 — 直接修改下面的变量即可，改完保存后执行脚本立即生效
# ===========================================================================
# 命令行参数（如 -h / -p / --mimic）依然有效，会覆盖这里的默认值。
# 不确定该填什么？看 README「KNOCK-WAN-TERMUX.md」的「快速开始」章节。

# --- 模式（lan / wan）---
#   lan:  走原项目 chain knock_lan，无 rate limit，1s 步间直接成功
#   wan:  走 chain knock_wan_v4，必须先在路由器放宽 limit rate 1/minute
KNOCK_MODE="wan"

# --- 路由器/目标主机 ---
# 三选一（按优先级从高到低）：
#   1. KNOCK_HOST  : 直连 IP（最稳，不依赖 DNS；WAN 时填路由器公网 IP/DDNS）
#   2. KNOCK_DOMAIN: 域名（DDNS 友好，自动解析 A 记录）
#   3. KNOCK_API   : 从 nftables-web 后端自动拉（最省心，但需后端支持 GET /api/config）
# 留空表示「禁用此项」，从其余来源 / 命令行参数取值。
KNOCK_HOST=""                                          # WAN 例: "1.2.3.4"；LAN 例: "192.168.4.1"
KNOCK_DOMAIN=""                                        # 例: "router.example.com" / "home.duckdns.org"
KNOCK_API=""                                           # 例: "http://router.example.com:5000/api/config"

# --- 4 个敲门端口（必须与路由器 nftables-web 后端配置完全一致）---
KNOCK_PORTS="1234,5678,9012,3456"                      # 逗号分隔，正好 4 个

# --- 伪装模式 / 噪音包 ---
#  WAN 场景推荐 tls/stun/ntp（payload 看起来像 HTTPS/STUN/NTP）
KNOCK_MIMIC="tls"       # none | random | ntp | dns | tls | stun | wireguard
KNOCK_NOISE=2           # 每步之间插入几个噪音包到 53/123/443/3478/51820

# --- 步间节奏 ---
#  WAN 模式推荐 1s ± 0.3s（路由器 set timeout 8s 留足余量）
#  ⚠️ 路由器 WAN 链默认 limit rate 1/minute burst 1，必须放宽到 4/minute burst 4
#  LAN 模式推荐保持 1s ± 0.3s（无 rate limit）
KNOCK_INTERVAL=1.0
KNOCK_JITTER=0.3

# --- 噪音包目标端口（按需修改，例如改成你自己的内网服务端口）---
#  WAN 模式下脚本会自动剔除"噪音端口 == 敲门端口"，避免触发 @error_ips
KNOCK_NOISE_PORTS="53,123,443,3478,51820"

# --- WAN 启动自检：打印本机公网出口 IP（提醒检查黑名单）---
KNOCK_PRINT_PUBLIC_IP=1    # 1=打印，0=不打印

# ===========================================================================
# ⬇ 以下是实现细节，正常情况不需要改
# ===========================================================================

# ============ 脚本所在目录（用于找 .py 内核）============
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_KERNEL="${SCRIPT_DIR}/knock-wan-termux.py"

# ============ 缺省值（命令行参数会覆盖）============
MODE="$KNOCK_MODE"
HOST=""
PORTS="$KNOCK_PORTS"
API_URL="$KNOCK_API"
INTERVAL="$KNOCK_INTERVAL"
JITTER="$KNOCK_JITTER"
MIMIC="$KNOCK_MIMIC"
NOISE="$KNOCK_NOISE"
NOISE_PORTS_CFG="$KNOCK_NOISE_PORTS"
PRINT_PUBLIC_IP="$KNOCK_PRINT_PUBLIC_IP"
PROXY=""        # 暂未启用，留接口
DRY_RUN=0
QUIET=0

# ============ 工具函数 ============
err()  { printf '\033[31mERROR\033[0m: %s\n' "$*" >&2; }
info() { [ "$QUIET" -eq 1 ] && return 0; printf '\033[36m[Knock]\033[0m %s\n' "$*"; }
warn() { [ "$QUIET" -eq 1 ] && return 0; printf '\033[33m[WARN]\033[0m %s\n' "$*" >&2; }

usage() {
    sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ============ 参数解析 ============
while [ $# -gt 0 ]; do
    case "$1" in
        --mode)           [ -z "${2:-}" ] && { err "--mode 需要参数"; exit 1; }; MODE="$2"; shift 2 ;;
        -h|--host)        [ -z "${2:-}" ] && { err "-h 需要参数"; exit 1; }; HOST="$2"; shift 2 ;;
        -p|--ports)       [ -z "${2:-}" ] && { err "-p 需要参数"; exit 1; }; PORTS="$2"; shift 2 ;;
        --api)            [ -z "${2:-}" ] && { err "--api 需要参数"; exit 1; }; API_URL="$2"; shift 2 ;;
        -i|--interval)    [ -z "${2:-}" ] && { err "-i 需要参数"; exit 1; }; INTERVAL="$2"; shift 2 ;;
        -j|--jitter)      [ -z "${2:-}" ] && { err "-j 需要参数"; exit 1; }; JITTER="$2"; shift 2 ;;
        -m|--mimic)       [ -z "${2:-}" ] && { err "--mimic 需要参数"; exit 1; }; MIMIC="$2"; shift 2 ;;
        --noise)          [ -z "${2:-}" ] && { err "--noise 需要参数"; exit 1; }; NOISE="$2"; shift 2 ;;
        --noise-ports)    [ -z "${2:-}" ] && { err "--noise-ports 需要参数"; exit 1; }; NOISE_PORTS_CFG="$2"; shift 2 ;;
        --publicip)       PRINT_PUBLIC_IP=1; shift ;;
        --no-publicip)    PRINT_PUBLIC_IP=0; shift ;;
        --dry-run)        DRY_RUN=1; shift ;;
        -q|--quiet)       QUIET=1; shift ;;
        --help|-?)        usage 0 ;;
        *)                err "未知参数: $1"; usage 1 ;;
    esac
done

# ============ Python 检查 ============
if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    err "找不到 python3 / python"
    echo "  Termux 安装：pkg install python" >&2
    exit 1
fi
PY_BIN="$(command -v python3 || command -v python)"

if [ ! -f "$PY_KERNEL" ]; then
    err "找不到 Python 内核: $PY_KERNEL"
    exit 1
fi

# ============ 从 API 拉配置 ============
# 优先级（高 → 低）：命令行 -h > KNOCK_API > KNOCK_HOST > KNOCK_DOMAIN
if [ -n "$API_URL" ] && [ -z "$HOST" ]; then
    info "从 $API_URL 拉取配置..."
    if ! CONFIG_JSON="$("$PY_BIN" - "$API_URL" <<'PYEOF' 2>/dev/null
import json, sys, urllib.request, urllib.error
url = sys.argv[1]
try:
    req = urllib.request.Request(url, headers={"User-Agent": "knock-lan-termux/1.0"})
    with urllib.request.urlopen(req, timeout=5) as r:
        data = json.load(r)
    cfg = data.get("config", data) if isinstance(data, dict) else {}
    print(cfg.get("router_ip4", ""))
    print(",".join(str(cfg.get(f"knock{i}_port", i)) for i in (1, 2, 3, 4)))
except Exception as e:
    sys.stderr.write(f"拉取失败: {e}\n")
    sys.exit(1)
PYEOF
    )"; then
        err "API 拉取失败，请用 -h/-p 显式指定"
        exit 1
    fi
    HOST="$(echo "$CONFIG_JSON" | sed -n '1p')"
    PORTS="$(echo "$CONFIG_JSON" | sed -n '2p')"
    info "拉取成功: host=$HOST ports=$PORTS"
fi

# ============ HOST 兜底：配置区 KNOCK_HOST → KNOCK_DOMAIN 解析 ============
if [ -z "$HOST" ]; then
    if [ -n "$KNOCK_HOST" ]; then
        HOST="$KNOCK_HOST"
        info "使用 KNOCK_HOST=$HOST"
    elif [ -n "$KNOCK_DOMAIN" ]; then
        info "解析 KNOCK_DOMAIN=$KNOCK_DOMAIN ..."
        # 优先 getent（glibc），否则走 Python（termux 通用）
        RESOLVED_IP="$(getent ahostsv4 "$KNOCK_DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')"
        if [ -z "$RESOLVED_IP" ]; then
            RESOLVED_IP="$("$PY_BIN" - "$KNOCK_DOMAIN" <<'PYEOF' 2>/dev/null
import socket, sys
try:
    infos = socket.getaddrinfo(sys.argv[1], None, socket.AF_INET)
    print(infos[0][4][0])
except Exception as e:
    sys.stderr.write(f"域名解析失败: {e}\n")
    sys.exit(1)
PYEOF
            )" || RESOLVED_IP=""
        fi
        if [ -z "$RESOLVED_IP" ]; then
            err "域名解析失败: $KNOCK_DOMAIN"
            err "  检查网络/DNS，或直接用 KNOCK_HOST 填 IP"
            exit 1
        fi
        HOST="$RESOLVED_IP"
        info "  -> $HOST"
    fi
fi

# ============ 校验 ============
if [ -z "$HOST" ]; then
    err "host 未指定"
    echo "  三选一：编辑脚本顶部 KNOCK_HOST / KNOCK_DOMAIN / KNOCK_API" >&2
    echo "  或命令行：-h <ip>  --api <url>" >&2
    exit 1
fi

IFS=',' read -r P1 P2 P3 P4 <<EOF
$PORTS
EOF

for p in "$P1" "$P2" "$P3" "$P4"; do
    if ! echo "$p" | grep -qE '^[0-9]+$' || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
        err "无效端口 '$p'（必须 1-65535）"
        exit 1
    fi
done

case "$MIMIC" in
    none|random|noise|ntp|dns|tls|stun|wireguard) ;;
    *) err "无效 --mimic: $MIMIC"; exit 1 ;;
esac

case "$MODE" in
    lan|wan) ;;
    *) err "无效 --mode: $MODE（仅 lan / wan）"; exit 1 ;;
esac

# ============ WAN 模式：噪音端口剔除敲门端口 ============
# 路由器 knock_wan_v4：任何「非敲门端口」的敲门包都会进入 @error_ips 30s 惩罚窗口。
# 因此噪音端口必须严格避开 KNOCK_PORTS（避免被路由器记成失败包）。
if [ "$MODE" = "wan" ]; then
    SAFE_NOISE_PORTS=""
    IFS=',' read -ra _np <<< "$NOISE_PORTS_CFG"
    for np in "${_np[@]}"; do
        np="$(echo "$np" | tr -d ' ')"
        [ -z "$np" ] && continue
        skip=0
        for p in "$P1" "$P2" "$P3" "$P4"; do
            if [ "$np" = "$p" ]; then
                skip=1
                break
            fi
        done
        if [ "$skip" = "0" ]; then
            SAFE_NOISE_PORTS="${SAFE_NOISE_PORTS:+$SAFE_NOISE_PORTS,}$np"
        fi
    done
    NOISE_PORTS="$SAFE_NOISE_PORTS"
    if [ -z "$NOISE_PORTS" ] && [ "$NOISE" -gt 0 ]; then
        warn "噪音目标端口全部被剔除（与敲门端口重叠），噪音禁用"
        NOISE=0
    fi
fi

# ============ WAN 模式：打印本机公网出口 IP ============
# 不做 TCP verify（用户要求），只是提示本机公网 IP，方便用户在路由器上检查
# 该 IP 是否已在 @error_ips4 / blacklist4 中。
if [ "$MODE" = "wan" ] && [ "$PRINT_PUBLIC_IP" = "1" ] && [ "$DRY_RUN" = "0" ]; then
    info "查询本机公网出口 IP..."
    PUBIP=""
    # 优先 ifconfig.co（无 API key，纯净 IP 返回）
    PUBIP="$(curl -sS --max-time 5 https://ifconfig.co 2>/dev/null | tr -d ' \n')"
    if [ -z "$PUBIP" ] || ! echo "$PUBIP" | grep -qE '^[0-9.]+$'; then
        PUBIP="$(curl -sS --max-time 5 https://api.ipify.org 2>/dev/null | tr -d ' \n')"
    fi
    if [ -z "$PUBIP" ] || ! echo "$PUBIP" | grep -qE '^[0-9.]+$'; then
        PUBIP="<无法获取，请检查网络>"
    fi
    info "  本机公网出口 IP: $PUBIP"
    info "  ⚠️  如果该 IP 已在路由器 add_to_blacklist4 中，敲门必失败"
    info "      路由器上：nft list set inet fw4 blacklist4"
    info "      解封：nft delete element inet fw4 blacklist4 { $PUBIP }"
fi

# ============ 显示概要 ============
info "mode=$MODE  target=$HOST  ports=$P1 $P2 $P3 $P4  interval=${INTERVAL}s±${JITTER}s  mimic=$MIMIC  noise=$NOISE"
if [ "$NOISE" -gt 0 ] && [ -n "$NOISE_PORTS" ]; then
    info "  noise_targets=$NOISE_PORTS"
fi
if [ "$MODE" = "wan" ]; then
    warn "WAN 模式：路由器 knock_wan_v4 链默认有 limit rate 1/minute burst 1"
    warn "         若未在路由器放宽限速，4 步敲门 100% 失败"
fi

# ============ 调 Python 内核 ============
if [ "$DRY_RUN" -eq 1 ]; then
    info "[dry-run] 实际不发送，只打印参数"
fi

# 透传所有参数到 Python
HOST="$HOST" \
PORTS="$PORTS" \
INTERVAL="$INTERVAL" \
JITTER="$JITTER" \
MIMIC="$MIMIC" \
NOISE="$NOISE" \
NOISE_PORTS="$NOISE_PORTS" \
MODE="$MODE" \
DRY_RUN="$DRY_RUN" \
QUIET="$QUIET" \
    "$PY_BIN" "$PY_KERNEL"
RC=$?

case $RC in
    0) info "4 步敲门已发送" ;;
    2) warn "部分包发送失败（不影响主体，UDP 无连接）" ;;
    *) err "Python 内核异常退出 (rc=$RC)"; exit 1 ;;
esac

info "验证（路由器 SSH）：nft list set inet fw4 allowed4"
info "白名单 5h（whitelist_timeout），超时后重新敲门"
exit 0
