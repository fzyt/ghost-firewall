#!/bin/bash
# knock-lan.sh — LAN 端口敲门客户端（nftables-web-v2）
#
# nftables 模板里 chain knock_lan 已实现 LAN 端 4 步敲门流程：
#   knock1 (8s 内) -> knock2 (8s 内) -> knock3 (8s 内) -> knock4 -> 加入 @allowed4
# 白名单默认持续 5 小时（whitelist_timeout 配置）。
#
# 用法：
#   knock-lan.sh                                    # 自动从 nftables-web 配置读
#   knock-lan.sh -h 192.168.4.1                     # 显式指定路由器 IP（端口从配置读）
#   knock-lan.sh -p 1234,5678,9012,3456             # 显式指定 4 个端口
#   knock-lan.sh -h 192.168.4.1 -p 1234,5678,9012,3456
#
# 验证方法（路由器上）：
#   nft list set inet fw4 allowed4
# 应能看到你的客户端 IP（带 expires 过期时间）
#
# 退出码：
#   0  - 4 步全部发出（无论路由器是否接收，UDP 无连接）
#   1  - 参数错误 / 配置文件解析失败

set -e

CONFIG="/etc/nftables/nftables-web-config.json"
HOST=""
PORTS=""
INTERVAL=1   # 步间间隔（秒），模板 timeout 8s 留足余量

usage() {
    sed -n '2,18p' "$0"
    exit "${1:-0}"
}

# 参数解析
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--host)
            [ -z "${2:-}" ] && { echo "ERROR: -h 需要参数" >&2; usage 1; }
            HOST="$2"; shift 2 ;;
        -p|--ports)
            [ -z "${2:-}" ] && { echo "ERROR: -p 需要参数" >&2; usage 1; }
            PORTS="$2"; shift 2 ;;
        -i|--interval)
            [ -z "${2:-}" ] && { echo "ERROR: -i 需要参数" >&2; usage 1; }
            INTERVAL="$2"; shift 2 ;;
        --help|-?)
            usage 0 ;;
        *)
            echo "ERROR: 未知参数: $1" >&2
            usage 1 ;;
    esac
done

# 缺省值：从 nftables-web 配置读
if [ -z "$HOST" ] || [ -z "$PORTS" ]; then
    if [ ! -f "$CONFIG" ]; then
        echo "ERROR: 找不到 $CONFIG" >&2
        echo "  请用 -h 和 -p 显式指定主机和端口（不依赖配置文件）" >&2
        exit 1
    fi
    if command -v python3 >/dev/null 2>&1; then
        # ⚠️ 这里**不许 eval**（P1-39）。
        #
        # 老写法是让 python 打印 `HOST="..."` / `PORTS="..."` 再交给 shell 的
        # eval 解析。配置里的 router_ip4 是**用户可写**的字段，写成
        #     x"; rm -rf /; echo "
        # 就能在 eval 里执行任意命令 ——
        # 配置文件是**数据**，不是代码。
        #
        # 现在：python 只输出**纯值**（一行一个、不带引号），
        # 用 sed 取出来，**完全不经过 shell 的二次解析**；
        # 再叠加下面的 host 白名单校验，恶意值到不了任何命令里。
        if ! CONFIG_VALS="$(python3 - "$CONFIG" <<'PYEOF'
import json, sys

def safe(s):
    """只保留「值」能有的字符 —— 结果必须是数据，不能是代码。

    允许：字母、数字、点、冒号（IPv6）、短横线、下划线
    排除：引号、反引号、$、分号、管道、括号、空白、斜杠…
    """
    return "".join(ch for ch in str(s) if ch.isalnum() or ch in ".:_-")

try:
    with open(sys.argv[1]) as f:
        c = json.load(f)
    host = safe(c.get("router_ip4", "")) or "192.168.1.1"
    ports = [safe(c.get(f"knock{i}_port", i)) for i in (1, 2, 3, 4)]
    print(host)
    print(",".join(ports))
except Exception as e:
    print(f"ERROR: 解析 {sys.argv[1]} 失败: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
        )"; then
            echo "ERROR: 解析配置 $CONFIG 失败" >&2
            exit 1
        fi
        HOST=$(printf '%s\n' "$CONFIG_VALS" | sed -n '1p')
        PORTS=$(printf '%s\n' "$CONFIG_VALS" | sed -n '2p')
    elif command -v jsonfilter >/dev/null 2>&1; then
        # OpenWrt 自带 jsonfilter
        HOST=$(jsonfilter -e '$.router_ip4' < "$CONFIG" 2>/dev/null || echo "")
        PORTS=$(jsonfilter -e '$.knock1_port' < "$CONFIG" 2>/dev/null)
        P2=$(jsonfilter -e '$.knock2_port' < "$CONFIG" 2>/dev/null)
        P3=$(jsonfilter -e '$.knock3_port' < "$CONFIG" 2>/dev/null)
        P4=$(jsonfilter -e '$.knock4_port' < "$CONFIG" 2>/dev/null)
        PORTS="${PORTS},${P2},${P3},${P4}"
    else
        echo "ERROR: 找不到 python3 或 jsonfilter，无法解析配置" >&2
        echo "  请用 -h 和 -p 显式指定" >&2
        exit 1
    fi
fi

if [ -z "$HOST" ] || [ -z "$PORTS" ]; then
    echo "ERROR: host 或 ports 仍为空" >&2
    echo "  HOST='$HOST' PORTS='$PORTS'" >&2
    exit 1
fi

# 解析端口
IFS=',' read -r P1 P2 P3 P4 <<EOF
$PORTS
EOF

for p in "$P1" "$P2" "$P3" "$P4"; do
    if ! echo "$p" | grep -qE '^[0-9]+$' || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
        echo "ERROR: 无效端口 '$p'（必须 1-65535 的整数）" >&2
        exit 1
    fi
done

# host 白名单：只接受 IP 或合法主机名（P1-38 的第一道防线）
#
# 为什么必须校验：host 会进 `bash -c` 的命令串（老写法）或 /dev/udp 的
# 路径部分。带 `;` `$(...)` 的值会被 shell 解析成**额外的命令**；
# 带 `/` 的值能穿越 /dev/udp/ 这个路径前缀。
# 允许：数字、字母、点、冒号（IPv6）、短横线、下划线
# 明确排除：斜杠、空白、引号、反引号、$、分号、管道、括号…
valid_host() {
    [ -n "$1" ] || return 1
    case "$1" in
        *[!0-9A-Za-z.:_-]*) return 1 ;;
    esac
    return 0
}

if ! valid_host "$HOST"; then
    echo "ERROR: 非法的主机地址 '$HOST'" >&2
    echo "  只允许 IP 或主机名（字母/数字/点/冒号/短横线/下划线）" >&2
    exit 1
fi

echo "[LAN-Knock] target=$HOST ports=$P1 $P2 $P3 $P4 interval=${INTERVAL}s"

# 发送单个 UDP 包
# 优先顺序：bash 内置 /dev/udp > ncat > nc
# bash 内置 /dev/udp 是几乎所有 Linux/macOS 都支持的特性
send_udp() {
    local host="$1" port="$2"
    if [ -n "${BASH_VERSION:-}" ]; then
        # bash 内置：用 timeout 限制阻塞时间
        #
        # ⚠️ host/port **不能**插进命令串（P1-38）。
        # 老写法：bash -c "exec 3<>/dev/udp/${host}/${port} && printf 'k' >&3"
        # —— host 里带 `;` 或 `$(...)` 会被 shell 解析成**额外的命令**，
        # 配置文件是数据，值不该被当代码执行。
        # 现在：值作为**位置参数**传进去，命令串里只用 "$1"/"$2" 引用 ——
        # 位置参数不会被再次解析 ⇒ 注入不成立。
        timeout 3 bash -c 'exec 3<>/dev/udp/"$1"/"$2" && printf "k" >&3' _ "$host" "$port" 2>/dev/null || true
    elif command -v ncat >/dev/null 2>&1; then
        printf 'k' | ncat -u -w 2 "$host" "$port" 2>/dev/null || true
    elif command -v nc >/dev/null 2>&1; then
        # BusyBox nc 和 OpenBSD nc 参数略有不同，逐一尝试
        printf 'k' | nc -u -w 2 "$host" "$port" 2>/dev/null || \
        printf 'k' | nc -u "$host" "$port" </dev/null 2>/dev/null || true
    else
        echo "ERROR: 没有可用的 UDP 发送工具（bash /dev/udp、ncat、nc 都不可用）" >&2
        return 1
    fi
}

for i in 1 2 3 4; do
    # ⚠️ 不用 `eval echo \$P$i` 取端口。
    # eval 会把 $P1 的**值**再解析一遍：值里带 `$(...)` 就可能执行命令。
    # 这里用 case 直接取，值从头到尾只被当数据。
    case "$i" in
        1) port="$P1" ;;
        2) port="$P2" ;;
        3) port="$P3" ;;
        4) port="$P4" ;;
    esac
    echo "[LAN-Knock] step $i -> $host:$port"
    send_udp "$HOST" "$port"
    if [ "$i" -lt 4 ]; then
        sleep "$INTERVAL"
    fi
done

echo "[LAN-Knock] 4 步敲门已发送（UDP 无连接，发送成功即认为完成）"
echo "[LAN-Knock] 验证方法（路由器 SSH）："
echo "    nft list set inet fw4 allowed4"
echo "  你应该看到 ${HOST} 以外的本机 IP（即客户端 LAN IP）出现在列表中"
echo "[LAN-Knock] 白名单默认 5 小时（whitelist_timeout），超时后需重新敲门"
exit 0
