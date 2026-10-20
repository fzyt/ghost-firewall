#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# nftables-web-v2 一键安装脚本
# 兼容 OpenWrt 21.02+ / 23.05+
# 项目: https://github.com/username/nftables-web-v2
#

set -e

# ============================================================
# 变量定义
# ============================================================
VERSION="0.7.9.1"
PROJECT_NAME="nftables-web-v2"
INSTALL_DIR="/opt/nftables-web-v2"
CONFIG_DIR="/etc/nftables"
CONFIG_FILE="${CONFIG_DIR}/nftables-web-config.json"
NFTABLES_CONF="/etc/nftables.conf"
INITD_SCRIPT="/etc/init.d/nftables-web"
LOG_FILE="/var/log/nftables-web-setup.log"
GITHUB_REPO="fzyt/ghost-firewall"
ACME_EMAIL="admin@example.com"
ARG_FORCE=0

# 自动检测包管理器
detect_pkg_manager() {
    if command -v opkg >/dev/null 2>&1; then
        PKG_MANAGER="opkg"
    elif command -v apk >/dev/null 2>&1; then
        PKG_MANAGER="apk"
    else
        die "未找到包管理器（opkg 或 apk）"
    fi
}

pkg_install() {
    for pkg in "$@"; do
        case "$PKG_MANAGER" in
            opkg)
                if opkg list-installed | grep -q "^${pkg} "; then
                    info "已安装: ${pkg}"; continue
                fi
                info "安装: ${pkg}"
                opkg install "$pkg" || warn "安装失败: ${pkg}"
                ;;
            apk)
                if apk info -e "$pkg" >/dev/null 2>&1; then
                    info "已安装: ${pkg}"; continue
                fi
                info "安装: ${pkg}"
                # --no-cache：apk 的下载缓存在 /var/cache/apk，那是在 **overlay** 上
                # （不是 tmpfs）。不清理的话下载的包会再存一份 —— OpenWrt 的
                # overlay 常常只有 80~90MB，一份 50MB 的缓存直接把它撑满。
                apk add --no-cache "$pkg" || warn "安装失败: ${pkg}"
                ;;
        esac
    done
}

# ============================================================
# 下载器自愈（OpenWrt 25.x 的鸡生蛋问题）
# ============================================================
#
# 现象（2026-10-20 在 .245 实测）：
#   `apk add nginx-full ... wget-ssl` 同一个事务里，wget-ssl 的 postinst
#   把 /usr/bin/wget 换成 SSL 版，而它依赖 libssl.so.3（libopenssl3 包）。
#   libopenssl3 恰恰要靠 wget 下载 —— apk 用 wget 下到一半，wget 已经坏了：
#       ERROR: wget: exited with error 127
#       ERROR: unable to select packages: libopenssl3 (no such package)
#   结果不是"少装一个包"，是**apk 的下载器自己被装坏了**，之后什么都下不来。
#   nginx-full / wget-ssl / openssl-util / python3-openssl 全部依赖 libopenssl3。
#
# 解法：curl 在 OpenWrt 上链的是 **mbedTLS 而不是 OpenSSL**，不依赖 libssl.so.3
# ⇒ 拿 curl 顶替 wget 把 libopenssl3 拉下来，wget-ssl 随即恢复正常。
#
# 为什么必须自愈而不是让用户手动处理：这一步失败时报的是
# "unable to select packages"，完全看不出真正的原因是"下载器自己坏了"，
# 用户只会反复重试安装，而重试永远失败。
#
# ⚠️ 判据必须是「输出特征」，**不能**拿 `wget --version` 的退出码当判据
#   （2026-10-20 在 .147 全新机上踩过这个坑）：
#   OpenWrt 25.x 原装的 /usr/bin/wget 是指向 /bin/uclient-fetch 的软链，
#   而 uclient-fetch **不支持 --version**：
#       $ wget --version
#       wget: unrecognized option: version        （退出码 1）
#   拿退出码当判据 ⇒ 把**好用的**下载器误判成坏掉 ⇒ 装上一堆依赖 curl 的
#   shim，可全新机上 curl 还没装 ⇒ 整个安装全盘失败。
#
#   真坏掉（wget-ssl 缺 libssl.so.3）的特征是**动态链接失败**：
#       /usr/libexec/wget-ssl: Error relocating ...: symbol not found: ...
#   两种输出特征完全不同，不会混淆。
#
downloader_healthy() {
    # 压根没有 wget = 坏
    if ! command -v wget >/dev/null 2>&1; then
        return 1
    fi
    local out
    out="$(wget --version 2>&1 || true)"
    # 动态链接失败 / 共享库缺失 —— wget-ssl 缺 libssl.so.3 的典型特征
    if echo "$out" | grep -qE "Error relocating|symbol not found|error while loading shared libraries"; then
        return 1
    fi
    return 0
}

repair_downloader() {
    # 只在 apk 上有这个问题（opkg 的 wget 依赖关系不同）
    [ "$PKG_MANAGER" = "apk" ] || return 0

    # 下载器能用就不动它
    if downloader_healthy; then
        return 0
    fi

    warn "wget 不可用（多半是缺 libssl.so.3 —— libopenssl3 要靠 wget 下，wget-ssl 却依赖它）"
    if [ -x /usr/bin/curl ]; then
        info "临时用 curl 顶替 wget（curl 链的是 mbedTLS，不依赖 libssl.so.3）"
    elif [ -x /bin/uclient-fetch ]; then
        info "临时用 uclient-fetch 顶替 wget（curl 还没装，先用 busybox 自带的）"
    else
        die "wget 不可用，且既没有 curl 也没有 /bin/uclient-fetch —— 无法继续下载依赖"
    fi

    local shim=/usr/bin/wget
    if [ -e "$shim" ]; then
        mv "$shim" "${shim}.broken" 2>/dev/null || true
    fi
    cat > "$shim" <<'SHIM'
#!/bin/sh
# wget -> curl / uclient-fetch 兼容 shim（临时用，见 setup.sh 的 repair_downloader 注释）
URL=""; OUT="-"; TMO=600; NOCHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    -q|--quiet|--no-verbose) shift ;;
    --no-check-certificate) NOCHECK=1; shift ;;
    -T) TMO="$2"; shift 2 ;;
    --timeout=*) TMO="${1#--timeout=}"; shift ;;
    --tries=*|--tries) shift ;;
    -O) OUT="$2"; shift 2 ;;
    --output-document=*) OUT="${1#--output-document=}"; shift ;;
    -U|--user-agent) shift 2 ;;
    -*) shift ;;
    *) URL="$1"; shift ;;
  esac
done
[ -z "$URL" ] && exit 1
# apk 给的 -T 60 对慢速出口不够（实测 2.3MB/60s 就超时），放大并加断点续传
[ "$TMO" -lt 600 ] 2>/dev/null && TMO=600
# 没有 CA 证书库的时候没法校验，只能放弃校验
[ -d /etc/ssl/certs ] || NOCHECK=1
[ -n "$(ls -A /etc/ssl/certs 2>/dev/null)" ] || NOCHECK=1

# 后端优先级：curl → /bin/uclient-fetch
# ⚠️ 运行时才判断，不能写死在安装时 —— 全新机上装 curl 之前 shim 就得能用。
if [ -x /usr/bin/curl ]; then
  # ⚠️ 必须带 -f（--fail）：curl 默认对 HTTP 404 **也返回 exit 0**，
  # 而 apk 只看退出码 —— 不加 -f 的话，apk 会把一个 146 字节的
  # "404 Not Found" 错误页当成 .apk 装上去，报错信息完全对不上真正原因。
  CK=""; [ "$NOCHECK" = "1" ] && CK="-k"
  if [ "$OUT" = "-" ]; then
    exec /usr/bin/curl -fsSL $CK --max-time "$TMO" --retry 8 --retry-delay 3 --retry-all-errors "$URL"
  else
    exec /usr/bin/curl -fsSL $CK --max-time "$TMO" --retry 8 --retry-delay 3 --retry-all-errors -C - -o "$OUT" "$URL"
  fi
elif [ -x /bin/uclient-fetch ]; then
  # uclient-fetch 没有 --fail / --retry，但 HTTP 错误码它自己会返回非 0。
  # ⚠️ 它不支持 `-O -`（会把 "-" 当成文件名），走 stdout 时干脆不传 -O。
  UC=""; [ "$NOCHECK" = "1" ] && UC="--no-check-certificate"
  if [ "$OUT" = "-" ]; then
    exec /bin/uclient-fetch -q -T "$TMO" $UC "$URL"
  else
    exec /bin/uclient-fetch -q -T "$TMO" $UC --continue -O "$OUT" "$URL"
  fi
else
  echo "wget shim: 找不到 curl，也没有 /bin/uclient-fetch" >&2
  exit 127
fi
SHIM
    chmod +x "$shim" 2>/dev/null || true
}

# 装完（且 libopenssl3 已就位）之后把 wget 换回原版
restore_downloader() {
    [ "$PKG_MANAGER" = "apk" ] || return 0
    # ⚠️ 要检查 **wget-ssl 本体**能不能跑，不能检查 `wget --version` ——
    # 那时 /usr/bin/wget 已经是我们装的 shim，它当然能跑，
    # 用它当判据会把「还没修好」误判成「修好了」。
    local ssl_bin=""
    for cand in /usr/libexec/wget-ssl /usr/libexec/wget; do
        if [ -x "$cand" ]; then ssl_bin="$cand"; break; fi
    done
    if [ -n "$ssl_bin" ] && "$ssl_bin" --version >/dev/null 2>&1; then
        # 让 /usr/bin/wget 指向 wget-ssl —— apk 的 postinst 本来就是这么干的，
        # 但如果中途被我们的 shim 顶掉了，这里补回来。
        if [ -L /usr/bin/wget ] && [ "$(readlink /usr/bin/wget)" = "$ssl_bin" ]; then
            ok "✅ wget 已是 wget-ssl"
        else
            mv -f /usr/bin/wget /usr/bin/wget.shim 2>/dev/null || true
            ln -sf "$ssl_bin" /usr/bin/wget 2>/dev/null || true
            ok "✅ wget 已指向 wget-ssl"
        fi
        # ⚠️ 旧的原件（.broken）**不回填** —— 回填会把「apk 刚装好的 SSL wget」
        # 换回旧的 uclient-fetch 软链，等于把 https 支持又拆了。
        # 留个 .orig 备份就行。
        if [ -e /usr/bin/wget.broken ]; then
            mv -f /usr/bin/wget.broken /usr/bin/wget.broken.orig 2>/dev/null || true
        fi
    else
        info "wget-ssl 仍不可用，保留兼容 shim（不影响安装，但 wget 的 https 依赖它）"
    fi
}

# ============================================================
# nginx 能力自检（v0.8.0 网关的硬前置）
# ============================================================
# 认证网关的每个公网请求都要经 auth_request 转发给认证服务核对 token。
# 缺这个模块不是「降级」，是网关必然 500 —— 所以这里不做 warn+skip，
# 直接 die：让装完的人立刻知道，而不是部署完才发现网关不通。
check_nginx_modules() {
    if ! command -v nginx >/dev/null 2>&1; then
        die "nginx 未安装成功 —— 网关无法工作，请检查网络后重试"
    fi

    # ⚠️ 先分清「nginx 跑不起来」和「nginx 起来了但缺模块」——
    # 这两种的修法完全不同，报错混在一起会把人带沟里。
    #
    # 跑不起来的最常见原因：缺 libssl.so.3（libopenssl3 包）。
    # 那台机器上 nginx -V 一行 configure 参数都不输出，只有一串
    # "Error relocating /usr/sbin/nginx: symbol not found" ——
    # 肉眼看过去跟"没装 auth_request"一模一样。
    if ! nginx -V >/dev/null 2>&1; then
        local why
        why="$(nginx -V 2>&1 | head -1)"
        if echo "$why" | grep -q "libssl.so.3\|libcrypto.so.3"; then
            die "nginx 缺少 libssl.so.3 / libcrypto.so.3（libopenssl3 包）
     多半是 apk 装 wget-ssl 时把自己的依赖 libopenssl3 顶掉了 ——
     wget-ssl 的 postinst 替换了 /usr/bin/wget，而 apk 正是用 wget 下载包的。
     修法见 README「OpenWrt 25.x 已知问题」一节。
     原始报错: ${why}"
        fi
        die "nginx 无法执行（${why}）—— 请先修好 nginx 再重试"
    fi

    if ! nginx -V 2>&1 | grep -q "http_auth_request_module"; then
        die "当前 nginx 缺少 auth_request 模块（多半装的是 nginx-ssl），而 v0.8.0 认证网关强依赖它。请安装 nginx-full：opkg install nginx-full"
    fi

    if ! nginx -V 2>&1 | grep -q "http_realip_module"; then
        # 缺 realip 不致命（只影响日志里客户端 IP 的还原），不阻断安装
        warn "nginx 缺少 realip 模块，网关访问日志里的客户端 IP 可能显示为代理地址"
    fi

    ok "✅ nginx 模块自检通过（auth_request 就绪）"
}

pkg_update() {
    case "$PKG_MANAGER" in
        opkg) opkg update ;;
        apk) apk update ;;
    esac
}

# 参数解析
ARG_VERSION=""
ARG_LOCAL=""
SKIP_NGINX=0

# ============================================================
# 颜色输出
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    local level="$1"; shift
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${ts} [${level}] $*" | tee -a "$LOG_FILE"
}

info()  { log "INFO " "$*"; }
warn()  { log "WARN " "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }
ok()    { log "OK   " "${GREEN}$*${NC}"; }

die() {
    error "$@"
    error "安装中止，请检查上方日志。"
    exit 1
}

# ============================================================
# 探测 LAN 接口的 IPv4 网段 / 广播 / 主机地址
#
# 输出三行 shell 赋值（可直接 eval），探测不到时什么都不输出。
#
# 为什么必须带掩码（2026-10-15 修复，.224 实跑复现）：
# 旧实现是
#     ip -4 addr show "$LAN_IFACE" | grep inet | awk '{print $2}' \
#         | cut -d/ -f1 | sed 's/\.[0-9]*$/.0/'
# 三个缺陷叠在同一个管道里：
#   1. `cut -d/ -f1` 把掩码整个丢掉。192.168.100.224/24 → "192.168.100.0"，
#      写进配置后 _safe_cidr 归一化成 /32 —— 网关里 public=false 的反代
#      只放行 1 个地址，整个 LAN（256 台）都打不开。安装过程不报错。
#   2. 没有 head -1。LAN 接口挂第二个 IPv4（VLAN/多网段）时输出是两行，
#      直接嵌进 JSON 就成 "192.168.100.0\n10.8.0.0" —— **整个 config.json
#      变成非法 JSON**，启动时静默回退 DEFAULT_CONFIG，于是 trusted_ip4 变成
#      192.168.100.2、转发规则指向 192.168.4.226，而接口照样返回 success。
#      这比缺陷 1 严重得多。
#   3. broadcast4 靠 "${lan_subnet4%.*}.255" 拼，只对 /24 成立；
#      掩码补回来之后它还会拼成 "192.168.100.0/24.255" 这种非法值。
#
# 改用 python3 而不是 awk 手算位运算：python3 本来就是硬依赖（后端是 Flask，
# install_deps 会装，本函数由 init_config 在其之后调用），ipaddress 的
# 网络号/广播号语义不需要自己维护。
detect_lan_ipv4() {
    command -v python3 >/dev/null 2>&1 || return 0

    # 用文件传参而不是插值：接口名来自 uci，不可控
    python3 - "$1" <<'PYEOF'
import ipaddress
import subprocess
import sys

iface = sys.argv[1] if len(sys.argv) > 1 else ''
cidr = ''
host = ''

# 1) 从接口地址取「主机地址 + CIDR」。只取第一个 —— 多个 IPv4 绝不能拼进 JSON
#    （旧实现在这里没有 head -1，多地址 LAN 会写出非法 JSON）。
try:
    res = subprocess.run(['ip', '-4', 'addr', 'show', 'dev', iface],
                         capture_output=True, text=True, timeout=5)
    for line in res.stdout.splitlines():
        f = line.split()
        if len(f) >= 2 and f[0] == 'inet':
            host = f[1].split('/', 1)[0]
            cidr = f[1]
            break
except (OSError, subprocess.SubprocessError):
    pass

# 2) 拿不到地址时，回落到内核 route 表里已经算好的「网络地址 + 掩码」。
#    单独用 route 是有意义的：某些环境 addr 拿不到但 route 在。
try:
    if not cidr:
        res = subprocess.run(
            ['ip', '-4', 'route', 'show', 'dev', iface,
             'proto', 'kernel', 'scope', 'link'],
            capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            f = line.split()
            if f and '/' in f[0] and f[0][0].isdigit():
                cidr = f[0]
                break
except (OSError, subprocess.SubprocessError):
    pass

if not cidr:
    sys.exit(0)

try:
    net = ipaddress.ip_network(cidr, strict=False)
except ValueError:
    sys.exit(0)
if net.version != 4:
    sys.exit(0)

print('lan_subnet4=%s' % net)
print('lan_broadcast4=%s' % net.broadcast_address)
if host:
    print('lan_host4=%s' % host)
PYEOF
}

# 从网段算出广播地址。只在探测不到接口地址时兜底 —— 掩码不一定是 /24，
# 拼 "${x%.*}.255" 在 /23、/8 上都是错的。
detect_lan_broadcast4() {
    command -v python3 >/dev/null 2>&1 || return 0
    python3 - "$1" <<'PYEOF'
import ipaddress
import sys

try:
    net = ipaddress.ip_network(sys.argv[1] if len(sys.argv) > 1 else '',
                               strict=False)
except ValueError:
    sys.exit(0)
if net.version != 4:
    sys.exit(0)
print(net.broadcast_address)
PYEOF
}

# 从网段算出常用网关地址（网络地址 + 1）。只在探测不到主机地址时兜底。
detect_lan_ipv4_gateway() {
    command -v python3 >/dev/null 2>&1 || return 0
    python3 - "$1" <<'PYEOF'
import ipaddress
import sys

try:
    net = ipaddress.ip_network(sys.argv[1] if len(sys.argv) > 1 else '',
                               strict=False)
except ValueError:
    sys.exit(0)
if net.version != 4 or net.num_addresses < 2:
    sys.exit(0)
print(net.network_address + 1)
PYEOF
}

# ============================================================
# 工具函数
# ============================================================
is_interactive() {
    [ -t 0 ]
}

# ============================================================
# 帮助
# ============================================================
show_help() {
    cat <<EOF
nftables-web-v2 一键安装脚本 v${VERSION}

用法: $0 [选项]

选项:
  --version <tag>    安装指定版本（默认: v${VERSION}）
  --local <path>     从本地路径安装（开发用）
  --skip-nginx       跳过 nginx 安装与配置
  --force            强制覆盖已有项目文件
  --help             显示此帮助信息

示例:
  $0                        # 安装最新版本
  $0 --version v0.6.0       # 安装指定版本
  $0 --local ./             # 从本地路径安装
  $0 --skip-nginx           # 跳过 nginx
  $0 --force                # 强制覆盖

日志文件: ${LOG_FILE}
EOF
    exit 0
}

# ============================================================
# 参数解析
# ============================================================
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                [ -n "$2" ] || { error "--version 需要指定版本号"; show_help; }
                ARG_VERSION="$2"; shift 2 ;;
            --local)
                [ -n "$2" ] || { error "--local 需要指定本地路径"; show_help; }
                ARG_LOCAL="$2";   shift 2 ;;
            --skip-nginx) SKIP_NGINX=1;  shift ;;
            --force)      ARG_FORCE=1;   shift ;;
            --help)       show_help ;;
            *)
                error "未知参数: $1"
                show_help
                ;;
        esac
    done
}

# ============================================================
# 1. 环境检查
# ============================================================
check_env() {
    info "========== 环境检查 =========="

    # root 权限
    [ "$(id -u)" -eq 0 ] || die "请使用 root 权限运行此脚本"

    # OpenWrt 检测
    if [ -f /etc/openwrt_release ]; then
        . /etc/openwrt_release
        ok "检测到 OpenWrt: ${DISTRIB_DESCRIPTION}"
    else
        die "未检测到 OpenWrt 系统（/etc/openwrt_release 不存在）"
    fi

    # 架构
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|aarch64|arm*|mips*) ok "架构: ${arch}" ;;
        *) warn "架构 ${arch} 可能不受支持，继续安装..." ;;
    esac

    # 磁盘空间
    local avail
    avail="$(df -k / | awk 'NR==2{print $4}')"
    if [ "$avail" -lt 10240 ] 2>/dev/null; then
        die "磁盘空间不足（可用: $((avail/1024))MB，至少需要 10MB）"
    fi
    ok "磁盘空间: $((avail/1024))MB 可用"

    detect_pkg_manager
    ok "包管理器: ${PKG_MANAGER}"

    ok "✅ 环境检查通过"
}

# ============================================================
# 2. 安装依赖（带重试）
# ============================================================
install_deps() {
    info "========== 安装依赖 =========="

    # 下载器先自愈 —— 见 repair_downloader 的注释。
    # 不先修的话，apk 会在事务中途把 wget 换成坏的那个，之后什么都下不来。
    repair_downloader

    pkg_update || warn "包列表更新失败，继续尝试安装..."

    # ⚠️ 顺序有讲究，别随手调换：
    #   1. libopenssl3（apk）必须**先**装 —— 它提供 libssl.so.3，
    #      而 wget-ssl / nginx-full / openssl-util / python3-openssl 都依赖它。
    #      它自己又要靠 wget 下载，所以得在 wget-ssl 之前到位
    #      （否则就是那个鸡生蛋）。
    #   2. wget-ssl 放**最后** —— 它的 postinst 会替换 /usr/bin/wget，
    #      放前面的话后续包的下载就全靠坏掉的 wget 了。
    case "$PKG_MANAGER" in
        apk)  pkg_install libopenssl3 ;;
        opkg) pkg_install libssl libcrypto ;;
    esac

    # ⚠️ libopenssl3 是硬前置：nginx-full / wget-ssl / openssl-util /
    # python3-openssl 全都依赖它提供的 libssl.so.3。装不上就早点死，
    # 不然后面每个包都失败，最后报一堆毫不相干的错。
    #
    # ⚠️ 判存在性**不能**用 `ls a b c` —— ls 只要有**任何一个**路径不存在
    # 就返回非 0，哪怕其余的都在（2026-10-20 在 .147 踩过：
    # libssl.so.3 明明装好了，却因为另外两个候选路径不存在被判成"没装"）。
    if [ "$PKG_MANAGER" = "apk" ]; then
        local ssl_lib=""
        for cand in /usr/lib/libssl.so.3 /lib/libssl.so.3; do
            [ -e "$cand" ] && { ssl_lib="$cand"; break; }
        done
        if [ -z "$ssl_lib" ]; then
            ssl_lib="$(ls /usr/lib/libssl.so.3* /lib/libssl.so.3* 2>/dev/null | head -1)"
        fi
        if [ -z "$ssl_lib" ]; then
            die "libopenssl3 安装失败（找不到 libssl.so.3）——
     nginx-full / wget-ssl / openssl-util 都依赖它。
     常见原因：apk 事务里 wget-ssl 的 postinst 抢先替换了 /usr/bin/wget，
     把 apk 自己的下载器换成了缺 libssl.so.3 的坏版本。
     修法：先单独 'apk add --no-cache libopenssl3'，再重跑 setup.sh"
        fi
        ok "✅ libssl.so.3 就位（$ssl_lib）"
    fi

    pkg_install \
        nftables \
        python3 python3-light python3-requests python3-flask \
        ddns-scripts \
        ddns-scripts-cloudflare ddns-scripts-dnspod \
        ddns-scripts-noip ddns-scripts-nsupdate \
        ddns-scripts-godaddy \
        nginx-full \
        curl openssl-util socat \
        ca-certificates

    # wget-ssl 单独放最后（理由见上）
    pkg_install wget-ssl

    # ⚠️ 事务里 wget-ssl 的 postinst 可能把 wget 换成坏的那个 ——
    # 再自愈一次（这时 curl 已经在上面的批次里装好了）。
    if ! downloader_healthy; then
        warn "安装过程中 wget 被换成了不可用的版本，重新自愈"
        repair_downloader
    fi

    restore_downloader

    # v0.8.0 的单端口认证网关完全建立在 nginx 的 auth_request 之上：
    # 每个公网请求都要先问认证服务「这个人有 token 吗」，没有就 401。
    # OpenWrt 的 nginx-ssl 不含该模块，装它 = 装完看着一切正常，
    # 一开网关就整片 500。所以这里必须用 nginx-full 并当场验模块。
    check_nginx_modules

    # 安装 Python 依赖（blinker）
    #
    # ⚠️ OpenWrt 25.12 的仓库里**没有 blinker 包**，而 python3-flask 的依赖里
    # 也不含它 —— 但 Flask 3.x 的代码 `from flask.signals import Namespace`
    # 会 import blinker ⇒ 不装就 ImportError。
    # 老办法是 `pip3 install blinker`，但 python3-pip 本身 52MB，
    # 在 80MB 的 overlay 上根本装不下 ⇒ 改成**随包携带**：
    # vendor/blinker/ 里有纯 Python 源码，直接放进 site-packages。
    if ! python3 -c "import blinker" 2>/dev/null; then
        info "安装 Python 依赖: blinker"
        # 候选位置（按顺序找）：
        #   setup/vendor/blinker  ← 随 setup.sh 一起分发（一键安装只下一个
        #     setup.sh 时也能用，因为 vendor 在 setup/ 里）
        #   ../vendor/blinker    ← 仓库根布局（--local 装整仓时）
        local site_pkgs vendored=""
        site_pkgs="$(python3 -c 'import site,sys; print((site.getsitepackages() or [sys.prefix+"/lib/site-packages"])[0])' 2>/dev/null)"
        for cand in "$(dirname "$0")/vendor/blinker" "$(dirname "$0")/../vendor/blinker" \
                    "$(dirname "$0")/vendor" "$(dirname "$0")/../vendor"; do
            [ -d "$cand" ] || continue
            # ⚠️ 候选可能指到 blinker 包本身（里面有 __init__.py），
            # 也可能指到装着 blinker 的上级目录（里面有 blinker/__init__.py）。
            # 两种布局都要认，否则 cp 会去拷一个不存在的
            # "<dir>/blinker/blinker" —— 2026-10-20 在 .226 实测踩过：
            #   cp: can't stat '/tmp/pkg5/setup/vendor/blinker/blinker':
            #       No such file or directory
            if [ -f "$cand/__init__.py" ]; then
                vendored="$cand"; break
            elif [ -f "$cand/blinker/__init__.py" ]; then
                vendored="$cand/blinker"; break
            fi
        done
        if [ -n "$site_pkgs" ] && [ -n "$vendored" ]; then
            mkdir -p "$site_pkgs" 2>/dev/null
            # ⚠️ 目标已存在时，cp -r 会把源拷成 <target>/blinker/blinker（套一层），
            # 结果 import 照样失败。这里先清掉旧目标再拷。
            # （走到这个分支说明 blinker 本来就 import 不了，留着旧目录没意义。）
            if [ -d "$site_pkgs/blinker" ]; then
                rm -rf "$site_pkgs/blinker" 2>/dev/null || true
            fi
            # ⚠️ cp 的错误**不能**吞掉（2>/dev/null）——
            # 吞掉之后只剩一句"随包安装失败"，跟真正原因（路径拼错）完全对不上，
            # 现场根本没法排查。失败时把 cp 的原话打出来。
            local cp_err
            cp_err="$(cp -r "$vendored" "$site_pkgs/" 2>&1)" || {
                warn "  随包安装失败: ${cp_err}"
                install_blinker_via_pip
            }
            if [ -z "$cp_err" ]; then
                info "  已从随包源码安装到 $site_pkgs/blinker（省掉 python3-pip 的 52MB）"
            fi
        else
            info "  未找到随包 blinker（setup/vendor/blinker），改为 pip"
            warn "  ⚠️ pip 兜底需要 python3-pip（约 52MB），overlay 小于 100MB 的机器会装不下"
            install_blinker_via_pip
        fi
    fi

    if ! python3 -c "import blinker" 2>/dev/null; then
        warn "blinker 未能安装 —— Flask 会 ImportError，面板起不来"
    else
        ok "✅ blinker 就绪"
    fi

    ok "✅ 依赖安装完成"
}

# blinker 的 pip 兜底（随包安装失败时才走）
install_blinker_via_pip() {
    # ⚠️ 磁盘闸：python3-pip 自己就 52MB，overlay 只有 80~90MB 的机器上
    # 装它会直接把根文件系统撑满 —— 撑满之后 apk 装不动、log 写不进去、
    # 设备表现为一堆莫名其妙的失败。这里宁可直接报错，也别把盘塞爆。
    local avail_kb avail_mb
    avail_kb="$(df -k / | awk 'NR==2{print $4}')"
    avail_mb=$((avail_kb / 1024))
    if ! command -v pip3 >/dev/null 2>&1; then
        if [ "${avail_mb:-0}" -lt 80 ]; then
            die "磁盘空间不足（剩 ${avail_mb}MB），装不了 python3-pip（约 52MB）——
     blinker 的随包源码也没能用上（setup/vendor/blinker）。
     两条路都走不通时请手动放一份 blinker 到 site-packages。"
        fi
        case "$PKG_MANAGER" in
            opkg) pkg_install python3-pip ;;
            apk)  pkg_install python3-pip ;;
        esac
    fi
    pip3 install blinker --break-system-packages 2>/dev/null \
        || pip3 install blinker 2>/dev/null \
        || warn "blinker 安装失败"
}

# ============================================================
# 3. 安装 acme.sh（优先 opkg，fallback pipe）
# ============================================================
install_acme() {
    info "========== 安装 acme.sh =========="

    if [ -f ~/.acme.sh/acme.sh ] || command -v acme.sh >/dev/null 2>&1; then
        ok "acme.sh 已安装，跳过"
        return
    fi

    info "尝试通过 ${PKG_MANAGER} 安装 acme-acmesh..."
    if pkg_install acme-acmesh 2>/dev/null; then
        ok "✅ acme-acmesh 安装成功"
        return
    fi

    warn "${PKG_MANAGER} 安装 acme-acmesh 失败，尝试通过 curl pipe 安装..."
    warn "⚠️  安全提示：pipe 安装会从 get.acme.sh 下载并直接执行脚本"
    warn "    如果担心安全风险，请手动下载 acme.sh 源码后安装"

    curl -fsSL --connect-timeout 30 --retry 2 --max-time 120 https://get.acme.sh | sh -s email="${ACME_EMAIL}" \
        || { error "❌ acme.sh 安装失败，HTTPS 证书功能将不可用"; return; }

    # 确保 PATH 包含 acme.sh
    export PATH="$HOME/.acme.sh:$PATH"

    ok "✅ acme.sh 安装完成"
}

# ============================================================
# 4. nginx 配置
# ============================================================
setup_nginx() {
    [ "$SKIP_NGINX" -eq 1 ] && { warn "跳过 nginx 配置（--skip-nginx）"; return; }

    info "========== 配置 nginx =========="

    if ! command -v nginx >/dev/null 2>&1; then
        warn "nginx 未安装，跳过配置"
        return
    fi

    local nginx_conf="/etc/nginx/nginx.conf"
    local conf_d="/etc/nginx/conf.d"
    local site_conf="${conf_d}/nftables-web.conf"
    local marker="# Managed by nftables-web-v2 setup.sh"

    # 确保 conf.d 目录存在
    mkdir -p "$conf_d"

    # 4a. 处理主 nginx.conf：只写一次，确保 include conf.d/*.conf
    if [ -f "$nginx_conf" ]; then
        if [ ! -f "${nginx_conf}.bak" ]; then
            cp "$nginx_conf" "${nginx_conf}.bak"
            info "已备份原 nginx 配置"
        fi

        if ! grep -q "include.*conf\.d/\*\.conf" "$nginx_conf" 2>/dev/null; then
            warn "主 nginx.conf 缺少 include conf.d/*.conf，尝试添加..."
            # 在 http 块闭合前插入 include conf.d/*.conf。
            #
            # 原来这里用的是
            #     sed -i '/^http {/,/^}/{ /^}/i\    include conf.d/*.conf;\n'
            # 三个缺陷叠在一起，**在 BusyBox sed 上必然失败**（2026-10-16 .224
            # fresh install 实测复现，日志里稳定打「自动插入 include 失败」）：
            #   1. 范围首端 `/^http {/` 里的 `{` 是裸花括号。BusyBox 的正则解析器
            #      把它当区间量词的起始，直接报 `sed: unterminated {` 并放弃 ——
            #      连「文件不需要改」都不是，是根本没执行。
            #   2. 就算转义了，范围末端 `/^}/` 要求 `}` 在第 0 列，而 OpenWrt 的
            #      nginx.conf 里 http 的闭合括号是缩进的（`  }`），区间同样匹配不上。
            #   3. `i\` 文本里的 `\n` 和 `*.conf` 的 `*` 都没有按字面处理。
            #
            # 改用 awk 按花括号配平定位 http 的闭合位置，并且自带「已经插过就
            # 不插」的判断 —— 不依赖调用方的 grep 守卫，写成幂等操作。
            # 幂等与嵌套子块（http 里有 server{}）均在 .224 上实测通过。
            if awk '
                function bal(s,   t) { t = s; return gsub(/\{/, "{", t) - gsub(/\}/, "}", t) }
                /^[[:space:]]*http[[:space:]]*\{/ { inhttp = 1; has = 0; depth = 0 }
                {
                    if (inhttp && $0 ~ /^[[:space:]]*include[^#]*conf\.d\/\*\.conf/) has = 1
                    if (inhttp && !has && depth + bal($0) <= 0) { print "    include conf.d/*.conf;"; has = 1 }
                    print
                    if (inhttp) depth += bal($0)
                }
            ' "$nginx_conf" > "$nginx_conf.nftweb.tmp" 2>/dev/null && mv "$nginx_conf.nftweb.tmp" "$nginx_conf"; then
                if grep -q "include.*conf\.d/\*\.conf" "$nginx_conf" 2>/dev/null; then
                    ok "已添加 include conf.d/*.conf 到主配置"
                else
                    warn "自动插入后仍未找到 include conf.d/*.conf，请手动在 http 块内添加"
                fi
            else
                warn "自动插入 include 失败，请手动在 http 块内添加: include conf.d/*.conf;"
            fi
        fi
    else
        # 主配置不存在，写入最小配置
        cat > "$nginx_conf" <<'NGINX'
worker_processes auto;

events {
    worker_connections 512;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile      on;
    keepalive_timeout 65;
    server_tokens off;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml;
    gzip_min_length 256;

    include conf.d/*.conf;
}
NGINX
        ok "已生成最小 nginx.conf"
    fi

    # 4b. 写入站点配置（conf.d/nftables-web.conf）
    if [ -f "$site_conf" ]; then
        if head -1 "$site_conf" | grep -q "nftables-web-v2 setup.sh"; then
            info "站点配置已存在（由本脚本管理），将更新"
        else
            warn "站点配置 ${site_conf} 已存在但非本脚本管理，跳过覆盖"
            warn "如需覆盖，请手动删除该文件后重新运行"
            return
        fi
    fi

    # 默认不写 nginx 站点配置。原因：
    #  1. 面板本体直连 HTTPS 5443，自带证书，不经过 nginx；
    #  2. 这里写的 `listen 80 default_server` 会抢占 80 端口的默认站点，
    #     和面板自己管理的反代规则（面板也监听 80）冲突，nginx 会因
    #     duplicate default server 起不来；
    #  3. v0.8.0 已移除后端的 HTTP 5000 跳转器（它自 10-01 起就被
    #     防火墙 policy drop 拦住，实际不可达），没有需要被 proxy_pass 的目标。
    # 反代站点请在面板「反向代理」里配置，由面板自己生成 /etc/nginx/conf.d/*.conf。
    cat > "$site_conf" <<'SITECONF'
# Managed by nftables-web-v2 setup.sh
# 面板本身不需要 nginx 站点；反代请在 Web 面板「反向代理」中配置。
# 本文件保留为空 server 块以避免 nginx 缺少默认站点报错。
server {
    listen 127.0.0.1:8080;
    server_name _;
    return 404;
}
SITECONF

    # OpenWrt 上真正被 nginx 跑起来的是 uci.conf（procd 从 uci.conf.template
    # + UCI 配置生成到 /var/lib/nginx/uci.conf，/etc/nginx/uci.conf 是它的软链），
    # 它并不被 /etc/nginx/nginx.conf include。只 `nginx -t` 校验 nginx.conf
    # 等于校验了一份没人跑的配置，真出语法错时这里照样「通过」。
    #
    # ⚠️ 必须传软链路径 /etc/nginx/uci.conf，不能传 /var/lib/nginx/uci.conf。
    # nginx 解析配置里的相对 include 时，用的是 -c 参数的**字面目录**做 prefix，
    # uci.conf 第 21 行的 `include mime.types;` 因此会去 /etc/nginx/ 找。
    # 传 realpath 会报 "open() /var/lib/nginx/mime.types failed" 而假报语法错误。
    # （已实测：软链路径 exit 0，realpath 路径 exit 1）
    if nginx -t >/dev/null 2>&1; then
        /etc/init.d/nginx restart 2>/dev/null || true
        # restart 会重新生成 uci.conf，这时才校验真正生效的那份
        if [ -f /etc/nginx/uci.conf ]; then
            if nginx -t -c /etc/nginx/uci.conf >/dev/null 2>&1; then
                ok "✅ nginx 配置校验通过（面板直连 5443，反代在面板内配置）"
            else
                warn "❌ 运行时配置 /etc/nginx/uci.conf 有语法错误，请执行: nginx -t -c /etc/nginx/uci.conf"
            fi
        else
            ok "✅ nginx 配置校验通过（面板直连 5443，反代在面板内配置）"
        fi
    else
        warn "❌ nginx 配置语法错误，请手动检查（未重启 nginx）"
    fi

    # 80/443 被 uhttpd 占着是 OpenWrt 常态。网关默认 8443 不会撞，
    # 但用户把公网端口自定义成 443 时，nginx 会因 bind 失败进入崩溃循环。
    # 这里不自动停 uhttpd（停了会失去 LuCI 管理界面，得由用户自己决定），
    # 只把这件事在安装阶段就讲清楚。
    warn_port_conflicts
}

# ============================================================
# 80/443 端口占用提示
# ============================================================
warn_port_conflicts() {
    command -v netstat >/dev/null 2>&1 || return 0

    local busy=""
    for p in 80 443; do
        if netstat -tln 2>/dev/null | grep -qE ":${p}[[:space:]].*LISTEN"; then
            busy="${busy} ${p}"
        fi
    done

    if [ -n "$busy" ]; then
        info "注意：端口${busy} 已被其他服务占用（通常是 uhttpd / LuCI）。"
        info "  · 网关默认端口 8443，不受影响，可直接使用；"
        info "  · 若你打算把公网端口改成 443，必须先自行处理占用者，例如："
        info "      /etc/init.d/uhttpd disable && /etc/init.d/uhttpd stop"
        info "    （这会关闭 LuCI 管理界面，请确认你还留着 SSH 或其他管理入口。）"
    fi
}

# ============================================================
# 5. 项目部署
# ============================================================
deploy_project() {
    info "========== 部署项目 =========="

    # 检查目标目录是否已存在且非空
    if [ -d "$INSTALL_DIR" ] && [ "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ] && [ "$ARG_FORCE" -ne 1 ]; then
        if is_interactive; then
            echo -e "${YELLOW}目标目录 ${INSTALL_DIR} 已存在且非空。${NC}"
            printf "是否覆盖？[y/N] "
            read -r answer
            case "$answer" in
                y|Y|yes|YES) ;;
                *) warn "跳过项目部署（目标目录已存在）"; return ;;
            esac
        else
            warn "跳过项目部署（目标目录 ${INSTALL_DIR} 已存在且非空，非交互模式）"
            warn "如需覆盖，请使用 --force 参数"
            return
        fi
    fi

    # 优先使用本地路径
    if [ -n "$ARG_LOCAL" ]; then
        info "从本地路径安装: ${ARG_LOCAL}"
        if [ ! -d "${ARG_LOCAL}/backend" ] || [ ! -d "${ARG_LOCAL}/frontend" ]; then
            die "本地路径缺少 backend/ 或 frontend/ 目录"
        fi
        mkdir -p "$INSTALL_DIR"
        cp -r "${ARG_LOCAL}/"* "$INSTALL_DIR/"
        ok "✅ 本地部署完成"
        return
    fi

    # GitHub 安装
    local tag="${ARG_VERSION:-main}"
    local url
    if [ "$tag" = "main" ]; then
        url="https://github.com/${GITHUB_REPO}/archive/refs/heads/main.tar.gz"
    else
        url="https://github.com/${GITHUB_REPO}/archive/refs/tags/${tag}.tar.gz"
    fi
    local tmp_dir
    tmp_dir="$(mktemp -d)"

    info "下载 ${PROJECT_NAME} ${tag} ..."
    if curl --connect-timeout 30 --max-time 300 --retry 2 --retry-delay 3 \
         -fsSL -o "${tmp_dir}/archive.tar.gz" "$url" 2>/dev/null; then

        info "解压..."
        tar -xzf "${tmp_dir}/archive.tar.gz" -C "$tmp_dir"

        mkdir -p "$INSTALL_DIR"
        # 查找解压后的项目目录（可能是 ghost-firewall-{tag} 或 ghost-firewall-{tag#v}）
        local src_dir=""
        for candidate in "ghost-firewall-${tag#v}" "ghost-firewall-${tag}" "ghost-firewall-main"; do
            if [ -d "${tmp_dir}/${candidate}" ]; then
                src_dir="${tmp_dir}/${candidate}"
                break
            fi
        done
        # 如果精确匹配失败，取 tmp_dir 下唯一的子目录
        if [ -z "$src_dir" ]; then
            src_dir="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d | head -1)"
        fi
        if [ -n "$src_dir" ] && [ -d "$src_dir" ]; then
            cp -r "${src_dir}/." "$INSTALL_DIR/"
        else
            error "解压后未找到项目目录"
            rm -rf "$tmp_dir"
            return 1
        fi

        rm -rf "$tmp_dir"
        ok "✅ 项目部署完成 (${tag})"
    else
        rm -rf "$tmp_dir"
        error "从 GitHub 下载失败（仓库可能尚未公开或版本不存在）"
        error "下载 URL: ${url}"
        error "错误详情：请检查网络连接或确认版本 ${tag} 是否存在"
        warn "请使用 --local <path> 从本地安装"
        die "❌ 无法获取项目文件"
    fi
}

# ============================================================
# 6. 初始化配置
# ============================================================
init_config() {
    info "========== 初始化配置 =========="

    mkdir -p "$CONFIG_DIR"

    if [ -f "$CONFIG_FILE" ]; then
        ok "配置文件已存在，跳过: ${CONFIG_FILE}"
        return
    fi

    # init_config 在 setup_nftables 之前运行，需要自行检测接口
    if [ -z "$LAN_IFACE" ]; then
        LAN_IFACE="$(uci -q get network.lan.device 2>/dev/null || uci -q get network.lan.ifname 2>/dev/null || echo 'br-lan')"
    fi
    if [ -z "$WAN_IFACE" ]; then
        local wan_proto
        wan_proto="$(uci -q get network.wan.proto 2>/dev/null || true)"
        if [ "$wan_proto" = "pppoe" ]; then
            WAN_IFACE="pppoe-wan"
        elif [ -n "$wan_proto" ]; then
            WAN_IFACE="$(uci -q get network.wan.device 2>/dev/null || uci -q get network.wan.ifname 2>/dev/null || echo 'eth0')"
        else
            WAN_IFACE="pppoe-wan"  # 默认 pppoe
        fi
    fi

    local lan_subnet4 broadcast4 router_ip4 trusted_ip4 trusted_ip6
    local lan_broadcast4 lan_host4
    lan_subnet4="" broadcast4="" router_ip4=""
    lan_broadcast4="" lan_host4=""

    # 掩码必须带、必须是单值 —— 两个都会直接决定防火墙的放行范围。
    # 详见 detect_lan_ipv4() 的注释（旧实现为什么是部署级阻断）。
    #
    # 注意变量名对不上是故意的：探测函数产出 lan_broadcast4/lan_host4，
    # 这里再映射到 init_config 用的 broadcast4/router_ip4 —— 不能直接
    # 依赖 eval 出来的名字，否则两者一改名就静默退化成下面的兜底值。
    eval "$(detect_lan_ipv4 "$LAN_IFACE")"
    broadcast4="$lan_broadcast4"
    router_ip4="$lan_host4"

    # 兜底：探测失败时用 OpenWrt 默认网段。
    # 兜底值一律带掩码 —— 无掩码会被 _safe_cidr 归一成 /32，
    # 让 public=false 的反代只对 1 个地址开放。
    [ -z "$lan_subnet4" ] && lan_subnet4="${LAN_SUBNET4_FALLBACK:-192.168.1.0/24}"
    if [ -z "$broadcast4" ]; then
        # 按掩码算广播，不能用 "${x%.*}.255"（只对 /24 成立）
        broadcast4="$(detect_lan_broadcast4 "$lan_subnet4")"
    fi
    [ -z "$broadcast4" ] && broadcast4="${lan_subnet4%/*}"'.255'
    if [ -z "$router_ip4" ]; then
        # 网关地址：网络地址 + 1（192.168.1.0/24 → 192.168.1.1）
        router_ip4="$(detect_lan_ipv4_gateway "$lan_subnet4")"
    fi
    [ -z "$router_ip4" ] && router_ip4="192.168.1.1"

    # 自动检测信任 IP（LAN 网关 IP）
    trusted_ip4="$router_ip4"

    # 自动检测 IPv6 信任 IP（ULA 前缀或 LAN IPv6 地址）
    trusted_ip6="$(ip -6 addr show "$LAN_IFACE" 2>/dev/null | grep 'inet6.*fd' | awk '{print $2}' | head -1 | cut -d/ -f1 || echo '')"

    # 自动检测 IPv6 前缀
    local wan_prefix6 ula_prefix6
    wan_prefix6="$(ip -6 addr show "$WAN_IFACE" 2>/dev/null | grep 'inet6.*global' | awk '{print $2}' | head -1 | cut -d/ -f1)"
    ula_prefix6="$(ip -6 addr show "$LAN_IFACE" 2>/dev/null | grep 'inet6.*fd' | awk '{print $2}' | head -1 | cut -d/ -f1 || echo '')"

    # 随机端口敲门
    local k1=$((RANDOM % 50000 + 10000))
    local k2=$((RANDOM % 50000 + 10000))
    local k3=$((RANDOM % 50000 + 10000))
    local k4=$((RANDOM % 50000 + 10000))

    # 注意：下面的 heredoc 是未加引号的 <<EOF（需要 ${} 展开），
    # 所以 heredoc 内部绝对不能出现 # 注释行 —— 它们会被原样写进 JSON 文件，
    # 导致配置变成非法 JSON；load_config() 会判定损坏、删掉原文件并静默回退
    # DEFAULT_CONFIG（敲门端口退回 1/2/3/4、trusted_ip4 变成错的值）。
    # 需要解释的字段请写在这里（heredoc 之外）。
    #
    #   access_mode      只有 "lan"（LAN 全放行）和 "trusted"（LAN 默认丢包）两个合法值。
    #                     早前这里写的是 "knock"，一个从未实现的模式，会让模板走 trusted
    #                     分支，装完 LAN 默认全丢包，除白名单外谁都打不开面板。
    #   lan_allowed_ports 放行面板真实监听的 HTTPS 端口 5443。
    #                     v0.8.0 已删除后端的 5000 跳转器（它自 10-01 起就被
    #                     policy drop 拦住，从未可达），面板现在只有 5443 一个入口。
    #   trusted_ip4/6     用数组形式，与后端 _ip_set() 兼容。
    cat > "$CONFIG_FILE" <<EOF
{
    "wan_if": "${WAN_IFACE}",
    "lan_if": "${LAN_IFACE}",
    "router_ip4": "${router_ip4}",
    "router_ip6": "",
    "knock1_port": ${k1},
    "knock2_port": ${k2},
    "knock3_port": ${k3},
    "knock4_port": ${k4},
    "whitelist_timeout": 3600,
    "forward_rules": [],
    "trusted_ip4": ["${trusted_ip4}"],
    "trusted_ip6": ["${trusted_ip6}"],
    "foreign_scan_log": false,
    "ipv6_wan_lan_log": false,
    "wan_drop_log": false,
    "lan_drop_log": false,
    "forward_log": false,
    "lan_subnet4": "${lan_subnet4}",
    "lan_broadcast4": "${broadcast4}",
    "ula_prefix6": "${ula_prefix6}",
    "wan_prefix6": "${wan_prefix6}",
    "access_mode": "lan",
    "lan_allowed_ports": [22, 5443],
    "china_ip_block": false,
    "reverse_proxy": {
        "rules": [],
        "certificates": [],
        "settings": {
            "http_redirect_enabled": true,
            "hsts_enabled": true,
            "tls_min_version": "TLSv1.2",
            "auto_reload_nginx": true
        }
    }
}
EOF

    chmod 600 "$CONFIG_FILE"
    ok "✅ 配置文件已生成: ${CONFIG_FILE}"
    echo -e "${YELLOW}  访问地址: https://${router_ip4}:5443  （HTTPS，自签证书需手动信任）${NC}"
    echo -e "${YELLOW}  注意: 面板仅局域网可达，公网入口尚未启用${NC}"
    echo -e "${YELLOW}  安全模式: 端口敲门（${k1}-${k2}-${k3}-${k4}）${NC}"
    echo -e "${YELLOW}  请登录后修改敲门端口！${NC}"
}

# ============================================================
# 7. init.d 服务
# ============================================================
ensure_ubus() {
    if ! ubus list >/dev/null 2>&1; then
        warn "ubus 不可用，尝试启动 ubusd..."
        ubusd 2>/dev/null
        sleep 1
        if ! ubus list >/dev/null 2>&1; then
            warn "ubus 仍不可用，init.d 服务可能无法正常工作"
        else
            ok "ubusd 已启动"
        fi
    fi
}

# ============================================================
setup_service() {
    info "========== 配置服务 =========="

    if [ -f "$INITD_SCRIPT" ]; then
        ok "服务脚本已存在: ${INITD_SCRIPT}"
    else
        local init_src="${INSTALL_DIR}/backend/nftables-web.init"
        if [ -f "$init_src" ]; then
            cp "$init_src" "$INITD_SCRIPT"
            chmod 755 "$INITD_SCRIPT"
            ok "服务脚本已创建: ${INITD_SCRIPT}"
        else
            warn "源脚本不存在: ${init_src}，跳过"
        fi
    fi

    # ── 认证服务（进程 B，v0.8.0+）────────────────────────────
    # 独立进程、独立 init、独立配置，只监听 127.0.0.1。
    # 没装起来不会影响面板，但网关会因此 502 —— 所以要显式提示。
    local auth_init="${INSTALL_DIR}/backend/nftables-web-auth.init"
    local auth_initd="/etc/init.d/nftables-web-auth"
    if [ -f "$auth_init" ]; then
        cp -f "$auth_init" "$auth_initd"
        chmod 755 "$auth_initd"
        /etc/init.d/nftables-web-auth enable 2>/dev/null
        if /etc/init.d/nftables-web-auth restart >/dev/null 2>&1; then
            ok "认证服务已启动（127.0.0.1，公网不可达）"
        else
            warn "❌ 认证服务启动失败 —— 网关将全部 502，请检查 /var/log/nftables-web-auth-gateway.log"
        fi
    else
        warn "未找到 auth.init，跳过认证服务安装"
    fi

    /etc/init.d/nftables-web enable 2>/dev/null && ok "开机自启已启用"
    /etc/init.d/nftables-web restart 2>/dev/null && ok "✅ 服务已启动" || warn "❌ 服务启动失败，请检查日志"
}

# ============================================================
# 8. nftables 基础配置（自动检测接口）
# ============================================================
setup_nftables() {
    info "========== nftables 基础配置 =========="

    if [ -f "$NFTABLES_CONF" ]; then
        ok "nftables 配置已存在，跳过: ${NFTABLES_CONF}"
        return
    fi

    # 自动检测网络接口
    # PPPoE 拨号时必须用 pppoe-wan 虚拟接口，不能用物理接口
    local wan_proto
    wan_proto="$(uci -q get network.wan.proto 2>/dev/null || true)"
    if [ "$wan_proto" = "pppoe" ]; then
        WAN_IFACE="pppoe-wan"
    else
        WAN_IFACE="$(uci -q get network.wan.device 2>/dev/null || uci -q get network.wan.ifname 2>/dev/null || echo 'eth0')"
    fi
    LAN_IFACE="$(uci -q get network.lan.device 2>/dev/null || uci -q get network.lan.ifname 2>/dev/null || echo 'br-lan')"

    info "检测到 WAN 接口: ${WAN_IFACE}"
    info "检测到 LAN 接口: ${LAN_IFACE}"

    mkdir -p "$(dirname "$NFTABLES_CONF")"

    cat > "$NFTABLES_CONF" <<NFT
#!/usr/sbin/nft -f

# nftables-web-v2 引导配置
# 由 setup.sh 自动生成
#
# 这是一份「安装过渡期兜底」规则，不是最终防火墙：
# 装好之后由 /etc/nftables.d/99-custom-rules.nft（面板生成）接管整表。
#
# 两条硬约束，改动前务必理解：
# 1. 绝不能写 \`flush ruleset\` —— 会清空 fw4 正在生效的 table inet fw4，
#    造成装机瞬间路由器无防火墙。
# 2. 绝不能出现无 \`iifname\` 限制的 \`dport ... accept\` —— 那样等于把
#    SSH(22) 和管理面板对公网全开，与本项目「端口敲门才能放行」的设计矛盾。

define LAN_IFACE = ${LAN_IFACE}
define WAN_IFACE = ${WAN_IFACE}

table inet filter {
    # 服务端口集合（仅供排查参考，input 链不按此放行 WAN 流量）
    set tcp_services {
        type inet_service
        elements = { 22, 5443 }
    }

    set udp_services {
        type inet_service
        elements = { 53, 67, 68 }
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # 允许已建立的连接
        ct state established,related accept

        # 允许环回接口
        iif lo accept

        # 允许 ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # 允许 LAN（含 LAN 侧的 SSH 22 / 面板 5443 / DHCP / DNS）
        iifname \$LAN_IFACE accept

        # 注意：这里刻意不写 \`tcp dport @tcp_services accept\`。
        # LAN 已由上一行全放行，这条规则唯一的作用就是把 22/5443 暴露到 WAN。
        # WAN 侧只保留 established/related，公网服务一律由面板的敲门规则处理。

        # 记录并丢弃其他
        log prefix "[nftables DROP] " drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;

        ct state established,related accept
        iifname \$LAN_IFACE accept
        log prefix "[nftables FWD DROP] " drop
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}

# NAT
table nat {
    chain prerouting {
        type nat hook prerouting priority dstnat;
    }

    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname \$WAN_IFACE masquerade
    }
}
NFT

    chmod 644 "$NFTABLES_CONF"
    ok "nftables 引导配置已生成: ${NFTABLES_CONF}"

    # 尝试加载规则（用 -c 先预检语法，避免半截规则生效）
    if nft -c -f "$NFTABLES_CONF" 2>/dev/null; then
        if nft -f "$NFTABLES_CONF" 2>/dev/null; then
            ok "✅ nftables 引导规则已加载"
        else
            warn "❌ nftables 引导规则加载失败，fw4 仍在生效（未受影响）"
        fi
    else
        warn "❌ 引导规则语法错误，已跳过加载，fw4 仍正常生效"
    fi
}

# ============================================================
# 8b. 关闭 LuCI 的 80/443
#
# 80/443 属于 OpenWrt 自带的 LuCI（nginx._lan / nginx._redirect2ssl），
# 不是本项目的反代 —— 本项目在 8443。个人宽带用不上 LuCI，部署时直接关掉，
# 公网上就少两个监听口。之后仍可在面板里随时打开（配置项 luci_enabled）。
#
# 三个关键点（.224 真机踩出来的）：
#   1. 这个 uci-nginx 不认 section 里的 enabled 选项，只能整段摘掉
#   2. /etc/nginx/uci.conf 是软链到 /var/lib/nginx/uci.conf，
#      重新渲染要删**目标**，删软链会让 nginx_init 判假并静默回落到
#      /etc/nginx/nginx.conf
#   3. 本项目网关的 8443 走 conf.d/*.conf（模板里无条件 include），
#      与 LuCI 无关；关完必须确认 8443 还在听，否则立刻还原
# ============================================================
close_luci_ports() {
    local conf="/etc/config/nginx"
    local rendered="/var/lib/nginx/uci.conf"

    # ── uhttpd 版 LuCI（OpenWrt 24.10+ / 25.12）──────────────
    #
    # 2026-10-20 在 .166（OpenWrt 25.12.5）实测：LuCI **不再由 nginx 提供**，
    # 而是由 **uhttpd** 提供，80/443 全被 uhttpd 占着；
    # /etc/config/nginx 里**根本没有** _lan / _redirect2ssl 段。
    #
    # ⇒ 下面那段「grep 不到 _lan ⇒ 本来就未启用」在这台机器上是**假的成功**：
    # 它会打印「LuCI 80/443 本来就未启用」然后返回 0，
    # 而 uhttpd 正开着 80/443，LuCI 界面照常能访问。
    #
    # 开关点（实测自 /etc/init.d/uhttpd）：
    #     config_get_bool enabled "$cfg" 'enabled' 1
    #     [ $enabled -gt 0 ] || return
    # ⇒ enabled=0 + commit 之后 uhttpd 开机也不起；再 stop 掉当前实例。
    local uhconf="/etc/config/uhttpd"
    if [ -f "$uhconf" ] && grep -q "/cgi-bin/luci" "$uhconf" 2>/dev/null; then
        info "检测到 uhttpd 版 LuCI（$uhconf 里有 /cgi-bin/luci）"
        if uci set uhttpd.main.enabled=0 2>/dev/null && uci commit uhttpd 2>/dev/null; then
            /etc/init.d/uhttpd stop >/dev/null 2>&1
            sleep 1
            # 复核：端口还在就是没关掉，不能报成功
            if netstat -tln 2>/dev/null | grep -qE ':80[[:space:]]|:443[[:space:]]'; then
                warn "⚠️ uhttpd 已停但 80/443 仍在监听，LuCI 未真正关闭"
            else
                ok "✅ LuCI 80/443 已关闭（uhttpd 已停，且开机不再启动）"
            fi
        else
            warn "⚠️ 改 uhttpd.main.enabled 失败，LuCI 80/443 未关闭"
        fi
    fi

    if [ ! -f "$conf" ]; then
        warn "⚠️ 找不到 $conf，跳过关闭 LuCI 80/443"
        return 0
    fi
    if ! grep -q "config server '_lan'\|config server '_redirect2ssl'" "$conf" 2>/dev/null; then
        ok "LuCI 80/443 本来就未启用"
        return 0
    fi

    # 留一份原始配置，供面板上「重新打开 LuCI」时还原
    local snap="/etc/nftables/nginx-luci.snapshot"
    mkdir -p /etc/nftables
    [ -f "$snap" ] || cp "$conf" "$snap" && chmod 600 "$snap"

    # 摘掉两个 section 整块（config 行是块首，遇到下一个 config 行即结束）
    awk '
        /^[[:space:]]*config[[:space:]]/ {
            n=$3
            gsub(/'"'"'/, "", n)
            skip = (n == "_lan" || n == "_redirect2ssl")
        }
        !skip { print }
    ' "$conf" > "$conf.nftweb.tmp" || { warn "⚠️ 生成临时配置失败，LuCI 未改动"; return 0; }
    mv "$conf.nftweb.tmp" "$conf"

    # 重新渲染：删的是渲染产物的目标，不是软链本身
    [ -f "$rendered" ] && rm -f "$rendered"
    if command -v nginx-util >/dev/null 2>&1; then
        nginx-util init_lan >/dev/null 2>&1
    fi
    if nginx -t -c /etc/nginx/uci.conf -g "daemon off;" >/dev/null 2>&1; then
        /etc/init.d/nginx reload >/dev/null 2>&1
        sleep 1
        ok "✅ LuCI 80/443 已关闭（需要时可在面板里重新打开）"
    else
        warn "❌ nginx 配置校验失败，已保持原 LuCI 配置"
        [ -f "$snap" ] && cp "$snap" "$conf"
    fi

    # 兜底：网关端口是本项目唯一的公网入口，绝不能被一起带下去。
    #
    # **只在网关确实启用时才检查**。默认配置 gateway_enabled=false，
    # 此时 8443 本来就没人听，无条件检查会把自己刚关掉的 LuCI 又还原回去 ——
    # 等于「部署后自动关闭 80/443」这个功能在该路径上静默失效。
    #
    # 配置是 JSON 文件（CONFIG_FILE），不是 uci，所以用 python3 读。
    gw_enabled=no
    gw_port=8443
    if [ -f "$CONFIG_FILE" ] && command -v python3 >/dev/null 2>&1; then
        eval "$(python3 - "$CONFIG_FILE" <<'PYEOF'
import json, sys
try:
    c = json.load(open(sys.argv[1]))
except Exception:
    c = {}
print('gw_enabled=%s' % ('yes' if c.get('gateway_enabled') else 'no'))
print('gw_port=%s' % (c.get('gateway_port') or 8443))
PYEOF
)" 2>/dev/null || gw_enabled=no
    fi

    if [ "$gw_enabled" = "yes" ] && [ -f /etc/nginx/conf.d/00-nftables-web-gateway.conf ]; then
        if ! netstat -lnt 2>/dev/null | grep -q ":$gw_port "; then
            warn "❌ 关闭 LuCI 后网关 $gw_port 不在监听 —— 正在自动还原 LuCI"
            cp "$snap" "$conf"
            [ -f "$rendered" ] && rm -f "$rendered"
            command -v nginx-util >/dev/null 2>&1 && nginx-util init_lan >/dev/null 2>&1
            /etc/init.d/nginx reload >/dev/null 2>&1
        fi
    fi
}

# ============================================================
# 9. 完成提示
# ============================================================
show_summary() {
    local ip
    ip="$(ip -4 addr show br-lan 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)"
    [ -z "$ip" ] && ip="$(ip -4 addr show 2>/dev/null | awk '/inet / && !/127.0.0.1/{print $2}' | head -1 | cut -d/ -f1)"

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  ${PROJECT_NAME} 安装完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "  访问地址: ${BLUE}https://${ip}:5443${NC}（自签证书需手动信任）"
    echo -e "  版本:     v${VERSION}"
    echo -e "  配置文件: ${CONFIG_FILE}"
    echo ""
    echo -e "${GREEN}========================================${NC}"
    info "安装日志: ${LOG_FILE}"
}

# ============================================================
# main
# ============================================================
main() {
    parse_args "$@"

    # 初始化日志
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "--- setup.sh started $(date) ---" > "$LOG_FILE"

    echo -e "${BLUE}nftables-web-v2 安装脚本 v${VERSION}${NC}"
    echo ""

    check_env
    install_deps

    # 部署前再次检查空间
    local deploy_avail
    deploy_avail="$(df -k / | awk 'NR==2{print $4}')"
    if [ "$deploy_avail" -lt 5120 ] 2>/dev/null; then
        die "磁盘空间不足，无法部署项目文件（可用: $((deploy_avail/1024))MB，至少需要 5MB）"
    fi

    install_acme
    setup_nginx
    deploy_project
    init_config
    ensure_ubus
    setup_service
    setup_nftables
    close_luci_ports
    show_summary

    ok "✅ 全部完成！"
}

main "$@"
