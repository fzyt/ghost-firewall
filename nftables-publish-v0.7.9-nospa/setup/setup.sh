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
                apk add "$pkg" || warn "安装失败: ${pkg}"
                ;;
        esac
    done
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

    pkg_update || warn "包列表更新失败，继续尝试安装..."

    pkg_install \
        nftables \
        python3 python3-light python3-requests python3-flask \
        ddns-scripts \
        ddns-scripts-cloudflare ddns-scripts-dnspod \
        ddns-scripts-noip ddns-scripts-nsupdate \
        ddns-scripts-godaddy ddns-scripts-namecheap \
        nginx-full \
        curl openssl-util socat \
        ca-certificates wget-ssl

    # v0.8.0 的单端口认证网关完全建立在 nginx 的 auth_request 之上：
    # 每个公网请求都要先问认证服务「这个人有 token 吗」，没有就 401。
    # OpenWrt 的 nginx-ssl 不含该模块，装它 = 装完看着一切正常，
    # 一开网关就整片 500。所以这里必须用 nginx-full 并当场验模块。
    check_nginx_modules

    # 安装 Python 依赖（pip）
    if ! python3 -c "import blinker" 2>/dev/null; then
        info "安装 Python 依赖: blinker"
        # 确保 pip 可用
        if ! command -v pip3 >/dev/null 2>&1; then
            case "$PKG_MANAGER" in
                opkg) pkg_install python3-pip ;;
                apk) pkg_install python3-pip ;;
            esac
        fi
        pip3 install blinker --break-system-packages 2>/dev/null || pip3 install blinker 2>/dev/null || warn "blinker 安装失败"
    fi

    ok "✅ 依赖安装完成"
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
            # 在 http 块内最后一个 } 之前插入
            if sed -i '/^http {/,/^}/{ /^}/i\    include conf.d/*.conf;\n' "$nginx_conf" 2>/dev/null; then
                ok "已添加 include conf.d/*.conf 到主配置"
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

    local lan_subnet4 broadcast4
    lan_subnet4="$(ip -4 addr show "$LAN_IFACE" 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 | sed 's/\.[0-9]*$/.0/')"
    [ -z "$lan_subnet4" ] && lan_subnet4="192.168.1.0"
    broadcast4="${lan_subnet4%.*}.255"

    local router_ip4 trusted_ip4 trusted_ip6
    router_ip4="$(ip -4 addr show "$LAN_IFACE" 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1)"
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
    show_summary

    ok "✅ 全部完成！"
}

main "$@"
