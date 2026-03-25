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
VERSION="0.7.7"
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
    if [ "$avail" -lt 51200 ] 2>/dev/null; then
        die "磁盘空间不足（可用: $((avail/1024))MB，至少需要 50MB）"
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
        nginx-ssl \
        curl openssl-util socat \
        ca-certificates wget-ssl

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

    cat > "$site_conf" <<'SITECONF'
# Managed by nftables-web-v2 setup.sh
# 反向代理到 nftables-web-v2 后端

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # 禁止访问隐藏文件
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTPS server（证书就绪后取消注释）
# server {
#     listen 443 ssl default_server;
#     listen [::]:443 ssl default_server;
#     server_name _;
#
#     ssl_certificate     /etc/nginx/ssl/fullchain.pem;
#     ssl_certificate_key /etc/nginx/ssl/key.pem;
#     ssl_protocols       TLSv1.2 TLSv1.3;
#     ssl_ciphers         HIGH:!aNULL:!MD5;
#     ssl_prefer_server_ciphers on;
#
#     location / {
#         proxy_pass http://127.0.0.1:5000;
#         proxy_set_header Host $host;
#         proxy_set_header X-Real-IP $remote_addr;
#         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#         proxy_set_header X-Forwarded-Proto $scheme;
#     }
# }
SITECONF

    nginx -t 2>/dev/null && {
        /etc/init.d/nginx restart 2>/dev/null || true
        ok "✅ nginx 配置完成"
    } || warn "❌ nginx 配置语法错误，请手动检查"
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
    local tag="${ARG_VERSION:-v${VERSION}}"
    local url="https://github.com/${GITHUB_REPO}/archive/refs/tags/${tag}.tar.gz"
    local tmp_dir
    tmp_dir="$(mktemp -d)"

    info "下载 ${PROJECT_NAME} ${tag} ..."
    if curl --connect-timeout 30 --max-time 300 --retry 2 --retry-delay 3 \
         -fsSL -o "${tmp_dir}/archive.tar.gz" "$url" 2>/dev/null; then

        info "解压..."
        tar -xzf "${tmp_dir}/archive.tar.gz" -C "$tmp_dir"

        mkdir -p "$INSTALL_DIR"
        if [ -d "${tmp_dir}/ghost-firewall-${tag#v}" ]; then
            cp -r "${tmp_dir}/ghost-firewall-${tag#v}/"* "$INSTALL_DIR/"
        elif [ -d "${tmp_dir}/${PROJECT_NAME}-${tag}" ]; then
            cp -r "${tmp_dir}/${PROJECT_NAME}-${tag}/"* "$INSTALL_DIR/"
        else
            cp -r "${tmp_dir}/"* "$INSTALL_DIR/"
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

    local lan_subnet4 broadcast4
    lan_subnet4="$(ip -4 addr show "$LAN_IFACE" 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 | sed 's/\.[0-9]*$/.0/')"
    [ -z "$lan_subnet4" ] && lan_subnet4="192.168.1.0"
    broadcast4="${lan_subnet4%.*}.255"

    local router_ip4
    router_ip4="$(ip -4 addr show "$LAN_IFACE" 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1)"
    [ -z "$router_ip4" ] && router_ip4="192.168.1.1"

    # 自动检测 IPv6 前缀
    local wan_prefix6 ula_prefix6
    wan_prefix6="$(ip -6 addr show "$WAN_IFACE" 2>/dev/null | grep 'inet6.*global' | awk '{print $2}' | head -1 | cut -d/ -f1)"
    ula_prefix6="$(ip -6 addr show "$LAN_IFACE" 2>/dev/null | grep 'inet6.*fd' | awk '{print $2}' | head -1 | cut -d/ -f1 || echo '')"

    # 随机端口敲门
    local k1=$((RANDOM % 50000 + 10000))
    local k2=$((RANDOM % 50000 + 10000))
    local k3=$((RANDOM % 50000 + 10000))
    local k4=$((RANDOM % 50000 + 10000))

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
    "trusted_ip4": [],
    "trusted_ip6": [],
    "foreign_scan_log": false,
    "ipv6_wan_lan_log": false,
    "wan_drop_log": false,
    "lan_drop_log": false,
    "forward_log": false,
    "lan_subnet4": "${lan_subnet4}",
    "lan_broadcast4": "${broadcast4}",
    "ula_prefix6": "${ula_prefix6}",
    "wan_prefix6": "${wan_prefix6}",
    "access_mode": "knock",
    "lan_allowed_ports": [22, 5000],
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
    echo -e "${YELLOW}  访问地址: http://${router_ip4}:5000${NC}"
    echo -e "${YELLOW}  安全模式: 端口敲门（${k1}-${k2}-${k3}-${k4}）${NC}"
    echo -e "${YELLOW}  请登录后修改敲门端口！${NC}"
}

# ============================================================
# 7. init.d 服务
# ============================================================
setup_service() {
    info "========== 配置服务 =========="

    if [ -f "$INITD_SCRIPT" ]; then
        ok "服务脚本已存在: ${INITD_SCRIPT}"
    else
        cat > "$INITD_SCRIPT" <<'INITD'
#!/bin/sh /etc/rc.common

START=99
STOP=10

USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command python3 /opt/nftables-web-v2/backend/app.py
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param workdir /opt/nftables-web-v2/backend
    procd_close_instance
}

stop_service() {
    # procd handles SIGTERM
    :
}
INITD
        chmod 755 "$INITD_SCRIPT"
        ok "服务脚本已创建: ${INITD_SCRIPT}"
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
    wan_proto="$(uci -q get network.wan.proto 2>/dev/null)"
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

# nftables-web-v2 基础配置
# 由 setup.sh 自动生成

flush ruleset

define LAN_IFACE = ${LAN_IFACE}
define WAN_IFACE = ${WAN_IFACE}

table inet filter {
    # 服务端口集合
    set tcp_services {
        type inet_service
        elements = { 22, 80, 443, 5000 }
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

        # 允许 LAN
        iifname \$LAN_IFACE accept

        # 允许指定 TCP 服务
        tcp dport @tcp_services accept

        # 允许指定 UDP 服务
        udp dport @udp_services accept

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
    ok "nftables 配置已生成: ${NFTABLES_CONF}"

    # 尝试加载规则
    nft -f "$NFTABLES_CONF" 2>/dev/null && ok "✅ nftables 规则已加载" \
        || warn "❌ nftables 规则加载失败，请手动检查配置（接口名称可能需要调整）"
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
    echo -e "  访问地址: ${BLUE}http://${ip}:5000${NC}"
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
    install_acme
    setup_nginx
    deploy_project
    init_config
    setup_service
    setup_nftables
    show_summary

    ok "✅ 全部完成！"
}

main "$@"
