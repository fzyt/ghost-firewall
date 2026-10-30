#!/usr/bin/env bash
# =============================================================================
# nftables-web-v2 一键部署（开发机执行，SSH 驱动 OpenWrt 设备）
#
# 用法:
#   ./tools/deploy.sh --host 192.168.100.233
#   ./tools/deploy.sh --host 192.168.100.233 --apply
#   ./tools/deploy.sh --host 192.168.100.233 --dry-run
#
# 两条路径（自动判定，--fresh 可强制）:
#   upgrade  设备上已经装过 Ghost Firewall → **只换代码**，不动任何用户状态
#   fresh    设备上还没有（或已被重置）→ 走 setup.sh 全新安装
#
# 设计上的几条硬规矩:
#   1. **只覆盖，不删除。** 配置文件、口令、密钥、限流表一个都不碰。
#      （老 redeploy.sh 里的 `rm -rf $APP` 会把「谁能进这台路由器」的
#      凭据一起删掉 —— 那不是清装，那是把门拆了。）
#   2. **换代码 ≠ 生效。** 规则集和 nginx 网关配置都是面板**运行时**生成的，
#      部署代码不会让它们变。想生效要显式 --apply。
#   3. **令牌密钥不能变。** nftables-web-secret 变了 = 所有设备的网关令牌
#      全部作废 = 用户全部要重新登录。部署前后比对 md5，不一致就大声报。
#   4. **不重启路由器。** 只重启本项目的两个服务。
#   5. **失败就回滚。** 备份目录里带一份 restore.sh，任何一步失败自动回滚。
#
# 退出码: 0 = 成功（含自检全过）；1 = 失败（已回滚）；2 = 参数/环境问题
# =============================================================================
set -euo pipefail

# ── 设备侧路径（与产品代码里的常量保持一致）───────────────────────────
APP_DIR="/opt/nftables-web-v2"
CFG_DIR="/etc/nftables"
RULES_FILE="/etc/nftables.d/99-custom-rules.nft"
GW_CONF="/etc/nginx/conf.d/00-nftables-web-gateway.conf"
PANEL_INIT="/etc/init.d/nftables-web"
GW_INIT="/etc/init.d/nftables-web-auth"
PANEL_PID="/var/run/nftables-web.pid"
GW_PID="/var/run/nftables-web-auth.pid"
PANEL_LOG="/var/log/nftables-web.log"
GW_LOG="/var/log/nftables-web-auth-gateway.log"
BACKUP_ROOT="/root/nftables-web-backups"
NFTWEB_USER="nftweb"
PANEL_PORT="5443"
GW_PORT="8443"
AUTH_PORT="8444"

# ── 参数 ─────────────────────────────────────────────────────────────
HOST=""
SSH_USER="root"
SSH_PORT="22"
SSH_IDENTITY="${HOME}/.ssh/id_ed25519"
SRC=""
APPLY=0
FRESH=0
DRY_RUN=0
ASSUME_YES=0
NO_VERIFY=0
KEEP_BACKUPS="5"

# ── 运行时状态 ───────────────────────────────────────────────────────
MODE=""
BACKUP_DIR=""
TS=""
LOCAL_VERSION=""
REMOTE_LAN_ADDR=""
ROLLBACK_DONE=0
IS_OPENWRT=0
HAS_INSTALL=0
FAILED_CHECKS=0
RULE_MD5_BEFORE=""
CRON_COUNT_BEFORE=""
TOKEN_SECRET_MD5_BEFORE=""
CHECK_FAILURES=()

# ── 输出 ─────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    C_BLUE=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""; C_OFF=""
fi

say()  { printf '%s==> %s%s\n' "$C_BLUE" "$*" "$C_OFF"; }
step() { printf '%s    %s%s\n' "$C_DIM" "$*" "$C_OFF"; }
ok()   { printf '%s  ✅ %s%s\n' "$C_GREEN" "$*" "$C_OFF"; }
warn() { printf '%s  ⚠️  %s%s\n' "$C_YELLOW" "$*" "$C_OFF"; }
err()  { printf '%s  ❌ %s%s\n' "$C_RED" "$*" "$C_OFF"; }
die()  { err "$*"; exit 2; }

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

选项:
  --host <ip>        目标设备地址（必填）
  --user <name>      SSH 用户（默认 root）
  --port <n>         SSH 端口（默认 22）
  --identity <file>  SSH 私钥（默认 ~/.ssh/id_ed25519）
  --source <dir>     源码目录（默认本脚本所在的产品目录）
  --apply            部署后**应用**规则集并重新生成 nginx 网关配置
                     （默认不应用：换代码不动线上防火墙行为）
  --fresh            强制走全新安装路径（默认自动判定）
  --dry-run          只打印计划，不动设备
  --yes              不做交互确认
  --no-verify        跳过部署后的自检
  --keep <n>         设备上保留最近几份备份（默认 5，0 = 全留）
EOF
}

# ── 参数解析 ─────────────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --host)      HOST="${2:-}"; shift 2 ;;
            --user)      SSH_USER="${2:-}"; shift 2 ;;
            --port)      SSH_PORT="${2:-}"; shift 2 ;;
            --identity)  SSH_IDENTITY="${2:-}"; shift 2 ;;
            --source)    SRC="${2:-}"; shift 2 ;;
            --apply)     APPLY=1; shift ;;
            --fresh)     FRESH=1; shift ;;
            --dry-run)   DRY_RUN=1; shift ;;
            --yes|-y)    ASSUME_YES=1; shift ;;
            --no-verify) NO_VERIFY=1; shift ;;
            --keep)      KEEP_BACKUPS="${2:-}"; shift 2 ;;
            -h|--help)   usage; exit 0 ;;
            *)           die "未知参数: $1（--help 看用法）" ;;
        esac
    done
    [ -n "$HOST" ] || die "缺少 --host"
    [ -n "$SSH_IDENTITY" ] || die "--identity 不能为空"
    [ -f "$SSH_IDENTITY" ] || die "SSH 私钥不存在: $SSH_IDENTITY"
    case "$KEEP_BACKUPS" in ''|*[!0-9]*) die "--keep 必须是数字" ;; esac

    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -z "$SRC" ]; then
        SRC="$(cd "$SCRIPT_DIR/.." && pwd)"
    fi
    [ -d "$SRC/backend" ] || die "源码目录里没有 backend/: $SRC"
    [ -f "$SRC/VERSION" ] || die "源码目录里没有 VERSION: $SRC"
    LOCAL_VERSION="$(tr -d ' \t\n\r' < "$SRC/VERSION")"
}

SSH_OPTS=()
SSH_TARGET=""

build_ssh_opts() {
    SSH_OPTS=(
        -o BatchMode=yes
        -o StrictHostKeyChecking=accept-new
        -o ConnectTimeout=10
        -o IdentitiesOnly=yes
        -o LogLevel=ERROR
        -p "$SSH_PORT"
        -i "$SSH_IDENTITY"
    )
}

rssh() { ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "$@"; }
# 在设备上跑一段 sh 脚本（stdin）
rsh()  { ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "sh -s"; }

# ── 本地预检 ─────────────────────────────────────────────────────────
precheck_local() {
    say "本地预检"
    local c
    for c in ssh tar gzip md5sum git; do
        command -v "$c" >/dev/null 2>&1 || die "本机缺少命令: $c"
    done
    ok "命令齐全"
    step "源码目录: $SRC"
    step "待部署版本: v$LOCAL_VERSION"
    if git -C "$SRC" rev-parse --git-dir >/dev/null 2>&1; then
        local rev branch dirty
        rev="$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo '?')"
        branch="$(git -C "$SRC" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
        if [ -n "$(git -C "$SRC" status --porcelain 2>/dev/null)" ]; then
            dirty="　⚠️ 工作区有未提交改动"
        else
            dirty=""
        fi
        step "git: ${branch}@${rev}${dirty}"
    fi
}

# ── 阶段 1：连通 + 身份确认 ──────────────────────────────────────────
phase_connect() {
    say "阶段 1/9　连通性与身份确认"
    SSH_TARGET="${SSH_USER}@${HOST}"
    build_ssh_opts

    local uname
    uname="$(rssh 'uname -a' 2>/dev/null)" \
        || die "SSH 不通: ${SSH_TARGET}（端口 $SSH_PORT，密钥 $SSH_IDENTITY）"
    step "$uname"

    if rssh 'test -f /etc/openwrt_release' 2>/dev/null; then
        local desc
        desc="$(rssh 'grep DISTRIB_DESCRIPTION /etc/openwrt_release' 2>/dev/null | cut -d"'" -f2)"
        ok "确认是 OpenWrt: ${desc:-未知}"
        IS_OPENWRT=1
    else
        IS_OPENWRT=0
        warn "不是 OpenWrt —— 只支持 linux_gateway 部署形态，请确认后再继续"
        if [ "$ASSUME_YES" != 1 ] && [ "$DRY_RUN" != 1 ]; then
            confirm "仍然继续？" || die "已取消"
        fi
    fi

    if rssh 'test -d /opt/nftables-web-v2/backend' 2>/dev/null; then
        step "检测到已安装的 Ghost Firewall"
        HAS_INSTALL=1
    else
        step "未检测到已安装的 Ghost Firewall"
        HAS_INSTALL=0
    fi
}

# ── 阶段 2：判定路径 ────────────────────────────────────────────────
phase_detect_mode() {
    say "阶段 2/9　判定部署路径"
    if [ "$FRESH" = 1 ]; then
        MODE="fresh"
    elif [ "$HAS_INSTALL" = 1 ]; then
        MODE="upgrade"
    else
        MODE="fresh"
    fi
    if [ "$MODE" = "fresh" ]; then
        ok "路径：**全新安装**（装依赖 → 生成配置 → 装服务）"
        [ "$IS_OPENWRT" = 1 ] || warn "全新安装依赖 setup.sh，只在 OpenWrt 上可用"
    else
        ok "路径：**升级**（只换代码，不动用户状态、不动线上规则）"
    fi
}

# ── 阶段 3：备份（升级路径）─────────────────────────────────────────
phase_backup() {
    if [ "$MODE" != "upgrade" ]; then
        say "阶段 3/9　备份"
        step "全新安装，无既有状态可备份"
        return 0
    fi
    say "阶段 3/9　备份"

    TS="$(date +%Y%m%d-%H%M%S)"
    BACKUP_DIR="${BACKUP_ROOT}/${TS}"
    if [ "$DRY_RUN" = 1 ]; then
        step "[dry-run] 将备份到 $BACKUP_DIR"
        return 0
    fi

    rssh "mkdir -p '$BACKUP_DIR'" || die "备份目录创建失败"

    # 备份脚本。BK 通过环境变量传进去（heredoc 是 quoted 的，不能直接展开）。
    rssh "BK='$BACKUP_DIR'; export BK; sh -s" <<'EOS' || die "备份过程出错"
set -e
mkdir -p "$BK"

# 代码
[ -d /opt/nftables-web-v2/backend ] && cp -a /opt/nftables-web-v2/backend "$BK/backend" || true
[ -d /opt/nftables-web-v2/frontend ] && cp -a /opt/nftables-web-v2/frontend "$BK/frontend" || true
[ -f /opt/nftables-web-v2/VERSION ] && cp -a /opt/nftables-web-v2/VERSION "$BK/VERSION" || true

# init 脚本
[ -f /etc/init.d/nftables-web ] && cp -a /etc/init.d/nftables-web "$BK/initd-nftables-web" || true
[ -f /etc/init.d/nftables-web-auth ] && cp -a /etc/init.d/nftables-web-auth "$BK/initd-nftables-web-auth" || true

# 用户状态（配置 / 密钥 / 口令 / 限流表）
[ -d /etc/nftables ] && cp -a /etc/nftables "$BK/etc-nftables" || true

# 规则文件 + nginx 网关配置
[ -f /etc/nftables.d/99-custom-rules.nft ] && cp -a /etc/nftables.d/99-custom-rules.nft "$BK/rules-99-custom-rules.nft" || true
[ -f /etc/nginx/conf.d/00-nftables-web-gateway.conf ] && cp -a /etc/nginx/conf.d/00-nftables-web-gateway.conf "$BK/gateway.conf" || true

# 现场快照（只读，用来对比和排查）
nft list ruleset > "$BK/ruleset-active.txt" 2>/dev/null || true
crontab -l > "$BK/crontab.txt" 2>/dev/null || true
uci export > "$BK/uci-export.txt" 2>/dev/null || true

# 关键文件的 md5 清单（部署前后对比用）
: > "$BK/manifest-before.txt"
for f in /etc/nftables/nftables-web-config.json \
         /etc/nftables/nftables-web-secret \
         /etc/nftables/nftables-web-session-secret \
         /etc/nftables/nftables-web-password \
         /etc/nftables.d/99-custom-rules.nft \
         /etc/nginx/conf.d/00-nftables-web-gateway.conf; do
    if [ -f "$f" ]; then md5sum "$f" >> "$BK/manifest-before.txt"; fi
done
echo "已备份 $(wc -l < "$BK/manifest-before.txt") 个关键文件的清单"
EOS

    # 备份完整性校验：代码必须备份到，否则回滚无意义
    if ! rssh "test -d '$BACKUP_DIR/backend'"; then
        die "备份不完整（没有 $BACKUP_DIR/backend），中止 —— 不动设备"
    fi
    ok "已备份到 $BACKUP_DIR"

    # 现场基线（部署后对比）
    RULE_MD5_BEFORE="$(rssh "md5sum '$RULES_FILE' 2>/dev/null | cut -d' ' -f1" || true)"
    # 注意这里内层用单引号：写成 "$(rssh "… || true")" 的话，内层双引号在
    # $( ) 里没配平，bash 会把右括号吞进引号里 → 「寻找匹配的 ) 时遇到了
    # 未预期的 EOF」。这个坑踩过一次。
    CRON_COUNT_BEFORE="$(rssh 'crontab -l 2>/dev/null | grep -c . || true')"
    TOKEN_SECRET_MD5_BEFORE="$(rssh "md5sum '$CFG_DIR/nftables-web-secret' 2>/dev/null | cut -d' ' -f1" || true)"
    step "规则集 md5（部署前）: ${RULE_MD5_BEFORE:-无}"
    step "crontab 条数（部署前）: ${CRON_COUNT_BEFORE:-0}"
    step "令牌密钥 md5（部署前）: ${TOKEN_SECRET_MD5_BEFORE:-无}"

    write_restore_script
}

write_restore_script() {
    # 生成回滚脚本。
    #
    # 注意这里为什么是「heredoc 走 stdin + 单独一条 rssh」：如果把 heredoc
    # 塞进 rssh 的双引号参数里，脚本正文中的 " 会把那个双引号字符串提前闭合，
    # bash 解析直接崩（这个坑踩过一次）。
    # 现在：rssh 跑 `cat > 文件`，正文从 stdin 进去；正文里用 __BK__ 占位，
    # 落盘后再用 sed 把真实路径替换进去。
    rssh "cat > '$BACKUP_DIR/restore.sh'" <<'EOS' || die "回滚脚本生成失败"
#!/bin/sh
# 由 deploy.sh 自动生成 —— 回滚到部署前的状态。
# 用法: sh <备份目录>/restore.sh
set -e
BK='__BK__'

echo '==> 停止服务'
/etc/init.d/nftables-web stop 2>/dev/null || true
/etc/init.d/nftables-web-auth stop 2>/dev/null || true
sleep 1

echo '==> 恢复代码'
if [ -d "$BK/backend" ]; then
    rm -rf /opt/nftables-web-v2/backend
    cp -a "$BK/backend" /opt/nftables-web-v2/backend
fi
if [ -d "$BK/frontend" ]; then
    rm -rf /opt/nftables-web-v2/frontend
    cp -a "$BK/frontend" /opt/nftables-web-v2/frontend
fi
[ -f "$BK/VERSION" ] && cp -a "$BK/VERSION" /opt/nftables-web-v2/VERSION

echo '==> 恢复 init 脚本'
[ -f "$BK/initd-nftables-web" ] && cp -a "$BK/initd-nftables-web" /etc/init.d/nftables-web
[ -f "$BK/initd-nftables-web-auth" ] && cp -a "$BK/initd-nftables-web-auth" /etc/init.d/nftables-web-auth

echo '==> 恢复用户状态（配置 / 密钥 / 口令 / 限流表）'
[ -d "$BK/etc-nftables" ] && cp -a "$BK/etc-nftables/." /etc/nftables/

echo '==> 恢复规则文件与 nginx 配置'
[ -f "$BK/rules-99-custom-rules.nft" ] && cp -a "$BK/rules-99-custom-rules.nft" /etc/nftables.d/99-custom-rules.nft
[ -f "$BK/gateway.conf" ] && cp -a "$BK/gateway.conf" /etc/nginx/conf.d/00-nftables-web-gateway.conf

echo '==> 重启服务'
/etc/init.d/nftables-web start 2>/dev/null || true
/etc/init.d/nftables-web-auth start 2>/dev/null || true
sleep 3

echo '==> 完成。如需强制回滚规则集: nft -f /etc/nftables.d/99-custom-rules.nft'
EOS
    rssh "sed -i 's|__BK__|$BACKUP_DIR|g' '$BACKUP_DIR/restore.sh' && chmod 755 '$BACKUP_DIR/restore.sh'" \
        || die "回滚脚本路径替换失败"
    ok "回滚脚本: $BACKUP_DIR/restore.sh"
}

# ── 阶段 4：传输 ─────────────────────────────────────────────────────
phase_transfer() {
    say "阶段 4/9　传输文件"

    if [ "$MODE" = "fresh" ]; then
        # 全新安装：先传到暂存目录，再由 setup.sh 复制到安装目录。
        # （不能直接传到 $APP_DIR 再让 setup.sh --local $APP_DIR ——
        #   cp -r 同目录会报错，setup.sh 的 set -e 会让它当场死掉。）
        local stage="/tmp/nftables-web-stage"
        step "传到暂存目录 $stage"
        if [ "$DRY_RUN" = 1 ]; then
            step "[dry-run] tar -C $SRC -czf - backend frontend setup VERSION | ssh ... tar -C $stage -xzf -"
            step "[dry-run] sh $stage/setup/setup.sh --local $stage --force"
            return 0
        fi
        rssh "rm -rf '$stage' && mkdir -p '$stage'"
        tar -C "$SRC" -czf - backend frontend setup VERSION \
            | rssh "tar -C '$stage' -xzf -" || die "传输失败"
        ok "已传输到暂存目录"

        say "阶段 4b/9　全新安装（setup.sh）"
        step "setup.sh --local $stage --force"
        rssh "sh '$stage/setup/setup.sh' --local '$stage' --force" \
            || die "setup.sh 失败（详见设备上 /var/log/nftables-web-setup.log）"
        ok "setup.sh 完成"
        return 0
    fi

    # 升级：覆盖代码。frontend/ 也要 —— 面板的 UI 是从 ../frontend 提供的
    # （app.py: send_from_directory('../frontend', 'index.html')），
    # 不是 backend/static/（后者是网关自己的登录页和门户）。
    step "覆盖 backend/ frontend/ VERSION"
    if [ "$DRY_RUN" = 1 ]; then
        step "[dry-run] tar -C $SRC -czf - backend frontend VERSION | ssh ... tar -C $APP_DIR -xzf -"
        return 0
    fi
    rssh "mkdir -p '$APP_DIR'"
    tar -C "$SRC" -czf - backend frontend VERSION \
        | rssh "tar -C '$APP_DIR' -xzf -" || die "传输失败"
    # 清掉可能残留的 __pycache__（旧 .pyc 会让新代码不生效）
    rssh "find '$APP_DIR/backend' -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true"
    ok "代码已覆盖"

    step "安装 init 脚本"
    rssh "cp -f '$APP_DIR/backend/nftables-web.init' '$PANEL_INIT' && chmod 755 '$PANEL_INIT'"
    rssh "cp -f '$APP_DIR/backend/nftables-web-auth.init' '$GW_INIT' && chmod 755 '$GW_INIT'"
    ok "init 脚本已更新"
}

# ── 阶段 5：权限与密钥 ──────────────────────────────────────────────
phase_permissions() {
    say "阶段 5/9　权限与密钥"
    if [ "$DRY_RUN" = 1 ]; then
        step "[dry-run] 校正 /etc/nftables 下各文件的权限"
        return 0
    fi

    # 只在文件**已存在**时改权限 —— 绝不在这里创建文件。
    # 谁负责创建、什么时候创建，是 init 脚本和面板的事。
    rssh "sh -s" <<'EOS' || die "权限校正失败"
set -e
CFG=/etc/nftables
NFTWEB=nftweb

# 面板会话签名密钥：0600 root:root —— 网关读不到（v0.8.7 的 P0-3）
if [ -f "$CFG/nftables-web-session-secret" ]; then
    chown 0:0 "$CFG/nftables-web-session-secret"
    chmod 600 "$CFG/nftables-web-session-secret"
fi
# 网关令牌密钥：0640 root:nftweb —— 只有网关读得到
if [ -f "$CFG/nftables-web-secret" ]; then
    chgrp "$NFTWEB" "$CFG/nftables-web-secret"
    chmod 640 "$CFG/nftables-web-secret"
fi
# 共享配置：0640 root:nftweb —— 网关要读（dns_credentials 是它的一部分）
if [ -f "$CFG/nftables-web-config.json" ]; then
    chgrp "$NFTWEB" "$CFG/nftables-web-config.json"
    chmod 640 "$CFG/nftables-web-config.json"
fi
# 口令哈希：0640 root:nftweb —— 网关要读
if [ -f "$CFG/nftables-web-password" ]; then
    chgrp "$NFTWEB" "$CFG/nftables-web-password"
    chmod 640 "$CFG/nftables-web-password"
fi
# 目录 setgid：新文件默认组跟目录走
if [ -d "$CFG" ]; then
    chgrp "$NFTWEB" "$CFG"
    chmod g+s "$CFG"
fi
true
EOS
    ok "权限已校正（session-secret 600 root:root；secret/config/password 640 root:nftweb）"

    # 令牌密钥必须没变
    local after
    after="$(rssh "md5sum '$CFG_DIR/nftables-web-secret' 2>/dev/null | cut -d' ' -f1" || true)"
    if [ -n "$TOKEN_SECRET_MD5_BEFORE" ] && [ -n "$after" ]; then
        if [ "$after" = "$TOKEN_SECRET_MD5_BEFORE" ]; then
            ok "令牌密钥未变（网关令牌仍然有效，用户不用重新登录）"
        else
            warn "令牌密钥变了！所有设备的网关令牌已作废，用户需要重新登录一次"
        fi
    fi
}

# ── 阶段 6：语法预检 ────────────────────────────────────────────────
phase_precheck() {
    say "阶段 6/9　语法预检（动服务之前）"
    if [ "$DRY_RUN" = 1 ]; then
        step "[dry-run] sh -n init 脚本 / python import / nft -c -f 规则集"
        return 0
    fi

    rssh "sh -n '$PANEL_INIT'" || die "面板 init 脚本语法错误"
    rssh "sh -n '$GW_INIT'" || die "网关 init 脚本语法错误"
    ok "两个 init 脚本语法正确"

    rssh "cd '$APP_DIR/backend' && python3 -c 'import app'" \
        || die "app.py import 失败（语法错误或缺依赖）"
    rssh "cd '$APP_DIR/backend' && python3 -c 'import auth_gateway'" \
        || die "auth_gateway.py import 失败（语法错误或缺依赖）"
    ok "两个 Python 模块都能 import"

    # 规则集语法预检：只 check，不 apply。
    # `nft -c -f` 是 --check，不真正加载；但它会解析整个文件，
    # 所以语法错、hook 冲突、表不存在这些都能提前抓到。
    rssh "sh -s" <<'EOS' || die "规则集语法预检失败 —— 中止，不动现有服务"
set -e
cd /opt/nftables-web-v2/backend
python3 - <<'PYEOF'
import app
cfg = app.load_config()
r = app.build_rules(cfg)
open('/tmp/precheck.nft', 'w').write(r)
print('生成规则行数:', len(r.splitlines()))
PYEOF
nft -c -f /tmp/precheck.nft
echo "nft -c 通过"
rm -f /tmp/precheck.nft
EOS
    ok "规则集语法预检通过（nft -c -f，未实际加载）"
}

# ── 阶段 7：重启服务 ────────────────────────────────────────────────
phase_restart() {
    say "阶段 7/9　重启服务"
    if [ "$DRY_RUN" = 1 ]; then
        step "[dry-run] $PANEL_INIT restart; $GW_INIT restart"
        return 0
    fi
    rssh "'$PANEL_INIT' restart" || warn "面板重启返回非零（看 $PANEL_LOG）"
    rssh "'$GW_INIT' restart" || warn "网关重启返回非零（看 $GW_LOG）"

    # 等端口（带退避，别一上去就判失败）
    local i
    for i in $(seq 1 20); do
        if rssh "netstat -tln 2>/dev/null | grep -q ':${AUTH_PORT} '"; then
            break
        fi
        sleep 1
    done
    ok "服务已重启"
}

# ── 阶段 8：应用（可选）─────────────────────────────────────────────
phase_apply() {
    say "阶段 8/9　应用规则集 + 重新生成 nginx 网关配置"
    if [ "$DRY_RUN" = 1 ]; then
        step "[dry-run] python3 -c 'app._deploy_all_rules(); app._deploy_gateway_nginx()'"
        return 0
    fi
    rssh "sh -s" <<'EOS' || die "应用失败（规则集/nginx 配置可能处于半更新状态，用备份回滚）"
set -e
cd /opt/nftables-web-v2/backend
python3 - <<'PYEOF'
import app
cfg = app.load_config()
ok1, msg1 = app._deploy_all_rules(cfg)
print('规则集:', ok1, msg1)
ok2, msg2 = app._deploy_gateway_nginx(cfg)
print('nginx 网关配置:', ok2, msg2)
if not ok1:
    raise SystemExit('规则集应用失败')
if not ok2:
    raise SystemExit('nginx 网关配置应用失败')
PYEOF
EOS
    ok "规则集与 nginx 配置已应用"
}

# ── 阶段 9：自检 ────────────────────────────────────────────────────
phase_verify() {
    say "阶段 9/9　部署后自检"
    if [ "$NO_VERIFY" = 1 ]; then
        warn "已按要求跳过自检"
        return 0
    fi
    if [ "$DRY_RUN" = 1 ]; then
        step "[dry-run] 跳过自检"
        return 0
    fi

    # 进程：活着 + uid 正确
    local ppid gpuid ppuid
    ppid="$(rssh "cat '$PANEL_PID' 2>/dev/null" || true)"
    ppuid="$(rssh "awk '/^Uid:/{print \$2; exit}' '/proc/${ppid:-0}/status' 2>/dev/null" || true)"
    check_eq "面板进程在运行且 uid=0（root）" "0" "$ppuid"

    local gpid
    gpid="$(rssh "cat '$GW_PID' 2>/dev/null" || true)"
    gpuid="$(rssh "awk '/^Uid:/{print \$2; exit}' '/proc/${gpid:-0}/status' 2>/dev/null" || true)"
    check_eq "网关进程在运行且 uid=1000（nftweb，降权未丢）" "1000" "$gpuid"

    # 端口
    # 注意：netstat 里一个端口可能有**两行**（IPv4 0.0.0.0 + IPv6 :::），
    # 所以不能用 `grep -c` 的结果去等值比较 —— 得判「>= 1」。
    # （第一版写成 == 1，被自检抓了个正着，然后自动回滚了。）
    local p_listen g_listen a_listen
    p_listen="$(rssh "netstat -tln 2>/dev/null | grep -c ':${PANEL_PORT} '" || true)"
    check_eq "面板端口 ${PANEL_PORT} 在监听" "yes" "$(count_to_yes "$p_listen")"
    g_listen="$(rssh "netstat -tln 2>/dev/null | grep -c ':${GW_PORT} '" || true)"
    check_eq "网关端口 ${GW_PORT} 在监听（nginx）" "yes" "$(count_to_yes "$g_listen")"
    a_listen="$(rssh "netstat -tln 2>/dev/null | grep -c '127.0.0.1:${AUTH_PORT} '" || true)"
    check_eq "认证 API ${AUTH_PORT} 在监听（仅 127.0.0.1）" "yes" "$(count_to_yes "$a_listen")"

    # HTTP：面板绑的是 LAN 地址（不是 127.0.0.1），从监听套接字取地址
    REMOTE_LAN_ADDR="$(rssh "netstat -tln 2>/dev/null | awk '/:${PANEL_PORT} /{print \$4}' | head -1 | sed 's/:${PANEL_PORT}$//'" || true)"
    if [ -n "$REMOTE_LAN_ADDR" ]; then
        step "面板绑定地址: $REMOTE_LAN_ADDR"
        local pcode
        pcode="$(rssh "curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://${REMOTE_LAN_ADDR}:${PANEL_PORT}/" || true)"
        check_eq "面板 HTTPS 返回 200" "200" "$pcode"
    else
        warn "取不到面板绑定地址，跳过面板 HTTP 检查"
    fi

    local gcode acode
    gcode="$(rssh "curl -sk -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:${GW_PORT}/" || true)"
    check_eq "网关 HTTPS 返回 200" "200" "$gcode"
    acode="$(rssh "curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1:${AUTH_PORT}/auth/status" || true)"
    check_eq "认证 API /auth/status 返回 200" "200" "$acode"

    # 权限（busybox ls -l：$1 权限位 $3 属主 $4 属组）
    local perms
    perms="$(rssh "ls -l '$CFG_DIR/nftables-web-session-secret' 2>/dev/null | awk '{print \$1, \$3, \$4}'" || true)"
    check_eq "面板会话密钥 0600 root:root" "-rw------- root root" "$perms"
    perms="$(rssh "ls -l '$CFG_DIR/nftables-web-secret' 2>/dev/null | awk '{print \$1, \$3, \$4}'" || true)"
    check_eq "网关令牌密钥 0640 root:nftweb" "-rw-r----- root nftweb" "$perms"
    perms="$(rssh "ls -l '$CFG_DIR/nftables-web-config.json' 2>/dev/null | awk '{print \$1, \$3, \$4}'" || true)"
    check_eq "共享配置 0640 root:nftweb" "-rw-r----- root nftweb" "$perms"

    # 网关的 gid 必须等于配置文件的组 gid。
    #
    # 这一条不是凑数：网关读不到配置时**不报错**，只是静默回退到默认值
    # （auth_gateway.py 的 load_gateway_config：读失败返回空 dict）。
    # 于是「配置写着 A、网关按 B 跑」—— 现场极难查。
    # 全新安装踩过一次：setup.sh 把配置写成 0600 root:root，
    # 网关一直读不到，用户看到的现象是「配了但没生效」。
    local gwgid cfggrp
    gwgid="$(rssh "awk '/^Gid:/{print \$3; exit}' '/proc/${gpid:-0}/status' 2>/dev/null" || true)"
    cfggrp="$(rssh "ls -ln '$CFG_DIR/nftables-web-config.json' 2>/dev/null | awk '{print \$4}'" || true)"
    check_eq "网关的 gid = 配置文件的组 gid（读得到配置）" "$gwgid" "$cfggrp"

    # 版本号
    local rver
    rver="$(rssh "tr -d ' \t\n\r' < '$APP_DIR/VERSION' 2>/dev/null" || true)"
    check_eq "设备上的版本 = 本地版本 v$LOCAL_VERSION" "$LOCAL_VERSION" "$rver"

    # 全新安装的初始状态：还没设密码（第一次打开面板时设置）
    if [ "$MODE" = "fresh" ]; then
        local pset
        pset="$(rssh "curl -sk --max-time 8 https://127.0.0.1:${AUTH_PORT}/auth/status 2>/dev/null | grep -o '\"password_set\":[a-z]*' | head -1" || true)"
        [ -n "$pset" ] && ok "认证 API 报告面板口令状态: $pset" || warn "拿不到 password_set（网关读不到配置？）"
        if [ -f "$CFG_DIR/nftables-web-password" ]; then
            warn "口令文件已存在 —— 全新装出来却有旧口令？检查一下是不是没真的重置"
        else
            ok "口令文件不存在（全新状态正确，首次打开面板时设置）"
        fi
    fi

    # 旁证：规则集与 crontab 没被动过（升级路径）
    if [ "$MODE" = "upgrade" ]; then
        local rmd5 ccount
        rmd5="$(rssh "md5sum '$RULES_FILE' 2>/dev/null | cut -d' ' -f1" || true)"
        check_eq "规则集文件 md5 未变（没碰线上防火墙）" "$RULE_MD5_BEFORE" "$rmd5"
        ccount="$(rssh "crontab -l 2>/dev/null | grep -c . || true")"
        check_eq "crontab 条数未变" "$CRON_COUNT_BEFORE" "$ccount"
    fi

    if [ "$FAILED_CHECKS" -gt 0 ]; then
        err "自检 ${FAILED_CHECKS} 项不通过："
        local f
        for f in "${CHECK_FAILURES[@]}"; do
            err "    - $f"
        done
        return 1
    fi
    ok "自检全部通过"
}

# 监听条数 → yes/no。一个端口在 netstat 里可能有 IPv4 + IPv6 两行，
# 所以判的是「至少一行」，不是「恰好一行」。
count_to_yes() {
    case "${1:-0}" in
        ''|*[!0-9]*) echo no ;;
        *) if [ "$1" -ge 1 ]; then echo yes; else echo no; fi ;;
    esac
}

# 比较「实际值」与「期望值」，不一致就记进失败清单
check_eq() {
    local desc="$1" expect="$2" got="$3"
    if [ "$got" = "$expect" ]; then
        ok "$desc"
    else
        err "$desc —— 期望 ${expect}，实际 ${got:-无}"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        CHECK_FAILURES+=("$desc（期望 ${expect}，实际 ${got:-无}）")
    fi
}

# ── 收尾 ─────────────────────────────────────────────────────────────
phase_summary() {
    echo
    say "部署完成"
    local panel_addr
    panel_addr="$REMOTE_LAN_ADDR"
    if [ -z "$panel_addr" ]; then
        panel_addr="$(rssh "netstat -tln 2>/dev/null | awk '/:${PANEL_PORT} /{print \$4}' | head -1 | sed 's/:${PANEL_PORT}$//'" || true)"
    fi
    echo "  面板:    https://${panel_addr:-<设备LAN地址>}:${PANEL_PORT}"
    echo "  网关:    https://${HOST}:${GW_PORT}"
    echo "  版本:    v$LOCAL_VERSION"
    if [ -n "$BACKUP_DIR" ]; then
        echo "  备份:    $BACKUP_DIR"
        echo "  回滚:    ssh ${SSH_USER}@${HOST} 'sh $BACKUP_DIR/restore.sh'"
    fi
    if [ "$MODE" = "fresh" ]; then
        echo
        echo "  全新安装还需一步：首次打开面板会要求设置管理员密码"
        echo "    https://${panel_addr:-<设备LAN地址>}:${PANEL_PORT}"
        echo "  公网入口（8443）默认是关的，需要在面板里启用并配置反代规则。"
    elif [ "$APPLY" = 0 ]; then
        echo
        echo "  注意：本次**只换了代码**，线上规则集和 nginx 配置没动。"
        echo "        规则集/网关配置是面板运行时生成的 —— 要让改动生效，"
        echo "        在面板里点「应用」，或下次部署时加 --apply。"
    fi
    echo
}

# 备份轮转：只留最近 N 份
prune_backups() {
    [ "$MODE" = "upgrade" ] || return 0
    [ "$KEEP_BACKUPS" -gt 0 ] || return 0
    [ -n "$BACKUP_DIR" ] || return 0
    rssh "ls -1dt '$BACKUP_ROOT'/*/ 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | while read d; do rm -rf \"\$d\"; done" || true
    step "备份轮转：保留最近 $KEEP_BACKUPS 份"
}

# ── 交互确认 ─────────────────────────────────────────────────────────
confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    [ -t 0 ] || return 0
    printf '  %s [y/N] ' "$1"
    local a
    read -r a || return 1
    case "$a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ── 失败回滚 ─────────────────────────────────────────────────────────
do_rollback() {
    [ "$ROLLBACK_DONE" = 1 ] && return 0
    ROLLBACK_DONE=1
    if [ -z "$BACKUP_DIR" ] || [ "$DRY_RUN" = 1 ]; then
        warn "没有可回滚的备份（失败发生在备份之前，设备未被改动）"
        return 0
    fi
    err "正在回滚：$BACKUP_DIR/restore.sh"
    if rssh "sh '$BACKUP_DIR/restore.sh'" >/dev/null 2>&1; then
        ok "已回滚到部署前状态"
    else
        err "自动回滚失败！请手工执行：ssh ${SSH_USER}@${HOST} 'sh $BACKUP_DIR/restore.sh'"
    fi
}

on_exit() {
    local rc=$?
    if [ "$rc" -ne 0 ] && [ "$ROLLBACK_DONE" = 0 ] && [ -n "$BACKUP_DIR" ] && [ "$MODE" = "upgrade" ]; then
        do_rollback
    fi
    exit "$rc"
}

# ── 主流程 ───────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    precheck_local
    phase_connect
    phase_detect_mode
    phase_backup
    phase_transfer
    phase_permissions
    phase_precheck
    phase_restart
    if [ "$APPLY" = 1 ]; then
        phase_apply
    fi
    phase_verify
    phase_summary
    prune_backups
    trap - EXIT
    exit 0
}

trap on_exit EXIT
main "$@"
