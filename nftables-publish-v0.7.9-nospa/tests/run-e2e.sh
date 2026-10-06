#!/bin/sh
# e2e 测试环境准备 + 快捷入口
#
# playwright-core 和 Chromium 有几百 MB，绝不能进仓库。本脚本把它装到
# /tmp/nftv2-e2e（跨会话会丢，重跑 setup 即可），测试脚本通过
# PLAYWRIGHT_PATH 指过去。
#
# 用法：
#   bash tests/run-e2e.sh setup     装依赖 + 浏览器（只需一次）
#   bash tests/run-e2e.sh probe     枚举对账（不点击，安全）
#   bash tests/run-e2e.sh click     逐个点击（跳过破坏性和网络级按钮）
#   bash tests/run-e2e.sh all       逐个点击 + 破坏性按钮 + 门户
#   bash tests/run-e2e.sh portal    认证门户全链路
#   bash tests/run-e2e.sh audit     静态按钮清单（无需浏览器）
#
# 三档点击权限，逐级放开：
#   默认           只点无副作用的按钮
#   --destructive  连「删除/清空/应用规则」一起点（会改配置，跑前先备份）
#   --allow-network 连「重启网络/切 PPPoE」一起点 —— 这档会直接把网络搞挂。
#                  2026-10-06 就因此把测试机 192.168.100.224 搞到整机失联
#                  （ARP FAILED）且当时没有带外恢复入口。开之前务必确认
#                  有 Proxmox 控制台 / IPMI / 串口之类能救回来的通道。
#
# 环境变量：
#   E2E_HOST      面板所在主机，默认 192.168.100.224
#   E2E_PASSWORD  面板密码，默认 TestGW2026

set -e
MODULES_DIR="${E2E_MODULES_DIR:-/tmp/nftv2-e2e}"
PW_VERSION="1.49.0"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

setup() {
    info "准备 e2e 依赖 -> ${MODULES_DIR}"
    mkdir -p "$MODULES_DIR"
    cd "$MODULES_DIR"
    [ -f package.json ] || npm init -y >/dev/null 2>&1
    npm config set registry https://registry.npmmirror.com >/dev/null 2>&1 || true
    info "安装 playwright-core@${PW_VERSION}"
    npm i "playwright-core@${PW_VERSION}" 2>&1 | tail -2
    if [ ! -d "$HOME/.cache/ms-playwright/chromium-1148" ]; then
        info "下载 Chromium（国内直连可能慢，耐心等）"
        npx --yes "playwright-core@${PW_VERSION}" install chromium 2>&1 | tail -3
    else
        info "Chromium 已存在，跳过下载"
    fi
    ok "依赖就绪"
}

ensure() {
    [ -d "$MODULES_DIR/node_modules/playwright-core" ] || {
        warn "依赖不存在，自动 setup…"
        setup
    }
    PLAYWRIGHT_PATH="$MODULES_DIR/node_modules/playwright-core"
    export PLAYWRIGHT_PATH
}

run() {
    ensure
    cd "$ROOT"
    node tests/e2e_buttons.js "$@"
}

audit() {
    cd "$ROOT"
    python3 tests/button_audit.py "$@"
}

info() { echo "[INFO] $*"; }
ok()   { echo "[OK]   $*"; }
warn() { echo "[WARN] $*"; }

case "${1:-help}" in
    setup)  setup ;;
    probe)  shift; run probe "$@" ;;
    click)  shift; run click "$@" ;;
    portal) shift; run portal "$@" ;;
    all)    run click "$@"; run click --destructive "$@"; run portal "$@" ;;
    audit)  shift; audit "$@" ;;
    *)      sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
