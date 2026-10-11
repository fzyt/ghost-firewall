#!/bin/sh
# =============================================================================
# 内网免登录开关（auth_lan_bypass）一键管理
#
# 背景：这个开关打开时，任何来自内网网段的设备访问网关都直接放行，
#       连 auth_request 都不走。也就是「内网里任何东西 = 已认证」。
#       正式暴露公网前必须关掉。
#
# 用法：
#   ./lan-auth.sh off    关闭内网免登录（推荐，对外暴露前执行这个）
#   ./lan-auth.sh on     打开内网免登录（仅限完全隔离的纯内网环境）
#   ./lan-auth.sh status 查看当前状态并实测是否真的生效
# =============================================================================

PANEL="https://127.0.0.1:5443"
CONFIG="/etc/nftables/nftables-web-config.json"
PASSWORD="${NF_PASSWORD:-TestGW2026}"
RUN="/tmp/nf-testbed"

ok()   { echo "  ✅ $*"; }
bad()  { echo "  ❌ $*"; }
info() { echo "     $*"; }

read_setting() {
    python3 -c "
import json
try:
    print(json.load(open('$CONFIG')).get('auth_lan_bypass'))
except Exception:
    print('读取失败')
"
}

write_setting() {
    # $1 = true/false
    # 值通过 argv 传，不做字符串插值。
    # 原来写成 d['auth_lan_bypass'] = ($1 == 'true')，shell 会把 $1 展开成
    # 字面量 false，Python 里就成了 (false == 'true') → NameError。
    if ! python3 - "$1" "$CONFIG" <<'PYEOF'
import json, sys
want = (sys.argv[1] == 'true')
path = sys.argv[2]
with open(path) as f:
    d = json.load(f)
d['auth_lan_bypass'] = want
with open(path, 'w') as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
PYEOF
    then
        bad "写配置失败，开关未改变"
        return 1
    fi
}

restart() {
    /etc/init.d/nftables-web-auth restart >/dev/null 2>&1
    sleep 4
}

login() {
    mkdir -p "$RUN"
    curl -sk -X POST "${PANEL}/api/auth/login" \
         -H 'Content-Type: application/json' \
         -c "$RUN/cookies" --max-time 15 \
         -d "{\"password\":\"${PASSWORD}\"}" >/dev/null
}

# 实测：不带任何 cookie 去访问受保护路径，看是不是被拦到登录页。
# 这是唯一可信的判据 —— 配置文件改了不等于运行时生效。
probe() {
    # 探测路径取第一条 public_access=true 的规则，取不到就退回 /nas
    mkdir -p "$RUN"
    login
    P=$(curl -sk "${PANEL}/api/reverse-proxy/rules" -b "$RUN/cookies" --max-time 10 \
        | tr ',' '\n' | grep '"public_access":true' -B6 \
        | grep '"path_prefix"' | head -1 \
        | sed 's/.*"path_prefix":"\([^"]*\)".*/\1/')
    [ -z "$P" ] && P="/nas"
    CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "https://127.0.0.1:8443${P}/")
    # 返回 0 表示「已生效」，调用方据此决定退出码和文案。
    # 原来这里只打印不影响流程，脚本在写配置失败后照样打印
    # 「现在内网设备必须登录了」——失败了却报告成功，最坏的一种失败方式。
    if [ "$CODE" = "302" ]; then
        ok "未登录访问 ${P}/ -> 302 跳转登录页（认证已生效）"
        return 0
    elif [ "$CODE" = "200" ]; then
        bad "未登录访问 ${P}/ -> 200 直接放行（认证未生效！）"
        return 1
    else
        bad "未登录访问 ${P}/ -> HTTP ${CODE}（既没有跳转也没有拒绝，状态异常）"
        return 1
    fi
}

case "$1" in
  off)
    echo ""
    echo "──── 关闭内网免登录 ────"
    BEFORE=$(read_setting)
    echo "     改前: auth_lan_bypass = ${BEFORE}"
    if ! write_setting false; then
        bad "未做任何改动，脚本中止"
        exit 1
    fi
    restart
    AFTER=$(read_setting)
    echo "     改后: auth_lan_bypass = ${AFTER}"
    if [ "$AFTER" != "False" ]; then
        bad "配置写入后读回的值不是 False，开关未生效，中止"
        exit 1
    fi
    if probe; then
        echo ""
        echo "     ✅ 现在内网设备访问网关也必须登录了。"
        echo ""
    else
        echo ""
        bad "配置已改但运行时未生效，请检查认证服务状态"
        exit 1
    fi
    ;;
  on)
    echo ""
    echo "──── 打开内网免登录 ────"
    BEFORE=$(read_setting)
    echo "     改前: auth_lan_bypass = ${BEFORE}"
    if ! write_setting true; then
        bad "未做任何改动，脚本中止"
        exit 1
    fi
    restart
    AFTER=$(read_setting)
    echo "     改后: auth_lan_bypass = ${AFTER}"
    if [ "$AFTER" != "True" ]; then
        bad "配置写入后读回的值不是 True，开关未生效，中止"
        exit 1
    fi
    echo ""
    echo "     ⚠️  内网内任何设备现在都能免登录访问所有 public 服务。"
    echo ""
    ;;
  status)
    echo ""
    echo "──── 当前状态 ────"
    echo "     配置值: auth_lan_bypass = $(read_setting)"
    probe
    echo ""
    ;;
  *)
    echo "用法: $0 {off|on|status}"
    exit 1
    ;;
esac
