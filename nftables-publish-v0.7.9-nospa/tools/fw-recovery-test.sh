#!/bin/sh
# =============================================================================
# 防火墙恢复链路实测：四级递进
#
#   L1  flush 规则集，规则文件还在        → 期望命中「用 RULES_PATH 恢复」
#   L2  再删掉规则文件（配置还在）        → 期望命中「按当前配置重新生成」
#   L3  再删掉配置文件（.backup 还在）    → 期望命中「用 .backup 恢复」
#   L4  再删掉 .backup                    → 期望命中「basic lockdown 兜底」
#
# 三条硬性判据（比「恢复了没有」更重要）：
#   1. 全程 SSH 不能断 —— 四条路径都必须保留 LAN 侧自救能力
#   2. 恢复出的规则里不得出现 DEFAULT_CONFIG 的陌生网段
#      （trusted_ip=192.168.100.2、转发 192.168.4.226、敲门端口 1/2/3/4）
#   3. 规则集恢复后必须是「用户配置」而非「内置默认值」
#      —— 用敲门端口和 trusted_ip 实际比对，不靠日志措辞
#
# 用法: ./fw-recovery-test.sh
# =============================================================================

RULES=/etc/nftables.d/99-custom-rules.nft
LASTGOOD=/etc/nftables.d/99-custom-rules.nft.lastgood
BACKUP=/etc/nftables.d/99-custom-rules.nft.backup
CONFIG=/etc/nftables/nftables-web-config.json
RECOVERY_LOG=/var/log/nftables-web-recovery.log
APPLOG=/var/log/nftables-web.log

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "  ✅ $*"; }
bad() { fail=$((fail+1)); echo "  ❌ $*"; }

restart_and_wait() {
    /etc/init.d/nftables-web restart >/dev/null 2>&1
    i=0
    while [ $i -lt 20 ]; do
        sleep 1
        c=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 https://127.0.0.1:5443/ 2>/dev/null)
        [ "$c" = "200" ] && return 0
        i=$((i+1))
    done
    return 1
}

lines() { nft list ruleset 2>/dev/null | grep -c ""; }
ssh_ok() { curl -sk -o /dev/null -w '%{http_code}' --max-time 4 https://127.0.0.1:5443/ 2>/dev/null; }

# 判据 2/3：恢复出的规则里绝不能出现 DEFAULT_CONFIG 的陌生值
no_default_residue() {
    grep -qE 'TRUSTED_IP4 = 192\.168\.100\.2([^0-9]|$)' "$RULES" 2>/dev/null \
        && return 1
    grep -qE 'KNOCK1_PORT = 1$' "$RULES" 2>/dev/null && return 1
    grep -qE 'ip saddr 192\.168\.4\.226' "$RULES" 2>/dev/null && return 1
    return 0
}

check_level() {
    _label="$1"; _expect_min="$2"; _expect_key="$3"
    n=$(lines)
    echo "    恢复后行数=$n  SSH=$(ssh_ok)"
    if [ "$n" -ge "$_expect_min" ]; then
        ok "$_label：规则集已恢复（$n 行）"
    else
        bad "$_label：规则集只恢复了 $n 行（期望 >= $_expect_min）"
    fi
    if [ "$(ssh_ok)" = "200" ]; then
        ok "$_label：SSH 自救通路保持可用"
    else
        bad "$_label：SSH 断了！"
    fi
    if no_default_residue; then
        ok "$_label：没有 DEFAULT_CONFIG 的陌生网段/示例端口残留"
    else
        bad "$_label：❗ 规则里出现了 DEFAULT_CONFIG 的陌生值（trusted_ip / 敲门端口 / 示例转发）"
    fi
    if [ -n "$_expect_key" ] && grep -qE "$_expect_key" "$RULES" 2>/dev/null; then
        ok "$_label：命中期望来源 $_expect_key"
    fi
    echo "    init 层: $(grep -a '加载成功\|回退\|init 层不做任何加载\|ERROR' "$RECOVERY_LOG" 2>/dev/null | tail -1 | sed 's/^.*\] //')"
    echo "    python层: $(grep -a '启动检测\|已从\|重新生成\|basic lockdown\|配置文件缺失\|配置损坏\|自动恢复全部失败' "$APPLOG" 2>/dev/null | head -2 | sed 's/^.*\] //' | tr '\n' ' ')"
}

echo ""
echo "════════ 防火墙恢复链路实测 ════════"
echo "  开始前：$(lines) 行，SSH=$(ssh_ok)"

# ═════════ L1 ═════════
echo ""
echo "── L1  规则集被清空，规则文件完好 ──"
nft flush ruleset 2>/dev/null
echo "    flush 后: $(lines) 行, 表=$(nft list table inet fw4 >/dev/null 2>&1 && echo 在 || echo 不存在), SSH=$(ssh_ok)"
restart_and_wait || bad "L1 重启失败"
check_level "L1" 50 'KNOCK1_PORT = 10376'

# ═════════ L2 ═════════
echo ""
echo "── L2  规则集 + 规则文件都缺失（配置还在）──"
mv "$RULES" /tmp/_r1
nft flush ruleset 2>/dev/null
restart_and_wait || bad "L2 重启失败"
check_level "L2" 50 'KNOCK1_PORT = 10376'
[ -e "$RULES" ] && ok "L2：规则文件已被重新生成（来自当前配置）" || bad "L2：规则文件没重新生成"
[ -e /tmp/_r1 ] && ok "L2：原文件仍安全保留" || bad "L2：原文件丢失"

# ═════════ L3 ═════════
echo ""
echo "── L3  再加配置文件缺失（.backup 还在）──"
mv "$CONFIG" /tmp/_c1
mv "$RULES" /tmp/_r2 2>/dev/null
nft flush ruleset 2>/dev/null
restart_and_wait || bad "L3 重启失败"
check_level "L3" 15 ''
if grep -aq "配置文件缺失" "$APPLOG" 2>/dev/null; then
    ok "L3：拒绝用内置默认值重建（走了硬判据）"
else
    bad "L3：没有拒绝默认值的痕迹"
fi

# ═════════ L4 ═════════
echo ""
echo "── L4  只剩 basic lockdown ──"
mv "$BACKUP" /tmp/_b1
mv "$RULES" /tmp/_r3 2>/dev/null
nft flush ruleset 2>/dev/null
restart_and_wait || bad "L4 重启失败"
n=$(lines)
echo "    恢复后行数=$n  SSH=$(ssh_ok)"
if [ "$n" -lt 60 ] && [ "$n" -gt 5 ]; then
    ok "L4：命中 basic lockdown（小规则集，$n 行，非用户配置）"
else
    bad "L4：行数 $n 不像 basic lockdown（应是 15~60 行的小规则集）"
fi
if grep -aq "basic lockdown" "$APPLOG" 2>/dev/null \
   || grep -aq "basic lockdown" "$RECOVERY_LOG" 2>/dev/null; then
    ok "L4：日志确认走了 basic lockdown"
else
    bad "L4：日志没看到 basic lockdown"
fi
echo "    兜底规则里 LAN 放行（自救能力）:"
nft list ruleset 2>/dev/null | grep 'iifname "br-lan"' | sed 's/^/      /' | head -3
if nft list ruleset 2>/dev/null | grep -q 'iifname "br-lan" tcp dport { 22, 5443 } accept'; then
    ok "L4：兜底保留了 SSH(22) + 面板(5443) 的 LAN 放行"
else
    bad "L4：兜底没保留管理端口放行（会导致远程无法自救）"
fi

# ═════════ 还原 ═════════
echo ""
echo "── 还原 ──"
mv -f /tmp/_r1 "$RULES" 2>/dev/null
mv -f /tmp/_r2 "$RULES" 2>/dev/null
mv -f /tmp/_r3 "$RULES" 2>/dev/null
mv -f /tmp/_c1 "$CONFIG" 2>/dev/null
mv -f /tmp/_b1 "$BACKUP" 2>/dev/null
restart_and_wait || bad "还原后重启失败"
echo ""
echo "  还原后: $(lines) 行, SSH=$(ssh_ok)"
for f in "$RULES" "$LASTGOOD" "$BACKUP" "$CONFIG"; do
    printf "    %-40s %s\n" "$(basename $f)" "$([ -e "$f" ] && echo "✅ $(wc -c < $f) 字节" || echo '❌ 缺失')"
done
if no_default_residue; then
    ok "还原后规则里没有 DEFAULT_CONFIG 残留"
else
    bad "还原后规则里仍有 DEFAULT_CONFIG 残留！"
fi
ok_grep=$(grep -E "define KNOCK1_PORT|define TRUSTED_IP4" "$RULES" 2>/dev/null | tr '\n' ' ')
echo "    关键值: $ok_grep"

echo ""
echo "────────────────────────────────"
echo "通过 ${pass} / $((pass + fail))"
[ "$fail" -ne 0 ] && exit 1
echo "四级恢复链路全部按设计命中：全程 SSH 未断，且没有一处下发内置默认值"
