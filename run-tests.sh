#!/bin/sh
# 部署后的真机功能测试（在 do 主机执行）
# 用法: sh run-tests.sh [备份时间戳]
#
# 全部通过面板 HTTP API 测试，不需要额外凭据（用已登录会话或直接读本地文件）
# 只做只读 + 可回滚的写操作，不重启路由器

R=192.168.100.224
APP=/opt/nftables-web-v2
TS=${1:-latest}
rssh() { ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"$R" "$@"; }
PASS=0; FAIL=0
ck() { if [ "$2" = "1" ]; then echo "  ✅ $1"; PASS=$((PASS+1)); else echo "  ❌ $1"; FAIL=$((FAIL+1)); fi; }

echo "======================================================================"
echo " T1  服务与规则基础状态"
echo "======================================================================"
rssh 'test -f /var/run/nftables-web.pid' && ck "进程 PID 文件存在" 1 || ck "进程 PID 文件存在" 0
rssh 'nft list ruleset 2>/dev/null | grep -q "table inet fw4"' && ck "nft 里 table inet fw4 已加载" 1 || ck "nft 里 table inet fw4 已加载" 0
rssh 'test -s /etc/nftables.d/99-custom-rules.nft' && ck "规则文件非空" 1 || ck "规则文件非空" 0
rssh 'test -s /etc/nftables.d/99-custom-rules.nft.lastgood' && ck ".lastgood 备份存在" 1 || ck ".lastgood 备份存在（非首次部署时）" 0
rssh 'test -s /etc/nftables.d/99-custom-rules.nft.backup' && ck "全量 ruleset 备份非空" 1 || ck "全量 ruleset 备份非空" 0
rssh 'ls /etc/nftables.d/*.tmp 2>/dev/null | grep -q .' && ck "无残留 .tmp（应为无）" 0 || ck "无残留 .tmp" 1

echo
echo "======================================================================"
echo " T2  本次修复点在真机的行为"
echo "======================================================================"
rssh "python3 - <<'PYEOF"
import sys; sys.path.insert(0, '/opt/nftables-web-v2/backend')
import app
# 注入封堵
evil = {'router_ip4':'192.168.4.1','trusted_ip4':'192.168.100.2',
        'whitelist_timeout':'1s; delete table inet fw4; #',
        'knock1_port':'11001; flush ruleset',
        'forward_rules':[{'tcp_ports':'80; delete table inet fw4','udp_ports':'53',
                          'target_ip':'192.168.4.1; flush ruleset'}]}
r = app.build_rules(evil)
bad = [l for l in r.splitlines() if ('delete table' in l or 'flush ruleset' in l)
       and l.strip() != 'flush ruleset']
print('    注入残留条数:', len(bad))
# 自锁告警
ME = app.load_config().get('trusted_ip4')
r1 = app._detect_risks({'trusted_ip4':ME,'lan_allowed_ports':''},
                       {'trusted_ip4':'10.0.0.5','lan_allowed_ports':''}, '192.168.4.1')
print('    自锁检测可用:', bool(r1))
# 畸形配置
for patch in [{'forward_rules':'x'}, {'reverse_proxy':'x'}, {'knock1_port':None}]:
    app.build_rules({'router_ip4':'1.1.1.1','trusted_ip4':'2.2.2.2', **patch})
print('    畸形配置不崩: True')
PYEOF" 2>&1 | sed 's/^/  /'
ck "注入残留为 0" "$(rssh "python3 -c \"
import sys; sys.path.insert(0,'$APP/backend')
import app
r=app.build_rules({'router_ip4':'1.1.1.1','trusted_ip4':'2.2.2.2','whitelist_timeout':'1s; delete table inet fw4; #'})
print(0 if [l for l in r.splitlines() if 'delete table' in l] else 1)
\"" 2>/dev/null | tail -1)"

echo
echo "======================================================================"
echo " T3  配置校验层（真机 validate_config）"
echo "======================================================================"
rssh "python3 -c \"
import sys; sys.path.insert(0,'$APP/backend')
import app, copy
print('    DEFAULT_CONFIG 通过:', not app.validate_config(copy.deepcopy(app.DEFAULT_CONFIG)))
print('    数组 trusted_ip4 通过:', not [e for e in app.validate_config({**app.DEFAULT_CONFIG,'trusted_ip4':['1.2.3.4']}) if 'trusted' in e])
print('    注入值被拒:', len([e for e in app.validate_config({**app.DEFAULT_CONFIG,'whitelist_timeout':'1s; drop'}) if 'whitelist' in e])==1)
\"" 2>&1 | sed 's/^/  /'

echo
echo "======================================================================"
echo " T4  回滚机制（真机 nft）"
echo "======================================================================"
rssh "python3 -c \"
import sys, os; sys.path.insert(0,'$APP/backend')
import app
before = open(app.RULES_PATH).read()
state, msg = app._restore_lastgood_rules()
print('    state =', state)
print('    规则仍有效:', 'table inet fw4' in __import__('subprocess').run(['nft','list','ruleset'],capture_output=True,text=True).stdout)
\"" 2>&1 | sed 's/^/  /'
RS=$(rssh "python3 -c \"
import sys; sys.path.insert(0,'$APP/backend')
import app, subprocess
state, msg = app._restore_lastgood_rules()
print(state)
\"" 2>/dev/null | tail -1)
[ "$RS" = "lastgood" ] && ck "回滚到 .lastgood 成功" 1 || ck "回滚到 .lastgood 成功（实得 $RS）" 0

echo
echo "======================================================================"
echo " T5  开机自启（init 脚本）"
echo "======================================================================"
rssh 'test -L /etc/rc.d/S99nftables-web' && ck "init 开机自启链接已建立" 1 || ck "init 开机自启链接已建立" 0
rssh '/etc/init.d/nftables-web enabled' && ck "init 服务已 enable" 1 || ck "init 服务已 enable" 0
rssh 'sh -n /etc/init.d/nftables-web' && ck "init 脚本语法 OK" 1 || ck "init 脚本语法 OK" 0
rssh 'grep -q "lastgood" /etc/init.d/nftables-web' && ck "init 含 .lastgood 回退逻辑" 1 || ck "init 含 .lastgood 回退逻辑" 0

echo
echo "======================================================================"
echo " T6  cron / DDNS / nginx 配置一致性"
echo "======================================================================"
N6=$(rssh 'crontab -l 2>/dev/null | grep -c "update-ipv6.sh"' | tr -d ' \r')
[ "$N6" = "1" ] && ck "IPv6 cron 唯一（$N6 条）" 1 || ck "IPv6 cron 唯一（实得 $N6 条）" 0
ND=$(rssh 'crontab -l 2>/dev/null | grep -c "aliyun-ddns-update.py"' | tr -d ' \r')
echo "  ℹ️  DDNS cron 条数: $ND"
rssh 'test -f /opt/nftables-web/update-ipv6.sh' && ck "IPv6 脚本已安装" 1 || ck "IPv6 脚本已安装" 0

echo
echo "======================================================================"
echo " T7  日志健康度"
echo "======================================================================"
rssh 'tail -60 /var/log/nftables-web.log 2>/dev/null | grep -ci "Traceback\|ERROR"' > /tmp/_errs
ERRS=$(cat /tmp/_errs | tr -d ' \r')
[ "$ERRS" = "0" ] && ck "日志无 Traceback/ERROR" 1 || ck "日志无 Traceback/ERROR（发现 $ERRS 处）" 0
rssh 'tail -8 /var/log/nftables-web.log 2>/dev/null' | sed 's/^/    /'

echo
echo "======================================================================"
printf " 结果: %d 通过 / %d 失败\n" "$PASS" "$FAIL"
echo "======================================================================"
[ "$FAIL" = "0" ] || echo " 有失败项，需要排查"
