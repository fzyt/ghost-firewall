#!/bin/sh
# nftables-web 清空重装（不备份用户数据）
# 在 do 主机执行: sh redeploy.sh
# 前置: do 能免密 SSH 到 192.168.100.224

set -e
R=192.168.100.224
APP=/opt/nftables-web-v2
SRC=/home/kirito/claude/项目/nftables-web-v2/nftables-publish-v0.7.9-nospa
TS=$(date +%m%d_%H%M)
say() { echo "==> $*"; }
rssh() { ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"$R" "$@"; }

say "0. 连通 + 身份确认"
rssh 'echo "    SSH OK"' || { echo "!! SSH 不通"; exit 1; }
rssh 'grep -q OpenWrt /etc/openwrt_release || { echo "!! 不是 OpenWrt，中止"; exit 1; }; echo "    $(grep DISTRIB_DESCRIPTION /etc/openwrt_release | cut -d\" -f2)"'

# ---------------------------------------------------------------------
# 唯一保留项：web 配置
# 理由：trusted_ip4 / knock 端口 / router_ip4 都在这个文件里。
# 它是「谁能进这台路由器」的唯一凭据 —— 删了就没法再进来（含你自己），
# 而它只有几 KB 且是本项目自己生成的，不属于「旧数据」。
# ---------------------------------------------------------------------
say "1. 保留 web 配置（凭据所在，不可删）"
rssh "test -f /etc/nftables/nftables-web-config.json \
  && cp /etc/nftables/nftables-web-config.json /tmp/cfg-keep-\$TS.json \
  && echo '    已暂存: \$(wc -c < /tmp/cfg-keep-$TS.json) 字节' \
  || echo '    无旧配置，用默认值重建'"

say "2. 停服务"
rssh "/etc/init.d/nftables-web stop 2>/dev/null || true"
rssh "/etc/init.d/nftables-web disable 2>/dev/null || true"
rssh "pkill -f 'python3 app.py' 2>/dev/null || true"
rssh "sleep 2"
rssh "test -f /var/run/nftables-web.pid && echo '    ⚠ 进程仍在' || echo '    进程已停'"

say "3. 清空旧防火墙（规则 + 程序 + cron + nginx conf）"
rssh "rm -rf $APP"
rssh "rm -f /etc/nftables.d/99-custom-rules.nft*"
rssh "rm -f /etc/init.d/nftables-web /etc/rc.d/*nftables-web"
rssh "rm -f /opt/nftables-web/update-ipv6.sh /opt/nftables-web-v2/update-china-ips.sh /opt/nftables-web-v2/aliyun-ddns-update.py"
rssh "rm -f /etc/nftables/china-ips.nft"
rssh "crontab -l 2>/dev/null | grep -vE 'update-ipv6.sh|update-china-ips.sh|aliyun-ddns-update.py' | crontab - 2>/dev/null || true"
rssh "echo '    已清理。当前 nft 规则集行数: \$(nft list ruleset 2>/dev/null | wc -l)'"
rssh "echo '    剩余 cron:'; crontab -l 2>/dev/null | sed 's/^/      /' ; true"

say "4. 确认防火墙已清空（此时应无 table inet fw4）"
rssh "nft list tables 2>/dev/null | sed 's/^/    /' ; true"

say "5. 部署新代码"
rssh "mkdir -p $APP /etc/nftables /etc/nftables.d"
tar -C "$SRC" -czf - backend frontend setup VERSION 2>/dev/null \
  | ssh -o BatchMode=yes root@"$R" "tar -C $APP -xzf -"
rssh "find $APP -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true"
rssh "ls $APP | tr '\n' ' ' | sed 's/^/    已部署: /'; echo"

say "6. 装 init 脚本"
rssh "cp $APP/backend/nftables-web.init /etc/init.d/nftables-web && chmod 755 /etc/init.d/nftables-web"
rssh "sh -n /etc/init.d/nftables-web && echo '    init 语法 OK'"

say "7. 真实 nft 语法预检（部署前最后一道关）"
rssh "python3 -c \"
import sys; sys.path.insert(0,'$APP/backend')
import app
r = app.build_rules(app.load_config())
open('/tmp/precheck.nft','w').write(r)
print('    生成', len(r.splitlines()), '行')
\"" || { echo "!! 规则生成失败"; exit 1; }
if rssh "nft -c -f /tmp/precheck.nft" 2>/dev/null; then
  echo "    ✅ nft 语法校验通过"
else
  echo "!! nft 语法校验失败 —— 中止，不启动服务（当前无防火墙，需你从 LuCI 恢复）"
  exit 1
fi

say "8. 启动"
rssh "/etc/init.d/nftables-web enable"
rssh "/etc/init.d/nftables-web start"
rssh "sleep 5"
rssh "test -f /var/run/nftables-web.pid && echo \"    PID \$(cat /var/run/nftables-web.pid)\" || { echo '!! 没起来'; rssh 'tail -30 /var/log/nftables-web.log'; exit 1; }"
rssh "curl -sk --max-time 6 -o /dev/null -w '    面板 HTTP: %{http_code}\n' https://127.0.0.1:5443/"
rssh "echo '    nft 规则集行数: \$(nft list ruleset 2>/dev/null | wc -l)'"
rssh "nft list table inet fw4 2>/dev/null | head -3 | sed 's/^/    /'"

say ""
say "完成。接着跑: sh run-tests.sh"
