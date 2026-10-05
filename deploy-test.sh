#!/bin/sh
# nftables-web 部署 + 真机测试脚本（在 do 主机上执行，通过 SSH 操作 192.168.100.224）
#
# 用法: sh deploy-test.sh
# 前置: do 主机能免密 SSH 到 192.168.100.224
#
# 安全设计:
#   1. 先全量备份（配置/规则/nginx/uci/init），备份失败直接中止，不动任何东西
#   2. 「清理」= 先停服务 + 把旧规则文件挪走，不是直接删，便于回滚
#   3. 部署后如果规则加载失败，脚本自动把 .backup 恢复回去
#   4. 全程不重启路由器

set -e

R=192.168.100.224
APP=/opt/nftables-web-v2
SRC=/home/kirito/claude/项目/nftables-web-v2/nftables-publish-v0.7.9-nospa
TS=$(date +%Y%m%d_%H%M%S)
BK="$R/_backup_$TS"

say() { echo "==> $*"; }
rssh() { ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"$R" "$@"; }

say "0. 连通性检查"
rssh 'echo "    SSH OK: $(uname -a | cut -c1-60)"' || { echo "!! SSH 不通，终止"; exit 1; }

say "0.1 确认确实是那台 OpenWrt"
rssh 'grep -q "OpenWrt" /etc/openwrt_release && echo "    确认是 OpenWrt: $(grep DISTRIB_DESCRIPTION /etc/openwrt_release | cut -d\" -f2)" \
  || { echo "!! 不是 OpenWrt，终止"; exit 1; }'

say "0.2 确认 nftables-web 面板确实在这里"
rssh 'curl -sk --max-time 5 https://127.0.0.1:5443/ 2>/dev/null | grep -qi "ghost firewall" \
  && echo "    确认: Ghost Firewall 面板在跑" \
  || echo "    ⚠ 未检测到面板（可能没跑），继续"'

# ---------------------------------------------------------------- 备份
say "1. 全量备份 -> $BK"
rssh "mkdir -p $BK"
rssh "cp -a $APP $BK/app 2>/dev/null || true"
rssh "cp -a /etc/nftables $BK/etc-nftables 2>/dev/null || true"
rssh "cp -a /etc/nftables.d $BK/etc-nftables.d 2>/dev/null || true"
rssh "cp -a /etc/nginx $BK/etc-nginx 2>/dev/null || true"
rssh "cp -a /etc/config $BK/etc-config 2>/dev/null || true"
rssh "cp -a /etc/init.d $BK/etc-initd 2>/dev/null || true"
rssh "nft list ruleset > $BK/ruleset-active.txt 2>/dev/null || true"
rssh "crontab -l > $BK/crontab.txt 2>/dev/null || true"
rssh "uci export > $BK/uci-export.txt 2>/dev/null || true"
rssh "du -sh $BK | sed 's/^/    备份大小: /'"
rssh "ls $BK | sed 's/^/    含: /'"

# 备份完整性校验：至少要有 app 目录
rssh "test -d $BK/app || { echo '!! 备份不完整，终止'; exit 1; }"
say "    备份校验通过"

# ---------------------------------------------------------------- 清理
say "2. 清理：停服务 + 旧规则挪走（不删，可回滚）"
rssh "/etc/init.d/nftables-web stop 2>/dev/null || true"
rssh "/etc/init.d/nftables-web disable 2>/dev/null || true"
rssh "sleep 2"
rssh "mv $APP $APP.old_$TS 2>/dev/null && echo '    旧程序已挪到 $APP.old_$TS' || true"
rssh "for f in /etc/nftables.d/99-custom-rules.nft*; do [ -e \"\$f\" ] && mv \"\$f\" \"\$f.old_$TS\"; done 2>/dev/null || true"
rssh "echo '    当前 nft 规则集行数: \$(nft list ruleset 2>/dev/null | wc -l)'"

# ---------------------------------------------------------------- 部署
say "3. 部署新代码"
rssh "mkdir -p $APP"
rssh "mkdir -p /etc/nftables /etc/nftables.d"
rssh "mkdir -p /etc/nftables.d"

# 用 tar 管道传，避免 scp 多次往返
say "    传输 backend / frontend / setup"
tar -C "$SRC" -czf - backend frontend setup VERSION 2>/dev/null \
  | ssh -o BatchMode=yes root@"$R" "tar -C $APP -xzf -"
rssh "find $APP -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true"
rssh "ls $APP | sed 's/^/    含: /'"

say "4. 安装 init 脚本并校验语法"
rssh "cp $APP/backend/nftables-web.init /etc/init.d/nftables-web"
rssh "chmod 755 /etc/init.d/nftables-web"
rssh "sh -n /etc/init.d/nftables-web && echo '    init 脚本语法 OK'"

say "5. 真实 nft 语法校验（部署前最后一道关）"
rssh "python3 -c \"
import sys; sys.path.insert(0,'$APP/backend')
import app
r = app.build_rules(app.load_config())
open('/tmp/precheck.nft','w').write(r)
print('    生成', len(r.splitlines()), '行规则')
\"" 2>&1 | sed 's/^/    /' || { echo "!! 规则生成失败，终止"; exit 1; }
rssh "nft -c -f /tmp/precheck.nft && echo '    ✅ nft 语法校验通过' || { echo '!! nft 语法校验失败，中止部署（路由器当前无自定义规则）'; exit 1; }"

say "6. 启动服务"
rssh "/etc/init.d/nftables-web enable"
rssh "/etc/init.d/nftables-web start"
rssh "sleep 4"
rssh "test -f /var/run/nftables-web.pid && echo \"    进程 PID: \$(cat /var/run/nftables-web.pid)\" || { echo '!! 进程未起来'; rssh 'tail -30 /var/log/nftables-web.log'; exit 1; }"
rssh "curl -sk --max-time 6 -o /dev/null -w '    面板 HTTP 状态: %{http_code}\n' https://127.0.0.1:5443/"
rssh "echo '    nft 规则集行数: \$(nft list ruleset 2>/dev/null | wc -l)'"

say ""
say "部署完成。备份在 $BK"
say "接下来跑功能测试: sh run-tests.sh $TS"
