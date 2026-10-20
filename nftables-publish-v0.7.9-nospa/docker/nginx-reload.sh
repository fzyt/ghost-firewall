#!/bin/sh
# nginx reload 垫片
#
# 面板下发网关配置时调的是 `subprocess.run([NGINX_INIT_PATH, 'reload'])`
# （backend/app.py:6125）—— OpenWrt 上那是 /etc/init.d/nginx。
# 容器里没有 init 系统，所以给它一个等价的垫片。
#
# ⚠️ 参数一律忽略，只做 reload：面板传什么子命令都走同一条路。
set -e

# nginx 的临时目录得先在（nginx -t 会检查）
mkdir -p /data/nginx/tmp/body /data/nginx/tmp/proxy /data/nginx/tmp/fastcgi \
         /data/nginx/tmp/uwsgi /data/nginx/tmp/scgi

# 配置语法有问题就**不要** reload —— 让面板看到非 0 退出码，
# 它会报"渲染结果语法错误，已保持原配置"，这比 reload 失败诚实得多。
if ! nginx -t 2>/data/log/nginx-test.log; then
    cat /data/log/nginx-test.log >&2
    exit 1
fi

exec nginx -s reload
