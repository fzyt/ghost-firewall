#!/bin/sh
# 容器入口：起 nginx → 起认证服务 → 起面板
#
# 三个进程都要活着，少一个面板就会报"网关全部 502"。
# 用一个 trap 统一收掉，容器停的时候不留孤儿进程。
set -e

DATA=/data
mkdir -p "$DATA/nftables" "$DATA/nftables.d" "$DATA/log" \
         "$DATA/nginx/ssl/nftables-web" "$DATA/nginx/conf.d" \
         "$DATA/nginx/tmp/body" "$DATA/nginx/tmp/proxy" \
         "$DATA/nginx/tmp/fastcgi" "$DATA/nginx/tmp/uwsgi" \
         "$DATA/nginx/tmp/scgi" "$DATA/luci"

# nginx 的主配置里 include /data/nginx/conf.d/*.conf ——
# 目录不存在时 nginx -t 会报错，容器起不来。先放一个空的。
[ -f "$DATA/nginx/conf.d/.keep" ] || : > "$DATA/nginx/conf.d/.keep"

cleanup() {
    echo "[entrypoint] 收到退出信号，收拾进程"
    [ -n "${PANEL_PID:-}" ] && kill "$PANEL_PID" 2>/dev/null || true
    [ -n "${AUTH_PID:-}" ] && kill "$AUTH_PID" 2>/dev/null || true
    nginx -s quit 2>/dev/null || true
    exit 0
}
trap cleanup TERM INT

echo "[entrypoint] 启动 nginx"
nginx -t && nginx

# ── 放行 docker 网关来源 ──────────────────────────────────────
# 面板的访问边界默认跟着 lan_subnet4 走，而容器里探测到的还是
# OpenWrt 的默认网段 192.168.4.0/24。真实来源是 docker 网关
# （x.x.x.1），不在里面 → 面板会回 IP_NOT_ALLOWED，把人锁在门外。
#
# 这里按容器自己的地址推出所在网段（/16），作为**额外**放行。
# 注意是"额外"：配置里本来就不限制时，依然不限制。
CTR_IP="$(python3 - <<'PY'
import re, socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip = ''
try:
    s.connect(('8.8.8.8', 80))     # UDP connect 不发包，只用来选路由
    ip = s.getsockname()[0]
except Exception:
    pass
finally:
    s.close()
if not ip:
    try:
        for line in open('/proc/net/fib_trie'):
            m = re.match(r'\s*\|--\s+(\S+)', line)
            if m and not m.group(1).startswith('127.'):
                ip = m.group(1)
                break
    except Exception:
        pass
print(ip)
PY
)"
if [ -n "$CTR_IP" ]; then
    O1=$(echo "$CTR_IP" | cut -d. -f1)
    O2=$(echo "$CTR_IP" | cut -d. -f2)
    DOCKER_NET="${O1}.${O2}.0.0/16"
    # 这里是**追加**而不是覆盖。
    #
    # 为什么：docker 发布端口时，容器看到的来源地址取决于流量怎么进来 ——
    #   · 宿主机自己 curl 127.0.0.1:5443  → 容器看到 docker 网关 172.x.0.1
    #   · 局域网里的机器访问 192.168.100.218:5443 → 容器看到**那台机器的真实 IP**
    # 所以只放行容器自己的网段，用户从别的机器点面板时会被
    # IP_NOT_ALLOWED（403）挡在门外 —— 这正是这个测试环境最不该犯的错。
    #
    # compose 里已经给了宿主 LAN 的网段（可用 .env 覆盖），这里再补上
    # 容器网段，两边并集。
    if [ -n "${NFTABLES_WEB_PANEL_ALLOWED_NETS:-}" ]; then
        NFTABLES_WEB_PANEL_ALLOWED_NETS="${NFTABLES_WEB_PANEL_ALLOWED_NETS},${DOCKER_NET}"
    else
        NFTABLES_WEB_PANEL_ALLOWED_NETS="${DOCKER_NET}"
    fi
    export NFTABLES_WEB_PANEL_ALLOWED_NETS
    echo "[entrypoint] 容器地址 $CTR_IP → 放行网段: $NFTABLES_WEB_PANEL_ALLOWED_NETS"
else
    echo "[entrypoint] ⚠️ 算不出容器地址，面板可能回 IP_NOT_ALLOWED"
fi

echo "[entrypoint] 启动认证服务 (127.0.0.1:${AUTH_API_PORT:-8444})"
cd /app/backend
python3 auth_gateway.py >>"$DATA/log/auth-gateway.log" 2>&1 &
AUTH_PID=$!

# 等认证服务起来 —— 面板的网关自检会问它"活着吗"
i=0
while [ $i -lt 30 ]; do
    if python3 - <<'PY' 2>/dev/null
import socket, os, sys
s = socket.socket()
s.settimeout(1)
try:
    s.connect(('127.0.0.1', int(os.environ.get('AUTH_API_PORT', '8444'))))
except Exception:
    sys.exit(1)
finally:
    s.close()
PY
    then
        break
    fi
    i=$((i + 1))
    sleep 0.5
done
[ $i -ge 30 ] && echo "[entrypoint] ⚠️ 认证服务 15 秒没起来，看 $DATA/log/auth-gateway.log"

echo "[entrypoint] 启动面板 (0.0.0.0:${NFTABLES_WEB_HTTPS_PORT:-5443})"
python3 app.py >>"$DATA/log/panel.log" 2>&1 &
PANEL_PID=$!

echo "[entrypoint] 面板 PID=$PANEL_PID  认证 PID=$AUTH_PID"
echo "[entrypoint] 访问 https://localhost:${NFTABLES_WEB_HTTPS_PORT:-5443} （自签证书，需手动信任）"

# 盯着两个子进程：谁死了就整体退出，docker restart 能重新拉起来
while true; do
    if ! kill -0 "$PANEL_PID" 2>/dev/null; then
        echo "[entrypoint] 面板进程退出，容器一并退出"
        tail -30 "$DATA/log/panel.log" 2>/dev/null || true
        exit 1
    fi
    if ! kill -0 "$AUTH_PID" 2>/dev/null; then
        echo "[entrypoint] 认证服务进程退出，容器一并退出"
        tail -30 "$DATA/log/auth-gateway.log" 2>/dev/null || true
        exit 1
    fi
    sleep 5
done
