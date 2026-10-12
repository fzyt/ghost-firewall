#!/bin/sh
# nginx worker 降权 —— master 保留 root，worker 降到 nobody
#
# 为什么：master 需要 root（读私钥、bind 低端口），但**真正处理公网流量的
# 是 worker**。worker 以 root 运行时，nginx 侧任何一处漏洞（请求走私、
# 模块缺陷、配置误伤）都直接等于整台机器沦陷 —— 和认证网关那半个问题是
# 同一类，只是入口在 HTTP 层而不是应用层。
#
# 为什么私钥要 640 而不是保持 600：
#   app.py 在上传证书 / ACME 续期 / 自签生成三处都会 chmod(key, 0o600)。
#   只在这里改一次 nginx 的 user 是不够的 —— 下一次换证书，worker 立刻
#   读不到私钥，而 nginx 的表现只是「TLS 握手失败」，没有任何提示说明是
#   权限问题。所以 app.py 的 _harden_key_for_nginx_worker() 会在每次写入
#   之后补上组读权限，本脚本负责存量文件和 nginx 指令本身。
#
# 幂等：可重复执行。
set -e

NGINX_CONF="${NGINX_CONF:-/etc/nginx/uci.conf}"
UCI_CONF="${UCI_CONF:-/etc/nginx/uci.conf}"
WORKER_USER="${WORKER_USER:-nobody}"
SSL_DIR="${SSL_DIR:-/etc/nginx/ssl}"

say() { echo "  $*"; }

# ⚠️ 必须用服务实际加载的那份配置来校验。
#   实测踩过：`nginx -t` 读的是 /etc/nginx/nginx.conf，而 init 脚本起的是
#   `nginx -c /etc/nginx/uci.conf`。两份文件不同，校验错了文件会得到一个
#   假绿灯，然后 restart 才把网关弄挂 —— 而且挂的原因根本不在被验的那份里。
CONF="$NGINX_CONF"
[ -e "$UCI_CONF" ] && CONF="$UCI_CONF"

nginx_check() { nginx -t -c "$CONF" "$@"; }

# ── 1. worker 用户与组都必须存在 ────────────────────────────
# ⚠️ nginx 的 `user` 指令内部是 getpwnam() + getgrnam()，**两个都要查**，
#   而且用的是同一个名字。OpenWrt 的 /etc/passwd 里有 nobody，但
#   /etc/group 里只有 nogroup、没有 nobody —— 只查用户会漏掉这一半，
#   然后 nginx 报 `getgrnam("nobody") failed` 直接拒绝启动。
PASSWD_LINE=$(awk -F: -v u="$WORKER_USER" '$1==u {print $3":"$4}' /etc/passwd)
[ -n "$PASSWD_LINE" ] || { echo "找不到用户 $WORKER_USER（/etc/passwd）" >&2; exit 1; }
WORKER_UID=$(echo "$PASSWD_LINE" | cut -d: -f1)
WORKER_GID=$(echo "$PASSWD_LINE" | cut -d: -f2)

if ! grep -q "^${WORKER_USER}:" /etc/group; then
    echo "  /etc/group 里没有组 $WORKER_USER —— nginx 的 getgrnam() 会失败"
    echo "${WORKER_USER}:x:${WORKER_GID}:" >> /etc/group
    say "已补建组 ${WORKER_USER} (gid=${WORKER_GID})"
fi
say "worker ${WORKER_USER} uid=$WORKER_UID gid=$WORKER_GID"

# ── 2. 改 nginx 指令（先备份，改坏了能退回去）────────────────
BK="$CONF.bak-privesc"
[ -f "$CONF" ] || { echo "找不到 $CONF" >&2; exit 1; }
cp -p "$CONF" "$BK"

CUR=$(grep -E "^[[:space:]]*user[[:space:]]" "$CONF" | head -1 | awk '{print $2}' | tr -d ';')
CHANGED=0
if [ "$CUR" = "$WORKER_USER" ]; then
    say "nginx 已是 user $WORKER_USER，跳过指令改动"
else
    say "nginx 当前 user=$CUR -> $WORKER_USER"
    CHANGED=1
    if grep -qE "^[[:space:]]*user[[:space:]]" "$CONF"; then
        sed -i "s|^[[:space:]]*user[[:space:]].*|user $WORKER_USER;|" "$CONF"
    else
        # 没有 user 指令时插到 worker_processes 后面
        sed -i "s|^[[:space:]]*worker_processes|&\\nuser $WORKER_USER;|" "$CONF"
    fi
fi

# ── 3. 语法预检：必须用服务实际加载的那份配置 ──────────────────
if ! nginx_check 2>/tmp/nginx-t.err; then
    echo "nginx -t -c $CONF 失败，已还原配置" >&2
    cat /tmp/nginx-t.err >&2
    cp -p "$BK" "$CONF"
    exit 1
fi
say "nginx -t -c $CONF 通过"

# ── 4. 存量私钥补组读权限 ────────────────────────────────────
if [ -d "$SSL_DIR" ]; then
    N=0
    for k in $(find "$SSL_DIR" -name '*.key' -o -name 'privkey.pem' 2>/dev/null); do
        [ -f "$k" ] || continue
        chgrp "$WORKER_GID" "$k" && chmod 640 "$k" && N=$((N + 1))
    done
    say "已修正 $N 个私钥为 root:$WORKER_USER(gid $WORKER_GID) 640"
fi

# ── 5. 重启 ──────────────────────────────────────────────────
# ⚠️ 必须 restart，不能只 reload。
#   nginx 的 `user` 指令**只在 master 启动时生效**；SIGHUP reload 会重新
#   读配置、拉起新 worker，但 worker 的 uid 仍是 master 启动时那一个。
#   实测踩过：reload 之后 worker 仍然是 uid=0。
#   只有 stop + start 才会让 master 用新的 user 重新 fork。
#   公网入口会断 1~2 秒（面板 5443 是独立 Python 进程，不受影响）。
if [ "$CHANGED" = "1" ]; then
    say "user 指令有变更 -> 必须完整 restart（reload 不改 worker 身份）"
    /etc/init.d/nginx stop 2>/dev/null || true
    sleep 1
    /etc/init.d/nginx start
else
    say "user 指令未变更 -> reload 即可"
    nginx -s reload 2>/dev/null || /etc/init.d/nginx reload
fi
sleep 2

# ── 6. 复核：worker 必须真的降下去了 ─────────────────────────
# 注意两个不同的判据：
#   master 必须是 root（要 bind 低端口、读私钥），这不是降权失败
#   worker 必须等于 WORKER_UID，且不是 0
# 另外还要确认真的有一个 worker —— 一个都没有同样是失败
# （实测踩过：配置写对了但 nginx 压根没起来，循环体一次都不进，
#   BAD 保持 0，脚本却报「完成」。这里补上下限判断。）
BAD=0
NMASTER=0
NWORKER=0
for p in $(pgrep nginx 2>/dev/null); do
    CMD=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)
    case "$CMD" in
        *master*)
            NMASTER=$((NMASTER + 1))
            if [ "$(awk '/^Uid:/{print $2}' "/proc/$p/status" 2>/dev/null)" = "0" ]; then
                say "master pid=$p uid=0（保留 root，正确）"
            else
                echo "master pid=$p 不是 root —— master 需要 root" >&2; BAD=1
            fi
            ;;
        *worker*)
            NWORKER=$((NWORKER + 1))
            U=$(awk '/^Uid:/{print $2}' "/proc/$p/status" 2>/dev/null)
            if [ "$U" = "0" ]; then
                echo "worker pid=$p 仍是 uid=0，降权未生效" >&2; BAD=1
            elif [ "$U" != "$WORKER_UID" ]; then
                echo "worker pid=$p uid=$U，与期望 $WORKER_UID 不符" >&2; BAD=1
            else
                say "worker pid=$p uid=$U（已降权）"
            fi
            ;;
    esac
done

if [ "$NMASTER" -eq 0 ]; then
    echo "nginx 一个进程都没有 —— 服务没起来" >&2; BAD=1
elif [ "$NWORKER" -eq 0 ]; then
    echo "没有 worker 进程" >&2; BAD=1
fi

if [ "$BAD" != "0" ]; then
    echo "降权未达成，回滚 $CONF" >&2
    cp -p "$BK" "$CONF"
    # 回滚同样必须 restart：reload 不会把 worker 的 uid 改回去
    if [ "$CHANGED" = "1" ]; then
        /etc/init.d/nginx stop 2>/dev/null || true
        sleep 1
        /etc/init.d/nginx start 2>/dev/null || true
    else
        nginx -s reload 2>/dev/null || true
    fi
    exit 1
fi

echo "nginx worker 降权完成（master $NMASTER 个 uid=0，worker $NWORKER 个 uid=$WORKER_UID）"