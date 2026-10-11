#!/bin/sh
# =============================================================================
# 反代测试台：一键起一个临时后端 + 在认证网关上注册一条反代服务
#
# 设计要点：
#   * 后端只绑 127.0.0.1 —— 直连这条路从一开始就不存在，
#     任何「访问成功」都只可能来自网关转发，测试才有意义
#   * 后端记录每一笔请求到日志 —— 绕过能被证明，而不是只看状态码
#   * 服务名和前缀可指定，默认值互不冲突，方便反复起停
#
# 用法：
#   ./rp-testbed.sh up      启动临时后端 + 创建反代规则
#   ./rp-testbed.sh status  查看当前状态
#   ./rp-testbed.sh down    删除反代规则 + 停掉临时后端
#   ./rp-testbed.sh hits    查看临时后端收到过哪些请求（绕过证据）
# =============================================================================

PANEL="https://127.0.0.1:5443"
PASSWORD="${NF_PASSWORD:-TestGW2026}"
PORT="${NF_PORT:-15099}"
PREFIX="${NF_PREFIX:-/probe}"
NAME="${NF_NAME:-穿透测试台}"
BACKEND="127.0.0.1:${PORT}"
RUN="/tmp/nf-testbed"
LOG="${RUN}/hits.log"
PIDF="${RUN}/backend.pid"

ok()   { echo "  ✅ $*"; }
bad()  { echo "  ❌ $*"; }
info() { echo "     $*"; }

ensure_run_dir() {
    [ -d "$RUN" ] || mkdir -p "$RUN"
}

# ---- 临时后端 ---------------------------------------------------------------
# 只绑回环。命中时返回可识别的标记串，响应头带 X-Probe-Hit，
# 这样「拿到 200 且带这个头」= 请求真的到了后端。
start_backend() {
    ensure_run_dir
    if [ -f "$PIDF" ] && kill -0 "$(cat $PIDF)" 2>/dev/null; then
        info "临时后端已在运行 (PID $(cat $PIDF))"
        return 0
    fi
    : > "$LOG"
    python3 - "$PORT" "$LOG" <<'PYEOF' &
import sys, http.server, socketserver, datetime

PORT = int(sys.argv[1])
LOG = sys.argv[2]
MARK = "PROBE-BACKEND-HIT-7f3a9c2e"

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self):
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        ua = self.headers.get("User-Agent", "-")
        with open(LOG, "a") as f:
            f.write("%s  %s %s  ua=%s\n" % (ts, self.command, self.path, ua[:80]))

    def do_GET(self):
        self._record()
        body = ("<!doctype html><meta charset=utf-8>"
                "<h1>%s</h1><p>临时后端，仅供反代穿透测试。</p>" % MARK).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Probe-Hit", MARK)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.do_GET()

    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", PORT), H) as httpd:
    httpd.serve_forever()
PYEOF
    echo $! > "$PIDF"
    sleep 1
    if kill -0 "$(cat $PIDF)" 2>/dev/null; then
        ok "临时后端已启动 127.0.0.1:${PORT}  (PID $(cat $PIDF))"
    else
        bad "临时后端启动失败"
        return 1
    fi
}

stop_backend() {
    if [ -f "$PIDF" ]; then
        PID=$(cat "$PIDF")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null
            sleep 1
            ok "临时后端已停止 (PID $PID)"
        fi
        rm -f "$PIDF"
    else
        info "临时后端未在运行"
    fi
}

# ---- 面板 API 封装 ----------------------------------------------------------
api() {
    # $1=方法 $2=路径 $3=JSON 体（可空）
    if [ -n "$3" ]; then
        curl -sk -X "$1" "${PANEL}$2" \
             -H 'Content-Type: application/json' \
             -b "$RUN/cookies" -c "$RUN/cookies" \
             --max-time 20 -d "$3"
    else
        curl -sk -X "$1" "${PANEL}$2" \
             -H 'Content-Type: application/json' \
             -b "$RUN/cookies" -c "$RUN/cookies" \
             --max-time 20
    fi
}

login() {
    ensure_run_dir
    curl -sk -X POST "${PANEL}/api/auth/login" \
         -H 'Content-Type: application/json' \
         -c "$RUN/cookies" --max-time 15 \
         -d "{\"password\":\"${PASSWORD}\"}" >/dev/null
    api GET /api/reverse-proxy/rules >/dev/null 2>&1 \
        && ok "面板登录成功" \
        || { bad "面板登录失败"; return 1; }
}

find_rule_id() {
    api GET /api/reverse-proxy/rules \
      | tr ',' '\n' \
      | grep -B2 "\"path_prefix\":\"${PREFIX}\"" \
      | grep '"id"' \
      | head -1 \
      | sed 's/.*"id":"\([^"]*\)".*/\1/'
}

create_rule() {
    RULE_ID=$(find_rule_id)
    if [ -n "$RULE_ID" ]; then
        info "已存在前缀 ${PREFIX} 的规则 ($RULE_ID)，先删除"
        api DELETE "/api/reverse-proxy/rules/${RULE_ID}" >/dev/null
    fi
    RESP=$(api POST /api/reverse-proxy/rules \
      "{\"name\":\"${NAME}\",\"path_prefix\":\"${PREFIX}\",
        \"target_address\":\"${BACKEND}\",\"target_protocol\":\"http\",
        \"public_access\":true,\"websocket_enabled\":true,
        \"client_max_body_size\":\"10M\",\"icon\":\"🔬\"}")
    if echo "$RESP" | grep -q '"success":true'; then
        RID=$(echo "$RESP" | tr ',' '\n' | grep rule_id | head -1 | sed 's/.*"rule_id":"\([^"]*\)".*/\1/')
        ok "反代规则已创建  id=${RID}"
        ok "访问地址：https://<网关地址>${PREFIX}/   →  ${BACKEND}"
        echo "$RID" > "${RUN}/rule.id"
    else
        bad "创建失败: $(echo "$RESP" | head -c 200)"
        return 1
    fi
}

case "$1" in
  up)
    echo ""
    echo "──── 启动反代测试台 ────"
    start_backend && login && create_rule
    echo ""
    echo "  测试要点：后端只绑 127.0.0.1，公网/内网都无法直连。"
    echo "  任何访问成功都必须经过网关的 auth_request。"
    echo ""
    ;;
  down)
    echo ""
    echo "──── 关闭反代测试台 ────"
    login >/dev/null 2>&1
    if [ -f "${RUN}/rule.id" ]; then
        RID=$(cat "${RUN}/rule.id")
        api DELETE "/api/reverse-proxy/rules/${RID}" >/dev/null && ok "反代规则 ${RID} 已删除"
        rm -f "${RUN}/rule.id"
    else
        RID=$(find_rule_id)
        [ -n "$RID" ] && { api DELETE "/api/reverse-proxy/rules/${RID}" >/dev/null; ok "反代规则 ${RID} 已删除"; }
    fi
    stop_backend
    echo ""
    ;;
  status)
    echo ""
    echo "──── 测试台状态 ────"
    if [ -f "$PIDF" ] && kill -0 "$(cat $PIDF)" 2>/dev/null; then
        ok "临时后端运行中 (PID $(cat $PIDF))  ${BACKEND}"
    else
        bad "临时后端未运行"
    fi
    login >/dev/null 2>&1
    RID=$(find_rule_id)
    [ -n "$RID" ] && ok "反代规则存在 id=${RID} 前缀=${PREFIX}" || bad "无对应反代规则"
    curl -sk "https://127.0.0.1:5443/api/gateway/status" -b "$RUN/cookies" --max-time 10 \
      | head -c 200; echo
    echo ""
    ;;
  hits)
    echo ""
    echo "──── 临时后端收到的请求（绕过证据）────"
    if [ -s "$LOG" ]; then
        cat "$LOG"
        info "共 $(wc -l < "$LOG") 笔"
    else
        info "后端一次都没被访问到 —— 说明没有任何请求穿透网关"
    fi
    echo ""
    ;;
  *)
    echo "用法: $0 {up|down|status|hits}"
    exit 1
    ;;
esac
