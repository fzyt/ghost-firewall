#!/bin/sh
# =============================================================================
# 三个安全修复的真机复验
#
#   P1  域名型 target 解析不通 → 必须 400，且不得落盘
#   P2  重新登录              → 旧令牌必须立即失效
#   P3  /auth/status          → 必须限流，且响应体不含认证方式标记
#
# 全程只读 + 一次必然失败的写入尝试（不通域名），不改动任何配置。
# 用法: ./verify-fixes.sh        退出码 0 = 三项全过
# =============================================================================

PANEL="https://127.0.0.1:5443"
GW="https://127.0.0.1:8443"
AUTH="http://127.0.0.1:8444"
CONFIG="/etc/nftables/nftables-web-config.json"
PASSWORD="${NF_PASSWORD:-TestGW2026}"
RUN="/tmp/nf-verify"

ok=0; bad=0
ok()   { ok=$((ok+1));   echo "  ✅ $*"; }
bad()  { bad=$((bad+1)); echo "  ❌ $*"; }

mkdir -p "$RUN"
trap 'rm -f "$RUN/cookies" "$RUN/resp"' EXIT

echo ""
echo "════ 三个安全修复 · 真机复验 ════"

# ── P1 ────────────────────────────────────────────────────────────
echo ""
echo "── P1  域名型 target 解析不通必须被拒 ──"
curl -sk -c "$RUN/cookies" -X POST -H 'Content-Type: application/json' \
     -d "{\"password\":\"${PASSWORD}\"}" "${PANEL}/api/auth/login" >/dev/null

CODE=$(curl -sk -b "$RUN/cookies" -o "$RUN/resp" -w '%{http_code}' \
       -X POST -H 'Content-Type: application/json' \
       -d '{"name":"verify","path_prefix":"/vtest",
            "target_address":"no-such-host-nf-verify.invalid:80",
            "target_protocol":"http"}' \
       "${PANEL}/api/reverse-proxy/rules")
if [ "$CODE" = "400" ]; then
    ok "解析不通的域名被拒（HTTP 400）"
else
    bad "解析不通的域名被拒（实际 HTTP ${CODE}）"
fi
if grep -q "no-such-host-nf-verify.invalid" "$RUN/resp" 2>/dev/null; then
    ok "错误信息点名了主机名"
else
    bad "错误信息没有点名主机名：$(head -c 90 "$RUN/resp")"
fi
LEFT=$(python3 -c "
import json
d = json.load(open('$CONFIG'))
print(','.join(r['path_prefix'] for r in d.get('reverse_proxy', {}).get('rules', [])))
" 2>/dev/null)
case "$LEFT" in
    */vtest*|*vtest*) bad "毒规则落盘了：${LEFT}" ;;
    *)              ok "毒规则没有落盘（当前规则：${LEFT}）" ;;
esac

# ── P2 ────────────────────────────────────────────────────────────
echo ""
echo "── P2  重新登录必须吊销旧令牌 ──"
RESULT=$(cd "$RUN" && python3 - <<'PYEOF' 2>/dev/null
import ssl, urllib.request, urllib.error, json
from http.cookiejar import CookieJar, Cookie
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
GW, PW = "https://127.0.0.1:8443", "TestGW2026"

def call(o, u, m="GET", b=None, h=None):
    d = json.dumps(b).encode() if b else None
    hh = {"Content-Type": "application/json"}
    if h:
        hh.update(h)
    r = urllib.request.Request(u, data=d, method=m, headers=hh)
    try:
        x = o.open(r, timeout=15)
        return x.status, x.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

jar = CookieJar()
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                urllib.request.HTTPCookieProcessor(jar))
s, _ = call(o, GW + "/auth/login", "POST", {"password": PW}, {"Origin": GW})
t1 = next((c.value for c in jar if c.name == "gw_token"), None)
if not t1:
    print("LOGIN_FAIL")
    raise SystemExit
call(o, GW + "/auth/login", "POST", {"password": PW}, {"Origin": GW})
j2 = CookieJar()
j2.set_cookie(Cookie(version=0, name="gw_token", value=t1, port=None,
                     port_specified=False, domain="127.0.0.1", domain_specified=False,
                     domain_initial_dot=False, path="/", path_specified=True,
                     secure=True, expires=None, discard=True, comment=None,
                     comment_url=None, rest={"HttpOnly": None}, rfc2109=False))
oo = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                 urllib.request.HTTPCookieProcessor(j2))
s, b = call(oo, GW + "/auth/status")
try:
    print("STILL_VALID" if json.loads(b).get("authenticated") is True else "REVOKED")
except Exception:
    print("PARSE_FAIL")
PYEOF
)
case "$RESULT" in
    REVOKED)   ok "重新登录后旧令牌已失效" ;;
    STILL_VALID) bad "旧令牌仍然有效 —— P2 未生效" ;;
    LOGIN_FAIL)  bad "拿不到登录令牌，无法验证（确认面板密码 / NF_PASSWORD）" ;;
    *)           bad "验证脚本异常：${RESULT}" ;;
esac

# ── P3 ────────────────────────────────────────────────────────────
echo ""
echo "── P3  /auth/status 限流且不泄露认证方式 ──"
# 先看响应体，再打限流 —— 顺序反了的话，等下取到的是 429 的 body，
# 429 本来就不含 via，那样这条断言永远是绿的，等于没测。
BODY=$(curl -sk --max-time 5 "${AUTH}/auth/status")
case "$BODY" in
    *RATE_LIMITED*) bad "限流窗口还没恢复（连打前就被限流），等 60 秒后重跑" ;;
    *via*|*lan-bypass*) bad "响应体仍含认证方式标记：${BODY}" ;;
    *)                  ok "响应体不含 via / lan-bypass：${BODY}" ;;
esac

C200=0; C429=0; N=130
i=0
while [ $i -lt $N ]; do
    C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "${GW}/auth/status")
    [ "$C" = "200" ] && C200=$((C200+1))
    [ "$C" = "429" ] && C429=$((C429+1))
    i=$((i+1))
done
if [ "$C429" -gt 0 ] && [ "$C200" -gt 0 ]; then
    ok "限流生效（放行 ${C200} 次, 拦下 ${C429} 次）"
elif [ "$C429" -gt 0 ]; then
    bad "全程都是 429，放行为 0 —— 可能是上一轮限流没恢复，没测到正常路径"
else
    bad "连打 ${N} 次没有任何 429 —— 限流未生效"
fi

echo ""
echo "────────────────────────────────"
echo "通过 ${ok} / $((ok + bad))"
if [ "$bad" -ne 0 ]; then
    echo "有修复未生效或已回归"
    exit 1
fi
echo "三个修复在真机上全部生效"
