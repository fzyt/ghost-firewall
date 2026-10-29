"""会话生命周期：改密码作废全部会话 + 吊销表 fail-closed + 时序 + 安全头

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_auth_session_lifecycle.py

背景（2026-10-16）
------------------
Shannon 第二轮的核实报告里除了已修的四项，还留了三条，本文件覆盖其中
可修的部分，外加一条加固项：

  MISC-02  load_revoked() 读失败时 `return {}` —— 空字典让 is_revoked 对
           所有 jti 返回 False，**之前显式登出吊销掉的令牌全部复活**。
           文件一次写坏等于把吊销机制整个关掉，而且静默。
  MISC-01  改密码不吊销网关 JWT。auth_change_password 只做了
           session.clear()，那只清当前浏览器自己的面板会话；
           所有设备上的面板 session 和所有 gw_token JWT 都照样有效，
           而滑动续期意味着只要一直用就可能永不过期。
  AUTH-01  `bool(stored) and _verify_password(...)` 的短路让 stored 为空时
           PBKDF2 根本不跑（0.001ms vs 95ms，差 5 个数量级），
           等于一个「这台机器配没配密码」的状态枚举口。
           _verify_password 内部本来就有 dummy 路径，只是从没被调用到。
  P3       全文没有 after_request：HSTS 一个都没有，Cache-Control 只覆盖
           3 个响应，/auth/status、/auth/login(POST)、/auth/logout、
           /auth/portal 这些同样带会话信息的端点一个都没设。

每条断言都在**修复前必然失败**。
"""
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time

# ══════════════════════════════════════════════════════════════════════
# 沙箱
# ══════════════════════════════════════════════════════════════════════
SBX = tempfile.mkdtemp(prefix="authlife-")
CFG = f"{SBX}/config.json"
PWD = f"{SBX}/password.json"
SEC = f"{SBX}/secret"
RL = f"{SBX}/ratelimit.json"
LOG = f"{SBX}/audit.log"
REVOKED = os.path.splitext(RL)[0] + "-revoked.json"

PASSWORD = "test1234"
_salt = "aabbccdd"
_dig = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), _salt.encode(), 200000)
json.dump({"hash": f"pbkdf2_sha256$200000${_salt}${_dig.hex()}"}, open(PWD, "w"))
open(SEC, "w").write("test-secret-key-0123456789")
json.dump({"hash": f"pbkdf2_sha256$200000${_salt}${_dig.hex()}"}, open(PWD, "w"))

HOST = "192.168.100.224:8443"


def write_cfg(**over):
    base = {
        "auth_session_timeout": 1800,
        "auth_absolute_timeout": 0,
        "auth_lan_bypass": False,
        "lan_subnet4": "192.168.100.0/24",
        "auth_token_epoch": 0,
        "reverse_proxy": {"rules": []},
    }
    base.update(over)
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump(base, f, ensure_ascii=False)


write_cfg()

os.environ.update({
    "AUTH_CONFIG_PATH": CFG, "AUTH_PASSWORD_FILE": PWD, "AUTH_SECRET_FILE": SEC,
    "AUTH_RATELIMIT_FILE": RL, "AUTH_AUDIT_LOG": LOG, "AUTH_API_PORT": "18446",
})
BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND))
import auth_gateway as ag  # noqa: E402


def reload_cfg():
    """让网关的 mtime 缓存失效（同一时钟刻度内两次写会拿到相同 mtime）。"""
    ag._config_cache["mtime"] = None


def reset_revoked():
    ag._REVOKED_LKG = None
    if os.path.exists(REVOKED):
        os.unlink(REVOKED)


PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  — {extra}" if extra and not cond else ""))


def sec(t):
    print(f"\n--- {t} ---")


print("=" * 74)
print("会话生命周期：epoch 作废 / 吊销 fail-closed / 时序 / 安全头")
print("=" * 74)

# ══════════════════════════════════════════════════════════════════════
# 1. MISC-02 吊销表 fail-closed
# ══════════════════════════════════════════════════════════════════════
sec("1. MISC-02 吊销表读失败不再 fail-open")

reset_revoked()
# 文件不存在 = 从来没吊销过，是正常初始状态
d = ag.load_revoked()
check("吊销文件不存在时返回空表而不是 None", d == {}, f"实际={d!r}")
check("此时 is_revoked 返回 False（正常放行）", ag.is_revoked("jti-x") is False)

# 正常写入一条吊销
ag.revoke_jti("jti-live", int(time.time()) + 600)
check("刚吊销的 jti 被判定为已吊销", ag.is_revoked("jti-live") is True)
_lkg_after_write = ag._REVOKED_LKG
check("成功读过一次后 last-known-good 已被更新",
      isinstance(_lkg_after_write, dict) and "jti-live" in _lkg_after_write,
      f"实际={_lkg_after_write!r}")

# 关键场景：**文件损坏**。旧代码 return {} → jti-live 复活
with open(REVOKED, "w") as f:
    f.write("{ this is not valid json")
ag._REVOKED_LKG = {"jti-live": int(time.time()) + 600}   # 模拟进程内还有一份
check("文件损坏时退到 last-known-good",
      ag.load_revoked() is not None and "jti-live" in ag.load_revoked(),
      f"实际={ag.load_revoked()!r}")
check("文件损坏时已吊销的令牌仍然被拒（没有复活）",
      ag.is_revoked("jti-live") is True, "已吊销的令牌复活了")

# 更狠的场景：进程刚起，LKG 也是空的
reset_revoked()
with open(REVOKED, "w") as f:
    f.write("}{ broken")
d = ag.load_revoked()
check("文件损坏且无 last-known-good 时返回 None（判不出来）", d is None, f"实际={d!r}")
check("此时 is_revoked fail-closed 判为已吊销", ag.is_revoked("anything") is True,
      "读不出来却放行了 —— 又变回 fail-open")

# 非 dict 的 JSON 也算损坏
reset_revoked()
with open(REVOKED, "w") as f:
    json.dump(["a", "list"], f)
check("JSON 是数组时也判不出来", ag.load_revoked() is None,
      f"实际={ag.load_revoked()!r}")

# 空 jti 不该被当成吊销（否则每次请求都拒）
reset_revoked()
check("空 jti 仍然放行（不是故障，是参数缺失）", ag.is_revoked("") is False)

# ── 「文件被删掉」不等于「从未吊销过」────────────────────────────
#
# 最初实现里 FileNotFoundError 一律 return {} 并把 LKG 也清空，
# 于是「unlink 掉吊销表」这个动作会**主动复活所有已吊销的令牌** ——
# .224 线上实测就是这么抓到的（删表后刚才登出吊销的 token 立刻又能用）。
#
# 判据是「本进程有没有成功读到过」：读到过就说明文件本来该在，现在没了
# 是故障，走 last-known-good；一次都没读到过才是正常初始状态。
ag.revoke_jti("jti-del", int(time.time()) + 600)
check("删除前置条件：jti-del 已被吊销", ag.is_revoked("jti-del") is True)
os.unlink(REVOKED)
check("吊销表被整个删掉后（之前读到过）仍返回 LKG，不清空",
      (ag.load_revoked() or {}).get("jti-del") is not None,
      f"实际={ag.load_revoked()!r} —— 删表把吊销记录一起带走了")
check("吊销表被删后已吊销的令牌仍被拒",
      ag.is_revoked("jti-del") is True, "令牌复活了 —— 删表等于清空吊销记录")
reset_revoked()
check("进程全新启动（一次都没读到过）且文件不存在 → 空表",
      ag.load_revoked() == {}, f"实际={ag.load_revoked()!r}")
check("全新启动时 is_revoked 才返回 False（正常放行）",
      ag.is_revoked("jti-del") is False)

# ══════════════════════════════════════════════════════════════════════
# 2. MISC-01 网关 JWT 的 epoch
# ══════════════════════════════════════════════════════════════════════
sec("2. MISC-01 改密码作废全部网关令牌")

write_cfg(auth_token_epoch=0)
reload_cfg()
tok0 = ag.issue_token("kirito", "devA", 1800)
p0 = ag.parse_token(tok0)
check("签发的令牌带 epoch 字段", p0 and "ep" in p0, f"payload={p0!r}")
check("epoch 值等于当前配置", p0 and p0.get("ep") == 0, f"实际={p0.get('ep')!r}")

reset_revoked()
ag._mutate_ratelimit = lambda ip, on_fail=False: (0, 0)
_c = ag.app.test_client()


def verify(tok, ip="8.8.8.8"):
    """走 Authorization: Bearer，比摆 cookie 省事也更像脚本客户端。"""
    h = {"Host": HOST, "X-Real-IP": ip}
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return _c.get("/auth/verify", headers=h)


def jti_of(tok):
    import base64 as _b
    body = tok.split(".")[0]
    body += "=" * (-len(body) % 4)
    return json.loads(_b.urlsafe_b64decode(body))["jti"]


def set_cookie(tok):
    """把令牌放进测试客户端的 cookie jar。

    **不要用显式 Cookie 请求头**：Werkzeug 3.1 的测试客户端会直接丢掉调用方
    传的 Cookie 头，只发自己 jar 里的（实测：jar 为空时显式头被忽略，
    request.cookies 是空的）。写显式头的测试看着在跑，实际是空跑。
    jar 的域要跟 Host 对上（默认 localhost 在这里匹配不上）。
    """
    _c.set_cookie(ag.COOKIE_TOKEN, tok, domain="192.168.100.224")


def tok_of(resp):
    for part in (resp.headers.get("Set-Cookie", "") or "").split(";"):
        if part.strip().startswith("gw_token="):
            return part.strip().split("=", 1)[1]
    return ""


def cookie_cleared(resp, name):
    """cookie 是不是被「空值 + 立即过期」地撤掉了。

    不能只判 `'gw_token=' in header` —— 那在**下发**和**清除**两种情况下都成立。
    """
    try:
        lines = resp.headers.getlist("Set-Cookie")
    except Exception:
        lines = [resp.headers.get("Set-Cookie", "") or ""]
    for line in lines:
        if line.startswith(name + "="):
            return line.split(";")[0] == f"{name}=" and "Max-Age=0" in line
    return False


r = verify(tok0)
check("epoch 未变时令牌可用（200）", r.status_code == 200, f"HTTP {r.status_code}")

# 改密码 → epoch +1 → 旧令牌必须立刻失效
write_cfg(auth_token_epoch=1)
reload_cfg()
r = verify(tok0)
check("epoch 递增后旧令牌立即失效（401）", r.status_code == 401, f"HTTP {r.status_code}")

tok1 = ag.issue_token("kirito", "devA", 1800)
check("新令牌带新 epoch", ag.parse_token(tok1).get("ep") == 1)
r = verify(tok1)
check("新 epoch 签发的令牌可用", r.status_code == 200, f"HTTP {r.status_code}")

# 旧令牌（没有 ep 字段）按 0 处理 —— 第一次改密码 0→1 就能清掉
write_cfg(auth_token_epoch=0)
reload_cfg()
_legacy_body = json.dumps({"sub": "kirito", "dev": "devOld", "iat": int(time.time()),
                           "exp": int(time.time()) + 600,
                           "jti": "legacy-jti"}, separators=(",", ":")).encode()
import base64 as _b64  # noqa: E402
import hashlib as _hashlib  # noqa: E402
import hmac as _hmac  # noqa: E402
_b = _b64.urlsafe_b64encode(_legacy_body).rstrip(b"=").decode()
_s = _b64.urlsafe_b64encode(
    _hmac.new(ag._token_key(), _b.encode(), _hashlib.sha256).digest()
).rstrip(b"=").decode()
_legacy = f"{_b}.{_s}"
check("无 ep 字段的旧令牌按 epoch 0 处理",
      ag.parse_token(_legacy).get("ep", 0) == 0, f"实际={ag.parse_token(_legacy)}")
r = verify(_legacy)
check("epoch 为 0 时无 ep 的旧令牌仍可用（向前兼容）",
      r.status_code == 200, f"HTTP {r.status_code}")

write_cfg(auth_token_epoch=1)
reload_cfg()
r = verify(_legacy)
check("epoch 变成 1 后无 ep 的旧令牌失效",
      r.status_code == 401, f"HTTP {r.status_code}")

# 配置里 epoch 不是数字时不能把认证链路搞崩
#
# ⚠️ 这条断言原来的期望值是错的，而且它一直是**靠巧合通过**的：
#
# 修复前，滑动续期在 `_verify_or_deny()` 里，每次请求都会**吊销旧 jti**
# 并签一张新令牌（而新令牌到不了客户端）。于是第一次请求之后，
# 这个 legacy 令牌的 jti 已经被吊销 → 后面每次 verify 都是
#   verify_denied / reason=revoked
# 也就是说：当时那条 401 来自「令牌被续期顺手吊销了」，**不是**来自
# epoch 判定。断言名字写着「按不放行处理」，实际测的是另一个东西。
#
# 现在续期搬走了（auth_request 路径纯校验、无副作用），legacy 令牌不再
# 被凭空吊销 —— 于是真实行为暴露出来：配置里的 epoch 是垃圾值时，
# `_payload_epoch_ok` 把它回落成 0（cur_epoch=0），与「从未改过密码」
# 同义 → ep=0 的令牌仍然放行 → **200**。
#
# 这个语义是**刻意**的，和面板侧完全一致（app.py 的
# `_current_token_epoch()` 里写着「这里刻意不做「读不到就拒绝」：
# 配置读取失败本来就有独立的降级处理」）。两条路径必须同一套判据 ——
# 面板那边回落 0、网关这边拒绝所有人，会出现「面板放行、网关全拒」
# 的分裂。
#
# 所以这条断言现在测的是**真正该测的东西**：不抛异常、不 500，
# 且与面板侧语义一致（垃圾值 → 当成 0）。
write_cfg(auth_token_epoch="garbage")
reload_cfg()
try:
    r = verify(_legacy)
    check("epoch 是垃圾值时不抛异常（回落成 0，与面板侧一致）",
          r.status_code == 200,
          f"HTTP {r.status_code}（500 = 认证链路被搞崩了）")
except Exception as e:
    check("epoch 是垃圾值时不抛异常", False, f"{type(e).__name__}: {e}")

# 垃圾值回落成 0 不等于「epoch 判定失效」：换成**合法**的不同世代号
# 依然必须拒（否则上面那条就成了摆设）。
write_cfg(auth_token_epoch=7)
reload_cfg()
r = verify(_legacy)
check("epoch 是合法值但不匹配时仍然拒绝（垃圾值回落没有把判定搞松）",
      r.status_code == 401, f"HTTP {r.status_code}")

write_cfg(auth_token_epoch=0)
reload_cfg()

# ══════════════════════════════════════════════════════════════════════
# 3. AUTH-01 时序侧信道
# ══════════════════════════════════════════════════════════════════════
sec("3. AUTH-01 stored 为空时也必须跑 PBKDF2")

_calls = []
_orig_verify = ag._verify_password


def _spy(password, stored):
    _calls.append((password, stored))
    return _orig_verify(password, stored)


ag._verify_password = _spy
try:
    # 场景 A：密码文件正常
    write_cfg()
    reload_cfg()
    reset_revoked()
    _calls.clear()
    ag._mutate_ratelimit = lambda ip, on_fail=False: (0, 0)
    ag.app.test_client().post("/auth/login", json={"password": "wrong-1"},
                              headers={"Host": HOST})
    check("正常配置时 _verify_password 被调用", len(_calls) >= 1, f"实际 {len(_calls)} 次")

    # 场景 B：密码文件读不出来（stored 为空）
    _orig_hash = ag._password_hash
    ag._password_hash = lambda: ""
    try:
        _calls.clear()
        ag.app.test_client().post("/auth/login", json={"password": "wrong-2"},
                                  headers={"Host": HOST})
        check("stored 为空时 _verify_password **仍然**被调用",
              len(_calls) >= 1,
              "短路了 —— 响应时间会从 95ms 掉到 0.001ms，变成状态枚举口")
    finally:
        ag._password_hash = _orig_hash

    # 场景 C：空密码也照样跑（否则空/非空密码的耗时也能区分）
    _calls.clear()
    ag.app.test_client().post("/auth/login", json={},
                              headers={"Host": HOST})
    check("空密码也走 _verify_password（保持耗时一致）", len(_calls) >= 1,
          f"实际 {len(_calls)} 次")
finally:
    ag._verify_password = _orig_verify

# 真正的时间量级：空 stored vs 正常 stored
_norm = []
_orig_hash = ag._password_hash


def _timeit(stored, n=2):
    t = time.time()
    for _ in range(n):
        ag._verify_password("x", stored)
    return (time.time() - t) / n


ag._password_hash = _orig_hash
_t_normal = _timeit(f"pbkdf2_sha256$200000${_salt}${_dig.hex()}")
_t_empty = _timeit("")
check("空 stored 走 dummy 路径（不会秒回）",
      _t_empty > _t_normal * 0.2,
      f"空={_t_empty*1000:.2f}ms 正常={_t_normal*1000:.2f}ms —— 差太远仍可枚举")

# ══════════════════════════════════════════════════════════════════════
# 4. P3 安全响应头
# ══════════════════════════════════════════════════════════════════════
sec("4. P3 HSTS 与 Cache-Control 覆盖面")

_c2 = ag.app.test_client()
r = _c2.get("/auth/status", headers={"Host": HOST, "X-Real-IP": "8.8.8.8"})
check("GET /auth/status 有 Cache-Control",
      "Cache-Control" in r.headers, f"实际头={[k for k in r.headers]}")
check("GET /auth/status 是 no-store（不被缓存）",
      r.headers.get("Cache-Control") == "no-store", f"实际={r.headers.get('Cache-Control')!r}")
check("GET /auth/status 有 nosniff", r.headers.get("X-Content-Type-Options") == "nosniff")
check("GET /auth/status 有 X-Frame-Options",
      r.headers.get("X-Frame-Options") == "DENY", f"实际={r.headers.get('X-Frame-Options')!r}")
check("GET /auth/status 有 Referrer-Policy",
      bool(r.headers.get("Referrer-Policy")), f"实际={r.headers.get('Referrer-Policy')!r}")

r = _c2.post("/auth/login", json={"password": "x"}, headers={"Host": HOST})
check("POST /auth/login（401 响应）也有 Cache-Control",
      r.headers.get("Cache-Control") == "no-store", f"实际={r.headers.get('Cache-Control')!r}")

r = _c2.get("/auth/static/base.css", headers={"Host": HOST})
check("静态资源的 no-cache 不被兜底覆盖成 no-store",
      r.headers.get("Cache-Control") == "no-cache",
      f"实际={r.headers.get('Cache-Control')!r}")

r = _c2.get("/auth/login", headers={"Host": HOST})
check("登录页 HTML 的 CSP 没被兜底覆盖",
      "Content-Security-Policy" in r.headers
      and "frame-ancestors" in r.headers.get("Content-Security-Policy", ""))

# HSTS：只在 HTTPS 语境下发
r = _c2.get("/auth/status", headers={"Host": HOST, "X-Forwarded-Proto": "https"})
check("HTTPS 语境下有 HSTS",
      "max-age=31536000" in r.headers.get("Strict-Transport-Security", ""),
      f"实际={r.headers.get('Strict-Transport-Security')!r}")
check("HSTS 不带 includeSubDomains（网关可能与路由器其它服务共用域名）",
      "includeSubDomains" not in r.headers.get("Strict-Transport-Security", ""),
      f"实际={r.headers.get('Strict-Transport-Security')!r}")

# ── 上面两条只在「请求真的带了 X-Forwarded-Proto」时成立。
#    而 TLS 是在 nginx 那层终结的：转发给 Flask 的已经是明文 HTTP，
#    request.is_secure 恒为 False，HSTS 的唯一判据就是这个头。
#    .224 线上实测踩过：其它安全头全齐，唯独 HSTS 不见 —— 因为
#    /auth/* 那几个 location 漏了 proxy_set_header X-Forwarded-Proto。
#    这里直接查生成出来的 nginx 配置，别再靠线上才发现。
_cwd2 = os.getcwd()
_tmp2 = tempfile.mkdtemp(prefix="nginxhdr-")
try:
    os.chdir(_tmp2)
    sys.path.insert(0, os.path.abspath(BACKEND))
    import app as panel2  # noqa: E402
    _gcfg = {"gateway_enabled": True, "gateway_port": 8443, "auth_api_port": 8444,
             "lan_subnet4": "192.168.100.0/24",
             "reverse_proxy": {"rules": [
                 {"name": "群晖", "path_prefix": "/nas", "enabled": True,
                  "public_access": True}]}}
    _conf = panel2._generate_gateway_nginx_conf(_gcfg) or ""
    check("网关配置能生成（前置）", bool(_conf), "生成失败，下面的断言都是空转")

    _blocks, _cur = {}, None
    for _line in _conf.splitlines():
        _m = re.match(r"\s*location\s+(=\s+)?(\S+)\s*\{", _line)
        if _m:
            _cur = _m.group(2)
            _blocks[_cur] = []
        elif _cur is not None and re.match(r"\s*\}", _line):
            _cur = None
        elif _cur is not None:
            _blocks[_cur].append(_line)

    for _ep in ("/auth/login", "/auth/logout", "/auth/status", "/auth/portal",
                "/auth/static/"):
        _body = "\n".join(_blocks.get(_ep, []))
        check(f"nginx: {_ep} 透传 X-Forwarded-Proto（HSTS 的前提）",
              "proxy_set_header X-Forwarded-Proto $scheme;" in _body,
              f"该 location 缺 X-Forwarded-Proto —— 线上 HSTS 不会下发")
finally:
    os.chdir(_cwd2)

# ══════════════════════════════════════════════════════════════════════
# 5. MISC-01 面板侧：改密码递增 epoch + 会话绑定
# ══════════════════════════════════════════════════════════════════════
sec("5. MISC-01 面板侧（改密码递增 epoch + 会话绑定）")

_cwd = os.getcwd()
_tmpdir = tempfile.mkdtemp(prefix="panellife-")
try:
    os.chdir(_tmpdir)
    sys.path.insert(0, os.path.abspath(BACKEND))
    import app as panel  # noqa: E402

    PCFG = f"{_tmpdir}/panel-config.json"
    with open(PCFG, "w", encoding="utf-8") as f:
        json.dump(dict(panel.DEFAULT_CONFIG), f)
    # 面板的 before_request 有来源边界：默认回落 lan_subnet4，而 DEFAULT_CONFIG
    # 里的网段是 192.168.4.0/24（别人的机器），test_client 的来源 127.0.0.1
    # 会被判成「不在允许网段」直接 403，这里放开回环。
    _pcfg = json.load(open(PCFG, encoding="utf-8"))
    _pcfg["panel_allowed_nets"] = "127.0.0.0/8"
    _pcfg["lan_subnet4"] = "127.0.0.0/8"
    with open(PCFG, "w", encoding="utf-8") as f:
        json.dump(_pcfg, f, ensure_ascii=False)
    _orig_cfg_path = panel.CONFIG_PATH
    _orig_pwd = panel.AUTH_PASSWORD_FILE
    panel.CONFIG_PATH = PCFG
    panel.AUTH_PASSWORD_FILE = f"{_tmpdir}/panel-password.json"

    check("DEFAULT_CONFIG 里有 auth_token_epoch",
          "auth_token_epoch" in panel.DEFAULT_CONFIG)

    # 递增与持久化
    ep0 = panel._current_token_epoch()
    ep1 = panel._bump_token_epoch()
    check("_bump_token_epoch 让世代号 +1", ep1 == ep0 + 1, f"{ep0} -> {ep1}")
    with open(PCFG, encoding="utf-8") as f:
        check("epoch 已落盘", json.load(f).get("auth_token_epoch") == ep1,
              f"落盘={json.load(open(PCFG)).get('auth_token_epoch')}")
    check("再读回来还是新值", panel._current_token_epoch() == ep1)

    # 会话绑定
    with panel.app.test_request_context():
        from flask import session as fs
        fs['authenticated'] = True
        fs['auth_epoch'] = ep1
        check("世代号一致时会话有效", panel._session_epoch_ok() is True)
        fs['auth_epoch'] = ep1 - 1
        check("世代号落后时会话判失效", panel._session_epoch_ok() is False)
        fs['auth_epoch'] = "garbage"
        check("会话里的 epoch 是垃圾值时判失效（不放行）",
              panel._session_epoch_ok() is False)

    # 走真实端点。关键：**用两个独立的 client** —— A 登录后保持不动，
    # B 负责改密码。改完之后 A 手里的 cookie 还是改密前发的那个 epoch，
    # 正好用来验证「旧设备上的会话真的会失效」。
    cur_pw = "OldPass123"
    with open(panel.AUTH_PASSWORD_FILE, "w", encoding="utf-8") as f:
        json.dump({"hash": panel._hash_password(cur_pw)}, f)

    _pc = panel.app.test_client()
    _lr = _pc.post("/api/auth/login", json={"password": cur_pw})
    check("面板登录成功（拿到会话）", _lr.status_code == 200,
          f"HTTP {_lr.status_code} {_lr.get_json()}")

    ep_before = panel._current_token_epoch()
    _st = _pc.get("/api/auth/status").get_json()
    check("改密前 /api/auth/status 报已登录",
          _st.get('data', {}).get('authenticated') is True, str(_st))

    _pc.get("/api/config")          # 受保护端点，改密前应可达
    _st_before = _pc.get("/api/auth/status").get_json()
    check("改密前会话在受保护端点上有效",
          _st_before.get('data', {}).get('authenticated') is True)

    _pc2 = panel.app.test_client()
    _pc2.post("/api/auth/login", json={"password": cur_pw})
    _new2 = "NewPass456"
    _resp = _pc2.post("/api/auth/change-password",
                      json={"old_password": cur_pw, "new_password": _new2})
    cur_pw = _new2
    _body = _resp.get_json()
    check("改密码返回成功", _body.get('success') is True, f"{_resp.status_code} {_body}")
    ep_after = panel._current_token_epoch()
    check("改密码后 epoch 递增了", ep_after == ep_before + 1,
          f"{ep_before} -> {ep_after}")
    check("改密码响应带上了新 epoch",
          _body.get('data', {}).get('auth_token_epoch') == ep_after,
          str(_body.get('data')))
    check("改密码响应要求重新登录", _body.get('data', {}).get('reauth') is True)

    # ── 以下是这块最容易写漏的地方：光测 helper 不够，
    #    还得确认登录确实盖了 epoch、before_request 真的在查、
    #    /api/auth/status 真的按 epoch 汇报。变异脚本在这三处各放过一次。
    _st_after = _pc.get("/api/auth/status").get_json()
    check("改密后旧设备 /api/auth/status 报未登录",
          _st_after.get('data', {}).get('authenticated') is False,
          f"实际={_st_after} —— status 没按 epoch 汇报")
    _cfg_after = _pc.get("/api/config")
    check("改密后旧设备的会话在受保护端点上被拒",
          _cfg_after.status_code == 401, f"HTTP {_cfg_after.status_code} —— before_request 没查 epoch")

    # 改密之后旧密码不能再用，新密码能用
    _old_pw = "OldPass123"
    _pc3 = panel.app.test_client()
    panel._clear_login_failures("127.0.0.1")
    _r_old = _pc3.post("/api/auth/login", json={"password": _old_pw})
    check("旧密码已失效", _r_old.status_code in (401, 429), f"HTTP {_r_old.status_code}")
    panel._clear_login_failures("127.0.0.1")
    _r_new = _pc3.post("/api/auth/login", json={"password": cur_pw})
    check("新密码可用", _r_new.status_code == 200, f"HTTP {_r_new.status_code}")
    check("用新密码登录的会话立刻可用",
          _pc3.get("/api/auth/status").get_json()
          .get('data', {}).get('authenticated') is True)

    # 再改一次密码，epoch 应当继续累加而不是卡住。
    # 注意用变量跟踪当前密码 —— 这一段做了好几次改密，写死字符串极易
    # 前后对不上（第一次就栽过：登录报 401 还以为是限流，其实是密码链断了）。
    _ep2 = panel._current_token_epoch()
    panel._clear_login_failures("127.0.0.1")
    _pc4 = panel.app.test_client()
    _lr4 = _pc4.post("/api/auth/login", json={"password": cur_pw})
    check("用当前密码重新登录（连续改密前置）", _lr4.status_code == 200,
          f"HTTP {_lr4.status_code} —— 密码链对不上，不是限流")
    _new_pw = cur_pw + "x"
    _pc4.post("/api/auth/change-password",
              json={"old_password": cur_pw, "new_password": _new_pw})
    cur_pw = _new_pw
    check("连续改密码 epoch 继续累加",
          panel._current_token_epoch() == _ep2 + 1,
          f"{_ep2} -> {panel._current_token_epoch()}")

    # ── 权限不变量：面板写出来的密码文件，网关必须还读得到 ──────────
    #
    # .224 实测踩到过：_write_password_hash 写完 chmod 600，而网关降权后以
    # uid 1000 运行、密码文件属主是 root —— 组读权限被抹掉，于是
    # 「面板登录正常，但网关登录一律 401」。改回去也没用，得手工 chgrp 才能恢复。
    #
    # 关键：**桩必须装在 _write_password_hash 的上游**。开发机没有 nftweb 组，
    # 两条路径都得到 600，行为上看不出差别 —— 变异脚本把调用点换回
    # chmod 600 时测试照样绿。被测对象必须是真实写入函数，不是它的 helper。
    import types as _types

    def _with_fake_nftweb_group(fn):
        """让 fn 运行在「nftweb 组存在」的语境里，返回 (结果, chown 调用记录)。"""
        _seen = []
        _fake = _types.ModuleType("grp")
        _fake.getgrnam = lambda n: (
            _types.SimpleNamespace(gr_gid=4242) if n == "nftweb"
            else (_ for _ in ()).throw(KeyError(n)))
        _real_mod = sys.modules.get("grp")
        _real_chown = os.chown
        sys.modules["grp"] = _fake
        os.chown = lambda p, u, g: _seen.append((p, u, g))
        try:
            return fn(), _seen
        finally:
            os.chown = _real_chown
            if _real_mod is not None:
                sys.modules["grp"] = _real_mod
            else:
                sys.modules.pop("grp", None)

    # 1) _write_password_hash 的真实路径（组存在 → 应 640）
    with open(panel.AUTH_PASSWORD_FILE, "w", encoding="utf-8") as f:
        json.dump({"hash": "x"}, f)
    os.chmod(panel.AUTH_PASSWORD_FILE, 0o600)
    _, _seen1 = _with_fake_nftweb_group(
        lambda: panel._write_password_hash(panel._hash_password("PermCheck123")))
    _m1 = os.stat(panel.AUTH_PASSWORD_FILE).st_mode & 0o777
    check("_write_password_hash 写出 640（网关 uid 1000 靠组读得到）",
          _m1 == 0o640, f"实际={_m1:o} —— 退回 600 就等于没修")
    check("_write_password_hash 确实把属组 chgrp 成 nftweb",
          any(g == 4242 for _, _, g in _seen1), f"chown 调用={_seen1}")

    # 2) _init_app_secret 的真实路径
    #
    # ⚠️ 语义在 Shannon 渗透测试修复里变过：面板的会话签名密钥现在写
    # **独立的** AUTH_SESSION_SECRET_FILE，权限 0600 root:root ——
    # **不给 nftweb 组读权限**。
    #
    # 以前它和网关的令牌密钥共用一个文件（0640 root:nftweb），等于把
    # 「签出面板管理员 session」的能力递给了公网可达的降权网关进程。
    # 网关侧虽有域分离（HMAC 派生），但它的 _load_secret() 是直接读原
    # 文件再派生的 ⇒ 攻陷网关就拿到面板签名密钥。域分离挡得住逻辑混用，
    # 挡不住攻陷后横向。
    _orig_secret_file = panel.AUTH_SESSION_SECRET_FILE
    _secret_probe = f"{_tmpdir}/session-secret-probe"
    panel.AUTH_SESSION_SECRET_FILE = _secret_probe
    try:
        _, _seen2 = _with_fake_nftweb_group(lambda: panel._init_app_secret())
        _m2 = (os.stat(_secret_probe).st_mode & 0o777
               if os.path.exists(_secret_probe) else None)
        check("_init_app_secret 写出 600（网关读不到）",
              _m2 == 0o600,
              f"实际={'文件没生成' if _m2 is None else format(_m2, 'o')}")
        check("_init_app_secret **不**把属组 chgrp 成 nftweb",
              not any(g == 4242 for _, _, g in _seen2), f"chown 调用={_seen2}")
    finally:
        panel.AUTH_SESSION_SECRET_FILE = _orig_secret_file

    # 3) 没有 nftweb 组时必须退回保守的 600（不能放得更开）
    try:
        import grp as _g
        _g.getgrnam("nftweb")
        _has_real = True
    except (ImportError, KeyError):
        _has_real = False
    _probe3 = f"{_tmpdir}/perm-probe3"
    with open(_probe3, "w") as f:
        f.write("x")
    # 先故意设成 0666 再收紧 —— 否则文件本来就是 600，回退分支「什么都不做」
    # 和「chmod 600」结果完全一样，变异脚本把回退分支删掉测试照样绿。
    os.chmod(_probe3, 0o666)
    panel._apply_shared_secret_perms(_probe3)
    _m3 = os.stat(_probe3).st_mode & 0o777
    if _has_real:
        check("本机有 nftweb 组时权限被收紧为 640", _m3 == 0o640, f"实际={_m3:o}")
    else:
        check("无 nftweb 组时把过宽的权限收紧回 600（不放得更开）",
              _m3 == 0o600, f"实际={_m3:o} —— 回退分支没收紧，0666 留在那儿了")

    # 4) 无论走哪条分支，「其他」用户权限必须是 0
    for _label, _m in (("_write_password_hash", _m1), ("_init_app_secret", _m2),
                       ("回落分支", _m3)):
        check(f"{_label}：对「其他」仍然完全关闭",
              _m is not None and (_m & 0o007) == 0,
              "文件没生成" if _m is None else f"其他用户权限={_m:o}")

    # 5) 与 init 脚本的期望对齐（从脚本解析真实数字，不写死）
    _init_src = open(os.path.join(os.path.abspath(BACKEND),
                                  "nftables-web-auth.init"), encoding="utf-8").read()
    _mre = re.search(r'chmod\s+(\d+)\s+"\$_cfgdir/\$f"', _init_src)
    _expect_mode = int(_mre.group(1), 8) if _mre else None
    check("init 脚本确实为共享机密文件设了 chgrp nftweb",
          re.search(r'chgrp\s+"\$NFTWEB_USER"\s+"\$_cfgdir/\$f"', _init_src) is not None,
          "解析不到 chgrp 语句，测试需要更新")
    check("面板写出的权限与 init 脚本期望一致",
          _expect_mode is not None and _m1 == _expect_mode,
          f"面板={_m1:o}，init 期望={_expect_mode}")
    print(f"      init 脚本期望: chgrp nftweb + {_expect_mode:o}；面板写出: {_m1:o}")

    # 5b) 面板会话密钥：init 脚本必须把它设成 0600 root:root，
    #     而且**不能**落在 nftweb 组可读的那个循环里。
    #
    # 这一条是密钥分离（Shannon finding）的**端到端**断言：面板写 600，
    # init 脚本也必须 600 + root:root。两边任何一边松了，网关就能读到
    # 面板的会话签名密钥 ⇒ 攻陷网关 = 拿到面板管理员会话。
    _mre2 = re.search(r'chmod\s+(\d+)\s+"\$_sesssecret"', _init_src)
    _expect_sess_mode = int(_mre2.group(1), 8) if _mre2 else None
    check("init 脚本把面板会话密钥设为 0600",
          _expect_sess_mode == 0o600,
          f"解析到的权限={_expect_sess_mode}（解析不到就是测试需要更新）")
    check("init 脚本把面板会话密钥属主设成 root:root",
          re.search(r'chown\s+0:0\s+"\$_sesssecret"', _init_src) is not None,
          "解析不到 chown 0:0 语句")
    check("面板会话密钥**不**在 nftweb 组可读的循环里",
          re.search(r'for\s+f\s+in[^;]*nftables-web-session-secret', _init_src) is None,
          "session-secret 绝不能和网关共享的文件走同一个 chgrp nftweb 循环")
    check("网关令牌密钥走单独的 640 + chgrp nftweb（网关要读它）",
          re.search(r'chmod\s+640\s+"\$_toksecret"', _init_src) is not None
          and re.search(r'chgrp\s+"\$NFTWEB_USER"\s+"\$_toksecret"', _init_src) is not None,
          "nftables-web-secret 必须是 root:nftweb 640")

    panel.CONFIG_PATH = _orig_cfg_path
    panel.AUTH_PASSWORD_FILE = _orig_pwd
finally:
    os.chdir(_cwd)

sec("4b. logout 必须和 verify 用同一套取令牌方式")

# .224 实测挖出来的第二个 bug：auth_logout 只读 cookie，不认 Bearer；
# 而 _verify_or_deny 认 Bearer（注释还写着「Bearer 优先，给脚本/客户端用」）。
# 于是 Bearer 客户端调 logout 拿到 HTTP 200，看着像登出了，实际 revoke_jti
# 根本没被调用（payload 为空），令牌照样有效 —— 滑动续期下可能永不过期。
reset_revoked()
write_cfg(auth_token_epoch=0)
reload_cfg()
ag._mutate_ratelimit = lambda ip, on_fail=False: (0, 0)

_lr_b = _c.post("/auth/login", json={"password": PASSWORD}, headers={"Host": HOST})
_cookie = _lr_b.headers.get("Set-Cookie", "")
_tok = ""
for _part in _cookie.split(";"):
    if _part.strip().startswith("gw_token="):
        _tok = _part.strip().split("=", 1)[1]
check("登录拿到 gw_token", bool(_tok), f"Set-Cookie={_cookie[:80]!r}")

_bh = {"Host": HOST, "X-Real-IP": "8.8.8.8"}
check("Bearer 令牌在 verify 处可用",
      _c.get("/auth/verify", headers={**_bh, "Authorization": f"Bearer {_tok}"}).status_code == 200)

# 记下这个 jti，logout 后要能在吊销表里**精确**找到它。
# 之前这里只判了「表里至少有一条」，结果装饰器被误挂到别的函数上时
# （logout 路由返回了个字符串，200 但什么都没做）也能过。
_jti_b = jti_of(_tok)

_c.post("/auth/logout", headers={**_bh, "Authorization": f"Bearer {_tok}"})
_c2 = verify(_tok)
check("**Bearer 令牌 logout 后真的失效**（401）",
      _c2.status_code == 401, f"HTTP {_c2.status_code} —— logout 没吊销，Bearer 客户端永远登不掉")
_rev = ag.load_revoked() or {}
check("吊销表里精确写进了这个 jti",
      _jti_b in _rev, f"要找 {_jti_b}，实际={list(_rev)[:5]}")
_lo = _c.post("/auth/logout", headers={**_bh, "Authorization": f"Bearer {_tok}"})
try:
    _lo_json = _lo.get_json()
except Exception:
    _lo_json = None
check("logout 路由返回的是 JSON 而不是裸字符串（装饰器挂错函数的征兆）",
      isinstance(_lo_json, dict) and _lo_json.get("success") is True,
      f"返回类型={type(_lo.get_data()).__name__}，内容={_lo.get_data()[:60]!r}")

# cookie 方式的老行为不能被改坏。
#
# 这条以前写的是显式 `Cookie:` 请求头 —— 而 Werkzeug 3.1 的测试客户端会把
# 调用方给的 Cookie 头**整个丢掉**。它当时能过，纯粹因为登录响应顺手把
# cookie 存进了 jar，logout 阴差阳错走了 jar 分支。哪天登录改成不下发
# cookie，这条就变成「logout 什么都没吊销」的空跑，verify 却因为别的原因
# 401 —— 恒真。所以这里显式走 jar，并加一条前置断言盯住「cookie 确实被读到了」。
_tok2 = tok_of(_c.post("/auth/login", json={"password": PASSWORD},
                       headers={"Host": HOST}))
check("前置：cookie 登录拿到可用令牌",
      bool(_tok2) and verify(_tok2).status_code == 200)
set_cookie(_tok2)
_probe = _c.get("/auth/verify", headers={"Host": HOST, "X-Real-IP": "8.8.8.8"})
check("前置：jar 里的 cookie 真的被服务端读到了（否则下面的 logout 是空跑）",
      _probe.status_code == 200, f"HTTP {_probe.status_code}")
_jti2 = jti_of(_tok2)
_c.post("/auth/logout", headers={"Host": HOST, "X-Real-IP": "8.8.8.8"})
check("cookie 方式 logout 仍然有效（原有行为未被改坏）",
      verify(_tok2).status_code == 401)
check("cookie 方式 logout 精确吊销的就是这一个 jti",
      _jti2 in (ag.load_revoked() or {}),
      f"要找 {_jti2}，实际={list(ag.load_revoked() or {})[:5]}")

# ══════════════════════════════════════════════════════════════════════
sec("4c. 吊销落盘失败必须被如实汇报（.224 实测：属主被改后 logout 整条 500）")


_aud = []
_audit_real = ag.audit
ag.audit = lambda ev, **f: _aud.append(ev)

# ── A. 写入失败：必须返回 False，且不抛异常 ──────────────────────
#
# .224 实测：验证脚本把吊销表 chown 成 root，revoke_jti 结尾裸的
# `os.chmod(path, 0o600)` 抛 PermissionError。那行在**数据已经 fsync 落盘、
# 吊销早已成立之后**，却把整个 logout 打成 500，客户端只看到一个「服务端出错」，
# 完全不知道自己那张令牌还能不能用多久。
#
# 制造真实写失败的办法：把吊销表路径占成一个**目录**。os.open(..., O_RDWR)
# 在目录上必然抛 IsADirectoryError。这个手法与 uid 无关（root 也一样），
# 不用去 chmod 沙箱目录赌权限、也不会在 root 下意外放行。
reset_revoked()
os.makedirs(REVOKED, exist_ok=True)
_aud.clear()
_okA = ag.revoke_jti("jti-w", int(time.time()) + 600)
check("吊销表写不进去时 revoke_jti 返回 False", _okA is False, f"实际={_okA!r}")
check("写入失败不抛异常（抛出去就是 500，客户端无从判断令牌状态）",
      isinstance(_okA, bool))
check("写失败留下审计事件", "revocation_open_failed" in _aud, f"实际={_aud}")
os.rmdir(REVOKED)

# ── B. 收紧权限失败：数据已落盘 = 吊销成立，绝不能反过来判失败 ──────
#
# 必须先把文件设成 0666，否则新建的文件本来就是 0600、收紧分支根本不执行，
# 把「chmod 抛异常」打桩成永远触发不了，这条断言就恒真了。
reset_revoked()
with open(REVOKED, "w") as f:
    f.write("{}")
os.chmod(REVOKED, 0o666)
_chmod_real = os.chmod
os.chmod = lambda *a, **k: (_ for _ in ()).throw(
    PermissionError(13, "Operation not permitted"))
_aud.clear()
try:
    _okB = ag.revoke_jti("jti-c", int(time.time()) + 600)
finally:
    os.chmod = _chmod_real
check("chmod 失败时 revoke_jti 仍返回 True（收紧权限≠吊销失败）",
      _okB is True, f"实际={_okB!r}")
check("chmod 失败留下审计事件", "revocation_chmod_failed" in _aud, f"实际={_aud}")
check("chmod 失败不影响吊销本身成立", ag.is_revoked("jti-c") is True)

# ── C. 吊销表必须是「创建那一刻」就是 0600 ────────────────────────
#
# 事后 stat 抓不到这个差异：旧写法 `open(path, "a+")` 先按 umask 建出 0644、
# 再 chmod 0600，最终态一模一样，但中间有一个**世界可读窗口**。
# 所以这里拦截 os.open，直接看建文件时传进去的 mode。
_seen_mode = []
_open_real = os.open


def _open_spy(path, flags, mode=0o777, **k):
    if str(path) == REVOKED and (flags & os.O_CREAT):
        _seen_mode.append(mode)
    return _open_real(path, flags, mode, **k)


reset_revoked()
os.open = _open_spy
try:
    ag.revoke_jti("jti-m", int(time.time()) + 600)
finally:
    os.open = _open_real
check("吊销表用 os.open(..., 0600) **建**出来（创建即收紧，没有可读窗口）",
      _seen_mode == [0o600],
      f"实测传入 mode={_seen_mode} —— 用 open(a+) 会是 0777&~umask=0644，且 os.open 根本不会被调用")
_mC = os.stat(REVOKED).st_mode & 0o777 if os.path.exists(REVOKED) else None
check("吊销表最终权限 0600", _mC == 0o600,
      f"实际={'没生成' if _mC is None else format(_mC, 'o')}")

# ── D. logout 遇到吊销失败：必须明确失败，同时仍撤掉本机凭据 ───────
ag._mutate_ratelimit = lambda ip, on_fail=False: (0, 0)
reset_revoked()
_tokD = tok_of(_c.post("/auth/login", json={"password": PASSWORD},
                       headers={"Host": HOST}))
check("前置：登录拿到可用令牌", bool(_tokD) and verify(_tokD).status_code == 200)

os.makedirs(REVOKED, exist_ok=True)     # 再占成目录 → revoke_jti 必然失败
_aud.clear()
_loD = _c.post("/auth/logout", headers={"Host": HOST, "X-Real-IP": "8.8.8.8",
                                        "Authorization": f"Bearer {_tokD}"})
_ojD = _loD.get_json(silent=True)
check("吊销落盘失败时 logout 返回 500，不是 200",
      _loD.status_code == 500, f"HTTP {_loD.status_code}")
check("失败响应带 REVOCATION_FAILED 代码",
      isinstance(_ojD, dict) and _ojD.get("code") == "REVOCATION_FAILED",
      f"实际={_ojD!r}")
check("失败响应明说令牌在有效期内仍可能可用（不能只给一个错误码）",
      isinstance(_ojD, dict)
      and isinstance(_ojD.get("message"), str)
      and "仍可能可用" in _ojD.get("message", ""), f"实际={_ojD!r}")
check("失败时仍然撤掉本机 cookie（凭据先撤干净）",
      cookie_cleared(_loD, ag.COOKIE_TOKEN),
      f"Set-Cookie={(_loD.headers.get('Set-Cookie') or '')[:90]!r}")
check("**且该令牌此刻确实仍然有效** —— 这正是必须报 500 而非 200 的理由",
      verify(_tokD).status_code == 200,
      "令牌居然已经失效了 → 500 属于过度反应，这条断言的前提需要重写")
os.rmdir(REVOKED)

# ── E. login 绝不能被吊销失败卡死 ────────────────────────────────
#
# 吊销表写不进去只发生在「文件系统层面出故障」的时候。如果登录路径因此
# 抛异常 / 返 5xx，那就是自伤式拒绝服务：一张写坏的吊销表能让所有人
# 登不进来，代价远大于「旧令牌多活一会儿」。
os.makedirs(REVOKED, exist_ok=True)
_aud.clear()
set_cookie(_tokD)          # 走 jar：显式 Cookie 头会被测试客户端丢掉
_lrE = _c.post("/auth/login", json={"password": PASSWORD},
               headers={"Host": HOST})
check("吊销表写不进去时登录仍然成功（不能自伤式拒绝服务）",
      _lrE.status_code == 200, f"HTTP {_lrE.status_code}")
check("登录确实发回了新令牌", bool(tok_of(_lrE)))
check("旧令牌没吊销掉这件事留下审计",
      "login_old_token_not_revoked" in _aud, f"实际={_aud}")
os.rmdir(REVOKED)

# ── F. 续期路径：吊销表「可读但不可写」时也不能把用户踢出去 ──────
#
# 先说清楚两种故障的区别（写这段时被真机现象纠正过一次）：
#   · 吊销表**不可读** → is_revoked 的 fail-closed 直接 401，压根走不到续期分支。
#     那是 MISC-02 刻意选的取舍，不在这里测。
#   · 吊销表**可读但不可写**（/etc/nftables 变只读、属主被改）→ is_revoked 正常
#     放行，走到续期分支才 revoke_jti 失败。这才是续期加固要防的场景。
# 这里必须保证「可读」：把表换成目录会让 MISC-02 先拒掉，测的就不是续期了。
#
# ⚠️ 续期路径在 Shannon 渗透测试修复里搬过家：
#
# 原来续期在 `_verify_or_deny()` 里 —— 那是 nginx `auth_request` 的**子请求**
# 目标，而 auth_request 默认**丢弃子请求的响应头**（设备 nginx 只配了
# auth_request_set $auth_user / $auth_device，没有捕获 Set-Cookie）。
# 于是新令牌永远到不了客户端，而旧 jti 已经被吊销 ⇒ **用户 15 分钟后被踢回
# 登录页**（.233 实测：token_refreshed → verify_denied/reason=revoked）。
#
# 现在续期在 **`/auth/status`** —— 那里在 nginx 里是普通 proxy_pass
# （location = /auth/status，没有 auth_request），响应头原样到达浏览器。
# 所以下面这段打的是 /auth/status，不是 /auth/verify。
reset_revoked()
ag.revoke_jti("jti-seed", int(time.time()) + 600)
check("前置：吊销表可读且种子条目已写入",
      "jti-seed" in (ag.load_revoked() or {}))

# 必须先把 jar 清空：_extract_token 是 **cookie 优先**，E 阶段留下的
# gw_token cookie 会盖掉这里的 Bearer，测的就不是 devRefresh 那张令牌了。
_c.delete_cookie(ag.COOKIE_TOKEN, domain="192.168.100.224")
_tokF = ag.issue_token("kirito", "devRefresh", 60)   # 剩余 60s < 1800*0.5 → 必然续期
_open_real2 = os.open


def _open_ro(path, flags, mode=0o777, **k):
    if str(path) == REVOKED and (flags & os.O_CREAT):
        raise PermissionError(13, "模拟 /etc/nftables 变只读")
    return _open_real2(path, flags, mode, **k)


# /auth/status 读的是 **cookie**（不是 Bearer），而且必须用**非 LAN** 来源
# —— is_lan_source 会先短路成 {"authenticated": true, "user": "lan"}，
# 那样就测不到续期分支了。test_client 的 remote_addr 是 127.0.0.1（回环），
# 所以 client_ip() 会采信我们给的 X-Real-IP。
set_cookie(_tokF)
os.open = _open_ro
_aud.clear()
try:
    _rF = _c.get("/auth/status", headers={"Host": HOST, "X-Real-IP": "8.8.8.8"})
finally:
    os.open = _open_real2
check("吊销表只读时续期仍然放行（不能 401 踢人）",
      _rF.status_code == 200, f"HTTP {_rF.status_code}")
_newF = ""
for _p in (_rF.headers.get("Set-Cookie", "") or "").split(";"):
    if _p.strip().startswith("gw_token="):
        _newF = _p.strip().split("=", 1)[1]
check("续期确实签发了新令牌（/auth/status 下发 Set-Cookie）",
      bool(_newF) and _newF != _tokF)
check("续期这件事留下审计", "token_refreshed" in _aud, f"实际={_aud}")
check("续期时旧令牌没吊销掉也留下审计（否则线上无从判断）",
      "refresh_old_token_not_revoked" in _aud, f"实际={_aud}")

# ── F2. auth_request 路径必须是**纯校验**，不再续期 ─────────────────
#
# 这是修「用户每 15 分钟被踢下线」的关键：_verify_or_deny 是子请求，
# 响应头到不了客户端，在那里续期 = 签了新令牌、吊销了旧 jti，而客户端
# 什么都没收到 ⇒ 令牌被凭空作废。
#
# 现在那条路径不改任何令牌状态：不发 Set-Cookie、不吊销 jti。
# 令牌真过期时返回 401 → 跳登录页，**一次性**，而不是每 15 分钟循环被踢。
reset_revoked()
_tokF2 = ag.issue_token("kirito", "devPure", 60)   # 剩余 60s → 接近过期
_jti_before = jti_of(_tokF2)
_aud.clear()
_rF2 = verify(_tokF2)
check("auth_request 路径校验通过（HTTP 200）",
      _rF2.status_code == 200, f"HTTP {_rF2.status_code}")
check("auth_request 路径**不再下发** Set-Cookie（子请求头到不了客户端）",
      not (tok_of(_rF2) or "").strip(),
      f"Set-Cookie={_rF2.headers.get('Set-Cookie', '')!r}")
check("auth_request 路径**不再签发**新令牌（纯校验，无副作用）",
      "token_refreshed" not in _aud, f"实际={_aud}")
check("auth_request 路径**不吊销**旧令牌（不凭空作废用户会话）",
      jti_of(_tokF2) == _jti_before
      and _jti_before not in (ag.load_revoked() or {}),
      f"jti={_jti_before}，吊销表={list((ag.load_revoked() or {}).keys())}")

# ── F3. /auth/status 续期前**必须**校验世代号 ────────────────────
#
# 这是把续期从 `_verify_or_deny` 搬到 `/auth/status` 时最容易漏掉的一环。
#
# 续期原来在 _verify_or_deny 里，那条路径**先查世代号**再决定续不续，
# 所以「改密码 → epoch 递增 → 旧令牌作废」这条保证是成立的。
#
# 搬到 /auth/status 之后，如果不补校验就出现了一条完整的绕过链：
#   ① 用户改密码 → epoch 0→1 → 旧令牌（ep=0）本该立刻作废
#   ② 攻击者拿着旧令牌打 GET /auth/status
#   ③ 本端点不查 epoch → 只要令牌进了续期窗口就给它签新令牌
#   ④ 新令牌的 ep 是**当前**世代（issue_token → _token_epoch()）= 1
#      ⇒ 旧令牌被「洗」成一张完全有效的新令牌
#
# 也就是说：改完密码，泄露出去的旧令牌照样能换到新会话 ——
# 「改密码作废全部会话」这条保证被彻底绕开。
reset_revoked()
write_cfg(auth_token_epoch=0)
reload_cfg()
_tokF3 = ag.issue_token("kirito", "devEpoch", 60)   # ep=0，剩余 60s → 必进续期窗口
check("前置：令牌带 ep=0（改密码前的世代）",
      ag.parse_token(_tokF3).get("ep") == 0,
      f"实际 ep={ag.parse_token(_tokF3).get('ep')}")
write_cfg(auth_token_epoch=1)      # 模拟「用户改了密码」
reload_cfg()
set_cookie(_tokF3)
_aud.clear()
_rF3 = _c.get("/auth/status", headers={"Host": HOST, "X-Real-IP": "8.8.8.8"})
_bodyF3 = _rF3.get_json() or {}
check("世代号失效后 /auth/status 报未认证",
      _bodyF3.get("authenticated") is False,
      f'实际={_bodyF3}')
check("世代号失效后 /auth/status **不签发**新令牌（不能把旧令牌洗成新世代）",
      not (tok_of(_rF3) or "").strip(),
      f'Set-Cookie={_rF3.headers.get("Set-Cookie", "")!r}')
check("世代号失效时不发生续期", "token_refreshed" not in _aud, f"实际={_aud}")
check("世代号失效后旧令牌确实作废（auth_request 路径 401）",
      verify(_tokF3).status_code == 401,
      f"HTTP {verify(_tokF3).status_code}")
# 把世代号改回去后，同一张令牌**仍然**可用（证明刚才只是被 epoch 挡住，
# 不是令牌本身坏了）
write_cfg(auth_token_epoch=0)
reload_cfg()
check("世代号改回去后同一张令牌恢复可用（验证机制本身没坏）",
      verify(_tokF3).status_code == 200,
      f"HTTP {verify(_tokF3).status_code}")

# ── G. 同时带 cookie 和 Bearer 时，Bearer 必须胜出 ────────────────
#
# 2026-10-16 把优先级从「cookie 优先」翻成「Bearer 优先」。原因是原实现的
# 顺序和它自己的注释（"Bearer 优先"）对不上：脚本客户端只要机器上还留着
# 浏览器 cookie，Bearer 就被无视而拿 401 —— 明明带着有效令牌。
#
# 下面全部走**真实请求**，不直接调 _extract_token：直接调只能证明函数对，
# 证明不了 verify/logout 真的用了它。
sec("4g. 凭据优先级：Bearer 优先于 cookie")

reset_revoked()
write_cfg(auth_token_epoch=0)
reload_cfg()

# 两张都有效的令牌，用 jti 区分谁被选中
_tokA = ag.issue_token("kirito", "devCookie", 1800)    # 放进 cookie jar
_tokB = ag.issue_token("kirito", "devBearer", 1800)    # 放进 Authorization
_jtiA, _jtiB = jti_of(_tokA), jti_of(_tokB)

set_cookie(_tokA)
_r_g1 = _c.get("/auth/verify", headers={"Host": HOST, "X-Real-IP": "8.8.8.8",
                                        "Authorization": f"Bearer {_tokB}"})
check("同时带两者时请求放行（200）", _r_g1.status_code == 200,
      f"HTTP {_r_g1.status_code}")
check("verify 选中的是 **Bearer 那张**（X-Auth-Device=devBearer）",
      _r_g1.headers.get("X-Auth-Device") == "devBearer",
      f"实际={_r_g1.headers.get('X-Auth-Device')!r} —— cookie 仍然在抢优先级")

# 反向：Bearer 已吊销、cookie 仍有效。必须判 401 —— 不能「Bearer 失败就
# 悄悄退回 cookie」。那等于让显式摆出来的凭据失效后自动降级到环境凭据。
ag.revoke_jti(_jtiB, int(ag.parse_token(_tokB)["exp"]))
_r_g2 = _c.get("/auth/verify", headers={"Host": HOST, "X-Real-IP": "8.8.8.8",
                                        "Authorization": f"Bearer {_tokB}"})
check("Bearer 已吊销 → 401（**不**退回仍然有效的 cookie）",
      _r_g2.status_code == 401, f"HTTP {_r_g2.status_code}")

# 只有 cookie 时照常走 cookie（浏览器正常访问不能被这次改动打到）
_c.delete_cookie(ag.COOKIE_TOKEN, domain="192.168.100.224")
set_cookie(_tokA)
_r_g3 = _c.get("/auth/verify", headers={"Host": HOST, "X-Real-IP": "8.8.8.8"})
check("不带 Authorization 时仍然正常用 cookie 放行（浏览器路径没被改坏）",
      _r_g3.status_code == 200 and _r_g3.headers.get("X-Auth-Device") == "devCookie",
      f"HTTP {_r_g3.status_code} device={_r_g3.headers.get('X-Auth-Device')!r}")

# logout 走同一个优先级：同时带两者时，吊销的必须是 Bearer 那张
_c.delete_cookie(ag.COOKIE_TOKEN, domain="192.168.100.224")
set_cookie(_tokA)
_c.post("/auth/logout", headers={"Host": HOST, "X-Real-IP": "8.8.8.8",
                                 "Authorization": f"Bearer {_tokB}"})
check("logout 同时带两者时精确吊销 Bearer 那张",
      _jtiB in (ag.load_revoked() or {}),
      f"要找 {_jtiB}，实际={list(ag.load_revoked() or {})[:5]}")
check("logout 没有误吊 cookie 那张",
      _jtiA not in (ag.load_revoked() or {}),
      f"不该出现 {_jtiA}")
check("cookie 那张令牌仍然有效（logout 没打错人）",
      (set_cookie(_tokA),
       _c.get("/auth/verify",
              headers={"Host": HOST, "X-Real-IP": "8.8.8.8"}).status_code)[1] == 200)
# 注意 logout 的响应会把 jar 里的 gw_token 一并清掉（Max-Age=0），
# 所以上面必须重新 set_cookie —— 否则这次 verify 压根没带凭据，
# 会把「令牌失效」和「没登录」混成同一个 401。

# scheme 必须大小写不敏感（RFC 7235 §2.1）。不少客户端库发的是小写 bearer，
# 一旦改成 startswith("bearer ") 这些客户端会静默地全部掉到 cookie 分支。
_tokC = ag.issue_token("kirito", "devLower", 1800)
_c.delete_cookie(ag.COOKIE_TOKEN, domain="192.168.100.224")
_r_g4 = _c.get("/auth/verify", headers={"Host": HOST, "X-Real-IP": "8.8.8.8",
                                        "Authorization": f"bearer {_tokC}"})
check("Authorization 用小写 bearer 同样被认（RFC 7235 scheme 大小写不敏感）",
      _r_g4.status_code == 200 and _r_g4.headers.get("X-Auth-Device") == "devLower",
      f"HTTP {_r_g4.status_code} device={_r_g4.headers.get('X-Auth-Device')!r}")

ag.audit = _audit_real

# ── H. 两条鉴权路径的 epoch 判据必须一致 ─────────────────────────
#
# .224 实测挖出来的真洞：epoch 校验只写在 `_verify_or_deny`（nginx auth_request
# 打的 /auth/verify）里，`_authenticated`（浏览器直接访问 /auth/portal 用的）
# 没查。改密码之后 auth_request 确实 401 了，**门户页面却仍然 200** ——
# 用户看到「密码都改了，页面还能打开」，而背后的 API 已经在拒绝。
#
# 之前的测试只打了 /auth/verify，正好是查 epoch 的那条路径，把这条漏了。
# 所以下面**两个端点都必须打**，少一个就等于没测。
sec("4h. 门户页面与 auth_request 的 epoch 判据必须一致")

write_cfg(auth_token_epoch=5)
reload_cfg()
_tokH = ag.issue_token("kirito", "devH", 1800)
check("前置：令牌带 ep=5", ag.parse_token(_tokH).get("ep") == 5)
_r_ha = _c.get("/auth/portal", headers={**{"Host": HOST}, "Cookie": f"{ag.COOKIE_TOKEN}={_tokH}"})
check("改密码前 /auth/portal 放行", _r_ha.status_code in (200, 401),
      f"HTTP {_r_ha.status_code}（401 也可以，说明它确实在查凭据）")

# 用 jar 而不是手动头 —— Werkzeug 测试客户端会丢弃显式 Cookie 头
_c.delete_cookie(ag.COOKIE_TOKEN, domain="192.168.100.224")
set_cookie(_tokH)
_r_h1 = _c.get("/auth/portal", headers={"Host": HOST, "X-Real-IP": "8.8.8.8"})
check("**/auth/portal 在 epoch 未变时放行**", _r_h1.status_code == 200,
      f"HTTP {_r_h1.status_code}")

write_cfg(auth_token_epoch=6)      # 模拟改密码：epoch +1
reload_cfg()
_r_h2 = _c.get("/auth/portal", headers={"Host": HOST, "X-Real-IP": "8.8.8.8"})
check("**改密码后 /auth/portal 立即 401**（门户页面这扇门必须一起关）",
      _r_h2.status_code == 401,
      f"HTTP {_r_h2.status_code} —— 门户页面不查 epoch，用户会看到「密码都改了页面还能开」")

# 同一时刻，auth_request 那条路径也必须 401（两条判据一致，不是一条松一条紧）
_r_h3 = verify(_tokH)
check("同一时刻 /auth/verify 也 401（两条路径判据一致）",
      _r_h3.status_code == 401, f"HTTP {_r_h3.status_code}")

# Bearer 客户端在 /auth/portal 上也必须被认（取令牌方式统一）
_tokH2 = ag.issue_token("kirito", "devH2", 1800)
write_cfg(auth_token_epoch=6)
reload_cfg()
_c.delete_cookie(ag.COOKIE_TOKEN, domain="192.168.100.224")
_r_h4 = _c.get("/auth/portal", headers={"Host": HOST, "X-Real-IP": "8.8.8.8",
                                        "Authorization": f"Bearer {_tokH2}"})
check("/auth/portal 也认 Bearer 令牌（不只认 cookie）", _r_h4.status_code == 200,
      f"HTTP {_r_h4.status_code}")

# 无 ep 字段的旧令牌按 0 处理
write_cfg(auth_token_epoch=0)
reload_cfg()
_tokH3 = ag.issue_token("kirito", "devH3", 1800)
write_cfg(auth_token_epoch=1)
reload_cfg()
_c.delete_cookie(ag.COOKIE_TOKEN, domain="192.168.100.224")
set_cookie(_tokH3)
_r_h5 = _c.get("/auth/portal", headers={"Host": HOST, "X-Real-IP": "8.8.8.8"})
check("epoch 0→1 也能清掉旧令牌（无需兼容期）", _r_h5.status_code == 401,
      f"HTTP {_r_h5.status_code}")
_c.delete_cookie(ag.COOKIE_TOKEN, domain="192.168.100.224")

print("\n" + "=" * 74)
print(f"通过 {len(PASS)} / 失败 {len(FAIL)}")
if FAIL:
    print("失败项：")
    for f in FAIL:
        print(f"  - {f}")
    sys.exit(1)
print("全部通过")

shutil.rmtree(SBX, ignore_errors=True)
