"""认证网关（auth_gateway.py）安全修复回归测试 —— 沙箱，不触碰真实路径。

运行:  python3 tests/test_gateway_auth_fixes.py

覆盖本批次修的缺陷：
  P1-1  重新登录要吊销 **Bearer 客户端**的旧令牌（原来只吊销 cookie 里的）
  P1-2  登录表单必须 method="post"（原来没写 method → 默认 GET → 密码进 URL）
  P1-3  吊销表写盘后要立刻刷新 last-known-good 快照
  P1-4  /auth/status 要查世代号（epoch）
  P1-5  /auth/portal 要执行绝对 TTL
  P1-6  滑动续期时旧令牌必须作废（吊销表写不进去时也要作废）
  P1-7  审计日志的属主/权限要在降权之前摆正
  P1-8  审计日志轮转后的新文件不能是 0644（world-readable）
  P1-10 限流表损坏不能把登录打成 500
  P1-11 登录 CSRF 的 origin 锚点要换成服务端自己知道的域名 + 比端口
  P1-12 绑环回断言要看真实监听套接字，不只看环境变量
  P1-13 门户页要发 HSTS
  P1-14 令牌 cookie 的 Max-Age 以令牌自己的 exp 为准
  P1-15 lan_subnet4 配成 /1 也不能当内网
  P1-16 回环对端不再隐式当可信 LAN
  P2-1  限流表要有 IP 数量上限
  P2-2  降级模式的内存兜底表要有上限 + 成功登录要删键
  P2-3  吊销表要有容量上限
  P1-45 审计写入要限流，超限要合并成汇总（不能静默丢），成功登录永远记

沙箱约定：
  · 所有临时文件都在 tempfile.mkdtemp() 里，真实路径一律不碰；
  · os.setuid / setgid / initgroups 一类身份切换全部打桩；
  · 断言都是行为级的（真的调函数、真的看结果），文本匹配只作补充。
"""
import contextlib
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import socket
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")

SBX = tempfile.mkdtemp(prefix="gwfix-sbx-")
CFG = os.path.join(SBX, "config.json")
PWD = os.path.join(SBX, "password.json")
SEC = os.path.join(SBX, "secret")
RL = os.path.join(SBX, "ratelimit.json")
LOG = os.path.join(SBX, "audit.log")
REV = os.path.join(SBX, "ratelimit-revoked.json")

# 预置密码: test1234
_salt = "aabbccdd"
_digest = hashlib.pbkdf2_hmac("sha256", b"test1234", _salt.encode(), 200000)
with open(PWD, "w", encoding="utf-8") as f:
    json.dump({"hash": f"pbkdf2_sha256$200000${_salt}${_digest.hex()}"}, f)
with open(SEC, "w", encoding="utf-8") as f:
    f.write("test-secret-key-0123456789")

BASE_CFG = {
    "auth_session_timeout": 1800,
    "auth_absolute_timeout": 0,
    "auth_lan_bypass": True,
    "lan_subnet4": "192.168.100.0/24",
    "gateway_enabled": True,
    "reverse_proxy": {"rules": [
        {"name": "群晖", "path_prefix": "/nas", "enabled": True, "public_access": True},
    ]},
}


def write_cfg(data):
    """写配置并让 auth_gateway 的 mtime 缓存失效。

    load_gateway_config 按 mtime 缓存，同一时钟刻度内两次写入会拿到完全
    相同的 mtime → 缓存 key 不变 → 读到上一轮的陈旧配置。所以必须集中
    在一个 helper 里失效缓存（现有测试踩过这个坑）。
    """
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    try:
        import auth_gateway
        auth_gateway._config_cache["mtime"] = None
    except Exception:
        pass


write_cfg(BASE_CFG)

os.environ.update({
    "AUTH_CONFIG_PATH": CFG,
    "AUTH_PASSWORD_FILE": PWD,
    "AUTH_SECRET_FILE": SEC,
    "AUTH_RATELIMIT_FILE": RL,
    "AUTH_AUDIT_LOG": LOG,
    "AUTH_API_PORT": "18477",
})

# ── 导入前把身份切换类调用打桩（沙箱里绝不能真的改进程身份）────────────
class _FakeOs:
    """只挡下身份切换类函数，其余属性一律转发给真 os。

    用 __getattr__ 转发而不是只留几个函数：auth_gateway 在导入期还会
    import subprocess（它要 os.waitpid），一个「只暴露几个函数」的假 os
    会把整个导入顶崩。
    """

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def getuid(self):
        return self._real.getuid()

    def geteuid(self):
        return self._real.geteuid()

    def initgroups(self, *a, **k):
        return None

    def setgid(self, *a, **k):
        return None

    def setuid(self, *a, **k):
        return None


_real_os = os
sys.modules["os"] = _FakeOs(_real_os)
try:
    sys.path.insert(0, BACKEND)
    import auth_gateway as ag
finally:
    sys.modules["os"] = _real_os
    os = _real_os

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"  {'✅' if ok else '❌'} {name}" + (f"  {detail}" if detail and not ok else ""))


def sec(title):
    print(f"\n--- {title} ---")


HOST = "gw.example.com"
WAN = {"X-Real-IP": "8.8.8.8", "Host": HOST}
LAN = {"X-Real-IP": "192.168.100.50", "Host": HOST}


def client():
    return ag.app.test_client()


def with_token(tok, hdr=None, path="/auth/verify"):
    c = client()
    c.set_cookie(ag.COOKIE_TOKEN, tok, domain=HOST)
    return c.get(path, headers=hdr or dict(WAN))


def make_token(ttl=1800, iat=None, ep=None, dev="dev-fix"):
    """自己签一张令牌（可以指定 iat / ep，用来构造超期与世代不符的样本）。"""
    now = int(time.time())
    iat = now if iat is None else iat
    payload = {
        "sub": "kirito", "dev": dev, "iat": iat, "exp": now + ttl,
        "jti": secrets.token_urlsafe(12),
        "ep": ag._token_epoch() if ep is None else ep,
    }
    body = ag._b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = ag._b64e(hmac.new(ag._token_key(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def jti_of(tok):
    p = ag.parse_token(tok)
    return (p or {}).get("jti", "")


def read_audit():
    try:
        with open(LOG, "r", encoding="utf-8", errors="replace") as f:
            return [json.loads(l) for l in f if l.strip()]
    except (OSError, ValueError):
        return []


def audit_events():
    return [r.get("event", "") for r in read_audit()]


def _raw_log():
    try:
        with open(LOG, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def reset_audit():
    try:
        os.remove(LOG)
    except OSError:
        pass


# ══════════════════════════════════════════════════════════════════════
sec("P1-1  重新登录要吊销 Bearer 客户端的旧令牌")
# ══════════════════════════════════════════════════════════════════════
old_bearer = make_token(ttl=1800, dev="dev-bearer")
old_jti = jti_of(old_bearer)
check("前置：Bearer 旧令牌初始有效", not ag.is_revoked(old_jti))
# ⚠️ 这次登录**只带 Authorization 头、不带 cookie** —— Bearer 客户端本来
# 就没有 cookie。带着 cookie 一起发的话，旧实现照样能从 cookie 里找到旧
# 令牌并吊销，这条测试就抓不到「只吊销 cookie」这个缺陷了。
c = client()
r = c.post("/auth/login", json={"password": "test1234"},
           headers={"Authorization": f"Bearer {old_bearer}", "Host": HOST})
check("带 Bearer 重新登录 → 成功", r.status_code == 200, f"HTTP {r.status_code}")
check("Bearer 旧令牌已被吊销（原来只吊销 cookie 里的）",
      ag.is_revoked(old_jti), "Bearer 客户端的旧令牌仍然有效")
check("吊销落到了磁盘吊销表",
      old_jti in (ag.load_revoked() or {}), str(list((ag.load_revoked() or {}).keys())))

# 只带 cookie（不带 Bearer）的老路径也不能退化
old_cookie = make_token(ttl=1800, dev="dev-cookie")
old_cookie_jti = jti_of(old_cookie)
c2 = client()
c2.set_cookie(ag.COOKIE_TOKEN, old_cookie, domain=HOST)
c2.post("/auth/login", json={"password": "test1234"}, headers={"Host": HOST})
check("cookie 旧令牌同样被吊销", ag.is_revoked(old_cookie_jti))

# ══════════════════════════════════════════════════════════════════════
sec("P1-2  登录表单必须 method=post（默认 GET 会把明文密码塞进 URL）")
# ══════════════════════════════════════════════════════════════════════
login_html = os.path.join(BACKEND, "static", "login.html")
html = ""
if os.path.exists(login_html):
    with open(login_html, "r", encoding="utf-8", errors="replace") as f:
        html = f.read()
form_tags = re.findall(r"<form[^>]*>", html, re.I)
check("登录页存在 <form>", bool(form_tags), f"找到 {len(form_tags)} 个")
check("每个 <form> 都显式写了 method=\"post\"",
      bool(form_tags) and all(re.search(r'method\s*=\s*["\']post["\']', t, re.I)
                               for t in form_tags),
      str(form_tags))
# 服务端真的发出去的那份也要对（静态文件路由直接读同一个文件）
c3 = client()
r3 = c3.get("/auth/static/login.html", headers={"Host": HOST})
check("服务端下发的登录页含 method=\"post\"",
      r3.status_code == 200 and 'method="post"' in (r3.get_data(as_text=True) or ""),
      f"HTTP {r3.status_code}")

# ══════════════════════════════════════════════════════════════════════
sec("P1-3  吊销表写盘后要立刻刷新 last-known-good 快照")
# ══════════════════════════════════════════════════════════════════════
ag._REVOKED_LKG = None
jti_lkg = secrets.token_urlsafe(8)
ok = ag.revoke_jti(jti_lkg, int(time.time()) + 3600)
check("revoke_jti 落盘成功", ok)
with open(REV, "w", encoding="utf-8") as f:
    f.write("{ 这不是合法 JSON")          # 把表写坏
# ⚠️ 这里**不能**把 _REVOKED_LKG 清成 None —— 那等于模拟「进程刚起、
# 表就是坏的」，测的就不是「写后有没有刷新快照」了。要测的正是：
# revoke_jti() 写完之后，进程内的 last-known-good 里**已经有**这条吊销。
data = ag.load_revoked()
check("文件损坏时退到 last-known-good", isinstance(data, dict), repr(data))
check("LKG 里含**刚写入**的那条吊销（写后不刷新 = 刚登出的令牌会复活）",
      jti_lkg in (data or {}), str(list((data or {}).keys())))
check("文件坏掉后 is_revoked 仍然判为已吊销",
      ag.is_revoked(jti_lkg))
with open(REV, "w", encoding="utf-8") as f:
    json.dump({}, f)

# ══════════════════════════════════════════════════════════════════════
sec("P1-4  /auth/status 必须查世代号")
# ══════════════════════════════════════════════════════════════════════
write_cfg(dict(BASE_CFG, auth_token_epoch=0))
tok_ep0 = make_token(ttl=1800, ep=0)
c4 = client()
c4.set_cookie(ag.COOKIE_TOKEN, tok_ep0, domain=HOST)
r4 = c4.get("/auth/status", headers=dict(WAN))
check("epoch 一致 → 已认证", (r4.get_json() or {}).get("authenticated") is True,
      str(r4.get_json()))
write_cfg(dict(BASE_CFG, auth_token_epoch=1))
c5 = client()
c5.set_cookie(ag.COOKIE_TOKEN, tok_ep0, domain=HOST)
r5 = c5.get("/auth/status", headers=dict(WAN))
check("epoch 递增后旧令牌在 /auth/status 上作废",
      (r5.get_json() or {}).get("authenticated") is False, str(r5.get_json()))
write_cfg(BASE_CFG)

# ══════════════════════════════════════════════════════════════════════
sec("P1-5  /auth/portal 必须执行绝对 TTL")
# ══════════════════════════════════════════════════════════════════════
write_cfg(dict(BASE_CFG, auth_absolute_timeout=3600))
old_tok = make_token(ttl=600, iat=int(time.time()) - 7200)   # 签发于 2 小时前
c6 = client()
c6.set_cookie(ag.COOKIE_TOKEN, old_tok, domain=HOST)
r6 = c6.get("/auth/portal", headers=dict(WAN))
check("超过绝对上限的令牌在 /auth/portal 上被拒（原来这条路径不查）",
      r6.status_code == 401, f"HTTP {r6.status_code}")
r6b = with_token(old_tok, dict(WAN), "/auth/verify")
check("同一条令牌在 /auth/verify 上同样被拒（两条路径判据一致）",
      r6b.status_code == 401, f"HTTP {r6b.status_code}")
fresh_tok = make_token(ttl=600)
r6c = with_token(fresh_tok, dict(WAN), "/auth/portal")
check("绝对上限内的令牌在 /auth/portal 上放行", r6c.status_code == 200,
      f"HTTP {r6c.status_code}")
write_cfg(BASE_CFG)

# ══════════════════════════════════════════════════════════════════════
sec("P1-6  滑动续期时旧令牌必须作废（吊销表写不进去时也要）")
# ══════════════════════════════════════════════════════════════════════
old6 = make_token(ttl=100, dev="dev-refresh")       # 剩余 100s → 落入续期窗口
jti6 = jti_of(old6)
_orig_open = ag.os.open


def _open_ro(path, flags, mode=0o777, **kw):
    """让吊销表「只读可写不了」（模拟目录只读 / 属主被改）。"""
    if "revoked" in str(path):
        raise PermissionError(13, "Read-only file system")
    return _orig_open(path, flags, mode, **kw)


ag.os.open = _open_ro
try:
    c7 = client()
    c7.set_cookie(ag.COOKIE_TOKEN, old6, domain=HOST)
    r7 = c7.get("/auth/status", headers=dict(WAN))
finally:
    ag.os.open = _orig_open
check("吊销表写不进去时 /auth/status 仍然放行（不能 401 踢人）",
      r7.status_code == 200, f"HTTP {r7.status_code}")
check("续期仍下发新令牌 cookie",
      "gw_token=" in (r7.headers.get("Set-Cookie") or ""),
      f"Set-Cookie={r7.headers.get('Set-Cookie')!r}")
check("旧 jti 进吊销表失败时仍然作废（进程内名单兜底）",
      ag.is_revoked(jti6), "被取代的令牌仍然有效 —— 续期没有起到急停作用")
r7b = with_token(old6, dict(WAN), "/auth/verify")
check("旧令牌在 /auth/verify 上被拒", r7b.status_code == 401, f"HTTP {r7b.status_code}")

# ══════════════════════════════════════════════════════════════════════
sec("P1-7  审计日志的属主/权限要在降权之前摆正")
# ══════════════════════════════════════════════════════════════════════
os.makedirs(SBX, exist_ok=True)
with open(LOG, "a", encoding="utf-8"):
    pass
os.chmod(LOG, 0o666)
ag._prepare_audit_log()
mode = os.stat(LOG).st_mode & 0o777
check("审计日志权限被收紧到 0640（world 不可读）", mode == 0o640, oct(mode))

# root 路径：属主改成 root、属组改成网关的 gid、权限 0660
_called = []
_orig_geteuid, _orig_chown, _orig_chmod = ag.os.geteuid, ag.os.chown, ag.os.chmod
ag.os.geteuid = lambda: 0
ag.os.chown = lambda p, u, g: _called.append(("chown", p, u, g))
ag.os.chmod = lambda p, m: _called.append(("chmod", p, m))
_old_gid = os.environ.get("AUTH_DROP_GID")
os.environ["AUTH_DROP_GID"] = "1000"
try:
    ag._prepare_audit_log()
finally:
    ag.os.geteuid, ag.os.chown, ag.os.chmod = _orig_geteuid, _orig_chown, _orig_chmod
    if _old_gid is None:
        os.environ.pop("AUTH_DROP_GID", None)
    else:
        os.environ["AUTH_DROP_GID"] = _old_gid
check("降权前把审计日志属主改成 root:网关gid",
      ("chown", LOG, 0, 1000) in _called, str(_called))
check("属组可写（0660）—— 网关照常写，但改不了属主/权限",
      ("chmod", LOG, 0o660) in _called, str(_called))

# ══════════════════════════════════════════════════════════════════════
sec("P1-8 / P1-45-3  轮转后的新文件不能是 0644")
# ══════════════════════════════════════════════════════════════════════
reset_audit()
_old_max = ag.AUDIT_LOG_MAX_BYTES
ag.AUDIT_LOG_MAX_BYTES = 400
ag._ensure_audit_file(LOG)
# audit() 里要取 client_ip() → 必须在请求上下文里调（否则连 ip 都取不到，
# 记录直接被吞掉，测的就不是轮转而是「什么也没发生」）。
with ag.app.test_request_context("/auth/verify", headers=dict(WAN)):
    for i in range(40):
        ag.audit("probe", i=i)
mode_after = os.stat(LOG).st_mode & 0o777
check("审计日志权限始终是 0640", mode_after == 0o640, oct(mode_after))
check("轮转确实发生过（文件没无限长）", os.path.getsize(LOG) <= 400 + 400,
      f"size={os.path.getsize(LOG)}")
rotated = [f for f in os.listdir(SBX) if f.endswith(".1")]
if rotated:
    m1 = os.stat(os.path.join(SBX, rotated[0])).st_mode & 0o777
    check("轮转出来的上一代也是 0640", m1 == 0o640, oct(m1))
ag.AUDIT_LOG_MAX_BYTES = _old_max
reset_audit()

# 目录不可写时（真机常态）：就地轮转，权限不能退化
ag.AUDIT_LOG_MAX_BYTES = 400
ag._ensure_audit_file(LOG)
_orig_replace = ag.os.replace


def _replace_boom(*a, **k):
    raise OSError(13, "Read-only file system")


ag.os.replace = _replace_boom
try:
    with ag.app.test_request_context("/auth/verify", headers=dict(WAN)):
        for i in range(40):
            ag.audit("probe", i=i)
finally:
    ag.os.replace = _orig_replace
mode_after = os.stat(LOG).st_mode & 0o777
check("就地轮转后权限没有退化到 0644", mode_after == 0o640, oct(mode_after))
check("就地轮转后文件仍然有界", os.path.getsize(LOG) <= 400 + 400,
      f"size={os.path.getsize(LOG)}")
check("就地轮转保留了最近的记录（不是静默丢光）",
      any("probe" in (r.get("event", "") + str(r.get("i", ""))) for r in read_audit()),
      f"剩 {len(read_audit())} 条，原始内容={_raw_log()[:300]!r}")
ag.AUDIT_LOG_MAX_BYTES = _old_max
reset_audit()

# ══════════════════════════════════════════════════════════════════════
sec("P1-10  限流表损坏不能把登录打成 500")
# ══════════════════════════════════════════════════════════════════════
with open(RL, "w", encoding="utf-8") as f:
    f.write("{ 坏掉的 JSON")
c8 = client()
r8 = c8.post("/auth/login", json={"password": "test1234"}, headers={"Host": HOST})
check("限流表损坏时登录不返回 500", r8.status_code != 500, f"HTTP {r8.status_code}")
check("限流表损坏时登录仍按正常语义走（密码对 → 200）",
      r8.status_code == 200, f"HTTP {r8.status_code} body={r8.get_json()}")
try:
    os.remove(RL)
except OSError:
    pass

# ══════════════════════════════════════════════════════════════════════
sec("P1-11  登录 CSRF 的 origin 锚点")
# ══════════════════════════════════════════════════════════════════════
write_cfg(dict(BASE_CFG, gateway_port=8443, reverse_proxy={
    "settings": {"base_domain": "fzyto.top"},
    "rules": [{"name": "群晖", "host": "siyuan.fzyto.top", "path_prefix": "/nas",
               "enabled": True, "public_access": True}],
}))


def login_with_origin(origin, host="fzyto.top"):
    c = client()
    h = {"Host": host}
    if origin is not None:
        h["Origin"] = origin
    return c.post("/auth/login", json={"password": "test1234"}, headers=h)


r = login_with_origin("https://fzyto.top:8443")
check("同源 Origin（配置里的域名）→ 放行", r.status_code != 403, f"HTTP {r.status_code}")
r = login_with_origin("https://siyuan.fzyto.top:8443")
check("同源子域 → 放行", r.status_code != 403, f"HTTP {r.status_code}")
r = login_with_origin("https://evil.example.com")
check("跨站 Origin → 403", r.status_code == 403, f"HTTP {r.status_code}")
r = login_with_origin("https://evil.example.com", host="evil.example.com")
check("Origin 与 Host 同时伪造仍被拒（锚点不是客户端可控的 Host）",
      r.status_code == 403, f"HTTP {r.status_code}")
r = login_with_origin("https://fzyto.top:9999")
check("同主机但**端口不同** → 403（端口纳入比较）", r.status_code == 403,
      f"HTTP {r.status_code}")
r = login_with_origin("https://fzyto.top")
check("同源默认端口 → 放行", r.status_code != 403, f"HTTP {r.status_code}")
write_cfg(BASE_CFG)

# ══════════════════════════════════════════════════════════════════════
sec("P1-12  绑环回断言要看真实监听套接字")
# ══════════════════════════════════════════════════════════════════════
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 0))
refused = False
try:
    ag._assert_socket_loopback(s)
except SystemExit as e:
    refused = (e.code == 1)
except Exception as e:            # noqa: BLE001
    refused = False
    print(f"    （抛的不是 SystemExit：{type(e).__name__}: {e}）")
finally:
    s.close()
check("监听 0.0.0.0 → 拒绝启动（SystemExit(1)）", refused)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
passed = True
try:
    ag._assert_socket_loopback(s)
except SystemExit:
    passed = False
except Exception:                # noqa: BLE001
    passed = False
finally:
    s.close()
check("监听 127.0.0.1 → 放行", passed)

# ══════════════════════════════════════════════════════════════════════
sec("P1-13  门户页要发 HSTS")
# ══════════════════════════════════════════════════════════════════════
c9 = client()
r9 = c9.get("/", headers={"Host": HOST})          # 不带 X-Forwarded-Proto
hsts = r9.headers.get("Strict-Transport-Security", "")
check("门户页（无 X-Forwarded-Proto）也带 HSTS", "max-age=" in hsts, repr(hsts))
check("HSTS 不带 includeSubDomains（避免误伤同域其它服务）",
      "includeSubDomains" not in hsts, repr(hsts))

# ══════════════════════════════════════════════════════════════════════
sec("P1-14  令牌 cookie 的 Max-Age 以令牌自己的 exp 为准")
# ══════════════════════════════════════════════════════════════════════
from flask import Response
tok14 = make_token(ttl=100, dev="dev-maxage")
exp14 = ag.parse_token(tok14)["exp"]
with ag.app.test_request_context():
    resp = Response("ok")
    ag._set_cookies(resp, tok14, "dev-maxage")
    set_cookie = resp.headers.get("Set-Cookie", "")
m = re.search(r"Max-Age=(\d+)", set_cookie)
max_age = int(m.group(1)) if m else -1
check("Max-Age 不超过令牌的真实寿命",
      0 < max_age <= (exp14 - int(time.time())) + 2, f"Max-Age={max_age} exp={exp14}")
check("Max-Age 就是令牌剩下的寿命（不是会话 TTL 1800）",
      max_age < 1800, f"Max-Age={max_age}")

# ══════════════════════════════════════════════════════════════════════
sec("P1-15  lan_subnet4 配成 /1 也不能当内网")
# ══════════════════════════════════════════════════════════════════════
write_cfg(dict(BASE_CFG, lan_subnet4="0.0.0.0/1"))
with ag.app.test_request_context("/auth/verify", headers=dict(WAN)):
    check("配成 0.0.0.0/1 时公网 IP 不算内网",
          not ag.is_lan_source(ag.load_gateway_config()),
          "半个 IPv4 地址空间被当成了内网")
write_cfg(dict(BASE_CFG, lan_subnet4="0.0.0.0/0"))
with ag.app.test_request_context("/auth/verify", headers=dict(WAN)):
    check("配成 0.0.0.0/0 时公网 IP 不算内网",
          not ag.is_lan_source(ag.load_gateway_config()))
write_cfg(dict(BASE_CFG, lan_subnet4="192.168.100.0/24"))
with ag.app.test_request_context("/auth/verify", headers=dict(LAN)):
    check("正常网段仍然算内网", ag.is_lan_source(ag.load_gateway_config()))
write_cfg(BASE_CFG)

# ══════════════════════════════════════════════════════════════════════
sec("P1-16  回环对端不再隐式当可信 LAN")
# ══════════════════════════════════════════════════════════════════════
c10 = client()                       # test client 的来源就是 127.0.0.1
r10 = c10.get("/auth/verify", headers={"Host": HOST})   # 不带 X-Real-IP
check("回环来源不再免凭据拿到 200", r10.status_code != 200, f"HTTP {r10.status_code}")
write_cfg(dict(BASE_CFG, auth_lan_bypass_loopback=True))
c11 = client()
r11 = c11.get("/auth/verify", headers={"Host": HOST})
check("显式打开 auth_lan_bypass_loopback 后回环才恢复免密（留了退路）",
      r11.status_code == 200, f"HTTP {r11.status_code}")
write_cfg(BASE_CFG)

# ══════════════════════════════════════════════════════════════════════
sec("P2-1  限流表要有 IP 数量上限")
# ══════════════════════════════════════════════════════════════════════
_old_cap = ag.RATELIMIT_MAX_IPS
ag.RATELIMIT_MAX_IPS = 5
try:
    for i in range(40):
        ag._mutate_ratelimit(f"10.9.{i // 256}.{i % 256}", on_fail=True)
finally:
    ag.RATELIMIT_MAX_IPS = _old_cap
try:
    with open(RL, "r", encoding="utf-8") as f:
        table = json.load(f)
except Exception:                    # noqa: BLE001
    table = {}
check("限流表的 IP 数量被上限卡住", len(table) <= 5, f"表里 {len(table)} 条")
try:
    os.remove(RL)
except OSError:
    pass

# ══════════════════════════════════════════════════════════════════════
sec("P2-2  内存兜底表要有上限 + 成功登录要删键")
# ══════════════════════════════════════════════════════════════════════
ag._RATE_FALLBACK.clear()
ag._ratelimit_fallback_mutate("1.2.3.4", on_fail=True)
check("失败后兜底表里留下该 IP", "1.2.3.4" in ag._RATE_FALLBACK)
ag._ratelimit_fallback_mutate("1.2.3.4", on_fail=False)
check("成功登录后**删键**（原来只是置空，键永远留着）",
      "1.2.3.4" not in ag._RATE_FALLBACK, str(list(ag._RATE_FALLBACK.keys())))
_old_cap = ag.RATE_FALLBACK_MAX_IPS
ag.RATE_FALLBACK_MAX_IPS = 5
try:
    for i in range(40):
        ag._ratelimit_fallback_mutate(f"10.8.0.{i}", on_fail=True)
finally:
    ag.RATE_FALLBACK_MAX_IPS = _old_cap
check("兜底表的大小被上限卡住", len(ag._RATE_FALLBACK) <= 5,
      f"表里 {len(ag._RATE_FALLBACK)} 条")
ag._RATE_FALLBACK.clear()

# ══════════════════════════════════════════════════════════════════════
sec("P2-3  吊销表要有容量上限")
# ══════════════════════════════════════════════════════════════════════
_old_cap = ag.REVOKED_MAX_ENTRIES
ag.REVOKED_MAX_ENTRIES = 5
try:
    for i in range(20):
        ag.revoke_jti(f"cap-jti-{i}", int(time.time()) + 3600)
finally:
    ag.REVOKED_MAX_ENTRIES = _old_cap
table = ag.load_revoked() or {}
check("吊销表的条目数被上限卡住", len(table) <= 5, f"表里 {len(table)} 条")
check("刚写进去的那条没有被上限挤掉",
      "cap-jti-19" in table, str(list(table.keys())))

# ══════════════════════════════════════════════════════════════════════
sec("P1-45  审计写入限流 + 汇总（不静默丢）+ 成功登录永远记")
# ══════════════════════════════════════════════════════════════════════
reset_audit()
n = ag.AUDIT_RATE_MAX + 30
for i in range(n):
    with_token("not-a-token", dict(WAN), "/auth/verify")      # 未认证 → verify_denied
events = audit_events()
denied = events.count("verify_denied")
throttled = events.count("audit_throttled")
check("未认证请求被限流（verify_denied 没被无限写下去）",
      denied <= ag.AUDIT_RATE_MAX + 2, f"写了 {denied} 条")
check("超限的部分**不是静默丢弃**，而是合并成 audit_throttled 汇总",
      throttled >= 1, f"audit_throttled {throttled} 条")
summary = [r for r in read_audit() if r.get("event") == "audit_throttled"]
check("汇总记录里带「被合并掉多少条」（发生了 N 次这个事实没丢）",
      bool(summary) and int(summary[-1].get("suppressed", 0)) >= 1,
      str(summary[-1] if summary else None))
# 成功登录必须永远记下来（限流不能把审计变成后门）
c12 = client()
r12 = c12.post("/auth/login", json={"password": "test1234"}, headers={"Host": HOST})
check("限流触发后成功登录仍然落审计",
      "login_ok" in audit_events(), f"事件表={audit_events()[-6:]}")
check("成功登录返回 200（限流没有把主链路掐死）", r12.status_code == 200,
      f"HTTP {r12.status_code}")
reset_audit()

# ══════════════════════════════════════════════════════════════════════
sec("回归  改完之后原有行为不能被弄坏")
# ══════════════════════════════════════════════════════════════════════
write_cfg(BASE_CFG)
tok = make_token(ttl=1800, dev="dev-regress")
check("正常令牌仍能在 /auth/verify 上通过",
      with_token(tok, dict(WAN), "/auth/verify").status_code == 200)
check("内网来源仍然免密（lan_subnet4 语义不变）",
      with_token("x", dict(LAN), "/auth/verify").status_code == 200)
c13 = client()
r13 = c13.post("/auth/login", json={"password": "test1234"}, headers={"Host": HOST})
check("正常登录仍然 200", r13.status_code == 200, f"HTTP {r13.status_code}")
check("正常登录下发 gw_token cookie",
      "gw_token=" in (r13.headers.get("Set-Cookie") or ""))

print("\n" + "=" * 60)
print(f"  合计: ✅ {len(PASS)}   ❌ {len(FAIL)}")
if FAIL:
    print("\n  失败项：")
    for f in FAIL:
        print(f"    - {f}")
    sys.exit(1)
print("  全部通过")
shutil.rmtree(SBX, ignore_errors=True)
