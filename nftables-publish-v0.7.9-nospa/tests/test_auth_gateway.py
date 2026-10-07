"""进程 B 认证网关功能测试（沙箱，不触碰真实路径）

运行:  python3 tests/test_auth_gateway.py
依赖: 只用标准库 + 已安装的 flask/werkzeug；不需要 root，不碰任何真实配置路径。
"""
import base64, hashlib, hmac, json, os, shutil, sys, time

SBX = "/tmp/authgw-sbx"
shutil.rmtree(SBX, ignore_errors=True)
os.makedirs(SBX, exist_ok=True)

CFG = f"{SBX}/config.json"
PWD = f"{SBX}/password.json"
SEC = f"{SBX}/secret"
RL = f"{SBX}/ratelimit.json"
LOG = f"{SBX}/audit.log"

# 预置密码: test1234
salt = "aabbccdd"
digest = hashlib.pbkdf2_hmac("sha256", b"test1234", salt.encode(), 200000)
json.dump({"hash": f"pbkdf2_sha256$200000${salt}${digest.hex()}"}, open(PWD, "w"))
open(SEC, "w").write("test-secret-key-0123456789")
json.dump({
    "auth_session_timeout": 1800,
    "auth_absolute_timeout": 0,
    "auth_lan_bypass": True,
    "lan_subnet4": "192.168.100.0/24",
    "reverse_proxy": {"rules": [
        {"name": "群晖", "path_prefix": "/nas", "enabled": True, "public_access": True},
        {"name": "相册", "path_prefix": "/photos/", "enabled": True, "public_access": False},
        {"name": "关闭的", "path_prefix": "/off", "enabled": False},
        {"name": "无前缀", "enabled": True},
    ]},
}, open(CFG, "w"), ensure_ascii=False)

os.environ.update({
    "AUTH_CONFIG_PATH": CFG, "AUTH_PASSWORD_FILE": PWD, "AUTH_SECRET_FILE": SEC,
    "AUTH_RATELIMIT_FILE": RL, "AUTH_AUDIT_LOG": LOG, "AUTH_API_PORT": "18444",
})
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
import auth_gateway as ag

PASS, FAIL = [], []
def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  {extra}" if extra and not cond else ""))

WAN = {"X-Real-IP": "8.8.8.8", "Host": "gw.example.com"}
LAN = {"X-Real-IP": "192.168.100.50", "Host": "gw.example.com"}
c = ag.app.test_client()
HOST = "gw.example.com"
def with_tok(t, hdr=None):
    """用 cookie jar 带上 token（domain 必须与 Host 一致，否则不会被发送）"""
    cc = ag.app.test_client()
    cc.set_cookie("gw_token", t, domain=HOST)
    return cc.get("/auth/verify", headers=hdr or dict(WAN))

print("\n=== 1. Token 签发/校验 ===")
tok = ag.issue_token("kirito", "dev-123", 1800)
p = ag.parse_token(tok)
check("正常 token 可解析", p and p["sub"] == "kirito" and p["dev"] == "dev-123")
body, _, sig = tok.partition(".")
forged = f"{body}.{ag._b64e(b'0'*32)}"
check("签名被篡改 → None", ag.parse_token(forged) is None)
check("空 token → None", ag.parse_token("") is None)
check("无点号 → None", ag.parse_token("abcdef") is None)
check("两段点号 → None", ag.parse_token("a.b.c") is None)
exp_tok = ag.issue_token("u", "d", -10)
check("已过期 token → None", ag.parse_token(exp_tok) is None)

print("\n=== 2. /auth/verify fail-closed（核心） ===")
r = c.get("/auth/verify", headers=WAN)
check("WAN 无 token → 401", r.status_code == 401, f"实际 {r.status_code}")
r = c.get("/auth/verify", headers=WAN, headers_bad=None) if False else c.get("/auth/verify", headers={**WAN, "Cookie": f"gw_token={forged}"})
check("WAN 伪造签名 → 401", r.status_code == 401, f"实际 {r.status_code}")
r = c.get("/auth/verify", headers={**LAN})
check("LAN 免认证 → 200", r.status_code == 200, f"实际 {r.status_code}")
check("LAN 响应带 X-Auth-User", r.headers.get("X-Auth-User") == "lan")
r = with_tok(tok)
check("WAN 有效 token → 200", r.status_code == 200, f"实际 {r.status_code}")
check("200 响应带 X-Auth-User", r.headers.get("X-Auth-User") == "kirito")

print("\n=== 3. 异常路径必须 401（绝不能 200/500） ===")
orig_cfg, orig_parse = ag.load_gateway_config, ag.parse_token
try:
    ag.load_gateway_config = lambda: (_ for _ in ()).throw(RuntimeError("模拟配置读取炸了"))
    r = c.get("/auth/verify", headers=WAN)
    check("配置读取抛异常 → 401", r.status_code == 401, f"实际 {r.status_code}")
    ag.load_gateway_config = orig_cfg
    ag.parse_token = lambda t: (_ for _ in ()).throw(ValueError("模拟解析炸了"))
    # 用 WAN 路径：LAN 免认证会在解析 token 之前短路返回 200（设计如此），
    # 所以异常注入必须打在 WAN 路径上才能验证兜底。
    r = with_tok(tok, dict(WAN))
    check("WAN 下 parse 抛异常 → 401", r.status_code == 401, f"实际 {r.status_code}")
finally:
    ag.load_gateway_config, ag.parse_token = orig_cfg, orig_parse

print("\n=== 4. 吊销 ===")
t2 = ag.issue_token("kirito", "dev-abc", 1800)
p2 = ag.parse_token(t2)
ag.revoke_jti(p2["jti"], p2["exp"])
r = with_tok(t2)
check("已吊销 token → 401", r.status_code == 401, f"实际 {r.status_code}")

print("\n=== 5. 登录 ===")
r = c.post("/auth/login", json={"password": "wrong"}, headers=WAN)
check("错误密码 → 401", r.status_code == 401, f"实际 {r.status_code}")
check("错误密码不回显 remaining 之外的敏感信息", "password" not in json.dumps(r.get_json()).lower())
r = c.post("/auth/login", json={"password": "test1234"}, headers=WAN)
check("正确密码 → 200", r.status_code == 200, f"实际 {r.status_code} {r.get_json()}")
sc = "\n".join(r.headers.get_all("Set-Cookie"))
check("下发 token cookie", "gw_token=" in sc)
check("cookie 是 HttpOnly", "HttpOnly" in sc)
check("cookie 是 Secure", "Secure" in sc)
check("cookie 是 SameSite=Lax", "SameSite=Lax" in sc or "samesite=lax" in sc.lower())
check("下发 device cookie", "gw_device=" in sc)

print("\n=== 6. CSRF ===")
r = c.post("/auth/login", json={"password": "test1234"},
           headers={**WAN, "Origin": "http://evil.example.net"})
check("跨站 Origin → 403", r.status_code == 403, f"实际 {r.status_code}")
r = c.post("/auth/login", json={"password": "test1234"},
           headers={**WAN, "Referer": "http://evil.example.net/x"})
check("跨站 Referer → 403", r.status_code == 403, f"实际 {r.status_code}")

print("\n=== 7. 限流落盘（重启不失效） ===")
shutil.rmtree(RL, ignore_errors=True)
codes = []
for i in range(7):
    r = c.post("/auth/login", json={"password": "bad"}, headers={**WAN, "X-Real-IP": "1.2.3.4"})
    codes.append(r.status_code)
check("连续失败后被锁 → 出现 429", 429 in codes, f"实际 {codes}")
check("锁定期内返回 429", codes[-1] == 429, f"实际 {codes[-1]}")
check("限流文件已落盘", os.path.exists(RL))
if os.path.exists(RL):
    d = json.load(open(RL))
    check("落盘里有该 IP 的锁定记录",
          "1.2.3.4" in d and d["1.2.3.4"].get("locked_until", 0) > time.time())

print("\n=== 8. 绝对上限 ===")
cfg = json.load(open(CFG)); cfg["auth_absolute_timeout"] = 60
json.dump(cfg, open(CFG, "w"), ensure_ascii=False)
ag._config_cache["mtime"] = None   # 强制下次重读，绕开 mtime 缓存
old = ag.issue_token("kirito", "dev-old", 1800)
pp = ag.parse_token(old)
pp["iat"] = int(time.time()) - 300   # 签发于 5 分钟前
body2 = ag._b64e(json.dumps(pp, separators=(",", ":")).encode())
old2 = f"{body2}.{ag._b64e(hmac.new(ag._token_key(), body2.encode(), hashlib.sha256).digest())}"
r = with_tok(old2)
check("超绝对上限 → 401", r.status_code == 401, f"实际 {r.status_code}")
cfg["auth_absolute_timeout"] = 0
json.dump(cfg, open(CFG, "w"), ensure_ascii=False)
ag._config_cache["mtime"] = None

print("\n=== 9. 门户服务列表 ===")
r = c.get("/auth/portal", headers=LAN)
check("LAN 免认证可取门户 → 200", r.status_code == 200, f"实际 {r.status_code}")
svcs = r.get_json()["services"]
check("只列出已启用且有前缀的", len(svcs) == 2, f"实际 {len(svcs)}: {svcs}")
check("路径已规整（去掉尾斜杠）", all(not s["path"].endswith("/") for s in svcs))
check("public 标记正确", {s["path"]: s["public"] for s in svcs} == {"/nas": True, "/photos": False})

print("\n=== 10. 审计日志 ===")
check("审计日志已生成", os.path.exists(LOG))
if os.path.exists(LOG):
    lines = [json.loads(l) for l in open(LOG) if l.strip()]
    evts = {l["event"] for l in lines}
    check("记录了 login_ok", "login_ok" in evts)
    check("记录了 login_fail", "login_fail" in evts)
    check("记录了 verify_denied", "verify_denied" in evts)
    check("记录了吊销路径", "logout" in evts or "verify_denied" in evts)
    check("每条都有时间戳和来源", all("ts" in l and "ip" in l for l in lines))

print("\n=== 11. 安全修复回归（Shannon 2026-10-07 + 实测复现）===")
# 这组全部写成「旧代码上会失败」，避免修复被无意改回去。
# 每一项都在 .224 上实测复现过，不是推演。

# 11.1 配了 lan_subnet4 就只认它，不能被 is_private 放宽
print("\n--- 11.1 lan_subnet4 收紧范围（旧代码会误放行）---")
for ip, should_pass, why in [
    ("192.168.100.50", True,  "配置网段内，应当放行"),
    ("192.168.50.5",   False, "私网但不在 192.168.100.0/24，不该放行"),
    ("10.0.0.5",       False, "私网但不在配置网段，不该放行"),
    ("172.16.3.4",     False, "私网但不在配置网段，不该放行"),
    ("8.8.8.8",        False, "公网，本就不该放行"),
]:
    r = ag.app.test_client().get("/auth/verify", headers={"X-Real-IP": ip, "Host": HOST})
    ok = (r.status_code == 200) if should_pass else (r.status_code == 401)
    check(f"{ip:<15} {'放行' if should_pass else '拒绝'}", ok,
          f"实际 {r.status_code} — {why}")
    if should_pass:
        check(f"{ip:<15} 标记为 lan-bypass", r.headers.get("X-Auth-Via") == "lan-bypass")

# 一个网段都没配时，才允许回落到 RFC1918（保留旧的默认行为）
_orig_cfg = json.load(open(CFG))
_saved = dict(_orig_cfg)
_orig_cfg.pop("lan_subnet4", None)
_orig_cfg.pop("lan_subnet6", None)
json.dump(_orig_cfg, open(CFG, "w"), ensure_ascii=False)
ag._config_cache["mtime"] = None  # 同上
r = ag.app.test_client().get("/auth/verify", headers={"X-Real-IP": "192.168.50.5", "Host": HOST})
check("未配网段时仍回落 is_private", r.status_code == 200,
      f"实际 {r.status_code} — 完全没配网段时不该把行为改掉")
json.dump(_saved, open(CFG, "w"), ensure_ascii=False)

# 缺省值本身也要钉住：auth_lan_bypass 这个键**整个缺失**时必须要求认证
# （fail-closed）。主测试配置里总是显式写了 True，不专门测一次的话，
# 把缺省值改回 True 不会有任何测试失败。
_c = json.load(open(CFG))
_saved2 = dict(_c)
_c.pop("auth_lan_bypass", None)
json.dump(_c, open(CFG, "w"), ensure_ascii=False)
ag._config_cache["mtime"] = None  # load_gateway_config 按 mtime 缓存，不清会读到陈旧配置
r = ag.app.test_client().get("/auth/verify", headers={"X-Real-IP": "192.168.100.50", "Host": HOST})
check("配置缺失 auth_lan_bypass 时不放行（fail-closed）", r.status_code == 401,
      f"实际 {r.status_code} — 缺配置时应当要求认证而不是默认免认证")
json.dump(_saved2, open(CFG, "w"), ensure_ascii=False)

# 11.2 Origin: null 必须按跨站拒绝（旧代码放进白名单放行了）
print("\n--- 11.2 CSRF：Origin: null 不再放行（旧代码返回 401 走到了密码校验）---")
def login_with(origin=None, referer=None, ip="203.0.113.7"):
    h = {"X-Real-IP": ip, "Host": HOST, "Content-Type": "application/json"}
    if origin is not None: h["Origin"] = origin
    if referer is not None: h["Referer"] = referer
    return ag.app.test_client().post("/auth/login", headers=h, json={"password": "x"})

r = login_with(origin="null")
check("Origin: null → 403", r.status_code == 403, f"实际 {r.status_code}")
r = login_with(origin="https://evil.example.com")
check("跨站 Origin → 403", r.status_code == 403, f"实际 {r.status_code}")
r = login_with(origin=f"https://{HOST}")
check("同源 Origin → 非 403", r.status_code != 403, f"实际 {r.status_code}")
r = login_with(referer=f"https://{HOST}/")
check("同源 Referer（无 Origin）→ 非 403", r.status_code != 403, f"实际 {r.status_code}")
r = login_with(referer="https://evil.example.com/x")
check("跨站 Referer → 403", r.status_code == 403, f"实际 {r.status_code}")
r = login_with()   # curl/脚本：什么都不带
check("无 Origin 无 Referer → 非 403（脚本仍可用）", r.status_code != 403, f"实际 {r.status_code}")

# 11.3 滑动续期要吊销旧 token（旧代码只签新的，旧的永远有效）
print("\n--- 11.3 续期吊销旧 token（旧代码让登出对已泄露 token 失效）---")
# 触发续期的条件是「剩余时间 < 会话 TTL 的一半」= 1800/2 = 900 秒，
# 所以这里签一张剩余 100 秒的：既仍然有效，又必然落入续期区间。
old = ag.issue_token("kirito", "dev-rot", 100)
old_jti = ag.parse_token(old)["jti"]
check("旧 token 初始有效且未被吊销",
      ag.parse_token(old) is not None and not ag.is_revoked(old_jti))
cc = ag.app.test_client()
cc.set_cookie("gw_token", old, domain=HOST)
r = cc.get("/auth/verify", headers={"X-Real-IP": "8.8.8.8", "Host": HOST})
check("带旧 token 请求被接受并触发续期", r.status_code == 200, f"实际 {r.status_code}")

# 注意：parse_token 只验签名与 exp，**不查吊销表**（吊销在 _verify_or_deny 里
# 单独用 is_revoked 判）。所以不能断言 parse_token(old) is None —— 那测的是
# 另一件事。要断言的是「旧 token 真的进了吊销表，且真的被拒绝」。
check("续期后旧 jti 已进吊销表", ag.is_revoked(old_jti),
      "旧 jti 未被吊销 = 攻击者截获的凭据不会因受害者续期而失效")
cc2 = ag.app.test_client()
cc2.set_cookie("gw_token", old, domain=HOST)
r2 = cc2.get("/auth/verify", headers={"X-Real-IP": "8.8.8.8", "Host": HOST})
check("续期后旧 token 被 /auth/verify 拒绝", r2.status_code == 401, f"实际 {r2.status_code}")

print("\n" + "="*60)
print(f"通过 {len(PASS)} / {len(PASS)+len(FAIL)}")
if FAIL:
    print("失败项:")
    for f in FAIL: print("  -", f)
    sys.exit(1)
print("全部通过")
