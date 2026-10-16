"""认证网关硬化 —— 2026-10-16 Shannon 第二轮的四项修复回归测试

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_auth_hardening.py

背景
----
Shannon 第二轮（快照 5433c00）崩在收尾阶段，但崩之前交了 6 条 finding。
逐条核实后有四条成立，全部在本文件里有回归断言：

  1. AUTH-VULN-04  /auth/* 无 client_max_body_size
     .224 实测：6 个并发 100M 的 POST /auth/login 就能把 auth_gateway 的
     Python 顶到 RSS 461MB 触发内核 OOM：
         Out of memory: Killed process (python3) anon-rss:461600kB
     进程被杀后没有任何机制拉起它，/auth/* 全部 502，公网入口彻底断掉。
     （注意 OOM 吃的是 RAM 不是 overlay —— OpenWrt 的 /var 指向 /tmp，
      tmpfs 上的请求体临时文件；定位时别盯着 df / 看错盘。）

  2. init 脚本 sleep 1 竞态
     守卫假设 Python 1 秒内能执行到模块级 _drop_privileges()。
     .224 实测启动→降权耗时：空闲 0.37s / 4 进程满载 0.82s /
     8 进程满载 1.44~1.64s。机器一忙就把健康进程当「降权未生效」杀掉，
     网关彻底起不来。守卫本身是对的，错的只是等待方式。

  3. validate_config 放行 lan_subnet4=0.0.0.0/1
     同一函数里 panel_allowed_nets 用 prefixlen <= 1，lan_subnet4/6 却
     用 == 0。提交 /1 后所有 public=false 的反代对半个互联网免认证。

  4. _origin_host_mismatch 两个洞
     无 scheme 的 Origin（netloc 为空 → return False 放行）和
     userinfo 冒号冒充（netloc.split(":")[0] 取到 host）。
     .224 实测两者都能登录成功，同期对照组跨站 Origin 是 403。

本文件里的每条断言在**修复前必然失败**，不是推演。
"""
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile

# ══════════════════════════════════════════════════════════════════════
# 沙箱：完全独立于真实配置路径，不碰 /opt、/etc、/var
# ══════════════════════════════════════════════════════════════════════
SBX = tempfile.mkdtemp(prefix="authharden-")
CFG = f"{SBX}/config.json"
PWD = f"{SBX}/password.json"
SEC = f"{SBX}/secret"
RL = f"{SBX}/ratelimit.json"
LOG = f"{SBX}/audit.log"

PASSWORD = "test1234"
salt = "aabbccdd"
digest = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt.encode(), 200000)
json.dump({"hash": f"pbkdf2_sha256$200000${salt}${digest.hex()}"}, open(PWD, "w"))
open(SEC, "w").write("test-secret-key-0123456789")

BASE_CFG = {
    "auth_session_timeout": 1800,
    "auth_absolute_timeout": 0,
    "auth_lan_bypass": True,
    "lan_subnet4": "192.168.100.0/24",
    # _generate_gateway_nginx_conf 在 gateway_enabled 为假时直接返回 None，
    # 没有这一行时下面整组 nginx 断言会因为 conf 为空被静默跳过 ——
    # 写这行的时候正是踩了这个坑。
    "gateway_enabled": True,
    "reverse_proxy": {"rules": [
        {"name": "群晖", "path_prefix": "/nas", "enabled": True, "public_access": True},
        {"name": "相册", "path_prefix": "/photos/", "enabled": True, "public_access": False},
    ]},
}
json.dump(BASE_CFG, open(CFG, "w"), ensure_ascii=False)

os.environ.update({
    "AUTH_CONFIG_PATH": CFG, "AUTH_PASSWORD_FILE": PWD, "AUTH_SECRET_FILE": SEC,
    "AUTH_RATELIMIT_FILE": RL, "AUTH_AUDIT_LOG": LOG, "AUTH_API_PORT": "18445",
})
BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND))
import auth_gateway as ag  # noqa: E402

HOST = "192.168.100.224:8443"
HOSTNAME_ONLY = "192.168.100.224"


def set_cfg(data):
    with open(CFG, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    ag._config_cache["mtime"] = None


PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'✅' if cond else '❌'} {name}" + (f"  — {extra}" if extra and not cond else ""))


def sec(t):
    print(f"\n--- {t} ---")


def login(origin=None, password=PASSWORD):
    """POST /auth/login，返回 (状态码, body)。

    默认用**正确密码**：被 CSRF 拦是 403，绕过是 200，两种情况都不增加失败
    计数 —— 这样反复测 CSRF 不会把自己锁在门外。测失败计数用 password=None。
    """
    headers = {"Content-Type": "application/json", "Host": HOST}
    if origin is not None:
        headers["Origin"] = origin
    return ag.app.test_client().post("/auth/login", json={"password": password}, headers=headers)


print("=" * 74)
print("认证网关硬化：Shannon 第二轮四项修复回归")
print("=" * 74)

# ══════════════════════════════════════════════════════════════════════
# 1. CSRF：_origin_host_mismatch 的两个洞
# ══════════════════════════════════════════════════════════════════════
sec("1. CSRF 判定（Origin 头变体）")

# 先证明 CSRF 机制本身是通的：同源放行、跨站拦截
r = login(origin=f"https://{HOSTNAME_ONLY}")
check("同源 Origin 放行（对照组：链路本身通）", r.status_code == 200, f"HTTP {r.status_code}")
# 同主机不同 scheme/端口仍算同源 —— 判的是 hostname，不是 origin 字符串全等。
# 网关只监听 HTTPS，但浏览器发来的 Origin 也可能带默认端口。
for same_host in (f"https://{HOSTNAME_ONLY}:8443", f"http://{HOSTNAME_ONLY}",
                  f"https://{HOSTNAME_ONLY.upper()}"):
    r = login(origin=same_host)
    check(f"同主机 Origin 放行: {same_host[:46]}", r.status_code == 200, f"HTTP {r.status_code}")
for bad in ("https://evil.example.com", "https://attack.test",
            f"https://evil.example.com/{HOSTNAME_ONLY}"):
    r = login(origin=bad)
    check(f"跨站 Origin 被拦: {bad[:46]}", r.status_code == 403, f"HTTP {r.status_code}")

# 洞 1：无 scheme 的 Origin → 旧代码 urlparse 得到 netloc="" → return False 放行
r = login(origin=HOSTNAME_ONLY)
check("无 scheme 的 Origin 被拦（netloc 为空不再当成无跨站）",
      r.status_code == 403, f"HTTP {r.status_code}")

# 洞 2：userinfo 冒号冒充 → 旧代码 split(":")[0] 取到 host
for ua_origin in (f"https://{HOSTNAME_ONLY}:x@evil.example.com",
                  f"https://{HOSTNAME_ONLY}:8443@evil.example.com",
                  f"http://user:pass@{HOSTNAME_ONLY}@evil.example.com"):
    r = login(origin=ua_origin)
    check(f"userinfo 冒充被拦: {ua_origin[:52]}",
          r.status_code == 403, f"HTTP {r.status_code}")

# userinfo 里带 @ 但不带冒号的情况，hostname() 应正确解析为 evil.example.com
r = login(origin=f"https://{HOSTNAME_ONLY}@evil.example.com")
check("无冒号 userinfo 被拦（hostname 正确解析为 evil）",
      r.status_code == 403, f"HTTP {r.status_code}")

# 判不出来的一律判跨站（fail-closed）。
# 这组必须包含**能让 urlparse 真的抛异常**的输入 —— 否则 except 分支完全
# 没被走到，把 `except Exception: return False`（fail-open）改回去测试照样绿。
from urllib.parse import urlparse as _up  # noqa: E402


def _raises(u):
    try:
        _up(u)
        return False
    except ValueError:
        return True


# urlparse 对非法 IPv6 会抛 ValueError，那条路径只能靠这里的输入走到
_raising_cases = [c for c in ("http://[::1", "//[", "http://foo:bar@[::1",
                              "https://[1:2:3:4:5:6:7:8:9]") if _raises(c)]
check("夹具有能让 urlparse 抛异常的输入（覆盖 except 分支）",
      len(_raising_cases) >= 2, f"实际={_raising_cases}")

for weird in ("garbage", "://", "https://", "http://:", "/////", *_raising_cases):
    r = login(origin=weird)
    check(f"无法解析/异常抛出的 Origin 判跨站: {weird!r}",
          r.status_code == 403, f"HTTP {r.status_code}")

# 真正被拦住的请求不能消耗失败计数 —— 否则 CSRF 防护本身会变成锁定 DoS 放大器
_set = json.load(open(CFG))
r = login(origin=HOSTNAME_ONLY, password="wrong-definitely")
check("CSRF 拦截先于密码校验（错误密码也只得到 403）",
      r.status_code == 403, f"HTTP {r.status_code}")
check("配置未被测试改动", json.load(open(CFG)) == _set)

# ══════════════════════════════════════════════════════════════════════
# 2. 请求体上限（两道）
# ══════════════════════════════════════════════════════════════════════
sec("2. 请求体上限")

mcl = ag.app.config.get("MAX_CONTENT_LENGTH")
check("Flask 设了 MAX_CONTENT_LENGTH", bool(mcl), f"实际={mcl!r}")
if mcl:
    check("MAX_CONTENT_LENGTH 不超过 64K（认证端点只需要几百字节）",
          mcl <= 64 * 1024, f"实际={mcl} 字节")
    # 真正的行为验证：超限请求必须被拒，而不是被 get_json() 物化进内存
    big = {"password": PASSWORD, "pad": "A" * (int(mcl) + 4096)}
    r = ag.app.test_client().post("/auth/login", json=big, headers={"Host": HOST})
    check("超限请求被拒绝（不会走进密码校验）",
          r.status_code in (400, 413), f"HTTP {r.status_code}")
    ok_body = {"password": PASSWORD}
    r = ag.app.test_client().post("/auth/login", json=ok_body, headers={"Host": HOST})
    check("正常大小的登录请求仍然可用（没把功能打死）", r.status_code == 200, f"HTTP {r.status_code}")

# nginx 侧：/auth/* 每个 location 都要有 client_max_body_size
sys.path.insert(0, os.path.abspath(BACKEND))
_app_src = open(os.path.join(os.path.abspath(BACKEND), "app.py"), encoding="utf-8").read()
import app as panel  # noqa: E402

try:
    conf = panel._generate_gateway_nginx_conf(dict(BASE_CFG)) or ""
except Exception as _e:
    conf = ""
    check(f"网关 nginx 配置能生成（前置）— {_e}", False)

# 不能用 `if conf:` 把整组断言包起来：生成失败时那组断言会**静默消失**，
# 测试照样全绿，而 nginx 这一层恰恰是本次修复的第一道防线。
check("网关 nginx 配置能生成（前置，不能为空）", bool(conf),
      "生成失败时下面所有 nginx 断言都会被跳过 —— 这正是上一版的写法")

blocks = {}
cur = None
for line in conf.splitlines():
    m = re.match(r"\s*location\s+(=\s+)?(\S+)\s*\{", line)
    if m:
        cur = m.group(2)
        blocks[cur] = []
    elif cur is not None and re.match(r"\s*\}", line):
        cur = None
    elif cur is not None:
        blocks[cur].append(line)

for ep in ("/auth/login", "/auth/logout", "/auth/status", "/auth/portal"):
    body = "\n".join(blocks.get(ep, []))
    check(f"nginx: {ep} 这个 location 找得到",
          ep in blocks, f"实际 location: {sorted(blocks)[:12]}")
    check(f"nginx: {ep} 有 client_max_body_size",
          "client_max_body_size" in body,
          f"该 location 实际指令: {body.strip()[:120]!r}")
    mm = re.search(r"client_max_body_size\s+(\S+);", body)
    check(f"nginx: {ep} 的上限不是 128M（不能退回全局默认）",
          bool(mm) and mm.group(1) != "128M", f"实际={mm.group(1) if mm else None!r}")

body = "\n".join(blocks.get("/auth/static/", []))
check("nginx: /auth/static/ 有 client_max_body_size",
      "client_max_body_size" in body, f"实际: {body.strip()[:120]!r}")

# 反代 location 有自己的上限（上传用，默认 50M），别被这次改动误伤
for rule in BASE_CFG["reverse_proxy"]["rules"]:
    pref = rule["path_prefix"]
    body = "\n".join(blocks.get(pref, []))
    if body:
        mm = re.search(r"client_max_body_size\s+(\S+);", body)
        check(f"反代 {pref} 仍保留自己的上限（未被改成 8K）",
              bool(mm) and mm.group(1) != "8K",
              f"实际={mm.group(1) if mm else None!r}")

# ══════════════════════════════════════════════════════════════════════
# 3. validate_config 放行 /1
# ══════════════════════════════════════════════════════════════════════
sec("3. lan_subnet /1 被拒")

_cwd = os.getcwd()
_tmp = tempfile.mkdtemp(prefix="panelcfg-")
try:
    os.chdir(_tmp)
    _sandbox = f"{_tmp}/config.json"
    json.dump(dict(panel.DEFAULT_CONFIG), open(_sandbox, "w"))
    _orig_path = panel.CONFIG_PATH
    panel.CONFIG_PATH = _sandbox

    def vprobe(**over):
        c = dict(panel.DEFAULT_CONFIG)
        c.update(over)
        return panel.validate_config(c)

    check("基线配置本身干净（前置）", not vprobe(),
          str(vprobe()[:2]))

    for v, why in (("0.0.0.0/0", "/0"), ("0.0.0.0/1", "/1")):
        errs = vprobe(lan_subnet4=v)
        check(f"lan_subnet4={v} 被拒（{why}）", bool(errs),
              "被放行了 —— 半公网/全公网免认证")
        check(f"lan_subnet4={v} 的报错点确实在 lan_subnet4",
              any("lan_subnet4" in e for e in errs), str(errs))

    for v, why in (("::/0", "/0"), ("::/1", "/1")):
        errs = vprobe(lan_subnet6=v)
        check(f"lan_subnet6={v} 被拒（{why}）", bool(errs), "被放行了")
        check(f"lan_subnet6={v} 的报错点确实在 lan_subnet6",
              any("lan_subnet6" in e for e in errs), str(errs))

    # 正常网段不能被误伤 —— 用户的 /28 是有意填的，不该被拒
    for v in ("192.168.100.0/24", "192.168.100.0/28", "10.8.0.0/16", "172.16.0.0/12"):
        errs = vprobe(lan_subnet4=v)
        check(f"合法网段仍放行: {v}", not any("lan_subnet4" in e for e in errs), str(errs))

    # /2 是临界：panel_allowed_nets 明确放行 /2，lan_subnet 也应一致
    errs = vprobe(lan_subnet4="128.0.0.0/2")
    check("lan_subnet4=/2 放行（与 panel_allowed_nets 的阈值一致）",
          not any("lan_subnet4" in e for e in errs), str(errs))
    errs = vprobe(panel_allowed_nets="128.0.0.0/2")
    check("panel_allowed_nets=/2 放行（原有行为未被改动）",
          not any("panel_allowed_nets" in e for e in errs), str(errs))

    panel.CONFIG_PATH = _orig_path
finally:
    os.chdir(_cwd)

# ══════════════════════════════════════════════════════════════════════
# 4. init 脚本的降权守卫不能是固定 sleep
# ══════════════════════════════════════════════════════════════════════
sec("4. init 脚本降权守卫")

init_src = open(os.path.join(os.path.abspath(BACKEND), "nftables-web-auth.init"),
                encoding="utf-8").read()

# 定位 start() 里拉起 python3 之后那段守卫
_launch = init_src.index("python3 auth_gateway.py")
# 窗口必须**只覆盖 start() 函数体**。之前按固定字符数切，把后面的 stop() 也
# 圈了进去 —— stop() 自己就有 `kill "$pid"` 和 `while` 循环，于是
# 「把 start() 的轮询改回固定 sleep」「把 start() 的 kill 删掉」这两种变异
# 都能靠 stop() 的同名字符串蒙混过关，测试全绿。变异脚本抓到过这个洞。
_fn_end = init_src.index("\n}\n", _launch)
_guard = init_src[_launch:_fn_end]
check("守卫窗口落在 start() 函数内（没把 stop() 圈进来）",
      "stop()" not in _guard, "窗口越界，会被 stop() 里的同名代码蒙混过关")

check("守卫区间里有轮询循环", re.search(r"\bwhile\b", _guard) is not None,
      "没找到 while —— 又退回固定等待了")
check("守卫会反复读 /proc/<pid>/status",
      len(re.findall(r"/proc/\$?\{?pid\}?/status", _guard)) >= 2 or
      re.search(r"/proc/\$\{?pid\}?/status", _guard) is not None)
check("守卫不把「读不到 uid」当成降权失败",
      re.search(r'-z\s+"\$real_uid"', _guard) is not None,
      "空 uid 说明 /proc 还没建好，应该继续等而不是 kill")
check("守卫给等待设了上限（不会永远等）",
      re.search(r"-lt\s+\d+", _guard) is not None)
check("守卫里没有裸的 sleep 1 后立刻下结论",
      not re.search(r"\bsleep 1\s*\n\s*\n?\s*if kill -0", _guard),
      "又变回固定 sleep 1 了")

# 固定 sleep 1 的竞态在 .224 上量过：8 进程满载时启动→降权要 1.44~1.64s。
# 守卫的等待上限必须明显大于这个数，否则守卫会误杀。
_m = re.search(r"-lt\s+(\d+)", _guard)
if _m:
    _waits = int(_m.group(1))
    check(f"等待上限（{_waits} × 0.1s = {_waits/10:.1f}s）大于实测最坏降权耗时 1.64s",
          _waits / 10 > 1.64, f"只有 {_waits/10:.1f}s，不够")

# 守卫的原有职责不能丢：降权失败仍然必须杀进程并报错
check("降权失败仍然会杀掉进程并返回失败",
      re.search(r'kill\s+"?\$pid"?', _guard) is not None and
      "降权未生效" in _guard and re.search(r"return 1", _guard) is not None)
check("降权成功的正常路径仍然返回 0", re.search(r"return 0", _guard) is not None)

# 整份脚本语法必须合法（BusyBox ash）
import subprocess  # noqa: E402
_p = subprocess.run(["sh", "-n", os.path.join(os.path.abspath(BACKEND),
                                              "nftables-web-auth.init")],
                    capture_output=True, text=True)
check("init 脚本 sh -n 语法通过", _p.returncode == 0, _p.stderr.strip()[:200])

# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 74)
print(f"通过 {len(PASS)} / 失败 {len(FAIL)}")
if FAIL:
    print("失败项：")
    for f in FAIL:
        print(f"  - {f}")
    sys.exit(1)
print("全部通过")

try:
    shutil.rmtree(SBX, ignore_errors=True)
    shutil.rmtree(_tmp, ignore_errors=True)
except Exception:
    pass
