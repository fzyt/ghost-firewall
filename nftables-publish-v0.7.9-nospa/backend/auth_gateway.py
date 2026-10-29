"""
认证网关服务（进程 B）—— 单端口认证 + 反代分发入口的认证后端。

═══════════════════════════════════════════════════════════════════════
架构定位
═══════════════════════════════════════════════════════════════════════
  进程 A（app.py，5443）  管理面板，仅 LAN 可达。写配置、管 nftables、看日志
  nginx（gateway_port）  公网唯一入口，按 path 前缀分发，做 auth_request
  进程 B（本文件）        认证 API，只监听 127.0.0.1，公网完全不可达

本进程**不 import app.py** —— 进程隔离是刻意的：面板崩了不该带走认证，
反过来也一样。两边只通过磁盘上的同一份 config.json 交换数据。

═══════════════════════════════════════════════════════════════════════
安全契约（改代码前请先读这一段）
═══════════════════════════════════════════════════════════════════════
1. /auth/verify 走 nginx auth_request。nginx 的判定规则是：
      2xx → 放行；401/403 → 拒绝；其他（500 等）→ 报错，同样不放行。
   所以本文件里 **verify 的任何异常路径都必须返回 401**。
   一旦某个 except 分支漏了 token 校验而返回 200，就是完全绕过认证。
   下面的 _verify_or_deny() 把这件事做成结构上不可能漏。

2. token 密钥从 SECRET 文件派生，不直接复用 Flask SECRET_KEY，
   避免两个用途共用同一密钥材料。

3. 登录失败计数 **落盘**。面板进程 A 原来的 _failed_logins 是内存 dict，
   进程重启即清零 → 攻击者重启等待即可绕过。本进程不重复这个错误。

4. 登录失败时，返回体与耗时对「密码错」和「根本没设密码」保持一致，
   防用户名/状态枚举。
"""

import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import subprocess
import threading
import time

import fcntl

from flask import (Flask, Response, jsonify, request, send_from_directory)
from werkzeug.exceptions import RequestEntityTooLarge

# ══════════════════════════════════════════════════════════════════════
# 路径与常量（全部可用环境变量覆盖，便于沙箱测试）
# ══════════════════════════════════════════════════════════════════════

CONFIG_PATH = os.environ.get(
    "AUTH_CONFIG_PATH", "/etc/nftables/nftables-web-config.json")
PASSWORD_FILE = os.environ.get(
    "AUTH_PASSWORD_FILE", "/etc/nftables/nftables-web-password")
SECRET_FILE = os.environ.get(
    "AUTH_SECRET_FILE", "/etc/nftables/nftables-web-secret")
RATELIMIT_FILE = os.environ.get(
    "AUTH_RATELIMIT_FILE", "/etc/nftables/nftables-web-auth-ratelimit.json")
AUDIT_LOG = os.environ.get(
    "AUTH_AUDIT_LOG", "/var/log/nftables-web-auth.log")
# 审计日志体积上限。日志落在 tmpfs 上（.224 的 /var -> /tmp），吃的是内存，
# 所以必须有界；2 MiB ≈ 5900 条记录，轮转后总占用 ≤ 4 MiB。
AUDIT_LOG_MAX_BYTES = int(os.environ.get("AUTH_AUDIT_LOG_MAX_BYTES", str(2 * 1024 * 1024)))

BIND_HOST = os.environ.get("AUTH_BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("AUTH_API_PORT", "8444"))

# 安全参数
TOKEN_TTL_DEFAULT = 1800        # 滑动窗口 30 分钟
# 绝对上限：无论多活跃，到点强制重登。
#
# 2026-10-16 从 0 改成 43200（12 小时）。原来默认 0 = 不启用，于是滑动续期
# 可以无限续命 —— 一张被截获的令牌只要受害者还在用，攻击者那张就永不过期，
# 登出也只吊销得到「受害者手上那一张」（Shannon AUTH-VULN-03）。
# 12 小时的取舍：既保证一天至少重新认证一次，又不至于正常使用时被打断；
# 需要更长的管理员可以调到 604800（7 天，上限由 _absolute_ttl 兜住）。
TOKEN_ABS_TTL_DEFAULT = 43200
TOKEN_REFRESH_RATIO = 0.5       # 剩余不足一半时才重新签发，避免每个资源都回 Set-Cookie
DEVICE_COOKIE_TTL = 31536000    # 设备标识 cookie 一年
PBKDF2_ITERATIONS_MIN = 100000  # 拒绝迭代数过低的存量哈希（等于没加固）

# PBKDF2 并发闸门：限制「同时在跑的 PBKDF2 个数」，防止 GIL 争用把
# 并发做成负优化。
#
# 2026-10-10 实测，同一份代码在两台机器上结论完全相反：
#
#   .224 OpenWrt  Python 3.11.14  2 核  → pbkdf2_hmac **不释放 GIL**
#       并发数   实测墙钟   串行预期   相对串行
#          1      141ms     150ms     1.06x
#          2      529ms     300ms     0.57x   并发反而更慢
#          4     1818ms     601ms     0.33x
#          8     4800ms    1201ms     0.25x   ← threaded=True 的实测形态
#
#   .249 debian   Python 3.13.5   4 核  → pbkdf2_hmac **释放 GIL**
#          2       98ms     189ms     1.94x   并发有效
#          8      218ms     758ms     3.47x
#
# 也就是说「限不限并发」既取决于 Python 版本，也取决于核数，写死任何
# 一个值都会在另一半机器上犯错：写死 1 会让 3.13 上的并发白白排队，
# 写死「不限制」会让 3.11 上的网关被几个并发登录拖垮 4 倍。
# 所以启动时实测一次，按结果决定闸门大小。
#
# 判据：2 线程耗时 / 1 线程耗时。释放 GIL 时应≈1，不释放时应≈2。
# 阈值取 1.4：即使只有 2 核，真并行也能拿到 ~2.0，区分度充足。
def _probe_pbkdf2_parallelism():
    """返回 (闸门大小, 判定说明)。探测失败一律回退到 1（串行最安全）。"""
    iters = 20000   # 只为测出串并行差异，2 万轮足够且不拖慢启动

    def run(n):
        ready, done = threading.Barrier(n + 1), threading.Barrier(n + 1)

        def worker():
            ready.wait()
            hashlib.pbkdf2_hmac("sha256", b"A" * 1024, b"probe", iters)
            done.wait()

        ts = [threading.Thread(target=worker) for _ in range(n)]
        for t in ts:
            t.start()
        ready.wait()
        t0 = time.perf_counter()
        done.wait()
        wall = time.perf_counter() - t0
        for t in ts:
            t.join()
        return wall

    try:
        run(1)                                    # 预热，避开首次调用的冷启动噪声
        one = min(run(1) for _ in range(2))
        two = min(run(2) for _ in range(2))
    except Exception:
        return 1, "探测失败，回退串行"
    if one <= 0:
        return 1, "探测结果异常，回退串行"
    ratio = two / one
    if ratio < 1.4:
        return max(1, os.cpu_count() or 1), f"并发有效（2线程耗时比 {ratio:.2f}）"
    return 1, f"并发无收益（2线程耗时比 {ratio:.2f}，PBKDF2 不释放 GIL）"


PBKDF2_GATE_SIZE, PBKDF2_GATE_WHY = _probe_pbkdf2_parallelism()
PBKDF2_GATE = threading.BoundedSemaphore(PBKDF2_GATE_SIZE)

COOKIE_TOKEN = "gw_token"
COOKIE_DEVICE = "gw_device"

HEADER_FINGERPRINT = "X-Device-Fingerprint"
HEADER_ORIG_SVC = "X-Original-URI"

# 前端静态资源（登录页 / 门户页 / 指纹脚本）。自包含，不引外链。
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
STATIC_ALLOWED = frozenset({
    "base.css", "fingerprint.js", "login.html", "login.js",
    "portal.html", "portal.js", "pixelfield.js", "gate.css",
})

# 两个 HTML 页面的 CSP。两者只差 form-action：登录页有表单要提交到
# /auth/login，门户页没有表单。
#
# 抽成常量是因为 /auth/static/ 也必须用同一套 —— 之前 CSP 只加在
# `/` 和 `GET /auth/login` 两个路由上，而 /auth/static/ 是白名单里的
# 静态文件直达路径，同样能取到 login.html / portal.html。
# 真机实测过：/auth/static/login.html 返回 200 且**没有**该响应头，
# nginx 里 location /auth/static/ 排在 location /auth/ 之前，
# 最长前缀匹配，所以它真的可达，不是一纸空谈。
CSP_LOGIN_HTML = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
CSP_PORTAL_HTML = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; "
    "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
)

# 网关内部端点占用的前缀（与 app.py 的 _RESERVED_GATEWAY_PREFIXES 保持一致）
RESERVED_PREFIXES = ("/_auth", "/auth")

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
# 请求体上限 —— nginx 层已经限了 GATEWAY_AUTH_MAX_BODY，这里是第二道。
#
# 不能只靠 nginx：这份配置会被面板重新生成，也可能被运维手工改过。
# 没有这一层时，auth_login 里的 request.get_json() 会把整个 body 物化进内存
# （100MB 的 body 实测把进程顶到 RSS 461MB，直接触发内核 OOM）。
# 认证端点的请求体只有 {"password":"..."}，8K 远超所需。
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024


@app.after_request
def _harden_response(resp):
    """补齐各端点漏掉的安全响应头。

    2026-10-16：此前只有静态资源、门户页、登录页三处**逐个手写**了
    Cache-Control / nosniff / CSP，而 /auth/status、/auth/login(POST)、
    /auth/logout、/auth/portal 这些同样带会话信息的端点一个都没有 ——
    登录/登出的响应可能被 bfcache 或中间代理缓存下来。

    这里用 setdefault 兜底：已经显式设过的（静态资源的 no-cache、
    HTML 页的 CSP）保持原值不被覆盖。

    为什么加 HSTS：8443 是 HTTPS-only（nginx 终结 TLS），缺 HSTS 时
    首访降级到 http:// 不会被浏览器记住。max-age 取一年，不带
    includeSubDomains —— 网关可能和路由器上其它服务共用域名，
    把子域一起钉死会误伤它们。
    """
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault("Pragma", "no-cache")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp


# ══════════════════════════════════════════════════════════════════════
# 密钥派生
# ══════════════════════════════════════════════════════════════════════

def _load_secret() -> bytes:
    """读取持久化密钥。

    与 app.py 的 _init_app_secret 同源文件，但这里派生独立子密钥，
    使 token 签名密钥与 Flask session 密钥互不相关。
    """
    if os.path.exists(SECRET_FILE):
        try:
            with open(SECRET_FILE, "r") as f:
                raw = f.read().strip()
            if raw:
                return raw.encode()
        except OSError:
            pass
    return secrets.token_hex(32).encode()


def _token_key() -> bytes:
    """从主密钥派生 token 专用密钥（域分离）。"""
    return hmac.new(_load_secret(), b"nftables-web/auth-token/v1", hashlib.sha256).digest()


# ══════════════════════════════════════════════════════════════════════
# 配置读取（带 mtime 缓存，避免每个请求都读盘）
# ══════════════════════════════════════════════════════════════════════

_config_cache = {"mtime": None, "data": None}


def load_gateway_config() -> dict:
    """读共享配置。读失败一律返回安全默认，绝不抛异常影响认证链路。"""
    try:
        mtime = os.path.getmtime(CONFIG_PATH)
    except OSError:
        return {}
    if _config_cache["mtime"] == mtime and _config_cache["data"] is not None:
        return _config_cache["data"]
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except (OSError, json.JSONDecodeError):
        # 配置读不了时用空 dict：此时 _session_ttl 回落到默认值，
        # 门户服务列表为空 —— 都是「不放行」的方向，安全。
        data = {}
    _config_cache["mtime"] = mtime
    _config_cache["data"] = data
    return data


def _int(v, default):
    try:
        if isinstance(v, bool):
            return default
        n = int(v)
        return n if n == v or isinstance(v, float) else default
    except (TypeError, ValueError):
        return default


def _session_ttl(cfg) -> int:
    ttl = _int(cfg.get("auth_session_timeout"), TOKEN_TTL_DEFAULT)
    return ttl if 60 <= ttl <= 86400 else TOKEN_TTL_DEFAULT


def _absolute_ttl(cfg) -> int:
    """绝对上限。**取不到合法正值时回落到默认值，不再回落到 0。**

    2026-10-16：原来这里 `else 0`，也就是「配置缺失/非法 → 绝对上限关闭」。
    改成默认有上限之后，这条分支就成了漏洞的最后一道口子：存量配置的
    auth_absolute_timeout 里躺着一个显式的 0（旧的出厂默认值），面板侧的
    迁移要等它保存配置才会落盘，而网关是**直接读磁盘**的 —— 在那之前
    这个 0 一直生效，风险一点没关。

    所以在执行点兜底：任何非正数或越界的值一律取默认。真的需要更长的
    上限就配一个 1..604800 的正数，语义清晰且是显式配置。

    这里和 validate_config 的范围校验（0..604800）刻意不一致：校验要放过
    存量的 0，否则老配置连保存都会被拒；执行则不能认 0。当校验侧把 0
    迁走之后，两边自然收敛。
    """
    ttl = _int(cfg.get("auth_absolute_timeout"), TOKEN_ABS_TTL_DEFAULT)
    return ttl if 0 < ttl <= 604800 else TOKEN_ABS_TTL_DEFAULT


# ══════════════════════════════════════════════════════════════════════
# 密码校验
# ══════════════════════════════════════════════════════════════════════

def _verify_password(password: str, stored: str) -> bool:
    """PBKDF2-HMAC-SHA256 校验，常量时间比较。

    整个函数体都在 PBKDF2_GATE 里：真实路径和下面的 dummy 路径
    都必须过闸门。只给真实路径加会让异常路径绕开限流，出现
    「未配密码」的请求不排队、「配了密码」的排队——既泄露状态，
    又给了一个绕开限流的廉价入口。
    """
    with PBKDF2_GATE:
        try:
            algo, iters, salt, hash_hex = stored.split("$", 3)
            if algo != "pbkdf2_sha256":
                raise ValueError("algo")
            iters = int(iters)
            if iters < PBKDF2_ITERATIONS_MIN:
                # 迭代数过低 = 哈希强度形同虚设，直接拒绝而不是"降级接受"
                raise ValueError("iters")
        except Exception:
            # 即便哈希损坏/未配置，也要真跑一次 PBKDF2。原来这条路径直接
            # return False，耗时不到 1ms；正常路径要跑几万到几十万轮迭代。
            # 攻击者只发一个 {"password":"x"} 就能靠响应耗时区分
            # 「部署没配密码」和「配了密码」——等于一个免认证的状态枚举口。
            # 迭代数取下限：既去掉那个数量级差异，又不让畸形配置触发
            # 天文数字的迭代把请求线程拖死。
            hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                b"nftables-web-dummy", PBKDF2_ITERATIONS_MIN)
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), iters)
        return hmac.compare_digest(digest.hex(), hash_hex)


def _password_hash() -> str:
    try:
        with open(PASSWORD_FILE, "r") as f:
            data = json.load(f)
        return data.get("hash", "") if isinstance(data, dict) else ""
    except (OSError, json.JSONDecodeError, AttributeError):
        return ""


# ══════════════════════════════════════════════════════════════════════
# Token：payload.signature（base64url，无填充）
# ══════════════════════════════════════════════════════════════════════

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _token_epoch() -> int:
    """当前令牌世代号。改一次密码就 +1，之前签发的令牌全部作废。

    为什么需要它：登出只吊销**自己那一个** jti，而改密码这个动作
    本该让所有设备上的旧会话一起失效。面板侧 auth_change_password 原来
    只做了 session.clear()（那只清当前浏览器自己的面板会话），网关 JWT
    完全没动 —— 改完密码，所有设备上用旧密码拿到的 gw_token 继续有效，
    而且滑动续期意味着只要一直用，它可能永不过期。
    """
    try:
        return int(load_gateway_config().get("auth_token_epoch", 0) or 0)
    except (TypeError, ValueError):
        return 0


def issue_token(user: str, device_id: str, ttl: int, abs_deadline: int = 0) -> str:
    now = int(time.time())
    exp = now + ttl
    if abs_deadline:
        exp = min(exp, abs_deadline)
    payload = {
        "sub": user,
        "dev": device_id,
        "iat": now,
        "exp": exp,
        "jti": secrets.token_urlsafe(12),   # 每次续期换新，杜绝旧 token 重放
        # 世代号：缺这个字段的旧令牌按 0 处理，所以第一次改密码
        # （0 → 1）就能把它们一次性清掉，不需要额外的兼容期。
        "ep": _token_epoch(),
    }
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(hmac.new(_token_key(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def parse_token(token: str):
    """校验签名与 exp。返回 payload dict，任何异常/不合法一律返回 None。"""
    if not token or not isinstance(token, str) or token.count(".") != 1:
        return None
    body, _, sig = token.partition(".")
    try:
        expected = hmac.new(_token_key(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64d(sig), expected):
            return None
        payload = json.loads(_b64d(body))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp <= int(time.time()):
        return None
    return payload


# ══════════════════════════════════════════════════════════════════════
# 吊销表（落盘 + fcntl 锁）
# ══════════════════════════════════════════════════════════════════════

def _revocation_path() -> str:
    return os.path.splitext(RATELIMIT_FILE)[0] + "-revoked.json"


# 进程内的 last-known-good 吊销表。
#
# 吊销表落盘且可能被写坏（写一半、磁盘满、权限丢）。一旦读不出来就必须有个
# 东西可退 —— 否则只能在「全部放行」和「全部拒绝」之间二选一。
_REVOKED_LKG = None


def load_revoked():
    """读吊销表。

    返回 None 表示「读不到、判不出来」—— 调用方**必须**按 fail-closed 处理。

    2026-10-16：这里原来是
        except (OSError, json.JSONDecodeError):
            return {}
    空字典会让 is_revoked 对所有 jti 返回 False —— 也就是**之前显式登出
    吊销掉的令牌全部复活**。文件一次写坏就等于把吊销机制整个关掉，而且是
    静默的。这和项目里「限流表损坏 fail-open、恢复链 fail-closed」的取舍
    相反：限流表坏了顶多多试几次，吊销表坏了是已失效的凭据重新可用。
    """
    global _REVOKED_LKG
    try:
        with open(_revocation_path(), "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("吊销表不是 JSON 对象")
    except FileNotFoundError:
        # 文件不存在有两种完全不同的含义，必须分开：
        #   · 进程启动至今**一次都没成功读到过** → 确实从未吊销过，正常初始状态
        #   · 刚才还读得好好的，现在没了         → 故障（被删/被清/挂载掉了）
        # 混为一谈会让「把吊销表删掉」这个动作**主动复活所有已吊销的令牌** ——
        # .224 线上实测踩到过：unlink 掉吊销文件后，刚才登出吊销掉的
        # token 立刻又能用了。所以第二种必须继续用 last-known-good。
        if _REVOKED_LKG is None:
            _REVOKED_LKG = {}
            return {}
        return _REVOKED_LKG
    except (OSError, json.JSONDecodeError, ValueError):
        # 退到 last-known-good；连它都没有（进程刚起、文件就是坏的），
        # 返回 None 交给 is_revoked 判为已吊销。
        if _REVOKED_LKG is None:
            return None
        return _REVOKED_LKG
    _REVOKED_LKG = data
    return data


def revoke_jti(jti: str, exp: int) -> bool:
    """吊销一个 jti。返回**是否真的落盘了**。exp 已过的不写盘，避免表无限增长。

    返回值不是装饰性的：吊销没落盘 = 那个令牌在服务端还活着。调用方必须
    据此决定是明确失败（logout）还是只留审计（login），不能静默当成功。

    2026-10-16 .224 实测踩到两个坑，这里一并改掉：

    1. 原来结尾是裸的 `os.chmod(path, 0o600)`。属主一旦被外部改动（我自己的
       验证脚本 chown 成 root），chmod 抛 PermissionError，把**已经 fsync
       落盘、吊销早已成立**的 logout 打成 500。收紧权限失败不等于吊销失败。
    2. 原来用 `open(path, "a+")` 先按 umask 建文件（644）再 chmod，中间有一个
       世界可读窗口。改成 os.open(..., 0o600) 在创建那一刻就是 0600。

    写入失败仍然必须失败 —— 那是「登出看着成功了，其实令牌还活着」。
    """
    if not jti or exp <= int(time.time()):
        # 令牌本来就已过期，登不登销都不影响可用性
        return True
    path = _revocation_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # O_CREAT 的 mode 只在**新建**时生效；已存在的文件保持原权限，
        # 交给下面的收紧逻辑处理。
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as e:
        # 典型触发：/etc/nftables 变成只读挂载，或吊销表被 chown 成了别人
        audit("revocation_open_failed", error=type(e).__name__)
        return False
    try:
        with os.fdopen(fd, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                try:
                    data = json.load(f)
                    if not isinstance(data, dict):
                        data = {}
                except (json.JSONDecodeError, ValueError):
                    data = {}
                data[jti] = exp
                # 清掉已过期的，防止文件无限增长
                now = int(time.time())
                data = {k: v for k, v in data.items()
                        if isinstance(v, int) and v > now}
                f.seek(0)
                f.truncate()
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except (OSError, ValueError, TypeError) as e:
        audit("revocation_write_failed", error=type(e).__name__)
        return False
    # 数据已 fsync 落盘、吊销成立，这里只负责把权限收回来。已经紧的**不动** ——
    # 属主不对时 chmod 本来就大概率没权，白白抛一次把 logout 打成 500。
    try:
        if (os.stat(path).st_mode & 0o777) & 0o077:
            os.chmod(path, 0o600)
    except OSError:
        audit("revocation_chmod_failed")
    return True


def is_revoked(jti: str) -> bool:
    if not jti:
        return False
    data = load_revoked()
    if data is None:
        # 吊销表读不了、又没有 last-known-good 可退：判不出来就当已吊销。
        # 安全关键路径必须 fail-closed —— 代价是这次所有人被拒，
        # 但「已登出的令牌复活」远比「临时登不出」严重。
        audit("revocation_unreadable")
        return True
    exp = data.get(jti)
    return isinstance(exp, int) and exp > int(time.time())


# ══════════════════════════════════════════════════════════════════════
# 登录限流（落盘 + fcntl 锁）
# ══════════════════════════════════════════════════════════════════════

RATE_LIMIT_WINDOW = 300     # 5 分钟内
RATE_LIMIT_MAX_FAILS = 5
RATE_LIMIT_LOCKOUT = 900    # 锁 15 分钟

# /auth/status 的只读限流状态（进程内，不落盘）
_STATUS_HITS = {}
_STATUS_RATE_LOCK = threading.Lock()

# 限流表不可用时的进程内兜底计数，以及「只警告一次」的闸门。
_RATELIMIT_DEGRADED = {"warned": False}
_RATE_FALLBACK = {}


def _ratelimit_degrade(e):
    """限流表落盘不可用 → 降级到进程内内存，并只警告一次。

    2026-10-16 `.224` 实测（跑真实用户流程时撞上）：`/etc/nftables` 是
    `drwxr-sr-x root:nftweb` —— **组只有 r-x，没有写权限**。网关降权后以
    uid 1000 运行，建不了这张表。init 脚本以 root 预建了它，所以平时不暴露；
    但表一旦缺失（误删、tmpfs 被清、`prepare_nftweb_files` 失败），
    `open(path, "a+")` 抛 PermissionError，整个 auth_login 走 except Exception
    → **HTTP 500**。

    后果是「一张表被删 = 所有人永久登不进」，而且**没有任何自愈路径** ——
    uid 1000 永远重建不出这张表。实测复现：移走表后连续两次登录都是 500，
    表也不会被重建。

    取舍：这里选 **fail-open**（放行 + 审计），不是 fail-closed。
      · 代价：抗暴力破解能力暂时下降（失败次数不再跨重启累计）。
      · 收益：不会把人锁在门外。
    这也正是项目里既定的取舍 —— 「限流表损坏 fail-open、吊销表损坏
    fail-closed」：限流表坏了顶多多试几次，吊销表坏了是已失效凭据重新可用。

    面板侧早就有同样的降级（`app.py` 的 `_ratelimit_degrade`），网关这边是漏的。
    """
    if not _RATELIMIT_DEGRADED["warned"]:
        _RATELIMIT_DEGRADED["warned"] = True
        print(f'[WARNING] 登录限流落盘不可用（{type(e).__name__}: {e}），'
              f'降级为内存计数 —— 网关重启后失败次数会清零', flush=True)
    audit("ratelimit_degraded", error=type(e).__name__)


def _ratelimit_fallback_mutate(ip: str, on_fail: bool):
    """限流表不可用时的内存版，语义与落盘版一致。

    同样要能真的挡住暴力破解 —— 降级不等于不设防，只是不跨重启累计。
    """
    now = time.time()
    rec = _RATE_FALLBACK.get(ip)
    rec = rec if isinstance(rec, dict) else {}
    fails = [t for t in rec.get("fails", [])
             if isinstance(t, (int, float)) and now - t < RATE_LIMIT_WINDOW]
    locked_until = rec.get("locked_until", 0)
    if isinstance(locked_until, (int, float)) and locked_until > now:
        return True, len(fails)
    if on_fail:
        fails.append(now)
        if len(fails) >= RATE_LIMIT_MAX_FAILS:
            rec = {"locked_until": now + RATE_LIMIT_LOCKOUT, "fails": []}
        else:
            rec = {"locked_until": 0, "fails": fails}
    else:
        rec = {}                       # 成功登录：清空该 IP 的失败记录
    _RATE_FALLBACK[ip] = rec
    return False, len(rec.get("fails", []))


def _mutate_ratelimit(ip: str, on_fail: bool):
    """原子地读改写限流表。返回 (locked, fail_count)。

    整段包在 try 里：限流表写不了**绝不能**把登录整个搞挂。
    见 `_ratelimit_degrade` 的说明（.224 实测：表缺失 = 永久 500）。
    """
    path = RATELIMIT_FILE
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except Exception as e:  # noqa: BLE001
        _ratelimit_degrade(e)
        return _ratelimit_fallback_mutate(ip, on_fail)
    try:
        with os.fdopen(fd, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.seek(0)
                try:
                    data = json.load(f)
                    if not isinstance(data, dict):
                        data = {}
                except (json.JSONDecodeError, ValueError):
                    data = {}

                now = time.time()
                rec = data.get(ip) if isinstance(data.get(ip), dict) else {}
                locked_until = rec.get("locked_until", 0)
                if isinstance(locked_until, (int, float)) and locked_until > now:
                    return True, len(rec.get("fails", []))

                if on_fail:
                    fails = [t for t in rec.get("fails", [])
                             if isinstance(t, (int, float)) and now - t < RATE_LIMIT_WINDOW]
                    fails.append(now)
                    rec["fails"] = fails
                    if len(fails) >= RATE_LIMIT_MAX_FAILS:
                        rec["locked_until"] = now + RATE_LIMIT_LOCKOUT
                        rec["fails"] = []
                    data[ip] = rec
                elif ip in data:
                    # 成功登录：清空该 IP 的失败记录
                    data.pop(ip, None)

                # 顺手清理过期条目，防止表无限膨胀
                cutoff = now - (RATE_LIMIT_LOCKOUT + RATE_LIMIT_WINDOW)
                for k in [k for k, v in data.items()
                          if not isinstance(v, dict)
                          or max(list(v.get("fails", []) or [0]) + [v.get("locked_until", 0)]) < cutoff]:
                    data.pop(k, None)

                f.seek(0)
                f.truncate()
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())

                rec = data.get(ip, {})
                return False, len(rec.get("fails", []))
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:  # noqa: BLE001
        # 读改写中途失败：计数没落盘，退回内存版。**不能**当成「没失败过」
        # 放行 —— 那等于把暴力破解防护悄悄关掉。
        _ratelimit_degrade(e)
        return _ratelimit_fallback_mutate(ip, on_fail)
    finally:
        # 已存在的文件可能还是 init 脚本之外的路径建出来的（0644）。
        # 收紧是 best-effort：数据已经 fsync、计数已经生效，
        # 收紧失败不该反过来把这次计数变成降级 —— 和 revoke_jti 同一个坑。
        try:
            if (os.stat(path).st_mode & 0o777) & 0o077:
                os.chmod(path, 0o600)
        except OSError:
            audit("ratelimit_chmod_failed")


# ══════════════════════════════════════════════════════════════════════
# 审计日志（JSONL 落盘 + syslog 转发）
# ══════════════════════════════════════════════════════════════════════

# 只有低频安全事件才进 syslog。verify_denied / token_refreshed 刻意排除：
# verify_denied 每个未认证请求都触发，全 WAN 打过来会把远程日志服务器刷爆，
# 真正该看的那几条反而被埋掉。这两类事件在本地 JSONL 里仍然是全的。
_SYSLOG_EVENTS = {"login_ok": "info", "logout": "info",
                  "login_fail": "warn", "lockout": "err"}
_SYSLOG_TAG = "nftables-web-auth"


def _sanitize(value, limit=120):
    """剥掉控制字符。

    UA / URI 都带客户端可控内容，原样写进 syslog 等于给了日志注入：
    一个 UA 里塞个换行，就能在远程日志里凭空伪造出一整行「登录成功」。
    所以非可打印字符一律丢掉，长度也截住。
    """
    if not value:
        return ""
    return "".join(c for c in str(value) if c.isprintable())[:limit].strip()


def _syslog(event: str, rec: dict):
    """发一条 syslog，让 logd 转发到远程日志服务器。

    本地 JSONL 才是权威记录，syslog 只是给它开一个外送通道，
    所以任何异常都吞掉 —— 不值得为一条日志冒认证流程的风险。
    """
    level = _SYSLOG_EVENTS.get(event)
    if not level:
        return
    parts = [event]
    for k in ("user", "ip", "device", "fp", "uri", "reason"):
        v = _sanitize(rec.get(k))
        if v:
            parts.append(f"{k}={v}")
    try:
        subprocess.run(
            ["logger", "-t", _SYSLOG_TAG, "-p", f"user.{level}", " ".join(parts)],
            capture_output=True, timeout=3,
        )
    except Exception:
        pass


def _audit_maybe_rotate(path: str, incoming: int = 0) -> None:
    """审计日志加上这一笔就会超上限就轮转。**任何失败都吞掉** —— 日志不能反过来阻断认证。

    2026-10-16（Shannon AUTH-VULN-05）：`audit()` 原来是无脑 `open(path, "a")`
    追加，没有任何上限。一条审计记录约 350 字节，被持续触发（爆破、认证
    失败、异常）时文件只涨不落。

    报告里把机制写成「占满磁盘」，这是**错的**：.224 上 `/var` 是 `/tmp`
    的软链、落在 tmpfs 上（实测 490 MiB），所以吃的是 **RAM**，不是磁盘。
    在一台只有 1 GB 内存的路由上，无上限的审计日志能把整机拖垮 ——
    这是可用性问题，也顺带是取证问题（进程 OOM 被杀时日志可能一起没）。

    判据是 `当前大小 + 这一行 > 上限` 而不是 `当前大小 >= 上限`：先判后写
    的写法会让当前文件最多溢出**一整行**（实测 4004 > 4000），于是
    「总占用 ≤ 2×上限」这条硬边界差一点点不成立。把这一行的长度算进去，
    边界才是真的。

    为什么单文件轮转、只留一代：
      · 总占用恒定 ≤ 2× 上限。2 MiB × 2 = 4 MiB，占 .224 可用内存的 0.5%，
        可以忽略；而留更多代在 tmpfs 上没有意义。
      · 面板的日志视图读的是**当前文件的尾部若干行**（app.py 里
        `raw_lines[-limit:]`），轮转后它照样读得到当前代，不受影响。
    """
    try:
        if os.path.getsize(path) + incoming <= AUDIT_LOG_MAX_BYTES:
            return
    except OSError:
        return          # 文件不存在：紧接着的写入会新建，无需轮转
    try:
        # 用 replace 而不是 rename —— 它是原子的，旧的 .1 不会和新内容混在一起，
        # 且天然完成「新一代覆盖上一代」。
        os.replace(path, path + ".1")
    except OSError:
        # 轮转不成（目录只读、跨设备等）就地截断：宁可丢历史，
        # 也不能让文件继续无限长把 RAM 吃光。
        try:
            open(path, "w").close()
        except OSError:
            pass


def audit(event: str, **fields):
    """写审计日志。任何失败都不能影响认证流程本身。"""
    try:
        rec = {
            "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            "event": event,
            "ip": client_ip(),
            "device": fields.pop("device", None),
            "fp": fields.pop("fp", None),
            "user": fields.pop("user", None),
            "ua": (request.headers.get("User-Agent", "") or "")[:200],
            "uri": (request.headers.get(HEADER_ORIG_SVC)
                    or request.path or "")[:200],
        }
        rec.update(fields)
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        _audit_maybe_rotate(AUDIT_LOG, len(line.encode("utf-8")))
        with open(AUDIT_LOG, "a") as f:
            f.write(line)
    except Exception:
        pass   # 审计失败不能反过来阻断认证

    # 放 try 外面：_syslog 自己吞所有异常，这里不该连带影响上面的落盘
    try:
        _syslog(event, rec)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════
# 请求上下文
# ══════════════════════════════════════════════════════════════════════

def client_ip() -> str:
    """取真实客户端 IP。

    本进程只监听 127.0.0.1，nginx 的 auth_request 侧会透传 X-Real-IP，
    所以正常路径必须读头 —— request.remote_addr 永远是 127.0.0.1。

    ⚠ 但**只有来自回环的请求才允许采信代理头**（2026-10-07 加固）。
    原来是无条件采信，于是「只要能碰到这个端口，就能声明任意源 IP」——
    而 is_lan_source 的免认证判定完全建立在源 IP 上，这条链一旦成立
    就是完整的认证绕过。Shannon 把这两条串成了攻击链，实测确认：
    直接打认证端口 + 伪造 X-Real-IP 为内网地址 → 免认证直通所有服务。

    现在非回环来源一律只认 remote_addr（即真实对端），判不出内网就
    自然落到「要认证」，方向是 fail-closed。
    """
    remote = (request.remote_addr or "").strip()
    try:
        from_local = ipaddress.ip_address(remote).is_loopback
    except ValueError:
        # 没有 remote_addr 的场景（单测客户端等）：按本机处理，
        # 否则测试无法构造 X-Real-IP。真实 HTTP 请求一定有 remote_addr。
        from_local = not remote

    ip = ""
    if from_local:
        ip = (request.headers.get("X-Real-IP")
              or request.headers.get("X-Forwarded-For", "").split(",")[0]
              or "")
    if not ip:
        ip = remote
    ip = ip.strip()
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ""


def is_lan_source(cfg) -> bool:
    """判断来源是否属于内网。判定失败一律判 False（要认证）。

    **配了 lan_subnet4 / lan_subnet6 就只认它们**，一个都没配才回落到
    is_private。

    2026-10-07 修复（Shannon 渗透测试 + 实测复现）：原来网段没命中时直接
    `return addr.is_private`，导致「配了网段等于没配」——

        lan_subnet4 = 192.168.100.0/24 的情况下实测：
            192.168.100.50 → 200 X-Auth-Via=lan-bypass   正确
            192.168.50.5   → 200 X-Auth-Via=lan-bypass   不该放行
            10.0.0.5       → 200 X-Auth-Via=lan-bypass   不该放行
            172.16.3.4     → 200 X-Auth-Via=lan-bypass   不该放行

    is_private 覆盖整个 RFC1918，于是**任何身处咖啡厅/酒店/公司/邻居 Wi-Fi
    的访客（源 IP 是私网段）访问公网网关端口时会被直接判定为内网、完全免认证**，
    直通所有 public_access=true 的服务。本函数原来的 docstring 恰恰写着
    「用户可以用 lan_subnet4 收紧范围」——那句话当时是假的。

    顺带把 auth_lan_bypass 的缺省值从 True 改成 False：配置缺失时应当
    要求认证（fail-closed），而不是默认放行。
    """
    if not cfg.get("auth_lan_bypass", False):
        return False
    ip = client_ip()
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if addr.is_loopback:
        return True

    subnets = []
    for key in ("lan_subnet4", "lan_subnet6"):
        raw = str(cfg.get(key, "") or "").strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        # /0 匹配一切。留着它等于把「全员免认证」的开关交给一个手滑的输入：
        # 实测把 lan_subnet4 设成 0.0.0.0/0 后，8.8.8.8 / 1.1.1.1 等公网 IP
        # 全部 /auth/verify → 200 + X-Auth-Via: lan-bypass，且面板保存接口
        # 不拦、risks 为空。配置可能被手改、被备份恢复、或被有写权限的人改，
        # 所以这里必须**不理会 /0**，而不是信任它。
        if net.prefixlen == 0:
            continue
        subnets.append(net)

    # 配了可用网段 → 只认网段。这才是 lan_subnet4 存在的意义。
    if subnets:
        return any(addr in n for n in subnets)

    # 一个可用网段都没有（压根没配，或配的全是 /0）：一律要求认证。
    # 原先这里回落到 addr.is_private，等于「对所有内网地址免认证」——
    # 咖啡厅/酒店/公司/邻居 Wi-Fi 的访客源 IP 就是私网段，能直接
    # 访问公网网关端口并被放行。fail-closed。
    return False


def device_id_from_request() -> str:
    did = request.cookies.get(COOKIE_DEVICE, "")
    if did and 8 <= len(did) <= 64 and all(
            c.isalnum() or c in "-_" for c in did):
        return did
    return secrets.token_urlsafe(16)


def fingerprint() -> str:
    fp = (request.headers.get(HEADER_FINGERPRINT) or "").strip()
    # 指纹由前端 JS 算出后传上来，这里只做长度/字符集收敛，不解释其语义
    return fp[:64] if fp and all(c.isalnum() or c in "-_" for c in fp) else ""


# ══════════════════════════════════════════════════════════════════════
# 端点
# ══════════════════════════════════════════════════════════════════════

@app.route("/auth/health")
def health():
    """存活探针。注意：只回进程状态，不代表认证可用。"""
    return jsonify({"ok": True, "service": "auth-gateway"})


@app.route("/auth/static/<path:filename>")
def static_files(filename):
    """登录页 / 门户页的静态资源。

    走白名单而不是 send_from_directory 的通配：即使 basename 校验
    出现意外，白名单也让「能读到的文件集合」是固定且可审计的。
    """
    if filename not in STATIC_ALLOWED:
        return jsonify({"success": False, "code": "NOT_FOUND"}), 404
    resp = send_from_directory(STATIC_DIR, filename)
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    # HTML 必须带 CSP：白名单里的 login.html / portal.html 从这里也能直接取到，
    # 少了这一头就等于多了一条绕过 CSP 的路。CSS/JS 加了也无害。
    if filename.endswith(".html"):
        resp.headers["Content-Security-Policy"] = (
            CSP_PORTAL_HTML if filename == "portal.html" else CSP_LOGIN_HTML)
    return resp


@app.route("/")
def portal_page():
    """门户页。真正的数据由 /auth/portal 以 JSON 提供。"""
    resp = send_from_directory(STATIC_DIR, "portal.html")
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    # 门户页自己只发同源请求；CSP 收紧到 'self'，
    # 连内联脚本都禁掉（页面用的是外部 .js 文件）。
    resp.headers["Content-Security-Policy"] = CSP_PORTAL_HTML
    return resp


@app.route("/auth/login", methods=["GET"])
def auth_login_page():
    """登录页本身。

    与 POST /auth/login 同路径不同方法。这里不校验登录态 ——
    未登录本来就该看到登录页；已登录的情况由前端 JS 探测后自动跳走。
    """
    resp = send_from_directory(STATIC_DIR, "login.html")
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = CSP_LOGIN_HTML
    return resp


def _status_rate_ok(window=60, limit=120):
    """/auth/status 的进程内滑动窗口限流。

    **刻意不用登录那个 _mutate_ratelimit**：那是文件锁、失败 5 次锁 15 分钟，
    拿来做只读状态查询的限流会把正常用户直接锁在门外。这里只做计数，
    最多让这一个端点慢下来，不影响登录、不落盘、不跨进程共享。

    内存里只留最近的源 IP，窗口过期即清，不会无界增长。
    """
    now = int(time.time())
    ip = client_ip() or "-"
    with _STATUS_RATE_LOCK:
        hits = [t for t in _STATUS_HITS.get(ip, []) if now - t < window]
        if len(hits) >= limit:
            _STATUS_HITS[ip] = hits          # 回写，避免被限流时无限增长
            return False
        hits.append(now)
        _STATUS_HITS[ip] = hits
        # 清掉没有近期记录的源 IP，防止字典无界增长
        if len(_STATUS_HITS) > 512:
            for k, v in list(_STATUS_HITS.items()):
                if not v or now - max(v) >= window:
                    _STATUS_HITS.pop(k, None)
    return True


@app.route("/auth/status", methods=["GET"])
def auth_status():
    # 限流：这个端点不需要密码就能打，未限流时等于一个免费的状态枚举口
    # （Shannon AUTH-05）。实测连打 30 次全部 200。
    # 阈值按「家庭路由器 + 少量设备」定：门户每次打开只调 1 次，
    # 同一 NAT 后面的几台设备共用一个源 IP，留 120 次/分钟余量很宽。
    if not _status_rate_ok():
        return jsonify({"success": False, "code": "RATE_LIMITED",
                        "message": "请求过于频繁，请稍后重试"}), 429

    cfg = load_gateway_config()
    if is_lan_source(cfg):
        # 不再返回 via="lan-bypass"（Shannon AUTHZ-06）。
        # 那个字符串等于把「内网豁免」这套机制直接讲给任何能连到这里的人听，
        # 可用来校准哪些来源 IP 被当作内网。门户真正需要的只是「有没有会话
        # 倒计时」，用 expires_in 在不在表达就够了，不必知道走的哪条路。
        return jsonify({
            "authenticated": True, "user": "lan",
            "device_id": device_id_from_request(),
        })
    payload = parse_token(request.cookies.get(COOKIE_TOKEN, ""))
    if not payload or is_revoked(payload.get("jti", "")):
        return jsonify({"authenticated": False})
    return jsonify({
        "authenticated": True,
        "user": payload.get("sub"), "device_id": payload.get("dev"),
        "fp": fingerprint(),
        "expires_in": max(0, int(payload["exp"]) - int(time.time())),
    })


@app.route("/auth/login", methods=["POST"])
def auth_login():
    cfg = load_gateway_config()

    # CSRF 缓解：非同源请求直接拒。密码登录是「主动操作」，
    # 跨站表单强制登录可把受害者踢下线并诱导其在伪造站点输入密码。
    #
    # Origin: null 不是「没检查」，而是浏览器明确报告「这个请求来自一个
    # 不透明来源」——沙箱 iframe（sandbox 属性）、data: URL、跨站重定向都会
    # 产生它。之前把 "null" 放进白名单等于给 CSRF 防护开了一条后门：
    # 攻击者页面把 /auth/login 塞进沙箱 iframe，就能拿受害者浏览器
    # 连打 5 次错误密码（5 分钟内），把受害者 IP 锁死 15 分钟，可反复触发。
    # 实测确认：Origin: null → 401（放行到密码校验），
    #          Origin: https://evil.example.com → 403（正确拦截）。
    #
    # 现在 null 一律按跨站拒绝。不影响正常客户端：不发 Origin 的
    # curl / 脚本走下面的「Origin 缺失」分支，逻辑没变。
    origin = (request.headers.get("Origin") or "").strip()
    referer = (request.headers.get("Referer") or "").strip()
    if origin == "null":
        audit("login_csrf_blocked", origin="null", referer=referer[:120])
        return jsonify({"success": False, "code": "BAD_ORIGIN",
                        "message": "请求来源不被信任"}), 403
    if origin and _origin_host_mismatch(origin):
        audit("login_csrf_blocked", origin=origin[:120])
        return jsonify({"success": False, "code": "BAD_ORIGIN",
                        "message": "请求来源不被信任"}), 403
    if not origin and referer and _origin_host_mismatch(referer):
        audit("login_csrf_blocked", referer=referer[:120])
        return jsonify({"success": False, "code": "BAD_ORIGIN",
                        "message": "请求来源不被信任"}), 403

    ip = client_ip()
    # 只读检查是否已被锁（不改动计数）
    if _is_locked(ip):
        audit("login_rate_limited")
        return jsonify({"success": False, "code": "RATE_LIMITED",
                        "message": "失败次数过多，请稍后再试"}), 429

    # 请求体上限 —— 在**读之前**判，不依赖 get_json 的异常行为。
    #
    # 为什么不只靠 get_json 抛 RequestEntityTooLarge：silent=True 会把它
    # 一并吞掉并返回 None，于是 password="" → 401 AUTH_FAILED。body 确实没被
    # 物化（安全目标达成了），但对外伪装成「密码错误」，既误导排查，也让调用方
    # 分不清「密码真的错了」和「包太大」。实测就是这个结果。
    #
    # 下面还有一道 except RequestEntityTooLarge。两道对「带 Content-Length 的
    # 超限请求」确实是冗余的（各自单独都够，实测删掉任何一道客户端仍拿到
    # 413），保留是纵深防御：前置检查不读 body，except 兜住 werkzeug 自己抛的
    # 情况。两条都失效才会退化成 401 —— 那种变异在测试里是被抓着的。
    _max_len = app.config.get("MAX_CONTENT_LENGTH") or 0
    if _max_len and (request.content_length or 0) > _max_len:
        audit("login_body_too_large")
        return jsonify({"success": False, "code": "PAYLOAD_TOO_LARGE",
                        "message": "请求体过大"}), 413

    try:
        body = request.get_json(silent=True) or {}
        password = str(body.get("password", ""))
    except RequestEntityTooLarge:
        audit("login_body_too_large")
        return jsonify({"success": False, "code": "PAYLOAD_TOO_LARGE",
                        "message": "请求体过大"}), 413
    except Exception:
        password = ""

    stored = _password_hash()
    # 这里**不能**写成 `bool(stored) and _verify_password(password, stored)`。
    #
    # 2026-10-16 实测：stored 为空（密码文件缺失/不可读）时，`and` 会短路，
    # _verify_password 一次都不跑 —— 0.001ms；而正常路径要跑 PBKDF2，
    # 约 95ms。差 5 个数量级，攻击者发一个 {"password":"x"} 就能靠响应
    # 时间枚举出「这台机器到底配没配密码」。
    #
    # _verify_password 内部本来就有 dummy 路径（stored 为空/畸形时照样真跑
    # 一次 PBKDF2，见它自己的注释），但前提是它得被调用到。先算再判，
    # 短路只留在最后的布尔表达式里。
    _ok = _verify_password(password, stored)
    ok = bool(password) and bool(stored) and _ok

    if not ok:
        _, fails = _mutate_ratelimit(ip, on_fail=True)
        audit("login_fail", device=device_id_from_request(), fp=fingerprint())
        # 响应体与耗时对「密码错」和「未设密码」保持一致，避免状态枚举
        remaining = max(0, RATE_LIMIT_MAX_FAILS - fails)
        return jsonify({"success": False, "code": "AUTH_FAILED",
                        "message": "密码错误", "remaining": remaining}), 401

    _mutate_ratelimit(ip, on_fail=False)   # 成功则清空该 IP 失败记录

    # 重新登录前先吊销当前浏览器带着的旧令牌。
    # 少了这一步（Shannon AUTH-02）：客户端已登录过、令牌仍在有效期内，
    # 再次登录会签发新令牌，但旧令牌不作废 —— 一旦旧令牌泄露（XSS、
    # 日志、抓包），用户在面板里重新登录并不能把攻击者踢下线。
    # 实测：重新登录后旧令牌访问 /auth/portal 仍返回 200，剩余有效期 1799 秒。
    _old = parse_token(request.cookies.get(COOKIE_TOKEN, ""))
    if _old:
        # 旧令牌吊销失败**不能**拦住本次登录。吊销表一旦写不进去（只读挂载 /
        # 属主被改），在这里抛异常等于「谁都登不进」的自伤式拒绝服务 ——
        # 旧令牌多活一会儿的代价，远小于所有人被锁在门外。这里放行但留审计。
        if not revoke_jti(_old.get("jti", ""), int(_old.get("exp", 0))):
            audit("login_old_token_not_revoked",
                  exp=int(_old.get("exp", 0)))

    did = device_id_from_request()
    ttl = _session_ttl(cfg)
    abs_to = _absolute_ttl(cfg)
    abs_deadline = int(time.time()) + abs_to if abs_to else 0
    token = issue_token("kirito", did, ttl, abs_deadline)

    audit("login_ok", device=did, fp=fingerprint(), user="kirito")

    resp = jsonify({"success": True, "user": "kirito", "device_id": did,
                    "expires_in": ttl})
    _set_cookies(resp, token, did)
    return resp


def _extract_token() -> str:
    """从 Authorization: Bearer 或 cookie 里取原始令牌。**Bearer 优先。**

    **两个入口必须用同一个函数**，否则会出这种不对称：
    `_verify_or_deny` 认 Bearer（给脚本/客户端用），而 auth_logout 只读
    cookie —— 于是 Bearer 客户端调 logout 拿到 HTTP 200，看着像登出了，
    实际 revoke_jti 根本没被调用（payload 为空），令牌照样有效到过期；
    滑动续期下甚至可能永不过期。.224 实测就是这样复现的。

    2026-10-16 把优先级从「cookie 优先」翻成「Bearer 优先」。
    原先 cookie 在前、注释却写着「Bearer 优先」，两者对不上；实际后果是
    脚本客户端只要机器上还留着浏览器 cookie，Bearer 就被无视而拿到 401 ——
    明明带着有效令牌却登不进去。

    为什么这样翻是安全的（不是把 CSRF 面放大）：
      · 浏览器**无法**被诱导跨站发送 Authorization 头。它不是 CORS 安全列表
        头，跨站 XHR 带它会触发预检；表单、`<img>`、`<script>` 更设不了。
      · 本项目全链路没有任何 Access-Control-* 响应头（已全库确认），
        预检拿不到放行。
      · 浏览器正常访问不带该头，行为完全不变（走 cookie 分支）。
    同时 Authorization 是客户端**显式**摆出来的凭据，优先级高于 cookie
    这个「顺带带上」的东西，本就应当如此。
    """
    authz = (request.headers.get("Authorization") or "").strip()
    if authz.lower().startswith("bearer "):
        return authz[7:].strip()
    return request.cookies.get(COOKIE_TOKEN, "") or ""


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    payload = parse_token(_extract_token())
    ok = True
    if payload:
        ok = revoke_jti(payload.get("jti", ""), int(payload.get("exp", 0)))
    audit("logout", device=device_id_from_request(), fp=fingerprint(),
          revocation=("ok" if ok else "FAILED"))
    if ok:
        resp = jsonify({"success": True})
    else:
        # 吊销没落盘 = 这个令牌在服务端仍然有效。**必须**明确失败：
        # 清掉 cookie 就回 200 的话，用户以为登出了，令牌其实还能用满整个 TTL，
        # 而滑动续期下可能永不过期 —— 这正是 AUTH-02 那类问题的复刻。
        # cookie 仍然要清：本机的凭据先撤掉，别等用户重登。
        audit("logout_revocation_failed")
        resp = jsonify({
            "success": False, "code": "REVOCATION_FAILED",
            "message": "吊销令牌落盘失败，本机凭据已清除但令牌在有效期内仍可能可用；"
                       "请改密码使全部令牌立即失效"})
    _set_cookies(resp, "", "", clear=True)
    return (resp, 200) if ok else (resp, 500)


def _verify_or_deny():
    """auth_request 专用校验。

    ⚠️ 结构性约束：本函数**只**在「确实校验通过」时返回 200，
    其余每一条路径（含所有异常）都返回 401。不要在这里加任何
    「调试时先放行」「暂时跳过」分支。
    """
    try:
        cfg = load_gateway_config()
        if is_lan_source(cfg):
            return Response(status=200, headers={
                "X-Auth-User": "lan",
                "X-Auth-Device": request.cookies.get(COOKIE_DEVICE, ""),
                "X-Auth-Via": "lan-bypass",
            })

        # 凭据：Bearer 优先、cookie 兜底（见 _extract_token 的说明）。
        # 2026-10-16 这里原来写的是「Bearer 优先」而实现是 cookie 优先，
        # 注释与代码对不上；现在实现跟注释一致了。
        raw = _extract_token()
        payload = parse_token(raw)
        if not payload:
            return _deny("no_token")
        # 世代号对不上 = 改过密码（或配置被重置）之后签的旧令牌，一律拒。
        # 放在 is_revoked 之后：吊销表可能读不了（fail-closed 全体拒绝），
        # 先走它能让这类故障得到更准的 deny 原因。
        # 判据与 `_authenticated` 共用 `_payload_epoch_ok` —— 两条鉴权路径
        # 必须同一套判据，各写一份迟早会漏掉一边（.224 实测就漏过一次）。
        if not _payload_epoch_ok(payload, cfg):
            return _deny("epoch_changed" if "ep" in payload else "epoch_missing")
        if is_revoked(payload.get("jti", "")):
            return _deny("revoked")

        now = int(time.time())
        exp = int(payload["exp"])
        ttl = _session_ttl(cfg)
        abs_to = _absolute_ttl(cfg)

        # 绝对上限：签发时间起算，超时强制重登
        if abs_to and now - int(payload.get("iat", now)) > abs_to:
            return _deny("absolute_timeout")

        headers = {
            "X-Auth-User": str(payload.get("sub", ""))[:64],
            "X-Auth-Device": str(payload.get("dev", ""))[:64],
            "X-Auth-Via": "token",
        }
        resp = Response(status=200, headers=headers)

        # 滑动续期：剩余不足一半才重签，避免每个静态资源都回一个 Set-Cookie
        if exp - now < ttl * TOKEN_REFRESH_RATIO:
            # 必须先吊销旧 jti 再签新的。否则攻击者截获的旧 token 在受害者
            # 反复续期期间一直是有效的 —— 更要命的是**登出也救不回来**：
            # 登出只吊销「当时手上那张」，受害者手里那张是续期后的新 token，
            # 攻击者那张是更早的、jti 从未被吊销的旧 token。
            # 结果是「登出」这个本该能一键切断的急停开关对已泄露凭据无效。
            # （Shannon 渗透测试 finding，实测确认调用链里确实缺这一句。）
            #
            # 吊销失败不拦续期。注意这只针对「表**可读但不可写**」这一种故障
            # （目录变只读、属主被改）。「表不可读」时 is_revoked 的 fail-closed
            # 早就把请求拒了，压根走不到这里 —— 那是 MISC-02 刻意选的取舍。
            # 这里抛异常同样糟：会被下面的 except Exception 接住变成 _deny()，
            # 于是每一次需要续期的请求都 401，比「旧 token 多活一会儿」严重得多。
            if not revoke_jti(payload.get("jti", ""), int(payload.get("exp", 0))):
                audit("refresh_old_token_not_revoked",
                      exp=int(payload.get("exp", 0)), device=payload.get("dev"))
            new_tok = issue_token(
                str(payload.get("sub", "kirito")),
                str(payload.get("dev", "")),
                ttl,
                int(payload.get("iat", now)) + abs_to if abs_to else 0,
            )
            _set_cookies(resp, new_tok, str(payload.get("dev", "")), raw=False)
            audit("token_refreshed", device=payload.get("dev"), fp=fingerprint())
        return resp

    except Exception as e:   # noqa: BLE001 —— 这里必须兜住一切
        # 认证链路里的任何异常都按「拒绝」处理，绝不返回 200
        try:
            audit("verify_exception", error=repr(e)[:200])
        except Exception:
            pass
        return _deny("exception")


@app.route("/auth/verify", methods=["GET"])
def auth_verify():
    return _verify_or_deny()


@app.route("/auth/portal", methods=["GET"])
def auth_portal():
    """门户服务列表。只返回已启用且已配 path 前缀的规则。"""
    cfg = load_gateway_config()
    if not _authenticated():
        return jsonify({"success": False, "code": "AUTH_REQUIRED"}), 401
    services = []
    rp = cfg.get("reverse_proxy")
    rules = rp.get("rules") if isinstance(rp, dict) else None
    # host 分发入口的对外地址需要带网关端口：网关按设计就跑在自定义高位端口上，
    # 漏掉端口点开就是 443 —— 要么打不开，要么撞上别的服务。
    try:
        gw_port = int(cfg.get("gateway_port", 8443) or 8443)
    except (TypeError, ValueError):
        gw_port = 8443
    port_part = "" if gw_port == 443 else f":{gw_port}"
    for r in (rules or []):
        if not isinstance(r, dict) or not r.get("enabled"):
            continue
        pfx = str(r.get("path_prefix", "") or "").strip().rstrip("/")
        if not pfx or pfx in RESERVED_PREFIXES:
            continue
        # host 分发入口（空 = 只有路径前缀入口）
        host = str(r.get("host", "") or "").strip().lower()
        services.append({
            "name": str(r.get("name") or pfx.lstrip("/"))[:64],
            "path": pfx,
            "public": bool(r.get("public_access")),
            "icon": str(r.get("icon") or "")[:16],
            # host 与 url：host 分发时门户要跳到**另一个域名**，
            # 光有 path 前缀拼不出那个地址。前端优先用 url。
            "host": host,
            "url": (f"https://{host}{port_part}/" if host else f"{pfx}/"),
        })
    services.sort(key=lambda s: s["path"])
    return jsonify({"success": True, "services": services,
                    "user": "kirito" if not is_lan_source(cfg) else "lan",
                    "device_id": device_id_from_request()})


def _payload_epoch_ok(payload, cfg) -> bool:
    """令牌世代号是否与当前配置一致（改密码后旧令牌一律作废）。

    **两个鉴权入口都必须用它。**
      · `_verify_or_deny` —— nginx auth_request 打的 /auth/verify
      · `_authenticated`  —— 浏览器直接访问 /auth/portal 等端点

    2026-10-16 `.224` 实测踩过这个坑：epoch 校验**只**写在 `_verify_or_deny`
    里，`_authenticated` 没查。结果改密码之后 nginx 的 auth_request 确实
    401 了，但**门户页面照样 200** —— 用户看到的是「密码都改了，页面还能打开」，
    而页面背后的 API 已经在拒绝。这种前后不一致比两边都失效更难排查，
    而且门户页面本身就是最该被关掉的那一扇门。

    旧令牌（无 `ep` 字段）按 0 处理，与 `_verify_or_deny` 的历史行为一致。
    """
    if not isinstance(payload, dict):
        return False
    try:
        tok_epoch = int(payload.get("ep", 0) or 0)
    except (TypeError, ValueError):
        return False
    try:
        cur_epoch = int(cfg.get("auth_token_epoch", 0) or 0)
    except (TypeError, ValueError):
        cur_epoch = 0
    return tok_epoch == cur_epoch


def _authenticated() -> bool:
    """端点级鉴权。与 `_verify_or_deny` 是**两条独立的路径**，判据必须一致。

    取令牌同样走 `_extract_token`：Bearer 优先、cookie 兜底。直接读 cookie
    会让带 Bearer 的脚本客户端在这个端点上被无视（和第二批修的 logout 同一个
    类别的不对称）。
    """
    cfg = load_gateway_config()
    if is_lan_source(cfg):
        return True
    payload = parse_token(_extract_token())
    return (bool(payload)
            and _payload_epoch_ok(payload, cfg)
            and not is_revoked(payload.get("jti", "")))


def _deny(reason: str):
    audit("verify_denied", reason=reason, fp=fingerprint())
    return Response(status=401, headers={"X-Auth-Deny-Reason": reason[:40]})


# ══════════════════════════════════════════════════════════════════════
# 辅助
# ══════════════════════════════════════════════════════════════════════

def _ratelimit_fallback_is_locked(ip: str) -> bool:
    """降级状态下该 IP 是否已被锁（只看内存计数）。"""
    rec = _RATE_FALLBACK.get(ip)
    if not isinstance(rec, dict):
        return False
    lu = rec.get("locked_until", 0)
    return isinstance(lu, (int, float)) and lu > time.time()


def _is_locked(ip: str) -> bool:
    """该 IP 是否已被限流锁定。

    **必须同时看落盘和内存两个来源。**
    2026-10-16 实测踩过：限流表降级（`.224` 上表被移走 / 目录不可写）时，
    `_mutate_ratelimit` 把计数写进 `_RATE_FALLBACK`，但这个判据只读文件，
    于是**计数照记、锁定判定永远读到 False** —— 降级期间暴力破解防护等于
    被悄悄关掉。实测 7 次连续错密码全是 401，一次 429 都没有。

    而且只读文件还会漏掉「文件能读、但写不进去」这一种：那时文件里是
    陈旧数据，内存里才是真实计数。所以规则是**任一来源说锁了就锁**。
    """
    try:
        with open(RATELIMIT_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            rec = data.get(ip)
            if isinstance(rec, dict):
                lu = rec.get("locked_until", 0)
                if isinstance(lu, (int, float)) and lu > time.time():
                    return True
    except (OSError, json.JSONDecodeError):
        pass
    return _ratelimit_fallback_is_locked(ip)


def _origin_host_mismatch(url: str) -> bool:
    """Origin/Referer 的 host 与本次请求 host 不一致 → 判为跨站。"""
    from urllib.parse import urlparse
    try:
        u = urlparse(url)
        # 解析不出 host 就是「判不出来」，按跨站处理，不能按「无跨站」放行。
        #
        # 2026-10-16 实测绕过：无 scheme 的 Origin
        #     Origin: 192.168.100.224
        # urlparse 得到 netloc=""，旧代码 `if not u.netloc: return False`
        # 直接放行。带正确密码实测 HTTP 200，登录成功；
        # 同一时刻对照组 `Origin: https://evil.example.com` 是 403。
        #
        # 浏览器不会为跨站请求发无 scheme 的 Origin，但脚本、浏览器扩展、
        # 以及任何能自己设头的客户端都可以 —— 而这正是 CSRF 要防的那类来源。
        host = (u.hostname or "").strip().lower()
        if not host:
            return True
        # 必须比 hostname 而不是 netloc。netloc 里可以塞 userinfo：
        #     Origin: https://192.168.100.224:x@evil/
        # 旧代码 `u.netloc.split(":")[0]` 会取到 "192.168.100.224" 冒充通过，
        # 实测同样 HTTP 200 登录成功（无冒号的 https://host@evil/ 则被正确
        # 拦成 403，因为那时 split 拿到的是整个 netloc）。
        # urlparse 的 .hostname 会正确剥掉 userinfo 和端口。
        return host != (request.host or "").split(":")[0].strip().lower()
    except Exception:
        return True


def _cookie_domain(cfg=None):
    """cookie 共享域（形如 ".fzyto.top"）；空串 = 按 host 各自存。

    这是 **host 分发保住网关认证** 的关键：浏览器按 host 存 cookie，
    门户在 fzyto.top 登录拿到的令牌，送到 siyuan.fzyto.top 时不会被带上
    —— 表现是「每换一个域名就要重登一次」，host 分发等于白做。
    把 cookie 的 Domain 抬到父域，一次登录覆盖所有子域。

    值由面板写进共享配置（reverse_proxy.settings.cookie_domain），
    认证服务只读不猜 —— 猜父域要 publicsuffix 列表，猜错就是
    「cookie 莫名其妙不生效」。
    """
    if cfg is None:
        cfg = load_gateway_config()
    rp = cfg.get("reverse_proxy")
    settings = rp.get("settings") if isinstance(rp, dict) else None
    settings = settings if isinstance(settings, dict) else {}
    # 语义与面板（app.py 的 _rp_cookie_domain）**必须一致**：
    #   · cookie_domain 这个键存在 → 用它（哪怕是空串 = 用户明确清空）
    #   · 键不存在 → 用 "." + base_domain 推导
    # 两边语义不一致的后果是「面板说共享、认证服务不共享」——
    # 而且面板上完全看不出来（接口返回的是现算的生效值）。
    if "cookie_domain" in settings:
        cd = str(settings.get("cookie_domain") or "").strip().lower()
        if not cd:
            return ""
        base = _safe_cookie_base(cd.lstrip("."))
        return ("." + base) if base else ""
    bd = _safe_cookie_base(str(settings.get("base_domain") or "").strip().lower())
    return ("." + bd) if bd else ""


def _safe_cookie_base(value):
    """把 cookie 域的 base 部分净化成合法主机名；非法返回空串。

    值来自面板（那边已经净化过），这里再过一道是**防御性**的：
    配置文件可能被手工改坏，而这个值会直接进 Set-Cookie 的 Domain 属性 ——
    带分隔符的话浏览器会整条拒收 cookie，登录直接失效。
    """
    v = (value or "").strip().lower()
    if not v or len(v) > 253:
        return ""
    if any(c in v for c in (" ", "/", ":", "\t", "\n", "\r", ";", ",", "*", "@", "?")):
        return ""
    for lb in v.split("."):
        if not lb or len(lb) > 63:
            return ""
        if not all(c.isalnum() or c == "-" for c in lb):
            return ""
        if lb.startswith("-") or lb.endswith("-"):
            return ""
    return v


def _effective_cookie_domain(cfg=None):
    """本次响应实际该用的 cookie Domain（可能为空 = host-only）。

    ⚠️ **只有当请求主机本身在父域之下时才带 Domain 属性**。

    浏览器对「IP 地址 + Domain 属性」的 cookie 是**整条拒收**的
    （RFC 6265 §5.3 第 5 步：域名不匹配就丢弃整条 cookie，而不是只丢属性）。
    于是用 IP 访问网关时（https://192.168.100.233:8443/）如果硬带
    Domain=.fzyto.top，登录会**静默失败** —— 表现为「密码输对了又弹回登录页」，
    比不带 Domain 更难查。

    所以这里按请求主机判断：IP 字面量、以及不在父域之下的主机，一律退回
    host-only cookie（各域名各自登录，功能正常，只是不能共享）。
    """
    d = _cookie_domain(cfg)
    if not d:
        return ""
    base = d.lstrip(".")
    host = (request.host or "").split(":")[0].strip().lower()
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""          # IP 主机名：浏览器会整条拒收带 Domain 的 cookie
    except ValueError:
        pass
    if host == base or host.endswith("." + base):
        return d
    return ""


def _set_cookies(resp, token: str, device: str, clear: bool = False, raw: bool = True):
    """统一下发 cookie。

    token cookie 短寿（随 token exp），device cookie 长寿（一年）。
    HttpOnly 防 JS 读取，Secure 只走 HTTPS，SameSite=Lax 挡跨站携带。

    domain 只在「请求主机确实在共享域之下」时才带（见 _effective_cookie_domain）：
    抬到父域是为了让 host 分发出来的多个子域共用一次登录；
    但给 IP 主机名硬塞 Domain 属性会让浏览器整条拒收 cookie，登录直接失效。
    """
    cdom = _effective_cookie_domain(load_gateway_config())
    if clear:
        resp.set_cookie(COOKIE_TOKEN, "", max_age=0, httponly=True,
                        secure=True, samesite="Lax", path="/", domain=cdom or None)
        resp.set_cookie(COOKIE_DEVICE, "", max_age=0, httponly=True,
                        secure=True, samesite="Lax", path="/", domain=cdom or None)
        return
    cfg = load_gateway_config()
    if token:
        ttl = _session_ttl(cfg)
        resp.set_cookie(COOKIE_TOKEN, token, max_age=ttl, httponly=True,
                        secure=True, samesite="Lax", path="/", domain=cdom or None)
    if device:
        resp.set_cookie(COOKIE_DEVICE, device, max_age=DEVICE_COOKIE_TTL,
                        httponly=True, secure=True, samesite="Lax", path="/",
                        domain=cdom or None)


@app.errorhandler(Exception)
def _on_unhandled(err):
    """兜底处理器：认证服务里未捕获的异常一律不外泄细节。

    ⚠️ 重要：HTTPException（404/405/413 等）必须原样放行。
    它们是「请求本身不合法」，不是「服务内部出错」；统一转成 500 会让
    前端和 nginx 分不清到底是密码错了还是路径写错了。
    只有真正未预期的异常才落审计并回 500。
    """
    from werkzeug.exceptions import HTTPException
    if isinstance(err, HTTPException):
        return jsonify({
            "success": False,
            "code": err.name.upper().replace(" ", "_"),
            "message": err.description,
        }), err.code
    try:
        audit("unhandled_exception", error=repr(err)[:200])
    except Exception:
        pass
    return jsonify({"success": False, "code": "INTERNAL",
                    "message": "服务内部错误"}), 500


def _assert_loopback_bind():
    """拒绝绑定到非回环地址。

    2026-10-07：这段检查原先在 `if __name__ == "__main__":` 里面。
    一旦这个模块被 WSGI 方式加载（gunicorn / uWSGI / waitress /
    `flask run`），`__main__` 不成立，检查就**静默消失** —— 而绑
    0.0.0.0 意味着认证系统多一个可从公网直接触达的入口，是本项目
    安全模型里最不能破的一条（公网入口必须经 nginx auth_request）。
    提到模块加载时执行，导入即校验，绕过路径就没了。
    """
    if BIND_HOST not in ("127.0.0.1", "::1", "localhost"):
        print(f"[FATAL] 认证服务拒绝绑定 {BIND_HOST}：只允许 127.0.0.1/::1。"
              f"公网入口必须经 nginx auth_request。", flush=True)
        raise SystemExit(1)


# ══════════════════════════════════════════════════════════════════════
# 权限降级
# ══════════════════════════════════════════════════════════════════════

def _drop_privileges() -> bool:
    """把进程从 root 降到专用账号。返回是否真的降了。

    为什么这是本文件最要紧的一段
    ------------------------------
    本进程是**唯一直接处理公网请求的代码**：面板只在 LAN、认证 API 只在
    回环，但 nginx 的 auth_request 会把来自公网的每一次请求送进这里。
    所以「这个进程」本身就是公网攻击面的边界。

    它以 root 运行时，任何一处 RCE 的后果都不是「服务被攻破」，而是
    **整台机器沦陷**：
      · ``nft flush ruleset``  → 防火墙全开
      · kill 看门狗进程        → 规则集被清空后永远不再自愈
      · 读 /etc/shadow、SSH 私钥、改 nftables-web-config.json

    看门狗挡不住这个场景 —— 它和被保护的对象在同一个 root 权限域里，
    攻击者拿到 root 的第一件事就是把它关掉。**降权是把「一个服务的漏洞」
    限制成「一个服务的漏洞」的唯一手段。**

    三条硬约束
    ----------
    1. **失败即退出。** 绝不能「打印个警告然后继续以 root 跑」—— 那种
       代码比不写更糟：读代码的人以为已经降权了，实际没有。
    2. **顺序不能反。** ``setgid`` 必须在 ``setuid`` 之前：uid 一旦变成
       非 0，进程就再没权限改 gid，也没有任何办法退回 root。
    3. **必须清 supplementary groups。** 只 ``setuid`` 不 ``initgroups``
       的话，残留的组权限照样能读文件 —— 那种降权是假的。

    没设 ``AUTH_DROP_UID`` 就整体跳过：开发机和单元测试不以 root 跑，
    无条件降权只会让测试跑不起来。真机由 init 脚本注入这三个环境变量；
    没注入 = 维持既有行为，注入了就必须生效，否则拒绝启动。
    """
    raw_uid = os.environ.get("AUTH_DROP_UID", "").strip()
    if not raw_uid:
        return False

    try:
        uid = int(raw_uid)
        gid = int(os.environ.get("AUTH_DROP_GID", "").strip())
        user = os.environ.get("AUTH_DROP_USER", "").strip()
    except ValueError:
        print("[FATAL] AUTH_DROP_UID / AUTH_DROP_GID 必须是整数。拒绝启动。",
              flush=True)
        raise SystemExit(1)

    # uid=0 等于没降权。与其默默放行，不如让配置错误立刻暴露。
    if uid == 0:
        print("[FATAL] AUTH_DROP_UID=0 —— 那等于没有降权。拒绝启动。", flush=True)
        raise SystemExit(1)
    # 没有用户名就没法 initgroups，而不清组权限的 setuid 是假降权。
    if not user:
        print("[FATAL] 缺少 AUTH_DROP_USER：没有用户名就无法清 supplementary "
              "groups，这样的降权是假的。拒绝启动。", flush=True)
        raise SystemExit(1)

    if os.getuid() != 0:
        # 已经是非 root（例如被别的东西降过权再拉起的）。此时 setuid 到
        # 同 uid 是允许的，但身份对不上说明环境变量与实际不符，不能放过。
        if os.getuid() == uid and os.getgid() == gid:
            print(f"[OK] 进程本就是 {user}({uid}:{gid})，无需降权", flush=True)
            return True
        print(f"[FATAL] 当前 uid={os.getuid()} gid={os.getgid()}，"
              f"与要求降到的 {uid}:{gid} 不符。拒绝启动。", flush=True)
        raise SystemExit(1)

    try:
        # 顺序见上文约束 2、3：initgroups → setgid → setuid
        os.initgroups(user, gid)
        os.setgid(gid)
        os.setuid(uid)
    except (OSError, PermissionError, LookupError) as e:
        # 权限错误是 OSError 的子类，单独列出只为让日志一眼看出是权限问题
        print(f"[FATAL] 降权到 {user}({uid}:{gid}) 失败: "
              f"{type(e).__name__}: {e} —— 拒绝以 root 继续运行。", flush=True)
        raise SystemExit(1)

    # 复核。用 geteuid 不是 getuid：有效 uid 才是内核做权限判定用的那个。
    if os.geteuid() != uid or os.getuid() != uid or os.getgid() != gid:
        print(f"[FATAL] 降权后身份不符：euid={os.geteuid()} uid={os.getuid()} "
              f"gid={os.getgid()}，期望 {uid}/{uid}/{gid}。拒绝继续。", flush=True)
        raise SystemExit(1)

    print(f"[OK] 权限已降级：{user} uid={uid} gid={gid}", flush=True)
    return True


# 与 _assert_loopback_bind 同为模块级校验：导入即执行，WSGI 加载也逃不掉。
_assert_loopback_bind()
_drop_privileges()


# ══════════════════════════════════════════════════════════════════════
# 启动
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f" * 认证网关 : http://{BIND_HOST}:{BIND_PORT}", flush=True)
    print(f" * 端点     : /auth/status /auth/login /auth/logout /auth/verify /auth/portal",
          flush=True)
    print(f" * 公网可达 : 否（仅接受来自 nginx 的 auth_request 与本机请求）", flush=True)
    print(f" * PBKDF2   : 并发闸门 {PBKDF2_GATE_SIZE} —— {PBKDF2_GATE_WHY}",
          flush=True)

    app.run(host=BIND_HOST, port=BIND_PORT, threaded=True, debug=False)
