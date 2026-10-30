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
# 审计日志的权限位。init 脚本建的是 0640（属主 nftweb），但网关**轮转时**
# 用 `open(path, "a")` 重建文件 —— 那是 0666 & ~umask = 0644，
# **world-readable**。审计里有源 IP、设备 ID、指纹、UA、原始 URI。
# 所以这里定死一个值：所有创建 / 重建路径都用它，且轮转后必须回到它。
AUDIT_LOG_MODE = 0o640

# 审计写入的限流（每 IP 每分钟）。
#
# 2026-10-30：未认证者可以自由灌 —— /auth/verify 每被拒一次就写一行
# verify_denied，一个脚本几分钟就能把 2 MiB 的文件写满并触发轮转，
# 把**真正的登录成功记录**挤到上一代去（面板只读当前文件的尾部若干行，
# 挤掉之后「谁登录过」就查不到了）。
#
# 阈值取 120 条/分钟：与 /auth/status 的只读限流同量级（那里是 120/60s），
# 正常浏览器一次会话的认证相关请求也就个位数，120 留了十几倍余量。
# 超出时**不静默丢弃** —— 合并成一条 audit_throttled 汇总，
# 保留「发生了 N 次」这个事实（见 _audit_rate_gate）。
AUDIT_RATE_WINDOW = 60
AUDIT_RATE_MAX = 120

# 三张表的容量上限（都会落盘，全量重写）。
#
# 2026-10-30：这三张表原来都**没有数量上限**。
#   · 限流表：每条记录一个源 IP，一次失败就 json.load + truncate + 全量重写。
#     攻击者用大量源 IP 就能把表撑到几十 MB，于是**每一次登录尝试**都要
#     读写几十 MB —— 一次请求放大成一次磁盘写入，这是放大攻击面。
#   · 吊销表：每个已认证请求都全量重读重解析整个文件，同上。
#   · _RATE_FALLBACK：降级态的内存兜底，无界且从不清理。
#
# 上限取值 10000（限流表 / 吊销表）：
#   · 一条限流记录约 100 字节 → 10000 条 ≈ 1 MB，落在 tmpfs 上可忽略；
#   · 正常设备一辈子也攒不到这个数（一条记录 = 一次失败登录或一次登出，
#     绝对 TTL 12 小时还会把过期条目剪掉）；
#   · 攒到上限说明有人在**用大量源 IP 扫**，那正是要拦的场景。
# 超限时的行为见各自的实现注释（限流表/吊销表：淘汰最老/最先过期的条目；
# 内存兜底：淘汰最久没活动的条目）—— 一律**不拒绝新增**，
# 否则攻击者只要把表填满就能让**新来的**攻击者不受限流（把防护变成后门）。
RATELIMIT_MAX_IPS = int(os.environ.get("AUTH_RATELIMIT_MAX_IPS", "10000"))
REVOKED_MAX_ENTRIES = int(os.environ.get("AUTH_REVOKED_MAX_ENTRIES", "10000"))
# 内存兜底的容量上限。降级态没有落盘保护，一个内存炸弹就能把网关拖垮
# （设备只有 1 GB 内存）。4096 条 ≈ 几百 KB，够用。
RATE_FALLBACK_MAX_IPS = int(os.environ.get("AUTH_RATE_FALLBACK_MAX_IPS", "4096"))

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
# dummy 路径用的**基准**迭代数。
#
# 必须 ≥ 面板侧的真实默认（app.py 的 PBKDF2_ITERATIONS = 200000）：
# dummy 路径原来固定用 PBKDF2_ITERATIONS_MIN(100000)，而真实路径用存储
# 哈希里的 200000 —— 两条路径耗时差一个数量级。设备实测：
# **94.9ms vs 48.6ms（差 46.3ms，1.95x）**。攻击者用一个错密码就能靠
# 响应时间区分「哈希损坏/未配置」和「配置正常」，是个可用的状态枚举
# oracle（Shannon 渗透测试 finding，实测坐实）。
#
# 取 max(存储哈希里的真实 iters, MIN, 这个基准) —— 保证 dummy 路径
# **永远不慢于**真实路径，真实路径反而是「更慢的那个」，就再也区分不出来。
PBKDF2_ITERATIONS_DUMMY = 200000

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
    # HSTS：**无条件**下发（2026-10-30）。
    #
    # 原来是 `if request.is_secure or X-Forwarded-Proto == "https"` 才发。
    # 但 nginx 终结 TLS，转给 Flask 的已经是明文 HTTP，request.is_secure
    # 恒为 False —— 唯一的判据就是 X-Forwarded-Proto 头。
    # 而 nginx 只有 /auth/ 那几个 location 转发 `X-Forwarded-Proto $scheme`，
    # **`location = /`（门户页）不转发** —— 于是门户页永远拿不到 HSTS，
    # 而同一个站点的 /auth/login 却有。浏览器对同一个 origin 的策略是按
    # 响应头逐次判定的：登录页钉了 HSTS、门户页没钉 ⇒ 用户在门户页上
    # 首访 http:// 不会被浏览器记住并升级。
    #
    # 为什么可以无条件发：这个网关**只**通过 nginx 的 HTTPS 入口对外，
    # 8443 是 HTTPS-only。直连 127.0.0.1:8444 的明文访问只发生在本机，
    # 而 HSTS 对 IP 字面量与 localhost 本来就不生效（浏览器忽略），
    # 不会把本机的明文访问「钉死」成 https。
    #
    # ⚠️ 不带 includeSubDomains：网关可能和路由器上其它服务共用域名，
    # 把子域一起钉死会误伤它们（与 /auth/login 原有策略保持一致）。
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
        # 记住真实哈希里的迭代数，dummy 路径要用它（见下面 except 块）。
        # 解析失败时它是 0，except 里会退到基准值。
        iters = 0
        try:
            algo, iters_raw, salt, hash_hex = stored.split("$", 3)
            iters = int(iters_raw)
            if algo != "pbkdf2_sha256":
                raise ValueError("algo")
            if iters < PBKDF2_ITERATIONS_MIN:
                # 迭代数过低 = 哈希强度形同虚设，直接拒绝而不是"降级接受"
                raise ValueError("iters")
        except Exception:
            # 即便哈希损坏/未配置，也要真跑一次 PBKDF2。原来这条路径直接
            # return False，耗时不到 1ms；正常路径要跑几万到几十万轮迭代。
            # 攻击者只发一个 {"password":"x"} 就能靠响应耗时区分
            # 「部署没配密码」和「配了密码」——等于一个免认证的状态枚举口。
            #
            # ⚠️ 迭代数**不能**用 PBKDF2_ITERATIONS_MIN（Shannon finding，
            # 实测坐实）：那是 100000，而真实路径是 200000，两条路径差
            # 46.3ms（1.95x）——照样能区分。这里取三者的最大值，保证
            # dummy 路径**永远不慢于**真实路径。
            dummy_iters = max(iters, PBKDF2_ITERATIONS_MIN, PBKDF2_ITERATIONS_DUMMY)
            hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                b"nftables-web-dummy", dummy_iters)
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
    global _REVOKED_LKG
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
                # ── 容量上限（P2-3）────────────────────────────────────
                # 吊销表原来只按 exp 剪枝，**没有数量上限**。一次登出/续期
                # 写一条，绝对 TTL 12 小时 ⇒ 条目最长活 12 小时；高频登出
                # 就能把它撑得很大，而**每个已认证请求都要全量重读重解析**
                # 整个文件（is_revoked → load_revoked）—— 表越大，单个请求
                # 越贵，等于把一次请求放大成一次全表解析。
                #
                # 超限时淘汰**最先过期**的条目：它们马上就要自己失效，
                # 留着没有价值；而**刚刚写进去的这一条永远不淘汰** ——
                # 淘汰掉它等于「吊销没落盘」，比表大一点严重得多。
                #
                # 为什么不改成「拒绝新增」：攻击者只要把表填满，
                # 就能让**新来的**攻击者不受限流 —— 把防护变成后门。
                if len(data) > REVOKED_MAX_ENTRIES:
                    _victims = sorted((k for k in data if k != jti),
                                      key=lambda k: data[k])
                    for _k in _victims[:len(data) - REVOKED_MAX_ENTRIES]:
                        data.pop(_k, None)
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
    # ── 写后立刻刷新 last-known-good（P1-3）──────────────────────────
    # 原来这里**不刷新**：LKG 只在 load_revoked() 成功读到文件时才更新。
    # 于是出现这条链：
    #   ① 登出 → revoke_jti 写盘（文件里已经有这条吊销）
    #   ② 文件随后被写坏 / 被截断 / 磁盘只写了一半
    #   ③ 下一次鉴权 → load_revoked() 读不出来 → 退到 LKG
    #      而那份 LKG 是**吊销之前**的快照 —— 刚登出的令牌当场复活。
    # 「登出」这个本该一键切断的急停开关，恰好在最需要它的时刻失效。
    #
    # 写后立刻更新 LKG，这条链就断了：写盘成功 = 吊销成立，之后无论文件
    # 怎么坏，退到的都是**含这次吊销**的快照。
    _REVOKED_LKG = dict(data)
    return True


def _mark_superseded(jti: str, exp: int) -> None:
    """记下「这个 jti 已被续期取代」，本进程内不再认它。

    见 _SUPERSEDED_JTI 的说明：滑动续期时旧令牌必须死掉，
    而吊销表写不进去时它是唯一还能生效的地方。

    容量上限：先删已过期的，再按上限淘汰**最先过期**的条目
    （它们马上就要自己失效了，留着没价值）。
    """
    if not jti:
        return
    now = int(time.time())
    _SUPERSEDED_JTI[jti] = exp
    for k in [k for k, v in _SUPERSEDED_JTI.items()
              if not isinstance(v, int) or v <= now]:
        _SUPERSEDED_JTI.pop(k, None)
    if len(_SUPERSEDED_JTI) > _SUPERSEDED_JTI_MAX:
        victims = sorted(_SUPERSEDED_JTI.items(), key=lambda kv: kv[1])
        for k, _v in victims[:len(_SUPERSEDED_JTI) - _SUPERSEDED_JTI_MAX]:
            _SUPERSEDED_JTI.pop(k, None)


def is_revoked(jti: str) -> bool:
    if not jti:
        return False
    # 进程内「已被续期取代」的 jti —— 吊销表写不进去时的第二道保险。
    # 查它**不依赖**磁盘，所以表坏了、表只读、表不存在都不影响这一层。
    _sx = _SUPERSEDED_JTI.get(jti)
    if isinstance(_sx, int) and _sx > int(time.time()):
        return True
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


def _fallback_prune(now: float) -> None:
    """给内存兜底表剪枝：先删已经完全过期的，再按上限淘汰最久没活动的。

    为什么要有上限：降级态（限流表不可写）恰恰发生在最忙的时候 ——
    磁盘满、目录变只读、tmpfs 被清。这时候再留一张无界的内存表，
    就是把「限流表坏了」升级成「网关被内存炸弹打死」——
    而这台设备总共只有 1 GB 内存。
    """
    # ① 已经彻底过期的：不在锁定期内，且失败记录全部超出窗口
    for k in [k for k, v in _RATE_FALLBACK.items()
              if isinstance(v, dict)
              and not (isinstance(v.get("locked_until", 0), (int, float))
                       and v.get("locked_until", 0) > now)
              and not [t for t in (v.get("fails") or [])
                       if isinstance(t, (int, float)) and now - t < RATE_LIMIT_WINDOW]]:
        _RATE_FALLBACK.pop(k, None)
    # ② 还超上限 → 淘汰最久没活动的那些。
    #    同样是「不拒绝新增」：拒绝新增等于给攻击者一个「填满表就能
    #    让新来的攻击者不受限流」的后门。
    if len(_RATE_FALLBACK) > RATE_FALLBACK_MAX_IPS:
        def _last_active(v):
            if not isinstance(v, dict):
                return 0.0
            ts = [t for t in (v.get("fails") or []) if isinstance(t, (int, float))]
            lu = v.get("locked_until", 0)
            if isinstance(lu, (int, float)):
                ts.append(lu)
            return max(ts) if ts else 0.0
        victims = sorted(_RATE_FALLBACK.items(), key=lambda kv: _last_active(kv[1]))
        for k, _v in victims[:len(_RATE_FALLBACK) - RATE_FALLBACK_MAX_IPS]:
            _RATE_FALLBACK.pop(k, None)


def _ratelimit_fallback_mutate(ip: str, on_fail: bool):
    """限流表不可用时的内存版，语义与落盘版一致。

    同样要能真的挡住暴力破解 —— 降级不等于不设防，只是不跨重启累计。

    2026-10-30（P2-2）：原来这张表**无界、从不清理**，而且「成功登录」
    只是把该 IP 的记录**置成空 dict** —— 键还在。于是每个来过的源 IP
    都永久占着一条，谁也不删它。
    现在：
      · 成功登录 → **删键**（不是置空）
      · 失败路径每次改动后剪枝：先删已完全过期的，超上限再淘汰最久没活动的
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
            # ⚠️ 原来这里是 rec = {"locked_until": ..., "fails": []}
            # —— 清空 fails 后返回的 count 是 0，auth_login 算出
            # remaining = MAX - 0 = 5，「触发锁定的那一次」反而报
            # 「还剩 5 次」而且返 401。保留 fails → remaining = 0。
            rec = {"locked_until": now + RATE_LIMIT_LOCKOUT, "fails": fails}
        else:
            rec = {"locked_until": 0, "fails": fails}
        _RATE_FALLBACK[ip] = rec
        _fallback_prune(now)
    else:
        # 成功登录：**删键**。
        # 原来这里是 `rec = {}` 然后 `_RATE_FALLBACK[ip] = rec` ——
        # 键还在，只是内容空了，所以每个见过的源 IP 都永久留下一条。
        #
        # ⚠️ 这里**必须**直接删键，不能靠后面的剪枝兜底：剪枝只清「已完全
        # 过期」的条目，一条空记录会被它顺手清掉 —— 但那属于「碰巧被清掉」，
        # 不是「成功登录就删键」这条语义本身。语义要写在删除动作上。
        _RATE_FALLBACK.pop(ip, None)
        return False, 0
    # 返回真实的锁定状态（与落盘版语义一致）：触发锁定的那一次也报 True。
    _lu = rec.get("locked_until", 0)
    _locked = isinstance(_lu, (int, float)) and _lu > now
    return _locked, len(rec.get("fails", []))


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
                        # ⚠️ 原来这里有一行 `rec["fails"] = []`。
                        #
                        # 清空之后本函数返回的 fail_count 是 0，auth_login
                        # 算出 remaining = MAX - 0 = 5 —— **触发锁定的那一次
                        # 反而报「还剩 5 次」**，而且那次返回的是 401 而不是
                        # 429。.233 实测序列：4→3→2→1→5→429。
                        #
                        # 改成**保留** fails（长度 = MAX）→ remaining = 0。
                        # 「锁定期间不再累加失败次数」由上面那句
                        # `if locked_until > now: return True, ...` 负责。
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

                # ── 容量上限（P2-1）────────────────────────────────────
                # 原来这张表**没有数量上限**，只有「按时间过期」的清理。
                # 攻击者用大量源 IP 各试一次就能把表撑到几十 MB，而
                # **每一次登录尝试都要 json.load + truncate + 全量重写**
                # 整张表 —— 一个请求被放大成一次几十 MB 的磁盘写入，
                # 磁盘越慢越容易被拖垮（.224 只有 1 GB 内存）。
                #
                # 超限时淘汰**最久没活动**的条目（它们离过期最近，
                # 留着价值最低）。不改成「拒绝新增」：那等于给攻击者
                # 一个「把表填满就能让新来的攻击者不受限流」的后门。
                if len(data) > RATELIMIT_MAX_IPS:
                    def _last_active(v):
                        if not isinstance(v, dict):
                            return 0.0
                        ts = [t for t in (v.get("fails") or [])
                              if isinstance(t, (int, float))]
                        lu = v.get("locked_until", 0)
                        if isinstance(lu, (int, float)):
                            ts.append(lu)
                        return max(ts) if ts else 0.0
                    _victims = sorted(data.items(), key=lambda kv: _last_active(kv[1]))
                    for _k, _v in _victims[:len(data) - RATELIMIT_MAX_IPS]:
                        data.pop(_k, None)

                f.seek(0)
                f.truncate()
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())

                rec = data.get(ip, {})
                # 返回**真实的**锁定状态：触发锁定的那一次也要报 True，
                # 否则 auth_login 会把它当普通失败（401）而不是 429。
                _lu = rec.get("locked_until", 0)
                _locked = isinstance(_lu, (int, float)) and _lu > now
                return _locked, len(rec.get("fails", []))
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

# 审计限流的状态（进程内，不落盘）。
_AUDIT_HITS = {}          # ip -> [落盘时刻]
_AUDIT_SUMMARY = {}       # ip -> {"count": n, "event": "...", "ts": ...}
_AUDIT_RATE_LOCK = threading.Lock()
# 限流状态表本身也不能无界：攻击者换着源 IP 打，每分钟就能塞进几千个键。
_AUDIT_HITS_MAX = 4096

# 这些事件**永远**落盘，绕过审计限流。
#
# 为什么必须豁免：审计限流绝不能变成「攻击者可以让审计彻底失效」的后门。
# 攻击者只要能触发足够多的失败事件（刷 verify_denied 就行，那条路完全
# 不需要凭据），就可能把 login_ok 一起挤掉 —— 于是「谁登录过」彻底查不到，
# 而这恰恰是出事之后唯一真正要紧的问题。
_AUDIT_ALWAYS = ("login_ok", "logout")

# **会被未认证者随意触发**的事件 —— 只有这些才走限流。
#
# 限流针对的是「不需要任何凭据就能反复触发」的事件。限流范围必须**精确**：
# 放得太宽会把内部事件、内部测试事件一起限掉（那等于给审计加了个
# 说不清的静默丢弃），放得太窄又挡不住真正的灌爆路径。
# 下面这份名单覆盖了本文件里全部「未认证请求能走到」的事件：
#   verify_denied      —— 每个未认证请求都触发（最容易被灌的那条）
#   verify_exception   —— 校验链路抛异常
#   login_csrf_blocked —— 跨站登录尝试
#   login_fail         —— 密码错误
#   login_rate_limited —— 锁定期内的每次尝试
#   unhandled_exception—— 兜底处理器
# 其余事件（token_refreshed / logout / *_not_revoked / revocation_* …）
# 都需要已经拿到凭据才能触发，限流它们没有意义，却会让「谁认证过」
# 这类记录变得不完整。
_AUDIT_FLOODABLE = ("verify_denied", "verify_exception", "login_csrf_blocked",
                    "login_fail", "login_rate_limited", "unhandled_exception")

# 进程内「已被取代」的 jti —— 滑动续期时旧令牌的第二道保险。
#
# 2026-10-30（P1-6）：滑动续期必须让**旧令牌死掉**。正常情况下
# revoke_jti() 把它写进吊销表就够了；但吊销表写不进去时（目录只读、
# 属主被改）它写不进去 —— 那正是「被取代的令牌继续有效」的窗口：
# 服务端同时有两张有效令牌（旧的没死、新的又发出去），而攻击者手上
# 那张恰恰是旧的，「登出」这个急停开关对它无效。
#
# 进程内这张表补上这一刀：续期时**无论吊销表写没写成功**，旧 jti 都进
# 这里，is_revoked() 一并查它 ⇒ 旧令牌在本进程内立刻失效。
# 浏览器拿到的是新令牌（Set-Cookie 正常下发），所以**用户不会被踢下线**，
# 而攻击者手上的旧副本立刻作废 —— 这正是「续期」该有的语义。
#
# 局限（必须写清楚）：这张表**不跨进程重启**。吊销表可写时（正常情况）
# 磁盘上也有记录，重启不影响；吊销表不可写时，重启后旧令牌会复活，
# 直到它自己过期。所以这是「尽力而为」，不是「绝对保证」。
_SUPERSEDED_JTI = {}
_SUPERSEDED_JTI_MAX = 10000


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

    2026-10-30（P1-7 / P1-8 / P1-45）：轮转方式改了，原因是原来的方式
    **在真机上永远不可能成功**。
      · 原来的 `os.replace(path, path + ".1")` 需要**目录的写权限**。
        真机上 /var/log 是 root:root 0755，而网关降权后是 uid 1000 ——
        rename 要目录写权限，它没有。于是轮转永远失败，兜底分支只能
        `open(path, "w")` **就地截断**：审计历史被清空，文件继续增长。
        也就是说「出事那一刻最需要的那份记录」正好是最先被毁掉的。
      · 现在分两种情况：
          · 目录可写 → 仍然改名成 .1（保留上一代），并用 0640 重建新文件；
          · 目录不可写（真机的常态）→ **就地轮转**：留下尾部若干行，
            其余丢掉，重写同一个文件。就地重写只需要**文件自身的写权限**
            （属主是网关自己），完全不碰目录 —— 这才是降权后能真的跑通的
            那条路。
      · 两种方式产出的新文件权限都必须回到 0640：原来的 `open(path, "a")`
        重建出来的是 0666 & ~umask = **0644（world-readable）**，
        而审计里有源 IP、设备 ID、指纹、UA、原始 URI。
    """
    try:
        if os.path.getsize(path) + incoming <= AUDIT_LOG_MAX_BYTES:
            return
    except OSError:
        return          # 文件不存在：紧接着的写入会新建，无需轮转
    # 方式一：目录可写 → 改名保留上一代（原子，且天然「新一代覆盖上一代」）
    try:
        if os.access(os.path.dirname(path) or ".", os.W_OK):
            os.replace(path, path + ".1")
            _ensure_audit_file(path)
            return
    except OSError:
        pass
    # 方式二：目录不可写（真机常态）→ 就地轮转，只用文件自身的写权限
    _audit_rotate_in_place(path)


def _audit_rotate_in_place(path: str) -> None:
    """就地轮转：留下尾部若干行（总大小不超过上限的一半），其余丢掉。

    为什么保留尾部而不是直接截断：直接截断 = 这一代的记录**全部**没了，
    而「出事前后发生了什么」正好是最需要的那一段。保留尾部是在
    「文件必须有界」和「别把关键记录一起扔了」之间的折中。

    保留量按**字节预算**算（上限的一半），不是按固定行数 —— 行长随
    内容变化（UA 长度、字段数量），按行数算出来的字节数会飘，
    「文件必须有界」这条硬边界就不能保证了。至少保留一行，
    否则一次轮转就把文件清空，跟直接截断没区别。

    ⚠️ 就地重写不是原子的：面板正好在这一瞬间读，可能读到半截内容
    （面板那边用 errors="replace" 读，不会崩，最坏是显示错乱）。
    这比「轮转不了、日志无限长、RAM 被吃光」好得多。
    """
    try:
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        lines = []
    budget = max(1, AUDIT_LOG_MAX_BYTES // 2)
    keep, total = [], 0
    for ln in reversed(lines):
        sz = len(ln.encode("utf-8"))
        if keep and total + sz > budget:
            break
        keep.append(ln)
        total += sz
    keep.reverse()
    try:
        with open(path, "w") as f:
            f.writelines(keep)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        # 连重写都不行 → 至少别让它继续无限长（宁可丢历史）
        try:
            open(path, "w").close()
        except OSError:
            pass
    _ensure_audit_file(path)


def _ensure_audit_file(path: str) -> None:
    """确保审计文件存在，且权限不宽于 0640（world 不可读）。

    用 os.open 而不是 open(path, "a")：后者建出来的是 0666 & ~umask
    = 0644 —— 审计内容（源 IP / 设备 ID / 指纹 / UA）对全机可见。
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, AUDIT_LOG_MODE)
    except OSError:
        return
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        if (os.stat(path).st_mode & 0o777) & 0o007:
            os.chmod(path, AUDIT_LOG_MODE)
    except OSError:
        pass


def _audit_hits_prune(now: float) -> None:
    """给审计限流的状态表剪枝（它自己也不能无界）。"""
    for ip in [ip for ip, ts in _AUDIT_HITS.items()
               if not ts or now - max(ts) >= AUDIT_RATE_WINDOW]:
        _AUDIT_HITS.pop(ip, None)
    for ip in [ip for ip, s in _AUDIT_SUMMARY.items()
               if now - s.get("ts", 0) >= AUDIT_RATE_WINDOW * 2]:
        _AUDIT_SUMMARY.pop(ip, None)
    if len(_AUDIT_HITS) > _AUDIT_HITS_MAX:
        victims = sorted(_AUDIT_HITS.items(),
                         key=lambda kv: max(kv[1]) if kv[1] else 0)
        for ip, _ in victims[:len(_AUDIT_HITS) - _AUDIT_HITS_MAX]:
            _AUDIT_HITS.pop(ip, None)


def _audit_rate_gate(ip: str, event: str):
    """审计写入限流。返回 (本条是否照常写, 需要补写的汇总记录列表)。

    超配额时**不静默丢弃**：被吞掉的条数合并进一条 `audit_throttled`
    汇总记录（保留「发生了 N 次」这个事实），并且每满 100 条再补一条
    带累计数的记录 —— 万一进程被打死，计数也不至于全丢。

    丢掉审计记录比不写更糟：事后没人知道发生过什么。所以这里的取舍是
    「合并」而不是「丢弃」。
    """
    now = time.time()
    extras = []
    with _AUDIT_RATE_LOCK:
        hits = [t for t in _AUDIT_HITS.get(ip, []) if now - t < AUDIT_RATE_WINDOW]
        summary = _AUDIT_SUMMARY.get(ip)
        # 窗口翻篇 → 上一窗的汇总该落盘了（「那段时间被合并掉 N 条」）
        if summary and now - summary.get("ts", 0) >= AUDIT_RATE_WINDOW:
            extras.append({"event": "audit_throttled", "ip": ip,
                           "suppressed": summary.get("count", 0),
                           "kind": summary.get("event", ""),
                           "reason": "audit_rate_limit",
                           "window": AUDIT_RATE_WINDOW})
            _AUDIT_SUMMARY.pop(ip, None)
            summary = None
        if len(hits) < AUDIT_RATE_MAX:
            hits.append(now)
            _AUDIT_HITS[ip] = hits
            _audit_hits_prune(now)
            return True, extras
        # 超配额：本条不单独落盘，合并进汇总
        _AUDIT_HITS[ip] = hits
        if summary is None:
            summary = {"count": 0, "event": event, "ts": now}
            _AUDIT_SUMMARY[ip] = summary
        summary["count"] += 1
        if summary["count"] == 1 or summary["count"] % 100 == 0:
            extras.append({"event": "audit_throttled", "ip": ip,
                           "suppressed": summary["count"],
                           "kind": summary.get("event", ""),
                           "reason": "audit_rate_limit",
                           "window": AUDIT_RATE_WINDOW})
        _audit_hits_prune(now)
        return False, extras


def _audit_write(rec: dict) -> None:
    """把一条审计记录落盘（含轮转）。任何失败都不抛 —— 审计不能阻断认证。"""
    try:
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        os.makedirs(os.path.dirname(AUDIT_LOG) or ".", exist_ok=True)
        _audit_maybe_rotate(AUDIT_LOG, len(line.encode("utf-8")))
        # 精确指定权限位：open(path, "a") 建出来的是 0644（world-readable）。
        fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                     AUDIT_LOG_MODE)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except Exception:
        pass


def audit(event: str, **fields):
    """写审计日志。任何失败都不能影响认证流程本身。

    2026-10-30（P1-45）：加了**写入限流**。
    未认证者可以自由灌 —— /auth/verify 每被拒一次就写一行 verify_denied，
    一个脚本几分钟就能把 2 MiB 的文件写满并触发轮转，把**真正的登录成功
    记录**挤掉（面板只读当前文件的尾部若干行）—— 事后「谁登录过」就查不到。

    但限流**绝不能**变成「攻击者可以让审计彻底失效」的后门：
    `login_ok` / `logout` 永远落盘（见 _AUDIT_ALWAYS），
    其余事件超配额时合并成 `audit_throttled` 汇总（保留「发生了 N 次」）。
    """
    rec = {}
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
        allow, extras = True, []
        # 只有「未认证者能随意触发」的事件才走限流（见 _AUDIT_FLOODABLE）。
        # 限流范围必须精确：放得太宽会把内部事件也悄悄丢掉，
        # 那等于给审计加了个说不清的静默丢弃。
        if event in _AUDIT_FLOODABLE and event not in _AUDIT_ALWAYS:
            allow, extras = _audit_rate_gate(str(rec.get("ip") or "-"), event)
        if allow:
            _audit_write(rec)
        for ex in extras:
            _audit_write(ex)
    except Exception:
        pass   # 审计失败不能反过来阻断认证

    # 放 try 外面：_syslog 自己吞所有异常，这里不该连带影响上面的落盘
    try:
        _syslog(event, rec)
    except Exception:
        pass


def _prepare_audit_log() -> None:
    """在**降权之前**把审计日志的属主/权限摆正（此刻还是 root）。

    为什么必须在降权前做
    ------------------
    降权之后进程就是 uid 1000 了，再也改不了属主 —— 而「改属主」正是
    让审计日志**不可被网关自己篡改**的前提。

    原来的属主是网关自己（init 脚本 `chown nftweb:nftweb`）。
    后果：攻陷网关的进程（uid 1000）可以 chmod/chown **审计日志本身**
    —— 把它改成 0000（让取证一条都读不到）、或者干脆清空。
    也就是说「被攻陷的服务」能同时灭掉自己的痕迹，审计链在**最需要它**
    的那一刻断掉。

    改成属主 root、属组 = 网关的 gid、权限 0660：
      · 网关（组内）照常写 —— 审计功能完全不受影响；
      · 网关**改不了**属主/权限（不是属主），也**删不掉**（目录属 root）；
      · 面板（root）照常读 —— app.py 的日志视图不受影响。

    ⚠️ 这一步失败**不**让进程退出：审计写不进去最多是「少一份记录」，
    而拒绝启动 = 公网唯一入口直接断掉 —— 那是更严重的后果。
    但必须**大声告警**：静默失败会让人以为审计是完好的。
    """
    path = AUDIT_LOG
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    except OSError as e:
        print(f"[WARN] 审计日志目录建不了（{type(e).__name__}）—— 审计记录写不进去",
              flush=True)
        return
    try:
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                         AUDIT_LOG_MODE)
            os.close(fd)
    except OSError as e:
        print(f"[WARN] 审计日志建不了（{type(e).__name__}）—— 审计记录写不进去",
              flush=True)
        return
    try:
        gid = int(os.environ.get("AUTH_DROP_GID", "").strip() or 0)
    except ValueError:
        gid = 0
    try:
        if os.geteuid() == 0 and gid > 0:
            os.chown(path, 0, gid)
            os.chmod(path, 0o660)
        else:
            # 不是 root（或不知道组）：至少把 world 可读收回来
            if (os.stat(path).st_mode & 0o777) & 0o007:
                os.chmod(path, AUDIT_LOG_MODE)
    except OSError as e:
        print(f"[WARN] 审计日志属主/权限调整失败（{type(e).__name__}）—— "
              f"网关仍可写，但它也仍能改这份日志的权限", flush=True)


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

    2026-10-30（P1-16）：**回环不再无条件当内网**。
    原来这里有一句 `if addr.is_loopback: return True` —— 只要算出来的
    客户端 IP 是回环，就判成「内网」，于是 /auth/verify 直接返 200
    免凭据。

    为什么这是个真问题（不是「本地进程反正已经赢了」）：
      · 公网入口 nginx 的 `location = /`（门户页）与各服务的 location
        都会 `proxy_set_header X-Real-IP $remote_addr`，所以**公网来客**
        算出来的 IP 一定是他的真实公网 IP —— 远程打不到这条捷径。
      · 但**从路由器本机**访问公网入口（curl https://127.0.0.1:8443/xxx/）
        时 $remote_addr 就是 127.0.0.1 → 认证服务判成「内网」→ 免密 200。
        于是**任何能在路由器上跑起来的进程**（被攻陷的低权服务、
        容器里的程序、乃至一个能在路由器上打开网页的人）都能拿到
        所有 public_access=true 服务的**免认证访问**。
      · 更糟的是这条捷径还锚在客户端可控的 Host/X-Real-IP 上：
        本地进程随手伪造一个内网 IP 就能冒充「内网设备」。

    现在的语义：**内网 = 配出来的网段**（lan_subnet4 / lan_subnet6）。
    回环不再是隐式豁免 —— 要让它算内网，显式把 127.0.0.0/8 配进去。
    另外留了一个显式开关 `auth_lan_bypass_loopback`（默认关）：
    确实需要「本机免密」的部署可以显式打开，而不是靠一条隐式规则。
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

    # 回环豁免：**必须显式打开**（默认关）。
    # 见上面 P1-16 的说明 —— 隐式的「回环即内网」等于把免认证发给了
    # 路由器上任何能跑起来的进程。
    if addr.is_loopback:
        return bool(cfg.get("auth_lan_bypass_loopback", False))

    subnets = []
    for key in ("lan_subnet4", "lan_subnet6"):
        raw = str(cfg.get(key, "") or "").strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        # /0 **和 /1** 都不认（2026-10-30，P1-15）。
        #
        # 原来这里只挡 /0，/1 是漏的 —— 而 /1 匹配**半个 IPv4 地址空间**：
        # 配成 0.0.0.0/1 时，8.8.8.8 / 1.1.1.1 等公网 IP 全部落进「内网」
        # ⇒ 全部免认证，和 /0 的后果一样，只是范围小一半。
        # 面板侧（app.py 的 validate_config）早就是 `prefixlen <= 1`，
        # 网关这边还写着 `== 0` —— 同一个意图，两个守卫写歪了。
        # 现在两边口径一致：<= 1 一律不认。
        if net.prefixlen <= 1:
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

    # ⚠️ 世代号必须**在续期之前**校验（Shannon P0-1 修复引入的坑，已修）。
    #
    # 滑动续期原本在 `_verify_or_deny()` 里，那条路径**会**先查世代号，
    # 于是「改密码 → epoch 递增 → 旧令牌作废」这条保证是成立的。
    #
    # 续期搬到 /auth/status 之后，如果这里不补上校验，就出现了一条绕过：
    #   ① 用户改密码 → epoch 0→1 → 所有旧令牌（ep=0）本该立刻作废
    #   ② 攻击者拿着旧令牌打 GET /auth/status
    #   ③ 本端点不查 epoch → 只要令牌进入续期窗口（剩余不足一半 TTL），
    #      就给它签一张**新令牌**
    #   ④ 新令牌上的 ep 是**当前**世代（issue_token → _token_epoch()）= 1
    #      ⇒ 旧令牌借续期「洗」成了一张完全有效的新令牌
    #
    # 结果就是「改密码作废全部会话」这条保证被彻底绕开：改完密码，
    # 泄露出去的旧令牌照样能换到新会话。
    #
    # 判据与 `_verify_or_deny` 共用 `_payload_epoch_ok` —— 两条路径
    # 必须同一套判据。
    if not _payload_epoch_ok(payload, cfg):
        return jsonify({"authenticated": False})

    now = int(time.time())
    exp = int(payload["exp"])
    ttl = _session_ttl(cfg)
    abs_to = _absolute_ttl(cfg)
    resp = jsonify({
        "authenticated": True,
        "user": payload.get("sub"), "device_id": payload.get("dev"),
        "fp": fingerprint(),
        "expires_in": max(0, exp - now),
    })

    # ── 滑动续期放在这里（Shannon 渗透测试 finding，实测坐实）────────────
    #
    # 为什么必须放这里：`_verify_or_deny()` 是 nginx `auth_request` 的
    # **子请求**目标，auth_request 默认**丢弃子请求的响应头**。设备 nginx
    # 只配了 auth_request_set $auth_user / $auth_device 两条，没有捕获
    # Set-Cookie —— 在那里续期 = 签了新令牌、吊销了旧 jti，但新令牌**永远
    # 到不了客户端**。
    # .233 实测（修复前）：审计日志
    #   10:28:09 token_refreshed
    #   10:28:54 verify_denied / reason=revoked
    # 客户端全程没有 Set-Cookie ⇒ **每个用户 15 分钟后被踢回登录页**。
    #
    # /auth/status 在 nginx 里是普通 proxy_pass（location = /auth/status，
    # **没有** auth_request），响应头原样到达浏览器 ⇒ Set-Cookie 真的生效。
    # portal.js 每次打开门户都会调它（portal.js:263）。
    #
    # 安全前提：**必须持有有效令牌**才能走到这里 —— 令牌无效/被吊销时上面
    # 已经 return 了。攻击者拿不到别人的令牌，就无法靠反复调这个端点把
    # 对方的会话顶掉（续期只签发给他自己）。
    #
    # 绝对 TTL 不能被续期绕过：issue_token 的第四个参数是**原始 iat + 绝对
    # 上限**，续期不重置它。
    if exp - now < ttl * TOKEN_REFRESH_RATIO:
        # 必须先吊销旧 jti 再签新的。否则攻击者截获的旧 token 在受害者
        # 反复续期期间一直是有效的 —— 更要命的是**登出也救不回来**：
        # 登出只吊销「当时手上那张」，受害者手里那张是续期后的新 token，
        # 攻击者那张是更早的、jti 从未被吊销的旧 token。
        # 结果是「登出」这个本该能一键切断的急停开关对已泄露凭据无效。
        #
        # 吊销失败**不拦续期**（这是本项目明确的取舍）：
        # 吊销表写不进去时抛异常会被 except Exception 接住变成 500，
        # 于是每一次需要续期的请求都失败 —— 比「旧令牌多活一会儿」
        # 严重得多（那会把所有人踢回登录页）。
        #
        # 2026-10-30（P1-6）：「旧令牌多活一会儿」这件事被**收口**了 ——
        # 失败不再等于「当成成功」：
        #   ① 返回值照旧检查，失败照旧落审计（refresh_old_token_not_revoked）；
        #   ② **旧 jti 进进程内的「已被取代」名单**（_mark_superseded），
        #      is_revoked() 一并查它 ⇒ 旧令牌在本进程内立刻失效，
        #      哪怕吊销表一个字都写不进去。
        # 于是「被取代的令牌继续有效」这个窗口被关上了，而**用户不会被
        # 踢下线**（浏览器拿到的是新令牌，Set-Cookie 照常下发）。
        if not revoke_jti(payload.get("jti", ""), exp):
            audit("refresh_old_token_not_revoked",
                  exp=exp, device=payload.get("dev"))
        new_tok = issue_token(
            str(payload.get("sub", "kirito")),
            str(payload.get("dev", "")),
            ttl,
            int(payload.get("iat", now)) + abs_to if abs_to else 0,
        )
        # 新令牌签出来了 ⇒ 旧 jti 从此刻起作废（本进程内）。
        # 放在签发之后：万一签发失败，旧令牌还能继续用，不至于两头落空。
        _mark_superseded(payload.get("jti", ""), exp)
        _set_cookies(resp, new_tok, str(payload.get("dev", "")), raw=False)
        audit("token_refreshed", device=payload.get("dev"), fp=fingerprint())
    return resp


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
        locked, fails = _mutate_ratelimit(ip, on_fail=True)
        audit("login_fail", device=device_id_from_request(), fp=fingerprint())
        # 响应体与耗时对「密码错」和「未设密码」保持一致，避免状态枚举
        remaining = max(0, RATE_LIMIT_MAX_FAILS - fails)
        if locked:
            # ⚠️ 这次请求**触发了锁定**（或本来就在锁定期内）——
            # 必须返 429，不能返 401。
            #
            # 原来这里一律返 401，于是「第 5 次（触发锁定的那次）」返回的是
            # 「密码错误，还剩 5 次」—— 两处都错：既不是 429，remaining 也
            # 算错了。.233 实测序列：4→3→2→1→5→429。
            #
            # 审计仍记 login_fail ——「密码确实错了」是事实；429 只是
            # 「现在别再试了」这个限流状态，两者不冲突。
            remaining = 0
            audit("login_rate_limited", device=device_id_from_request(),
                  fp=fingerprint())
            return jsonify({"success": False, "code": "RATE_LIMITED",
                            "message": "尝试次数过多，已临时锁定，请稍后再试",
                            "remaining": 0}), 429
        return jsonify({"success": False, "code": "AUTH_FAILED",
                        "message": "密码错误", "remaining": remaining}), 401

    _mutate_ratelimit(ip, on_fail=False)   # 成功则清空该 IP 失败记录

    # 重新登录前先吊销当前浏览器带着的旧令牌。
    # 少了这一步（Shannon AUTH-02）：客户端已登录过、令牌仍在有效期内，
    # 再次登录会签发新令牌，但旧令牌不作废 —— 一旦旧令牌泄露（XSS、
    # 日志、抓包），用户在面板里重新登录并不能把攻击者踢下线。
    # 实测：重新登录后旧令牌访问 /auth/portal 仍返回 200，剩余有效期 1799 秒。
    #
    # 2026-10-30（P1-1）：原来这里读的是 **cookie**：
    #     _old = parse_token(request.cookies.get(COOKIE_TOKEN, ""))
    # 于是 **Bearer 客户端**的旧令牌根本不会被吊销 —— 脚本/CLI 用
    # `Authorization: Bearer` 登录时，cookie 里根本没有令牌，
    # 旧令牌原封不动地继续有效（而且滑动续期下可能永不过期）。
    # 这正是 2026-10-16 给 logout 修过的同一个类别的不对称：
    # 那边已经改成走 `_extract_token()`（Bearer 优先、cookie 兜底），
    # 登录这条路径漏了。现在两边用同一个函数。
    _old = parse_token(_extract_token())
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

        # ⚠️ 这里**不做**滑动续期（Shannon 渗透测试 finding，实测坐实）。
        #
        # 本函数是 nginx `auth_request` 的**子请求**目标，而 auth_request
        # 默认**丢弃子请求的响应头** —— 设备 nginx 只配了
        #   auth_request_set $auth_user ...
        #   auth_request_set $auth_device ...
        # 两条，**没有捕获 Set-Cookie**。
        #
        # 所以原来在这里续期 = 签了新令牌 + 吊销了旧 jti，但新令牌**永远
        # 到不了客户端**。.233 实测：审计日志
        #   10:28:09 token_refreshed
        #   10:28:54 verify_denied / reason=revoked
        # 客户端全程没收到任何 Set-Cookie ⇒ **每个登录用户 15 分钟后被踢回
        # 登录页**，自 bfde5ec 起存在，所有部署都中招。
        #
        # 续期已搬到 `/auth/status`（那里在 nginx 里是普通 proxy_pass，
        # 响应头原样到达浏览器，Set-Cookie 才真的生效）。
        #
        # 这里退回**纯校验**、无副作用：既不改令牌状态，也不吊销 jti。
        # 令牌自然过期时返回 401 → 跳登录页，**一次性**，而不是每 15 分钟
        # 循环被踢。
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

    2026-10-30（P1-5）：补上**绝对 TTL**。
    原来这条路径只查「令牌有效 + 世代号对 + 没被吊销」，唯独不查
    「签发时间起算有没有超过绝对上限」。而 `_verify_or_deny`（nginx
    auth_request 走的那条）是查的 —— 于是同一个令牌：
      · 经 nginx 访问服务 → 401（绝对上限到了）
      · 直接访问 /auth/portal → 200（照样吐服务清单）
    12 小时前签发的令牌在 nginx 那条路已经被拒，却还能从门户这条门
    读出全部反代服务清单 —— 前后不一致，最难排查的那种。
    两条鉴权路径的判据必须一致：这里与 `_verify_or_deny` 用同一套
    （`_absolute_ttl` + iat）。
    """
    cfg = load_gateway_config()
    if is_lan_source(cfg):
        return True
    payload = parse_token(_extract_token())
    if not payload:
        return False
    if not _payload_epoch_ok(payload, cfg):
        return False
    if is_revoked(payload.get("jti", "")):
        return False
    # 绝对上限：签发时间起算，超时强制重登（与 _verify_or_deny 同一判据）
    abs_to = _absolute_ttl(cfg)
    if abs_to:
        now = int(time.time())
        if now - int(payload.get("iat", now)) > abs_to:
            return False
    return True


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
            # ⚠️ 读端必须拿共享锁（Shannon 渗透测试 finding）。
            #
            # 写端是「truncate + 就地写」，持 LOCK_EX。读端不拿锁的话，
            # 可能正好读到 truncate 之后、json.dump 之前的**半截 JSON**
            # → json.load 抛 JSONDecodeError → 被 except 吞掉 →
            # **当作「没锁定」放行** ⇒ 暴力破解防护被绕过。
            #
            # 拿 LOCK_SH 之后，读到的要么是完整的旧内容，要么是完整的新内容。
            # （写端本来就在同一个文件上用 LOCK_EX，两边配对。）
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                data = json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        if isinstance(data, dict):
            rec = data.get(ip)
            if isinstance(rec, dict):
                lu = rec.get("locked_until", 0)
                if isinstance(lu, (int, float)) and lu > time.time():
                    return True
    except (OSError, ValueError):
        # ValueError 覆盖 json.JSONDecodeError（它是 ValueError 的子类）
        # 以及其它解析异常 —— 读不到就当没锁定，交给下面的内存兜底判断。
        pass
    return _ratelimit_fallback_is_locked(ip)


def _trusted_host_names(cfg) -> set:
    """服务端**自己知道**的域名集合 —— CSRF 判定的锚点。

    来源全部是落盘配置里的域名（认证服务只读不猜）：
      · reverse_proxy.settings.base_domain   —— 面板从默认证书 SAN 推导并落盘
      · reverse_proxy.settings.cookie_domain  —— cookie 共享域
      · 每条反代规则的 host                  —— host 分发入口

    为什么不能用请求的 Host 头当锚点：Host 是**客户端可控**的。
    浏览器发起的跨站请求里，Host 永远是「受害者正在访问的那个主机」，
    所以「Origin 的主机 == Host 的主机」这个判据挡不住 **DNS 重绑定**：
    攻击者让 evil.com 解析到这台路由器，受害者浏览器于是发出
    Host: evil.com + Origin: https://evil.com —— 旧判据放行，
    攻击者就能借受害者的浏览器驱动登录（CSRF login）。
    锚点必须是**服务端自己写的**域名，攻击者碰不到。
    """
    hosts = set()
    rp = cfg.get("reverse_proxy")
    rp = rp if isinstance(rp, dict) else {}
    settings = rp.get("settings")
    settings = settings if isinstance(settings, dict) else {}
    for key in ("base_domain", "cookie_domain"):
        raw = str(settings.get(key, "") or "").strip().lower().lstrip(".")
        if raw:
            hosts.add(raw)
    rules = rp.get("rules")
    for r in (rules or []):
        if not isinstance(r, dict):
            continue
        h = str(r.get("host", "") or "").strip().lower()
        if h:
            hosts.add(h)
    return hosts


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _origin_host_mismatch(url: str) -> bool:
    """Origin/Referer 与本服务是否不同源 → 判为跨站。

    2026-10-30（P1-11）：锚点从「客户端可控的 Host 头」换成
    **服务端自己知道的域名**（见 _trusted_host_names），并且**端口纳入比较**。

    端口为什么必须比：浏览器的同源策略按 scheme + host + **port** 算。
    同一个主机名的 8443 和 443 是两个不同的源 —— 只比主机名等于把
    「同主机不同端口」这种跨源请求放过去了。

    允许的端口：scheme 的默认端口（https=443 / http=80）+ 配置里的
    **对外端口** gateway_port（设备 nginx 真正监听的那个）。
    认证服务自己的内部端口（auth_api_port）不在其中 ——
    浏览器看到的源永远是 nginx 那侧的端口。
    """
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
        scheme = (u.scheme or "").lower()
        # u.port 对非法端口会抛 ValueError → 走下面的 except → 判跨站。
        port = u.port
        if port is None:
            port = 443 if scheme == "https" else 80

        try:
            cfg = load_gateway_config()
        except Exception:
            cfg = {}
        # 请求自己的主机名（客户端可控，只在「配置里没有域名」时当锚）
        req_host = (request.host or "").split(":")[0].strip().lower()

        trusted = _trusted_host_names(cfg)
        if trusted:
            if host in trusted:
                host_ok = True
            elif any(host.endswith("." + t) for t in trusted):
                # 共享域下的子域也算：base_domain=fzyto.top 时，
                # 用户从 siyuan.fzyto.top 访问登录页是正常用法。
                host_ok = True
            elif _is_ip_literal(req_host) and host == req_host:
                # 用 IP 直访的部署：IP 字面量**不可能**被 DNS 重绑定，
                # 所以仍然认它 —— 否则 IP 访问直接登不进去。
                host_ok = True
            else:
                host_ok = False
        else:
            # 配置里一个域名都没有 ⇒ 这是纯 IP 部署。没有域名可锚，
            # DNS 重绑定（evil.com 解析到本机）也就无从谈起，
            # 退回与 Host 头比较（与旧行为一致，不制造新的登录故障）。
            host_ok = (host == req_host)
        if not host_ok:
            return True

        allowed = {80, 443}
        try:
            allowed.add(int(cfg.get("gateway_port", 8443) or 8443))
        except (TypeError, ValueError):
            allowed.add(8443)
        return port not in allowed
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


def _token_max_age(token: str, cfg=None) -> int:
    """令牌 cookie 的 Max-Age —— 以**令牌自己的 exp** 为准。

    2026-10-30（P1-14）：原来 `_set_cookies` 用的是 `_session_ttl(cfg)`
    （滑动窗口 TTL，默认 1800 秒），而令牌的 exp 可能**比它短**：
      · 绝对上限（auth_absolute_timeout）把 exp 卡在 `iat + 上限`，
        离滑动窗口到期还早；
      · 续期签发的新令牌 exp = min(now+ttl, 原 iat + 绝对上限)，同理。

    于是出现「**cookie 比令牌活得久**」：令牌在服务端已经作废，
    浏览器还一直带着它。表现是「明明刚登录成功，怎么又要登录」——
    因为每个请求带过去的都是一张死令牌。
    反过来（cookie 先死、令牌还活着）只是少登一次，无害。
    所以 Max-Age 必须以令牌的真实寿命为准；解析不出来时才退回会话 TTL。
    """
    ttl = _session_ttl(cfg if cfg is not None else load_gateway_config())
    payload = parse_token(token)
    if not payload:
        return ttl
    exp = payload.get("exp")
    if not isinstance(exp, int):
        return ttl
    return max(0, exp - int(time.time()))


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
        resp.set_cookie(COOKIE_TOKEN, token, max_age=_token_max_age(token, cfg),
                        httponly=True, secure=True, samesite="Lax", path="/",
                        domain=cdom or None)
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

    ⚠️ 这一层查的是**环境变量**，不是事实 —— 2026-10-30（P1-12）
    补了真正查内核里那个监听套接字的那一层（_assert_socket_loopback）。
    两层都要：环境变量这一层管住「配置写错」，套接字那一层管住
    「实际绑到了别处」。
    """
    if BIND_HOST not in ("127.0.0.1", "::1", "localhost"):
        print(f"[FATAL] 认证服务拒绝绑定 {BIND_HOST}：只允许 127.0.0.1/::1。"
              f"公网入口必须经 nginx auth_request。", flush=True)
        raise SystemExit(1)


def _assert_socket_loopback(sock) -> None:
    """检查**真实监听套接字**绑在哪 —— 不是回环就拒绝启动。

    2026-10-30（P1-12）：原来只有 `_assert_loopback_bind()`，它看的是
    **环境变量** AUTH_BIND_HOST。环境变量不是事实：
      · `localhost` 解析到什么就是什么（/etc/hosts 是可改的文件）；
      · 将来有人把 bind 地址换成别的，断言照样通过；
      · 万一有一处代码用了另一个 bind 地址，这层完全看不见。

    而这条断言保护的是本项目安全模型里最不能破的一条：
    **认证服务只能绑回环**，公网入口必须经 nginx auth_request ——
    绑 0.0.0.0 等于给认证系统开一个可从公网直接触达的入口。

    `sock.getsockname()` 拿的是 bind() 之后的**真实地址**，
    是内核层面的事实，不是配置层面的声明。

    失败即退出（SystemExit(1)），与本文件其它校验一致：
    「校验类的失败」绝不能变成「打印个警告然后继续跑」。
    """
    try:
        addr = sock.getsockname()
    except OSError as e:
        print(f"[FATAL] 读不到监听套接字地址（{type(e).__name__}）—— 拒绝启动。",
              flush=True)
        raise SystemExit(1)
    host = addr[0] if isinstance(addr, tuple) else addr
    host = str(host or "").strip()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        print(f"[FATAL] 监听地址 {host!r} 不是合法 IP —— 拒绝启动。", flush=True)
        raise SystemExit(1)
    if not ip.is_loopback:
        print(f"[FATAL] 实际监听地址 {host} 不是回环 —— 拒绝启动。"
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
# 审计日志必须在**降权之前**摆正属主/权限 —— 降权之后就再也改不了属主了。
_prepare_audit_log()
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

    # 用 make_server 而不是 app.run —— 只有拿到 server 对象才检查得了
    # **真实监听套接字**（2026-10-30，P1-12）。app.run() 在内部建好
    # server 就直接 serve_forever，套接字压根不经过我们的手。
    from werkzeug.serving import make_server
    try:
        _srv = make_server(BIND_HOST, BIND_PORT, app, threaded=True)
    except OSError as e:
        print(f"[FATAL] 监听 {BIND_HOST}:{BIND_PORT} 失败（{type(e).__name__}: {e}）"
              f" —— 拒绝启动。", flush=True)
        raise SystemExit(1)
    # 内核层面的事实：绑完之后的真实地址。不是回环 → 拒绝启动。
    _assert_socket_loopback(_srv.socket)
    print(f" * 监听地址 : {_srv.socket.getsockname()[0]}:{BIND_PORT}"
          f"（已核验为回环）", flush=True)
    _srv.serve_forever()
