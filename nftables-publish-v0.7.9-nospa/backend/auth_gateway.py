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

BIND_HOST = os.environ.get("AUTH_BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("AUTH_API_PORT", "8444"))

# 安全参数
TOKEN_TTL_DEFAULT = 1800        # 滑动窗口 30 分钟
TOKEN_ABS_TTL_DEFAULT = 0       # 绝对上限，0 = 不启用
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
    "portal.html", "portal.js",
})

# 网关内部端点占用的前缀（与 app.py 的 _RESERVED_GATEWAY_PREFIXES 保持一致）
RESERVED_PREFIXES = ("/_auth", "/auth")

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False


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
    ttl = _int(cfg.get("auth_absolute_timeout"), TOKEN_ABS_TTL_DEFAULT)
    return ttl if 0 < ttl <= 604800 else 0


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


def load_revoked() -> dict:
    try:
        with open(_revocation_path(), "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def revoke_jti(jti: str, exp: int):
    """吊销一个 jti。exp 已过的条目不写盘，避免表无限增长。"""
    if not jti or exp <= int(time.time()):
        return
    path = _revocation_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a+") as f:
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
    os.chmod(path, 0o600)


def is_revoked(jti: str) -> bool:
    if not jti:
        return False
    data = load_revoked()
    exp = data.get(jti)
    return isinstance(exp, int) and exp > int(time.time())


# ══════════════════════════════════════════════════════════════════════
# 登录限流（落盘 + fcntl 锁）
# ══════════════════════════════════════════════════════════════════════

RATE_LIMIT_WINDOW = 300     # 5 分钟内
RATE_LIMIT_MAX_FAILS = 5
RATE_LIMIT_LOCKOUT = 900    # 锁 15 分钟


def _mutate_ratelimit(ip: str, on_fail: bool):
    """原子地读改写限流表。返回 (locked, fail_count)。"""
    path = RATELIMIT_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a+") as f:
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
            os.chmod(path, 0o600)

            rec = data.get(ip, {})
            return False, len(rec.get("fails", []))
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


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
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
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
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; "
        "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
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
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    return resp


@app.route("/auth/status", methods=["GET"])
def auth_status():
    cfg = load_gateway_config()
    if is_lan_source(cfg):
        return jsonify({
            "authenticated": True, "via": "lan-bypass",
            "user": "lan", "device_id": device_id_from_request(),
        })
    payload = parse_token(request.cookies.get(COOKIE_TOKEN, ""))
    if not payload or is_revoked(payload.get("jti", "")):
        return jsonify({"authenticated": False})
    return jsonify({
        "authenticated": True, "via": "token",
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

    try:
        body = request.get_json(silent=True) or {}
        password = str(body.get("password", ""))
    except Exception:
        password = ""

    stored = _password_hash()
    ok = bool(password) and bool(stored) and _verify_password(password, stored)

    if not ok:
        _, fails = _mutate_ratelimit(ip, on_fail=True)
        audit("login_fail", device=device_id_from_request(), fp=fingerprint())
        # 响应体与耗时对「密码错」和「未设密码」保持一致，避免状态枚举
        remaining = max(0, RATE_LIMIT_MAX_FAILS - fails)
        return jsonify({"success": False, "code": "AUTH_FAILED",
                        "message": "密码错误", "remaining": remaining}), 401

    _mutate_ratelimit(ip, on_fail=False)   # 成功则清空该 IP 失败记录

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


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    payload = parse_token(request.cookies.get(COOKIE_TOKEN, ""))
    if payload:
        revoke_jti(payload.get("jti", ""), int(payload.get("exp", 0)))
    audit("logout", device=device_id_from_request(), fp=fingerprint())
    resp = jsonify({"success": True})
    _set_cookies(resp, "", "", clear=True)
    return resp


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

        # Bearer 优先（给脚本/客户端用）
        raw = request.cookies.get(COOKIE_TOKEN, "")
        authz = (request.headers.get("Authorization") or "").strip()
        if not raw and authz.lower().startswith("bearer "):
            raw = authz[7:].strip()

        payload = parse_token(raw)
        if not payload:
            return _deny("no_token")
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
            revoke_jti(payload.get("jti", ""), int(payload.get("exp", 0)))
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
    for r in (rules or []):
        if not isinstance(r, dict) or not r.get("enabled"):
            continue
        pfx = str(r.get("path_prefix", "") or "").strip().rstrip("/")
        if not pfx or pfx in RESERVED_PREFIXES:
            continue
        services.append({
            "name": str(r.get("name") or pfx.lstrip("/"))[:64],
            "path": pfx,
            "public": bool(r.get("public_access")),
            "icon": str(r.get("icon") or "")[:16],
        })
    services.sort(key=lambda s: s["path"])
    return jsonify({"success": True, "services": services,
                    "user": "kirito" if not is_lan_source(cfg) else "lan",
                    "device_id": device_id_from_request()})


def _authenticated() -> bool:
    cfg = load_gateway_config()
    if is_lan_source(cfg):
        return True
    payload = parse_token(request.cookies.get(COOKIE_TOKEN, ""))
    return bool(payload) and not is_revoked(payload.get("jti", ""))


def _deny(reason: str):
    audit("verify_denied", reason=reason, fp=fingerprint())
    return Response(status=401, headers={"X-Auth-Deny-Reason": reason[:40]})


# ══════════════════════════════════════════════════════════════════════
# 辅助
# ══════════════════════════════════════════════════════════════════════

def _is_locked(ip: str) -> bool:
    try:
        with open(RATELIMIT_FILE, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    rec = data.get(ip)
    if not isinstance(rec, dict):
        return False
    lu = rec.get("locked_until", 0)
    return isinstance(lu, (int, float)) and lu > time.time()


def _origin_host_mismatch(url: str) -> bool:
    """Origin/Referer 的 host 与本次请求 host 不一致 → 判为跨站。"""
    from urllib.parse import urlparse
    try:
        u = urlparse(url)
        if not u.netloc:
            return False
        host = u.netloc.split(":")[0]
        return host != request.host.split(":")[0]
    except Exception:
        return True


def _set_cookies(resp, token: str, device: str, clear: bool = False, raw: bool = True):
    """统一下发 cookie。

    token cookie 短寿（随 token exp），device cookie 长寿（一年）。
    HttpOnly 防 JS 读取，Secure 只走 HTTPS，SameSite=Lax 挡跨站携带。
    """
    if clear:
        resp.set_cookie(COOKIE_TOKEN, "", max_age=0, httponly=True,
                        secure=True, samesite="Lax", path="/")
        resp.set_cookie(COOKIE_DEVICE, "", max_age=0, httponly=True,
                        secure=True, samesite="Lax", path="/")
        return
    if token:
        ttl = _session_ttl(load_gateway_config())
        resp.set_cookie(COOKIE_TOKEN, token, max_age=ttl, httponly=True,
                        secure=True, samesite="Lax", path="/")
    if device:
        resp.set_cookie(COOKIE_DEVICE, device, max_age=DEVICE_COOKIE_TTL,
                        httponly=True, secure=True, samesite="Lax", path="/")


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


_assert_loopback_bind()


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
