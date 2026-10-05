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
import time

import fcntl

from flask import Flask, Response, jsonify, request

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

COOKIE_TOKEN = "gw_token"
COOKIE_DEVICE = "gw_device"

HEADER_FINGERPRINT = "X-Device-Fingerprint"
HEADER_ORIG_SVC = "X-Original-URI"

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
    """PBKDF2-HMAC-SHA256 校验，常量时间比较。"""
    try:
        algo, iters, salt, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters)
        if iters < PBKDF2_ITERATIONS_MIN:
            # 迭代数过低 = 哈希强度形同虚设，直接拒绝而不是"降级接受"
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), iters)
        return hmac.compare_digest(digest.hex(), hash_hex)
    except Exception:
        return False


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
# 审计日志（JSONL 落盘）
# ══════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════
# 请求上下文
# ══════════════════════════════════════════════════════════════════════

def client_ip() -> str:
    """取真实客户端 IP。

    nginx auth_request 侧会透传 X-Real-IP，本进程仅监听 127.0.0.1，
    所以 request.remote_addr 永远是 127.0.0.1 —— 必须用头。
    """
    ip = (request.headers.get("X-Real-IP")
          or request.headers.get("X-Forwarded-For", "").split(",")[0]
          or request.remote_addr or "")
    ip = ip.strip()
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ""


def is_lan_source(cfg) -> bool:
    """判断来源是否属于内网。判定失败一律判 False（要认证）。

    顺序很重要：**配置里显式指定的网段是权威**，先判它；
    没配或没命中才回落到 is_private。
    这样用户可以用 lan_subnet4 收紧范围（只放行真正的 LAN 网段），
    而不会被 is_private 的宽泛定义意外放宽。
    """
    if not cfg.get("auth_lan_bypass", True):
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

    for key in ("lan_subnet4", "lan_subnet6"):
        raw = str(cfg.get(key, "") or "").strip()
        if not raw:
            continue
        try:
            if addr in ipaddress.ip_network(raw, strict=False):
                return True
        except ValueError:
            continue

    return addr.is_private


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
    origin = (request.headers.get("Origin") or "").strip()
    referer = (request.headers.get("Referer") or "").strip()
    if origin and origin not in ("null",) and _origin_host_mismatch(origin):
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
    """兜底处理器：认证服务里未捕获的异常一律不外泄细节。"""
    try:
        audit("unhandled_exception", error=repr(err)[:200])
    except Exception:
        pass
    return jsonify({"success": False, "code": "INTERNAL",
                    "message": "服务内部错误"}), 500


# ══════════════════════════════════════════════════════════════════════
# 启动
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # 只绑 127.0.0.1：公网入口只有 nginx，nftables 也不为本端口生成任何放行规则。
    # 绑 0.0.0.0 会让认证系统多一个可被直接触达的入口，是重大配置错误。
    if BIND_HOST not in ("127.0.0.1", "::1", "localhost"):
        print(f"[FATAL] 认证服务拒绝绑定 {BIND_HOST}：只允许 127.0.0.1/::1。"
              f"公网入口必须经 nginx auth_request。", flush=True)
        raise SystemExit(1)

    print(f" * 认证网关 : http://{BIND_HOST}:{BIND_PORT}", flush=True)
    print(f" * 端点     : /auth/status /auth/login /auth/logout /auth/verify /auth/portal",
          flush=True)
    print(f" * 公网可达 : 否（仅接受来自 nginx 的 auth_request 与本机请求）", flush=True)

    app.run(host=BIND_HOST, port=BIND_PORT, threaded=True, debug=False)
