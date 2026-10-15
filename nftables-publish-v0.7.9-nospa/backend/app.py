# Version: 0.7.9.1
from flask import Flask, jsonify, request, send_from_directory, send_file, session
import os, subprocess, shutil, json, time, re, hmac, hashlib, base64, datetime, uuid, fcntl, io, zipfile, secrets, ssl, ipaddress, socket, threading, contextlib
from template_engine import load_template, generate_rules

# ======================= 认证配置 =======================
AUTH_PASSWORD_FILE = '/etc/nftables/nftables-web-password'
AUTH_SECRET_FILE = '/etc/nftables/nftables-web-secret'
AUTH_COOKIE_NAME = 'nftables_web_session'
AUTH_SESSION_LIFETIME = 12 * 3600   # 12 小时（最长生命周期）
AUTH_IDLE_TIMEOUT = 3600            # 1 小时无操作自动登出
PBKDF2_ITERATIONS = 200000
# 登录失败限流：N 秒内 M 次失败则锁 L 秒
AUTH_RATE_LIMIT_WINDOW = 300  # 5 分钟
AUTH_RATE_LIMIT_MAX_FAILS = 5
AUTH_RATE_LIMIT_LOCKOUT = 900  # 15 分钟

app = Flask(__name__)
CONFIG_PATH = '/etc/nftables/nftables-web-config.json'
RULES_PATH = '/etc/nftables.d/99-custom-rules.nft'

# 面板 HTTPS 端口（仅 LAN 可达，防火墙侧由 lan_allowed_ports 放行）。
# 定义在文件顶部：validate_config() 要用它做「网关端口不能占用面板端口」的交叉校验。
HTTPS_PORT = int(os.environ.get("NFTABLES_WEB_HTTPS_PORT", "5443"))


def _init_app_secret():
    """读取或生成 Flask SECRET_KEY（持久化到 /etc/nftables/nftables-web-secret）"""
    try:
        if os.path.exists(AUTH_SECRET_FILE):
            with open(AUTH_SECRET_FILE, 'r') as f:
                key = f.read().strip()
                if key:
                    return key
    except Exception:
        pass
    secret = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(AUTH_SECRET_FILE), exist_ok=True)
        with open(AUTH_SECRET_FILE, 'w') as f:
            f.write(secret)
        os.chmod(AUTH_SECRET_FILE, 0o600)
    except Exception:
        pass
    return secret


app.secret_key = _init_app_secret()
app.config['SESSION_COOKIE_NAME'] = AUTH_COOKIE_NAME
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True   # HTTPS 服务；Secure 标志防止中间人窃取 cookie
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(seconds=AUTH_SESSION_LIFETIME)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# 上传大小限制：证书 < 10KB，反代规则配置几百字节；16MB 富余足够
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB


# ======================= 密码哈希/验证（标准库 pbkdf2） =======================
def _hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256，200000 轮，无外部依赖"""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt, hash_hex = stored.split('$', 3)
        if algo != 'pbkdf2_sha256':
            return False
        digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), int(iters))
        return hmac.compare_digest(digest.hex(), hash_hex)
    except Exception:
        return False


def _password_set() -> bool:
    return os.path.exists(AUTH_PASSWORD_FILE)


def _read_password_hash() -> str:
    try:
        with open(AUTH_PASSWORD_FILE, 'r') as f:
            data = json.load(f)
        return data.get('hash', '')
    except Exception:
        return ''


def _write_password_hash(hash_str: str):
    os.makedirs(os.path.dirname(AUTH_PASSWORD_FILE), exist_ok=True)
    with open(AUTH_PASSWORD_FILE, 'w') as f:
        json.dump({'hash': hash_str, 'created_at': datetime.datetime.now().isoformat()}, f)
    os.chmod(AUTH_PASSWORD_FILE, 0o600)


def _is_authenticated() -> bool:
    return session.get('authenticated') is True


# 登录失败计数（IP -> [timestamp, ...]），用于限流
#
# 落盘，而不是内存 dict。
#
# 为什么：内存计数进程一重启就清零，攻击者只要能让面板重启（crash / 服务
# 被 manage 脚本重启 / 定时任务 reload）就能把计数抹掉，然后按 5 次一组慢慢
# 试 —— 5 分钟窗口 + 15 分钟锁定这个策略被绕开一半。
#
# 认证网关（auth_gateway.py，8443 的真正入口）早就是落盘的了，它的模块文档
# 里明确点名了本文件这个内存 dict 是「不重复的错误」。这里跟齐。
#
# 落盘口径与网关保持一致：按 IP 记、5 次/5 分钟锁 15 分钟、成功即清空、
# 过期条目顺手 GC。文件不可用时降级回内存（不能让限流文件的问题把登录
# 整个搞挂），并如实打日志。
PANEL_RATELIMIT_FILE = '/etc/nftables/nftables-web-panel-ratelimit.json'
_MAX_FAILED_LOGINS_IPS = 50000  # IP 数硬上限（防恶意创建大量 IP 条目撑爆文件/内存）
_request_counter = 0  # 用于触发定期 GC
_RATELIMIT_DEGRADED = {'warned': False}   # 文件不可用时只警告一次，别刷屏


def _ratelimit_read():
    """读限流表。返回 {ip: {'fails': [...], 'locked_until': t}}。"""
    try:
        with open(PANEL_RATELIMIT_FILE, 'r') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):
        return {}


def _ratelimit_write(data):
    """写限流表：唯一 tmp + 原子替换 + 600 权限。"""
    d = os.path.dirname(PANEL_RATELIMIT_FILE)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = PANEL_RATELIMIT_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, PANEL_RATELIMIT_FILE)


def _ratelimit_degrade(e):
    """落盘不可用 → 降级到内存，并只警告一次。

    不能因为限流文件写不了就把登录整个搞挂 —— 那等于把面板变成谁都进不去。
    """
    if not _RATELIMIT_DEGRADED['warned']:
        _RATELIMIT_DEGRADED['warned'] = True
        print(f'[WARNING] 登录限流落盘不可用（{type(e).__name__}: {e}），'
              f'降级为内存计数 —— 面板重启后失败次数会清零', flush=True)


def _ratelimit_state(ip):
    """取某个 IP 的 (fails, locked_until)，顺手做过期清理。返回 None 表示该 IP 无记录。"""
    rec = _ratelimit_read().get(ip)
    if not isinstance(rec, dict):
        return None
    now = time.time()
    fails = [t for t in rec.get('fails', [])
             if isinstance(t, (int, float)) and now - t < AUTH_RATE_LIMIT_LOCKOUT]
    lu = rec.get('locked_until', 0)
    lu = lu if isinstance(lu, (int, float)) else 0
    if not fails and lu <= now:
        return None
    return fails, lu


def _check_rate_limit(ip: str) -> tuple:
    """检查 IP 是否被限流。返回 (allowed: bool, retry_after: int|None)"""
    global _request_counter
    _request_counter += 1
    now = time.time()
    try:
        st = _ratelimit_state(ip)
    except OSError as e:
        _ratelimit_degrade(e)
        st = None
    if st is None:
        return True, None
    fails, locked_until = st
    # 已锁定：直接按 locked_until 算，不依赖 fails 是否还在
    if locked_until > now:
        return False, int(locked_until - now) + 1
    recent = [t for t in fails if now - t < AUTH_RATE_LIMIT_WINDOW]
    if len(recent) >= AUTH_RATE_LIMIT_MAX_FAILS:
        oldest = min(recent)
        return False, int(AUTH_RATE_LIMIT_LOCKOUT - (now - oldest)) + 1
    return True, None


def _record_login_failure(ip: str):
    """记录一次登录失败（落盘 + fcntl 排他锁）。"""
    try:
        _ratelimit_mutate(ip, on_fail=True)
    except OSError as e:
        _ratelimit_degrade(e)


def _clear_login_failures(ip: str):
    """登录成功，清空该 IP 的记录（落盘）。"""
    try:
        _ratelimit_mutate(ip, on_fail=False)
    except OSError as e:
        _ratelimit_degrade(e)


def _ratelimit_mutate(ip: str, on_fail: bool):
    """原子地读改写限流表。返回 (是否已锁, 失败次数)。

    持排他锁：面板是 threaded 的，两个并发登录同时读改写会丢计数，
    而「丢计数」正是这个机制要防的事。
    """
    d = os.path.dirname(PANEL_RATELIMIT_FILE)
    if d:
        os.makedirs(d, exist_ok=True)
    lock_path = PANEL_RATELIMIT_FILE + '.lock'
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        data = _ratelimit_read()
        now = time.time()
        rec = data.get(ip) if isinstance(data.get(ip), dict) else {}
        locked_until = rec.get('locked_until', 0)
        if not isinstance(locked_until, (int, float)):
            locked_until = 0

        if locked_until > now:
            return True, len(rec.get('fails', []) or [])

        if on_fail:
            fails = [t for t in (rec.get('fails') or [])
                     if isinstance(t, (int, float)) and now - t < AUTH_RATE_LIMIT_WINDOW]
            if len(fails) >= _MAX_FAILED_LOGINS_IPS:
                # 单个 IP 的时间戳列表也要有上限，别被同一 IP 灌爆
                fails = fails[-_MAX_FAILED_LOGINS_IPS:]
            fails.append(now)
            if len(fails) >= AUTH_RATE_LIMIT_MAX_FAILS:
                data[ip] = {'fails': [], 'locked_until': now + AUTH_RATE_LIMIT_LOCKOUT}
                _ratelimit_gc(data)
                _ratelimit_write(data)
                return True, 0
            rec['fails'] = fails
            rec['locked_until'] = 0
            data[ip] = rec
        elif ip in data:
            data.pop(ip, None)

        # 顺手 GC 过期条目，防止表无限膨胀
        _ratelimit_gc(data)
        _ratelimit_write(data)
        return False, len(data.get(ip, {}).get('fails', []) or [])
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _ratelimit_gc(data):
    """删掉已完全过期的 IP 条目"""
    now = time.time()
    cutoff = now - (AUTH_RATE_LIMIT_LOCKOUT + AUTH_RATE_LIMIT_WINDOW)
    for ip in [ip for ip, rec in data.items()
               if not isinstance(rec, dict)
               or max(list(rec.get('fails') or [0])
                      + [rec.get('locked_until', 0)
                         if isinstance(rec.get('locked_until'), (int, float)) else 0]) < cutoff]:
        data.pop(ip, None)


# 公开路径白名单（无需登录）
_STATIC_EXTENSIONS = ('js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'map')


# ══════════════════════════════════════════════════════════════════
# 面板的来源访问边界
#
# 为什么写在应用层而不是 nftables：这条边界存在的全部意义，是在防火墙
# 规则集丢失时（flush / 文件损坏 / 恢复链选错文件）还能挡住公网。写在
# nft 里的话，它会和规则集一起消失，等于什么都没做。
#
# 为什么不能复用 trusted_ip4：那个字段是**信任名单**（免密码 + 防火墙
# 优先放行），语义与「访问边界」相反；而且它的 _valid_ip() 用
# ipaddress.ip_address() 校验，根本不接受 CIDR。
# ══════════════════════════════════════════════════════════════════

_NETS_CACHE = {'mtime': None, 'nets': None}


def _parse_net_list(v):
    """把 panel_allowed_nets 归一化成网络对象列表。

    元素可以是 CIDR（192.168.100.0/24）、单个 IP（192.168.100.5，
    按 /32 处理）、或把上面两种用逗号／中文逗号混在一根字符串里。
    """
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        parts = [str(x).strip() for x in v]
    else:
        parts = [p.strip() for p in str(v).replace('，', ',').split(',')]
    nets = []
    for p in parts:
        if not p:
            continue
        try:
            nets.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            continue      # 非法值由 validate_config 负责报错，这里跳过不影响兜底
    return nets


def _ip_in_nets(ip_str, nets):
    """来源 IP 是否落在允许网段内。解析失败一律判否（宁可多挡）。"""
    try:
        addr = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def _panel_allowed_networks():
    """面板允许访问的来源网段。返回 [] 表示不限制（保持既有行为）。

    优先级：
      1. 配置里显式写了 panel_allowed_nets → 用它（要放行 VPN 之类就用这个）
      2. 没写，但**真实配置文件存在** → 用 lan_subnet4（默认跟随，零配置）
      3. 配置文件缺失/损坏，取不到 lan_subnet4 → 不限制

    第 3 条不能省：DEFAULT_CONFIG 里 lan_subnet4 写的是 192.168.4.0/24，
    那是别人的网段。真拿它去判定会把管理员自己锁在门外 —— 代码里
    _config_lost_after_setup() 早就在防同一类问题了。

    「文件存在」不等于「文件可用」：配置被写坏时 load_config() 会回落到
    DEFAULT_CONFIG，而那个默认值里的 lan_subnet4 正是陌生网段。只判
    os.path.exists 会让「文件存在但内容是坏的」这一种情况照样锁死管理员 ——
    所以这里必须再问一次 _config_corrupted()。
    """
    try:
        stamp = os.stat(CONFIG_PATH).st_mtime_ns
    except OSError:
        return []                       # 配置不存在 → 不限制
    if _NETS_CACHE['mtime'] == stamp:
        return _NETS_CACHE['nets']
    try:
        cfg = load_config()
        bad, err = _config_corrupted()
        if bad:
            print(f'[WARN] 配置损坏（{err}），面板访问边界本次不限制', flush=True)
            nets = []
        else:
            nets = _parse_net_list(cfg.get('panel_allowed_nets'))
            if not nets:
                nets = _parse_net_list(cfg.get('lan_subnet4'))
    except Exception as e:              # noqa: BLE001
        print(f'[WARN] 面板访问边界读取失败（{type(e).__name__}: {e}），本次不限制', flush=True)
        nets = []
    _NETS_CACHE.update(mtime=stamp, nets=nets)
    return nets


def _lan_bind_address(lan_if, retries=6, wait=2.0):
    """探测 lan_if 上内核**此刻实际持有**的 IPv4 地址，供 HTTPS 绑定使用。

    为什么不读配置里的 lan_ipaddr：绑定要的是内核当前有的地址。配置值可能
    是 DHCP 拿地址之前的旧值，也可能压根没有（LAN 走 DHCP）。探测不到就
    返回 ''，由调用方决定是拒绝启动还是降级 —— 本函数自己不做决定。
    """
    last = ''
    for i in range(max(1, retries)):
        try:
            res = subprocess.run(['ip', '-4', 'addr', 'show', 'dev', lan_if],
                                 capture_output=True, text=True, timeout=5)
        except Exception as e:          # noqa: BLE001
            last = f'{type(e).__name__}: {e}'
        else:
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('inet '):
                        addr = line.split()[1].split('/')[0]
                        try:
                            ipaddress.ip_address(addr)
                            return addr
                        except ValueError:
                            last = f'解析出的地址非法: {addr!r}'
            else:
                last = (res.stderr or res.stdout).strip()[:120]
        if i + 1 < max(1, retries):
            time.sleep(wait)
    print(f'[WARN] {lan_if} 上探测不到 IPv4 地址（{last or "无输出"}），已尝试 {retries} 次', flush=True)
    return ''


@app.before_request
def _require_auth():
    """全局认证拦截器
    - Content-Length 超 MAX_CONTENT_LENGTH 直接 413（在认证前，避免上传大文件撑爆内存）
    - IPv6 客户端直接拒绝（管理界面只支持 IPv4 访问）
    - 静态资源（带扩展名）直接放行
    - / 根路径放行（让登录页 HTML 能加载）
    - /api/auth/* 公开端点放行
    - 已登录请求：检查 idle 超时
    - 未登录返回 401
    """
    path = request.path
    client_ip = request.remote_addr or ''

    # Content-Length 上限检查（认证前拦截大请求体）
    max_cl = app.config.get('MAX_CONTENT_LENGTH')
    if max_cl:
        try:
            cl = int(request.headers.get('Content-Length') or 0)
            if cl > max_cl:
                return jsonify({'success': False, 'code': 'PAYLOAD_TOO_LARGE', 'message': f'请求体超过 {max_cl} 字节'}), 413
        except (ValueError, TypeError):
            pass

    # IPv6 客户端直接拒绝（管理界面只支持 IPv4）
    if ':' in client_ip:
        return jsonify({'success': False, 'code': 'IPV6_NOT_ALLOWED', 'message': '管理界面仅支持 IPv4 访问'}), 403

    # 来源访问边界：不在允许网段内的请求，连登录页都不给。
    # 放在 IPv6 判定之后 —— v6 已经在上一行拒了，白名单不必覆盖 v6，
    # 否则会把原本的 IPV6_NOT_ALLOWED 变成 IP_NOT_ALLOWED，丢掉原有的可诊断性。
    _allow_nets = _panel_allowed_networks()
    if _allow_nets and not _ip_in_nets(client_ip, _allow_nets):
        print(f'[WARN] 拒绝非白名单来源访问面板: {client_ip}', flush=True)
        return jsonify({'success': False, 'code': 'IP_NOT_ALLOWED',
                        'message': '来源地址不在面板允许的网段内'}), 403

    # 静态资源放行（前端 JS / CSS / 图片 / 字体）
    last = path.rsplit('/', 1)[-1]
    if '.' in last and last.rsplit('.', 1)[-1].lower() in _STATIC_EXTENSIONS:
        return None

    # 根路径放行（前端 SPA 入口，登录页 HTML 在此加载）
    if path == '/' or path == '':
        return None

    # 公开认证端点放行
    if path.startswith('/api/auth/'):
        return None

    # 敲门信息端点：自己内部做 LAN 校验（不放在这里放行，避免误开放到公网）
    if path == '/api/knock-info':
        return None

    # 已登录：检查 idle 超时
    if _is_authenticated():
        last_active = session.get('last_active', 0)
        if time.time() - last_active > AUTH_IDLE_TIMEOUT:
            session.clear()
            return jsonify({'success': False, 'code': 'AUTH_EXPIRED', 'message': '会话过期，请重新登录'}), 401
        # 更新 last_active（每次请求刷新）
        session['last_active'] = time.time()
        return None

    # 未登录：API 返回 401 JSON；其他也返回 401（前端拦截后跳登录）
    return jsonify({'success': False, 'code': 'AUTH_REQUIRED', 'message': '未登录'}), 401


@app.after_request
def _security_headers(resp):
    """HTTPS 响应加 HSTS + 通用安全 header"""
    # HSTS：只在 HTTPS 响应里加（让浏览器记住以后走 HTTPS）
    if request.is_secure:
        resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # 通用：禁止 MIME sniffing、限制 referrer
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    # CSP：内网单页面应用，限制脚本和样式只允许 self + unsafe-inline（兼容 Alpine.js inline event）
    #
    # ⚠️ 'unsafe-eval' 是 Alpine.js 的硬性要求，删了会让整个面板变成静态页面。
    # Alpine 不预编译 x-data / @click / x-show 这些表达式字符串，而是在运行时用
    # new Function() 现场编译。缺 'unsafe-eval' 时浏览器直接抛
    # "Refused to evaluate a string as JavaScript"，Alpine 起不来 →
    # 所有 x-show 不生效 → 模态框遮罩常驻 → 连登录按钮都点不动。
    # 2026-10-06 真实浏览器实测才暴露出来（curl 级验收查不到这一层）。
    #
    # 认证门户（backend/static/）是自己写的原生 JS，不需要 eval，那两页的 CSP
    # 仍保持 'self' 不带 unsafe-eval —— 别把这里的安全收紧误套到门户上。
    resp.headers.setdefault('Content-Security-Policy', (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    ))
    return resp

# 默认配置
DEFAULT_CONFIG = {
    # 网络接口
    "wan_if": "pppoe-wan",
    "lan_if": "br-lan",
    "router_ip4": "192.168.100.1",
    "router_ip6": "",
    # 敲门端口
    "knock1_port": 1,
    "knock2_port": 2,
    "knock3_port": 3,
    "knock4_port": 4,
    # 白名单超时时间（秒），默认 5 小时
    "whitelist_timeout": 18000,
    # 端口转发（多条规则）
    "forward_rules": [
        {
            "tcp_ports": "41820, 41825",
            "udp_ports": "21116",
            "target_ip": "192.168.4.226"
        }
    ],
    # 信任IP
    "trusted_ip4": "192.168.100.2",
    "trusted_ip6": "fd93:86bb:a142:0:e9d:92ff:fe87:fd28",
    # 日志开关
    "foreign_scan_log": False,
    "ipv6_wan_lan_log": False,
    "wan_drop_log": False,
    "lan_drop_log": False,
    "forward_log": False,
    "whitelist_access_log": True,
    # 网络段配置
    "lan_subnet4": "192.168.4.0/24",
    "lan_broadcast4": "192.168.4.255",
    "ula_prefix6": "fd93:86bb:a142::/60",
    "wan_prefix6": "240e:390:4944:b191::/64",
    # 访问模式
    "access_mode": "lan",
    # LAN 自定义放行端口（信任模式下生效，逗号分隔端口号）
    "lan_allowed_ports": "",
    # 国外IP拦截
    "china_ip_block": False,
    # DNS 局域网解析
    "dns_lan_resolver_enabled": False,
    "dns_lan_servers": ["192.168.100.218"],
    "dns_lan_log": False,
    # ── v0.8.0 新增：部署模式 + 认证网关 ──────────────────────────
    # 部署模式。openwrt = 路由器本机（fw4 被接管，默认）。
    # linux_gateway = 普通 Linux 主机，前面有主路由做端口映射。
    #   该模式下 nftables 不会 flush 全局 ruleset，只接管自己的 table，
    #   且端口敲门机制失效（NAT 后源 IP 是主路由地址），需靠认证网关兜底。
    "deploy_mode": "openwrt",
    # 认证网关总开关。默认关 —— 灰度期间不影响现有访问，出问题关掉即回滚。
    "gateway_enabled": False,
    # 公网入口端口。可自定义（含家宽常用的非 443 高位端口），不写死。
    "gateway_port": 8443,
    # 进程 B（认证 API）的本地监听端口。只绑 127.0.0.1，绝不对外。
    "auth_api_port": 8444,
    # 滑动窗口秒数：每次成功访问刷新。30 分钟 = 1800。
    "auth_session_timeout": 1800,
    # 绝对上限秒数：无论多活跃，到点强制重登。0 = 不启用。
    "auth_absolute_timeout": 0,
    # LAN 来源是否免认证。True = 认证只保护公网这一面（默认，符合「内网可信」）。
    "auth_lan_bypass": True,
    # ── v0.8.1 新增：LuCI 80/443 开关 ─────────────────────────────────
    # 80/443 属于 OpenWrt 自带的 LuCI（nginx._lan / nginx._redirect2ssl），
    # 不是本项目的反代（本项目在 8443）。个人宽带用不上 LuCI，默认关掉，
    # 需要时从面板重新打开。部署时 setup.sh 也会自动关一次。
    "luci_enabled": False,
}


def load_config():
    """加载配置，如果不存在则返回默认值

    配置损坏时**仍然返回默认值**（Web UI 不能因此不可用），但会把损坏原因记到
    _LAST_LOAD_ERROR，并在 _config_corrupted() 里暴露出来。

    为什么不能只是「返回默认值」：DEFAULT_CONFIG 里写死了别人的网段
    （trusted_ip4=192.168.100.2、lan_subnet4=192.168.4.0/24、转发到
    192.168.4.226）。一旦损坏后照常下发规则，就会拿这些值去改真实防火墙，
    而且接口回报 success: true —— 用户完全无感知。宁可拒绝下发。
    """
    global _LAST_LOAD_ERROR
    _LAST_LOAD_ERROR = None
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            _LAST_LOAD_ERROR = str(e)
            # JSON 损坏或读失败：备份损坏文件并返回默认值（避免 Web UI 不可用）
            try:
                backup_path = CONFIG_PATH + f'.corrupted.{int(time.time())}'
                shutil.copy(CONFIG_PATH, backup_path)
                os.remove(CONFIG_PATH)
                print(f"[WARNING] 配置损坏已备份: {backup_path} ({e})", flush=True)
            except Exception:
                pass
            return dict(DEFAULT_CONFIG)
        # 顺序很关键：必须**先迁移用户配置，再合并默认值**。
        # 反过来的话，DEFAULT_CONFIG 自带的 forward_rules 示例会先进来，
        # 于是 _migrate_forward_rules 里 `"forward_rules" not in config` 恒为
        # False，迁移成了永远不执行的死代码 —— 旧配置里的
        # tcp_services/dsm_ip4 被无声丢弃，用户拿到的转而是 DEFAULT 里的
        # 示例规则 41820,41825 → 192.168.4.226（别人的网段）。
        config = _migrate_forward_rules(config)
        # 合并默认值（防止新增字段丢失）
        result = dict(DEFAULT_CONFIG)
        result.update(config)
        # v0.8.0 → v0.8.1：反代规则从「独立站点 + 网关」双轨迁到网关单轨。
        # 必须在合并默认值之后做 —— 否则连默认值里的示例规则都会被迁移掉。
        result = _migrate_rp_rules(result)
        return result
    # 配置文件不存在。**绝不能用它来重建防火墙**。
    #
    # 2026-10-11 真机实测踩过：配置被移走后启动恢复拿 DEFAULT_CONFIG 重建了
    # 防火墙，生效的敲门端口变成 1/2/3/4、trusted_ip 变成 192.168.100.2、
    # 转发规则指向 192.168.4.226，而且全程报「已恢复 ruleset」——
    # 也就是说 someone at 192.168.100.2 直接成了可信管理机，免敲门进面板。
    #
    # UI 仍然要能用，所以这里照旧返回默认值；但 _config_corrupted() 会把这个
    # 情况报成异常，所有「真正改防火墙」的入口都必须先问它。
    #
    # 判据不能只看规则文件在不在：实测场景里配置和规则文件是被一起移走的，
    # 规则文件不在 -> 误判成「全新安装」-> 又落回 DEFAULT_CONFIG。
    # 所以改成「任一历史产物存在即认为配过」：
    #   规则文件 / .lastgood / .backup / 配置的 .backup
    # 全都不存在才是真正的全新安装，用默认值无害。
    if _config_lost_after_setup():
        _LAST_LOAD_ERROR = (
            f'配置文件不存在（{CONFIG_PATH}），但存在历史产物，说明配置曾存在后丢失')
        print(f'[ERROR] {_LAST_LOAD_ERROR}；'
              f'拒绝用内置默认值重建规则（默认值含示例端口与陌生网段）', flush=True)
        return dict(DEFAULT_CONFIG)
    return dict(DEFAULT_CONFIG)


def _config_lost_after_setup():
    """配置文件不在，但存在历史产物 → 配过又丢，不是全新安装。

    缺了配置就不能重建防火墙：DEFAULT_CONFIG 里写死了陌生网段
    （trusted_ip4=192.168.100.2、转发到 192.168.4.226、敲门端口 1/2/3/4）。
    宁可退到 basic lockdown，也不要把这些值下发到真实网卡上。
    """
    if os.path.exists(CONFIG_PATH):
        return False
    markers = [
        RULES_PATH,
        RULES_PATH + '.lastgood',
        RULES_PATH + '.backup',
        CONFIG_PATH + '.backup',
    ]
    return any(os.path.exists(p) for p in markers)


# 上一次 load_config() 读到的配置是否损坏。None = 正常。
# 由 load_config 写入，由 _config_corrupted() 读。
_LAST_LOAD_ERROR = None


def _config_corrupted():
    """最近一次 load_config() 是否读到了损坏的配置。

    返回 (bool, str)：True 时第二个元素是损坏原因。
    「应用规则 / 预览规则」这类会真正改防火墙的入口必须先问它 —— 用硬编码的
    DEFAULT_CONFIG 去下发 nft 规则，等于把别人的网段写进真实防火墙。
    """
    return (_LAST_LOAD_ERROR is not None, _LAST_LOAD_ERROR or '')


class ConfigCorruptedError(RuntimeError):
    """配置损坏时拒绝写盘。

    为什么必须阻断「保存」而不只是阻断「下发」：
    实测（2026-10-12）配置损坏后调 /api/gateway/config 会返回 200，
    并且把 DEFAULT_CONFIG 连同改动一起 save_config 回磁盘。落盘之后
    `_config_lost_after_setup()` 判定为「全新安装」，守卫从此永远满足 ——
    一次瞬时损坏被固化成永久配置，而接口报的是成功。

    39 个字段里 19 个会被换成出厂值：敲门前缀 10376/23224/32760/13550
    变成 1/2/3/4、反代服务整个变 null、内网管理端口白名单清空，
    还会凭空多出一条把公网 41820/41825/21116 转发到 192.168.4.226 的规则。
    """


# 配置损坏时拒绝下发规则的统一提示
_CORRUPT_REFUSAL = ('配置文件已损坏（{err}），已拒绝下发规则。'
                    '请到「功能介绍/配置」页恢复配置，或手工修复 '
                    '{path} 后重试。损坏副本已另存为 {path}.corrupted.<时间戳>。')


def _config_corrupted_response():
    """损坏配置时给前端的标准应答（None 表示配置正常）"""
    bad, err = _config_corrupted()
    if not bad:
        return None
    return jsonify({
        'success': False,
        'code': 'CONFIG_CORRUPTED',
        'message': _CORRUPT_REFUSAL.format(err=err, path=CONFIG_PATH),
    }), 500


@app.errorhandler(ConfigCorruptedError)
def _handle_config_corrupted(e):
    """save_config 在配置损坏时抛的异常统一在这里变成 500 响应。

    为什么要单独一个 handler：save_config 有 8 个调用点（保存配置、网络配置、
    名单预设增删改、名单历史清理、反代配置落盘…）。在每个调用点手写 try/except
    迟早会漏一个，而漏掉的那个就是「静默把出厂配置写回磁盘」的那条路。
    统一抛 + 统一格式化，改一处就全覆盖。
    """
    return jsonify({'success': False,
                    'code': 'CONFIG_CORRUPTED',
                    'message': str(e)}), 500


def save_config(config, _force=False):
    """保存配置到 JSON 文件

    配置损坏时直接抛 ConfigCorruptedError，不落盘。守卫必须放在**最前面**：
    函数体第一件事是 `shutil.copy(CONFIG_PATH, CONFIG_PATH + '.backup')`，
    而 load_config() 检出损坏时会把原件移走、只留 .corrupted.*。所以配置损坏
    期间一旦有人保存，.backup 里那份唯一完好的配置会被损坏文件覆盖 ——
    等于把最后的恢复材料也毁掉。

    _force=True 只给恢复路径留（当前没有调用方，restore_config 走 os.replace
    不经过这里）；留着是为了将来需要「明知损坏也要写」时有个显式出口，
    而不是让调用方去改这个函数的实现。
    """
    if not _force:
        bad, err = _config_corrupted()
        if bad:
            raise ConfigCorruptedError(_CORRUPT_REFUSAL.format(err=err, path=CONFIG_PATH))
    # 自动备份当前配置
    if os.path.exists(CONFIG_PATH):
        shutil.copy(CONFIG_PATH, CONFIG_PATH + '.backup')
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    # 原子写 + 文件锁：先写临时文件再 rename，避免并发写入导致损坏
    tmp_path = CONFIG_PATH + '.tmp'
    lock_path = CONFIG_PATH + '.lock'
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            with open(tmp_path, 'w') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, CONFIG_PATH)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
    except Exception as e:
        # fcntl 不可用或锁失败：记录日志后回退到无锁模式（保留原子写）
        print(f"[WARNING] save_config 加锁失败（{type(e).__name__}: {e}），回退到无锁模式", flush=True)
        try:
            with open(tmp_path, 'w') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            if os.path.exists(tmp_path):
                os.replace(tmp_path, CONFIG_PATH)
        except Exception as e2:
            # 真正写失败：必须抛出，不能吞错（否则用户看不到保存失败）
            print(f"[ERROR] save_config 写入失败: {type(e2).__name__}: {e2}", flush=True)
            raise


def _migrate_forward_rules(config):
    """向后兼容：旧格式 tcp_services/udp_services/dsm_ip4 自动迁移为 forward_rules"""
    if "forward_rules" not in config and ("tcp_services" in config or "dsm_ip4" in config):
        config["forward_rules"] = [{
            "tcp_ports": config.get("tcp_services", ""),
            "udp_ports": config.get("udp_services", ""),
            "target_ip": config.get("dsm_ip4", ""),
            "target_ipv6": "",
        }]
        # 迁移后清理旧字段
        for old_key in ("tcp_services", "udp_services", "dsm_ip4"):
            config.pop(old_key, None)
    # 确保 forward_rules 存在且每个规则有 target_ipv6 字段
    if "forward_rules" not in config:
        config["forward_rules"] = []
    # 配置文件被手工改坏时 forward_rules 可能是字符串或含非 dict 元素。
    # 本函数在任何校验之前就会执行，这里不兜住的话 build_rules 会直接抛
    # AttributeError，导致「预览规则 / 应用规则」两个核心接口全部不可用。
    if not isinstance(config["forward_rules"], list):
        print("[WARNING] forward_rules 类型非法，已重置为空列表", flush=True)
        config["forward_rules"] = []
    else:
        cleaned = []
        for rule in config["forward_rules"]:
            if isinstance(rule, dict):
                rule.setdefault("target_ipv6", "")
                cleaned.append(rule)
            else:
                print(f"[WARNING] forward_rules 含非对象元素，已丢弃: {type(rule).__name__}", flush=True)
        config["forward_rules"] = cleaned
    return config


def _ipv6_prefix(addr_with_plen):
    """把 `240e:abcd:ef01:2345::1/64` 这样的地址转成它真正的 /64 前缀。

    为什么不能用 `':'.join(p for p in ip.split(':') if p)[:4]`：
    那种手工切段在「第 4 组为空」时会整体左移。实测（.224）：
        输入 fd12:3456:789a::1/64
        旧算法  fd12:3456:789a:1::/64   ← 第 4 组是空的，被过滤掉了，后面全部前移
        正确    fd12:3456:789a::/64

    而 ULA 的标准写法恰恰就是 `fdXX:XXXX:XXXX::/48`（第 4 组为空），
    也就是**这个分支平时几乎总是算错**，且算错后不报错，只是生成一组
    落在别人地址空间里的 IPv6 规则。

    交给 ipaddress 处理压缩展开，不做字符串手术。格式非法返回 None。
    """
    try:
        import ipaddress
        return str(ipaddress.ip_interface(addr_with_plen).network)
    except (ValueError, TypeError):
        return None


def _auto_detect_network(config=None):
    """自动检测网络段配置。

    接口名必须来自配置，不能写死 br-lan / pppoe-wan：
    实测踩过（2026-10-15）—— 配置里 wan_if=pppoe-wan，而本机出口其实是 eth1
    （uci 压根没有 network.wan 段），于是下面这条探测永远查不到任何地址：

        ip -6 addr show dev pppoe-wan scope global

    返回的 dict 里没有 WAN_PREFIX6，`config_to_variables` 就静默回落到
    DEFAULT_CONFIG 的 `240e:390:4944:b191::/64` —— 那是别人家宽带的前缀。
    IPv6 地址段生成规则全错，而且从检测到下发一路没有任何报错。

    同理 lan_if 写死 br-lan：linux_gateway 部署模式下 LAN 侧根本不是 br-lan，
    ULA 前缀探测同样恒空。

    config 传 None 时不读盘（调用方手里通常已经有 config），直接用默认接口名。
    """
    result = {}
    cfg = config if isinstance(config, dict) else {}
    lan_if = _safe_iface(cfg.get('lan_if'), 'br-lan')
    wan_if = _safe_iface(cfg.get('wan_if'), 'pppoe-wan')
    try:
        uci = parse_uci_config('/etc/config/network')
        ipaddr = uci.get('lan_ipaddr', '')
        netmask = uci.get('lan_netmask', '')
        if ipaddr and netmask:
            import ipaddress
            net = ipaddress.ip_network(f"{ipaddr}/{netmask}", strict=False)
            result['LAN_SUBNET4'] = str(net)
            result['LAN_BROADCAST4'] = str(net.broadcast_address)
        res = subprocess.run(['ip', '-6', 'addr', 'show', 'dev', lan_if], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            if 'inet6' in line and 'fd' in line:
                addr = line.strip().split()[1]
                _pfx = _ipv6_prefix(addr)
                if _pfx:
                    result['ULA_PREFIX6'] = _pfx
                    break
        res = subprocess.run(['ip', '-6', 'addr', 'show', 'dev', wan_if, 'scope', 'global'], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            if 'inet6' in line:
                addr = line.strip().split()[1]
                _pfx = _ipv6_prefix(addr)
                if _pfx:
                    result['WAN_PREFIX6'] = _pfx
                    break
    except FileNotFoundError:
        # /etc/config/network 不存在 = 不是 OpenWrt（linux_gateway 部署模式），
        # 属正常情况，不该刷警告。
        pass
    except Exception as e:
        # 探测失败必须留痕：这条路径曾经因为接口名写死而恒空，
        # WAN_PREFIX6 于是静默回落到 DEFAULT_CONFIG 里别人家宽带的前缀，
        # IPv6 地址段生成规则全错且一路无报错。
        print(f'[WARN] 自动检测网络段失败（接口名取自配置 '
              f'lan_if={lan_if} wan_if={wan_if}）: {type(e).__name__}: {e}',
              flush=True)
    return result

# ======================= 配置校验 =======================
# 所有会拼进 nft 规则模板的字段都必须先过白名单校验，否则可以注入任意 nft 指令。
# 典型：whitelist_timeout 传 "1s; delete table inet fw4; #" 会被原样拼进规则，
# 且 delete table 是合法 nft 语法，nft -c 语法预检也拦不住。
_RE_IFACE = re.compile(r'^[A-Za-z0-9_.-]{1,32}$')


def _is_port(v):
    # 用字符串判定而不是 isinstance(v, int)：bool 是 int 的子类，
    # isinstance(True, int) 为真且 True == 1，会让 JSON 里的 true
    # 混过端口范围检查；float 同理（443.5 的 str 也不是 digit）。
    # str().isdigit() 两种情况都会挡住。
    s = str(v).strip()
    if not s.isdigit() or len(s) > 5:
        return False
    n = int(s)
    return 1 <= n <= 65535


def _valid_ip(v, version=None):
    """合法 IPv4/IPv6 返回 True（version=4/6 时强制指定版本）"""
    try:
        addr = ipaddress.ip_address(str(v).strip())
    except ValueError:
        return False
    if version == 4:
        return addr.version == 4
    if version == 6:
        return addr.version == 6
    return True


def _bad_forward_target(ip, ip6, cfg):
    """端口转发目标地址的语义校验。返回错误说明字符串；没问题返回 ''。

    「格式合法」不等于「能用」。下面几类地址语法上都是合法 IP，但转发过去
    要么打不通、要么把流量送进一个不该暴露的服务：

      127.0.0.0/8     路由器自身回环 —— 外部来的包 DNAT 到回环后没有对应
                      的监听，等于黑洞；部分内核下会形成重定向环路
      169.254.0.0/16  链路本地 —— 云主机的元数据地址就在这里
                      （169.254.169.254）。把它设成转发目标，等于把云厂商
                      的凭据接口经由本机 NAT 暴露到公网
      0.0.0.0 / ::   未指定
      广播地址        局域网广播，发过去只会打扰全网
      路由器自身地址  DNAT 回自己 → 重定向环路

    注意 IPv4-mapped 的 ::ffff:127.0.0.1 也要一并挡住。
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return '不是合法 IP'

    if addr.is_loopback:
        return '指向路由器自身回环，转发过去打不通'
    if addr.is_link_local:
        return ('指向链路本地地址（含 169.254.169.254 云元数据地址），'
                '把它设成转发目标会把该接口经 NAT 暴露到公网')
    if addr.is_unspecified:
        return '未指定地址'
    if addr.version == 4:
        if addr == ipaddress.ip_address('255.255.255.255'):
            return '广播地址不能作为转发目标'
        lan4 = str((cfg or {}).get('lan_subnet4', '') or '').strip()
        bcast4 = str((cfg or {}).get('lan_broadcast4', '') or '').strip()
        if bcast4:
            try:
                if addr == ipaddress.ip_address(bcast4):
                    return '广播地址不能作为转发目标'
            except ValueError:
                pass
        if lan4:
            try:
                if addr in ipaddress.ip_network(lan4, strict=False):
                    pass  # 同网段地址是正常转发目标
            except ValueError:
                pass
    if addr.version == 6 and addr.ipv4_mapped is not None:
        return _bad_forward_target(str(addr.ipv4_mapped), ip6, cfg)

    # 转发目标指向路由器自己 → DNAT 回自身，形成重定向环路
    for key in ('router_ip4', 'router_ip6'):
        r = str((cfg or {}).get(key, '') or '').strip()
        if r and r == str(addr):
            return '指向路由器自身地址，转发会造成重定向环路'
    return ''


def _split_ports(v):
    """把逗号/中文逗号/空格分隔的端口串归一化为 int 列表；非法则抛 ValueError"""
    raw = v if isinstance(v, list) else str(v or '').replace('，', ',').split(',')
    out = []
    for item in raw:
        s = str(item).strip()
        if not s:
            continue
        if not _is_port(s):
            raise ValueError(f'端口非法: {s!r}（只允许 1-65535 的数字）')
        out.append(int(s))
    return out


def _rp_forward_conflicts(cfg):
    """端口转发指向「已启用的反代服务」时返回错误列表，否则空。

    为什么必须抽成独立函数
    --------------------
    这条检查以前只写在 validate_config 里，而 validate_config 只有
    /api/config 会调。反代的 POST/PUT/DELETE 走的是另一条路，压根不经过
    validate_config —— 于是「先建端口转发、再建指向同一后端的反代」这个
    顺序就绕过了检查，形成一条免登录的公网入口：端口转发走 nftables DNAT，
    不经过 nginx 的认证层。

    抽出来之后，validate_config 和反代 CRUD 共用同一份判断。两份逻辑迟早
    分叉 —— 反代的 PUT 那次就是这么漏的。

    参数是**完整的候选配置**（含将要落盘的那条规则），返回的是给用户看的
    错误文案列表。
    """
    rp_targets = set()
    rp = cfg.get('reverse_proxy')
    if isinstance(rp, dict) and isinstance(rp.get('rules'), list):
        for r in rp['rules']:
            if not isinstance(r, dict) or not r.get('enabled'):
                continue
            host, _, port = str(r.get('target_address', '')).rpartition(':')
            if host and _is_port(port):
                rp_targets.add((host.strip(), int(port)))

    errs = []
    if rp_targets and isinstance(cfg.get('forward_rules'), list):
        for i, r in enumerate(cfg.get('forward_rules') or [], 1):
            if not isinstance(r, dict):
                continue
            tgt = str(r.get('target_ip', '') or '').strip()
            if not tgt:
                continue
            try:
                exposed = {(tgt, p) for key in ('tcp_ports', 'udp_ports')
                           for p in _safe_ports(r.get(key, ''))}
            except Exception:
                continue
            for host, port in sorted(exposed & rp_targets):
                errs.append(
                    f'forward_rules[{i}]（端口 {port} → {tgt}）会绕过认证：'
                    f'{tgt}:{port} 已有已启用的反代规则承载该服务，'
                    f'端口转发走 nftables DNAT、不经过 nginx 的认证层，'
                    f'会形成一条免登录的公网入口。建议删掉这条转发，'
                    f'改用反代访问该服务。'
                )

    # luci_enabled：布尔。必须显式挡掉非布尔值 —— 它直接决定要不要动
    # /etc/config/nginx，收到 "false" 这种字符串时 Python 会当真值处理，
    # 结果是用户明明选了关闭却被打开。
    if 'luci_enabled' in cfg:
        lv = cfg.get('luci_enabled')
        if not isinstance(lv, bool):
            errs.append(f'luci_enabled 必须是布尔 true/false，实际收到 '
                        f'{type(lv).__name__}: {lv!r}')

    return errs


def validate_config(cfg):
    """校验配置中所有会进入 nft 规则的字段，返回错误列表（空列表 = 通过）"""
    errs = []

    for key in ('wan_if', 'lan_if'):
        v = str(cfg.get(key, '') or '')
        if v and not _RE_IFACE.match(v):
            errs.append(f'{key} 接口名非法: {v!r}（只允许字母数字及 _ . -，最长 32）')

    for key, ver, optional in (('router_ip4', 4, False), ('trusted_ip4', 4, False),
                               ('router_ip6', 6, True), ('trusted_ip6', 6, True)):
        raw = cfg.get(key)        # trusted_ip4/trusted_ip6 历史上有字符串和数组两种写法（setup.sh 写的是数组），
        # 这里必须都接受，否则老装机升级后每次保存配置都会被判 400
        if isinstance(raw, (list, tuple, set)):
            items = [str(x).strip() for x in raw if str(x).strip()]
            if not items and not optional:
                errs.append(f'{key} 不能为空')
            for it in items:
                if not _valid_ip(it, ver):
                    errs.append(f'{key} IPv{ver} 地址非法: {it!r}')
            continue
        v = str(raw or '').strip()
        if not v:
            if not optional:
                errs.append(f'{key} 不能为空')
            continue
        if not _valid_ip(v, ver):
            errs.append(f'{key} IPv{ver} 地址非法: {v!r}')

    # 面板来源访问边界。这里**必须**用 ip_network 而不是 _valid_ip：
    # _valid_ip 走 ipaddress.ip_address()，不接受 CIDR，而访问边界要写的
    # 就是网段（192.168.100.0/24）。另外 /0 与 /1 这类超大网段要挡掉 ——
    # 它等价于「不设边界」，写在这里会让配置看起来有防护、实际没有。
    if 'panel_allowed_nets' in cfg:
        _pv = cfg.get('panel_allowed_nets')
        _pitems = ([str(x).strip() for x in _pv] if isinstance(_pv, (list, tuple, set))
                   else [p.strip() for p in str(_pv or '').replace('，', ',').split(',')])
        _pitems = [x for x in _pitems if x]
        if not _pitems and _pv not in (None, [], '', ()):
            errs.append('panel_allowed_nets 解析后为空（分隔符写错了？）')
        for it in _pitems:
            try:
                _n = ipaddress.ip_network(it, strict=False)
            except ValueError:
                errs.append(f'panel_allowed_nets 非法: {it!r}（应为 CIDR 如 192.168.100.0/24，或单个 IP）')
                continue
            if _n.prefixlen <= 1:
                errs.append(f'panel_allowed_nets 网段过大: {it!r}（/{_n.prefixlen} 等于不设边界，'
                            f'至少要 /2；本机 LAN 通常是 /24）')

    for key in ('knock1_port', 'knock2_port', 'knock3_port', 'knock4_port'):
        if key in cfg and not _is_port(cfg[key]):
            errs.append(f'{key} 端口非法: {cfg[key]!r}（只允许 1-65535）')

    # 网段必须是具体网段，不能是 /0。
    #
    # 2026-10-07：Shannon 报 critical + 实测确认 —— 之前 _safe_cidr 只校验
    # 「是不是合法 CIDR」，0.0.0.0/0 与 ::/0 都合法，于是：
    #     POST /api/config {"lan_subnet4":"0.0.0.0/0"} → {"success":true,"risks":[]}
    #     → 8.8.8.8 / 1.1.1.1 等公网 IP 全部 /auth/verify → 200 + lan-bypass
    # 也就是说填错一个网段就让整个公网网关对全互联网免认证，保存时连风险
    # 提示都没有。认证服务侧现在也会忽略 /0（纵深防御），但配置入口不该
    # 放行它 —— 早失败、强提示，别把「全员免认证」交给一次手滑。
    for key in ('lan_subnet4', 'lan_subnet6'):
        raw = str(cfg.get(key, '') or '').strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            errs.append(f'{key} 网段非法: {raw!r}')
            continue
        if net.prefixlen == 0:
            errs.append(
                f'{key} 不能是 {raw}：它匹配所有地址，保存后公网任何来源都会被'
                f'当成内网而免认证。请填具体网段，如 192.168.100.0/24')

    try:
        _split_ports(cfg.get('lan_allowed_ports', ''))
    except ValueError as e:
        errs.append(f'lan_allowed_ports {e}')

    wt = cfg.get('whitelist_timeout')
    if wt is not None and str(wt).strip() != '' and not str(wt).strip().isdigit():
        errs.append(f'whitelist_timeout 非法: {wt!r}（只允许非负整数秒）')

    for s in (cfg.get('dns_lan_servers') or []):
        if not _valid_ip(s):
            errs.append(f'dns_lan_servers 含非法 IP: {s!r}')

    rules = cfg.get('forward_rules')
    if rules is not None and not isinstance(rules, list):
        errs.append('forward_rules 必须是数组')
    elif isinstance(rules, list):
        for i, r in enumerate(rules, 1):
            if not isinstance(r, dict):
                errs.append(f'forward_rules[{i}] 必须是对象')
                continue
            tgt = str(r.get('target_ip', '') or '').strip()
            if not _valid_ip(tgt):
                errs.append(f'forward_rules[{i}].target_ip 非法: {tgt!r}')
            else:
                why = _bad_forward_target(tgt, r.get('target_ipv6', ''), cfg)
                if why:
                    errs.append(f'forward_rules[{i}].target_ip 不可用: {tgt!r} — {why}')
            tgt6 = str(r.get('target_ipv6', '') or '').strip()
            if tgt6 and not _valid_ip(tgt6, 6):
                errs.append(f'forward_rules[{i}].target_ipv6 非法: {tgt6!r}')
            elif tgt6:
                why = _bad_forward_target(tgt6, tgt6, cfg)
                if why:
                    errs.append(f'forward_rules[{i}].target_ipv6 不可用: {tgt6!r} — {why}')
            for pk in ('tcp_ports', 'udp_ports'):
                if pk in r:
                    try:
                        _split_ports(r[pk])
                    except ValueError as e:
                        errs.append(f'forward_rules[{i}].{pk} {e}')

    rp = cfg.get('reverse_proxy')
    if rp is not None and not isinstance(rp, dict):
        errs.append('reverse_proxy 必须是对象')
    elif isinstance(rp, dict):
        rrs = rp.get('rules')
        if rrs is not None and not isinstance(rrs, list):
            errs.append('reverse_proxy.rules 必须是数组')
        elif isinstance(rrs, list):
            for i, r in enumerate(rrs, 1):
                if not isinstance(r, dict):
                    errs.append(f'reverse_proxy.rules[{i}] 必须是对象')
                    continue
                lp = str(r.get('listen_port', '') or '').strip()
                if lp and not _is_port(lp):
                    errs.append(f'reverse_proxy.rules[{i}].listen_port 非法: {lp!r}')

    # ------------------------------------------------------------------
    # 交叉检查：端口转发是否暴露了「已由反代承载认证」的服务
    #
    # 端口转发走 nftables DNAT（见 build_rules 里的 `dnat to {target_ip}`），
    # 是纯网络层的哑管道，不经过 nginx、不参与 auth_request。
    # 而 DNAT 不改写端口，所以公网端口 P 会落到 (target_ip, P)。
    # 若这个组合正好是某条已启用反代规则的后端地址，那条认证路径就被旁路了：
    # 敲门成功的 IP 可以直接访问该端口，完全不需要登录。
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # 端口转发与反代服务的交叉校验。实现见 _rp_forward_conflicts ——
    # 反代 CRUD 也要用它，所以不能在这里内联一份。
    # ------------------------------------------------------------------
    errs.extend(_rp_forward_conflicts(cfg))

    # ------------------------------------------------------------------
    # v0.8.0：部署模式 + 认证网关配置校验
    # ------------------------------------------------------------------
    mode = str(cfg.get('deploy_mode', 'openwrt') or 'openwrt').strip()
    if mode not in ('openwrt', 'linux_gateway'):
        errs.append(
            f"deploy_mode 非法: {mode!r}（合法值 openwrt | linux_gateway）"
        )

    if cfg.get('gateway_enabled'):
        gw_port = cfg.get('gateway_port', 8443)
        api_port = cfg.get('auth_api_port', 8444)

        if not _is_port(gw_port):
            errs.append(f"gateway_port 非法: {gw_port!r}（需为 1-65535 的整数）")
        if not _is_port(api_port):
            errs.append(f"auth_api_port 非法: {api_port!r}（需为 1-65535 的整数）")

        if _is_port(gw_port) and _is_port(api_port) and int(gw_port) == int(api_port):
            errs.append(
                f"gateway_port 与 auth_api_port 冲突：都是 {gw_port}。"
                f"网关端口是公网入口，认证 API 只监听 127.0.0.1，两者必须不同。"
            )
        if _is_port(gw_port) and int(gw_port) == int(HTTPS_PORT):
            errs.append(
                f"gateway_port 不能是 {HTTPS_PORT} —— 那是面板自己的 HTTPS 端口。"
                f"启用网关后面板仍需在 LAN 上可达，两者端口不能相同。"
            )

        for key, lo, hi in (('auth_session_timeout', 60, 86400),
                            ('auth_absolute_timeout', 0, 604800)):
            v = cfg.get(key, 0)
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                errs.append(f'{key} 必须是数字，当前为 {v!r}')
            elif not (lo <= v <= hi):
                errs.append(f'{key} 越界：{v}（合法范围 {lo}-{hi}）')

        abs_to = cfg.get('auth_absolute_timeout', 0)
        sl_to = cfg.get('auth_session_timeout', 1800)
        if (isinstance(abs_to, (int, float)) and isinstance(sl_to, (int, float))
                and 0 < abs_to < sl_to):
            errs.append(
                f"auth_absolute_timeout({abs_to}) 小于 auth_session_timeout({sl_to})，"
                f"绝对上限永远不会生效。请调大前者或调小后者。"
            )

    # ------------------------------------------------------------------
    # v0.8.0：单端口网关的 path 前缀
    #
    # 认证网关把所有服务收敛到一个端口，靠 URL 路径前缀区分，
    # 所以前缀必须唯一、合法、且不与网关自身的内部端点冲突。
    # ------------------------------------------------------------------
    seen_prefixes: dict = {}
    rp_cfg_v = cfg.get('reverse_proxy')
    if isinstance(rp_cfg_v, dict) and isinstance(rp_cfg_v.get('rules'), list):
        for i, r in enumerate(rp_cfg_v['rules'], 1):
            if not isinstance(r, dict):
                continue
            raw_prefix = r.get('path_prefix', '')
            if raw_prefix in (None, ''):
                continue
            norm = _safe_path_prefix(raw_prefix)
            if norm is None:
                errs.append(
                    f'reverse_proxy.rules[{i}].path_prefix 非法: {raw_prefix!r}'
                    f'（需形如 /nas，只允许字母数字和 - _ /，且不能含 ..）'
                )
                continue
            if not r.get('enabled'):
                continue
            if norm in _RESERVED_GATEWAY_PREFIXES:
                errs.append(
                    f'reverse_proxy.rules[{i}].path_prefix {norm!r} 与网关内部端点冲突，'
                    f'请换一个（保留前缀: {", ".join(sorted(_RESERVED_GATEWAY_PREFIXES))}）'
                )
                continue
            if norm in seen_prefixes:
                errs.append(
                    f'reverse_proxy.rules[{i}].path_prefix {norm!r} 与规则 '
                    f'{seen_prefixes[norm]} 重复。网关靠路径区分服务，前缀必须唯一。'
                )
                continue
            seen_prefixes[norm] = i

    return errs


def _safe_ports(v):
    """config_to_variables 用：非法端口直接丢弃，保证生成的规则里只可能出现合法端口号"""
    try:
        return _split_ports(v)
    except ValueError:
        return []


def _safe_port(v, default):
    """单个端口强制转型，非法回落默认值"""
    return int(v) if _is_port(v) else default


def _safe_iface(v, default):
    """接口名强制白名单，非法回落默认值（防 nft 语法注入）"""
    s = str(v or '').strip()
    return s if _RE_IFACE.match(s) else default


def _safe_ip(v, version=None, default="", strict=False):
    """config_to_variables 用：非法 IP 回落到默认值，保证生成的规则里不出现裸字符串。

    接受字符串和数组两种写法（setup.sh 写的是数组）；数组取第一个合法项。

    strict=True（默认 False）时**绝不**回落到 default，非法就返回空串，让这条
    规则干脆不生成。

    为什么要这个开关：default 里写的是硬编码网段上的地址，例如
    TRUSTED_IP4 回落成 192.168.4.229 而模板给信任 IP 放行全部端口全部协议。
    用户把信任 IP 填错或清空，结果不是「少一条白名单」，而是「凭空多出一条
    全端口授权」—— 属于意外授权，且用户完全无感知。授权类字段必须 fail-closed。
    而 ROUTER_IP4 这类路由字段的 default 是「首次部署的合理值」，不是授权，
    保留回落是对的，所以用 strict 区分而不是一刀切。
    """
    fallback = "" if strict else default
    if isinstance(v, (list, tuple, set)):
        for item in v:
            s = str(item).strip()
            if s and _valid_ip(s, version):
                return s
        # 数组里一个合法项都没有：同样不能静默回落成别人的 IP
        return fallback
    s = str(v or '').strip()
    return s if (s and _valid_ip(s, version)) else fallback


def _safe_cidr(v, default=""):
    """网段白名单校验。非法回落 default。

    必须单独一个函数：_safe_ip 只认单个 IP，喂进来 '192.168.100.0/24'
    会被判非法并静默回落 —— 那正好把「仅内网可达」的放行范围悄悄放大。
    """
    s = str(v or '').strip()
    if not s:
        return default
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except (ValueError, TypeError):
        return default


# 网关内部端点占用的路径前缀，服务前缀不得与之冲突
_RESERVED_GATEWAY_PREFIXES = frozenset({"/_auth", "/auth"})

_RE_PATH_PREFIX = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9_\-/]*$")


def _safe_path_prefix(v):
    """把 path 前缀规整成规范形式；非法返回 None。

    规则：必须以 / 开头、以 / 结尾或以字母数字结尾；只允许字母数字与 - _ /；
    拒绝 .. 与连续 //（防路径穿越与 nginx location 前缀歧义）。
    末尾斜杠统一去掉（nginx location 匹配时 /nas 与 /nas/ 等价）。
    """
    s = str(v or '').strip()
    if not s:
        return None
    if '..' in s or '//' in s:
        return None
    if not _RE_PATH_PREFIX.match(s):
        return None
    s = s.rstrip('/')
    if not s or s == '/':
        return None
    return s


def config_to_variables(config):
    """将 web 配置转换为模板变量"""
    config = _migrate_forward_rules(config)
    forward_rules = config.get("forward_rules", [])

    # 合并所有规则的端口（用于 WAN 链白名单放行）
    # 全部经过 _safe_ports / _is_port 过滤：非法端口直接丢弃，
    # 保证生成的 nft 规则里只可能出现合法端口号，堵死规则注入
    all_tcp = set()
    all_udp = set()
    for rule in forward_rules:
        if not isinstance(rule, dict):
            continue
        for p in _safe_ports(rule.get("tcp_ports", "")):
            all_tcp.add(p)
        for p in _safe_ports(rule.get("udp_ports", "")):
            all_udp.add(p)

    # 反代公网端口
    # reverse_proxy 被手工改坏时可能是字符串/列表，这里兜住避免 build_rules 崩掉
    rp_cfg = config.get("reverse_proxy")
    if not isinstance(rp_cfg, dict):
        rp_cfg = {}
    rp_rules = rp_cfg.get("rules")
    if not isinstance(rp_rules, list):
        rp_rules = []
    if config.get("gateway_enabled"):
        # 单端口网关模式：所有 public 服务共用 gateway_port 走认证，
        # 所以 WAN 白名单只需要放行这一个端口 —— 公网暴露面从「N 个反代端口」
        # 收敛成 1 个。只有确实存在「已启用 + public_access + 配了 path 前缀」
        # 的服务时才放行，免得开着一个没人用的公网端口。
        if any(r.get("public_access") for r, _p, _pr, _h, _tp in _gateway_services(config)):
            all_tcp.add(_safe_port(config.get("gateway_port"), 8443))
    else:
        for rule in rp_rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("enabled") and rule.get("public_access"):
                port = str(rule.get("listen_port", ""))
                if _is_port(port):
                    all_tcp.add(int(port))

    # 生成端口集合定义（直接带 elements；集合里是 int，join 前统一转 str）
    tcp_elems = ", ".join(str(p) for p in sorted(all_tcp)) if all_tcp else ""
    udp_elems = ", ".join(str(p) for p in sorted(all_udp)) if all_udp else ""
    port_sets_block = "    set tcp_services {\n        type inet_service;\n        flags interval;\n"
    if tcp_elems:
        port_sets_block += f"        elements = {{ {tcp_elems} }}\n"
    port_sets_block += "    }\n    set udp_services {\n        type inet_service;\n        flags interval;\n"
    if udp_elems:
        port_sets_block += f"        elements = {{ {udp_elems} }}\n"
    port_sets_block += "    }"

    # 自动检测网络段（接口名取自本份 config，不写死 br-lan / pppoe-wan）
    detected = _auto_detect_network(config)

    variables = {
        "WAN_IF": f'"{_safe_iface(config.get("wan_if"), "pppoe-wan")}"',
        "LAN_IF": f'"{_safe_iface(config.get("lan_if"), "br-lan")}"',
        "ROUTER_IP4": _safe_ip(config.get("router_ip4", ""), 4, "192.168.4.1"),
        "ROUTER_IP6": _safe_ip(config.get("router_ip6", ""), 6, ""),
        "LAN_SUBNET4": detected.get("LAN_SUBNET4", "192.168.4.0/24"),
        "LAN_BROADCAST4": detected.get("LAN_BROADCAST4", "192.168.4.255"),
        "ULA_PREFIX6": detected.get("ULA_PREFIX6", "fd93:86bb:a142::/60"),
        "WAN_PREFIX6": detected.get("WAN_PREFIX6", "240e:390:4944:b191::/64"),
        "KNOCK1_PORT": str(_safe_port(config.get("knock1_port", 1), 1)),
        "KNOCK2_PORT": str(_safe_port(config.get("knock2_port", 2), 2)),
        "KNOCK3_PORT": str(_safe_port(config.get("knock3_port", 3), 3)),
        "KNOCK4_PORT": str(_safe_port(config.get("knock4_port", 4), 4)),
        "PORT_SETS_BLOCK": port_sets_block,
        "TRUSTED_IP4": _safe_ip(config.get("trusted_ip4", ""), 4, "192.168.4.229", strict=True),
        "TRUSTED_IP6": _safe_ip(config.get("trusted_ip6", ""), 6, "fd93:86bb:a142:0:e9d:92ff:fe87:fd28", strict=True),
        "ACCESS_MODE": config.get("access_mode") if config.get("access_mode") in ("lan", "trusted") else "trusted",
        "CHINA_IP_BLOCK": "true" if config.get("china_ip_block", True) else "false",
        # 决定 forward 链要不要放行普通 LAN→WAN：本机做 DNS 递归解析时只允许
        # 内网访问路由器自己的 DNS（见 template_engine 的 __LAN_WAN_GENERAL__）。
        "DNS_LAN_RESOLVER_ENABLED": ("true" if config.get("dns_lan_resolver_enabled", False)
                                     else "false"),
        # 决定 ruleset 前导块：openwrt 接管整机 / linux_gateway 只重建自有表。
        # 非法值一律按 openwrt 处理 —— 宁可行为等同现状，也不要意外不清表。
        "DEPLOY_MODE": (config.get("deploy_mode")
                        if config.get("deploy_mode") == "linux_gateway"
                        else "openwrt"),
    }

    # LAN 自定义放行端口规则
    lan_ports = _safe_ports(config.get("lan_allowed_ports", ""))
    if lan_ports:
        variables["LAN_ALLOWED_RULES"] = ("        iifname $LAN_IF tcp dport { "
                                          + ", ".join(str(p) for p in lan_ports) + " } accept")
    else:
        variables["LAN_ALLOWED_RULES"] = ""

    # 为每条规则生成转发块
    forward_block = []
    nat_block = []
    forward_log = config.get("forward_log", False)
    for i, rule in enumerate(forward_rules, 1):
        if not isinstance(rule, dict):
            continue
        # target_ip 直接进 ip daddr / dnat to，也进注释行，非法一律回落丢弃整条规则
        target_ip = _safe_ip(rule.get("target_ip", ""), 4, "")
        tcp_ports = _safe_ports(rule.get("tcp_ports", ""))
        udp_ports = _safe_ports(rule.get("udp_ports", ""))
        if not target_ip or not (tcp_ports or udp_ports):
            continue

        tcp_set_str = "{ " + ", ".join(str(p) for p in tcp_ports) + " }" if tcp_ports else ""
        udp_set_str = "{ " + ", ".join(str(p) for p in udp_ports) + " }" if udp_ports else ""

        # 转发链规则
        fwd_lines = [f"# 端口转发规则 {i}: -> {target_ip}"]
        if tcp_ports:
            tcp_log_part = f'log prefix "[I4-ALVN-T-{i}] " ' if forward_log else ''
            fwd_lines.append(
                f"        iifname $WAN_IF meta nfproto ipv4 oifname $LAN_IF \\\n"
                f"            ip saddr @allowed4 ip daddr {target_ip} tcp dport {tcp_set_str} \\\n"
                f"            {tcp_log_part}accept"
            )
        if udp_ports:
            udp_log_part = f'log prefix "[I4-ALVN-U-{i}] " ' if forward_log else ''
            fwd_lines.append(
                f"        iifname $WAN_IF meta nfproto ipv4 oifname $LAN_IF \\\n"
                f"            ip saddr @allowed4 ip daddr {target_ip} udp dport {udp_set_str} \\\n"
                f"            {udp_log_part}accept"
            )
        forward_block.append("\n".join(fwd_lines))

        # NAT 规则
        nat_lines = [f"# NAT 规则 {i}: -> {target_ip}"]
        if tcp_ports:
            nat_lines.append(f"        iifname $WAN_IF tcp dport {tcp_set_str} dnat to {target_ip}")
        if udp_ports:
            nat_lines.append(f"        iifname $WAN_IF udp dport {udp_set_str} dnat to {target_ip}")
        nat_block.append("\n".join(nat_lines))

    variables["FORWARD_RULES_BLOCK"] = "\n\n".join(forward_block)
    variables["NAT_RULES_BLOCK"] = "\n\n".join(nat_block)

    # IPv6 集合定义（每个规则一个独立集合）
    ipv6_sets = []
    for i, rule in enumerate(forward_rules, 1):
        ipv6_sets.append(f"    set nas_ip6_{i} {{\n        type ipv6_addr;\n        flags dynamic;\n    }}")
    variables["IPV6_SETS_BLOCK"] = "\n".join(ipv6_sets)

    # IPv6 转发规则（每个规则独立，指向对应的 @nas_ip6_{i}）
    ipv6_fwd_block = []
    for i, rule in enumerate(forward_rules, 1):
        if not isinstance(rule, dict):
            continue
        tcp_ports = _safe_ports(rule.get("tcp_ports", ""))
        udp_ports = _safe_ports(rule.get("udp_ports", ""))
        if not (tcp_ports or udp_ports):
            continue
        tcp_set_str = "{ " + ", ".join(str(p) for p in tcp_ports) + " }" if tcp_ports else ""
        udp_set_str = "{ " + ", ".join(str(p) for p in udp_ports) + " }" if udp_ports else ""
        log_part = 'log prefix "[I6-ALVN-T-' + str(i) + '] " ' if forward_log else ''

        lines = [f"# IPv6 转发规则 {i}"]
        if tcp_ports:
            lines.append(
                f"        iifname $WAN_IF meta nfproto ipv6 oifname $LAN_IF \\\n"
                f"            ip6 saddr @allowed6 ip6 daddr @nas_ip6_{i} \\\n"
                f"            tcp dport {tcp_set_str} \\\n"
                f"            {log_part}accept"
            )
        if udp_ports:
            log_part_udp = 'log prefix "[I6-ALVN-U-' + str(i) + '] " ' if forward_log else ''
            lines.append(
                f"        iifname $WAN_IF meta nfproto ipv6 oifname $LAN_IF \\\n"
                f"            ip6 saddr @allowed6 ip6 daddr @nas_ip6_{i} \\\n"
                f"            udp dport {udp_set_str} \\\n"
                f"            {log_part_udp}accept"
            )
        ipv6_fwd_block.append("\n".join(lines))
    variables["IPV6_FWD_RULES_BLOCK"] = "\n\n".join(ipv6_fwd_block)

    # IPv6 拒绝规则（每个规则独立）
    ipv6_den_block = []
    for i, rule in enumerate(forward_rules, 1):
        if not isinstance(rule, dict):
            continue
        tcp_ports = _safe_ports(rule.get("tcp_ports", ""))
        udp_ports = _safe_ports(rule.get("udp_ports", ""))
        if not (tcp_ports or udp_ports):
            continue
        tcp_set_str = "{ " + ", ".join(str(p) for p in tcp_ports) + " }" if tcp_ports else ""
        udp_set_str = "{ " + ", ".join(str(p) for p in udp_ports) + " }" if udp_ports else ""
        log_part = 'log prefix "[I6-DEN-T-' + str(i) + '] " ' if forward_log else ''

        lines = []
        if tcp_ports:
            lines.append(f"        iifname $WAN_IF meta nfproto ipv6 oifname $LAN_IF \\\n            ip6 daddr @nas_ip6_{i} tcp dport {tcp_set_str} \\\n            {log_part}drop")
        if udp_ports:
            log_part_udp = 'log prefix "[I6-DEN-U-' + str(i) + '] " ' if forward_log else ''
            lines.append(f"        iifname $WAN_IF meta nfproto ipv6 oifname $LAN_IF \\\n            ip6 daddr @nas_ip6_{i} udp dport {udp_set_str} \\\n            {log_part_udp}drop")
        if lines:
            lines.insert(0, f"# IPv6 拒绝规则 {i}")
            ipv6_den_block.append("\n".join(lines))
    variables["IPV6_DEN_RULES_BLOCK"] = "\n\n".join(ipv6_den_block)

    # IPv6 LAN→WAN DNS 转发规则（仅在 ROUTER_IP6 有值时生成，否则 nft 会因 set 包含空字符串报错）
    router_ip6 = (config.get("router_ip6") or "").strip()
    if router_ip6:
        variables["IPV6_LAN_WAN_DNS_BLOCK"] = (
            f"        iifname $LAN_IF oifname $WAN_IF meta nfproto ipv6 udp dport 53 ip6 daddr {{ {router_ip6}, 2400:3200::1, 2400:3200:baba::1 }} accept\n"
            f"        iifname $LAN_IF oifname $WAN_IF meta nfproto ipv6 tcp dport 53 ip6 daddr {{ {router_ip6}, 2400:3200::1, 2400:3200:baba::1 }} accept"
        )
    else:
        variables["IPV6_LAN_WAN_DNS_BLOCK"] = ""

    # DNS 局域网解析规则（允许 LAN 客户端通过路由器查询内网 DNS 服务器）
    if config.get("dns_lan_resolver_enabled", False):
        dns_lan_servers = config.get("dns_lan_servers") or []
        if isinstance(dns_lan_servers, str):
            dns_lan_servers = [s.strip() for s in dns_lan_servers.split(",") if s.strip()]
        log_part = 'log prefix "[DNS-LAN] " ' if config.get("dns_lan_log", False) else ''

        rules = []
        for srv in dns_lan_servers:
            # srv 直接进 ip daddr 和 comment 字符串，非法 IP 必须丢弃
            if not _valid_ip(srv, 4):
                continue
            rules.append(
                f"        iifname $LAN_IF oifname $LAN_IF ip daddr {srv} udp dport 53 \\\n"
                f"            {log_part}accept comment \"DNS-LAN-to-{srv}\""
            )
            rules.append(
                f"        iifname $LAN_IF oifname $LAN_IF ip daddr {srv} tcp dport 53 \\\n"
                f"            {log_part}accept comment \"DNS-LAN-to-{srv}\""
            )
        variables["DNS_LAN_BLOCK"] = "\n\n".join(rules)
    else:
        variables["DNS_LAN_BLOCK"] = ""

    return variables


def config_to_log_switches(config):
    """从配置中提取日志开关"""
    return {
        "foreign_scan_log": config.get("foreign_scan_log", False),
        "ipv6_wan_lan_log": config.get("ipv6_wan_lan_log", False),
        "wan_drop_log": config.get("wan_drop_log", False),
        "lan_drop_log": config.get("lan_drop_log", False),
        "forward_log": config.get("forward_log", False),
        "whitelist_access_log": config.get("whitelist_access_log", True),
    }


# === API 端点 ===

@app.route('/')
def serve_index():
    return send_from_directory('../frontend', 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    if '..' in filename or filename.startswith('/'):
        return jsonify({"error": "forbidden"}), 403
    return send_from_directory('../frontend', filename)


@app.route('/api/config', methods=['GET'])
def get_config():
    """获取当前配置"""
    config = load_config()
    # 这三个只读视图的作用只有一个：让界面能显示「配置说一套、系统实际做另一套」。
    #
    # 全部包在 try 里 —— /api/config 是面板的主数据源，它为了三个锦上添花的
    # 字段整个挂掉是不可接受的。读不到就给 None/空列表，界面少一条提示而已。
    try:
        luci_actual = _luci_actual_state()
    except Exception as e:
        luci_actual = None
        print(f'[WARN] 读 LuCI 实际状态失败: {type(e).__name__}: {e}', flush=True)
    try:
        luci_ports = sorted(_luci_ports_listening())
    except Exception as e:
        luci_ports = []
        print(f'[WARN] 读 LuCI 监听端口失败: {type(e).__name__}: {e}', flush=True)
    try:
        gw_actual = _gateway_actual_state(config)
    except Exception as e:
        gw_actual = None
        print(f'[WARN] 读网关实际状态失败: {type(e).__name__}: {e}', flush=True)
    return jsonify(dict(config,
                       success=True,
                       luci_actual=luci_actual,
                       luci_ports_listening=luci_ports,
                       gateway_actual=gw_actual))


def _client_is_lan(client_ip):
    """判断请求方是否来自内网（依据 config 里的 lan_subnet4，其次用自动检测结果）"""
    if not client_ip or ':' in client_ip:
        return False
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    candidates = []
    cfg = load_config()
    for src in (cfg.get('lan_subnet4'), _auto_detect_network(cfg).get('LAN_SUBNET4')):
        try:
            if src:
                candidates.append(ipaddress.ip_network(str(src), strict=False))
        except ValueError:
            continue
    return any(addr in net for net in candidates)


@app.route('/api/knock-info', methods=['GET'])
def get_knock_info():
    """供 LAN 内客户端（knock-lan.sh / Termux 脚本）读取敲门端口。

    为什么需要这个端点：
    - 原脚本用 `GET /api/config` 拉配置，但该端点在全局鉴权后面，未登录必返 401，
      该功能实际上从来没工作过；
    - 而且 /api/config 会泄露整个防火墙配置，绝不能匿名开放。

    安全约束：
    - 只允许来自内网的请求，公网调用一律 403；
    - 只返回 4 个敲门端口，不返回任何其他配置。
      敲门端口序列就是「密钥」，一旦从公网可读，端口敲门就失去意义，
      所以 WAN 场景必须由用户在 LAN 上查看后手工填进客户端脚本。
    """
    client_ip = request.remote_addr or ''
    if not _client_is_lan(client_ip):
        return jsonify({
            'success': False,
            'code': 'LAN_ONLY',
            'message': '该端点仅允许内网访问。公网场景请在局域网内查看端口后手工配置客户端。',
        }), 403
    cfg = load_config()
    ports = [int(_safe_port(cfg.get(f'knock{i}_port', i), i)) for i in (1, 2, 3, 4)]
    return jsonify({
        'success': True,
        'data': {
            'knock_ports': ports,
            'knock_ports_str': ",".join(str(p) for p in ports),
            'router_ip4': _safe_ip(cfg.get('router_ip4', ''), 4, ""),
        },
    })


@app.route('/api/config', methods=['POST'])
def post_config():
    """保存配置（不应用）。

    风险拦截（与 /api/rules/preview-changes 共用 _detect_risks）：
    - critical 级风险（如请求者把自己从 trusted_ip4 中移除）必须显式 confirm=true 才保存
    - 其他级别风险不阻止保存，但通过 risks 字段告知前端展示警告
    - 前端正常流程：preview-changes → 弹窗确认 → confirmSaveConfig() 传 confirm:true
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400

    # merge 到现有配置，避免前端只发部分字段时清空其他配置
    old_cfg = load_config()
    incoming = {k: v for k, v in data.items() if k != 'confirm'}  # confirm 不入配置

    # 只读键：GET 为了让前端能显示「实际状态」会多给几个字段，而前端是把
    # 整个 config 对象原样回传的。这些键不是配置，绝不能落盘。
    readonly_hits = sorted(k for k in incoming if k in READONLY_CONFIG_KEYS)
    for k in READONLY_CONFIG_KEYS:
        incoming.pop(k, None)

    # 网关配置块不归这个端点管，原样剔除。
    #
    # 这个接口只落盘、不下发 nginx。留着 gateway_enabled 就会造出
    # 「磁盘说开、8443 实际没人听」的状态（.224 实测），而面板各处都显示
    # 「已启用」，没有任何一处会收敛。宁可前端传了也不生效 —— 生效路径只有
    # /api/gateway/config，那边改完会真的下发并校验结果。
    ignored = sorted(k for k in incoming if k in GATEWAY_OWNED_CONFIG_KEYS)
    for k in GATEWAY_OWNED_CONFIG_KEYS:
        incoming.pop(k, None)
    if ignored:
        print(f'[WARN] /api/config 忽略了网关专属字段 {ignored}（只能由 /api/gateway/config 修改）',
              flush=True)
    if readonly_hits:
        print(f'[WARN] /api/config 丢弃了只读字段 {readonly_hits}（它们不是配置）',
              flush=True)

    new_cfg = dict(old_cfg)
    new_cfg.update(incoming)

    # 字段白名单校验：会进 nft 规则的字段必须合法，
    # 否则可注入任意 nft 指令（如 whitelist_timeout="1s; delete table inet fw4; #"）
    errs = validate_config(new_cfg)
    if errs:
        return jsonify({
            'success': False,
            'code': 'INVALID_CONFIG',
            'message': '配置校验失败，未保存',
            'errors': errs,
        }), 400

    requester_ip = request.remote_addr or ''
    risks = _detect_risks(old_cfg, new_cfg, requester_ip)

    # trusted_ip4 归一化成单值再落盘。
    #
    # 必须放在 _detect_risks **之后**：风险检测要看到未归一化的多值，才能报出
    # 「有 N 个被丢弃」。先归一化的话这条告警就永远不触发了。
    #
    # 为什么要在保存时归一化：配置里存着数组、规则里只认第一个，而两者之间
    # 没有任何东西提醒用户。存成单值，配置与执行就永远一致了。
    _eff_trusted, _ignored_trusted = _trusted_ip_single(new_cfg.get('trusted_ip4'))
    new_cfg['trusted_ip4'] = _eff_trusted or ''

    critical_risks = [r for r in risks if r.get('level') == 'critical']

    # critical 风险（如自锁）必须显式确认；绕过前端直接打 API 会被 409 拒绝
    if critical_risks and not data.get('confirm'):
        return jsonify({
            'success': False,
            'code': 'CRITICAL_RISK',
            'message': '检测到可能导致自锁的变更，请确认后再保存',
            'data': {'risks': risks},
        }), 409

    try:
        save_config(new_cfg)
    except OSError as e:
        # 磁盘满 / 权限不足时 save_config 会抛出，不能让异常冒泡成 500 裸栈
        return jsonify({'success': False, 'message': f'配置保存失败: {e}'}), 500

    # LuCI 80/443 开关：只在**实际状态与期望不一致**时才动 nginx。
    #
    # 判据刻意用「实际 vs 期望」而不是「配置变没变」。后者会漏掉：
    #   · 升级到带 luci_enabled 的版本时，老配置没这字段 → 取 DEFAULT False，
    #     而机器上 LuCI 一直开着；此时「配置没变」，开关永远不会被触发
    #   · 用户手工 uci 改过、或上次切换失败只回滚了配置项
    # 这两种情况下 .224 实测都真的发生过：配置显示 False，80/443 照常在听。
    #
    # 每次保存都 reload 一次 nginx 会打断正在服务的连接，所以仍然要先比一次。
    luci_msg = None
    want_luci = bool(new_cfg.get('luci_enabled', False))
    try:
        luci_actual = _luci_actual_state()
    except Exception as _se:
        luci_actual = None
        print(f'[WARN] 读 LuCI 实际状态失败: {_se}', flush=True)
    if luci_actual is not None and luci_actual != want_luci:
        ok, luci_msg = _apply_luci_toggle(want_luci)
        if not ok:
            # 配置已经落盘了（luci_enabled 的值是对的），但系统没跟上。
            # 如实报失败并回滚这个字段，免得面板显示「已关闭」而 80/443 还在听。
            new_cfg['luci_enabled'] = old_cfg.get('luci_enabled', False)
            try:
                save_config(new_cfg)
            except OSError:
                pass
            return jsonify({
                'success': False,
                'code': 'LUCI_TOGGLE_FAILED',
                'message': f'LuCI 80/443 切换失败，已回滚配置项: {luci_msg}',
                'data': {'risks': risks},
            }), 500
        if not want_luci and not _gateway_port_alive(config=new_cfg):
            # 关 LuCI 绝不能把网关带下去。这是本项目唯一的公网入口。
            new_cfg['luci_enabled'] = True
            try:
                save_config(new_cfg)
                _apply_luci_toggle(True)
            except OSError:
                pass
            return jsonify({
                'success': False,
                'code': 'GATEWAY_DOWN',
                'message': (f'关闭 LuCI 后网关 {_safe_port(new_cfg.get("gateway_port"), 8443)} '
                            f'端口不可达，已自动把 LuCI 重新打开并回滚配置项'),
                'data': {'risks': risks},
            }), 500

    return jsonify({
        'success': True,
        'message': '配置已保存' + (f'（{luci_msg}）' if luci_msg else ''),
        # 非 critical 风险通过这里告知前端
        'data': {'risks': risks, 'luci': luci_msg,
                 'ignored_gateway_fields': ignored,
                 'ignored_readonly_fields': readonly_hits},
    })


@app.route('/api/config/restore', methods=['POST'])
def restore_config():
    """恢复上次备份的防火墙配置"""
    backup_path = CONFIG_PATH + '.backup'
    if not os.path.exists(backup_path):
        return jsonify({"success": False, "message": "没有可恢复的备份文件"}), 400
    tmp_path = CONFIG_PATH + '.restore.tmp'
    lock_path = CONFIG_PATH + '.lock'
    lock_fd = None
    try:
        # 1. 同一把写锁：save_config 也在用。恢复期间并发保存会把
        #    「恢复出来的旧配置」和「并发写入的新配置」互相覆盖，
        #    结果取决于谁最后落盘。
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        except OSError as e:
            print(f'[WARN] restore_config 加锁失败（继续无锁恢复）: {e}', flush=True)

        # 2. 先写临时文件再 replace：shutil.copy 是「边读边写」直接落到
        #    CONFIG_PATH，中途失败/磁盘满会留下一个截断的 JSON。
        #    而 load_config 遇到截断 JSON 会当损坏处理 → 备份成
        #    .corrupted.* 后**静默回落到 DEFAULT_CONFIG**，
        #    等于「恢复配置」反而把配置弄丢了。
        shutil.copy(backup_path, tmp_path)
        with open(tmp_path, 'r') as f:
            json.load(f)          # 校验恢复出来的确实是完整 JSON
        os.replace(tmp_path, CONFIG_PATH)
        return jsonify({"success": True, "message": "配置已恢复，请刷新页面"})
    except Exception as e:
        _unlink_quiet(tmp_path)
        return jsonify({"success": False,
                        "message": f"恢复失败，原配置未被改动: {e}"}), 500
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            except OSError:
                pass


def build_rules(config):
    """生成规则，替换白名单超时时间"""
    variables = config_to_variables(config)
    log_switches = config_to_log_switches(config)
    rules = generate_rules(variables, log_switches, load_lists())
    # 白名单超时强制非负整数：这里是 rules.replace() 字符串拼接，
    # 任意非数字内容都会被原样写进 nft 规则（可注入 delete table 等指令）
    whitelist_timeout = config.get("whitelist_timeout", 18000)
    if not str(whitelist_timeout).strip().isdigit():
        whitelist_timeout = 18000
    timeout_str = f"timeout {int(whitelist_timeout)}s"
    rules = rules.replace("timeout 5h", timeout_str)
    return rules


@app.route('/api/rules/preview', methods=['GET'])
def preview_rules():
    """预览当前配置生成的规则（不写入文件）"""
    config = load_config()
    rules = build_rules(config)
    return jsonify({"success": True, "rules": rules})


def _diff_nft_rules(old_text: str, new_text: str) -> dict:
    """对比两份 nft 规则文本，返回 diff 摘要和重要变更行（限 30 条）"""
    import difflib
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    diff = list(difflib.unified_diff(old_lines, new_lines, lineterm='', n=0))

    added = [line[1:] for line in diff if line.startswith('+') and not line.startswith('+++')]
    removed = [line[1:] for line in diff if line.startswith('-') and not line.startswith('---')]

    return {
        'old_line_count': len(old_lines),
        'new_line_count': len(new_lines),
        'added_count': len(added),
        'removed_count': len(removed),
        'added_sample': added[:15],   # 至多展示 15 条
        'removed_sample': removed[:15],
        'has_changes': len(added) > 0 or len(removed) > 0,
    }


def _ip_list(v):
    """trusted_ip4 的原始写法（单串 / 逗号串 / 列表）拆成字符串列表。"""
    if v is None:
        return []
    if isinstance(v, str):
        return [p.strip() for p in v.replace('，', ',').split(',') if p.strip()]
    if isinstance(v, (list, tuple, set)):
        return [str(p).strip() for p in v if str(p).strip()]
    s = str(v).strip()
    return [s] if s else []


def _trusted_ip_single(v):
    """trusted_ip4 归一化成**单个** IP —— 与 build_rules 实际生效的口径一致。

    为什么必须是单值：本项目从头到尾按「一个信任 IP」设计。
      · build_rules 走 `_safe_ip(..., strict=True)`，注释写明「数组取第一个合法项」
      · 前端是单个 `<input x-model="config.trusted_ip4">`
      · 模板里 `ip saddr $TRUSTED_IP4 accept` 给这一个 IP 全端口全协议放行

    .224 实测（2026-10-15）配置里是
    `['192.168.100.224', '192.168.100.1', '192.168.100.249']` 三个，
    生成的规则只有 `define TRUSTED_IP4 = 192.168.100.224`。
    另外两个管理机在 policy drop 下被挡在外面，而且没有任何提示。

    原来这里用 `_ip_set()` 归一化成**集合**，自锁告警按 3 个算，
    而规则只认 1 个 —— 告警与实际执行的口径本身就不一致。

    返回 (生效的单个 IP 或 None, 被忽略的其余项列表)。

    生效值直接委托 _safe_ip(..., strict=True) —— 那是 build_rules 真正调用的
    解析器。刻意不自己「智能」处理：一旦这里和它分叉，自锁告警就会和实际
    执行的口径对不上，而那正是要修的东西。
    （例：逗号串 'a,b' 在 _safe_ip 眼里是**一个**非法 IP → 整个信任白名单
    不生成，而不是「取 a」。这里如实报「无 + 两个都被丢弃」，
    与实际一致。validate_config 本来也会把这种写法 400 掉。）
    """
    effective = _safe_ip(v, 4, '', strict=True) or None
    ignored = [x for x in _ip_list(v) if x != effective]
    return effective, ignored


def _ip_set(v):
    """把 trusted_ip4（单串/逗号串/列表）归一化成 IPv4 集合。

    必须显式切分：直接 set("192.168.100.2") 会把字符串拆成
    {'1','9','6','2','.','8','0'}，导致自锁告警恒不触发。

    ⚠️ 只在真的需要「集合」语义的场景用。trusted_ip4 实际按单值生效，
    判断自锁风险请用 _trusted_ip_single —— 口径必须和 build_rules 一致。
    """
    return {p for p in _ip_list(v) if _valid_ip(p, 4)}


def _port_set(v):
    """把 lan_allowed_ports（逗号串/列表）归一化成端口整数集合"""
    try:
        return set(_split_ports(v))
    except ValueError:
        return set()


def _detect_risks(old_cfg: dict, new_cfg: dict, requester_ip: str) -> list:
    """检测可能把用户锁在外面的风险"""
    risks = []
    # 1. SSH 端口变化（lan_allowed_ports 取消 22）
    old_lan_ports = _port_set(old_cfg.get('lan_allowed_ports', []))
    new_lan_ports = _port_set(new_cfg.get('lan_allowed_ports', []))
    if 22 in old_lan_ports and 22 not in new_lan_ports:
        risks.append({
            'level': 'high',
            'message': 'LAN 允许端口移除了 22（SSH），可能影响远程管理',
        })
    # 2. trusted_ip4 移除请求者自己的 IP
    #
    # 口径必须是「实际生效的那个」，不是配置里写了几个就算几个。
    # build_rules 用 _safe_ip(..., strict=True) 只取数组第一个合法项，
    # 这里原来用 _ip_set() 按集合算 —— 告警说「你还在白名单里」，
    # 而生成的规则里可能根本没有你，于是 critical 自锁拦不住。
    old_trusted, _old_ignored = _trusted_ip_single(old_cfg.get('trusted_ip4'))
    new_trusted, new_ignored = _trusted_ip_single(new_cfg.get('trusted_ip4'))
    if requester_ip and requester_ip == old_trusted and requester_ip != new_trusted:
        risks.append({
            'level': 'critical',
            'message': f'你的 IP {requester_ip} 不再是 trusted_ip4（保存后立即被锁在外面）',
        })
    # 2b. 配了多个信任 IP —— 只有第一个生效，其余被静默丢弃。
    # 这是 .224 上真实发生过的：配了 3 个，规则只认第 1 个。
    if new_ignored:
        risks.append({
            'level': 'high',
            'message': f'trusted_ip4 只支持一个 IP：当前生效的是 '
                       f'{new_trusted or "（无）"}，以下将被丢弃 '
                       f'{"、".join(new_ignored)}。'
                       f'多写不会多放行，请改成单个 IP。',
        })
    # 3. access_mode 改了
    old_mode = old_cfg.get('access_mode', 'lan')
    new_mode = new_cfg.get('access_mode', 'lan')
    if old_mode != new_mode:
        risks.append({
            'level': 'medium',
            'message': f'访问模式从 {old_mode} 改为 {new_mode}',
        })
    # 4. 切到 trusted 模式但请求者自己不在白名单 —— 信任模式下非白名单流量全丢，
    #    等同于自锁。只在「模式真正切到 trusted」的那一刻报，
    #    否则留在 trusted 模式下改别的字段时每次保存都误报。
    if (new_mode == 'trusted' and old_mode != 'trusted'
            and requester_ip and requester_ip != new_trusted):
        risks.append({
            'level': 'critical',
            'message': f'切到 trusted（信任）模式后内网默认全丢弃，而你的 IP {requester_ip} '
                       f'不是 trusted_ip4（{new_trusted or "未设置"}），保存后会被防火墙拦住',
        })

    # 5. 面板来源访问边界把请求者自己关在外面
    #    只在「本来能进、改完不能进」时报，避免每次保存都误报。
    def _panel_nets(cfg):
        nets = _parse_net_list(cfg.get('panel_allowed_nets'))
        if nets:
            return nets
        # 与 _panel_allowed_networks 同一套前提：只有真实配置**且没损坏**时
        # 才敢用 lan_subnet4。配置坏了 load_config() 会回落 DEFAULT_CONFIG，
        # 那里面的 lan_subnet4 是 192.168.4.0/24 —— 拿它判自锁会在本机
        # 报一条根本不存在的「你把自己关在外面」。
        if os.path.exists(CONFIG_PATH) and not _config_corrupted()[0]:
            return _parse_net_list(cfg.get('lan_subnet4'))
        return []

    if requester_ip:
        old_pn = _panel_nets(old_cfg)
        new_pn = _panel_nets(new_cfg)
        if (new_pn and old_pn and _ip_in_nets(requester_ip, old_pn)
                and not _ip_in_nets(requester_ip, new_pn)):
            risks.append({
                'level': 'critical',
                'message': f'面板访问边界改动后，你的 IP {requester_ip} 不在允许网段 '
                           f'({", ".join(str(n) for n in new_pn)}) 内！'
                           f'保存后将立即连不上面板，只能走 SSH 改配置',
            })
    return risks


@app.route('/api/rules/preview-changes', methods=['POST'])
def preview_rules_changes():
    """预览即将保存的 config 变更（不写文件、不应用 nft）

    请求体: {"proposed": {<要修改的 config 字段>}}
    返回: {
        success: True,
        data: {
            diff: {old/new 行数, added/removed 数和样例, has_changes},
            risks: [{level, message}, ...],
            new_rules_text: str,  // 完整的新规则（让用户能复制检查）
        }
    }
    """
    if not _is_authenticated():
        return jsonify({'success': False, 'code': 'AUTH_REQUIRED'}), 401
    data = request.get_json(silent=True) or {}
    proposed = data.get('proposed', {})
    if not isinstance(proposed, dict):
        return jsonify({'success': False, 'message': 'proposed 必须是对象'}), 400

    old_cfg = load_config()
    new_cfg = dict(old_cfg)
    new_cfg.update(proposed)

    try:
        new_rules_text = build_rules(new_cfg)
    except Exception as e:
        return jsonify({'success': False, 'message': f'生成规则失败: {e}'}), 400

    # 旧规则文本（从 RULES_PATH 读）
    old_rules_text = ''
    if os.path.exists(RULES_PATH):
        try:
            with open(RULES_PATH, 'r') as f:
                old_rules_text = f.read()
        except Exception:
            pass

    diff = _diff_nft_rules(old_rules_text, new_rules_text)
    requester_ip = request.remote_addr or ''
    risks = _detect_risks(old_cfg, new_cfg, requester_ip)

    return jsonify({
        'success': True,
        'data': {
            'diff': diff,
            'risks': risks,
            'new_rules_text': new_rules_text,
        },
    })


@app.route('/api/rules/save', methods=['POST'])
def save_rules():
    """已废弃 —— 转发到 /api/rules/apply 的完整安全路径。

    原实现是 build_rules() + 直接写盘，绕过了 v0.8.x 加的**全部**三样东西：

      · _config_corrupted_response()：配置损坏时 load_config() 返回硬编码的
        DEFAULT_CONFIG（内含他人网段）。原实现拿它直接落盘，等于把陌生网段
        写进真实防火墙，还回报 success: true。/api/rules/apply 正是为了堵
        这一点才有 _config_corrupted_response()。
      · _FW_APPLY_LOCK：与看门狗的 nft -f 交叉执行会得到无法预测的中间规则集。
      · _apply_ruleset() 的语法校验与失败回滚：原实现写完就返回，
        规则集坏掉要等看门狗下次自愈才被发现。

    本文件 2082 行的注释已经写明「避免出现某条路径跳过了校验和回滚」——
    这条路径当时就是那个例外。tools/check-api-coverage.py 报出它全仓 0 引用，
    是个没有任何调用方的旁路。保留端点只为不打断可能存在的外部调用方
    （curl / 脚本），语义直接对齐 apply。
    """
    return apply_rules()


# === 网络配置辅助函数 ===

def sanitize_uci_value(value):
    """过滤 UCI 值中的危险字符，防止注入恶意配置行"""
    if not value:
        return ''
    return value.replace('\n', '').replace('\r', '').replace("'", '').replace('`', '')


def extract_uci_value(line):
    """从 UCI option 行提取值，如 "option device 'br-lan'" -> "br-lan" """
    parts = line.split(None, 2)
    if len(parts) >= 3:
        return parts[2].strip().strip("'\"")
    return ''


def get_lan_ipv6():
    """获取 br-lan 接口的第一个 IPv6 地址"""
    try:
        result = subprocess.run(['ip', '-6', 'addr', 'show', 'dev', 'br-lan'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('inet6') and 'fe80' not in line and 'scope global' in line:
                addr = line.split()[1].split('/')[0]
                return addr
        # 如果没有 global 地址，取 link-local
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('inet6') and 'fe80' in line:
                addr = line.split()[1].split('/')[0]
                return addr
    except:
        pass
    return ''


def parse_uci_config(path):
    """简单的 UCI 配置解析器"""
    result = {
        'lan_device': '', 'lan_proto': '', 'lan_ipaddr': '', 'lan_netmask': '',
        'wan_device': '', 'wan_proto': '',
        'wan_pppoe_username': '', 'wan_pppoe_password': '',
        'wan_pppoe': False,
        'lan_ip6': '',
    }
    current_section = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if re.match(r"config interface 'lan'$", line):
                current_section = 'lan'
            elif re.match(r"config interface 'wan'$", line):
                current_section = 'wan'
            elif line.startswith("config interface 'wan6'"):
                current_section = 'wan6'
            elif line.startswith("config "):
                current_section = None
            elif current_section == 'lan':
                if 'option device' in line or 'option ifname' in line:
                    result['lan_device'] = extract_uci_value(line)
                elif 'option proto' in line:
                    result['lan_proto'] = extract_uci_value(line)
                elif 'option ipaddr' in line:
                    result['lan_ipaddr'] = extract_uci_value(line)
                elif 'option netmask' in line:
                    result['lan_netmask'] = extract_uci_value(line)
            elif current_section == 'wan':
                if 'option ifname' in line or 'option device' in line:
                    result['wan_device'] = extract_uci_value(line)
                elif 'option proto' in line:
                    proto = extract_uci_value(line)
                    result['wan_proto'] = proto
                    if proto == 'pppoe':
                        result['wan_pppoe'] = True
                elif 'option username' in line:
                    result['wan_pppoe_username'] = extract_uci_value(line)
                elif 'option password' in line:
                    result['wan_pppoe_password'] = extract_uci_value(line)
            elif current_section == 'wan6':
                if 'option ifname' in line or 'option device' in line:
                    result['wan6_device'] = extract_uci_value(line)
                elif 'option proto' in line:
                    result['wan6_proto'] = extract_uci_value(line)
                elif 'option ip6addr' in line:
                    result['wan6_ip6addr'] = extract_uci_value(line)
    return result


def update_uci_wan_config(path, data):
    """更新 /etc/config/network 中的 wan 接口配置"""
    with open(path, 'r') as f:
        lines = f.readlines()

    new_lines = []
    has_pppoe = data.get('wan_pppoe', False)
    wan_device = sanitize_uci_value(data.get('wan_device', ''))
    # 检测 WAN 设备：只认"不在 LAN 桥成员里"的物理网卡。
    #
    # ⚠️ 这里原本有个会造成失联的兜底：检测不到就 `wan_device = 'eth0'`。
    # 但 eth0 恰恰是 br-lan 的唯一从属端口（上面的检测正是为了把它排除掉），
    # 兜底等于把 WAN 强行绑到 br-lan 的网卡上 → 桥塌掉 → 整机失联。
    # 2026-10-06 实测踩中：x86 单网卡 OpenWrt 上点「PPPoE 拨号」+「保存网络
    # 配置」+「重启网络」，设备当场 ARP FAILED，Proxmox 未开带外口，无法远程恢复。
    # 检测不到独立 WAN 网卡就必须拒绝，绝不能猜一个设备名写进配置。
    detected = False
    lan_ports = set()          # 提到 try 外：异常路径下也要能报出"哪些卡被 LAN 占了"
    try:
        import subprocess as _sp
        with open(path, 'r') as f:
            for line in f:
                if 'list ports' in line:
                    p = line.strip().split("'")[-2] if "'" in line else ''
                    if p:
                        lan_ports.add(p)
        # 用 ls /sys/class/net/ 检测接口（兼容 BusyBox）
        r = _sp.run(['ls', '/sys/class/net/'], capture_output=True, text=True, timeout=5)
        for name in r.stdout.strip().split():
            if (name.startswith('eth') or name.startswith('ens') or name.startswith('enp')) and name not in lan_ports:
                wan_device = name
                detected = True
                break
    except Exception:
        pass
    if not detected:
        lan_desc = ', '.join(sorted(lan_ports)) if lan_ports else '未知'
        raise ValueError(
            f"未检测到独立的 WAN 网卡（已占用于 LAN 桥的设备：{lan_desc}）。"
            f"本机只有一张物理网卡，无法同时做 LAN 和 PPPoE WAN —— "
            f"继续写入会让 WAN 抢走 LAN 的网卡，导致设备失联。"
            f"请先在 OpenWrt 里划出第二张网卡专供 WAN，或改用其它上网方式。"
        )
    pppoe_username = sanitize_uci_value(data.get('wan_pppoe_username', ''))
    pppoe_password = sanitize_uci_value(data.get('wan_pppoe_password', ''))
    if not pppoe_username:
        raise ValueError("PPPoE 拨号需要填写宽带账号（当前为空），已中止保存以免写出不可用的配置。")
    shutil.copy(path, path + '.backup')

    # 保存 wan6 块内容，以便切换回非 PPPoE 时恢复
    saved_wan6_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if re.match(r"config interface 'wan'$", stripped):
            new_lines.append(line)
            if has_pppoe:
                new_lines.append(f"\toption device '{wan_device}'\n")
                new_lines.append(f"\toption proto 'pppoe'\n")
                new_lines.append(f"\toption username '{pppoe_username}'\n")
                new_lines.append(f"\toption password '{pppoe_password}'\n")
                new_lines.append(f"\toption ipv6 'auto'\n")
                new_lines.append(f"\toption mtu '1492'\n")
            else:
                new_lines.append(f"\toption device '{wan_device}'\n")
                new_lines.append(f"\toption proto 'dhcp'\n")
            # 跳过 wan 块内的旧 option 行，但保留注释行
            i += 1
            while i < len(lines):
                next_stripped = lines[i].strip()
                if next_stripped.startswith('config '):
                    break
                if next_stripped == '':
                    if i + 1 < len(lines) and not lines[i+1].strip().startswith('config '):
                        new_lines.append(lines[i])
                        i += 1
                        continue
                    break
                # 保留注释行
                if next_stripped.startswith('#'):
                    new_lines.append(lines[i])
                i += 1
            continue

        if stripped.startswith("config interface 'wan6'"):
            # 收集 wan6 块所有行
            wan6_block = [line]
            i += 1
            while i < len(lines):
                if lines[i].strip().startswith('config '):
                    break
                wan6_block.append(lines[i])
                i += 1
            if has_pppoe:
                # PPPoE 模式：删除 wan6，但保存内容以便恢复
                saved_wan6_lines = wan6_block
                continue
            else:
                new_lines.extend(wan6_block)
                continue

        new_lines.append(line)
        i += 1

    # 切换回非 PPPoE 时，如果 wan6 被删除过且原文件中不再存在，则恢复
    if not has_pppoe and saved_wan6_lines:
        has_wan6 = any(re.match(r"config interface 'wan6'", l.strip()) for l in new_lines)
        if not has_wan6:
            new_lines.append('\n')
            new_lines.extend(saved_wan6_lines)

    # 如果文件中没有 wan 块，在末尾追加
    has_wan_block = any(re.match(r"config interface 'wan'$", l.strip()) for l in new_lines)
    if not has_wan_block:
        new_lines.append('\n')
        if has_pppoe:
            new_lines.append("config interface 'wan'\n")
            new_lines.append(f"\toption device '{wan_device}'\n")
            new_lines.append(f"\toption proto 'pppoe'\n")
            new_lines.append(f"\toption username '{pppoe_username}'\n")
            new_lines.append(f"\toption password '{pppoe_password}'\n")
            new_lines.append(f"\toption ipv6 'auto'\n")
            new_lines.append(f"\toption mtu '1492'\n")
        else:
            new_lines.append("config interface 'wan'\n")
            new_lines.append(f"\toption device '{wan_device}'\n")
            new_lines.append(f"\toption proto 'dhcp'\n")

    # 如果没有 wan6 块，在末尾追加
    has_wan6_block = any(re.match(r"config interface 'wan6'", l.strip()) for l in new_lines)
    if not has_wan6_block:
        new_lines.append('\n')
        new_lines.append("config interface 'wan6'\n")
        new_lines.append(f"\toption device '{wan_device}'\n")
        new_lines.append("\toption proto 'dhcpv6'\n")

    with open(path, 'w') as f:
        f.writelines(new_lines)


# === 网络配置 API ===

@app.route('/api/network/interfaces', methods=['GET'])
def get_interfaces():
    """获取可用网络接口列表"""
    interfaces = []
    net_path = '/sys/class/net'
    for name in os.listdir(net_path):
        if name == 'lo':
            continue
        state_path = os.path.join(net_path, name, 'operstate')
        state = 'unknown'
        if os.path.exists(state_path):
            with open(state_path) as f:
                state = f.read().strip()
        interfaces.append({'name': name, 'state': state})
    interfaces.sort(key=lambda x: x['name'])
    return jsonify({"success": True, "interfaces": interfaces})


@app.route('/api/network/config', methods=['GET'])
def get_network_config():
    """读取 OpenWrt 网络配置"""
    try:
        config = parse_uci_config('/etc/config/network')
        config['lan_ip6'] = get_lan_ipv6()
    except FileNotFoundError:
        return jsonify({"success": True, "message": "网络配置文件不存在，显示默认值", **dict(
            lan_device='', lan_proto='', lan_ipaddr='', lan_netmask='',
            wan_device='', wan_proto='', wan_pppoe_username='', wan_pppoe_password='',
            wan_pppoe=False, lan_ip6='',
        )})
    except Exception as e:
        return jsonify({"success": False, "message": f"读取网络配置失败: {str(e)}"}), 500
    return jsonify({"success": True, **config})


def _ensure_lan_essentials(path, has_pppoe=False):
    """确保 LAN 接口关键字段存在，防止配置丢失导致路由器失联"""
    with open(path, 'r') as f:
        content = f.read()
    lan_match = re.search(r"config interface 'lan'\n((?:[ \t][^\n]*\n)*?)(?=\nconfig |\n*\Z)", content)
    if not lan_match:
        return
    lan_block = lan_match.group(1)
    defaults = {
        'ipaddr': '192.168.100.1',
        'netmask': '255.255.255.0',
        'proto': 'static',
        'device': 'br-lan',
        'ip6assign': '60',
    }
    needs_update = False
    for key, default in defaults.items():
        if f'option {key}' not in lan_block:
            needs_update = True
            break
    # PPPoE 模式下强制 LAN proto 为 static
    if has_pppoe and re.search(r"option\s+proto\s+'dhcp'", lan_block):
        lan_block = re.sub(r"option\s+proto\s+'dhcp'", "option proto 'static'", lan_block)
        needs_update = True
    if needs_update:
        for key, default in defaults.items():
            if f'option {key}' not in lan_block:
                lan_block = lan_block.rstrip('\n') + f"\n\toption {key} '{default}'\n"
        content = content.replace(lan_match.group(1), lan_block)
        with open(path, 'w') as f:
            f.write(content)


@app.route('/api/network/config', methods=['POST'])
def save_network_config():
    """保存 OpenWrt 网络配置"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    try:
        # PPPoE 拨号模式下，检查防火墙规则是否已应用
        if data.get('wan_pppoe', False):
            result = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'allowed4'],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return jsonify({
                    "success": False,
                    "message": "防火墙规则未生效，PPPoE 拨号成功后将无防火墙保护。请先配置好防火墙规则并点击\"应用规则\"，再\"保存网络配置\"。",
                    "code": "RULES_NOT_APPLIED"
                }), 400
        update_uci_wan_config('/etc/config/network', data)
        if data.get('wan_pppoe', False):
            _ensure_lan_essentials('/etc/config/network', has_pppoe=True)
        # 同步 LAN IP 到 Web 配置
        with open('/etc/config/network', 'r') as f:
            content = f.read()
        lan_match = re.search(r"config interface 'lan'\n((?:[ \t][^\n]*\n)*?)(?=\nconfig |\n*\Z)", content)
        if lan_match:
            ip_match = re.search(r"option\s+ipaddr\s+'([^']+)'", lan_match.group(1))
            if ip_match:
                new_ip = ip_match.group(1)
                web_config = load_config()
                if web_config.get('router_ip4') != new_ip:
                    web_config['router_ip4'] = new_ip
                    save_config(web_config)
        return jsonify({"success": True, "message": "网络配置已保存（需重启网络生效）"})
    except ValueError as e:
        # 配置本身不合法（例如单网卡机器上要求开 PPPoE）属于客户端问题，
        # 走 400 + 明确 code，别混进 500 让前端只显示一句"保存失败"，
        # 用户根本不知道是自己这台机器没有第二张网卡。
        return jsonify({"success": False, "code": "INVALID_NETWORK", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/network/restart', methods=['POST'])
def restart_network():
    """重启网络服务，然后走统一下发路径把防火墙规则装回去。

    为什么必须改成调 _apply_ruleset 而不再自己写文件跑 nft：
    原实现是 `build_rules` → `open(RULES_PATH,'w')` → `nft -f`，四样全缺 ——
      · 不查 _config_corrupted()：配置损坏时把 DEFAULT_CONFIG（敲门端口 1/2/3/4、
        转发指向 192.168.4.226）直接下发，实测返回 200「防火墙规则已重新应用」
      · 不持 _FW_APPLY_LOCK：可与看门狗的 nft -f 交叉执行
      · open(...,'w') 是 truncate+write 非原子：与 os.replace 交叉会读到半截文件
      · 没有 nft -c 预检、没有 .lastgood 备份

    顺序也从「先写文件再重启网络」改成「先重启网络再下发」：网络重启会重载
    fw4 并冲掉规则集，所以下发必须发生在重启之后。_apply_ruleset 自己会写
    RULES_PATH，init 脚本开机兜底照样能用。
    """
    try:
        config = load_config()
        # 重启网络会重载 fw4 并冲掉当前规则集 —— 先确认能下发，再去重启。
        # 顺序反过来会出现「网络已经断了、规则却装不回来」的窗口：
        # 守卫只在 _apply_ruleset 里，而那时 damage 已经造成。
        bad, err = _config_corrupted()
        if bad:
            return jsonify({"success": False, "code": "CONFIG_CORRUPTED",
                            "message": _CORRUPT_REFUSAL.format(err=err, path=CONFIG_PATH)}), 500
        subprocess.run(['/etc/init.d/network', 'restart'],
                       capture_output=True, text=True, timeout=30)
        # 等待网络接口恢复（阻塞 5s 是可接受的，后续要加载 nft 规则）
        time.sleep(5)
        ok, message = _apply_ruleset(config)
        if not ok:
            return jsonify({"success": False, "message":
                            f"网络已重启，但防火墙规则未生效，{message}"}), 500
        return jsonify({"success": True, "message": "网络已重启，防火墙规则已重新应用"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/firewall/status', methods=['GET'])
def get_firewall_status():
    """检测 fw4 和 nftables 运行状态"""
    try:
        # 检测 fw4 状态
        result = subprocess.run(['/etc/init.d/firewall', 'status'],
                                capture_output=True, text=True, timeout=5)
        fw4_active = 'inactive' not in result.stdout

        # 检测 nftables 是否已配置（检查 allowed4 set 是否存在）
        result2 = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'allowed4'],
                                 capture_output=True, text=True, timeout=5)
        nftables_loaded = result2.returncode == 0

        # init 脚本检测
        init_exists = os.path.exists('/etc/init.d/nftables-web')

        init_enabled = False
        if init_exists:
            r = subprocess.run(['/etc/init.d/nftables-web', 'enabled'],
                               capture_output=True, text=True, timeout=5)
            init_enabled = r.returncode == 0

        # 检查 init 脚本是否包含 fw4 stop（最新版本）
        init_has_fw4_stop = False
        if init_exists:
            with open('/etc/init.d/nftables-web', 'r') as f:
                init_content = f.read()
            init_has_fw4_stop = 'firewall stop' in init_content and 'firewall disable' in init_content

        return jsonify({
            "success": True,
            "fw4_active": fw4_active,       # true=fw4在运行(红点), false=已停止(绿点)
            "nftables_loaded": nftables_loaded,  # true=已配置(绿点), false=未配置(红点)
            "init_exists": init_exists,
            "init_enabled": init_enabled,
            "init_has_fw4_stop": init_has_fw4_stop,
            "init_up_to_date": init_exists and init_enabled and init_has_fw4_stop
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/firewall/repair-init', methods=['POST'])
def repair_init_script():
    """重新安装 init 脚本"""
    try:
        import shutil
        src = '/opt/nftables-web-v2/backend/nftables-web.init'
        dst = '/etc/init.d/nftables-web'
        if not os.path.exists(src):
            return jsonify({"success": False, "message": "源脚本不存在"}), 400
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)
        subprocess.run(['/etc/init.d/nftables-web', 'enable'],
                       capture_output=True, text=True, timeout=5)
        return jsonify({"success": True, "message": "init 脚本已修复并启用开机自启"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


def _restore_lastgood_rules():
    """回滚：恢复上一版自定义规则文件并重新加载。

    自定义规则集以 `flush ruleset` 开头、完全接管规则表，因此不能用 fw4 回滚
    （fw4 会重新生成 table inet fw4 并与自定义规则冲突）。正确做法是恢复上一版
    自定义规则；连上一版都不可用时退到 _apply_basic_lockdown() 的最小防护。

    返回 (state, message)。**state 必须如实反映实际结果**，因为调用方要把它
    映射成给用户看的文案：曾经把「恢复上一版」和「套用最小兜底」压成一个 bool，
    导致最坏情况（fw4 已停、新规则没装上、兜底也没装上 = 路由器裸奔）
    被描述成「已启用最小兜底防护」，用户据此以为安全了。
      'lastgood' —— 已恢复到上一版自定义规则
      'lockdown' —— 只套用了最小兜底（端口转发/敲门等规则全丢）
      'failed'   —— 什么都没恢复，路由器当前可能无任何防火墙
    """
    backup = RULES_PATH + '.lastgood'
    if os.path.exists(backup):
        try:
            # 用 copy 而不是 os.replace/move：回滚失败时（nft -f 非 0）如果
            # 把 .lastgood 搬走了，这份唯一的回滚材料就没了 —— 再出一次故障
            # 就只能退到 _apply_basic_lockdown，端口转发/敲门规则全丢。
            # 搬走的代价是「回滚成功后 .lastgood 消失」，留着没有额外成本。
            shutil.copy(backup, RULES_PATH)
            res = subprocess.run(['nft', '-f', RULES_PATH],
                                 capture_output=True, text=True, timeout=30)
            if res.returncode == 0 and not _ruleset_is_empty():
                print('[OK] 已回滚到上一版自定义规则', flush=True)
                return 'lastgood', '已回滚到上一版规则'
            # 回滚没生效：把 RULES_PATH 恢复到「上一版的备份」内容，
            # 至少磁盘上的材料还在，下次还能再试一次。
            print(f'[WARN] 回滚后 nft -f 返回 {res.returncode if res else "超时"}，'
                  f'已保留 .lastgood 供下次重试', flush=True)
        except Exception as e:
            print(f'[WARN] 回滚上一版规则失败: {type(e).__name__}: {e}', flush=True)
    if _apply_basic_lockdown():
        print('[WARN] 无可用历史规则，已套用最小兜底防护（端口转发/敲门规则未生效）', flush=True)
        return 'lockdown', ('无历史规则可回滚，已套用最小兜底防护；'
                            '端口转发/敲门等规则当前未生效，请尽快重新应用')
    print('[ERROR] 回滚失败：无历史规则且最小兜底也未生效，路由器当前可能无防火墙', flush=True)
    return 'failed', ('回滚失败：无历史规则且最小兜底也未生效，'
                      '路由器当前可能处于无防火墙状态，请立即通过 SSH 手工执行 '
                      'nft -f /etc/nftables.d/99-custom-rules.nft')


def _apply_ruleset(config):
    """把 config 生成成规则并安全加载。返回 (ok, message)。

    流程：生成 -> 写临时文件 -> `nft -c` 语法预检 -> 原子替换 -> 停 fw4 ->
    `nft -f` -> 失败则回滚到上一版（再失败退到最小兜底防护）。

    反代规则增删改、网关配置、/api/rules/apply、/api/network/restart 共用本函数，
    避免出现「某条路径跳过了校验和回滚」的不一致。

    守卫也放在这里，而不是挂在单个 HTTP 端点上。原来 `_config_corrupted_response()`
    全库只有 /api/rules/apply 一个调用点，于是同一份损坏配置下：
        /api/rules/apply   → 500 拒绝下发 ✅
        /api/network/restart → 200 照常下发（自己写文件自己跑 nft -f）
        /api/gateway/config  → 200 下发并把 DEFAULT_CONFIG 写回磁盘
    沉到公共路径后，无论从哪个门进来都会撞上。
    """
    # 在取锁之前判断：这是一次纯内存检查，没有理由占着锁。
    # 看门狗（_auto_recover_ruleset_if_empty）自己也会查一遍并退到
    # .backup / basic lockdown，所以这里拦它不会影响自愈能力。
    bad, err = _config_corrupted()
    if bad:
        print(f'[ERROR] 配置损坏（{err}），拒绝按默认配置下发 nft 规则', flush=True)
        return False, _CORRUPT_REFUSAL.format(err=err, path=CONFIG_PATH)

    # 与看门狗共用锁：两个 nft -f 交叉执行会得到无法预测的中间规则集，
    # 而且看门狗的 _try_apply_rules_file 与这里的回滚逻辑会互相覆盖文件。
    _FW_APPLY_LOCK.acquire()
    try:
        return _apply_ruleset_locked(config)
    finally:
        _FW_APPLY_LOCK.release()


def _apply_ruleset_locked(config):
    """_apply_ruleset 的实现体。调用方必须已持有 _FW_APPLY_LOCK。"""
    rules = build_rules(config)
    os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)

    # 确保 include 所需的文件存在（避免因文件缺失导致校验失败）
    if config.get("china_ip_block", False):
        os.makedirs('/etc/nftables', exist_ok=True)
        if not os.path.exists('/etc/nftables/china-ips.nft'):
            open('/etc/nftables/china-ips.nft', 'w').close()

    # 1. 先写临时文件做语法预检（nft -c 只检查不执行），校验通过才落到正式路径
    tmp_path = RULES_PATH + '.tmp'
    with open(tmp_path, 'w') as f:
        f.write(rules)
    try:
        check = subprocess.run(['nft', '-c', '-f', tmp_path],
                               capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        _unlink_quiet(tmp_path)
        return False, "nft 语法校验超时，未应用"
    except (FileNotFoundError, OSError) as e:
        _unlink_quiet(tmp_path)
        return False, f"无法执行 nft 命令: {e}"
    if check.returncode != 0:
        _unlink_quiet(tmp_path)
        return False, f"规则语法错误，未应用: {check.stderr or check.stdout}"

    # 2. 备份当前落盘版本（供 nft -f 失败时回滚），再原子替换
    lastgood = RULES_PATH + '.lastgood'
    had_old = os.path.exists(RULES_PATH)
    if had_old:
        try:
            shutil.copy(RULES_PATH, lastgood)
        except OSError as e:
            # 备份失败 = 没有回滚材料。接下来的 os.replace 会把旧文件覆盖掉，
            # 万一 nft -f 再失败就什么都恢复不了。所以这里直接中止。
            # （此前是把 had_old 改成 False 继续往下走：失败分支看到
            #  not had_old 就把刚写好的 RULES_PATH 删掉，而 .lastgood 从没
            #  创建过 —— 结果是磁盘上既没有旧规则也没有新规则。）
            print(f'[ERROR] 备份旧规则失败，已中止应用（避免无回滚材料时覆盖现有规则）: {e}',
                  flush=True)
            _unlink_quiet(tmp_path)
            return False, f'备份现有规则失败，已中止应用（未改动现有规则）: {e}'
        # 备份必须真的可读。copy 返回成功不等于内容写全了（磁盘满、权限、
        # 配额都可能），拿一个打不开的备份当回滚材料比没有更危险。
        try:
            with open(lastgood, 'rb') as bf:
                bf.read(1)
        except OSError as e:
            print(f'[ERROR] 备份校验失败，已中止应用: {e}', flush=True)
            _unlink_quiet(tmp_path)
            return False, f'备份现有规则校验失败，已中止应用（未改动现有规则）: {e}'
    os.replace(tmp_path, RULES_PATH)

    # 3. 首次应用前额外备份一次完整 ruleset（仅当两个 backup 都不存在时）
    if not os.path.exists(RULES_PATH + '.backup') \
            and not os.path.exists('/etc/nftables.d/99-custom-rules.nft.backup'):
        try:
            # 注意：stdout= 与 capture_output=True 互斥，同时传会抛
            # TypeError("stdout and stderr arguments may not be used with
            # capture_output")，导致这份备份从来就没成功写过
            with open('/etc/nftables.d/99-custom-rules.nft.backup', 'w') as bf:
                r = subprocess.run(['nft', 'list', 'ruleset'], stdout=bf,
                                   stderr=subprocess.PIPE, timeout=5)
            if r.returncode != 0:
                print(f'[WARN] 备份完整 ruleset 返回码非 0: {r.returncode}', flush=True)
        except Exception as e:
            print(f'[WARN] 备份完整 ruleset 失败: {e}', flush=True)

    # 4. 确保 fw4 已停止
    # 兜住异常：/etc/init.d/firewall 不存在（fw4 未安装 / 非 OpenWrt 系统）时
    # 不应让整个规则应用崩掉 —— 自有规则集本来就不依赖 fw4 才能加载
    try:
        subprocess.run(['/etc/init.d/firewall', 'stop'],
                       capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        print(f'[WARN] 停止 fw4 失败（继续按自有规则加载）: {type(e).__name__}: {e}',
              flush=True)

    # 5. 执行 nft -f；失败必须回滚，绝不能把路由器留在「fw4 已停 + 规则没装」的空档
    try:
        result = subprocess.run(['nft', '-f', RULES_PATH],
                                capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        result = None
    if result is None or result.returncode != 0:
        if not had_old:
            _unlink_quiet(RULES_PATH)
        state, state_msg = _restore_lastgood_rules()
        detail = (result.stderr or result.stdout) if result is not None else "nft -f 超时"
        return False, f"nft -f 失败，{state_msg}：{detail}"

    # 6. 应用成功后，静默确保 IPv6 自动更新 cron 已安装
    try:
        _ensure_ipv6_cron()
    except Exception as e:
        print(f'[WARN] 安装 IPv6 cron 失败: {e}', flush=True)
    return True, "规则已应用"


@app.route('/api/rules/apply', methods=['POST'])
def apply_rules():
    """保存规则并执行 nft -f（先校验后写盘，失败自动回滚）"""
    config = load_config()
    # 配置损坏时 load_config 返回的是硬编码 DEFAULT_CONFIG（内含他人网段）。
    # 直接拿它下发规则 = 把陌生网段写进真实防火墙，而且回报 success: true。
    refused = _config_corrupted_response()
    if refused is not None:
        return refused
    ok, message = _apply_ruleset(config)
    if not ok:
        # 语法类问题算客户端错误，其余算服务端错误
        code = 400 if ("语法" in message or "超时" in message) else 500
        return jsonify({"success": False, "message": message}), code
    return jsonify({"success": True, "message": message})


# IPv6 自动更新脚本：安装路径与 cron 频率必须全局唯一。
# 原来 _ensure_ipv6_cron 用 */10、install_ipv6_cron 用 0 * * * *，
# 且各自只删「完全等于自己那行」的条目，两边都跑过就会留下重复 cron。
IPV6_SCRIPT_PATH = '/opt/nftables-web/update-ipv6.sh'
IPV6_CRON_ENTRY = f'*/10 * * * * {IPV6_SCRIPT_PATH}'


def _upsert_cron_for(script_path, cron_entry):
    """把某个脚本的 cron 条目写成唯一一条：先按脚本路径删掉所有历史条目再追加。

    返回 (ok, message)。按「脚本路径」而不是「整行」去重，
    这样即使历史上装了不同频率的条目也能收敛成一条。
    """
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
        lines = result.stdout.splitlines() if result.returncode == 0 else []
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return False, f"读取 crontab 失败: {e}"
    lines = [ln for ln in lines if script_path not in ln]
    if cron_entry:
        lines.append(cron_entry)
    try:
        proc = subprocess.run(['crontab', '-'], input='\n'.join(lines) + '\n',
                              capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return False, f"写入 crontab 失败: {e}"
    if proc.returncode != 0:
        return False, f"crontab 更新失败: {(proc.stderr or proc.stdout).strip()}"
    return True, "crontab 已更新"


def _ensure_ipv6_cron():
    """静默确保 IPv6 自动更新脚本和 crontab 已就绪（幂等）"""
    os.makedirs(os.path.dirname(IPV6_SCRIPT_PATH), exist_ok=True)
    with open(IPV6_SCRIPT_PATH, 'w') as f:
        f.write(IPV6_CRON_SCRIPT)
    os.chmod(IPV6_SCRIPT_PATH, 0o755)

    ok, msg = _upsert_cron_for(IPV6_SCRIPT_PATH, IPV6_CRON_ENTRY)
    if not ok:
        print(f'[WARN] IPv6 cron 配置失败: {msg}', flush=True)
    return ok


# === IPv6 辅助函数和 API ===

def _get_wan_ipv6_prefix():
    """获取公网 IPv6 前缀（前4段）和完整地址，优先从 WAN 接口获取，回退到 LAN 接口"""
    config = load_config()
    wan_if = config.get("wan_if", "pppoe-wan")
    lan_if = config.get("lan_if", "br-lan")

    def _extract_from_interface(ifname):
        """从指定接口提取 scope global 的 IPv6 地址和前缀"""
        result = subprocess.run(
            ['ip', '-6', 'addr', 'show', ifname],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if 'scope global' in line:
                parts = line.split()
                if 'inet6' in parts:
                    idx = parts.index('inet6')
                    addr_full = parts[idx + 1].split('/')[0]
                    if addr_full and addr_full != '::':
                        segments = addr_full.split(':')
                        prefix = ':'.join(segments[:4])
                        return addr_full, prefix
        return "", ""

    full_addr, prefix = _extract_from_interface(wan_if)
    source = "wan"
    if not full_addr:
        full_addr, prefix = _extract_from_interface(lan_if)
        source = "lan" if full_addr else "none"
    return {"full_addr": full_addr, "prefix": prefix, "source": source}


def _extract_ipv6_suffix(addr):
    """提取 IPv6 地址的最后4段作为后缀"""
    segments = addr.split(':')
    if len(segments) < 4:
        return ""
    return ':'.join(segments[-4:])


@app.route('/api/network/wan-ipv6', methods=['GET'])
def get_wan_ipv6():
    """获取 WAN 接口的公网 IPv6 信息"""
    try:
        info = _get_wan_ipv6_prefix()
        if not info["full_addr"]:
            return jsonify({"success": False, "message": "WAN 接口无公网 IPv6 地址"}), 404
        return jsonify({"success": True, **info})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/network/update-ipv6', methods=['POST'])
def update_ipv6():
    """更新 nas_ip6 合集：拼接 WAN 前缀 + 各规则 IPv6 后缀"""
    try:
        config = load_config()
        wan_info = _get_wan_ipv6_prefix()
        if not wan_info["prefix"]:
            return jsonify({"success": False, "message": "WAN 接口无公网 IPv6 前缀，无法更新"}), 400

        prefix = wan_info["prefix"]
        forward_rules = config.get("forward_rules", [])
        updated = []
        failed = []
        skipped = []

        # 与 IPV6_CRON_SCRIPT 保持一致：写路由器本机地址，供 DDNS 的
        # ip_script 读。之前只有 cron 脚本写这个文件，手动点「更新 IPv6」
        # 只改了内核 set，/tmp/ddns-ipv6-* 始终是空的 —— 阿里云 DDNS 和
        # 通用 DDNS（ip_script=/bin/cat /tmp/ddns-ipv6-N）读到的还是旧值，
        # IPv6 记录静默停在过期地址上，没有任何报错。
        try:
            with open("/tmp/ddns-ipv6-0", "w") as f:
                f.write(f"{prefix}::1")
        except OSError as e:
            print(f"[WARN] 写 /tmp/ddns-ipv6-0 失败: {e}", flush=True)

        for idx, rule in enumerate(forward_rules, 1):
            set_name = f"nas_ip6_{idx}"
            target_ipv6 = rule.get("target_ipv6", "").strip()
            suffix = _extract_ipv6_suffix(target_ipv6) if target_ipv6 else ""

            if not target_ipv6 or not suffix:
                # 没配 IPv6 目标的规则：仍然要清空它的 set（配过的地址可能
                # 已经被删掉了），但不算「失败」。
                skipped.append({
                    "set_name": set_name,
                    "target_ipv6": target_ipv6,
                    "reason": "未配置 target_ipv6，已清空该集合",
                })
                _nft_set_write(['flush', 'set', 'inet', 'fw4', set_name])
                continue

            full_ipv6 = f"{prefix}:{suffix}"

            # flush 与 add 放进**同一个 nft 事务**。
            #
            # 原来是先 nft flush set 再 nft add element 两条独立命令：
            # add 失败时（比如地址格式被内核拒了）set 已经空了 —— 原来那条
            # 还能用的 IPv6 地址被清掉、新地址没加上，而接口照样回
            # 「已更新 N 条」。IPv6 访问静默失效，界面上是绿的。
            #
            # nft -f 是整份文件一个事务：任一行失败则整体不生效，
            # 旧地址原地不动。
            batch = (f"flush set inet fw4 {set_name}\n"
                     f"add element inet fw4 {set_name} {{ {full_ipv6} }}\n")
            try:
                with _FW_APPLY_LOCK:
                    result = subprocess.run(['nft', '-f', '-'], input=batch,
                                            capture_output=True, text=True,
                                            timeout=10)
            except subprocess.TimeoutExpired:
                result = None

            if result is not None and result.returncode == 0:
                updated.append({
                    "set_name": set_name,
                    "target_ipv6": target_ipv6,
                    "suffix": suffix,
                    "full_ipv6": full_ipv6,
                    "success": True,
                    "error": None,
                })
                # 与 cron 脚本一样把完整地址落到中转文件，DDNS 才读得到
                try:
                    with open(f"/tmp/ddns-ipv6-{idx}", "w") as f:
                        f.write(full_ipv6)
                except OSError as e:
                    print(f"[WARN] 写 /tmp/ddns-ipv6-{idx} 失败: {e}", flush=True)
            else:
                err = ('nft 命令超时' if result is None
                       else (result.stderr or result.stdout or '').strip()
                       [:200])
                print(f"[ERROR] {set_name} 更新失败（{full_ipv6}）：{err}", flush=True)
                failed.append({
                    "set_name": set_name,
                    "target_ipv6": target_ipv6,
                    "full_ipv6": full_ipv6,
                    "error": err or '未知错误',
                })

        # 汇总口径必须是「成功的条数」，不是「尝试的条数」。
        # 之前这里 len(updated) 数的是尝试，3 条里第 2 条失败也报「已更新 3 条」，
        # 顶层 success 还无条件是 True —— 前端只弹这个 message，
        # 逐条的 success/error 根本没人读。
        if failed:
            message = (f"成功 {len(updated)} 条，失败 {len(failed)} 条："
                       + "、".join(f['set_name'] for f in failed))
        else:
            message = f"已更新 {len(updated)} 条 IPv6 地址"
            if skipped:
                message += f"（{len(skipped)} 条未配置 IPv6 目标，已清空）"

        return jsonify({
            "success": not failed,
            "prefix": prefix,
            "updated": updated,
            "failed": failed,
            "skipped": skipped,
            "succeeded_count": len(updated),
            "failed_count": len(failed),
            "message": message,
        }), (200 if not failed else 500)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


IPV6_CRON_SCRIPT = '''#!/bin/sh
# IPv6 合集自动更新脚本 - 由 nftables-web 生成
# 从 nftables-web 配置读取 IPv6 后缀，拼接 WAN 前缀后更新各规则对应的 nas_ip6_{i} 合集
CONFIG="/etc/nftables/nftables-web-config.json"
WAN_IF=$(jsonfilter -e '$.wan_if' $CONFIG 2>/dev/null || echo "pppoe-wan")
LAN_IF=$(jsonfilter -e '$.lan_if' $CONFIG 2>/dev/null || echo "br-lan")
PREFIX=$(ip -6 addr show dev "$WAN_IF" scope global 2>/dev/null | grep 'inet6' | head -1 | awk '{print $2}' | cut -d: -f1-4)
if [ -z "$PREFIX" ]; then
    PREFIX=$(ip -6 addr show dev "$LAN_IF" scope global 2>/dev/null | grep 'inet6' | head -1 | awk '{print $2}' | cut -d: -f1-4)
fi

if [ -z "$PREFIX" ]; then exit 0; fi

# 写入路由器本机 IPv6（DDNS 用）
echo -n "$PREFIX::1" > /tmp/ddns-ipv6-0

# 从配置读取每条规则的 target_ipv6 后缀，拼接并添加到对应的 nas_ip6_{i} 合集
# 使用 python3 解析 JSON（OpenWrt jsonfilter 不支持 [*] 通配符）
python3 - "$CONFIG" "$PREFIX" << 'PYEOF'
import json, subprocess, sys
config_path, prefix = sys.argv[1], sys.argv[2]
with open(config_path) as f:
    config = json.load(f)
for i, rule in enumerate(config.get("forward_rules", []), 1):
    set_name = f"nas_ip6_{i}"
    subprocess.run(["nft", "flush", "set", "inet", "fw4", set_name],
                   capture_output=True, timeout=10)
    suffix = rule.get("target_ipv6", "").strip()
    if not suffix:
        continue
    parts = suffix.split(":")
    suffix_4 = ":".join(parts[-4:]) if len(parts) >= 4 else ""
    if not suffix_4:
        continue
    full = f"{prefix}:{suffix_4}"
    subprocess.run(["nft", "add", "element", "inet", "fw4", set_name, "{", full, "}"],
                   capture_output=True, timeout=10)
    with open(f"/tmp/ddns-ipv6-{i}", "w") as f:
        f.write(full)
PYEOF
'''


@app.route('/api/scripts/update-ipv6.sh', methods=['GET'])
def get_ipv6_script():
    """返回 IPv6 自动更新脚本内容"""
    return IPV6_CRON_SCRIPT, 200, {'Content-Type': 'text/x-shellscript'}


@app.route('/api/network/install-ipv6-cron', methods=['POST'])
def install_ipv6_cron():
    """安装 IPv6 自动更新脚本到 crontab"""
    try:
        os.makedirs(os.path.dirname(IPV6_SCRIPT_PATH), exist_ok=True)
        with open(IPV6_SCRIPT_PATH, 'w') as f:
            f.write(IPV6_CRON_SCRIPT)
        os.chmod(IPV6_SCRIPT_PATH, 0o755)

        # 与 _ensure_ipv6_cron 共用同一条目并按脚本路径去重，不会装出重复 cron
        ok, msg = _upsert_cron_for(IPV6_SCRIPT_PATH, IPV6_CRON_ENTRY)
        if not ok:
            return jsonify({"success": False, "message": f"crontab 更新失败: {msg}"}), 500

        return jsonify({
            "success": True,
            "message": f"脚本已安装到 {IPV6_SCRIPT_PATH}，crontab 已配置每 10 分钟执行",
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


CHINA_IPS_SCRIPT = '''#!/bin/sh
# 中国IP集合自动更新脚本
# 从 GitHub 下载中国IP列表，转换为 nftables 集合格式
NFT_FILE="/etc/nftables/china-ips.nft"
URL="https://cdn.jsdelivr.net/gh/17mon/china_ip_list@master/china_ip_list.txt"

TMP=$(mktemp)
wget -qO "$TMP" "$URL" 2>/dev/null
if [ ! -s "$TMP" ]; then
    echo "下载失败"
    rm -f "$TMP"
    exit 1
fi

mkdir -p /etc/nftables

# 生成 nftables 文件：先清空合集，再逐条添加
echo "# 中国IP集合 - 自动生成 $(date)" > "$NFT_FILE"
echo "flush set inet fw4 china_ipv4" >> "$NFT_FILE"

COUNT=0
ELEMENTS=""
while IFS= read -r line; do
    line=$(echo "$line" | tr -d '\\r' | grep -oE '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+(/[0-9]+)?')
    if [ -n "$line" ]; then
        if [ -n "$ELEMENTS" ]; then
            ELEMENTS="${ELEMENTS}, "
        fi
        ELEMENTS="${ELEMENTS}${line}"
        COUNT=$((COUNT+1))
        # 每500条flush一次避免单行过长
        if [ $((COUNT % 500)) -eq 0 ]; then
            echo "add element inet fw4 china_ipv4 { ${ELEMENTS} }" >> "$NFT_FILE"
            ELEMENTS=""
        fi
    fi
done < "$TMP"

# 写入剩余的
if [ -n "$ELEMENTS" ]; then
    echo "add element inet fw4 china_ipv4 { ${ELEMENTS} }" >> "$NFT_FILE"
fi

rm -f "$TMP"
echo "完成，共 $COUNT 条中国IP，已写入 $NFT_FILE"
echo "请执行: nft -f /etc/nftables/china-ips.nft"
'''


@app.route('/api/firewall/china-ips-script', methods=['GET'])
def get_china_ips_script():
    """返回中国IP自动更新脚本内容"""
    return CHINA_IPS_SCRIPT, 200, {'Content-Type': 'text/x-shellscript'}


@app.route('/api/firewall/update-china-ips', methods=['POST'])
def update_china_ips():
    """手动触发执行中国IP更新脚本"""
    script_path = '/opt/nftables-web-v2/update-china-ips.sh'
    if not os.path.exists(script_path):
        return jsonify({"success": False, "message": "脚本未安装，请先执行安装"}), 400
    try:
        result = subprocess.run(
            ['sh', script_path],
            capture_output=True, text=True, timeout=120
        )
        return jsonify({
            "success": result.returncode == 0,
            "message": result.stdout.strip(),
            "error": result.stderr.strip() if result.returncode != 0 else None,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "脚本执行超时（120秒）"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/firewall/install-china-ips', methods=['POST'])
def install_china_ips():
    """安装中国IP自动更新脚本到 crontab 并立即执行一次"""
    try:
        # 检查国外IP拦截是否启用
        config = load_config()
        if not config.get("china_ip_block", True):
            return jsonify({"success": False, "message": "国外IP拦截未启用，无需安装"}), 400

        script_path = '/opt/nftables-web-v2/update-china-ips.sh'
        os.makedirs(os.path.dirname(script_path), exist_ok=True)

        with open(script_path, 'w') as f:
            f.write(CHINA_IPS_SCRIPT)
        os.chmod(script_path, 0o755)

        # 添加 crontab：每周一凌晨3点执行
        cron_entry = '0 3 * * 1 /opt/nftables-web-v2/update-china-ips.sh'
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
        existing = result.stdout.splitlines()
        if cron_entry not in existing:
            existing.append(cron_entry)
            proc = subprocess.run(['crontab', '-'], input='\n'.join(existing) + '\n',
                                  capture_output=True, text=True, timeout=10)
            if proc.returncode != 0:
                return jsonify({"success": False, "message": f"crontab 更新失败: {proc.stderr}"}), 500

        # 自动执行一次
        run_result = subprocess.run(
            ['sh', script_path],
            capture_output=True, text=True, timeout=120
        )

        return jsonify({
            "success": True,
            "script_path": script_path,
            "cron": cron_entry,
            "run_output": run_result.stdout.strip(),
            "run_error": run_result.stderr.strip() if run_result.returncode != 0 else None,
            "run_success": run_result.returncode == 0,
            "message": "脚本已安装，crontab 已配置每周一凌晨3点执行" + ("，首次执行成功" if run_result.returncode == 0 else "，首次执行失败"),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "脚本执行超时（120秒）"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# === DDNS 配置 ===

DDNS_PROVIDER_NAMES = {
    "cloudflare.com-v4": "Cloudflare",
    "dnspod.cn": "DNSPod 腾讯云（2.0旧版）",
    "dnspod.cn-v3": "DNSPod 腾讯云 3.0",
    "dnspod-v3.tencentcloudapi.com": "DNSPod 腾讯云 3.0",
    "huaweicloud.com": "华为云",
    "cloud.google.com-v1": "Google Cloud DNS",
    "google.com": "Google Domains",
    "godaddy.com-v1": "GoDaddy",
    "no-ip.com": "No-IP",
    "gandi.net": "Gandi",
    "freedns.42.pl": "FreeDNS",
    "porkbun.com": "Porkbun",
    "digitalocean.com": "DigitalOcean",
}

DDNS_PROVIDER_DIR = '/usr/share/ddns/default'
DDNS_CONFIG_PATH = '/etc/config/ddns'
DDNS_INIT_SCRIPT = '/etc/init.d/ddns'


def _mask_password(pwd):
    """密码掩码：长度>4 显示前2后2，否则显示****"""
    if not pwd:
        return ''
    if len(pwd) > 4:
        return pwd[:2] + '****' + pwd[-2:]
    return '****'


def _parse_ddns_config():
    """解析 uci show ddns 输出，返回 service 列表"""
    try:
        result = subprocess.run(['uci', 'show', 'ddns'], capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    services = {}
    for line in result.stdout.strip().splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        value = value.strip("'\"")
        parts = key.split('.', 2)
        if len(parts) < 2 or parts[0] != 'ddns':
            continue
        name = parts[1]
        if len(parts) == 2 and value == 'service':
            services[name] = {
                'name': name, 'enabled': False, 'use_ipv6': False,
                'service_name': '', 'lookup_host': '', 'domain': '',
                'username': '', 'password': '', 'interface': '',
                'ip_source': '', 'ip_network': '', 'param_enc': '', 'param_opt': '',
                'ipv6_source': '', 'ip_script': '',
                'sub_domain': '', 'main_domain': '',
            }
        elif len(parts) == 3 and name in services:
            field = parts[2]
            if field in ('enabled', 'use_ipv6'):
                services[name][field] = value == '1'
            elif field in services[name]:
                services[name][field] = value

    svc_list = list(services.values())
    for svc in svc_list:
        svc['password'] = _mask_password(svc['password'])
        # 从 ip_script 反推 ipv6_source
        ip_script = svc.get('ip_script', '')
        if svc.get('ip_source') == 'script' and '/tmp/ddns-ipv6-' in ip_script:
            idx = ip_script.split('/tmp/ddns-ipv6-')[-1]
            svc['ipv6_source'] = 'router' if idx == '0' else f'rule_{idx}'
        # 从 UCI domain 值反向拆分为 sub_domain 和 main_domain
        domain_val = svc.get('domain', '')
        sub_domain = ''
        main_domain = ''
        service_name = svc.get('service_name', '')
        if service_name == 'google.com':
            # FQDN 格式: host.example.com
            parts = domain_val.rsplit('.', 1)
            if len(parts) == 2:
                sub_domain = parts[0]
                main_domain = parts[1]
            else:
                main_domain = domain_val
        else:
            # @ 分隔格式: host@maindomain 或 @maindomain（主域名本身）
            if domain_val.startswith('@'):
                sub_domain = '@'
                main_domain = domain_val[1:].lstrip('.')
            elif '@' in domain_val:
                sub_domain, main_domain = domain_val.split('@', 1)
            else:
                # 无 @ 说明只有主域名或旧格式
                parts = domain_val.rsplit('.', 1)
                if len(parts) == 2:
                    sub_domain = parts[0]
                    main_domain = parts[1]
                else:
                    main_domain = domain_val
        svc['sub_domain'] = sub_domain
        svc['main_domain'] = main_domain
    return svc_list


def _uci_set(key, value):
    """执行 uci set。

    值**完全不要加引号** —— uci 自己按第一个 `=` 分割并处理转义，
    手动加引号反而会把它当成值的一部分。

    2026-10-06 在 .224 上逐条实测（括号内是 `uci get` 的读回结果）：
        set k=250            → 250        ✅
        set k=%F %R          → %F %R      ✅（含空格也没问题）
        set k=三重双引号pw   → 原样保留    ✅（ddns 密码的写法）
        set k=it's           → it's       ✅
        set k=a=b / a\\b / a;b → 原样保留   ✅
    而加引号的写法会出事：
        set k="250"          → "250"      ❌ 引号进了值
        set k='%F %R'        → 双重包裹   ❌
    前者会让 ddns-scripts 的 $((ddns_loglines + 1)) 报 arithmetic syntax error，
    DDNS 永远起不来。

    必须剥掉换行：值里带换行会被 uci 当成新的一条指令，
    造成 UCI 配置注入（domain/param_opt 等用户字段未过滤）。其余字符
    （引号、等号、分号、反斜杠）实测都由 uci 正确处理，不需要我们转义。

    注意：本函数的文档字符串里刻意不写三连引号序列，否则会提前闭合 docstring。
    """
    if value is None:
        safe_val = ''
    else:
        safe_val = str(value).replace('\n', ' ').replace('\r', ' ')
    return subprocess.run(['uci', '-q', 'set', f'{key}={safe_val}'],
                          capture_output=True, text=True, timeout=10)


# === DDNS API ===

@app.route('/api/ddns/ipv6-sources', methods=['GET'])
def get_ddns_ipv6_sources():
    """返回可用的 IPv6 来源列表（根据 forward_rules 动态生成）"""
    sources = [{"id": "router", "name": "路由器本机 IPv6"}]
    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        rules = config.get('forward_rules', [])
        for i, rule in enumerate(rules):
            target = rule.get('target_ip', f'规则{i+1}')
            sources.append({"id": f"rule_{i+1}", "name": f"转发规则 {i+1}"})
    except Exception:
        pass
    return jsonify({"success": True, "sources": sources})


@app.route('/api/ddns/providers', methods=['GET'])
def get_ddns_providers():
    """获取已安装的 DDNS 服务商列表"""
    providers = []
    if os.path.isdir(DDNS_PROVIDER_DIR):
        for fname in os.listdir(DDNS_PROVIDER_DIR):
            if not fname.endswith('.json'):
                continue
            provider_id = fname[:-5]  # 去掉 .json
            display_name = DDNS_PROVIDER_NAMES.get(provider_id, provider_id)
            providers.append({'id': provider_id, 'name': display_name})
    providers.sort(key=lambda x: x['name'])
    return jsonify({"success": True, "providers": providers})


@app.route('/api/ddns/config', methods=['GET'])
def get_ddns_config():
    """获取 DDNS 配置列表"""
    try:
        services = _parse_ddns_config()
        # 读取当前 IPv6 地址文件
        ipv6_addresses = {}
        for i in range(10):
            key = 'router' if i == 0 else f'rule_{i}'
            try:
                with open(f'/tmp/ddns-ipv6-{i}') as f:
                    ipv6_addresses[key] = f.read().strip()
            except Exception:
                pass
        return jsonify({"success": True, "services": services, "ipv6_addresses": ipv6_addresses})
    except Exception as e:
        return jsonify({"success": False, "message": f"读取 DDNS 配置失败: {str(e)}"}), 500


@app.route('/api/ddns/save', methods=['POST'])
def save_ddns_config():
    """保存 DDNS 配置（先清除所有 service，再重建）"""
    data = request.get_json(silent=True)
    if not data or 'services' not in data:
        return jsonify({"success": False, "message": "请求体缺少 services 字段"}), 400

    services = data['services']
    try:
        # 1. 先获取现有的 service 名称和密码缓存
        existing = _parse_ddns_config()
        # 缓存原始密码（掩码值跳过写入时使用）
        import re as _re
        password_cache = {}
        for svc in existing:
            svc_name = svc.get('name', '')
            uci_name = _re.sub(r'[^a-zA-Z0-9_]', '_', svc_name) or svc_name
            # 从 UCI 读取原始未掩码密码
            result = subprocess.run(
                ['uci', '-q', 'get', f'ddns.{uci_name}.password'],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                password_cache[uci_name] = result.stdout.strip()

        # 2. 删除所有现有 service 块
        for svc in existing:
            subprocess.run(['uci', '-q', 'delete', f'ddns.{svc["name"]}'],
                           capture_output=True, text=True, timeout=10)

        # 3. 重建 global 块
        subprocess.run(['uci', 'set', 'ddns.global=ddns'],
                       capture_output=True, text=True, timeout=10)
        _uci_set('ddns.global.ddns_dateformat', '%F %R')
        _uci_set('ddns.global.ddns_loglines', '250')
        _uci_set('ddns.global.upd_privateip', '0')

        # 4. 添加每个 service
        for i, svc in enumerate(services):
            svc_name = svc.get('name', f'ddns_{i + 1}')
            # UCI section 名称只允许字母、数字、下划线，中文等无效
            uci_name = re.sub(r'[^a-zA-Z0-9_]', '_', svc_name) or f'ddns_{i + 1}'
            subprocess.run(['uci', 'set', f'ddns.{uci_name}=service'],
                           capture_output=True, text=True, timeout=10)
            _uci_set(f'ddns.{uci_name}.enabled', '1' if svc.get('enabled') else '0')
            _uci_set(f'ddns.{uci_name}.service_name', svc.get('service_name', ''))
            # 拼接域名
            sub = svc.get('sub_domain', '').strip()
            main = svc.get('main_domain', '').strip()
            service_name = svc.get('service_name', '')
            if service_name == 'google.com':
                domain_val = f"{sub}.{main}" if sub else main
                lookup_host = domain_val
            else:
                if sub == '@':
                    domain_val = f"@{main}"
                elif sub:
                    domain_val = f"{sub}@{main}"
                else:
                    domain_val = main
                lookup_host = f"{sub}.{main}" if sub and sub != '@' else main
            _uci_set(f'ddns.{uci_name}.domain', domain_val)
            _uci_set(f'ddns.{uci_name}.lookup_host', lookup_host)
            # Cloudflare API Token: username 自动设为 Bearer
            svc_username = svc.get('username', '')
            if 'cloudflare' in svc.get('service_name', ''):
                svc_username = 'Bearer'
            _uci_set(f'ddns.{uci_name}.username', svc_username)
            # 密码：如果包含掩码标记则从缓存还原原始密码。
            # 注意：这里绝对不能用 continue —— 密码只是 20 个字段之一，
            # continue 会连带跳过后面 interface/ip_source/ip_script/use_ipv6/
            # param_enc/check_interval/dns_server 等全部配置，
            # 造成「接口返回保存成功但该条 DDNS 记录配置残缺、静默不更新」。
            pwd = svc.get('password', '')
            if '****' in str(pwd):
                cached_pwd = password_cache.get(uci_name, '')
                pwd = cached_pwd if cached_pwd else ''   # 取不到就留空，不中断循环
            _uci_set(f'ddns.{uci_name}.password', pwd)
            _uci_set(f'ddns.{uci_name}.interface', svc.get('interface', 'wan'))
            ipv6_source = svc.get('ipv6_source', '')
            if svc.get('use_ipv6') and ipv6_source:
                # 映射 ipv6_source 到 ip_script
                _uci_set(f'ddns.{uci_name}.ip_source', 'script')
                idx = '0' if ipv6_source == 'router' else ipv6_source.replace('rule_', '')
                _uci_set(f'ddns.{uci_name}.ip_script', f'/bin/cat /tmp/ddns-ipv6-{idx}')
                _uci_set(f'ddns.{uci_name}.ipv6_source', ipv6_source)
            else:
                _uci_set(f'ddns.{uci_name}.ip_source', svc.get('ip_source', 'network'))
                _uci_set(f'ddns.{uci_name}.ipv6_source', '')
            _uci_set(f'ddns.{uci_name}.ip_network', svc.get('ip_network', 'wan'))
            _uci_set(f'ddns.{uci_name}.use_ipv6', '1' if svc.get('use_ipv6') else '0')
            _uci_set(f'ddns.{uci_name}.param_enc', svc.get('param_enc', ''))
            _uci_set(f'ddns.{uci_name}.param_opt', svc.get('param_opt', ''))
            # ddns-scripts 必需的运行参数
            check_interval = svc.get('check_interval', 10)
            _uci_set(f'ddns.{uci_name}.check_interval', str(check_interval))
            _uci_set(f'ddns.{uci_name}.check_unit', 'minutes')
            _uci_set(f'ddns.{uci_name}.force_interval', '72')
            _uci_set(f'ddns.{uci_name}.force_unit', 'hours')
            _uci_set(f'ddns.{uci_name}.retry_interval', '60')
            _uci_set(f'ddns.{uci_name}.retry_interval_unit', 'seconds')
            _uci_set(f'ddns.{uci_name}.retry_max_count', '0')
            # 使用外部 DNS 查询注册 IP，避免本地 DNS 缓存导致检测不到变化
            _uci_set(f'ddns.{uci_name}.dns_server', '1.1.1.1')

        # 5. commit
        result = subprocess.run(['uci', 'commit', 'ddns'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return jsonify({"success": False, "message": f"uci commit 失败: {result.stderr}"}), 500

        # 6. 确保 DDNS 服务已启用并重启（后台重启，避免阻塞）
        subprocess.run([DDNS_INIT_SCRIPT, 'enable'], capture_output=True, text=True, timeout=10)
        subprocess.Popen([DDNS_INIT_SCRIPT, 'restart'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return jsonify({"success": True, "message": f"已保存 {len(services)} 条 DDNS 记录"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "UCI 命令执行超时"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/ddns/restart', methods=['POST'])
def restart_ddns():
    """重启 DDNS 服务"""
    try:
        result = subprocess.run([DDNS_INIT_SCRIPT, 'restart'],
                                capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return jsonify({"success": False, "message": f"重启失败: {result.stderr or result.stdout}"}), 500
        return jsonify({"success": True, "message": "DDNS 服务已重启"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "DDNS 重启超时（15秒）"}), 500
    except FileNotFoundError:
        return jsonify({"success": False, "message": "DDNS 服务未安装"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/ddns/status', methods=['POST'])
def ddns_status():
    """获取 DDNS 服务状态和日志"""
    try:
        # 服务状态
        status_result = subprocess.run([DDNS_INIT_SCRIPT, 'status'],
                                       capture_output=True, text=True, timeout=10)
        running = status_result.returncode == 0

        # 日志
        log_result = subprocess.run(['logread', '-e', 'ddns'],
                                    capture_output=True, text=True, timeout=10)
        log_lines = log_result.stdout.strip().splitlines()[-50:] if log_result.stdout.strip() else []

        return jsonify({
            "success": True,
            "running": running,
            "status_output": status_result.stdout.strip(),
            "logs": log_lines,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "查询超时"}), 500
    except FileNotFoundError:
        return jsonify({"success": False, "message": "DDNS 服务未安装"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# === 阿里云 DDNS ===

ALIYUN_DDNS_CONFIG_PATH = '/etc/nftables/aliyun-ddns-config.json'


def _aliyun_mask_secret(secret):
    """AccessKey Secret 掩码"""
    if not secret:
        return ''
    if len(secret) > 6:
        return secret[:2] + '****' + secret[-2:]
    return '****'


def _load_aliyun_ddns_config():
    """加载阿里云 DDNS 配置"""
    if os.path.exists(ALIYUN_DDNS_CONFIG_PATH):
        with open(ALIYUN_DDNS_CONFIG_PATH, 'r') as f:
            return json.load(f)
    return None


def _save_aliyun_ddns_config(config):
    """保存阿里云 DDNS 配置"""
    os.makedirs(os.path.dirname(ALIYUN_DDNS_CONFIG_PATH), exist_ok=True)
    with open(ALIYUN_DDNS_CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    os.chmod(ALIYUN_DDNS_CONFIG_PATH, 0o600)


def _generate_ddns_update_script():
    """生成阿里云 DDNS 自动更新脚本"""
    script_path = "/opt/nftables-web-v2/aliyun-ddns-update.py"
    script_content = '''#!/usr/bin/env python3
"""阿里云 DDNS 自动更新脚本（由 nftables-web 生成）"""
import json, sys, os, urllib.request, urllib.parse, hmac, hashlib, base64, datetime, uuid

CONFIG_PATH = "/etc/nftables/aliyun-ddns-config.json"

def _sign(params, secret):
    qs = "&".join(f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe='')}" for k, v in sorted(params.items()))
    sts = "GET&" + urllib.parse.quote("/", safe='') + "&" + urllib.parse.quote(qs, safe='')
    return base64.b64encode(hmac.new((secret + "&").encode(), sts.encode(), hashlib.sha1).digest()).decode()

def _api(action, ak_id, ak_secret, region, extra={}):
    params = {"Action": action, "Format": "json", "Version": "2015-01-09", "AccessKeyId": ak_id,
              "SignatureMethod": "HMAC-SHA1", "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
              "SignatureVersion": "1.0", "SignatureNonce": str(uuid.uuid4()), "RegionId": region}
    params.update(extra)
    params["Signature"] = _sign(params, ak_secret)
    url = "https://alidns.aliyuncs.com/?" + "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params.items())
    with urllib.request.urlopen(urllib.request.Request(url), timeout=15) as resp:
        return json.loads(resp.read())

try:
    with open(CONFIG_PATH) as f:
        config = json.load(f)
    records = config.get("records", [])
    ak_id = config.get("access_key_id", "")
    ak_secret = config.get("access_key_secret", "")
    region = config.get("region_id", "cn-hangzhou")
    domain = config.get("domain", "")
    if not ak_id or not ak_secret or not domain:
        sys.exit(0)
    
    source_map = {"router": "0"}
    for i in range(1, 10):
        source_map[f"rule_{i}"] = str(i)
    
    for rec in records:
        if not rec.get("enabled"):
            continue
        rr = rec.get("rr", "")
        rtype = rec.get("type", "")
        ipv6_source = rec.get("ipv6_source", "")
        value = rec.get("value", "").strip()
        
        if ipv6_source:
            idx = source_map.get(ipv6_source)
            if idx is not None:
                try:
                    with open(f"/tmp/ddns-ipv6-{idx}") as f:
                        value = f.read().strip()
                except:
                    pass
            if not value:
                continue
        # A 记录自动获取路由器公网 IPv4
        if rtype == "A":
            try:
                import urllib.request as _ur
                _req = _ur.Request("https://ipv4.icanhazip.com")
                with _ur.urlopen(_req, timeout=5) as _r:
                    value = _r.read().decode().strip()
            except:
                pass
        if not value:
            continue
        
        # 查询现有记录，值相同则跳过
        result = _api("DescribeDomainRecords", ak_id, ak_secret, region, {"DomainName": domain, "RRKeyWord": rr, "Type": rtype})
        found_same = False
        for r in result.get("DomainRecords", {}).get("Record", []):
            if r.get("RR") == rr and r.get("Type") == rtype:
                if r.get("Value") == value:
                    found_same = True
                else:
                    _api("DeleteDomainRecord", ak_id, ak_secret, region, {"RecordId": str(r["RecordId"])})
                break
        if not found_same:
            _api("AddDomainRecord", ak_id, ak_secret, region, {"DomainName": domain, "RR": rr, "Type": rtype, "Value": value})
except Exception as e:
    with open("/tmp/aliyun-ddns-error.log", "a") as f:
        f.write(f"{datetime.datetime.now().isoformat()}: {e}\\n")
    sys.exit(1)
'''
    os.makedirs(os.path.dirname(script_path), exist_ok=True)
    with open(script_path, 'w') as f:
        f.write(script_content)
    os.chmod(script_path, 0o755)


def _manage_ddns_cron(config):
    """管理 DDNS 自动更新的 cron 条目，返回 (ok, message)"""
    cron_entry = "*/10 * * * * /opt/nftables-web-v2/aliyun-ddns-update.py"
    has_enabled = any(rec.get("enabled") for rec in config.get("records", []))

    # 读取当前 crontab（crontab -l 在无 crontab 时返回非 0，属正常情况）
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
        current_crontab = result.stdout if result.returncode == 0 else ""
    except Exception:
        current_crontab = ""

    # 删除旧的 DDNS cron 条目
    lines = [line for line in current_crontab.splitlines()
             if "aliyun-ddns-update.py" not in line]

    # 如果有启用的记录，追加新条目
    if has_enabled:
        lines.append(cron_entry)

    # 写回 crontab
    new_crontab = "\n".join(lines) + ("\n" if lines else "")
    try:
        proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True,
                              capture_output=True, timeout=10)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return False, f"crontab 命令执行失败: {e}"
    # 必须检查返回码：原来忽略失败，导致自动更新静默不生效
    if proc.returncode != 0:
        return False, f"crontab 写入失败: {(proc.stderr or proc.stdout).strip()}"
    return True, "crontab 已更新"


def _aliyun_sign(params, access_key_secret, method="GET"):
    """阿里云 API 签名"""
    import urllib.parse
    qs = "&".join(f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe='')}" for k, v in sorted(params.items()))
    string_to_sign = method + "&" + urllib.parse.quote("/", safe='') + "&" + urllib.parse.quote(qs, safe='')
    h = hmac.new((access_key_secret + "&").encode(), string_to_sign.encode(), hashlib.sha1)
    return base64.b64encode(h.digest()).decode()


def _aliyun_api(action, access_key_id, access_key_secret, region_id, extra_params={}):
    """调用阿里云 DNS API"""
    import urllib.request, urllib.parse
    params = {
        "Action": action,
        "Format": "json",
        "Version": "2015-01-09",
        "AccessKeyId": access_key_id,
        "SignatureMethod": "HMAC-SHA1",
        "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SignatureVersion": "1.0",
        "SignatureNonce": str(uuid.uuid4()),
        "RegionId": region_id,
    }
    params.update(extra_params)
    params["Signature"] = _aliyun_sign(params, access_key_secret)
    url = "https://alidns.aliyuncs.com/?" + "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params.items())
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _aliyun_ddns_update(config, rr, rtype, value):
    """通过阿里云 API 更新单条 DNS 记录（删除+添加，避免 RecordId 精度问题）"""
    domain = config['domain']
    ak_id = config['access_key_id']
    ak_secret = config['access_key_secret']
    region = config.get('region_id', 'cn-hangzhou')

    # 查询现有记录
    result = _aliyun_api("DescribeDomainRecords", ak_id, ak_secret, region, {
        "DomainName": domain,
        "RRKeyWord": rr,
        "Type": rtype,
    })
    records = result.get('DomainRecords', {}).get('Record', [])

    for r in records:
        if r.get('RR') == rr and r.get('Type') == rtype:
            if r.get('Value') == value:
                return {"success": True, "message": "IP 未变化，无需更新"}
            # 删除旧记录
            _aliyun_api("DeleteDomainRecord", ak_id, ak_secret, region, {
                "RecordId": r['RecordId'],
            })
            break

    # 添加新记录
    _aliyun_api("AddDomainRecord", ak_id, ak_secret, region, {
        "DomainName": domain,
        "RR": rr,
        "Type": rtype,
        "Value": value,
    })
    return {"success": True, "message": f"记录 {rr}.{rtype} 已更新为 {value}"}


@app.route('/api/aliyun-ddns/status', methods=['GET'])
def aliyun_ddns_status():
    """检查阿里云 DDNS 配置状态"""
    config = _load_aliyun_ddns_config()
    response = {
        "success": True,
        "cli_installed": True,  # 不再依赖 aliyun-cli
        "cli_configured": config is not None and bool(config.get('access_key_id')),
        "config_exists": config is not None,
    }

    if config:
        safe = dict(config)
        safe['access_key_secret'] = _aliyun_mask_secret(safe.get('access_key_secret', ''))
        response['config'] = safe
        response["records"] = config.get("records", [])

    return jsonify(response)


@app.route('/api/aliyun-ddns/setup', methods=['POST'])
def aliyun_ddns_setup():
    """配置阿里云 AccessKey"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400

    access_key_id = data.get('access_key_id', '').strip()
    access_key_secret = data.get('access_key_secret', '').strip()
    region_id = data.get('region_id', 'cn-hangzhou').strip()
    domain = data.get('domain', '').strip()

    if not access_key_id or not access_key_secret:
        return jsonify({"success": False, "message": "access_key_id 和 access_key_secret 不能为空"}), 400

    # 验证 AK 是否有效（尝试查询域名列表）
    try:
        _aliyun_api("DescribeDomains", access_key_id, access_key_secret, region_id)
    except Exception as e:
        return jsonify({"success": False, "message": f"AccessKey 验证失败: {str(e)}"}), 400

    # 保存到配置文件（合并已有配置）
    existing = _load_aliyun_ddns_config() or {}
    existing['access_key_id'] = access_key_id
    existing['access_key_secret'] = access_key_secret
    existing['region_id'] = region_id
    if domain:
        existing['domain'] = domain
    _save_aliyun_ddns_config(existing)

    return jsonify({"success": True, "message": "AccessKey 配置完成"})


@app.route('/api/aliyun-ddns/records', methods=['GET'])
def aliyun_ddns_records():
    """获取阿里云 DNS 记录列表"""
    config = _load_aliyun_ddns_config()
    if not config or not config.get('domain'):
        return jsonify({"success": False, "message": "请先配置域名（保存配置时设置 domain 字段）"}), 400

    domain = config['domain']

    try:
        output = _aliyun_api("DescribeDomainRecords",
                             config['access_key_id'], config['access_key_secret'],
                             config.get('region_id', 'cn-hangzhou'),
                             {"DomainName": domain})

        records = []
        for r in output.get('DomainRecords', {}).get('Record', []):
            records.append({
                'record_id': r.get('RecordId', ''),
                'rr': r.get('RR', ''),
                'type': r.get('Type', ''),
                'value': r.get('Value', ''),
            })

        # 合并本地配置（启用状态、IPv6 来源等）
        # 同时支持 record_id 和 rr+type 两种匹配方式
        local_records_map = {}
        for lr in config.get('records', []):
            key = lr.get('record_id', '') or f"{lr.get('rr','')}:{lr.get('type','')}"
            local_records_map[key] = lr

        for r in records:
            key1 = r.get('record_id', '')
            key2 = f"{r.get('rr','')}:{r.get('type','')}"
            local = local_records_map.get(key1) or local_records_map.get(key2) or {}
            r['enabled'] = local.get('enabled', False)
            r['ipv6_source'] = local.get('ipv6_source', '')

        # 返回配置（掩码）
        safe_config = dict(config)
        safe_config['access_key_secret'] = _aliyun_mask_secret(safe_config.get('access_key_secret', ''))

        return jsonify({
            "success": True,
            "records": records,
            "config": safe_config,
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/aliyun-ddns/save', methods=['POST'])
def aliyun_ddns_save():
    """保存阿里云 DDNS 配置"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400

    # 合并已有配置，避免前端只发 records 时覆盖凭证
    existing = _load_aliyun_ddns_config() or {}
    existing.update(data)
    # AAAA 记录 ipv6_source 为空时默认设为 router（路由器本机 IPv6）
    # 因为前端下拉默认选中第一项但实际值为空，@change 不会触发
    for rec in existing.get('records', []):
        if (rec.get('type') or rec.get('Type', '')) == 'AAAA' and not rec.get('ipv6_source'):
            rec['ipv6_source'] = 'router'
    # 统一大小写键，阿里云 API 返回 Type/RR/Value/RecordId，生成脚本使用小写
    for rec in existing.get('records', []):
        for big, small in [('Type','type'), ('RR','rr'), ('Value','value'), ('RecordId','record_id')]:
            if rec.get(big) and not rec.get(small):
                rec[small] = rec[big]
    # 如果 access_key_secret 是掩码值则保留原值
    if '****' in str(existing.get('access_key_secret', '')):
        old = _load_aliyun_ddns_config()
        if old:
            existing['access_key_secret'] = old.get('access_key_secret', '')

    _save_aliyun_ddns_config(existing)

    # 生成自动更新脚本
    _generate_ddns_update_script()

    # 管理 cron 条目（失败要如实告知，否则自动更新静默不生效）
    cron_ok, cron_msg = _manage_ddns_cron(existing)
    if not cron_ok:
        return jsonify({"success": False,
                        "message": f"配置已保存，但自动更新 cron 配置失败：{cron_msg}"}), 500

    return jsonify({"success": True, "message": "配置已保存"})


@app.route('/api/aliyun-ddns/test', methods=['POST'])
def aliyun_ddns_test():
    """测试单条 DNS 记录更新"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400

    rr = data.get('rr', '')
    rtype = data.get('type', '')
    ipv6_source = data.get('ipv6_source', '')
    value = data.get('value', '').strip()

    # 如果选择了 IPv6 来源且未手动输入值，从文件读取实际 IP
    if ipv6_source and not value:
        source_map = {"router": "0"}
        for i in range(1, 10):
            source_map[f"rule_{i}"] = str(i)
        idx = source_map.get(ipv6_source)
        if idx is not None:
            try:
                with open(f'/tmp/ddns-ipv6-{idx}') as f:
                    value = f.read().strip()
            except (IOError, OSError):
                pass

    if not all([rr, rtype, value]):
        return jsonify({"success": False, "message": "rr, type, value 都不能为空" + ("（IPv6 来源文件不存在或为空）" if ipv6_source and not value else "")}), 400

    config = _load_aliyun_ddns_config()
    if not config or not config.get('domain'):
        return jsonify({"success": False, "message": "请先配置域名"}), 400

    try:
        result = _aliyun_ddns_update(config, rr, rtype, value)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════
# 系统日志：logread + 认证审计 → 合并成一条时间线
# ══════════════════════════════════════════════════════════════════════

# 认证服务落盘的审计日志。路径写死，不接受请求参数 —— 见 _read_audit_events。
AUTH_AUDIT_LOG = "/var/log/nftables-web-auth.log"

# logread 输出： Tue Oct  6 18:52:41 2026 daemon.err dropbear[615]: Bad password ...
#
# 三处刻意的宽松，都是为了「宁可解析得糙，也不要静默丢行」——日志页一旦
# 悄悄少给几行，用户就没法信它了：
#   · 星期几和年份都是可选的。OpenWrt 的 logread 会输出星期，但 busybox
#     syslogd -L 落到文件里的就不一定有，不能把格式差异当成格式错误。
#   · facility 用 [\w.-]+ 贪婪匹配，再回溯找最后一个点。贪婪只在单个
#     token 内生效（字符类不含空白），所以 "my.app-name_v2.info" 能正确
#     拆成 facility=my.app-name_v2 / level=info，而 "daemon.err" 不会
#     被后面的消息内容带偏。
#   · 程序名和 pid 整段可选："kernel.crit " 这种没有 "prog:" 结构的
#     也能收下，而不是整行丢掉。
_SYSLOG_RE = re.compile(
    r"^(?:(?P<wday>\w{3})\s+)?(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hms>\d{2}:\d{2}:\d{2})(?:\s+(?P<year>\d{4}))?\s+"
    r"(?P<fac>[\w.-]+)\.(?P<lvl>[\w-]+)(?:\[\d+\])?\s+"
    r"(?:(?P<prog>\S+?)(?:\[(?P<pid>\d+)\])?:\s?)?(?P<msg>.*)$"
)

_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
           "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}

# 级别序，数字小的更严重。前端排序/筛选和导出都用它。
LOG_LEVEL_ORDER = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "error": 3,
                   "warn": 4, "warning": 4, "notice": 5, "info": 6, "debug": 7}

AUTH_SOURCE = "nftables-web-auth"

# 认证事件 → 日志级别。
# 刻意不含 verify_denied / token_refreshed：前者每个未认证请求都会触发，
# 后者每半个 TTL 一次。它们留在 JSONL 审计里，不进 syslog，
# 否则远程转发会被刷屏（转发配置见 /api/logd/config）。
AUTH_EVENT_LEVEL = {
    "login_ok": "info",
    "logout": "info",
    "login_fail": "warn",
    "lockout": "err",
}
AUTH_EVENT_TEXT = {
    "login_ok": "登录成功",
    "login_fail": "登录失败",
    "logout": "登出",
    "lockout": "来源被锁定",
}


def _mem_total_kb():
    """物理内存总量（KB）。给日志页算 log_size 占用比例用，读不到就返回 0。"""
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1])
    except (IOError, OSError, ValueError, IndexError):
        pass
    return 0


def _log_size_kb():
    """logd 内存环形缓冲上限（/etc/config/system 的 log_size，单位 KB）。

    logd 在启动时按这个值分配缓冲，运行中改配置不重启服务是不生效的 ——
    这是 /api/logd/config 保存时必须重启 log 的原因。
    返回 0 表示未设置，用 logd 自身默认值（OpenWrt 为 128KB）。
    """
    try:
        r = subprocess.run(["uci", "-q", "get", "system.@system[0].log_size"],
                           capture_output=True, text=True, timeout=10)
        return int(r.stdout.strip())
    except (ValueError, OSError, subprocess.SubprocessError):
        return 0


def _iso_from_syslog(m, now_year):
    """syslog 时间头 → (ISO 字符串, epoch)。解析不出来返回 (None, 0)。"""
    mon = _MONTHS.get(m.group("mon").lower())
    if not mon:
        return None, 0
    year = int(m.group("year")) if m.group("year") else now_year
    try:
        h, mi, sec = (int(x) for x in m.group("hms").split(":"))
        dt = datetime.datetime(year, mon, int(m.group("day")), h, mi, sec)
    except (ValueError, TypeError):
        return None, 0
    return dt.isoformat(timespec="seconds"), int(dt.timestamp())


def _read_audit_events(limit=2000):
    """读认证服务的 JSONL 审计日志，转成统一日志条目。

    路径**写死**：这里读的是 root 起的文件，路径一旦可由请求控制，
    就等于给了面板一个任意读文件的洞。
    单行坏掉就跳过：auth_gateway 的 audit() 被刻意写成「任何失败都不影响
    认证」，所以它的日志天生可能有半截行，不能因为一行坏就整个失败。
    """
    out = []
    try:
        with open(AUTH_AUDIT_LOG, "r", errors="replace") as f:
            raw_lines = f.readlines()
    except (IOError, OSError):
        return out          # 文件不存在 = 认证服务没写过 = 正常情况

    for line in (raw_lines[-limit:] if limit else raw_lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue

        event = str(rec.get("event") or "")[:64]
        level = AUTH_EVENT_LEVEL.get(event, "info")
        ts_raw = str(rec.get("ts") or "")
        try:
            dt = datetime.datetime.fromisoformat(ts_raw)
            ts, epoch = dt.isoformat(timespec="seconds"), int(dt.timestamp())
        except ValueError:
            ts, epoch = ts_raw, 0

        ip = str(rec.get("ip") or "")[:64]
        user = str(rec.get("user") or "")[:64]
        # 消息列给人读，结构化字段单独留给前端做徽章
        msg = AUTH_EVENT_TEXT.get(event, event)
        if user:
            msg += f"  user={user}"
        if ip:
            msg += f"  ip={ip}"

        out.append({
            "ts": ts,
            "epoch": epoch,
            "level": level,
            "source": AUTH_SOURCE,
            "kind": "auth",
            "facility": "auth",
            "pid": "",
            "message": msg,
            "event": event,
            "ip": ip,
            "user": user,
            "device": str(rec.get("device") or "")[:64],
            "fp": str(rec.get("fp") or "")[:64],
            "ua": str(rec.get("ua") or "")[:200],
            "uri": str(rec.get("uri") or "")[:200],
            "reason": str(rec.get("reason") or "")[:120],
        })
    return out


@app.route("/api/system/logs", methods=["GET"])
def get_system_logs():
    """系统日志 = logread 全量 + 认证审计，合并成一条按时间倒序的时间线。

    2026-10-06 在 .224 上实测后改版，原来那版有三个说不通的地方：
    1. 固定 `logread -l 5000`，但 log_size 默认才 128KB，环形缓冲写满后
       logread 实际只返回 1582 行，UI 却照样显示「共 N 条」，让人误以为是全量。
       现在把水位、已用字节、容量估算一起返回，前端顶部画出来。
    2. 只读 logread，认证服务的 /var/log/nftables-web-auth.log
       （login_ok / login_fail / logout，带设备指纹）面板一条都看不到 ——
       数据一直在采，只是没有出口。
    3. 时间戳直接透传 syslog 文本（"Tue Oct  6 18:52:41 2026"），
       排序和筛选都别扭。现在统一成 ISO。
    """
    try:
        lines = request.args.get("lines", 20000, type=int)
        lines = min(max(lines, 1), 20000)

        # 取全量而不是 logread -l N：水位要按整个缓冲区算，
        # 而 logread -l N 在缓冲写满时返回的就是全部，再 slice 一次是白费。
        result = subprocess.run(
            ["logread"], capture_output=True, text=True, timeout=20
        )
        if result.returncode != 0:
            return jsonify({
                "success": False,
                "message": result.stderr.strip() or "logread 执行失败"
            }), 500

        raw = result.stdout
        now_year = datetime.datetime.now().year
        entries = []
        sources = {}
        unparsed = 0

        for line in raw.split("\n"):
            if not line.strip():
                continue
            m = _SYSLOG_RE.match(line)
            ts, epoch = _iso_from_syslog(m, now_year) if m else (None, 0)
            if not ts:
                # 解析不了的照样计数返回。悄悄少几行，日志页就没法被信任了。
                unparsed += 1
                continue
            prog = (m.group("prog") or "—").strip()
            entries.append({
                "ts": ts,
                "epoch": epoch,
                "level": m.group("lvl").lower(),
                "source": prog,
                "kind": "syslog",
                "facility": m.group("fac"),
                "pid": m.group("pid") or "",
                "message": m.group("msg"),
            })
            sources[prog] = sources.get(prog, 0) + 1

        syslog_count = len(entries)

        for e in _read_audit_events():
            entries.append(e)
            sources[AUTH_SOURCE] = sources.get(AUTH_SOURCE, 0) + 1

        entries.sort(key=lambda e: e["epoch"], reverse=True)
        entries = entries[:lines]

        # 水位：真实上限是字节不是行数，实测 ≈86 字节/行，
        # 所以「还能装多少行」只能按当前平均行长估算，不能当成准数。
        size_kb = _log_size_kb()
        total_bytes = len(raw.encode("utf-8", "replace"))
        total_lines = raw.count("\n")
        cap_bytes = size_kb * 1024
        avg_bytes = (total_bytes / total_lines) if total_lines else 0
        est_lines = int(cap_bytes / avg_bytes) if (cap_bytes and avg_bytes) else 0

        sources = dict(sorted(sources.items(), key=lambda x: x[1], reverse=True))

        return jsonify({
            "success": True,
            "total": len(entries),
            "logs": entries,
            "sources": sources,
            "buffer": {
                "log_size_kb": size_kb,
                "used_bytes": total_bytes,
                "total_lines": total_lines,
                "used_pct": round(total_bytes / cap_bytes * 100, 1) if cap_bytes else 0,
                "est_capacity_lines": est_lines,
                "avg_bytes_per_line": round(avg_bytes, 1) if avg_bytes else 0,
                "mem_total_kb": _mem_total_kb(),
            },
            "auth_merged": len(entries) - syslog_count if syslog_count else 0,
            "unparsed": unparsed,
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500



# ── logd 远程日志转发配置 ──────────────────────────────────────────────
import re

@app.route("/api/logd/config", methods=["GET"])
def get_logd_config():
    """读取当前 logd 远程日志转发配置 + 环形缓冲上限"""
    try:
        result = subprocess.run(
            ["uci", "show", "system"], capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        config = {"success": True, "log_ip": "", "log_port": "", "log_proto": "",
                  "log_size": _log_size_kb()}
        for key, field in [
            ("system.@system[0].log_ip", "log_ip"),
            ("system.@system[0].log_port", "log_port"),
            ("system.@system[0].log_proto", "log_proto"),
        ]:
            m = re.search(rf"^{re.escape(key)}='(.*)'", output, re.MULTILINE)
            if m:
                config[field] = m.group(1)
        return jsonify(config)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# log_size 是 logd 的内存环形缓冲，单位 KB。范围按 OpenWrt 实际能给的范围给：
# 下限 16（太小几乎记不住东西），上限 8192（再大对家用路由器就是自杀）。
LOG_SIZE_MIN_KB = 16
LOG_SIZE_MAX_KB = 8192


@app.route("/api/logd/config", methods=["POST"])
def set_logd_config():
    """保存并应用 logd 配置（远程转发 + 环形缓冲大小）

    ⚠ log_size 只在 logd 启动时读取，改了必须重启 /etc/init.d/log 才生效，
    而 **重启会清空内存里的环形缓冲**（.224 实测 1580 行 → 1 行）。
    所以下面只要真的改了任何配置就重启，并如实告诉前端「缓冲已清空」，
    让 UI 能提示用户 —— 否则用户保存完回头看日志全没了却不知道是谁干的。
    """
    try:
        data = request.get_json(force=True)
        log_ip = data.get("log_ip", "").strip()
        log_port = data.get("log_port", "").strip()
        log_proto = data.get("log_proto", "").strip()

        # log_size 可选：前端不传就不动它，避免只改转发时误清缓冲
        raw_size = data.get("log_size", None)
        new_size = None
        if raw_size is not None and str(raw_size).strip() != "":
            try:
                new_size = int(str(raw_size).strip())
            except ValueError:
                return jsonify({"success": False,
                                "message": "log_size 必须是整数（KB）"}), 400
            if not (LOG_SIZE_MIN_KB <= new_size <= LOG_SIZE_MAX_KB):
                return jsonify({"success": False, "message":
                                f"log_size 需在 {LOG_SIZE_MIN_KB}–{LOG_SIZE_MAX_KB} KB 之间"}), 400

        # 如果 log_ip 为空，则删除转发配置
        fwd_changed = False
        if not log_ip:
            for key in [
                "system.@system[0].log_ip",
                "system.@system[0].log_port",
                "system.@system[0].log_proto",
            ]:
                r = subprocess.run(
                    ["uci", "get", key], capture_output=True, text=True, timeout=10
                )
                if r.returncode == 0 and r.stdout.strip():
                    fwd_changed = True
                subprocess.run(
                    ["uci", "delete", key], capture_output=True, text=True, timeout=10
                )
        else:
            # 验证 log_ip：简单 IP 格式
            ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
            if not re.match(ip_pattern, log_ip):
                return jsonify({"success": False, "message": "log_ip 格式无效"}), 400
            parts = log_ip.split(".")
            if any(not (0 <= int(p) <= 255) for p in parts):
                return jsonify({"success": False, "message": "log_ip 格式无效"}), 400

            # 验证 log_port：1-65535
            if log_port:
                if not log_port.isdigit() or not (1 <= int(log_port) <= 65535):
                    return jsonify({"success": False, "message": "log_port 必须是 1-65535 的数字"}), 400

            # 验证 log_proto
            if log_proto and log_proto not in ("tcp", "udp"):
                return jsonify({"success": False, "message": "log_proto 只允许 tcp 或 udp"}), 400

            for key, val in [
                ("system.@system[0].log_ip", log_ip),
                ("system.@system[0].log_port", log_port),
                ("system.@system[0].log_proto", log_proto),
            ]:
                r = subprocess.run(
                    ["uci", "-q", "get", key], capture_output=True, text=True, timeout=10
                )
                if not (r.returncode == 0 and r.stdout.strip() == val):
                    fwd_changed = True
                _uci_set(key, val)

        size_changed = False
        if new_size is not None:
            cur = _log_size_kb()
            if cur != new_size:
                _uci_set("system.@system[0].log_size", new_size)
                size_changed = True

        subprocess.run(["uci", "commit", "system"], timeout=10)

        restarted = False
        if fwd_changed or size_changed:
            subprocess.run(["/etc/init.d/log", "restart"], timeout=15)
            restarted = True

        msgs = []
        if size_changed:
            msgs.append(f"log_size 已改为 {new_size}KB")
        if fwd_changed:
            msgs.append("转发配置已保存" if log_ip else "转发配置已清除")
        if restarted:
            msgs.append("log 服务已重启（内存中的历史日志已清空）")
        if not msgs:
            msgs.append("配置未变化，未重启 log 服务")

        return jsonify({
            "success": True,
            "message": "；".join(msgs),
            "restarted": restarted,
            "buffer_cleared": restarted,
            "log_size": new_size if new_size is not None else _log_size_kb(),
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# === 黑白名单管理 API ===

VALID_SET_NAMES = {"allowed4", "allowed6", "blacklist4", "blacklist6"}

# 名单成员落盘路径。规则集以 `flush ruleset` 开头、每次应用都会整体重建，
# 只存在于内核 set 里的成员会被静默清空 —— 必须落盘并在生成时回填。
LISTS_PATH = '/etc/nftables/nftables-web-lists.json'
LISTS_LOCK_PATH = LISTS_PATH + '.lock'
# 锁降级告警只打一次，见 _lists_file_lock
_LISTS_LOCK_WARNED = False


@contextlib.contextmanager
def _lists_file_lock():
    """名单读-改-写的跨进程/跨线程排他锁（与 save_config 的 .lock 同一套做法）。

    锁失败（文件系统不支持 flock、目录不可写等）时退化为无锁继续 —— 名单只是
    便捷数据，不值得因为拿不到锁就把「加一个 IP」这种小操作整个拒掉。但每次都打
    警告会把日志刷爆，所以只打第一次：之后仍在无锁运行（唯一 tmp 路径保证不会写坏
    文件，丢的那一层只是并发时的更新丢失），状态没变就不必反复说。
    """
    global _LISTS_LOCK_WARNED
    lock_fd = None
    try:
        os.makedirs(os.path.dirname(LISTS_LOCK_PATH), exist_ok=True)
        lock_fd = os.open(LISTS_LOCK_PATH, os.O_CREAT | os.O_RDWR)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
    except Exception as e:   # noqa: BLE001
        if not _LISTS_LOCK_WARNED:
            _LISTS_LOCK_WARNED = True
            print(f'[WARNING] 名单加锁失败（{type(e).__name__}: {e}），本次起无锁执行', flush=True)
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass
            lock_fd = None
    try:
        yield
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


def load_lists():
    """读取落盘名单成员。

    返回 {set_name: [ip, ...]}。文件不存在/损坏时返回空结构并告警，
    不能让一次坏文件把整个名单读取路径搞崩（否则名单管理页整个不可用）。
    """
    empty = {n: [] for n in sorted(VALID_SET_NAMES)}
    if not os.path.exists(LISTS_PATH):
        return empty
    try:
        with open(LISTS_PATH, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f'[WARN] 名单文件读取失败（本次按空名单处理）: {e}', flush=True)
        return empty
    if not isinstance(data, dict):
        print(f'[WARN] 名单文件格式非法（本次按空名单处理）: {type(data).__name__}', flush=True)
        return empty
    out = dict(empty)
    for name in empty:
        items = data.get(name)
        if not isinstance(items, list):
            continue
        out[name] = [str(x).strip() for x in items if str(x).strip()]
    return out


def save_lists(data):
    """原子写回名单文件（与 save_config 同样用临时文件 + replace）

    临时文件名必须每次唯一：白/黑名单的「全部清空」是前端 Promise.all **并发**发
    allowed4 与 allowed6 两个请求，两个 save_lists 若共用一个固定 tmp 路径 ——
      · 先后 open 同一个 tmp，先 replace 的把 tmp 挪走，后一个 os.replace 直接
        FileNotFoundError → 用户看到「清空失败」，实测真机 2/2 稳定复现；
      · 更糟的是两个 fd 交错写进同一个文件，产出「一份完整 JSON + 一段尾巴」的
        残缺文件，load_lists 解析失败后按**空名单**处理 —— 白名单/黑名单被整体
        静默清空，下次「应用规则」再把这个空状态写进内核。
    并发丢失更新（两个请求各自读到旧快照、后写的把先写的覆盖回去）由 _mutate_lists
    里的 flock 解决，两者缺一不可。
    """
    os.makedirs(os.path.dirname(LISTS_PATH), exist_ok=True)
    payload = {n: sorted({str(x).strip() for x in (data.get(n) or []) if str(x).strip()})
               for n in sorted(VALID_SET_NAMES)}
    tmp = f'{LISTS_PATH}.tmp.{os.getpid()}.{threading.get_ident()}'
    try:
        with open(tmp, 'w') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, LISTS_PATH)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _mutate_lists(set_name, add=(), remove=(), clear=False):
    """改名单并落盘。返回更新后的 {set_name: [...]}。

    调用方必须先确认内核 nft 操作成功再调这里 —— 顺序不能反：
    先落盘再改内核，内核失败就会造成「磁盘说有、内核没有」。

    整个读-改-写必须持排他锁：调用方是并发到达的（一次「全部清空」= 两个请求），
    不加锁时两个请求都读到旧快照，后写的会把先写的覆盖回去。
    """
    with _lists_file_lock():
        data = load_lists()
        cur = list(data.get(set_name, []))
        if clear:
            cur = []
        for ip in remove:
            cur = [x for x in cur if x != ip]
        for ip in add:
            if ip not in cur:
                cur.append(ip)
        data[set_name] = cur
        save_lists(data)
    return data

# 历史/预设容量上限
LIST_HISTORY_MAX = 100


def _list_type_from_set(set_name):
    """从 set_name 推出 list_type: 'whitelist' | 'blacklist'"""
    if set_name.startswith("allowed"):
        return "whitelist"
    if set_name.startswith("blacklist"):
        return "blacklist"
    return "unknown"


def _detect_ip_version(ip):
    """返回 4 / 6，非法返回 None（标准库 ipaddress，无外部依赖）"""
    try:
        import ipaddress
        if '/' in ip:  # CIDR 不允许加入 set
            return None
        try:
            ipaddress.IPv4Address(ip)
            return 4
        except (ipaddress.AddressValueError, ValueError):
            pass
        try:
            ipaddress.IPv6Address(ip)
            return 6
        except (ipaddress.AddressValueError, ValueError):
            pass
    except Exception:
        pass
    return None


def _record_list_history(action, ip, list_type, label='', preset_id=''):
    """记录名单操作历史。list_type: 'whitelist' / 'blacklist'，action: 'add'/'delete'/'flush'"""
    config = load_config()
    history = config.setdefault('list_history', [])
    entry = {
        'id': 'h_' + uuid.uuid4().hex[:12],
        'ts': datetime.datetime.now().isoformat(),
        'action': action,
        'ip': ip,
        'type': list_type,
        'label': label,
        'preset_id': preset_id,
    }
    history.insert(0, entry)  # 最新的在前
    config['list_history'] = history[:LIST_HISTORY_MAX]
    save_config(config)


def _next_preset_id(presets):
    used = {p.get('id', '') for p in presets}
    for i in range(1, 99999):
        cid = f"p_{i:04d}"
        if cid not in used:
            return cid
    return "p_" + uuid.uuid4().hex[:8]


def _check_ip_in_set(ip, list_type):
    """实时查询 IP 是否在对应 set 中。返回 bool（找不到 set 时返回 False）"""
    set_name = ('allowed' if list_type == 'whitelist' else 'blacklist') + (
        '6' if _detect_ip_version(ip) == 6 else '4'
    )
    try:
        result = subprocess.run(
            ['nft', 'list', 'set', 'inet', 'fw4', set_name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return False
        # 复用 _parse_nft_set_output 做精确匹配。
        # 原先用 `ip in stdout.split('elements',1)[-1]` 子串判断，
        # 会让 1.2.3.4 误匹配 11.2.3.45 / 1.2.3.400，
        # 且 'elements' 不存在时 [-1] 取整段输出导致必然误判。
        return ip in _parse_nft_set_output(result.stdout)
    except Exception:
        return False


def _parse_nft_set_output(output):
    """从 nft list set 输出中提取 IP 地址及过期时间，返回 {ip: expires_str|None}"""
    result = {}
    for m in re.finditer(r'elements = \{([^}]+)\}', output):
        block = m.group(1)
        for entry in block.split(','):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split()
            ip = parts[0]
            if not ip:
                continue
            # 查找 "expires <value>"
            expires = None
            for i, p in enumerate(parts):
                if p == "expires" and i + 1 < len(parts):
                    expires = parts[i + 1]
                    break
            result[ip] = expires
    return result


@app.route('/api/lists/whitelist', methods=['GET'])
def get_whitelist():
    """读取白名单 (allowed4 + allowed6)"""
    try:
        result4 = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'allowed4'],
                                 capture_output=True, text=True, timeout=10)
        result6 = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'allowed6'],
                                 capture_output=True, text=True, timeout=10)
        return jsonify({
            "success": True,
            "allowed4": _parse_nft_set_output(result4.stdout) if result4.returncode == 0 else {},
            "allowed6": _parse_nft_set_output(result6.stdout) if result6.returncode == 0 else {},
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/lists/blacklist', methods=['GET'])
def get_blacklist():
    """读取黑名单 (blacklist4 + blacklist6)"""
    try:
        result4 = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'blacklist4'],
                                 capture_output=True, text=True, timeout=10)
        result6 = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'blacklist6'],
                                 capture_output=True, text=True, timeout=10)
        return jsonify({
            "success": True,
            "blacklist4": _parse_nft_set_output(result4.stdout) if result4.returncode == 0 else {},
            "blacklist6": _parse_nft_set_output(result6.stdout) if result6.returncode == 0 else {},
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


def _nft_set_write(args, timeout=10):
    """对内核 set 做一次写操作，**持有 _FW_APPLY_LOCK**。

    为什么名单的增量操作必须持锁：`_FW_APPLY_LOCK` 当初引入就是为了防
    「增量 nft 操作与看门狗的 nft -f 交叉执行」，代码注释里写得很明白，
    但只有 `_apply_ruleset()` 和 `_recover_ruleset_if_unhealthy()` 两处真的拿了。
    名单的 add/delete/flush/apply 全在锁外裸跑 subprocess。

    交叉执行的两种坏结果，第二种更要命：

      ① add 落在 `nft -f` 的 `flush ruleset` 之后 → 内核元素被冲掉。
         而 `_mutate_lists()` 是在内核成功之后才落盘的，磁盘上记着这个 IP，
         内核里没有 —— 用户看到「已封禁」，实际已经放行。

      ② add 撞上重建中途、set 还不存在的窗口 → nft 报错，接口回 400，
         但那是几百毫秒的瞬时状态，不是用户能理解的失败原因。

    统一从这里走，避免以后再新增一个「忘了加锁」的名单操作。
    """
    with _FW_APPLY_LOCK:
        return subprocess.run(['nft'] + list(args), capture_output=True,
                              text=True, timeout=timeout)


@app.route('/api/lists/add', methods=['POST'])
def list_add():
    """添加 IP 到指定名单"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    set_name = data.get('set_name', '').strip()
    ip = data.get('ip', '').strip()
    if not set_name or not ip:
        return jsonify({"success": False, "message": "set_name 和 ip 不能为空"}), 400
    if set_name not in VALID_SET_NAMES:
        return jsonify({"success": False, "message": f"无效的 set_name，允许值: {', '.join(sorted(VALID_SET_NAMES))}"}), 400
    # 校验 IP 格式（标准库 ipaddress；防止协议层注入和数据合法性问题）
    if _detect_ip_version(ip) is None:
        return jsonify({"success": False, "message": f"无效的 IP 地址: {ip!r}（应为单个 IPv4/IPv6，不支持 CIDR）"}), 400
    try:
        result = _nft_set_write(['add', 'element', 'inet', 'fw4', set_name, '{', ip, '}'])
        if result.returncode != 0:
            return jsonify({"success": False, "message": f"添加失败: {result.stderr.strip() or result.stdout.strip()}"}), 400
        # 内核改成功之后再落盘。规则集以 flush ruleset 开头、每次应用都会重建，
        # 只存在内核里的成员会在重建后静默消失 —— 用户以为还封着，其实已放行。
        _mutate_lists(set_name, add=[ip])
        _record_list_history('add', ip, _list_type_from_set(set_name))
        return jsonify({"success": True, "message": f"已添加 {ip} 到 {set_name}"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "nft 命令执行超时"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400


@app.route('/api/lists/delete', methods=['POST'])
def list_delete():
    """从指定名单删除 IP"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    set_name = data.get('set_name', '').strip()
    ip = data.get('ip', '').strip()
    if not set_name or not ip:
        return jsonify({"success": False, "message": "set_name 和 ip 不能为空"}), 400
    if set_name not in VALID_SET_NAMES:
        return jsonify({"success": False, "message": f"无效的 set_name，允许值: {', '.join(sorted(VALID_SET_NAMES))}"}), 400
    # 校验 IP 格式（与 list_add 保持一致，防止绕过前端校验）
    if _detect_ip_version(ip) is None:
        return jsonify({"success": False, "message": f"无效的 IP 地址: {ip!r}（应为单个 IPv4/IPv6，不支持 CIDR）"}), 400
    try:
        result = _nft_set_write(['delete', 'element', 'inet', 'fw4', set_name, '{', ip, '}'])
        if result.returncode != 0:
            return jsonify({"success": False, "message": f"删除失败: {result.stderr.strip() or result.stdout.strip()}"}), 400
        _mutate_lists(set_name, remove=[ip])
        _record_list_history('delete', ip, _list_type_from_set(set_name))
        return jsonify({"success": True, "message": f"已从 {set_name} 删除 {ip}"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "nft 命令执行超时"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400


@app.route('/api/lists/flush', methods=['POST'])
def list_flush():
    """清空指定名单"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    set_name = data.get('set_name', '').strip()
    if not set_name:
        return jsonify({"success": False, "message": "set_name 不能为空"}), 400
    if set_name not in VALID_SET_NAMES:
        return jsonify({"success": False, "message": f"无效的 set_name，允许值: {', '.join(sorted(VALID_SET_NAMES))}"}), 400
    try:
        result = _nft_set_write(['flush', 'set', 'inet', 'fw4', set_name])
        if result.returncode != 0:
            return jsonify({"success": False, "message": f"清空失败: {result.stderr.strip() or result.stdout.strip()}"}), 400
        _mutate_lists(set_name, clear=True)
        _record_list_history('flush', '-', _list_type_from_set(set_name))
        return jsonify({"success": True, "message": f"已清空 {set_name}"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "nft 命令执行超时"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400


# ======================= 名单历史 / IP 预设 =======================

@app.route('/api/lists/presets', methods=['GET'])
def list_get_presets():
    """列出所有 IP 预设（每个 preset 附带 is_active：当前是否在 set 里）"""
    config = load_config()
    presets = config.get('ip_presets', [])
    enriched = []
    for p in presets:
        item = dict(p)
        item['is_active'] = _check_ip_in_set(p.get('ip', ''), p.get('type', 'whitelist'))
        enriched.append(item)
    return jsonify({'success': True, 'data': {'presets': enriched, 'total': len(enriched)}})


@app.route('/api/lists/presets', methods=['POST'])
def list_create_preset():
    """新建 IP 预设"""
    data = request.get_json(silent=True) or {}
    label = data.get('label', '').strip()
    ip = data.get('ip', '').strip()
    list_type = data.get('type', 'whitelist').strip()
    auto_expire = bool(data.get('auto_expire', True))

    if not label or len(label) > 64:
        return jsonify({'success': False, 'message': '标签需 1-64 字符'}), 400
    if not ip or _detect_ip_version(ip) is None:
        return jsonify({'success': False, 'message': 'IP 地址格式错误'}), 400
    if list_type not in ('whitelist', 'blacklist'):
        return jsonify({'success': False, 'message': 'type 只能是 whitelist 或 blacklist'}), 400

    config = load_config()
    presets = config.setdefault('ip_presets', [])
    # 同 IP + type 视为重复
    for p in presets:
        if p.get('ip') == ip and p.get('type') == list_type:
            return jsonify({'success': False, 'message': '同 IP+类型的预设已存在'}), 400

    entry = {
        'id': _next_preset_id(presets),
        'label': label,
        'ip': ip,
        'type': list_type,
        'auto_expire': auto_expire,
        'created_at': datetime.datetime.now().isoformat(),
    }
    presets.append(entry)
    save_config(config)
    return jsonify({'success': True, 'data': {'preset': entry, 'message': '预设已添加'}})


@app.route('/api/lists/presets/<preset_id>', methods=['PUT'])
def list_update_preset(preset_id):
    """编辑 IP 预设"""
    data = request.get_json(silent=True) or {}
    config = load_config()
    presets = config.get('ip_presets', [])
    preset = next((p for p in presets if p.get('id') == preset_id), None)
    if not preset:
        return jsonify({'success': False, 'message': '预设不存在'}), 404

    if 'label' in data:
        label = str(data['label']).strip()
        if not label or len(label) > 64:
            return jsonify({'success': False, 'message': '标签长度需 1-64 字符'}), 400
        preset['label'] = label
    if 'ip' in data:
        ip = str(data['ip']).strip()
        if _detect_ip_version(ip) is None:
            return jsonify({'success': False, 'message': 'IP 地址格式错误'}), 400
        preset['ip'] = ip
    if 'type' in data:
        if data['type'] not in ('whitelist', 'blacklist'):
            return jsonify({'success': False, 'message': 'type 只能是 whitelist 或 blacklist'}), 400
        preset['type'] = data['type']
    if 'auto_expire' in data:
        preset['auto_expire'] = bool(data['auto_expire'])

    save_config(config)
    return jsonify({'success': True, 'data': {'preset': preset, 'message': '预设已更新'}})


@app.route('/api/lists/presets/<preset_id>', methods=['DELETE'])
def list_delete_preset(preset_id):
    """删除 IP 预设（不影响已在 set 里的 IP）"""
    config = load_config()
    presets = config.get('ip_presets', [])
    new_presets = [p for p in presets if p.get('id') != preset_id]
    if len(new_presets) == len(presets):
        return jsonify({'success': False, 'message': '预设不存在'}), 404
    config['ip_presets'] = new_presets
    save_config(config)
    return jsonify({'success': True, 'data': {'message': '预设已删除'}})


@app.route('/api/lists/presets/<preset_id>/apply', methods=['POST'])
def list_apply_preset(preset_id):
    """一键把预设 IP 加入对应 set（不删除现有 set 元素，只追加）"""
    config = load_config()
    presets = config.get('ip_presets', [])
    preset = next((p for p in presets if p.get('id') == preset_id), None)
    if not preset:
        return jsonify({'success': False, 'message': '预设不存在'}), 404

    ip = preset.get('ip', '')
    ip_ver = _detect_ip_version(ip)
    if ip_ver is None:
        return jsonify({'success': False, 'message': '预设 IP 格式错误'}), 400

    set_name = ('allowed' if preset['type'] == 'whitelist' else 'blacklist') + (
        '6' if ip_ver == 6 else '4'
    )

    # 检测 set 是否支持 timeout（flags 含 timeout 才允许带 timeout 子句）
    # OpenWrt fw4: allowed4/allowed6 是 'flags dynamic,timeout' 支持；blacklist4/6 是 'flags dynamic' 不支持
    set_supports_timeout = False
    try:
        list_r = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', set_name],
                                capture_output=True, text=True, timeout=5)
        if list_r.returncode == 0:
            # 从 'flags dynamic,timeout' 或 'flags timeout' 等中判断
            import re as _re
            m = _re.search(r'flags\s+([^\n]+)', list_r.stdout)
            if m and 'timeout' in m.group(1).split(','):
                set_supports_timeout = True
    except Exception:
        pass

    if preset.get('auto_expire', True) and set_supports_timeout:
        # 白名单默认 5h，黑名单默认 30 天
        # 注意：OpenWrt 自带 nft 不支持 'timeout <N> s' 的空格 + 单位写法，
        #       必须用 'timeout <N>s'（无空格、无单位后缀视为秒）
        timeout_s = 5 * 3600 if preset['type'] == 'whitelist' else 30 * 86400
        cmd = ['nft', 'add', 'element', 'inet', 'fw4', set_name,
               '{', ip, 'timeout', f'{timeout_s}s', '}']
    else:
        # 不支持 timeout（黑名单 set）或用户选择永久：直接永久写入
        cmd = ['nft', 'add', 'element', 'inet', 'fw4', set_name,
               '{', ip, '}']

    try:
        result = _nft_set_write(cmd[1:])
        if result.returncode != 0:
            return jsonify({
                'success': False,
                'message': f'添加失败: {result.stderr.strip() or result.stdout.strip()}'
            }), 400
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'message': 'nft 命令超时'}), 400

    _mutate_lists(set_name, add=[ip])
    _record_list_history('add', ip, preset['type'],
                         label=preset.get('label', ''), preset_id=preset_id)
    return jsonify({
        'success': True,
        'data': {
            'message': f'已添加 {preset.get("label", ip)} ({ip}) 到 {set_name}',
            'set_name': set_name,
        }
    })


@app.route('/api/lists/history', methods=['GET'])
def list_get_history():
    """获取名单操作历史（默认 20 条，最多 100）"""
    config = load_config()
    try:
        limit = int(request.args.get('limit', 20))
    except (TypeError, ValueError):
        limit = 20
    limit = max(1, min(limit, 100))
    history = config.get('list_history', [])[:limit]
    return jsonify({'success': True, 'data': {
        'history': history,
        'total': len(config.get('list_history', [])),
        'limit': limit,
    }})


@app.route('/api/lists/history/clear', methods=['POST'])
def list_clear_history():
    """清空名单历史（不影响 set 里的实际 IP）"""
    config = load_config()
    config['list_history'] = []
    save_config(config)
    return jsonify({'success': True, 'data': {'message': '历史已清空'}})


# ======================= 反向代理模块 =======================
# nftables-web v0.7.6 — HTTPS 反向代理管理

ACME_SH_PATH = os.path.expanduser("~/.acme.sh/acme.sh")
NGINX_SSL_DIR = "/etc/nginx/ssl"
NGINX_CONF_DIR = "/etc/nginx/conf.d"

# nftables-web 自身服务用证书（自签或导入）
NFTABLES_WEB_SSL_DIR = os.path.join(NGINX_SSL_DIR, "nftables-web")
NFTABLES_WEB_CERT = os.path.join(NFTABLES_WEB_SSL_DIR, "fullchain.pem")
NFTABLES_WEB_KEY = os.path.join(NFTABLES_WEB_SSL_DIR, "privkey.pem")

# nginx worker 运行用户。master 仍需 root（要读私钥、要 bind 低端口），
# 但 worker 才是真正处理公网流量的进程 —— 它以 root 运行的话，nginx 侧
# 任何一处漏洞都直接等于整台机器沦陷，和认证网关那半个问题是同一类。
NGINX_WORKER_USER = "nobody"


def _harden_key_for_nginx_worker(path):
    """私钥 chmod 600 之后，补上 nginx worker 的组读权限。

    为什么必须跟着每次证书写入一起做
    ------------------------------
    写入私钥的路径一共五条，其中三条会自己 `chmod(key, 0o600)`：
        · 上传        app.py  cert_file.save 后 chmod
        · 重新上传    app.py  cert_file.save 后 chmod
        · 自签生成    app.py  openssl 之后 chmod
    另外两条是 ACME 路径（_acme_issue / _acme_renew），acme.sh 自己写出
    privkey.pem 600 root，**项目这边根本不 chmod**，所以必须显式调本函数。

    chmod 600 本身是对的 —— 私钥本就不该被别人读到。但 nginx worker 现在以
    NGINX_WORKER_USER 运行，它必须能读私钥才能做 TLS 握手，于是：
        只改一次 nginx 的 user → 下一次换证书，worker 立刻读不到私钥
    而 nginx 的表现是「握手失败」，前端只看到一个 TLS 报错，没有任何提示
    说明是权限 —— 这种故障极难排查。

    所以规则是：**谁把私钥写到磁盘上，谁就负责保证 nginx worker 读得到。**
    640 root:<worker 组> 对「其他用户」依然完全关闭；worker 组在 OpenWrt
    上是 nobody 组、没有任何成员，实际暴露面和 600 等价，只是多了 nginx
    这一条读取路径。

    解析不到用户或 chown 失败都不抛异常 —— 证书该存还是要存，
    降权是加固措施，不该反过来把证书流程搞挂。
    """
    try:
        import grp
        gid = grp.getgrnam(NGINX_WORKER_USER).gr_gid
    except (ImportError, KeyError):
        return False
    try:
        os.chown(path, 0, gid)
        os.chmod(path, 0o640)
        return True
    except OSError:
        return False

# 注：面板 HTTPS 端口 HTTPS_PORT 已提到文件顶部定义（validate_config 需要它做端口交叉校验）

# TLS 版本映射
TLS_VERSION_MAP = {
    "TLSv1.0": "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
    "TLSv1.1": "TLSv1.1 TLSv1.2 TLSv1.3",
    "TLSv1.2": "TLSv1.2 TLSv1.3",
    "TLSv1.3": "TLSv1.3",
}

def _is_port_in_use(port):
    """检测端口是否被占用"""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def _sanitize_domain(domain):
    """净化域名，防止路径遍历和注入"""
    domain = domain.strip().lower()
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$', domain):
        raise ValueError(f"无效域名格式: {domain}")
    return domain


def _host_resolvable(host, timeout=3.0):
    """域名能不能解析成 IP。

    **为什么必须在这里挡**：nginx 在 `nginx -t`（配置解析阶段）就会去解析
    proxy_pass 里的 upstream 域名，解析不到直接 `[emerg] host not found in
    upstream`，整份网关配置生成失败。而反代的保存顺序是「先落盘、后部署」，
    部署失败不会回滚配置 —— 于是这条毒规则永久留在配置 JSON 里，
    之后**每一次**反代保存都会重新生成同样失败的配置并返回 500。

    实测（.224）：POST 一条 target=evil.example.com:80 的规则后，
    连续 4 次 PUT 全部 500，就是这条规则在反复污染。

    返回三态，而不是简单的 True/False：
      True  —— 能解析，安全
      False —— 明确解析不到（NXDOMAIN / 无 A 记录），必须拒绝
      None  —— 解析器超时或本机无 DNS 出口，无法判定，放行但由部署兜底
    """
    if not host:
        return None
    # 字面量 IP 不需要解析
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    result = {}

    def _resolve():
        try:
            socket.setdefaulttimeout(timeout)
            result['ok'] = bool(socket.getaddrinfo(host, None))
        except Exception:
            result['ok'] = False

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        # 超时 ≠ 解析不到。本机可能压根没有 DNS 出口（比如只有 /etc/hosts
        # 的离线环境），此时拒绝会把合法配置也挡在门外。
        return None
    return result.get('ok', False)


def _sanitize_target_address(addr):
    """校验目标地址格式（IPv4:port 或 domain:port）
    - IPv4：每段 0-255
    - domain：复用 _sanitize_domain 校验规则（a-z 0-9 - .）
    - port：1-65535
    """
    if not isinstance(addr, str) or not addr or ':' not in addr:
        raise ValueError(f"无效目标地址（缺端口）: {addr!r}")
    host, port_str = addr.rsplit(':', 1)
    # 校验端口：1-65535
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"无效目标地址（端口非数字）: {addr!r}")
    if port < 1 or port > 65535:
        raise ValueError(f"无效目标地址（端口越界 1-65535）: {addr!r}")
    # 校验 host：非空
    if not host:
        raise ValueError(f"无效目标地址（host 为空）: {addr!r}")
    # IPv4？
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
        parts = host.split('.')
        if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
            return addr
        raise ValueError(f"无效目标地址（IPv4 段数或越界）: {addr!r}")
    # domain：复用 _sanitize_domain 严格校验
    _sanitize_domain(host)
    return addr


def _sanitize_name(name):
    """净化反代规则名称（用于 UI 显示和 nginx 注释）
    - 去除换行（防 nginx 注释被切断）
    - 去除 '#'（防 nginx 注释结构被破坏）
    - 最长 64 字符
    """
    if not name:
        return ''
    name = str(name).replace('\n', '').replace('\r', '').replace('#', '')
    return name.strip()[:64]


def _sanitize_client_max_body_size(value):
    """净化 client_max_body_size 值
    - 空值合法（表示不生成该指令，走 nginx 默认 1M）
    - 必须匹配 \\d+[KMG]?（如 '50M', '1G', '1024'）
    """
    if value is None:
        return ''
    value = str(value).strip()
    if not value:
        return ''
    # 单位大小写都要接受：nginx 文档里的标准写法是小写（client_max_body_size 10m;），
    # 真机 nginx/1.26.3 实测 10m 合法。原来只允许大写 K/M/G，用户照文档填
    # 最常见的 10m 反而被拒。
    if not re.match(r'^\d+[kKmMgG]?$', value):
        raise ValueError(f"无效的 client_max_body_size: '{value}'（必须是数字，可选后缀 K/M/G，例如 10m、50M、1G）")
    return value.upper()


# 反代默认设置
def _validate_rp_service(data, existing=None, all_rules=None):
    """反代服务字段的统一校验与规范化入口。

    返回 (clean, err)：clean 是清洗后的规则字典，err 非 None 时表示校验失败。

    **为什么要统一**：v0.8.0 之前 POST 与 PUT 各自抄了一份校验，PUT 那边
    漏掉了 listen_port 与 target_protocol，两个字段未经任何校验就写进
    配置 —— target_protocol 能直接注入 nginx 指令（实测可注入出第二个
    server 块），listen_port 能拼进文件路径。两份校验迟早会再次分叉，
    所以这里只留一个入口，POST/PUT 共用。

    v0.8.1 起反代服务只存在于认证网关一条路径上（统一 gateway_port +
    path 前缀），证书用网关的统一证书，因此不再需要 domain /
    listen_port / ssl_cert_id。
    """
    existing = existing or {}
    all_rules = all_rules or []

    def pick(key, default=None):
        v = data.get(key)
        return existing.get(key, default) if v is None else v

    clean = {}

    # 名称：仅用于 UI 与 nginx 注释，不参与匹配
    clean["name"] = _sanitize_name(pick("name", "")) or ""

    # 启用开关：同样要挡 bool 混型
    en = pick("enabled", True)
    clean["enabled"] = bool(en) if isinstance(en, (bool, int)) else True

    # 路径前缀：网关分发的唯一依据，必须有
    prefix = _safe_path_prefix(pick("path_prefix", ""))
    if not prefix:
        return None, ("path_prefix 必填，且必须是 /xxx 形式"
                      "（只允许字母数字与 - _ /，不能包含 .. 或 //）")
    if prefix in _RESERVED_GATEWAY_PREFIXES:
        return None, f"path_prefix {prefix!r} 是网关保留前缀，不能使用"
    for r in all_rules:
        if r.get("id") == existing.get("id"):
            continue
        other = _safe_path_prefix(r.get("path_prefix", ""))
        if other == prefix:
            return None, f"path_prefix {prefix!r} 与规则「{r.get('name') or r.get('id')}」重复"
    clean["path_prefix"] = prefix

    # 目标地址
    target = pick("target_address", "")
    try:
        clean["target_address"] = _sanitize_target_address(str(target or '').strip())
    except ValueError as e:
        return None, str(e)

    # 域名型目标必须先确认解析得通。nginx 在 nginx -t 阶段就会解析 upstream
    # 域名，解析不到整份网关配置就生成失败（详见 _host_resolvable 的说明）。
    _t_host = clean["target_address"].rsplit(':', 1)[0]
    if _host_resolvable(_t_host) is False:
        return None, (f"目标地址 {_t_host!r} 解析不到 IP。"
                      "nginx 生成配置时会立刻失败并让整个网关配置不可用，"
                      "请改用可解析的主机名或直接填 IP")

    # 目标协议：白名单，绝不能直接拼进 proxy_pass
    proto = str(pick("target_protocol", "http")).strip().lower()
    if proto not in ("http", "https"):
        return None, "target_protocol 只允许 http 或 https"
    clean["target_protocol"] = proto

    # 公网访问开关：True=公网可达但必须登录；False=仅内网网段
    pa = pick("public_access", False)
    if isinstance(pa, (bool, int)):
        clean["public_access"] = bool(pa)
    else:
        clean["public_access"] = False

    # 上传体积限制
    try:
        clean["client_max_body_size"] = _sanitize_client_max_body_size(
            pick("client_max_body_size", ""))
    except ValueError as e:
        return None, str(e)

    # WebSocket
    ws = pick("websocket_enabled", True)
    clean["websocket_enabled"] = bool(ws) if isinstance(ws, (bool, int)) else True

    # 门户图标：只允许短字符串，进门户页渲染
    clean["icon"] = _sanitize_name(str(pick("icon", "") or ""))[:16]

    return clean, None


def _migrate_rp_rules(config):
    """把 v0.8.0 的反代规则迁移到 v0.8.1 的「网关服务」结构。

    v0.8.0 一条规则同时生成「独立站点 conf」和「网关 location」两套暴露面，
    但 path_prefix 既没有写入路径也没有 UI，导致网关那一侧永远是空的 ——
    实际只有无认证的独立站点在跑。v0.8.1 砍掉独立站点，只留网关。

    迁移规则：
      · 有 path_prefix 的原样保留
      · 没有的，从 domain 第一段派生一个（nas.example.com → /nas），
        冲突时补数字后缀；派生不出来（无 domain）就用规则序号兜底
      · domain / listen_port / ssl_cert_id 三个字段丢弃
    """
    rp = config.get("reverse_proxy")
    if not isinstance(rp, dict):
        return config
    rules = rp.get("rules")
    if not isinstance(rules, list):
        return config

    used = set()
    out = []
    for idx, r in enumerate(rules, 1):
        if not isinstance(r, dict):
            continue
        prefix = _safe_path_prefix(r.get("path_prefix", ""))
        if not prefix:
            base = ""
            dom = str(r.get("domain", "") or "").strip().lower()
            if dom:
                first = re.split(r'[.\-]', dom)[0]
                base = _safe_path_prefix('/' + first) or ''
            if not base:
                base = f'/svc{idx}'
            prefix = base
            n = 1
            while prefix in used:
                n += 1
                cand = _safe_path_prefix(f'{base}{n}')
                if not cand:
                    break
                prefix = cand
            print(f'[INFO] 反代规则 {r.get("id") or idx} 已迁移到网关结构，'
                  f'自动分配路径前缀 {prefix}（可在反代管理页修改）', flush=True)
        used.add(prefix)
        migrated = {
            "id": r.get("id") or f'rp_{idx:03d}',
            "name": _sanitize_name(r.get("name", "")),
            "enabled": bool(r.get("enabled", True)),
            "path_prefix": prefix,
            "target_address": r.get("target_address", ""),
            "target_protocol": str(r.get("target_protocol", "http") or "http").lower(),
            "public_access": bool(r.get("public_access", False)),
            "client_max_body_size": r.get("client_max_body_size", "") or "",
            "websocket_enabled": bool(r.get("websocket_enabled", True)),
            "icon": _sanitize_name(str(r.get("icon", "") or ""))[:16],
            "updated_at": r.get("updated_at", ""),
        }
        out.append(migrated)
    rp["rules"] = out
    return config


RP_DEFAULT_SETTINGS = {
    "http_redirect_enabled": True,
    "hsts_enabled": True,
    "tls_min_version": "TLSv1.2",
    "auto_reload_nginx": True,
}


DNS_PROVIDERS = {
    "ali": {
        "name": "阿里云 DNS",
        "acme_param": "dns_ali",
        "fields": [
            {"key": "Ali_Key", "label": "AccessKey ID", "type": "text"},
            {"key": "Ali_Secret", "label": "AccessKey Secret", "type": "password"}
        ],
        "auto_fill": "aliyun"
    },
    "tencent": {
        "name": "腾讯云 DNSPod",
        "acme_param": "dns_tencent",
        "fields": [
            {"key": "Tencent_SecretId", "label": "SecretId", "type": "text"},
            {"key": "Tencent_SecretKey", "label": "SecretKey", "type": "password"}
        ]
    },
    "cf": {
        "name": "Cloudflare",
        "acme_param": "dns_cf",
        "fields": [
            {"key": "CF_Token", "label": "API Token", "type": "text"}
        ]
    },
    "huaweicloud": {
        "name": "华为云 DNS",
        "acme_param": "dns_huaweicloud",
        "fields": [
            {"key": "HUAWEICLOUD_Username", "label": "Username", "type": "text"},
            {"key": "HUAWEICLOUD_Password", "label": "Password", "type": "password"}
        ]
    },
    "porkbun": {
        "name": "Porkbun",
        "acme_param": "dns_porkbun",
        "fields": [
            {"key": "PORKBUN_API_KEY", "label": "API Key", "type": "text"},
            {"key": "PORKBUN_SECRET_API_KEY", "label": "Secret API Key", "type": "password"}
        ]
    },
    "godaddy": {
        "name": "GoDaddy",
        "acme_param": "dns_gd",
        "fields": [
            {"key": "GD_Key", "label": "API Key", "type": "text"},
            {"key": "GD_Secret", "label": "API Secret", "type": "password"}
        ]
    },
    "namesilo": {
        "name": "NameSilo",
        "acme_param": "dns_namesilo",
        "fields": [
            {"key": "Namesilo_Key", "label": "API Key", "type": "text"}
        ]
    },
    "google": {
        "name": "Google Domains",
        "acme_param": "dns_google",
        "fields": [
            {"key": "GOOGLE_ACCESS_TOKEN", "label": "Access Token", "type": "text"}
        ]
    },
    "duckdns": {
        "name": "DuckDNS",
        "acme_param": "dns_duckdns",
        "fields": [
            {"key": "DUCKDNS_TOKEN", "label": "Token", "type": "text"}
        ]
    },
    "linode": {
        "name": "Linode",
        "acme_param": "dns_linode",
        "fields": [
            {"key": "LINODE_API_KEY", "label": "API Token", "type": "text"}
        ]
    }
}


def _get_dns_credentials(rp, provider_id):
    """获取某 DNS 提供商的凭证，阿里云自动从 DDNS 配置读取"""
    if provider_id == "ali":
        ak_id, ak_secret = _acme_load_aliyun_credentials()
        if ak_id and ak_secret:
            return {"Ali_Key": ak_id, "Ali_Secret": ak_secret}
        return None
    stored = rp.get("dns_credentials", {}).get(provider_id, {})
    return stored if stored else None


def _get_rp_config():
    """获取 reverse_proxy 配置段，确保结构完整"""
    config = load_config()
    # 配置文件被手工改坏时 reverse_proxy 可能不是 dict，
    # setdefault 不会纠正已存在的错误类型，必须显式校验
    rp = config.get("reverse_proxy")
    if not isinstance(rp, dict):
        print("[WARNING] reverse_proxy 结构非法，已重置", flush=True)
        rp = {}
        config["reverse_proxy"] = rp
    if not isinstance(rp.get("rules"), list):
        rp["rules"] = []
    if not isinstance(rp.get("certificates"), list):
        rp["certificates"] = []
    rp.setdefault("settings", dict(RP_DEFAULT_SETTINGS))
    return config, rp


def _save_rp_config(config):
    """保存包含 reverse_proxy 的完整配置"""
    save_config(config)


def _find_rp_rule(rp, rule_id):
    """按 id 查找反代规则"""
    for r in rp.get("rules", []):
        if r["id"] == rule_id:
            return r
    return None


def _find_rp_cert(rp, cert_id):
    """按 id 查找证书"""
    for c in rp.get("certificates", []):
        if c["id"] == cert_id:
            return c
    return None


def _next_id(prefix, existing_ids):
    """生成下一个可用 ID，格式 prefix_001"""
    nums = []
    for rid in existing_ids:
        m = re.search(r'(\d+)$', rid)
        if m:
            nums.append(int(m.group(1)))
    n = max(nums) + 1 if nums else 1
    return f"{prefix}_{n:03d}"


def _cert_key_pair_ok(cert_path, key_path):
    """校验证书与私钥是否配对，返回 (是否配对, 失败原因)。

    为什么必须校验
    --------------
    上传/重传原来只做了域名正则 + 三字段非空，然后把文件直接落盘。
    传错私钥（很容易：同一域名换证书时把两个文件选反了）的话，nginx 会
    拿着不匹配的 key 做 TLS 握手 —— 表现是浏览器一个证书错误，
    而面板这边 expires_at 正常、UI 照样显示「● 有效」，排障方向会被
    完全带偏到「是不是 nginx 配置错了」。

    做法是比较两边的公钥：`openssl x509 -pubkey` 取证书里的公钥，
    `openssl pkey -pubout` 取私钥推导出的公钥。用 pkey 而不是 rsa，
    是为了 RSA / ECDSA 两种私钥都能过。
    """
    if not (cert_path and key_path and os.path.exists(cert_path)
            and os.path.exists(key_path)):
        return False, "证书或私钥文件不存在"
    try:
        c = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-pubkey"],
                           capture_output=True, text=True, timeout=10)
        k = subprocess.run(["openssl", "pkey", "-in", key_path, "-pubout"],
                           capture_output=True, text=True, timeout=10)
    except Exception as e:
        # 校验不了不等于校验失败 —— openssl 缺失等环境问题不该拦住用户存证书
        return True, f"无法校验（{type(e).__name__}），已跳过"
    if c.returncode != 0:
        return False, "证书文件无法解析（可能不是 PEM 格式的 x509 证书）"
    if k.returncode != 0:
        return False, "私钥文件无法解析（可能不是 PEM 格式的私钥）"
    pub_c = "".join(c.stdout.split())
    pub_k = "".join(k.stdout.split())
    if pub_c != pub_k:
        return False, "证书与私钥不配对（两个文件的公钥不一致）"
    return True, "配对正常"


def _get_cert_expiry(cert_path):
    """用 openssl 读取证书过期时间，返回 (expires_at_str, days_remaining)"""
    if not cert_path or not os.path.exists(cert_path):
        return None, -1
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-enddate", "-issuer", "-subject"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None, -1
        output = result.stdout
        m = re.search(r"notAfter=(.+)", output)
        if not m:
            return None, -1
        raw = m.group(1).strip()
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                dt = datetime.datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        else:
            return None, -1
        expires_at = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        now = datetime.datetime.utcnow()
        days_remaining = (dt - now).days
        return expires_at, days_remaining
    except Exception:
        return None, -1


# 本面板生成/管理的 nginx 文件标记。conf.d/*.conf 会被 include 进 http 上下文，
# 所以标记本身也必须是合法 nginx 注释。
RP_CONF_MARKER = "# Managed by nftables-web-v2"

# nginx 服务控制脚本。集中成一个常量：OpenWrt 是 /etc/init.d/nginx，
# 普通 Linux 发行版是 systemctl，散落硬编码会让非 OpenWrt 部署直接失败
# （FileNotFoundError），也让测试无法替换。
NGINX_INIT_PATH = '/etc/init.d/nginx'

GATEWAY_CONF_NAME = "00-nftables-web-gateway.conf"
GATEWAY_CONF_MARKER = "# Managed by nftables-web-v2 auth gateway"
# 网关专用 SSL 会话缓存区。名字必须与机器上其它 server 块（如 OpenWrt LuCI 的
# shared:SSL:32k）不同 —— nginx 共享内存区名全局唯一，同名不同大小会让整份配置
# 加载失败，表现为「网关端口起不来」而不是任何明确报错。
GATEWAY_SSL_ZONE = "SSLGATEWAY"
GATEWAY_SSL_CACHE_SIZE = "10m"

# 网关配置块由 /api/gateway/config **独占**。
#
# 为什么必须划清边界：/api/config（面板上到处都在点的「保存配置」）是无字段白名单的
# 全量 merge，它写 gateway_enabled 时**不会**下发 nginx。.224 实测就是这么坏的：
#   1) 反代管理页点「保存网关配置」，前端表单还是硬编码默认值 false
#      → /api/gateway/config 删掉 00-nftables-web-gateway.conf 并 reload
#      → 8443 无人监听，公网唯一入口没了，接口回 200「已停用」
#   2) 别的页面点「保存配置」，把 gateway_enabled=true 写回磁盘，但不下发
#   结果：磁盘 true、面板「已启用」、conf 文件不存在、8443 死，且无任何机制收敛
#
# 所以这块字段只认自己的端点：/api/config 一律剔除（并回报剔了哪些），
# /api/gateway/config 才允许改 —— 那边改完会真的下发 nginx 并校验结果。
GATEWAY_OWNED_CONFIG_KEYS = frozenset({
    'gateway_enabled',
    'gateway_port',
    'auth_api_port',
    'auth_session_timeout',
    'auth_absolute_timeout',
    'auth_lan_bypass',
})

# /api/config 的 GET 为了让前端显示「实际状态」会多给这几个键，而前端把整个
# config 对象原样回传 POST。它们是**只读视图**，落盘就是污染配置。
READONLY_CONFIG_KEYS = frozenset({
    'success',
    'luci_actual',
    'luci_ports_listening',
    'gateway_actual',
})


# ══════════════════════════════════════════════════════════════════════
# LuCI 80/443 开关
#
# 80/443 不是本项目的：它们是 OpenWrt 自带 LuCI 的两个 server 段
#     nginx._lan            listen 443 ssl   （带 restrict_locally，只放行内网段）
#     nginx._redirect2ssl   listen 80        （302 跳转，**没有任何限制**）
# 本项目的反代在 8443（conf.d/00-nftables-web-gateway.conf，模板里是无条件
# include，与 LuCI 无关）。
#
# 为什么关：个人宽带用不上 LuCI，8443 已经承担管理入口。少两个监听口是净收益。
# 为什么默认关：公网设备上「默认不监听」才是安全默认，需要时再从面板打开。
#
# 实现注意（都是 .224 真机踩出来的）：
#   1. /etc/nginx/uci.conf 是**符号链接** → /var/lib/nginx/uci.conf。
#      重新渲染要删的是链接的**目标**，删链接本身会让 nginx_init 的
#      `if [ -e "${UCI_CONF}" ]` 判假、回落到 /etc/nginx/nginx.conf，
#      结果是 LuCI 没了但日志里看不出原因。删目标就没事。
#   2. 光 `uci set .../enabled=0` 没用 —— 这个 uci-nginx 不认 enabled 选项，
#      实测毫无效果。只能把整个 section 拿掉。
#   3. 改完必须 `nginx-util init_lan` 重新渲染，`/etc/init.d/nginx restart`
#      自己也会调它，但保险起见显式先渲染再 reload。
#   4. 关掉之后这台机器上只剩 SSH 和 5443 面板 —— 两者都不依赖 LuCI。
# ══════════════════════════════════════════════════════════════════════

LUCI_CONF_PATH = '/etc/config/nginx'
LUCI_RENDERED_PATH = '/var/lib/nginx/uci.conf'   # /etc/nginx/uci.conf 指向它
LUCI_SNAPSHOT_PATH = '/etc/nftables/nginx-luci.snapshot'
NGINX_UTIL_PATH = '/usr/bin/nginx-util'
LUCI_SECTIONS = ('_lan', '_redirect2ssl')
# 本项目网关监听的端口：关 LuCI 时它必须照常在听，否则就是改坏了
GATEWAY_PORT = 8443


def _uci_conf_text(path=None):
    # 默认值刻意写成 None：写成 `path=LUCI_CONF_PATH` 会在**函数定义时**求值，
    # 之后改模块级常量不再生效 —— 测试改不动路径，线上换路径也换不掉。
    path = path or LUCI_CONF_PATH
    try:
        with open(path, 'r', errors='ignore') as f:
            return f.read()
    except OSError:
        return ''


def _uci_section_names(text):
    """列出 /etc/config/nginx 里所有 section 名字（按出现顺序）"""
    names = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith('config '):
            continue
        parts = s.split(None, 2)
        if len(parts) >= 3:
            nm = parts[2].strip()
            if nm.startswith("'") and nm.endswith("'") and len(nm) >= 2:
                nm = nm[1:-1]
            names.append(nm)
    return names


def _uci_strip_sections(text, drop):
    """从 /etc/config/nginx 文本里删掉指定 section 整块。

    刻意不碰 `uci delete` 子命令：uci 的 delete 在多行 option / list 场景下
    容易留下半截配置，而这个文件的 section 结构简单（config 行为块首），
    按行块切更可控。
    """
    out, skipping = [], False
    for line in text.splitlines(keepends=True):
        s = line.strip()
        if s.startswith('config '):
            parts = s.split(None, 2)
            nm = parts[2].strip() if len(parts) >= 3 else ''
            if nm.startswith("'") and nm.endswith("'") and len(nm) >= 2:
                nm = nm[1:-1]
            skipping = nm in drop
        if not skipping:
            out.append(line)
    return ''.join(out)


def _luci_snapshot():
    """留一份原始 /etc/config/nginx，供「重新打开 LuCI」时还原。

    只在快照不存在时写 —— 反复开关不能把被用户改过的配置覆盖成最初的版本。
    """
    if os.path.exists(LUCI_SNAPSHOT_PATH):
        return True
    try:
        os.makedirs(os.path.dirname(LUCI_SNAPSHOT_PATH), exist_ok=True)
        shutil.copy(LUCI_CONF_PATH, LUCI_SNAPSHOT_PATH)
        os.chmod(LUCI_SNAPSHOT_PATH, 0o600)
        return True
    except OSError as e:
        print(f'[WARN] LuCI 配置快照失败（关闭后无法自动还原）: {e}', flush=True)
        return False


def _luci_ports_listening():
    """当前 80/443 是否真在监听。用真实端口状态判断，不看配置文件。"""
    listening = set()
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            for info in socket.getaddrinfo('127.0.0.1', 0, fam,
                                          socket.SOCK_STREAM, socket.SOL_TCP):
                pass
        except OSError:
            pass
    # 用 /proc/net/tcp(+6) 直读：不依赖 ss/netstat，BusyBox 也一样
    for f in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            with open(f) as fh:
                next(fh, None)
                for ln in fh:
                    cols = ln.split()
                    if len(cols) < 4 or cols[3] != '0A':   # 0A = LISTEN
                        continue
                    port = int(cols[1].split(':')[1], 16)
                    if port in (80, 443):
                        listening.add(port)
        except (OSError, ValueError, IndexError):
            continue
    return listening


def _luci_reload_nginx(what):
    """重新渲染 uci.conf 并 reload nginx。返回 (ok, 说明)。"""
    if not os.path.exists(NGINX_UTIL_PATH):
        return False, f'{NGINX_UTIL_PATH} 不存在（非 OpenWrt / 未装 nginx-full）'
    # 删的是渲染产物的**目标**，不是 /etc/nginx/uci.conf 那个符号链接
    try:
        if os.path.exists(LUCI_RENDERED_PATH):
            os.unlink(LUCI_RENDERED_PATH)
    except OSError as e:
        return False, f'清理旧渲染产物失败: {e}'
    try:
        r = subprocess.run([NGINX_UTIL_PATH, 'init_lan'],
                           capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return False, f'nginx-util 失败: {type(e).__name__}: {e}'
    if r.returncode != 0:
        return False, f'nginx-util returncode={r.returncode}: {(r.stderr or r.stdout)[:160]}'
    # nginx -t 通过才 reload —— 语法错的话宁可保持原状，也不要把 nginx 弄挂
    try:
        t = subprocess.run(['nginx', '-t', '-c', '/etc/nginx/uci.conf',
                            '-g', 'daemon off;'],
                           capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return False, f'nginx -t 失败: {type(e).__name__}: {e}'
    if t.returncode != 0:
        return False, f'渲染结果语法错误，已保持原配置: {(t.stderr or t.stdout)[:200]}'
    try:
        subprocess.run([NGINX_INIT_PATH, 'reload'],
                       capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return False, f'reload 失败: {type(e).__name__}: {e}'
    time.sleep(1.5)
    return True, f'nginx 已重新渲染并 reload（{what}）'


def _luci_actual_state():
    """LuCI 当前**实际**是不是开着 —— 看 /etc/config/nginx 里那两段还在不在。

    这才是「实际状态」；配置文件里的 luci_enabled 只是「期望状态」。
    两者可能对不上，而且必然会对不上：
      · 升级到带 luci_enabled 的版本时，老配置里根本没这个字段，
        走 DEFAULT 取到 False，但机器上 LuCI 一直开着
      · 用户手工 uci 改了、或在 LuCI 界面里改了什么
      · 上一次切换失败，配置项已回滚而系统没跟上
    只比「配置有没有变」会漏掉以上全部情形。
    """
    names = set(_uci_section_names(_uci_conf_text()))
    return bool(names & set(LUCI_SECTIONS))


def _luci_reconcile(desired):
    """把 LuCI 实际状态调到期望状态。返回 (是否动过, 说明)。"""
    want = bool(desired)
    try:
        actual = _luci_actual_state()
    except Exception as e:
        return False, f'读 LuCI 状态失败: {e}'
    if actual == want:
        return False, '实际状态已与配置一致'
    return _apply_luci_toggle(want)


def _apply_luci_toggle(enabled):
    """按配置里的 luci_enabled 开关 LuCI 的 80/443。返回 (ok, 说明)。

    enabled=False → 从 /etc/config/nginx 摘掉 _lan / _redirect2ssl 两段
    enabled=True  → 从快照整份还原（用户中途改过 LuCI 配置也不会被覆盖，
                    因为快照只在第一次关之前写一次）
    """
    text = _uci_conf_text()
    if not text:
        return False, f'读不到 {LUCI_CONF_PATH}，未改动 LuCI'
    present = set(_uci_section_names(text))

    if not enabled:
        if not (present & set(LUCI_SECTIONS)):
            return True, 'LuCI 80/443 本来就没在配置里，无需处理'
        _luci_snapshot()
        new_text = _uci_strip_sections(text, LUCI_SECTIONS)
        tmp = LUCI_CONF_PATH + '.nftweb.tmp'
        try:
            with open(tmp, 'w') as f:
                f.write(new_text)
            os.replace(tmp, LUCI_CONF_PATH)
        except OSError as e:
            _unlink_quiet(tmp)
            return False, f'写入 {LUCI_CONF_PATH} 失败: {e}'
        ok, msg = _luci_reload_nginx('已摘除 LuCI 的 80/443')
        if not ok:
            return False, msg
        left = _luci_ports_listening()
        if left:
            return False, f'已改配置但 {sorted(left)} 仍在监听，未达到预期（{msg}）'
        return True, 'LuCI 80/443 已关闭'

    # enabled=True
    if present & set(LUCI_SECTIONS):
        return True, 'LuCI 80/443 已经在配置里，无需处理'
    if not os.path.exists(LUCI_SNAPSHOT_PATH):
        return False, (f'没有 {LUCI_SNAPSHOT_PATH} 快照，无法自动还原 LuCI 配置。'
                       f'请手工在 /etc/config/nginx 里补上 server 段后 reload nginx')
    try:
        shutil.copy(LUCI_SNAPSHOT_PATH, LUCI_CONF_PATH)
    except OSError as e:
        return False, f'从快照还原失败: {e}'
    ok, msg = _luci_reload_nginx('已从快照还原 LuCI')
    if not ok:
        return False, msg
    return True, 'LuCI 80/443 已重新打开'


def _gateway_port_alive(port=None, config=None):
    """网关端口是否还在听 —— 关 LuCI 时绝不能把它带下去。

    端口**必须取自配置**（gateway_port），不能写死 GATEWAY_PORT：
    用户把公网入口改成 9443 之后，这里还去连 8443 会得到两个方向的错误答案 ——
    8443 上恰好有别的东西在听就误判「网关健在」，没人听就把一个好好的
    网关当成已经死了，然后触发 GATEWAY_DOWN 回滚，白白把 LuCI 又打开。
    """
    if port is None:
        if config is None:
            config = load_config()
        port = _safe_port(config.get('gateway_port'), 8443)
    try:
        with socket.create_connection(('127.0.0.1', int(port)), timeout=3):
            return True
    except (OSError, ValueError, TypeError):
        return False


def _gateway_conf_path():
    return os.path.join(NGINX_CONF_DIR, GATEWAY_CONF_NAME)


def _gateway_actual_state(config=None):
    """网关当前**实际**是什么状态。

    和 luci_enabled 的教训一模一样：配置文件里的 gateway_enabled 只是「期望」。
    实测（.224）配置写着 true、面板也显示「已启用」，而
    /etc/nginx/conf.d/00-nftables-web-gateway.conf 已经不在了 —— 8443 无人监听，
    公网唯一入口是死的，界面却毫无提示。

    判据给三项，因为三者会各自单独出错：
      conf_exists   文件在不在（被谁删了 / 从没部署过）
      port_listening 端口有没有人听（conf 在但 nginx 没 reload 也会是死的）
      enabled       两者都成立才算真的开着
    """
    if config is None:
        config = load_config()
    exists = os.path.exists(_gateway_conf_path())
    port = _safe_port(config.get('gateway_port'), 8443)
    listening = _gateway_port_alive(port=port)
    return {
        'nginx_conf_exists': exists,
        'port': port,
        'port_listening': listening,
        'enabled': bool(exists and listening),
    }


def _is_managed_conf(conf_path):
    """判断某个 nginx conf 是否由本面板生成（只认文件头标记）"""
    try:
        with open(conf_path, 'r', errors='ignore') as f:
            first = f.readline().strip()
        return first in (RP_CONF_MARKER, GATEWAY_CONF_MARKER)
    except OSError:
        return False


def _gateway_services(config):
    """取出参与网关分发的服务列表（已启用 + 有合法 path 前缀）。

    返回 [(rule, prefix, protocol, host, port), ...]，越界的配置在这里被丢掉，
    保证生成的 nginx 配置里只可能出现经过净化的值。
    """
    rp = config.get("reverse_proxy")
    rules = rp.get("rules") if isinstance(rp, dict) else None
    out = []
    for r in (rules or []):
        if not isinstance(r, dict) or not r.get("enabled"):
            continue
        prefix = _safe_path_prefix(r.get("path_prefix", ""))
        if not prefix or prefix in _RESERVED_GATEWAY_PREFIXES:
            continue
        protocol, addr = "http", str(r.get("target_address", "") or "").strip()
        if not addr:
            continue
        if "://" in addr:
            protocol, _, addr = addr.partition("://")
            protocol = protocol.lower()
        if protocol not in ("http", "https"):
            continue
        host, _, port = addr.rpartition(":")
        host, port = host.strip(), port.strip()
        if not host or not _is_port(port):
            continue
        if not (_RE_IFACE.match(host) or _valid_ip(host, 6) or _valid_ip(host, 4)):
            continue
        out.append((r, prefix, protocol, host, int(port)))
    out.sort(key=lambda x: x[1])
    return out


def _generate_gateway_nginx_conf(config):
    """生成单端口认证网关的 nginx 配置。

    结构：
      /_auth      internal，只给 auth_request 用，外部无法直接访问
      /auth/*     认证端点（登录/登出/状态/门户），浏览器直接访问
      /           门户页（转发到认证服务的 /auth/portal）
      /<prefix>/  每个服务一个 location
        · public_access=true  → 所有来源可达，但必须过 auth_request
        · public_access=false → 只放行 LAN 网段，直接 deny 其他来源

    为什么 public_access=false 不用认证层拦：认证层只管「有没有 token」，
    管不了「从哪来」。一个 WAN 用户登录后照样能摸到这个服务。
    来源限制必须在 nginx 里用 allow/deny 落地，才是真的只对内网开放。

    注意：log_format 必须在 http 上下文里定义。conf.d/*.conf 正是被
    include 进 http 的，所以放在文件顶部是合法的。
    """
    if not config.get("gateway_enabled"):
        return None

    port = _safe_port(config.get("gateway_port"), 8443)
    api_port = _safe_port(config.get("auth_api_port"), 8444)
    services = _gateway_services(config)
    settings = {}
    # reverse_proxy 必须是 dict，不能只在下面取 settings 时才判类型。
    #
    # DEFAULT_CONFIG 里压根没有 reverse_proxy 这个键，全新安装（或配置文件
    # 缺失回落到默认配置）时 config.get("reverse_proxy") 就是 None。
    # 紧接着的 rp.get("certificates") 会直接 AttributeError，
    # 整个网关配置生成崩掉 —— 表现为「全新装完打开网关开关就报错」，
    # .224 真机复现过。_get_rp_config() 本来会做这个规范化，
    # 但这个函数是绕开它自己读 config 的，所以得自己兜住。
    rp = config.get("reverse_proxy")
    if not isinstance(rp, dict):
        rp = {}
    if isinstance(rp.get("settings"), dict):
        settings = rp["settings"]

    cert_id = str(settings.get("default_cert_id", "") or "")
    certs = {c.get("id"): c for c in (rp.get("certificates") or [])
             if isinstance(c, dict)}
    chosen = certs.get(cert_id)
    if not chosen:
        # 回落到面板自签/自带证书
        cert_path, key_path = NFTABLES_WEB_CERT, NFTABLES_WEB_KEY
    else:
        cert_path = chosen.get("cert_path", "")
        key_path = chosen.get("key_path", "")

    lan_cidr = _safe_cidr(config.get("lan_subnet4"), "192.168.0.0/16")
    tls_min = settings.get("tls_min_version", "TLSv1.2")
    tls_protos = TLS_VERSION_MAP.get(tls_min, "TLSv1.2 TLSv1.3")
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    L = []
    L.append(GATEWAY_CONF_MARKER)
    L.append(f"# 认证网关：单端口 {port}，{len(services)} 个服务按 path 前缀分发")
    L.append(f"# 生成时间: {now_str}")
    L.append("# 请勿手动修改 —— 面板会在保存配置时重新生成本文件")
    L.append("")

    # 访问日志：现状是项目生成的 nginx conf 里一条 access_log 都没有，
    # 设备识别、审计、异常检测全都依赖这一条，是整个方案的地基。
    # 记 $uri 而不是 $request_uri：后者带查询串，容易把敏感参数写进日志。
    L.append("log_format nftgw '$time_iso8601 $remote_addr $request_method '")
    L.append("                '$status $body_bytes_sent rt=$request_time '")
    L.append("                'host=\"$host\" uri=\"$uri\" '")
    L.append("                'ua=\"$http_user_agent\" ref=\"$http_referer\" '")
    L.append("                'auth_user=\"$auth_user\" auth_dev=\"$auth_device\"';")
    L.append("")

    L.append("server {")
    L.append(f"    listen {port} ssl;")
    L.append(f"    listen [::]:{port} ssl;")
    L.append("    http2 on;")
    L.append("    server_tokens off;")
    # 认证身份变量的服务器级默认值。
    #
    # 少了这两行：「网关开着 + 一个反代服务都没有」会让整份配置被 nginx 拒绝加载。
    # 原因很隐蔽 —— access_log 的 log_format 引用了 $auth_user / $auth_device，
    # 而真正给它们赋值的 auth_request_set 只写在「每个反代服务」的 location 里。
    # 服务数为 0 时那个循环一次都不执行，两个变量从头到尾没人定义，nginx 启动就
    # [emerg] unknown "auth_user" variable 直接罢工。
    #
    # 这不是什么边角状态：删掉最后一个反代服务后保存配置，落地的就是它。
    # 而且后果不是「网关少了点东西」，是**整个网关连同 portal、登录页一起没了**。
    #
    # 这里显式给出空默认值，变量恒存在；服务 location 里的 auth_request_set
    # 会在认证子请求返回后覆盖成真实值，不影响鉴权与审计。
    L.append("    # 认证身份变量默认值（服务 location 内由 auth_request_set 覆盖）")
    L.append('    set $auth_user "";')
    L.append('    set $auth_device "";')
    L.append("")
    L.append("    # SSL")
    L.append(f"    ssl_certificate {cert_path};")
    L.append(f"    ssl_certificate_key {key_path};")
    L.append(f"    ssl_protocols {tls_protos};")
    L.append("    ssl_prefer_server_ciphers on;")
    L.append("    ssl_session_timeout 1d;")
    # 共享内存区名在 nginx 里是全局的：同名但大小不同会直接 [emerg] 拒绝加载整份配置。
    # OpenWrt 的 LuCI 已经声明了 shared:SSL:32k，这里若再用 shared:SSL:50m 就冲突。
    # 用独立的区名彻底避开与其他 server 块的碰撞。
    L.append(f"    ssl_session_cache shared:{GATEWAY_SSL_ZONE}:{GATEWAY_SSL_CACHE_SIZE};")
    L.append("    ssl_session_tickets off;")
    L.append("")
    L.append("    access_log /var/log/nginx/nftables-web-gateway.access.log nftgw;")
    L.append("    error_log  /var/log/nginx/nftables-web-gateway.error.log warn;")
    L.append("")

    # ── 认证子请求入口 ──────────────────────────────────────────
    # internal = 外部无法直接访问 /_auth，只能由 nginx 内部发起。
    L.append("    # 认证子请求：仅供 auth_request 调用，外部无法直接访问")
    L.append("    location = /_auth {")
    L.append("        internal;")
    L.append(f"        proxy_pass http://127.0.0.1:{api_port}/auth/verify;")
    L.append("        proxy_pass_request_body off;")
    L.append("        proxy_set_header Content-Length \"\";")
    L.append("        proxy_set_header Cookie $http_cookie;")
    L.append("        proxy_set_header Authorization $http_authorization;")
    L.append("        # 认证服务只听 127.0.0.1，remote_addr 永远是本机，")
    L.append("        # 判断「是否内网来源」必须靠这里透传的真实客户端 IP。")
    L.append("        proxy_set_header X-Real-IP $remote_addr;")
    L.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
    L.append("        proxy_set_header X-Original-URI $request_uri;")
    L.append("        proxy_read_timeout 10s;")
    L.append("    }")
    L.append("")

    # ── 认证端点（浏览器直连） ──────────────────────────────────
    #
    # 公网只需要这 5 个端点，必须逐个精确列举，绝不能图省事写成
    # `location /auth/` —— 那是**前缀匹配**，会把认证服务下所有 /auth/* 一并
    # 暴露出去，其中包括：
    #   /auth/verify  仅供上面的 location = /_auth 以 auth_request 方式内部调用
    #                  （它自带 internal; 保护），本不该有任何外部入口
    #   /auth/health  探活端点，外部可达等于泄露服务存在与内部状态
    # 认证服务里任何新加的 /auth/* 端点都会默认被这个前缀匹配带出去 ——
    # 属于典型的「默认开放」，所以改成白名单式精确列举。
    L.append("    # 认证端点：只暴露登录/登出/状态/门户数据/静态资源，其余一律 404")
    for _ep, _comment in (("/auth/login", "登录页 GET + 登录提交 POST"),
                          ("/auth/logout", "登出"),
                          ("/auth/status", "会话状态"),
                          ("/auth/portal", "门户服务列表（需已认证）")):
        L.append(f"    # {_comment}")
        L.append(f"    location = {_ep} {{")
        L.append(f"        proxy_pass http://127.0.0.1:{api_port}{_ep};")
        L.append("        proxy_set_header X-Real-IP $remote_addr;")
        L.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
        L.append("        proxy_set_header X-Original-URI $request_uri;")
        L.append("        proxy_set_header Host $host;")
        L.append("    }")
        L.append("")

    L.append("    # 认证页面的 CSS/JS（白名单文件，见 auth_gateway.STATIC_ALLOWED）")
    L.append("    location /auth/static/ {")
    L.append(f"        proxy_pass http://127.0.0.1:{api_port};")
    L.append("        proxy_set_header X-Real-IP $remote_addr;")
    L.append("        proxy_set_header Host $host;")
    L.append("    }")
    L.append("")

    L.append("    # 其余 /auth/* 一律不认：verify / health 等内部端点到此为止")
    L.append("    location /auth/ {")
    L.append("        return 404;")
    L.append("    }")
    L.append("")

    # ── 门户页 ──────────────────────────────────────────────────
    # 转发到认证服务的根路径（那里返回门户 HTML）。
    # 不要转 /auth/portal —— 那是给页面调用的 JSON 接口。
    L.append("    # 门户页：登录后展示可访问的服务列表")
    L.append("    location = / {")
    L.append(f"        proxy_pass http://127.0.0.1:{api_port};")
    L.append("        proxy_set_header X-Real-IP $remote_addr;")
    L.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
    L.append("        proxy_set_header Host $host;")
    L.append("        # 门户是内网入口，不该被搜索引擎收录")
    L.append("        add_header X-Robots-Tag \"noindex, nofollow\" always;")
    L.append("    }")
    L.append("")

    # ── 各服务 location ─────────────────────────────────────────
    for rule, prefix, protocol, host, tport in services:
        name = _sanitize_name(rule.get("name") or prefix)
        try:
            cmbs = _sanitize_client_max_body_size(rule.get("client_max_body_size", "")) or "0"
        except ValueError:
            # 配置被手工改坏时退回「不限」，但不能因此让整份配置生成失败
            print(f'[WARN] 服务 {name} 的 client_max_body_size 非法，已按不限处理', flush=True)
            cmbs = "0"
        L.append(f"    # ---- {name} ----")
        L.append(f"    location {prefix}/ {{")
        L.append(f"        proxy_pass {protocol}://{host}:{tport}/;")
        L.append("        proxy_set_header Host $http_host;")
        L.append("        proxy_set_header X-Real-IP $remote_addr;")
        L.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
        L.append("        proxy_set_header X-Forwarded-Proto $scheme;")
        L.append("        proxy_set_header X-Forwarded-Host $host;")
        L.append("        proxy_set_header X-Forwarded-Port $server_port;")
        L.append("        proxy_set_header X-Auth-User $auth_user;")
        L.append("        proxy_set_header X-Auth-Device $auth_device;")

        if rule.get("public_access"):
            # 公网可达 → 无条件要求认证
            L.append("        # public_access=true：所有来源可达，但必须先过认证")
            L.append("        auth_request /_auth;")
            L.append("        error_page 401 = @to_login;")
            L.append("        auth_request_set $auth_user $upstream_http_x_auth_user;")
            L.append("        auth_request_set $auth_device $upstream_http_x_auth_device;")
        else:
            # 仅内网 → 按来源地址拦截，不进认证
            L.append(f"        # public_access=false：仅内网 {lan_cidr} 可达，公网直连被拒")
            L.append(f"        allow {lan_cidr};")
            # 回环白名单：IPv4 和 IPv6 都要写。
            # 原来只写了 `allow ::1;` —— 于是 `curl https://127.0.0.1:8443/dsm/`
            # 从路由器本机发起的 IPv4 回环请求不在 lan_cidr 里，直接吃 deny all
            # 变成 403，而同样语义的 `curl https://[::1]:8443/dsm/` 却能通。
            # 同一个「本机」两种结果，纯属遗漏。
            # 安全上没有风险：127.0.0.1 只有路由器自己发起的连接才是这个源地址，
            # 公网侧根本无法伪造（WAN 入向本来就有反伪造 drop）。
            L.append("        allow 127.0.0.1;")
            L.append("        allow ::1;")
            L.append("        deny all;")
            L.append("        auth_request_set $auth_user \"lan\";")
            L.append("        auth_request_set $auth_device $cookie_gw_device;")

        # 认证服务不可达时的 fail-closed 行为：
        # auth_request 拿不到上游 → nginx 自己返回 5xx，不会放行。
        L.append("        proxy_read_timeout 300s;")
        L.append("        proxy_send_timeout 300s;")
        L.append("        proxy_buffering off;")
        L.append("        proxy_request_buffering off;")
        if rule.get("websocket_enabled", True):
            L.append("        proxy_http_version 1.1;")
            L.append("        proxy_set_header Upgrade $http_upgrade;")
            L.append("        proxy_set_header Connection \"upgrade\";")
        else:
            L.append("        proxy_http_version 1.1;")
        # 上传体积限制：用户配的值在这里**真正生效**。
        # v0.8.0 这里硬编码 0（不限），界面上填的 client_max_body_size
        # 只对已废弃的独立站点生效，网关这一侧被完全忽略 —— 配了没反应。
        # 0 是 nginx 的「不限」，仍作为空值时的默认。
        L.append(f"        client_max_body_size {cmbs};   # 上传体积限制（0=不限）")
        L.append("    }")
        L.append("")

    # ── 跳登录 ──────────────────────────────────────────────────
    # 端口必须显式带上：nginx 变量 $host 只含主机名、不含端口，
    # 而本项目的网关端口按设计就是自定义高位端口（家宽常用非 443）。
    # 漏掉端口会把用户甩到 443 去 —— 要么打不开，要么撞上别的服务。
    # 这里用配置里的 port 而非 $http_host：后者是客户端可控的 Host 头，
    # 拼进重定向就是 Host Header 注入。$host 经 nginx 校验，相对安全。
    if port == 443:
        L.append("    location @to_login {")
        L.append("        return 302 https://$host/auth/login?next=$request_uri;")
        L.append("    }")
    else:
        L.append(f"    location @to_login {{")
        L.append(f"        return 302 https://$host:{port}/auth/login?next=$request_uri;")
        L.append("    }")
    L.append("")
    L.append("    location = /favicon.ico { return 204; }")
    L.append("}")
    L.append("")

    return "\n".join(L)


def _deploy_gateway_nginx(config=None):
    """生成并启用网关 nginx 配置。返回 (ok, message)。

    与 _deploy_all_rules 同样的安全约束：部署前整目录快照，
    `nginx -t` 失败时整体回滚，避免留下「新配置全错 + 旧配置全没」的状态。
    网关关掉时是删除本面板的网关配置文件（不碰别人的）。
    """
    if config is None:
        config = load_config()
    conf_path = os.path.join(NGINX_CONF_DIR, GATEWAY_CONF_NAME)
    enabled = bool(config.get("gateway_enabled"))

    content = _generate_gateway_nginx_conf(config) if enabled else None
    if enabled and not content:
        return False, "网关已启用，但没有可分发的服务（需要已启用且配置了 path 前缀的反代规则）"

    backup_dir = NGINX_CONF_DIR + '.gwdeploybak'
    shutil.rmtree(backup_dir, ignore_errors=True)
    have_backup = False
    if os.path.isdir(NGINX_CONF_DIR):
        try:
            shutil.copytree(NGINX_CONF_DIR, backup_dir)
            have_backup = True
        except OSError as e:
            print(f'[WARN] 网关配置快照失败: {e}', flush=True)

    def _undo(msg):
        # ⚠️ 顺序不能反。原先是「先 rmtree 快照，再 copytree 回来」——
        # 快照先被删掉，copytree 必然失败，于是每次回滚都报「回滚也失败」；
        # 更糟的是它在失败前已经把整个 NGINX_CONF_DIR 删了，用户自己放在
        # conf.d 下的站点配置会全部丢失。这个顺序错误在本文件里出现过两次
        # （另一处在 _deploy_all_rules 的 _rollback），一律改成
        # 「先恢复，最后才清理快照」。
        if not have_backup:
            shutil.rmtree(backup_dir, ignore_errors=True)
            # 没有历史可回滚，如实说明，不谎称已回滚
            return False, f"{msg}（无可回滚的历史配置）"
        try:
            shutil.rmtree(NGINX_CONF_DIR, ignore_errors=True)
            shutil.copytree(backup_dir, NGINX_CONF_DIR)
        except Exception as e:
            # 恢复失败时**保留快照**，让用户还能手工捞回来
            print(f'[ERROR] 网关配置回滚失败，快照保留在 {backup_dir}: {e}', flush=True)
            return False, (f"{msg}（回滚失败，快照已保留在 {backup_dir}，"
                           f"请手工恢复: {e}）")
        shutil.rmtree(backup_dir, ignore_errors=True)
        _nginx_reload()
        return False, f"{msg}（已回滚 nginx 配置）"

    try:
        os.makedirs(NGINX_CONF_DIR, exist_ok=True)
        if enabled:
            tmp = conf_path + '.tmp'
            with open(tmp, 'w') as f:
                f.write(content)
            ok, msg = _nginx_test()
            if not ok:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                return _undo(f"网关配置校验失败：{msg}")
            os.replace(tmp, conf_path)
        else:
            # 只删自己那个文件
            if os.path.exists(conf_path):
                try:
                    with open(conf_path) as f:
                        if f.readline().strip() == GATEWAY_CONF_MARKER:
                            os.remove(conf_path)
                except OSError as e:
                    return False, f"删除网关配置失败：{e}"

        ok, msg = _nginx_test()
        if not ok:
            return _undo(f"nginx -t 失败：{msg}")

        # 走 _nginx_reload 而不是裸调 init 脚本：它自带降级（init → nginx -s
        # reload → 直接启动）。裸调在普通 Linux（systemctl 环境，没有
        # /etc/init.d/nginx）会抛 FileNotFoundError，让整个部署崩掉。
        _r_ok, r_msg = _nginx_reload()
        if not _r_ok:
            return False, f"网关配置已写入，但 nginx 重载失败：{r_msg}"
        shutil.rmtree(backup_dir, ignore_errors=True)
        if enabled:
            n = len(_gateway_services(config))
            return True, f"认证网关已启用：端口 {config.get('gateway_port')}，{n} 个服务"
        return True, "认证网关已停用，配置已移除"
    except Exception as e:
        return _undo(f"部署网关配置异常：{e}")


def _nginx_test():
    """测试 nginx 配置，忽略 warn 只检查 error"""
    try:
        result = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=10)
        output = result.stderr or result.stdout or ""
        if result.returncode != 0:
            return False, output.strip()
        # 只关心 error 行，warn 可忽略
        for line in output.splitlines():
            if "error" in line.lower():
                return False, line.strip()
        return True, "nginx 配置语法正确"
    except FileNotFoundError:
        return False, "nginx 未安装"
    except subprocess.TimeoutExpired:
        return False, "nginx -t 命令超时"
    except Exception as e:
        return False, str(e)


def _nginx_reload():
    """重载 nginx，如果没运行则启动"""
    try:
        result = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, "nginx 已重载"
    except Exception:
        pass
    # reload 失败，尝试直接启动
    try:
        result = subprocess.run(["nginx"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, "nginx 已启动"
        else:
            return False, f"nginx 启动失败: {result.stderr}"
    except Exception as e:
        return False, f"nginx 启动失败: {str(e)}"


def _acme_load_aliyun_credentials():
    """从阿里云 DDNS 配置中读取 AK/SK，返回 (ak_id, ak_secret)"""
    cfg = _load_aliyun_ddns_config()
    if not cfg:
        return None, None
    return cfg.get("access_key_id", ""), cfg.get("access_key_secret", "")


def _acme_issue(domain, dns_provider="ali", dns_credentials=None):
    """使用 acme.sh + 指定 DNS 提供商申请证书，返回 (ok, result_dict)"""
    domain = _sanitize_domain(domain)
    provider = DNS_PROVIDERS.get(dns_provider)
    if not provider:
        return False, {"error": f"不支持的 DNS 提供商: {dns_provider}"}

    # 收集凭证
    if dns_credentials:
        creds = dns_credentials
    else:
        return False, {"error": f"未提供 {provider['name']} 的 DNS 凭证"}

    # 检查必填字段
    for field in provider["fields"]:
        if not creds.get(field["key"]):
            return False, {"error": f"缺少字段: {field['label']}"}

    if not os.path.exists(ACME_SH_PATH):
        return False, {"error": f"acme.sh 未安装: {ACME_SH_PATH}"}

    cert_dir = os.path.join(NGINX_SSL_DIR, domain)
    os.makedirs(cert_dir, exist_ok=True)

    env = os.environ.copy()
    for field in provider["fields"]:
        env[field["key"]] = creds[field["key"]]

    # 申请证书
    try:
        result = subprocess.run(
            [ACME_SH_PATH, "--issue", "--dns", provider["acme_param"], "-d", domain, "--force"],
            capture_output=True, text=True, env=env, timeout=300
        )
        if result.returncode != 0:
            return False, {"error": "证书申请失败", "log": (result.stderr + result.stdout)[-2000:]}
    except subprocess.TimeoutExpired:
        return False, {"error": "证书申请超时（5分钟）"}
    except Exception as e:
        return False, {"error": str(e)}

    # 安装证书
    fullchain = os.path.join(cert_dir, "fullchain.pem")
    keyfile = os.path.join(cert_dir, "privkey.pem")
    certfile = os.path.join(cert_dir, "cert.pem")
    try:
        result = subprocess.run(
            [ACME_SH_PATH, "--install-cert", "-d", domain,
             "--fullchain-file", fullchain,
             "--key-file", keyfile,
             "--cert-file", certfile,
             "--reloadcmd", "nginx -s reload"],
            capture_output=True, text=True, env=env, timeout=60
        )
        if result.returncode != 0:
            return False, {"error": "证书安装失败", "log": (result.stderr + result.stdout)[-2000:]}
    except Exception as e:
        return False, {"error": str(e)}

    # acme.sh 以 root 写出 privkey.pem（600 root）。nginx worker 现在以
    # NGINX_WORKER_USER 运行，不补组读权限的话它读不到私钥 → TLS 握手失败，
    # 而面板这边 expires_at 正常、UI 显示「有效」，故障表现为浏览器一个
    # 证书错误，排障方向会被完全带偏。
    _harden_key_for_nginx_worker(keyfile)

    expires_at, days = _get_cert_expiry(fullchain)
    return True, {
        "cert_path": fullchain,
        "key_path": keyfile,
        "expires_at": expires_at,
        "days_remaining": days,
    }


def _acme_renew(domain, dns_provider="ali", dns_credentials=None):
    """使用 acme.sh 续期证书"""
    domain = _sanitize_domain(domain)
    provider = DNS_PROVIDERS.get(dns_provider)
    if not provider:
        return False, {"error": f"不支持的 DNS 提供商: {dns_provider}"}

    creds = dns_credentials or {}
    if not os.path.exists(ACME_SH_PATH):
        return False, {"error": "acme.sh 未安装"}

    env = os.environ.copy()
    for field in provider["fields"]:
        if creds.get(field["key"]):
            env[field["key"]] = creds[field["key"]]

    try:
        result = subprocess.run(
            [ACME_SH_PATH, "--renew", "-d", domain, "--force"],
            capture_output=True, text=True, env=env, timeout=120
        )
        if result.returncode != 0:
            return False, {"error": "证书续期失败", "log": (result.stderr + result.stdout)[-2000:]}
    except Exception as e:
        return False, {"error": str(e)}

    cert_dir = os.path.join(NGINX_SSL_DIR, domain)
    fullchain = os.path.join(cert_dir, "fullchain.pem")
    # 同 _acme_issue：续期会重写 privkey.pem，权限必须跟着补。
    # 路径固定可推导，不需要问 acme.sh 要 key 在哪。
    _harden_key_for_nginx_worker(os.path.join(cert_dir, "privkey.pem"))
    expires_at, days = _get_cert_expiry(fullchain)
    return True, {"new_expires_at": expires_at, "days_remaining": days}


def _deploy_all_rules(config=None):
    """重新生成认证网关配置并重载 nginx。

    v0.8.1：反代服务只有网关一条暴露面（gateway_port + path 前缀），
    不再为每条规则生成独立的站点 conf。原先这里同时生成两套 —— 一套无认证、
    一套有认证，导致 public_access 在两处含义不同、用户配的字段一半失效。

    保留的安全约束：
      1. 只删「属于本面板」的 conf（带本面板标记），用户自己放在 conf.d
         下的站点配置一律不动。
      2. 部署前整目录快照，nginx -t 失败时整体回滚。
    """
    if config is None:
        config = load_config()
    config = _migrate_rp_rules(config)

    # 部署前整目录快照（仅当已有内容时），供 nginx -t 失败时回滚
    backup_dir = NGINX_CONF_DIR + '.deploybak'
    shutil.rmtree(backup_dir, ignore_errors=True)
    if os.path.isdir(NGINX_CONF_DIR):
        try:
            shutil.copytree(NGINX_CONF_DIR, backup_dir)
        except OSError as e:
            print(f'[WARN] nginx conf 目录快照失败: {e}', flush=True)
            backup_dir = None
    else:
        backup_dir = None

    def _rollback(msg):
        if backup_dir is None or not os.path.isdir(backup_dir):
            # 首次部署：conf.d 原本就不存在，没有可回滚的历史状态。
            return False, f"{msg}（首次部署，无历史配置可回滚；新配置已写入磁盘但 nginx 未重载）"
        try:
            shutil.rmtree(NGINX_CONF_DIR, ignore_errors=True)
            shutil.copytree(backup_dir, NGINX_CONF_DIR)
            _nginx_reload()
        except Exception as e:
            print(f'[WARN] nginx conf 回滚失败: {e}', flush=True)
            shutil.rmtree(backup_dir, ignore_errors=True)
            return False, f"{msg}（回滚 nginx 配置也失败，请手工检查 {NGINX_CONF_DIR}）"
        # 恢复成功之后才清理快照
        shutil.rmtree(backup_dir, ignore_errors=True)
        return False, f"{msg}（已回滚 nginx 配置，nginx 仍运行原配置）"

    try:
        # 清理本面板遗留的旧站点 conf。
        # v0.8.0 之前每条规则都会生成 {domain}-{port}.conf，那批文件带本面板
        # 标记（RP_CONF_MARKER），现在没有任何用途，必须清掉 —— 留着就是
        # 一批无认证的站点配置还在 nginx 里跑着。
        removed = 0
        if os.path.isdir(NGINX_CONF_DIR):
            for fname in os.listdir(NGINX_CONF_DIR):
                if not fname.endswith('.conf') or fname == GATEWAY_CONF_NAME:
                    continue
                full = os.path.join(NGINX_CONF_DIR, fname)
                if _is_managed_conf(full):
                    try:
                        os.remove(full)
                        removed += 1
                    except OSError as e:
                        print(f'[WARN] 删除遗留 nginx 配置失败 {fname}: {e}', flush=True)
        if removed:
            print(f'[INFO] 已清理 {removed} 个 v0.8.0 遗留的独立站点配置', flush=True)

        # 生成网关配置（唯一一份）
        ok, msg = _deploy_gateway_nginx(config)
    except Exception as e:
        return _rollback(f"生成 nginx 配置时异常: {type(e).__name__}: {e}")

    if not ok:
        return _rollback(f"nginx 配置语法错误，未重载: {msg}")

    # 快照到 nginx -t 通过之后再清
    shutil.rmtree(backup_dir, ignore_errors=True)
    return True, msg



# ======================= 认证网关 API =======================
#
# 前端页面（门户/登录/指纹）还没做，但后端必须先可管：
# 否则「网关到底开没开、开着几个服务」只能靠翻配置文件，不符合可运维的要求。

@app.route('/api/gateway/status', methods=['GET'])
def gateway_status():
    config = load_config()
    services = _gateway_services(config)
    gw_port = _safe_port(config.get("gateway_port"), 8443)
    api_port = _safe_port(config.get("auth_api_port"), 8444)

    # 探测认证服务（进程 B）是否真的在跑
    auth_alive = False
    auth_msg = ""
    try:
        import urllib.request
        req = urllib.request.Request(
            f"http://127.0.0.1:{api_port}/auth/health", method="GET")
        with urllib.request.urlopen(req, timeout=3) as r:
            auth_alive = (r.status == 200)
    except Exception as e:
        auth_msg = f"{type(e).__name__}: {e}"[:120]

    # 网关实际状态（conf 在不在 / 端口有没有人听）。读不到就当"不确定但没开"，
    # 宁可让面板报警也不要谎报健康 —— 这个接口的唯一价值就是不骗人。
    try:
        actual = _gateway_actual_state(config)
    except Exception as e:
        actual = {'nginx_conf_exists': False, 'port': gw_port,
                  'port_listening': False, 'enabled': False,
                  'error': f'{type(e).__name__}: {e}'[:120]}

    return jsonify({
        "success": True,
        "data": {
            "enabled": bool(config.get("gateway_enabled")),
            # enabled 只是**期望**。面板必须能看见实际情况，否则就重演 .224 那一出：
            # 磁盘 true、界面「已启用」、而公网唯一入口 8443 早就没人听了。
            "actual": actual,
            "divergent": bool(config.get("gateway_enabled")) != bool(actual.get("enabled")),
            "gateway_port": gw_port,
            "auth_api_port": api_port,
            "auth_alive": auth_alive,
            "auth_error": auth_msg,
            "public_url": f"https://<你的域名或公网IP>:{gw_port}/" if config.get("gateway_enabled") else None,
            "session_timeout": _int_or(config.get("auth_session_timeout"), 1800),
            "absolute_timeout": _int_or(config.get("auth_absolute_timeout"), 0),
            "lan_bypass": bool(config.get("auth_lan_bypass", True)),
            "services": [
                {
                    "name": str(r.get("name") or p.lstrip("/"))[:64],
                    "path": p,
                    "public": bool(r.get("public_access")),
                    "url": f"/{p}/",
                }
                for r, p, _pr, _h, _tp in services
            ],
            "nginx_conf": os.path.join(NGINX_CONF_DIR, GATEWAY_CONF_NAME)
                           if config.get("gateway_enabled") else None,
        }
    })


def _int_or(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


@app.route('/api/gateway/config', methods=['POST'])
def gateway_set_config():
    """更新网关相关配置项并下发。字段全部走 validate_config，非法一律 400。"""
    config = load_config()
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "请求体必须是 JSON 对象"}), 400

    allowed = set(GATEWAY_OWNED_CONFIG_KEYS) | {'deploy_mode'}
    new_cfg = dict(config)
    changed = []
    for k, v in data.items():
        if k not in allowed:
            return jsonify({"success": False,
                            "message": f"不支持的字段 {k!r}（可改: {', '.join(sorted(allowed))}）"}), 400
        # isinstance(True, int) 在 Python 里为真，所以数字字段必须显式把 bool 挡掉 ——
        # 但**只能对数字字段挡**。写成 `isinstance(v, bool) or (...)` 时这个判断在 or 的
        # 左边、不受字段名约束，于是 gateway_enabled / auth_lan_bypass 这两个合法布尔项
        # 也被一律拒绝：前端 saveGatewayConfig 每次都发这两个字段，于是「保存网关配置」
        # 从 v0.8.0 落地起就永远 400，网关开关在面板上根本没法用。
        if k.endswith(("_port", "_timeout")) and (isinstance(v, bool) or not isinstance(v, (int, float))):
            return jsonify({"success": False, "message": f"{k} 类型非法: {v!r}"}), 400
        if not isinstance(v, (bool, int, float, str, type(None), list, dict)):
            return jsonify({"success": False, "message": f"{k} 类型非法: {type(v).__name__}"}), 400
        new_cfg[k] = v
        changed.append(k)

    errs = validate_config(new_cfg)
    if errs:
        return jsonify({"success": False, "message": "；".join(errs),
                        "errors": errs}), 400

    # 先部署、后落盘 —— 与反代规则 CRUD 同一顺序。
    # 原来是 save_config() 在前：一旦 nginx 部署失败，磁盘上已经是新配置，
    # 而生效的是旧配置，两者从此不一致；用户看到「配置已保存但网关部署失败」，
    # 下次再动别的字段时又会基于这份落盘配置重新生成，静默放大问题。
    # _deploy_gateway_nginx 自己带快照与 _undo，失败不留痕。
    deploy_ok, deploy_msg = _deploy_gateway_nginx(new_cfg)
    if not deploy_ok:
        return jsonify({"success": False,
                        "message": f"网关部署失败，配置未保存：{deploy_msg}"}), 500

    # 装完必须**看一眼它到底起没起来**。
    #
    # _deploy_gateway_nginx 成功只代表「文件写了、nginx -t 过了、reload 没报错」。
    # .224 实测过一种它看不见的失败：conf 在、reload 也成功，可端口没人听 ——
    # 而接口照样回 200「认证网关已启用」。公网唯一入口是死的，
    # 界面还告诉用户「已启用」，这个谎必须在这里就戳破。
    #
    # 关闭网关不做这项校验：那时候端口没人听才是预期结果。
    if bool(new_cfg.get('gateway_enabled')):
        actual = _gateway_actual_state(new_cfg)
        if not actual['enabled']:
            why = []
            if not actual['nginx_conf_exists']:
                why.append(f'配置 {_gateway_conf_path()} 不存在')
            if not actual['port_listening']:
                why.append(f'端口 {actual["port"]} 没有监听')
            return jsonify({
                "success": False,
                "code": "GATEWAY_NOT_LISTENING",
                "message": (f'网关配置已下发但 {actual["port"]} 端口没有真正监听'
                            f'（{"；".join(why)}），已判定为未启用；配置未保存'),
                "data": {"actual": actual},
            }), 500

    save_config(new_cfg)

    # 改的是防火墙侧要放行的端口，必须同步 nftables，否则「配好了但公网连不上」
    fw_ok, fw_msg = _apply_ruleset(new_cfg)
    if not fw_ok:
        return jsonify({"success": False,
                        "message": f"网关配置已下发，但防火墙放行更新失败：{fw_msg}"}), 500

    return jsonify({"success": True,
                    "data": {"changed": changed, "message": deploy_msg}})


# ======================= 反代规则 API =======================

@app.route('/api/reverse-proxy/rules', methods=['GET'])
def rp_get_rules():
    """列出反代服务。

    v0.8.1：每条服务对应网关里的一段 location，证书是网关的统一证书，
    所以这里不再返回每条规则各自的证书信息与独立 conf 路径。
    """
    config, rp = _get_rp_config()
    config = _migrate_rp_rules(config)
    rules_out = []
    for r in rp["rules"]:
        rules_out.append({
            **r,
            # 访问地址：网关统一入口 + 路径前缀，UI 直接展示这个
            "access_url": f"{_safe_port(config.get('gateway_port'), 8443)}"
                          f"{r.get('path_prefix', '')}/",
        })
    return jsonify({"success": True,
                    "data": {"rules": rules_out, "total": len(rules_out)}})



@app.route('/api/reverse-proxy/rules', methods=['POST'])
def rp_create_rule():
    """新建一条反代服务。

    v0.8.1：反代服务只存在于认证网关一条路径上（gateway_port + path 前缀），
    证书用网关的统一证书。所以这里不再有 domain / listen_port / ssl_cert_id，
    规则本身也不再对应任何独立的 nginx 站点文件。
    """
    config, rp = _get_rp_config()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400

    clean, err = _validate_rp_service(data, existing={}, all_rules=rp["rules"])
    if err:
        return jsonify({"success": False, "message": err}), 400

    new_id = _next_id("rp", [r["id"] for r in rp["rules"]])
    now_iso = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
    rule = {"id": new_id, **clean,
            "created_at": now_iso, "updated_at": now_iso}
    rp["rules"].append(rule)

    # 交叉校验：这条反代的目标如果已经有端口转发指向它，就形成了一条免登录
    # 的公网入口 —— DNAT 走 nftables，根本不经过 nginx 的认证层。
    # 必须放在 append 之后（config 里才是候选状态）、部署之前（拦住才不生成
    # nginx 配置）。rp 是 config 的子字典引用，所以 pop 能干净地撤销 append。
    conflicts = _rp_forward_conflicts(config)
    if conflicts:
        rp["rules"].pop()
        return jsonify({"success": False, "message": "；".join(conflicts)}), 400

    # 顺序：先部署、后落盘。
    # 部署失败时**不保存**，否则这条规则会永久留在配置里 —— 之后每一次
    # 反代保存都会重新生成同样失败的 nginx 配置并返回 500，整个功能瘫掉。
    # _get_rp_config 每次请求都重新 load_config()，所以不落盘即等于没发生。
    deploy_ok, deploy_msg = _deploy_all_rules(config)
    if not deploy_ok:
        return jsonify({"success": False,
                        "message": f"网关配置未生效，规则已丢弃: {deploy_msg}"}), 500

    _save_rp_config(config)

    fw_ok, fw_msg = _apply_ruleset(config)
    if not fw_ok:
        return jsonify({"success": False, "message": fw_msg}), 500

    return jsonify({"success": True, "data": {
        "rule_id": new_id, "message": "反代服务已创建",
        "nginx_reloaded": True}})

@app.route('/api/reverse-proxy/rules/<rule_id>', methods=['PUT'])
def rp_update_rule(rule_id):
    """更新一条反代服务。校验入口与新建完全一致（_validate_rp_service）。"""
    config, rp = _get_rp_config()
    rule = _find_rp_rule(rp, rule_id)
    if not rule:
        return jsonify({"success": False, "message": "规则不存在"}), 404
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400

    clean, err = _validate_rp_service(data, existing=rule, all_rules=rp["rules"])
    if err:
        return jsonify({"success": False, "message": err}), 400

    now_iso = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
    created_at = rule.get("created_at", now_iso)
    original = dict(rule)          # 交叉校验失败时要原样还回去
    rule.clear()
    rule.update({"id": rule_id, **clean,
                 "created_at": created_at,
                 "updated_at": now_iso})

    # 交叉校验（同新建）：改动后的目标若与端口转发撞上，就是免登录入口。
    # 校验的是「已改完」的候选状态，所以放在 mutate 之后、部署之前。
    conflicts = _rp_forward_conflicts(config)
    if conflicts:
        rule.clear()
        rule.update(original)
        return jsonify({"success": False, "message": "；".join(conflicts)}), 400

    # 同新建：先部署、后落盘，部署失败不保存（理由见 rp_create_rule）
    deploy_ok, deploy_msg = _deploy_all_rules(config)
    if not deploy_ok:
        return jsonify({"success": False,
                        "message": f"网关配置未生效，修改已丢弃: {deploy_msg}"}), 500

    _save_rp_config(config)

    fw_ok, fw_msg = _apply_ruleset(config)
    if not fw_ok:
        return jsonify({"success": False, "message": fw_msg}), 500

    return jsonify({"success": True, "data": {
        "rule_id": rule_id, "message": "反代服务已更新",
        "nginx_reloaded": True}})

@app.route('/api/reverse-proxy/rules/<rule_id>', methods=['DELETE'])
def rp_delete_rule(rule_id):
    config, rp = _get_rp_config()
    rule = _find_rp_rule(rp, rule_id)
    if not rule:
        return jsonify({"success": False, "message": "规则不存在"}), 404
    rp["rules"] = [r for r in rp["rules"] if r["id"] != rule_id]
    # v0.8.1 起反代服务没有独立的站点 conf，删除后由 _deploy_all_rules
    # 重新生成网关配置即可，不需要单独删文件。
    #
    # 同新建/修改：先部署、后落盘。删除是唯一「必须落盘」和「必须部署成功」
    # 方向相反的场景，所以顺序照旧保留先部署 —— 部署失败则不落盘，
    # 规则仍在配置里、nginx 也仍跑着含该规则的配置，两边一致。
    deploy_ok, deploy_msg = _deploy_all_rules(config)

    if deploy_ok:
        _save_rp_config(config)

    # 更新防火墙（走统一的安全流程：语法预检 + 原子写盘 + 失败回滚）
    fw_ok, fw_msg = _apply_ruleset(config)
    if not fw_ok:
        return jsonify({"success": False, "message": fw_msg}), 500

    # nginx 侧彻底失败时不能回 success:true。此前这条路径只把 deploy_ok 塞进
    # 响应体的 nginx_reloaded 字段，顶层仍报成功 —— 前端只认顶层 success，
    # 于是「部署失败、nginx 还在跑含已删站点的旧配置」被显示成「删除成功」。
    if not deploy_ok:
        return jsonify({
            "success": False,
            "code": "NGINX_DEPLOY_FAILED",
            "message": f"nginx 配置未生效，删除已丢弃: {deploy_msg}",
            "data": {"message": "删除未生效（nginx 配置生成失败，规则仍在配置中）",
                     "nginx_reloaded": False},
        }), 500
    return jsonify({"success": True, "data": {"message": "反代规则已删除", "nginx_reloaded": deploy_ok}})


@app.route('/api/reverse-proxy/rules/<rule_id>/test', methods=['POST'])
def rp_test_rule(rule_id):
    config, rp = _get_rp_config()
    rule = _find_rp_rule(rp, rule_id)
    if not rule:
        return jsonify({"success": False, "message": "规则不存在"}), 404
    target = rule.get("target_address", "")
    if not target:
        return jsonify({"success": False, "message": "目标地址为空"}), 400

    # 解析 host:port
    host = target
    port = 80
    if ":" in target:
        parts = target.rsplit(":", 1)
        host, port = parts[0], int(parts[1])
    if rule.get("target_protocol") == "https":
        port = port or 443

    # TCP 连通性测试
    import socket
    reachable = False
    response_ms = -1
    try:
        t0 = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        response_ms = int((time.time() - t0) * 1000)
        sock.close()
        reachable = True
    except Exception as e:
        return jsonify({"success": True, "data": {"target_reachable": False, "response_time_ms": -1, "ssl_valid": False, "message": f"连接失败: {str(e)}"}})

    return jsonify({"success": True, "data": {
        "target_reachable": True,
        "response_time_ms": response_ms,
        "ssl_valid": True,
        "message": f"目标服务可达 ({response_ms}ms)"
    }})


# ======================= DNS 提供商 API =======================

@app.route('/api/reverse-proxy/dns-providers', methods=['GET'])
def rp_get_dns_providers():
    """获取所有支持的 DNS 提供商列表"""
    config, rp = _get_rp_config()
    stored_creds = rp.get("dns_credentials", {})
    providers_out = []
    for pid, pinfo in DNS_PROVIDERS.items():
        # 检查是否已配置
        creds = _get_dns_credentials(rp, pid)
        configured = bool(creds)
        # 构造 fields（脱敏）
        fields_out = []
        for field in pinfo["fields"]:
            f = {"key": field["key"], "label": field["label"], "type": field["type"]}
            if creds and creds.get(field["key"]):
                if field["type"] == "password":
                    f["value"] = _mask_password(creds[field["key"]])
                else:
                    f["value"] = creds[field["key"]][:4] + "****" if len(creds[field["key"]]) > 4 else "****"
            fields_out.append(f)
        providers_out.append({
            "id": pid,
            "name": pinfo["name"],
            "acme_param": pinfo["acme_param"],
            "fields": fields_out,
            "configured": configured,
        })
    return jsonify({"success": True, "data": {"providers": providers_out}})


# ======================= SSL 证书 API =======================

@app.route('/api/reverse-proxy/certificates', methods=['GET'])
def rp_get_certs():
    config, rp = _get_rp_config()
    certs_out = []
    for c in rp.get("certificates", []):
        expires_at, days = _get_cert_expiry(c.get("cert_path", ""))
        # 读取 issuer
        issuer = ""
        cp = c.get("cert_path", "")
        if cp and os.path.exists(cp):
            try:
                r = subprocess.run(["openssl", "x509", "-in", cp, "-noout", "-issuer"],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    issuer = r.stdout.strip().replace("issuer=", "")
            except Exception:
                pass
        certs_out.append({
            **c,
            "expires_at": expires_at,
            "days_remaining": days,
            "issuer": issuer,
        })
    return jsonify({"success": True, "data": {"certificates": certs_out, "total": len(certs_out)}})


@app.route('/api/reverse-proxy/certificates/upload', methods=['POST'])
def rp_upload_cert():
    config, rp = _get_rp_config()
    domain = request.form.get("domain", "").strip()
    try:
        domain = _sanitize_domain(domain)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    cert_file = request.files.get("cert_file")
    key_file = request.files.get("key_file")
    if not domain or not cert_file or not key_file:
        return jsonify({"success": False, "message": "domain, cert_file, key_file 不能为空"}), 400

    cert_dir = os.path.join(NGINX_SSL_DIR, domain)
    os.makedirs(cert_dir, exist_ok=True)
    fullchain_path = os.path.join(cert_dir, "fullchain.pem")
    key_path = os.path.join(cert_dir, "privkey.pem")

    # 先落到临时文件校验，通过了再覆盖正式文件。
    # 直接 save 到正式路径的话，传错私钥就已经把原来能用的证书冲掉了 ——
    # 而 nginx 还在用旧证书配新私钥，故障立刻出现且不可逆。
    tmp_c = fullchain_path + ".upload.tmp"
    tmp_k = key_path + ".upload.tmp"
    try:
        cert_file.save(tmp_c)
        key_file.save(tmp_k)
        ok, why = _cert_key_pair_ok(tmp_c, tmp_k)
        if not ok:
            _unlink_quiet(tmp_c)
            _unlink_quiet(tmp_k)
            return jsonify({"success": False,
                            "message": f"证书校验未通过：{why}"}), 400
        os.replace(tmp_c, fullchain_path)
        os.replace(tmp_k, key_path)
    except Exception as e:
        _unlink_quiet(tmp_c)
        _unlink_quiet(tmp_k)
        return jsonify({"success": False, "message": f"写入证书失败: {e}"}), 500

    os.chmod(key_path, 0o600)
    _harden_key_for_nginx_worker(key_path)

    expires_at, days = _get_cert_expiry(fullchain_path)
    now_iso = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")

    # 同 domain 已存在 manual 证书时，视为"重新上传/续期"：
    # 复用旧 id 和 created_at，替换 entry 内容（保留反代规则的引用关系）
    existing_manual = None
    for c in rp.get("certificates", []):
        if c.get("domain") == domain and c.get("source") == "manual":
            existing_manual = c
            break

    if existing_manual:
        new_id = existing_manual["id"]
        cert_entry = {
            **existing_manual,
            "cert_path": fullchain_path,
            "key_path": key_path,
            "expires_at": expires_at,
            "days_remaining": days,
        }
        rp["certificates"] = [cert_entry if c["id"] == new_id else c
                              for c in rp["certificates"]]
        replaced = True
    else:
        new_id = _next_id("cert", [c["id"] for c in rp.get("certificates", [])])
        cert_entry = {
            "id": new_id,
            "domain": domain,
            "source": "manual",
            "cert_path": fullchain_path,
            "key_path": key_path,
            "expires_at": expires_at,
            "days_remaining": days,
            "auto_renew": False,
            "dns_provider": "",
            "created_at": now_iso,
        }
        rp["certificates"].append(cert_entry)
        replaced = False

    _save_rp_config(config)
    msg = "证书已重新上传（替换同域名旧证书）" if replaced else "证书上传成功"
    return jsonify({"success": True, "data": {"cert_id": new_id, "domain": domain, "cert_path": fullchain_path, "key_path": key_path, "expires_at": expires_at, "replaced": replaced, "message": msg}})


@app.route('/api/reverse-proxy/certificates/<cert_id>/download', methods=['GET'])
def rp_download_cert(cert_id):
    """打包下载证书（fullchain + key），前端需先 confirm 警告私钥风险"""
    config, rp = _get_rp_config()
    cert = _find_rp_cert(rp, cert_id)
    if not cert:
        return jsonify({"success": False, "message": "证书不存在"}), 404

    cert_path = cert.get("cert_path", "")
    key_path = cert.get("key_path", "")
    if not cert_path or not os.path.exists(cert_path):
        return jsonify({"success": False, "message": "证书文件不存在"}), 404
    if not key_path or not os.path.exists(key_path):
        return jsonify({"success": False, "message": "私钥文件不存在"}), 404

    domain = _sanitize_domain(cert.get("domain", cert_id))
    mem = io.BytesIO()
    try:
        with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
            z.write(cert_path, f"{domain}-fullchain.pem")
            z.write(key_path, f"{domain}-privkey.pem")
    except OSError as e:
        return jsonify({"success": False, "message": f"打包失败: {e}"}), 500

    mem.seek(0)
    return send_file(
        mem,
        as_attachment=True,
        download_name=f"{domain}.zip",
        mimetype="application/zip",
    )


@app.route('/api/reverse-proxy/certificates/<cert_id>/reupload', methods=['POST'])
def rp_reupload_cert(cert_id):
    """手动证书的"续期"：覆盖文件 + 刷新 expires_at，保留 cert id 和引用关系"""
    config, rp = _get_rp_config()
    cert = _find_rp_cert(rp, cert_id)
    if not cert:
        return jsonify({"success": False, "message": "证书不存在"}), 404
    if cert.get("source") != "manual":
        return jsonify({"success": False, "message": "仅手动证书支持 reupload，ACME 证书请用 /renew"}), 400

    cert_file = request.files.get("cert_file")
    key_file = request.files.get("key_file")
    if not cert_file or not key_file:
        return jsonify({"success": False, "message": "cert_file, key_file 不能为空"}), 400

    cert_path = cert.get("cert_path", "")
    key_path = cert.get("key_path", "")
    if not cert_path or not key_path:
        return jsonify({"success": False, "message": "证书路径配置异常"}), 500

    try:
        tmp_c = cert_path + ".reupload.tmp"
        tmp_k = key_path + ".reupload.tmp"
        cert_file.save(tmp_c)
        key_file.save(tmp_k)
        # 同 upload：先校验再覆盖。传错私钥时原来能用的证书必须保住 ——
        # nginx 正在用它，被冲掉就是立即且不可逆的握手失败。
        ok, why = _cert_key_pair_ok(tmp_c, tmp_k)
        if not ok:
            _unlink_quiet(tmp_c)
            _unlink_quiet(tmp_k)
            return jsonify({"success": False,
                            "message": f"证书校验未通过：{why}"}), 400
        os.replace(tmp_c, cert_path)
        os.replace(tmp_k, key_path)
        os.chmod(key_path, 0o600)
        _harden_key_for_nginx_worker(key_path)
    except OSError as e:
        return jsonify({"success": False, "message": f"写入文件失败: {e}"}), 500

    expires_at, days = _get_cert_expiry(cert_path)
    cert["expires_at"] = expires_at
    cert["days_remaining"] = days
    _save_rp_config(config)

    # 重新部署所有反代规则（刷新 nginx 配置 + reload）
    try:
        _deploy_all_rules(config)
    except Exception as e:
        # 文件已更新，配置已保存，reload 失败不影响主流程
        return jsonify({
            "success": True,
            "data": {
                "cert_id": cert_id,
                "expires_at": expires_at,
                "days_remaining": days,
                "message": f"证书已重新上传，但 nginx reload 失败: {e}",
            },
        }), 200

    return jsonify({
        "success": True,
        "data": {
            "cert_id": cert_id,
            "domain": cert.get("domain", ""),
            "expires_at": expires_at,
            "days_remaining": days,
            "message": "证书已重新上传并刷新 nginx",
        },
    })


@app.route('/api/reverse-proxy/certificates/request', methods=['POST'])
def rp_request_cert():
    config, rp = _get_rp_config()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"success": False, "message": "domain 不能为空"}), 400
    try:
        domain = _sanitize_domain(domain)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    # 检查域名唯一
    for c in rp.get("certificates", []):
        if c["domain"] == domain:
            return jsonify({"success": False, "message": f"域名 {domain} 已有证书"}), 400

    dns_provider = data.get("dns_provider", "ali").strip()
    if dns_provider not in DNS_PROVIDERS:
        return jsonify({"success": False, "message": f"不支持的 DNS 提供商: {dns_provider}"}), 400

    # 收集凭证：优先用请求中的，阿里云可以自动读取
    dns_credentials = data.get("dns_credentials")
    if not dns_credentials:
        dns_credentials = _get_dns_credentials(rp, dns_provider)
    if not dns_credentials:
        provider_name = DNS_PROVIDERS[dns_provider]["name"]
        if dns_provider == "ali":
            return jsonify({"success": False, "message": f"未提供 {provider_name} 凭证，且 DDNS 配置中未找到阿里云 AccessKey"}), 400
        return jsonify({"success": False, "message": f"请提供 {provider_name} 的 DNS 凭证"}), 400

    # 非阿里云：保存凭证到配置
    if dns_provider != "ali" and data.get("dns_credentials"):
        if "dns_credentials" not in rp:
            rp["dns_credentials"] = {}
        rp["dns_credentials"][dns_provider] = data["dns_credentials"]

    ok, result = _acme_issue(domain, dns_provider, dns_credentials)
    if not ok:
        return jsonify({"success": False, "message": result.get("error", "证书申请失败"), "log": result.get("log", "")}), 400

    now_iso = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
    new_id = _next_id("cert", [c["id"] for c in rp.get("certificates", [])])
    cert_entry = {
        "id": new_id,
        "domain": domain,
        "source": "auto",
        "dns_provider": dns_provider,
        "cert_path": result["cert_path"],
        "key_path": result["key_path"],
        "expires_at": result["expires_at"],
        "auto_renew": data.get("auto_renew", True),
        "renew_days": data.get("renew_days", 60),
        "created_at": now_iso,
    }
    rp["certificates"].append(cert_entry)
    _save_rp_config(config)
    return jsonify({"success": True, "data": {"cert_id": new_id, "domain": domain, **result, "message": "证书申请成功"}})


@app.route('/api/reverse-proxy/certificates/<cert_id>/renew', methods=['POST'])
def rp_renew_cert(cert_id):
    config, rp = _get_rp_config()
    cert = _find_rp_cert(rp, cert_id)
    if not cert:
        return jsonify({"success": False, "message": "证书不存在"}), 404
    if cert.get("source") != "auto":
        return jsonify({"success": False, "message": "手动上传的证书不支持在线续期"}), 400

    cert_provider = cert.get("dns_provider", "ali")
    dns_credentials = _get_dns_credentials(rp, cert_provider)
    if not dns_credentials:
        return jsonify({"success": False, "message": "未找到 DNS 凭证，无法续期"}), 400

    ok, result = _acme_renew(cert["domain"], cert_provider, dns_credentials)
    if not ok:
        return jsonify({"success": False, "message": result.get("error", "续期失败")}), 400

    cert["expires_at"] = result.get("new_expires_at", "")
    _save_rp_config(config)
    return jsonify({"success": True, "data": {"cert_id": cert_id, "domain": cert["domain"], **result, "message": "证书续期成功"}})


@app.route('/api/reverse-proxy/certificates/<cert_id>', methods=['DELETE'])
def rp_delete_cert(cert_id):
    config, rp = _get_rp_config()
    cert = _find_rp_cert(rp, cert_id)
    if not cert:
        return jsonify({"success": False, "message": "证书不存在"}), 404

    # v0.8.1 起规则不再各自持有证书，网关统一用 settings.default_cert_id。
    # 这里必须改成检查默认证书 —— 否则 referenced_by 恒为空，删证书这道
    # 保护形同虚设：把正在用的默认证书删掉，网关会退到面板自签证书，
    # 用户看到的是「浏览器证书警告」，而面板显示一切正常。
    settings = rp.setdefault("settings", dict(RP_DEFAULT_SETTINGS))
    is_gateway_default = settings.get("default_cert_id") == cert_id

    if is_gateway_default:
        return jsonify({
            "success": False,
            "message": "该证书正在被认证网关使用（网关统一证书），"
                       "请先在证书管理里切换网关默认证书再删除",
        }), 400

    # 兼容旧结构里可能残留的按规则引用
    referenced_by = [r for r in rp.get("rules", []) if r.get("ssl_cert_id") == cert_id]

    if referenced_by:
        # 默认拒绝删除，提示用户传 force=true&replace_cert_id=... 强制迁移
        force = request.args.get("force", "false").lower() == "true"
        replace_with = request.args.get("replace_cert_id", "").strip()
        if not (force and replace_with):
            return jsonify({
                "success": False,
                "message": f"证书被 {len(referenced_by)} 条规则引用，无法直接删除",
                "data": {
                    "referenced_by": [{"rule_id": r["id"], "domain": r["domain"]} for r in referenced_by],
                    "hint": "如需迁移引用并删除，传 ?force=true&replace_cert_id=<新证书id>"
                }
            }), 400

        # 验证替换目标证书存在且域名一致
        new_cert = _find_rp_cert(rp, replace_with)
        if not new_cert:
            return jsonify({"success": False, "message": "替换目标证书不存在"}), 400
        if new_cert.get("domain") != cert.get("domain"):
            return jsonify({"success": False, "message": "替换证书的域名必须与原证书一致"}), 400

        # 迁移引用关系
        for r in rp["rules"]:
            if r.get("ssl_cert_id") == cert_id:
                r["ssl_cert_id"] = replace_with

    # 删除证书文件前，先检查同目录下是否还有别的 cert_entry 在用
    # 防止误删共享文件（例如 ACME 续期后原 auto 证书和新 manual 证书指向同目录）
    domain = _sanitize_domain(cert.get("domain", ""))
    cert_dir = os.path.join(NGINX_SSL_DIR, domain)
    other_uses_same_dir = [
        c for c in rp.get("certificates", [])
        if c["id"] != cert_id
        and c.get("cert_path", "")
        and os.path.dirname(c.get("cert_path", "")) == cert_dir
    ]

    if not other_uses_same_dir and os.path.isdir(cert_dir):
        try:
            shutil.rmtree(cert_dir)
        except OSError as e:
            return jsonify({"success": False, "message": f"删除证书文件失败: {e}"}), 500

    rp["certificates"] = [c for c in rp["certificates"] if c["id"] != cert_id]
    _save_rp_config(config)
    return jsonify({"success": True, "data": {"message": "证书已删除", "migrated_rules": len(referenced_by) if referenced_by else 0}})


# ======================= nginx 管理 API =======================

@app.route('/api/reverse-proxy/nginx/test', methods=['POST'])
def rp_nginx_test():
    ok, msg = _nginx_test()
    return jsonify({"success": True, "data": {"valid": ok, "message": msg}})


@app.route('/api/reverse-proxy/nginx/reload', methods=['POST'])
def rp_nginx_reload():
    ok, msg = _nginx_reload()
    return jsonify({"success": True, "data": {"message": msg}})


@app.route('/api/reverse-proxy/nginx/preview/<rule_id>', methods=['GET'])
def rp_nginx_preview(rule_id):
    """预览这条服务在网关配置里实际生效的那一段。

    v0.8.1 起反代服务只有网关一份配置，预览的就是它的真实产物 ——
    之前这个端点拼的是独立站点 conf，还把路径写成 {domain}.conf
    （漏了 -listen_port 后缀），预览出来的内容与实际部署根本不是一回事。
    """
    config, rp = _get_rp_config()
    config = _migrate_rp_rules(config)
    rule = _find_rp_rule(rp, rule_id)
    if not rule:
        return jsonify({"success": False, "message": "规则不存在"}), 404
    full = _generate_gateway_nginx_conf(config) or ""
    marker = f"# ---- {_sanitize_name(rule.get('name') or rule.get('path_prefix'))} ----"
    seg = ''
    if marker in full:
        seg = full[full.index(marker):]
        seg = seg.split('\n    }\n', 1)[0] + '\n    }'
    return jsonify({"success": True, "data": {
        "config_content": seg or "# 网关未启用或该服务未启用",
        "config_path": GATEWAY_CONF_NAME,
    }})



# ======================= 全局设置 API =======================

@app.route('/api/reverse-proxy/settings', methods=['GET'])
def rp_get_settings():
    config, rp = _get_rp_config()
    settings = dict(rp.get("settings", RP_DEFAULT_SETTINGS))
    settings["default_cert_id"] = rp.get("settings", {}).get("default_cert_id")
    return jsonify({"success": True, "data": settings})


@app.route('/api/reverse-proxy/settings', methods=['POST'])
def rp_save_settings():
    config, rp = _get_rp_config()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    settings = rp.setdefault("settings", dict(RP_DEFAULT_SETTINGS))
    for key in ["http_redirect_enabled", "hsts_enabled", "tls_min_version", "auto_reload_nginx"]:
        if key in data:
            settings[key] = data[key]
    _save_rp_config(config)

    # 重新生成所有规则配置
    if settings.get("auto_reload_nginx", True):
        _deploy_all_rules(config)

    return jsonify({"success": True, "data": {"message": "设置已保存"}})



@app.route('/api/reverse-proxy/certificates/<cert_id>/set-default', methods=['POST'])
def rp_set_default_cert(cert_id):
    config, rp = _get_rp_config()
    certs = {c["id"] for c in rp.get("certificates", [])}
    if cert_id not in certs:
        return jsonify({"success": False, "message": f"证书 {cert_id} 不存在"}), 404
    settings = rp.setdefault("settings", dict(RP_DEFAULT_SETTINGS))
    settings["default_cert_id"] = cert_id
    _save_rp_config(config)
    return jsonify({"success": True, "data": {"message": "默认证书已设置", "default_cert_id": cert_id}})


# ======================= 认证 API =======================

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    """返回当前登录状态和系统是否已初始化密码"""
    return jsonify({
        'success': True,
        'data': {
            'authenticated': _is_authenticated(),
            'password_set': _password_set(),
        }
    })


@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    # 限流检查
    ip = request.remote_addr or 'unknown'
    allowed, retry_after = _check_rate_limit(ip)
    if not allowed:
        resp = jsonify({
            'success': False,
            'code': 'RATE_LIMITED',
            'message': f'登录失败次数过多，请 {retry_after} 秒后再试',
        })
        resp.status_code = 429
        resp.headers['Retry-After'] = str(retry_after)
        return resp

    data = request.get_json(silent=True) or {}
    pw = data.get('password', '')
    if not pw:
        return jsonify({'success': False, 'message': '密码不能为空'}), 400
    if not _password_set():
        return jsonify({'success': False, 'message': '系统尚未设置密码，请先初始化', 'code': 'NEED_SETUP'}), 400
    if not _verify_password(pw, _read_password_hash()):
        _record_login_failure(ip)
        return jsonify({'success': False, 'message': '密码错误'}), 401
    _clear_login_failures(ip)
    session.clear()
    session['authenticated'] = True
    session.permanent = True
    session['last_active'] = time.time()
    return jsonify({'success': True, 'data': {'message': '登录成功'}})


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    session.clear()
    return jsonify({'success': True, 'data': {'message': '已退出'}})


@app.route('/api/auth/setup', methods=['POST'])
def auth_setup():
    """首次设置密码（要求当前无密码文件存在）"""
    # setup 也加限流（防止恶意用户抢占 setup 流程）
    ip = request.remote_addr or 'unknown'
    allowed, retry_after = _check_rate_limit(ip)
    if not allowed:
        resp = jsonify({
            'success': False,
            'code': 'RATE_LIMITED',
            'message': f'操作过于频繁，请 {retry_after} 秒后再试',
        })
        resp.status_code = 429
        resp.headers['Retry-After'] = str(retry_after)
        return resp

    if _password_set():
        return jsonify({'success': False, 'message': '密码已设置，请用 /login 登录', 'code': 'ALREADY_SET'}), 400
    data = request.get_json(silent=True) or {}
    pw = data.get('password', '')
    if not pw or len(pw) < 4:
        return jsonify({'success': False, 'message': '密码长度至少 4 位'}), 400
    if len(pw) > 128:
        return jsonify({'success': False, 'message': '密码长度不能超过 128 位'}), 400
    try:
        _write_password_hash(_hash_password(pw))
    except OSError as e:
        # 写入时抛错（盘满 / 权限不足 / 临时 IO 错误）也要回滚 session
        session.clear()
        return jsonify({
            'success': False,
            'code': 'PASSWORD_WRITE_FAILED',
            'message': f'密码文件写入失败：{e}。请检查磁盘空间和权限后重试',
        }), 500
    # 二次校验：写入函数正常返回但文件可能因特殊场景未落盘
    if not _password_set():
        session.clear()
        return jsonify({
            'success': False,
            'code': 'PASSWORD_WRITE_FAILED',
            'message': '密码文件写入失败，请检查磁盘空间和权限后重试',
        }), 500
    _clear_login_failures(ip)
    session.clear()
    session['authenticated'] = True
    session.permanent = True
    session['last_active'] = time.time()
    return jsonify({'success': True, 'data': {'message': '密码设置成功，已自动登录'}})


@app.route('/api/auth/change-password', methods=['POST'])
def auth_change_password():
    """已登录用户修改密码"""
    # 限流：和登录失败共用同一套限制（防暴力枚举旧密码）
    client_ip = request.remote_addr or 'unknown'
    allowed, retry_after = _check_rate_limit(client_ip)
    if not allowed:
        resp = jsonify({'success': False, 'code': 'RATE_LIMITED', 'message': '尝试次数过多，请稍后再试'})
        resp.headers['Retry-After'] = str(retry_after or 60)
        return resp, 429
    if not _is_authenticated():
        return jsonify({'success': False, 'message': '未登录'}), 401
    data = request.get_json(silent=True) or {}
    old_pw = data.get('old_password', '')
    new_pw = data.get('new_password', '')
    if not old_pw or not new_pw:
        return jsonify({'success': False, 'message': 'old_password 和 new_password 不能为空'}), 400
    if len(new_pw) < 4 or len(new_pw) > 128:
        return jsonify({'success': False, 'message': '新密码长度需 4-128 位'}), 400
    if not _verify_password(old_pw, _read_password_hash()):
        # 旧密码错误也记录失败（防暴力枚举）
        _record_login_failure(client_ip)
        return jsonify({'success': False, 'message': '旧密码错误'}), 401
    _write_password_hash(_hash_password(new_pw))
    _clear_login_failures(client_ip)  # 修改成功清掉该 IP 的失败记录
    # 改完密码必须清掉当前会话：session 里只标记了 authenticated=True，
    # 不清的话改密码后所有设备上的旧会话仍然有效，等于没改。
    session.clear()
    return jsonify({'success': True, 'data': {
        'message': '密码已修改，请重新登录',
        'reauth': True,
    }})


def _pick_reverse_proxy_cert():
    """扫描反代证书目录，挑一个有效期 ≥30 天的证书用作 HTTPS 服务证书。

    返回 (cert_path, key_path) 或 None。
    优先选择剩余天数最多的证书（避免选到快过期的）。
    排除 nftables-web 自签目录（避免循环复用自签证书）。
    """
    if not os.path.isdir(NGINX_SSL_DIR):
        return None
    candidates = []
    try:
        for domain in os.listdir(NGINX_SSL_DIR):
            if domain == os.path.basename(NFTABLES_WEB_SSL_DIR):
                continue  # 排除自签证书目录
            fullchain = os.path.join(NGINX_SSL_DIR, domain, "fullchain.pem")
            privkey = os.path.join(NGINX_SSL_DIR, domain, "privkey.pem")
            if not (os.path.isfile(fullchain) and os.path.isfile(privkey)):
                continue
            try:
                _exp, days = _get_cert_expiry(fullchain)
                if days >= 30:
                    candidates.append((days, fullchain, privkey, domain))
            except Exception:
                continue
    except Exception:
        return None
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)  # 取剩余天数最多的
    _, fullchain, privkey, domain = candidates[0]
    print(f"[INFO] 使用反代证书 {fullchain} (domain={domain}, 剩余 {candidates[0][0]} 天)", flush=True)
    return fullchain, privkey


def _ensure_self_signed_cert():
    """如果自签证书不存在或快过期，则生成新的。

    自签证书 CN/SAN 用 router_ip4（或 hostname fallback），让浏览器接受时警告清晰。
    """
    need_generate = True
    if os.path.exists(NFTABLES_WEB_CERT) and os.path.exists(NFTABLES_WEB_KEY):
        try:
            expires_at, days = _get_cert_expiry(NFTABLES_WEB_CERT)
            if expires_at and days > 30:
                need_generate = False
        except Exception:
            pass

    if need_generate:
        # 选 CN：优先 router_ip4，否则 hostname
        cn = 'nftables-web.local'
        try:
            cfg = load_config()
            ip = (cfg.get('router_ip4') or '').strip()
            if ip:
                cn = ip
        except Exception:
            pass
        os.makedirs(NFTABLES_WEB_SSL_DIR, exist_ok=True)
        try:
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', NFTABLES_WEB_KEY,
                '-out', NFTABLES_WEB_CERT,
                '-days', '3650', '-nodes',
                '-subj', f'/CN={cn}',
                '-addext', f'subjectAltName=IP:{cn},DNS:{cn}',
            ], check=True, capture_output=True, text=True, timeout=30)
            os.chmod(NFTABLES_WEB_KEY, 0o600)
            _harden_key_for_nginx_worker(NFTABLES_WEB_KEY)
            os.chmod(NFTABLES_WEB_CERT, 0o644)
            print(f"[INFO] 已生成自签证书 (CN={cn}) 有效期 10 年", flush=True)
            return NFTABLES_WEB_CERT, NFTABLES_WEB_KEY
        except Exception as e:
            print(f"[WARNING] 自签证书生成失败：{e}", flush=True)
            return None
    return NFTABLES_WEB_CERT, NFTABLES_WEB_KEY


def _ensure_https_cert():
    """优先复用反代证书，否则自签。两者都失败返回 None（拒绝启动明文 HTTP）。"""
    rp_cert = _pick_reverse_proxy_cert()
    if rp_cert:
        return rp_cert
    print("[INFO] 反代证书目录无可用证书，回退到自签证书", flush=True)
    return _ensure_self_signed_cert()


def _ruleset_is_empty():
    """检查我们维护的 inet fw4 表是否还活着（nft list table inet fw4）。

    任何 subprocess 异常都视为"表不存在"（保守处理：宁可误报裸奔触发恢复，
    也不要漏报裸奔导致路由器真裸奔）。
    """
    try:
        res = subprocess.run(['nft', 'list', 'table', 'inet', 'fw4'],
                             capture_output=True, text=True, timeout=5)
        return res.returncode != 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        print(f'[WARN] _ruleset_is_empty() 异常，按"表不存在"处理: {e}', flush=True)
        return True


def _try_apply_rules_file(path):
    """尝试用 nft -f 应用规则文件，返回是否真的生效。

    双重验证（A-3 修复点）：
      1. nft -f returncode == 0
      2. _ruleset_is_functional() 返回 True（确认 fw4 表真存在且真的带策略）
    防止 "nft -f empty.nft" / "nft -f 假文件" 返回 0 但实际表不存在的情况。

    第二道检查用的是「严」判据而不是「表在不在」：
    nft 对整份文件是先解析后应用，语法错误会整体拒绝（这条实测过，现网零改动），
    但**语法合法、内容为空的文件会静默成功** —— 而现网本来就有 fw4 表时，
    「表还在吗」根本看不出区别，于是返回 True。

    这个误判不是小事：看门狗的重试循环是
        for p in (RULES_PATH, RULES_PATH + '.lastgood'):
            if os.path.exists(p) and _try_apply_rules_file(p): break
    一次假成功就会 break 掉，**.lastgood 永远轮不到**，接着走 basic lockdown ——
    而 basic lockdown 是降级，会丢掉端口转发。规则文件被清空这种场景
    （手工编辑、磁盘写满、脚本截断）恰好就是最需要 .lastgood 的一次。
    .224 真机演练过：空文件返回 True，现网 12 链 163 条规则一条没变。

    subprocess 异常（A-4 修复点）也返回 False，不抛出：
      - FileNotFoundError：nft 二进制不存在
      - TimeoutExpired：nft 卡死
      - OSError：底层资源错误
    """
    try:
        res = subprocess.run(['nft', '-f', path],
                             capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        print(f'[WARN] nft -f {path} 异常: {type(e).__name__}: {e}', flush=True)
        return False

    if res.returncode != 0:
        print(f'[WARN] nft -f {path} returncode={res.returncode}, '
              f'stderr={(res.stderr or res.stdout)[:200]}', flush=True)
        return False

    # 二次验证：returncode=0 也要确认规则真的落地了
    ok, detail = _ruleset_is_functional()
    if not ok:
        print(f'[WARN] nft -f {path} returncode=0 但规则集仍不可用（{detail}），'
              f'视为失败', flush=True)
        return False

    return True


def _unlink_quiet(path):
    """删除文件，忽略不存在/权限等异常（清理临时文件用）"""
    try:
        os.unlink(path)
    except OSError:
        pass


def _interface_exists(name):
    """网卡名在本机是否真实存在"""
    if not name:
        return False
    try:
        return bool(os.path.isdir(f'/sys/class/net/{name}'))
    except OSError:
        return False


def _detect_default_route_if():
    """从默认路由推断出口接口名（兜底防火墙找不到 lan_if 时用）"""
    try:
        with open('/proc/net/route', 'r') as f:
            lines = f.readlines()[1:]
    except OSError:
        return None
    for line in lines:
        parts = line.split()
        if len(parts) > 2 and parts[1] == '00000000':   # destination 0.0.0.0
            return parts[0] or None
    return None


def _apply_basic_lockdown(config=None):
    """兜底防火墙：WAN block / LAN allow / LAN 侧必要服务端口放行。
    只在主规则 + 备份都不可用时使用，保证路由器至少有基本保护。

    双重验证：nft -f - returncode=0 且 _ruleset_is_empty() == False。
    subprocess 异常不抛出，返回 False 让外层回退到下一级（虽然这里已经是最后一级）。

    接口名与端口必须读配置，不能写死 br-lan / 22：
    deploy_mode=linux_gateway 跑在普通 Linux 上，内核接口是 eth0，
    规则里写 `iifname "br-lan"` 一条都匹配不上 → policy drop 之下没有任何
    accept → 兜底防火墙一执行就把管理员自己关在门外，而日志还报「已应用」。
    """
    if config is None:
        try:
            config = load_config()
        except Exception as e:
            print(f'[WARN] basic lockdown 读配置失败，用保守默认: {e}', flush=True)
            config = {}

    lan_if = str(config.get("lan_if", "") or "").strip() or "br-lan"

    # 接口名必须真的存在。写错一个名字，规则照样加载成功、policy drop 照样
    # 生效，但没有任何一条 accept 匹配得上 —— 管理员被自己的兜底规则关在门外。
    # 所以这里宁可拒绝执行（返回 False，如实报「未生效」），也不装一份
    # 必然把自己锁死的规则。
    if not _interface_exists(lan_if):
        auto = _detect_default_route_if()
        if auto and _interface_exists(auto):
            print(f'[WARN] 配置的 lan_if={lan_if} 不存在，改用默认路由接口 {auto}', flush=True)
            lan_if = auto
        else:
            print(f'[ERROR] lan_if={lan_if} 在本机不存在且无法自动识别，'
                  f'拒绝执行兜底防火墙（避免 policy drop 下无 accept 把自己锁死）',
                  flush=True)
            return False

    # 只放行用户在配置里明确允许的 LAN 端口 + SSH + 面板自身端口。
    # 不放行的话兜底规则一执行就没法远程自救。
    ports = set()
    raw_ports = str(config.get("lan_allowed_ports", "") or "")
    for part in raw_ports.replace('，', ',').split(','):
        p = part.strip()
        if p.isdigit() and 0 < int(p) < 65536:
            ports.add(int(p))
    try:
        web_port = HTTPS_PORT
    except NameError:
        web_port = 5443
    ports.update({22, int(web_port)})

    port_list = ', '.join(str(p) for p in sorted(ports))
    rules = f'''table inet fw4 {{
    chain input {{
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state established,related accept
        # SSH / 面板只允许从 LAN 侧访问，绝不在 WAN 侧放行管理端口
        iifname "{lan_if}" tcp dport {{ {port_list} }} accept
        iifname "{lan_if}" accept
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        iifname "{lan_if}" accept
        oifname "{lan_if}" ct state established,related accept
    }}
    chain output {{
        type filter hook output priority 0; policy accept;
    }}
}}
'''
    # ⚠️ 必须先 flush 再装，不能直接 nft -f。
    #
    # nft -f 里的 `table X { chain Y { ... } }` 块是**追加**语义，不是替换。
    # .224 真机实测（2026-10-15）：在完整规则集已经生效的状态下装这份 lockdown，
    # input 链从 30 条变成 31 条 —— 原有那 30 条一条没少，`jump input_wan`
    # 还在，`iifname "eth1"` 的 WAN 判定全都还在跑。所谓「降级」实际上什么
    # 都没降，整个优先级 4 形同虚设。
    #
    # 项目自己的规则文件开头就是 `flush ruleset`，同一个道理。
    #
    # 只 flush inet fw4 这张表（不是整表集）：nft 表里还有别人放的规则，
    # 兜底防火墙的任务只是接管防火墙判定，不必连 nat 之类一起掀掉。
    try:
        subprocess.run(['nft', 'flush', 'table', 'inet', 'fw4'],
                       capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        # 表不存在时 flush 会失败，但下面的块会自己建表 —— 不是致命错误
        print(f'[WARN] flush table inet fw4 异常（继续，lockdown 会新建表）: {e}',
              flush=True)
    try:
        res = subprocess.run(['nft', '-f', '-'], input=rules,
                             capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        print(f'[WARN] basic lockdown nft 异常: {type(e).__name__}: {e}', flush=True)
        return False

    if res.returncode != 0:
        print(f'[WARN] basic lockdown returncode={res.returncode}, '
              f'stderr={(res.stderr or res.stdout)[:200]}', flush=True)
        return False

    # 二次验证：不能只看「表在不在」—— 追加语义下表一直都在，等于永远通过。
    # 必须确认 input 链里已经没有 jump input_wan，否则说明这次是追加不是替换，
    # 降级没生效，却要报「已套用最小兜底防护」。
    if _input_chain_still_references_wan():
        print('[WARN] basic lockdown 装上后 input 链仍在引用 input_wan —— '
              '规则是追加进去的，降级未真正生效', flush=True)
        return False

    if _ruleset_is_empty():
        print('[WARN] basic lockdown returncode=0 但 fw4 表仍不存在，视为失败', flush=True)
        return False

    return True


def _input_chain_still_references_wan():
    """input 链里还有没有跳向 input_wan 的 jump（= 完整规则集仍在生效）。"""
    try:
        res = subprocess.run(['nft', 'list', 'chain', 'inet', 'fw4', 'input'],
                             capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    return 'jump input_wan' in (res.stdout or '')


# ══════════════════════════════════════════════════════════════
# 防火墙看门狗（运行期自检）
#
# 启动时的 _auto_recover_ruleset_if_empty 只在服务启动那一刻跑一次。
# 如果规则集在服务运行期间被清空 —— 有人 enable 了 fw4、别的工具 flush、
# 内核异常 —— 不会有人发现，要等到面板服务重启才恢复。期间路由器是裸奔的。
#
# 三条安全约束，缺一个都可能把「自检」变成「定时砸防火墙」：
#   1. 滞回：连续 N 次判定不健康才动手。单次 nft 查询抖动（进程正忙、
#      超时）不得触发重载。
#   2. 冷却：动手之后 M 秒内不再尝试。否则规则永久损坏时会每 5 分钟
#      砸一次防火墙，把正常流量反复打断。
#   3. 互斥：与 /api/rules/apply 共用同一把锁，避免两个 nft -f 交叉。
# ══════════════════════════════════════════════════════════════

FW_WATCHDOG_DEFAULT_INTERVAL = 300       # 5 分钟
FW_WATCHDOG_MIN_INTERVAL = 60
FW_WATCHDOG_FAIL_THRESHOLD = 2           # 连续几次不健康才动手
FW_WATCHDOG_COOLDOWN = 900               # 动手后冷却 15 分钟

# 从 basic lockdown 切回完整规则集时，连续这么多次装不上就停手。
# 规则文件本身残缺时，每 5 分钟反复 nft -f 一次只是白白抖动规则集，
# 还不如如实报出来，让人手工「应用规则」重新生成一次。
_PROMOTE_MAX_FAILS = 3

# 与 _apply_ruleset 共用，防止看门狗和用户点击「应用规则」并发下发。
# 用可重入锁：本函数持锁期间会调 _auto_recover_ruleset_if_empty，
# 它内部又走 _apply_ruleset，会再次 acquire 同一把锁 —— 普通 Lock 直接死锁。
_FW_APPLY_LOCK = threading.RLock()

_WATCHDOG = {
    'stop': False,
    'fails': 0,
    'promote_fails': 0,
    'last_action_ts': 0.0,
    'last_check_ts': 0.0,
    'last_result': '尚未检查',
    'actions': 0,
}


def _fw_watchdog_settings():
    """读看门狗参数。配置读失败一律用默认值，绝不因为配置问题让自检失效。"""
    iv = FW_WATCHDOG_DEFAULT_INTERVAL
    en = True
    try:
        cfg = load_config()
        en = bool(cfg.get('fw_watchdog_enabled', True))
        iv = int(cfg.get('fw_watchdog_interval', FW_WATCHDOG_DEFAULT_INTERVAL))
    except Exception:
        pass
    # 间隔下限要兜住：间隔太短等于定时重载防火墙，比不检查还糟
    iv = max(FW_WATCHDOG_MIN_INTERVAL, iv)
    return en, iv


def _ruleset_is_degraded():
    """当前生效的是 basic lockdown（兜底规则），而不是完整规则集。

    判别标志：input 链里还有没有 `jump input_wan`（完整规则集一定有，
    basic lockdown 装完就没有了）。

    为什么必须有这个判据：`_ruleset_is_functional()` 的四条判据
    （表在 + 有 hook input + 有 policy drop + 是 filter hook）
    basic lockdown **全部满足**。所以降级一旦生效，看门狗就认定
    「防火墙正常」，此后再也不会切回 —— 敲门没了、端口转发没了、
    黑名单没了，而且没有任何自愈路径，只能人工点「应用规则」或重启。

    返回 (bool, str)：第一个是是否处于降级态，第二个是给人看的说明。
    """
    try:
        res = subprocess.run(['nft', 'list', 'table', 'inet', 'fw4'],
                             capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return False, f'无法查询规则集: {e}'
    if res.returncode != 0:
        return False, 'table inet fw4 不存在（不是降级态，是空）'
    out = res.stdout or ''
    # 判别标志：input 链里还有没有 `jump input_wan`。
    #
    # 刻意**不**用「input_wan 链存不存在」：basic lockdown 不会删掉那条链
    # （nft 的 table 块是追加语义，孤儿链会原样留着），它替换掉的只是
    # input 链的内容。.224 真机实测：装完 lockdown 后 `nft list table` 里
    # `chain input_wan` 赫然还在，但 input 链里已经没有跳向它的 jump 了。
    # 按链是否存在来判断，完整规则集和降级态会被判成同一个东西。
    if 'jump input_wan' in out:
        return False, '完整规则集'
    return True, 'basic lockdown（input 链已不再引用 input_wan：敲门/转发/黑名单均未生效）'


def _promote_lockdown_to_full():
    """处于 basic lockdown 时，尝试切回完整规则集。

    返回 (是否切回成功, 说明)。连续失败多次后停止重试 —— 规则文件本身
    就是残缺的，每 5 分钟反复 nft -f 一次只是白白抖动规则集，不如如实
    报出来让人手工重新应用一次。
    """
    if _WATCHDOG.get('promote_fails', 0) >= _PROMOTE_MAX_FAILS:
        return False, (f'仍是 basic lockdown，且规则文件连续 '
                       f'{_PROMOTE_MAX_FAILS} 次装不上（文件本身不完整），'
                       f'已停止自动重试，请手工「应用规则」一次')

    with _FW_APPLY_LOCK:
        # 拿锁后再判一次：可能正好有人在点「应用规则」
        degraded, _d = _ruleset_is_degraded()
        if not degraded:
            _WATCHDOG['promote_fails'] = 0
            return False, '已切回完整规则集'

        applied_from = None
        for p in (RULES_PATH, RULES_PATH + '.lastgood'):
            if os.path.exists(p) and _try_apply_rules_file(p):
                applied_from = p
                break

        if not applied_from:
            _WATCHDOG['promote_fails'] = _WATCHDOG.get('promote_fails', 0) + 1
            print(f'[WATCHDOG] 仍在 basic lockdown：规则文件与 .lastgood 都装不上'
                  f'（第 {_WATCHDOG["promote_fails"]} 次）', flush=True)
            return False, '仍在 basic lockdown：规则文件不可用'

        _WATCHDOG['promote_fails'] = 0
        degraded_after, _d2 = _ruleset_is_degraded()
        if degraded_after:
            print(f'[WATCHDOG] {applied_from} 已装上但仍缺 input_wan 链 —— '
                  f'该文件本身就是残缺的，需手工「应用规则」重新生成', flush=True)
            return False, f'已装 {applied_from}，但它本身不含完整规则集'
        print(f'[WATCHDOG] ✅ 已从 basic lockdown 切回完整规则集（{applied_from}）',
              flush=True)
        _WATCHDOG['actions'] = _WATCHDOG.get('actions', 0) + 1
        _WATCHDOG['last_action_ts'] = time.time()
        return True, f'已从 basic lockdown 切回完整规则集（{applied_from}）'


def _recover_ruleset_if_unhealthy():
    """规则集不健康时恢复。返回 (是否动手了, 说明)。

    三种状态要分开处理：
      · 表不在 / 表空        —— 走启动时那套四级恢复
      · 表在但链没挂策略      —— fw4 表被建出来了却是空的，重新加载规则文件即可，
                                没必要丢到 basic lockdown（那是降级，会丢端口转发）
      · 表健康但是降级态      —— basic lockdown 生效中。功能上「够用」，但敲门 /
                                端口转发 / 黑名单全丢，必须能自愈回切，
                                否则降级就是单向门。
    """
    functional, detail = _ruleset_is_functional()
    if functional:
        if not _ruleset_is_degraded()[0]:
            return False, '正常'
        return _promote_lockdown_to_full()

    with _FW_APPLY_LOCK:
        # 拿到锁之后再判一次：可能正好是用户在点「应用规则」，别抢
        functional, detail = _ruleset_is_functional()
        if functional:
            return False, '复查后已正常'

        reloaded = False
        if _ruleset_is_empty():
            print('[WATCHDOG] 规则集为空，触发启动级恢复链', flush=True)
            _auto_recover_ruleset_if_empty()
            reloaded = True
        else:
            print(f'[WATCHDOG] fw4 表存在但不可用（{detail}），重新加载规则文件',
                  flush=True)
            for _p in (RULES_PATH, RULES_PATH + '.lastgood'):
                if os.path.exists(_p) and _try_apply_rules_file(_p):
                    reloaded = True
                    break
            if not reloaded:
                # 原来这里没有这个分支：两个文件都不存在时 for 循环一次都不进，
                # 什么都没做就往下走复查。复查若恰好返回健康，就会报「已恢复」——
                # 实际上一条规则都没下发过。必须如实区分「做了什么」和「复查看着怎样」。
                print('[WATCHDOG] 规则文件与 .lastgood 均不存在，无法重新加载',
                      flush=True)

        functional, detail = _ruleset_is_functional()
        if functional:
            what = '已恢复' if reloaded else '复查后已正常（本次未执行任何重载）'
            return reloaded, f'{what}（{detail}）'
        if _apply_basic_lockdown():
            return True, '主恢复失败，已降级到 basic lockdown'
        return True, f'❗ 恢复失败：{detail} —— 路由器当前可能无防火墙'


def _watchdog_tick():
    """单次自检。看门狗线程和测试都走这里。"""
    _WATCHDOG['last_check_ts'] = time.time()
    en, _ = _fw_watchdog_settings()
    if not en:
        _WATCHDOG['last_result'] = '已停用'
        return None

    functional, detail = _ruleset_is_functional()
    if functional:
        _WATCHDOG['fails'] = 0
        # 功能判据对 basic lockdown 是成立的（表在 + policy drop + filter hook
        # 全都满足），所以这里必须再看一眼是不是降级态，否则
        # _promote_lockdown_to_full 永远没有机会被调用 —— 降级就成了单向门。
        degraded, degr = _ruleset_is_degraded()
        if not degraded:
            _WATCHDOG['promote_fails'] = 0
            _WATCHDOG['last_result'] = f'正常（{detail}）'
            return None
        # 降级态走独立的重试预算，不占用 fails / 阈值 / 冷却那套
        _WATCHDOG['last_result'] = f'降级运行中：{degr}'
        acted, msg = _promote_lockdown_to_full()
        if acted:
            _WATCHDOG['last_result'] = msg
            print(f'[WATCHDOG] 切回完整规则集：{msg}', flush=True)
            return True
        _WATCHDOG['last_result'] = msg
        return None

    _WATCHDOG['fails'] += 1
    if _WATCHDOG['fails'] < FW_WATCHDOG_FAIL_THRESHOLD:
        _WATCHDOG['last_result'] = (
            f'异常 {_WATCHDOG["fails"]}/{FW_WATCHDOG_FAIL_THRESHOLD}：{detail}'
            '（未达阈值，先观察）')
        print(f'[WATCHDOG] {detail}（连续第 {_WATCHDOG["fails"]} 次，'
              f'未达 {FW_WATCHDOG_FAIL_THRESHOLD} 次阈值，不动手）', flush=True)
        return None

    # 冷却：避免规则永久损坏时反复砸防火墙
    since = time.time() - _WATCHDOG['last_action_ts']
    if _WATCHDOG['last_action_ts'] and since < FW_WATCHDOG_COOLDOWN:
        _WATCHDOG['last_result'] = (
            f'异常但处于冷却期（还剩 {int(FW_WATCHDOG_COOLDOWN - since)}s）')
        return None

    _WATCHDOG['last_action_ts'] = time.time()
    _WATCHDOG['fails'] = 0
    acted, msg = _recover_ruleset_if_unhealthy()
    _WATCHDOG['actions'] += 1
    _WATCHDOG['last_result'] = msg
    print(f'[WATCHDOG] 触发恢复：{msg}', flush=True)
    return acted


def _watchdog_loop():
    """看门狗主循环。任何异常都不能让线程死掉 —— 死了就等于没有自检。"""
    while not _WATCHDOG['stop']:
        try:
            _, interval = _fw_watchdog_settings()
        except Exception:
            interval = FW_WATCHDOG_DEFAULT_INTERVAL
        # 分片睡眠，让 stop 能在 1 秒内生效，不必等满一个间隔
        slept = 0.0
        while slept < interval and not _WATCHDOG['stop']:
            time.sleep(1)
            slept += 1
        if _WATCHDOG['stop']:
            break
        try:
            _watchdog_tick()
        except Exception as e:
            _WATCHDOG['last_result'] = f'自检异常：{type(e).__name__}: {e}'
            print(f'[WATCHDOG] 自检异常（继续下一轮）: {e}', flush=True)


def _start_watchdog():
    """启动看门狗线程。已在跑就不重复起。"""
    global _WATCHDOG_THREAD
    if _WATCHDOG.get('thread') and _WATCHDOG['thread'].is_alive():
        return None
    _WATCHDOG['stop'] = False
    t = threading.Thread(target=_watchdog_loop, name='fw-watchdog', daemon=True)
    t.start()
    _WATCHDOG['thread'] = t
    print(f'[WATCHDOG] 防火墙自检已启动'
          f'（间隔 {_fw_watchdog_settings()[1]}s，'
          f'连续 {FW_WATCHDOG_FAIL_THRESHOLD} 次异常才动手，'
          f'冷却 {FW_WATCHDOG_COOLDOWN}s）', flush=True)
    return t


def _stop_watchdog():
    _WATCHDOG['stop'] = True
    t = _WATCHDOG.get('thread')
    if t and t.is_alive():
        t.join(timeout=3)


_WATCHDOG_THREAD = None


def _auto_recover_ruleset_if_empty():
    """启动时自动恢复 nftables ruleset（如果被清空）。

    恢复优先级：
    1. RULES_PATH（上次成功应用的规则；用户配置的最新）
    2. 按当前配置重新生成（仅当 RULES_PATH 缺失时）
    3. RULES_PATH.backup（首次 apply 时保存的"应用前"快照）
    4. basic lockdown（WAN block / LAN allow，兜底保证路由器不裸奔）

    任何一个通过双重验证（nft -f returncode=0 + fw4 表真存在）就停止。
    全部失败也只记录日志，不抛异常（ruleset 空只是"没规则"而非"程序错误"，
    不应阻止 Web 服务起来 —— 用户至少还能 SSH 进来手动修）。
    """
    if not _ruleset_is_empty():
        return  # 表存在 → ruleset 健康，无需恢复

    print('[WARN] 启动检测：nftables ruleset 为空（inet fw4 表不存在），尝试自动恢复...', flush=True)

    # 优先级 1：当前规则文件
    if os.path.exists(RULES_PATH):
        if _try_apply_rules_file(RULES_PATH):
            print(f'[INFO] ✅ 已从 {RULES_PATH} 恢复 ruleset', flush=True)
            return
        # 文件在，但 nft -f 装不上 —— 它已经损坏了（被截断 / 语法错 / 磁盘满写残）。
        # 这种情况必须和「文件不存在」同等对待：都靠当前配置重建兜底。
        # 先把坏文件留一份证据：重建会把 RULES_PATH 覆盖掉。
        try:
            _quarantine = RULES_PATH + '.corrupted'
            shutil.copy(RULES_PATH, _quarantine)
            print(f'[WARN] 从 {RULES_PATH} 恢复失败（文件存在但装不上 = 已损坏），'
                  f'坏文件留存到 {_quarantine}，尝试按当前配置重建...', flush=True)
        except OSError as qe:
            print(f'[WARN] 从 {RULES_PATH} 恢复失败（已损坏，且留存副本失败: '
                  f'{qe}），尝试按当前配置重建...', flush=True)
    else:
        print('[WARN] 规则文件不存在，尝试按当前配置重建...', flush=True)

    # 优先级 2：按当前配置重新生成
    #
    # 这一步必须排在 .backup 之前。.backup 是「首次 apply 之前」的快照，可能比
    # 当前配置旧好几周。实测踩过（2026-10-06）：规则文件 99-custom-rules.nft 丢失，
    # 启动恢复落到 9-18 的 backup —— 那份 backup 里的 trusted 白名单没有后来才
    # 加进去的管理机 IP，于是 input 链 policy drop 把管理员自己的 SSH 和面板
    # 一起挡在门外，只能从另一台仍在白名单里的机器登进去救。
    # 「保险丝不能装在电表箱里」：恢复用的规则必须来自当前配置，而不是历史快照。
    #
    # 判据是「优先级 1 成功了吗」，**不是**「规则文件存不存在」。
    # 原来这里写的是 `if not os.path.exists(RULES_PATH)`，于是规则文件
    # 存在但已损坏时，守卫判「文件在」→ 整个重建块被跳过 → 直落 .backup。
    # 而 .backup 是 nft list ruleset 的快照（不是规则文件副本），.224 实测
    # 它的 md5 停在 4 天前、行数只有当前的一半，且带着 78a8fb3 修掉之前的
    # 敲门限流老 bug（8 处 1/minute burst 1）。等于把「敲门从来没敲通过」
    # 这个已修的 bug 又装回去。
    #
    # 配置文件不在，就绝不按配置重建 —— 直接落到优先级 3 / 4。
    #
    # 这条比守卫更硬：守卫靠「存在历史产物」来区分全新安装，而实测场景里
    # 配置和规则文件是被一起移走的，守卫此时判不出异常；只有直接检查
    # 文件存不存在才靠得住。DEFAULT_CONFIG 的敲门端口是 1/2/3/4、
    # trusted_ip 是 192.168.100.2 —— 拿它重建等于把陌生网段下发到真实网卡。
    # 宁可退到 .backup 或 basic lockdown。
    if not os.path.exists(CONFIG_PATH):
        print('[ERROR] 配置文件缺失，跳过「按配置重建」，'
              '改用 .backup 或 basic lockdown 兜底', flush=True)
    else:
        try:
            # 配置损坏时 load_config() 拿的是硬编码 DEFAULT_CONFIG（含他人网段）。
            # 开机自动重建时用它，等于每次重启都把陌生网段写进防火墙 —— 必须在
            # 这条路径上也拦住，否则「应用规则」那头的守卫形同虚设。
            _cfg = load_config()
            _bad, _err = _config_corrupted()
            if _bad:
                print(f'[ERROR] 配置损坏（{_err}），拒绝按默认配置重建规则，'
                      f'改用 backup 恢复', flush=True)
            else:
                ok, msg = _apply_ruleset(_cfg)
                if ok:
                    print(f'[INFO] ✅ 规则文件不可用，已按当前配置重新生成并加载: {msg}',
                          flush=True)
                    return
                print(f'[WARN] 按当前配置重建失败（{msg}），尝试 backup...', flush=True)
        except Exception as e:
            print(f'[WARN] 按当前配置重建异常（{e}），尝试 backup...', flush=True)

    # 优先级 3：.backup 文件
    backup_path = RULES_PATH + '.backup'
    if os.path.exists(backup_path):
        if _try_apply_rules_file(backup_path):
            print(f'[INFO] ✅ 已从 {backup_path} 恢复 ruleset', flush=True)
            return
        print(f'[WARN] 从 {backup_path} 恢复失败，尝试 basic lockdown...', flush=True)

    # 优先级 4：basic lockdown（兜底）
    if _apply_basic_lockdown():
        print('[INFO] ✅ 已应用 basic lockdown（WAN block / LAN allow / SSH + Web 放行）', flush=True)
        return

    print('[ERROR] ❌ 自动恢复全部失败，ruleset 仍为空，请手动检查 nft 服务和规则文件', flush=True)


def _ruleset_is_functional():
    """比 _ruleset_is_empty 更严：表在、而且链真的带策略。

    为什么单独一个函数：_ruleset_is_empty 只看 `nft list table inet fw4` 的
    返回码，也就是「表在不在」。但表被 flush 空之后依然存在、返回码依然是 0 ——
    此时内核里一条规则都没有，_ruleset_is_empty 照样说「健康」。
    回滚链路依赖 _ruleset_is_empty 的宽松语义（宁可误报也不能漏报裸奔），
    所以这里另起一个更严的判断，只给健康检查用。

    返回 (bool, str)：第一个是是否可用，第二个是给人看的说明。
    """
    try:
        res = subprocess.run(['nft', 'list', 'table', 'inet', 'fw4'],
                             capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return False, f'无法查询规则集: {e}'
    if res.returncode != 0:
        return False, 'table inet fw4 不存在'
    out = res.stdout or ''
    if 'hook input' not in out:
        return False, 'input 链未挂载 —— 规则集不完整（可能被整体 flush 过）'
    if 'policy drop' not in out and 'policy reject' not in out:
        return False, 'input 链没有 drop/reject 默认策略 —— 防火墙可能未生效'
    if 'type filter hook input' not in out and 'type filter hook' not in out:
        return False, '未找到 filter 类型的 hook 链'
    return True, '正常'


@app.route('/api/rules/health', methods=['GET'])
def rules_health():
    """返回当前 nftables ruleset 健康状态（前端可查询/展示）

    ⚠️ 装饰器必须挂在本函数上，不能挂在 _ruleset_is_functional 上。
    原来挂在辅助函数上，Flask 于是把 (True, '正常') 当作响应返回 ——
    元组第一项是 bool，make_response 直接抛 "did not return a valid
    response"，这个接口从 2026-09-14 起一直是 500。
    之所以没人发现：前端从来没调用过它。
    """
    if not _is_authenticated():
        return jsonify({'success': False, 'code': 'AUTH_REQUIRED', 'message': '未登录'}), 401
    functional, detail = _ruleset_is_functional()
    degraded, degrade_detail = _ruleset_is_degraded()
    return jsonify({
        'success': True,
        'data': {
            # ruleset_loaded 保持原语义（表在不在），不破坏前端既有判断
            'ruleset_loaded': not _ruleset_is_empty(),
            # 新增：真正「防火墙生效」的判断
            'ruleset_functional': functional,
            'detail': detail,
            # 降级态：basic lockdown 生效中。ruleset_functional 仍然是 true
            # （表在、policy drop、filter hook 都满足），但敲门 / 端口转发 /
            # 黑名单全都没生效 —— 前端必须能把它和「完全正常」区分开，
            # 否则用户看到的永远是「正常」。
            'ruleset_degraded': degraded,
            'degraded_detail': degrade_detail,
            'watchdog': {
                'enabled': _fw_watchdog_settings()[0],
                'interval': _fw_watchdog_settings()[1],
                'fail_threshold': FW_WATCHDOG_FAIL_THRESHOLD,
                'cooldown': FW_WATCHDOG_COOLDOWN,
                'promote_max_fails': _PROMOTE_MAX_FAILS,
                'promote_fails': _WATCHDOG.get('promote_fails', 0),
                'running': bool(_WATCHDOG.get('thread')
                                and _WATCHDOG['thread'].is_alive()),
                'consecutive_fails': _WATCHDOG['fails'],
                'actions': _WATCHDOG['actions'],
                'last_result': _WATCHDOG['last_result'],
            },
            'rules_file': RULES_PATH,
            'rules_file_exists': os.path.exists(RULES_PATH),
            'backup_file_exists': os.path.exists(RULES_PATH + '.backup'),
        }
    })


def _build_ssl_context(cert_files):
    """构造 werkzeug SSL context"""
    if not cert_files:
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_files[0], cert_files[1])
        return ctx
    except Exception as e:
        print(f"[WARNING] SSL context 构造失败：{e}", flush=True)
        return None


def _start_servers():
    """启动单端口 HTTPS 面板服务（默认 5443，仅 LAN 可达）。

    启动前置条件：
    1. 先自动恢复 nftables ruleset（如果被清空，避免带病起服务）
    2. 必须有可用证书（反代证书优先，否则自签）；都失败 → 拒绝启动

    恢复规则优先级：当前规则文件 > .backup > basic lockdown（WAN block / LAN allow）

    注：v0.8.0 起移除了原先的 HTTP 5000 跳转器 —— 它在 10-01 那轮
    把 lan_allowed_ports 从 5000 改成 5443 之后已被防火墙 policy drop
    拦住，实际从未可达，属于死代码。对外只保留 HTTPS 5443 一个入口。
    """
    # ========== 启动时自动恢复 nftables ruleset ==========
    _auto_recover_ruleset_if_empty()

    # ========== 运行期防火墙自检 ==========
    # 启动恢复只覆盖「启动那一刻」。运行期规则集被清空（fw4 被别人 enable、
    # 别的工具 flush、内核异常）没人会发现，期间路由器裸奔。
    try:
        _start_watchdog()
    except Exception as e:
        print(f'[WATCHDOG] 启动失败（不影响 Web 服务）: {type(e).__name__}: {e}',
              flush=True)

    # ========== 启动时对齐 LuCI 80/443 ==========
    # 配置里的 luci_enabled 是**期望**，/etc/config/nginx 里那两段在不在才是
    # **实际**。升级上来时老配置没这字段（期望=False）而机器上 LuCI 一直开着，
    # 不在这里对齐就永远是「配置说关了、端口还开着」。
    # 失败不阻断启动：LuCI 开着只是多两个监听口，不是裸奔。
    try:
        _moved, _msg = _luci_reconcile(load_config().get('luci_enabled', False))
        if _moved:
            print(f'[LuCI] 启动对齐：{_msg}', flush=True)
    except Exception as e:
        print(f'[WARN] 启动时对齐 LuCI 80/443 失败（不影响启动）: '
              f'{type(e).__name__}: {e}', flush=True)

    import sys as _sys
    from werkzeug.serving import make_server

    cert_files = _ensure_https_cert()
    ssl_ctx = _build_ssl_context(cert_files)

    if not ssl_ctx:
        print("[FATAL] HTTPS 证书不可用，拒绝启动（避免密码明文传输）。", flush=True)
        print("        请检查：", flush=True)
        print("        1. /etc/nginx/ssl/<domain>/ 下是否有有效反代证书（≥30 天有效期）", flush=True)
        print("        2. 或确认 openssl 可用，以便生成自签证书", flush=True)
        _sys.exit(1)

    debug = os.environ.get('FLASK_DEBUG', '0') == '1'

    # 单端口模式：面板本体 HTTPS。
    #
    # 绑定到 LAN 地址而不是 0.0.0.0。原来的做法把「面板只在 LAN 可达」
    # 这件事完全外包给了防火墙 —— 而防火墙和被保护方在同一台机器上，
    # 规则集一旦丢失（flush / 文件损坏 / 恢复链选错），面板连同它的 root
    # 权限一起变成公网服务。绑地址是唯一一道不依赖防火墙的防线。
    #
    # 探测不到 LAN 地址时**拒绝启动**，不回落 0.0.0.0：管理界面「打不开」
    # 可以走 SSH 修（22 同样在 LAN 上），「降级成公网开放」则不可恢复。
    # 逃生口是显式的：NFTABLES_WEB_BIND=0.0.0.0，且会打日志。
    _bind = os.environ.get('NFTABLES_WEB_BIND', '').strip()
    _bind_source = '环境变量 NFTABLES_WEB_BIND'
    if not _bind:
        _cfg = load_config()
        _lan_if = str(_cfg.get('lan_if') or 'br-lan').strip() or 'br-lan'
        _bind = _lan_bind_address(_lan_if)
        _bind_source = f'探测 {_lan_if} 得到'
    if not _bind:
        print(f'[FATAL] 探测不到 LAN 接口地址，拒绝启动 —— 宁可打不开，也不能降级成公网开放。', flush=True)
        print('         处理方式：', flush=True)
        print(f'           1. SSH 登录本机（LAN 上任意未被防火墙关闭的 SSH 端口），确认 LAN 接口已拿到地址', flush=True)
        print(f'           2. 或确认 config.json 里 lan_if 写对了（当前：{_cfg.get("lan_if")!r}）', flush=True)
        print(f'           3. 实在要临时开放：export NFTABLES_WEB_BIND=0.0.0.0（会打日志，属显式降级）', flush=True)
        _sys.exit(1)

    https_server = make_server(_bind, HTTPS_PORT, app, ssl_context=ssl_ctx, threaded=True)

    print(f" * HTTPS 主服务  : https://{_bind}:{HTTPS_PORT}  (证书: {cert_files[0]})", flush=True)
    print(f" * 绑定来源      : {_bind_source}", flush=True)
    print(f" * 访问范围      : 仅 LAN（公网入口由独立网关端口承担，见 gateway_port 配置）", flush=True)
    print(f" * Cookie Secure : True（仅 HTTPS 传输，防 cookie 窃取）", flush=True)

    try:
        https_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        https_server.shutdown()


if __name__ == "__main__":
    _start_servers()
