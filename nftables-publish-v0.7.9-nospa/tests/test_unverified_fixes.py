"""2026-11-21 未核基线条目的修复 —— 行为级回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_unverified_fixes.py

背景
----
2026-10-29 的渗透测试留下 120 条基线 finding，上一轮只逐行核实了 32 条。
2026-11-21 把剩下 88 条全部核实完（56 已修 / 28 仍在 / 4 有争议），
本文件盯住**这一轮修掉的 18 个独立修复点**。

判据原则：**行为级**。
  · 能跑函数的 ⇒ 真跑函数，喂真实输入
  · 能跑 HTTP 的 ⇒ 真发请求，看真实响应
  · init 脚本 ⇒ 把函数原样抽出来，在沙箱里用假 /etc/passwd 真跑
  · 实在跑不了的（Werkzeug 内部行为）⇒ 用真实 Flask 进程做对照实验，
    再加一条源码断言钉住「显式覆盖而不是 setdefault」

覆盖清单（括号内是基线编号）：
  app.py          ①(6/35) 过宽网段守卫  ②(20) 中国IP超网  ③(22) isdigit 陷阱
                 ④(28) 出厂信任IP      ⑤(31) nginx 快照  ⑥(38/52) 读改写加锁
                 ⑦(69) 请求体类型      ⑧(77) 私钥缓存头
  auth_gateway.py ⑨(58) 吊销表读锁      ⑩(67) 免凭据留痕  ⑪(84) 孤立代理字符
                 ⑫(85) 异常状态码      ⑬(88) HTML 缓存头
  init 脚本        ⑭(59) 自建目录       ⑮(76) uid/gid=0  ⑯(78) 僵尸判活
"""
import fcntl
import importlib.util as ilu
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


# ── 全局看门狗 ────────────────────────────────────────────────────────
# 为什么必须有：这一轮要验的「save_config 不再复用锁 fd」那种退化会让
# update_config **永久阻塞**。主线程一旦跟着挂进 flock，整个测试脚本就
# 不再返回 —— 变异脚本只能靠超时收场，而「超时」不是「断言失败」，
# 判不出捕获（输出还卡在缓冲区里没 flush 出来）⇒ 假漏网。
#
# 所以：任何卡死都必须变成一条 [FAIL]。
# ⚠️ os._exit 会跳过 atexit —— 测试进程里没有要清理的东西；
#    被测源码的还原由变异脚本的父进程 finally 负责。
def _watchdog(_signum, _frame):
    sys.stdout.write('  [FAIL] 测试超时（全局看门狗触发）—— 代码里可能存在死锁\n')
    sys.stdout.flush()
    os._exit(1)


signal.signal(signal.SIGALRM, _watchdog)
signal.alarm(120)


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name
          + (f'  — {detail}' if (detail and not ok) else ''))


def sec(title):
    print(f'\n=== {title} ===')


def try_call(fn, *args):
    """调用 fn(*args)，把异常也变成返回值。

    返回 (值, 异常)。异常非 None 时值不可信。

    为什么需要它：变异脚本判「算不算捕获」的口径是**输出里必须有 [FAIL] 行**。
    测试脚本一旦崩掉就没有 [FAIL] ⇒ 判成漏网，而那次变异其实是被抓住的
    ⇒ 假漏网。崩必须变成红。
    """
    try:
        return fn(*args), None
    except Exception as _e:      # noqa: BLE001
        return None, _e


# ══════════════════════════════════════════════════════════════════════
# 沙箱准备
# ══════════════════════════════════════════════════════════════════════
SBX = tempfile.mkdtemp(prefix='nftv2_unver_')
os.environ.update({
    'AUTH_SESSION_SECRET_FILE': os.path.join(SBX, 'session-secret'),
    'AUTH_PASSWORD_FILE': os.path.join(SBX, 'password.json'),
    'AUTH_SECRET_FILE': os.path.join(SBX, 'secret'),
    'AUTH_CONFIG_PATH': os.path.join(SBX, 'gw-config.json'),
    'AUTH_RATELIMIT_FILE': os.path.join(SBX, 'ratelimit.json'),
    'AUTH_AUDIT_LOG': os.path.join(SBX, 'audit.log'),
    'AUTH_REVOCATION_FILE': os.path.join(SBX, 'revoked.json'),
    'AUTH_API_PORT': '18445',
    # 面板的来源边界是 fail-closed 的：不在白名单就 403。
    # 测试客户端的来源是 127.0.0.1 ⇒ 显式放行它。
    'NFTABLES_WEB_PANEL_ALLOWED_NETS': '127.0.0.1/32',
})

import auth_gateway as ag   # noqa: E402  （必须在环境变量设好之后 import）

# 网关配置：auth_lan_bypass 打开、lan_subnet4 覆盖测试客户端所在网段。
# 不开的话 is_lan_source() 恒为 False，「免凭据放行」那条路根本走不到。
with open(os.environ['AUTH_CONFIG_PATH'], 'w', encoding='utf-8') as _fh:
    json.dump({
        'auth_session_timeout': 1800,
        'auth_absolute_timeout': 0,
        'auth_lan_bypass': True,
        'lan_subnet4': '192.168.100.0/24',
        'reverse_proxy': {'rules': []},
    }, _fh, ensure_ascii=False)
ag._config_cache['mtime'] = None

app_spec = ilu.spec_from_file_location('_nftapp_unver', os.path.join(BACKEND, 'app.py'))
app = ilu.module_from_spec(app_spec)
app_spec.loader.exec_module(app)


def sec_app(title):
    print(f'\n=== {title} ===')


def _restore_runner():
    """在应用上下文里调 restore_config，返回 (是否成功, 说明)。"""
    with app.app.app_context():
        _resp = app.restore_config()
    return getattr(_resp, 'status_code', None) == 200, str(_resp)[:160]


def make_client():
    """造一个已登录的面板客户端。

    面板的业务 API 全都要过 before_request 的会话检查 ⇒ 未登录是 401。
    session_transaction 是既有测试（tests/test_config_ownership.py）的做法：
    authenticated=True 表示已登录。
    login_time 用未来时间 —— 它只参与「绝对生命周期上限」判定。
    last_active 必须给当前时间：idle 超时（app.py 的 AUTH_IDLE_TIMEOUT）
    读的是 last_active，缺省 0 ⇒ 会被当成 1970 年就空闲 ⇒ 401 AUTH_EXPIRED。
    auth_epoch 不设 ⇒ 判定为 0，必须与配置里的 auth_token_epoch(0) 一致。
    """
    c = app.app.test_client()
    with c.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = 9e9
        sess['last_active'] = time.time()
    return c


# ══════════════════════════════════════════════════════════════════════
# ①(6/35) 过宽网段：执行点必须回落，不能生成 allow 0.0.0.0/0
# ══════════════════════════════════════════════════════════════════════
sec_app('① 过宽网段守卫（基线 6/35）')
for bad in ('0.0.0.0/0', '0.0.0.0/1', '::/0', '::/1'):
    got = app._safe_cidr(bad, '192.168.0.0/16')
    check(f'_safe_cidr({bad!r}) 回落而不是原样返回',
          got == '192.168.0.0/16', f'实际={got!r}')
check('_safe_cidr 正常网段不受影响',
      app._safe_cidr('192.168.100.0/24', '192.168.0.0/16') == '192.168.100.0/24',
      app._safe_cidr('192.168.100.0/24', '192.168.0.0/16'))
check('_safe_cidr 非法值仍回落默认',
      app._safe_cidr('garbage', '192.168.0.0/16') == '192.168.0.0/16')
check('_safe_cidr 空值回落默认',
      app._safe_cidr('', '192.168.0.0/16') == '192.168.0.0/16')

# 端到端：生成的 nginx 配置里不允许出现 allow 0.0.0.0/0
_cfgdir = os.path.join(SBX, 'nginxconf')
os.makedirs(_cfgdir, exist_ok=True)
_old_nginx_dir = app.NGINX_CONF_DIR
app.NGINX_CONF_DIR = _cfgdir
try:
    _rules = []
    app._nginx_server_preamble(_rules, 8443, '/x/cert.pem', '/x/key.pem', 'TLSv1.2 TLSv1.3')
    _rules.append('    location /x {')
    app._nginx_service_location(
        _rules, {'public_access': False}, '/x', 'http', 'h', 80,
        app._safe_cidr('0.0.0.0/0', '192.168.0.0/16'), 8443)
    _rules.append('    }')
    _conf = '\n'.join(_rules)
    check('生成的 nginx 配置里没有 allow 0.0.0.0/0',
          'allow 0.0.0.0/0' not in _conf,
          [ln for ln in _rules if 'allow' in ln][:3])
finally:
    app.NGINX_CONF_DIR = _old_nginx_dir

# ══════════════════════════════════════════════════════════════════════
# ②(20) 中国 IP 名单：超网必须拒（形状合法 ≠ 语义合理）
# ══════════════════════════════════════════════════════════════════════
sec_app('② 中国 IP 名单拒超网（基线 20）')
_src = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
_i = _src.index('net = ipaddress.IPv4Network(addr + "/" + str(plen), strict=True)')
_seg = _src[_i:_i + 900]
check('超网检查在写盘之前（prefixlen <= 1 就 die）',
      'prefixlen <= 1' in _seg and _seg.index('prefixlen <= 1') < _seg.index('entries.append'),
      '顺序不对')
check('超网判定用的是 die（拒绝整个更新）而不是 continue（静默跳过）',
      'die(' in _seg[:_seg.index('entries.append')])

# ── 行为级：把 app.py 里「中国 IP 名单更新脚本」内嵌的那段 Python 校验
#    原样抽出来真跑一遍，喂一份含超网（0.0.0.0/0）的名单。
#    只盯源码字面量不够 —— die/continue 都是合法 shell 语法，
#    语义退化（超网被静默跳过 ⇒ 名单变成半个互联网）只有真跑才看得出来。
_hd_anchor = ('python3 - "$TMP" "$NFT_FILE" "$SHA_FILE" "$MIN_ENTRIES" '
               '"$ALLOW_UPDATE" << \'PYEOF\'')
_hi = _src.index(_hd_anchor)
_hj = _src.index('\nPYEOF', _hi)
_here_doc = _src[_hi + len(_hd_anchor):_hj]
_china_dir = os.path.join(SBX, 'china')
os.makedirs(_china_dir, exist_ok=True)
_raw = os.path.join(_china_dir, 'raw.txt')
with open(_raw, 'w', encoding='utf-8') as _fh:
    _fh.write('0.0.0.0/0\n1.2.3.0/24\n')
_nft_out = os.path.join(_china_dir, 'china-ips.nft')
_sha_out = os.path.join(_china_dir, 'china-ips.sha256')
_p = subprocess.run([sys.executable, '-', _raw, _nft_out, _sha_out, '1', '1'],
                    input=_here_doc, capture_output=True, text=True, timeout=60)
check('含 0.0.0.0/0 的名单被拒（退出码非 0）',
      _p.returncode != 0, f'rc={_p.returncode} out={_p.stdout[:120]}')
check('拒绝时明说是超网',
      '超网' in (_p.stdout + _p.stderr), (_p.stdout + _p.stderr)[:160])
check('被拒时原列表没被写（文件不存在）',
      not os.path.exists(_nft_out))

# ══════════════════════════════════════════════════════════════════════
# ③(22) isdigit 陷阱：'²'.isdigit() 为真但 int('²') 抛
# ══════════════════════════════════════════════════════════════════════
sec_app('③ isdigit 陷阱（基线 22）')
check('前提成立：\'²\'.isdigit() 为 True 而 int(\'²\') 抛 ValueError',
      '²'.isdigit() and not '²'.isascii())
for _lbl, _a, _want in (
        ('回落默认', ('²', 18000), 18000),
        ('正常数字原样', ('18000', 0), 18000),
        ('零是合法值', ('0', 7), 0),
        ('负号串回落', ('-5', 7), 7),
        ('非数字回落', ('abc', 7), 7)):
    _v, _exc = try_call(app._nonneg_int, *_a)
    check(f'_nonneg_int({_a[0]!r}) {_lbl}',
          _exc is None and _v == _want,
          repr(_exc) if _exc else repr(_v))

_base_cfg = dict(app.DEFAULT_CONFIG)
_base_cfg['lan_subnet4'] = '192.168.100.0/24'
_base_cfg['router_ip4'] = '192.168.100.1'
_base_cfg['trusted_ip4'] = '192.168.100.50'
_errs, _exc = try_call(app.validate_config,
                       {**_base_cfg, 'whitelist_timeout': '²'})
check('validate_config 拒掉 whitelist_timeout=\'²\'',
      _exc is None and any('whitelist_timeout' in e for e in (_errs or [])),
      repr(_exc) if _exc else str((_errs or [])[:3]))

# 生成阶段不得抛异常（原路径在这里 int() 炸 → apply 500）
try:
    _rules = app.build_rules({**_base_cfg, 'whitelist_timeout': '²'})
    check('build_rules 对 whitelist_timeout=\'²\' 不抛异常',
          'timeout 18000s' in _rules,
          [ln for ln in _rules.splitlines() if 'timeout' in ln][:2])
except Exception as _e:
    check('build_rules 对 whitelist_timeout=\'²\' 不抛异常', False, repr(_e))

# ══════════════════════════════════════════════════════════════════════
# ④(28) 出厂信任 IP：不再默认填某个具体 IP
# ══════════════════════════════════════════════════════════════════════
sec_app('④ 出厂信任 IP（基线 28）')
check('DEFAULT_CONFIG 的 trusted_ip4 是空的',
      app.DEFAULT_CONFIG.get('trusted_ip4') in ('', [], None),
      repr(app.DEFAULT_CONFIG.get('trusted_ip4')))
check('DEFAULT_CONFIG 的 trusted_ip6 是空的',
      app.DEFAULT_CONFIG.get('trusted_ip6') in ('', [], None),
      repr(app.DEFAULT_CONFIG.get('trusted_ip6')))
check('DEFAULT_CONFIG 整体通过 validate_config',
      not app.validate_config(dict(app.DEFAULT_CONFIG)),
      str(app.validate_config(dict(app.DEFAULT_CONFIG))[:3]))
_trusted_errs = app.validate_config({**_base_cfg, 'access_mode': 'trusted',
                                     'trusted_ip4': ''})
check('access_mode=trusted 且 trusted_ip4 为空 ⇒ 报错（不把自己锁门外而不提示）',
      any('trusted_ip4' in e for e in _trusted_errs), str(_trusted_errs[:3]))
_lan_errs = app.validate_config({**_base_cfg, 'access_mode': 'lan',
                                  'trusted_ip4': ''})
check('access_mode=lan 且 trusted_ip4 为空 ⇒ 合法',
      not _lan_errs, str(_lan_errs[:3]))
check('trusted 模式下填了 trusted_ip4 ⇒ 合法',
      not app.validate_config({**_base_cfg, 'access_mode': 'trusted',
                                'trusted_ip4': '192.168.100.50'}))

# restore_config 必须把「当前生效值」逐字段补回备份里缺的键 ——
# **哪怕那个生效值是空串**（trusted_ip4 的出厂值就是空串）。
#
# 「键缺失」与「键存在但为空」在下游不是一回事：前者要靠 DEFAULT_CONFIG
# 兜底，后者直接就是空。恢复的目标是「回到当前生效状态」。
_restore_dir = os.path.join(SBX, 'restore')
os.makedirs(_restore_dir, exist_ok=True)
app.CONFIG_PATH = os.path.join(_restore_dir, 'cfg.json')
_cur_cfg = dict(app.DEFAULT_CONFIG)
_cur_cfg['trusted_ip4'] = ''              # 出厂值：空串
with open(app.CONFIG_PATH, 'w', encoding='utf-8') as _fh:
    json.dump(_cur_cfg, _fh)
_bk_cfg = dict(_cur_cfg)
_bk_cfg.pop('trusted_ip4', None)          # 备份里**缺**这个键
with open(app.CONFIG_PATH + '.backup', 'w', encoding='utf-8') as _fh:
    json.dump(_bk_cfg, _fh)
_r_res, _r_exc = try_call(_restore_runner)
_r_ok, _r_msg = _r_res if _r_exc is None else (False, repr(_r_exc))
check('restore 成功', _r_ok is True, str(_r_msg)[:160])
try:
    with open(app.CONFIG_PATH, encoding='utf-8') as _fh:
        _after_restore = json.load(_fh)
except Exception as _e:      # noqa: BLE001
    _after_restore = {}
check('restore 后 trusted_ip4 键存在（哪怕值是空串）',
      'trusted_ip4' in _after_restore, str(sorted(_after_restore)[:6]))
check('restore 后 trusted_ip4 等于当前生效值',
      _after_restore.get('trusted_ip4') == _cur_cfg['trusted_ip4'],
      repr(_after_restore.get('trusted_ip4')))

# ══════════════════════════════════════════════════════════════════════
# ⑤(31) nginx 配置快照失败 ⇒ 拒绝部署，不留坏配置
# ══════════════════════════════════════════════════════════════════════
sec_app('⑤ nginx 快照失败 fail-closed（基线 31）')
_bad_nginx = os.path.join(SBX, 'badnginx')
os.makedirs(_bad_nginx, exist_ok=True)
try:
    os.symlink(os.path.join(SBX, 'no-such-target'), os.path.join(_bad_nginx, 'broken.conf'))
except OSError:
    pass
_old_nginx_dir = app.NGINX_CONF_DIR
app.NGINX_CONF_DIR = _bad_nginx
_old_gen = app._generate_gateway_nginx_conf
# 生成内容那步会牵扯证书/端口一堆依赖，这里直接给一份固定内容，
# 让测试聚焦在「快照失败」这一个环节上。
app._generate_gateway_nginx_conf = lambda cfg: 'server { listen 8443 ssl; }\n'
try:
    _res, _exc = try_call(app._deploy_gateway_nginx, {'gateway_enabled': True})
    _ok, _msg = _res if _exc is None else (None, repr(_exc))
    check('快照失败时拒绝部署（返回 False）',
          _ok is False, f'ok={_ok} msg={_msg}')
    check('拒绝时明说「磁盘未改动」',
          '磁盘未改动' in str(_msg), str(_msg))
    check('正式目录没被动过（坏配置没落盘）',
          not os.path.exists(os.path.join(_bad_nginx, '00-nftables-web-gateway.conf')))
finally:
    app.NGINX_CONF_DIR = _old_nginx_dir
    app._generate_gateway_nginx_conf = _old_gen

# ══════════════════════════════════════════════════════════════════════
# ⑥(38/52) 读-改-写整段加锁：可重入不死锁 + 并发不丢数据
# ══════════════════════════════════════════════════════════════════════
sec_app('⑥ 读改写加锁（基线 38/52）')
#
# 每个小节用**各自独立**的配置文件。
#
# 为什么：变异「save_config 不再复用锁 fd」会让 update_config 永久阻塞，
# 而那个死锁的线程会**一直占着那个锁文件**。后面的小节若还用同一个
# 配置文件，主线程的 save_config 就跟着一起挂死 ⇒ 整个脚本卡住，
# 既测不到后面的判据，也让变异验证只能靠超时收场。
_cfg_a = os.path.join(SBX, 'cfg-a.json')
_cfg_b = os.path.join(SBX, 'cfg-b.json')
_cfg_c = os.path.join(SBX, 'cfg-c.json')
_cfg_d = os.path.join(SBX, 'cfg-d.json')
_cfg_e = os.path.join(SBX, 'cfg-e.json')

app.CONFIG_PATH = _cfg_a
app.save_config({'a': 1, 'list_history': []})

# 6a. 可重入：update_config 内部调 save_config 不能自锁
#
# ⚠️ 必须放进**带超时的线程**里跑：自锁时 save_config 拿着另一把 fd 去
# flock 同一把锁 ⇒ 永久阻塞。直接在主线程调会把整个测试脚本挂死
# （进程不退、变异脚本只能靠超时收场，而「超时」不是「断言失败」，
#  判不出捕获）⇒ 必须让超时变成一条 [FAIL]。
_6a_res = {}


def _6a_run():
    try:
        _6a_res['r'] = app.update_config(lambda c: dict(c, b=2))
    except Exception as _e:      # noqa: BLE001
        _6a_res['e'] = _e


_t6a = threading.Thread(target=_6a_run, daemon=True)
_t6a.start()
_t6a.join(timeout=15)
if _t6a.is_alive():
    check('update_config 不会自锁（save_config 复用同一 fd）', False,
          '15 秒未返回 —— 疑似自锁（save_config 另开了 fd 加同一把锁）')
elif 'e' in _6a_res:
    check('update_config 不会自锁（save_config 复用同一 fd）', False,
          repr(_6a_res['e']))
else:
    _r = _6a_res.get('r')
    check('update_config 不会自锁（save_config 复用同一 fd）',
          _r is not None and _r.get('b') == 2, repr(_r))

# 6b. 并发两个线程各加一条 list_history ⇒ 两条都要在（原来会丢一条）
app.CONFIG_PATH = _cfg_b
app.save_config({'a': 1, 'list_history': []})


def _worker(tag):
    def _m(c):
        h = c.setdefault('list_history', [])
        h.insert(0, {'tag': tag})
        c['list_history'] = h[:50]
        return c
    try:
        app.update_config(_m)
    except Exception as _e:      # noqa: BLE001
        print('    [线程 %s 异常] %r' % (tag, _e))


_ts = [threading.Thread(target=_worker, args=(t,), daemon=True)
      for t in ('A', 'B')]
for _t in _ts:
    _t.start()
for _t in _ts:
    _t.join(timeout=15)
    if _t.is_alive():
        check('并发 update_config 不死锁', False, '线程超时未结束')
        break
else:
    check('并发 update_config 不死锁', True)
with open(_cfg_b, encoding='utf-8') as _fh:
    _after = json.load(_fh)
_tags = [e.get('tag') for e in _after.get('list_history', [])]
check('并发写 list_history 不丢数据（两条都在）',
      sorted(x for x in _tags if x) == ['A', 'B'], str(_tags))

# 6c. post_config 的版本闸在锁内：并发两个同 rev 的保存 ⇒ 一个 200 一个 409
app.CONFIG_PATH = _cfg_c
app.save_config({**app.DEFAULT_CONFIG, 'list_history': []})
_client = app.app.test_client()
_rev = app._config_rev(app.load_config())
_codes = []


def _post():
    c = make_client()
    r = c.post('/api/config', json={'config_rev': _rev, 'trusted_ip4': '192.168.100.50'})
    _codes.append(r.status_code)


_ps = [threading.Thread(target=_post, daemon=True) for _ in range(2)]
for _p in _ps:
    _p.start()
for _p in _ps:
    _p.join(timeout=15)
check('并发 POST /api/config：一个成功一个被版本闸拒下',
      sorted(_codes) == [200, 409], str(_codes))

# 6a-bis. update_config 自己开的锁文件，落盘那一刻就得是 0640。
#
# 为什么单独盯它：锁文件是**第一个**建出来的文件（配置本体还在旧版本），
# 而它是 world-readable 的话，任何本地用户都能看到「谁在改配置」，
# 也能读到配置里写进去的敏感值（明文令牌在某些分支里被截断进 URL）。
# 原来只有 save_config 那条路径被测到，update_config 这条（本轮新增的）
# 没有 —— 补上。
_cfg_lock = _cfg_a + '.lock'
if os.path.exists(_cfg_lock):
    os.unlink(_cfg_lock)
app.CONFIG_PATH = _cfg_a
try:
    app.update_config(lambda c: dict(c))
except Exception as _e:      # noqa: BLE001
    pass
check('update_config 建的配置锁文件落盘就是 0640（不是 umask 的 0644 再 chmod）',
      os.path.exists(_cfg_lock)
      and (os.stat(_cfg_lock).st_mode & 0o777) == 0o640,
      oct(os.stat(_cfg_lock).st_mode & 0o777)
      if os.path.exists(_cfg_lock) else '没建出来')

# 6d. update_config 必须真的取排他锁。
#
# 为什么要单独测这个：「不取锁」这个退化没法靠并发竞速稳定复现 ——
# 两个线程的 load→mutator→save 窗口极窄，竞速测试会 flaky，
# 而 flaky 的变异验证等于没有。这里改成**确定性的**：
# 主线程先占住同一把锁，另一个线程里的 update_config 必须被挡住。
#
# flock 是 OFD 语义：不同 open() 出来的 fd 加同一把锁会互相阻塞
# （同进程也一样）⇒ 「挡住」是确定行为，不是概率行为。
app.CONFIG_PATH = _cfg_d
_lock_path = _cfg_d + '.lock'
_lfd = os.open(_lock_path, os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(_lfd, fcntl.LOCK_EX)
_done_evt = threading.Event()


def _blocked():
    try:
        app.update_config(lambda c: c)
    finally:
        _done_evt.set()


_tb = threading.Thread(target=_blocked, daemon=True)
_tb.start()
time.sleep(1.5)                   # 给它时间去撞锁
_was_blocked = not _done_evt.is_set()
fcntl.flock(_lfd, fcntl.LOCK_UN)
os.close(_lfd)
_tb.join(timeout=15)
check('update_config 真的会取排他锁（锁被别人占着时它必须等）',
      _was_blocked, '锁被占着时 update_config 立刻返回了 —— 它没在加锁')

# ══════════════════════════════════════════════════════════════════════
# ⑦(69) 请求体类型：非字符串不该 500
# ══════════════════════════════════════════════════════════════════════
sec_app('⑦ 请求体类型检查（基线 69）')
app.CONFIG_PATH = _cfg_e
for _lbl, _data, _want in (
        ('对整数返回空串', {'ip': 123}, ''),
        ('对 None 返回空串', {'ip': None}, ''),
        ('对 dict 返回空串', {'ip': {'a': 1}}, ''),
        ('对字符串去空白', {'ip': '  1.2.3.4 '}, '1.2.3.4'),
        ('缺键返回空串', {}, '')):
    _v, _exc = try_call(app._req_str, _data, 'ip')
    check(f'_req_str {_lbl}',
          _exc is None and _v == _want,
          repr(_exc) if _exc else repr(_v))

for _ep, _body in (('/api/lists/add', {'set_name': 'whitelist', 'ip': 123}),
                   ('/api/lists/delete', {'set_name': 'whitelist', 'ip': 123}),
                   ('/api/lists/add', {'set_name': 'whitelist', 'ip': ['1.2.3.4']})):
    _c = make_client()
    _r = _c.post(_ep, json=_body)
    check(f'{_ep} 传非字符串 ip ⇒ 400 而不是 500',
          _r.status_code == 400, f'实际 {_r.status_code}')

_c = make_client()
_r = _c.post('/api/lists/add', json=['whitelist', '1.2.3.4'])
check('/api/lists/add 传数组请求体 ⇒ 400 而不是 500', _r.status_code == 400,
      f'实际 {_r.status_code}')

_c = make_client()
_r = _c.post('/api/lists/presets', json=['whitelist', '1.2.3.4'])
check('/api/lists/presets 传数组请求体 ⇒ 400 而不是 500',
      _r.status_code == 400, f'实际 {_r.status_code}')

# ══════════════════════════════════════════════════════════════════════
# ⑧(77) 私钥下载：响应必须 no-store
# ══════════════════════════════════════════════════════════════════════
sec_app('⑧ 私钥下载缓存头（基线 77）')
_i = _src.index('resp = send_file(')
_seg = _src[_i:_i + 700]
check('私钥下载用显式赋值而不是 setdefault',
      "resp.headers['Cache-Control'] = 'no-store'" in _seg,
      [ln.strip() for ln in _seg.splitlines() if 'Cache-Control' in ln])
# 对照实验：Werkzeug 的 send_file 确实会自带 no-cache，setdefault 压不住
try:
    import flask as _fl
    _a = _fl.Flask(__name__)

    @_a.route('/sf')
    def _sf():
        import io as _io
        return _fl.send_file(_io.BytesIO(b'x'), mimetype='application/octet-stream')

    _c2 = _a.test_client()
    _cc = _c2.get('/sf').headers.get('Cache-Control', '')
    check('对照：Werkzeug send_file 自带 no-cache（所以 setdefault 不够）',
          'no-cache' in _cc, _cc)
except Exception as _e:
    check('对照：Werkzeug send_file 自带 no-cache（所以 setdefault 不够）', False, repr(_e))

# ══════════════════════════════════════════════════════════════════════
# ⑨(58) 吊销表读端加共享锁
# ══════════════════════════════════════════════════════════════════════
sec('⑨ 吊销表读锁（基线 58）')
_gw_src = open(os.path.join(BACKEND, 'auth_gateway.py'), encoding='utf-8').read()
_i = _gw_src.index('def load_revoked():')
_seg = _gw_src[_i:_i + 2000]
check('load_revoked 读端取共享锁',
      'fcntl.flock(f.fileno(), fcntl.LOCK_SH)' in _seg,
      [ln.strip() for ln in _seg.splitlines() if 'flock' in ln])
check('读锁在 json.load 之前取',
      _seg.index('LOCK_SH') < _seg.index('json.load(f)'))
# 行为：文件坏掉时退回 LKG（不是空表）
# 吊销表路径不是独立环境变量 —— auth_gateway 从 RATELIMIT_FILE 推导。
_rev_file = os.path.splitext(ag.RATELIMIT_FILE)[0] + '-revoked.json'
ag._REVOKED_LKG = None
with open(_rev_file, 'w', encoding='utf-8') as _fh:
    json.dump({'jti_old': 9999999999}, _fh)
_loaded = ag.load_revoked()
check('正常读得到吊销条目', 'jti_old' in (_loaded or {}), repr(_loaded))
with open(_rev_file, 'w', encoding='utf-8') as _fh:
    _fh.write('{"jti_old": 99999')          # 半截 JSON
_loaded = ag.load_revoked()
check('半截文件退回 last-known-good（不是空表）',
      isinstance(_loaded, dict) and 'jti_old' in _loaded, repr(_loaded))

# ══════════════════════════════════════════════════════════════════════
# ⑩(67) 免凭据放行必须留痕
# ══════════════════════════════════════════════════════════════════════
sec('⑩ 免凭据放行留痕（基线 67）')
_audit = os.environ['AUTH_AUDIT_LOG']
_LAN_HEADERS = {'X-Real-IP': '192.168.100.50', 'Host': 'gw.example.com'}


def _audit_events():
    _ev = []
    try:
        with open(_audit, encoding='utf-8', errors='replace') as _fh:
            for _ln in _fh:
                try:
                    _ev.append(json.loads(_ln).get('event'))
                except Exception:      # noqa: BLE001
                    pass
    except OSError:
        pass
    return _ev


# 三条免凭据放行的路径都要留痕：
#   /auth/verify  —— nginx auth_request 走的那条
#   /auth/status  —— 门户轮询会话状态
#   /auth/portal  —— 门户页面本身
# 少一条就说明「有路径能绕过审计」，所以逐个端点验。
for _ep in ('/auth/verify', '/auth/status', '/auth/portal'):
    open(_audit, 'w', encoding='utf-8').close()
    _c = ag.app.test_client()
    _r = _c.get(_ep, headers=_LAN_HEADERS)
    check(f'LAN 豁免的 {_ep} 仍然返回 200', _r.status_code == 200,
          str(_r.status_code))
    _events = _audit_events()
    check(f'{_ep} 的免凭据放行有审计记录',
          'lan_bypass_granted' in _events, str(_events))

# ══════════════════════════════════════════════════════════════════════
# ⑪(84) 孤立代理字符 ⇒ 不抛异常、失败计数照记
# ══════════════════════════════════════════════════════════════════════
sec('⑪ 孤立代理字符（基线 84）')
try:
    _res = ag._verify_password('\ud800', 'pbkdf2_sha256$200000$aabb$deadbeef')
    check('_verify_password 对孤立代理字符返回 False 而不是抛异常',
          _res is False, repr(_res))
except Exception as _e:
    check('_verify_password 对孤立代理字符返回 False 而不是抛异常', False, repr(_e))

# ══════════════════════════════════════════════════════════════════════
# ⑫(85) 统一错误处理器不能回 200
# ══════════════════════════════════════════════════════════════════════
sec('⑫ 异常状态码（基线 85）')
from werkzeug.exceptions import HTTPException   # noqa: E402

_i = _gw_src.index('if isinstance(err, HTTPException):')
_seg = _gw_src[_i:_i + 700]
check('错误处理器对状态码做了区间夹取',
      '300 <= _code <= 599' in _seg or '300 <= _code' in _seg,
      [ln.strip() for ln in _seg.splitlines() if '_code' in ln][:3])
# 行为：构造一个 code=None 的 HTTPException，走处理器看返回码
try:
    _exc = HTTPException(description='x')
    _exc.code = None
    with ag.app.test_request_context('/'):
        _resp = ag.app.make_response(ag._on_unhandled(_exc))
        _code = _resp.status_code
    check('code=None 的 HTTPException 不会被当成 200', _code != 200, str(_code))
except Exception as _e:
    check('code=None 的 HTTPException 不会被当成 200', False, repr(_e))

# ══════════════════════════════════════════════════════════════════════
# ⑬(88) HTML 页面不缓存；CSS/JS 仍可缓存
# ══════════════════════════════════════════════════════════════════════
sec('⑬ 静态页缓存头（基线 88）')
_c = ag.app.test_client()
_r = _c.get('/auth/static/login.html', headers={'Host': 'gw.example.com'})
check('login.html 的 Cache-Control 是 no-store',
      _r.headers.get('Cache-Control') == 'no-store',
      _r.headers.get('Cache-Control'))
_r = _c.get('/auth/static/base.css', headers={'Host': 'gw.example.com'})
check('静态资源仍是 no-cache（可缓存但每次回源校验）',
      'no-cache' in (_r.headers.get('Cache-Control') or ''),
      _r.headers.get('Cache-Control'))

# ══════════════════════════════════════════════════════════════════════
# ⑭⑮⑯ init 脚本：把函数原样抽出来在沙箱里真跑
# ══════════════════════════════════════════════════════════════════════
sec('⑭⑮⑯ init 脚本三处（基线 59/76/78）')
_INIT = os.path.join(BACKEND, 'nftables-web-auth.init')
_init_src = open(_INIT, encoding='utf-8').read()


def _init_funcs(*names):
    """把 init 脚本里指定的函数原样抽出来（不改一行逻辑）。"""
    out = []
    for _n in names:
        _i = _init_src.index('\n%s() {' % _n) + 1
        _j = _init_src.index('\n}\n', _i) + 3
        out.append(_init_src[_i:_j])
    return '\n'.join(out)


def _run_sh(script, env=None):
    _p = subprocess.run(['sh'], input=script, capture_output=True, text=True,
                        env=env, timeout=30)
    return _p.returncode, _p.stdout, _p.stderr


# ⑭ 目录不存在时自己建
_t = os.path.join(SBX, 'nftdir')
_script = _init_funcs('_find_free_id', 'prepare_nftweb_files')
_script = _script.replace('_cfgdir="/etc/nftables"',
                          '_cfgdir="$CFG_TEST"')
_script += '\nNFTWEB_USER=nftweb\nCFG_TEST="%s"\nprepare_nftweb_files\necho "RC=$?"\n' % _t
_rc, _out, _err = _run_sh(_script)
check('prepare_nftweb_files 在目录不存在时自己建（不再因 chgrp 失败中止）',
      os.path.isdir(_t), f'rc={_rc} err={_err.strip()[:120]}')

# ⑮ uid/gid 为 0 的 nftweb 条目必须被拒
_t2 = os.path.join(SBX, 'pw')
os.makedirs(_t2, exist_ok=True)
with open(os.path.join(_t2, 'passwd'), 'w', encoding='utf-8') as _fh:
    _fh.write('root:x:0:0:root:/root:/bin/sh\nnftweb:x:0:0:nftweb:/var/nftables-web:/bin/false\n')
with open(os.path.join(_t2, 'group'), 'w', encoding='utf-8') as _fh:
    _fh.write('root:x:0:\nnftweb:x:0:\n')
_script = _init_funcs('_find_free_id', 'ensure_nftweb_user')
_script = _script.replace('/etc/passwd', os.path.join(_t2, 'passwd'))
_script = _script.replace('/etc/group', os.path.join(_t2, 'group'))
_script = _script.replace('/var/nftables-web', os.path.join(_t2, 'home'))
_script += '\nNFTWEB_USER=nftweb\nensure_nftweb_user\necho "RC=$?"\n'
_rc, _out, _err = _run_sh(_script)
check('uid=0 的 nftweb 条目被拒（降权等于没降）',
      'RC=0' not in _out and (_rc != 0 or '拒绝启动' in _err),
      f'rc={_rc} out={_out.strip()[:80]} err={_err.strip()[:120]}')
check('拒绝时明说是 uid/gid 为 0',
      'uid/gid 是 0' in _err or '等于 root' in _err, _err.strip()[:120])

# ⑯ 僵尸进程要当成「已经死了」
#
# ⚠️ 这里必须**只**用从 init 脚本里抽出来的那份 _proc_alive ——
#    不能在旁边再写一份同名的（哪怕一字不差）：shell 里后定义覆盖先定义，
#    写死的那份会把抽出来的那份盖掉 ⇒ 测的其实是测试自己写的那份，
#    init 脚本改了也测不出来（这种假测试比没测试更坏）。
_proc_fn = _init_funcs('_proc_alive')

_p = subprocess.run(
    ['sh', '-c',
     '%s\n'
     'echo "ALIVE_SELF=$(_proc_alive $$ && echo yes || echo no)"\n'
     % _proc_fn],
    capture_output=True, text=True, timeout=30)
check('init 脚本自带 _proc_alive 且对自己判活',
      'ALIVE_SELF=yes' in _p.stdout, _p.stdout.strip()[:120])

# 僵尸：用真僵尸进程验（fork 后不 wait ⇒ 子进程变僵尸）
_zomb_out = ''
try:
    _pid = os.fork()
    if _pid == 0:
        os._exit(0)
    time.sleep(0.4)
    _st = ''
    try:
        with open(f'/proc/{_pid}/status', encoding='utf-8') as _fh:
            for _ln in _fh:
                if _ln.startswith('State:'):
                    _st = _ln.split()[1]
                    break
    except OSError:
        pass
    _p2 = subprocess.run(
        ['sh', '-c',
         '%s\n'
         'if _proc_alive %d; then echo ZOMBIE_ALIVE=yes; else echo ZOMBIE_ALIVE=no; fi\n'
         % (_proc_fn, _pid)],
        capture_output=True, text=True, timeout=30)
    _zomb_out = _p2.stdout.strip()
    os.waitpid(_pid, 0)
except Exception as _e:      # noqa: BLE001
    _zomb_out = 'ERR %r' % _e
check('僵尸进程被判为「已经死了」（kill -0 对僵尸也成功，所以不能只看它）',
      'ZOMBIE_ALIVE=no' in _zomb_out, _zomb_out[:120])

# ══════════════════════════════════════════════════════════════════════
print('\n' + '=' * 74)
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    print('失败项：')
    for _f in FAIL:
        print('  - ' + _f)
    shutil.rmtree(SBX, ignore_errors=True)
    sys.exit(1)
print('全部通过')
shutil.rmtree(SBX, ignore_errors=True)
