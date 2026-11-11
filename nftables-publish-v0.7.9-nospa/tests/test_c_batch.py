"""打包清理批（2026-11-04 第十四/十五轮）的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_c_batch.py

覆盖这一批的四个改动：

  CB-1  router_ip4 自愈：机器换过 IP（.146 → .238）后，配置里的旧地址
        会被纠正 —— 这个值是**自签证书的 CN/SAN**，不纠正的话
        浏览器在新地址上照样报「证书与域名不匹配」
  CB-2  网关令牌密钥（P1-9）：进程内缓存 + 读不到时明确告警
        （原来每次调用都重读、读不到就换一把随机密钥 ⇒ 刚签的令牌立刻验不过）
  CB-3  访问边界降级（P1-26）：「面板当前不限制来源」这个状态
        必须能在界面上看见（原来只有服务端日志一行 [WARN]）
  CB-4  setup.sh 的三个 apk 缺陷 —— 单独一个文件
        tests/test_setup_apk_fallback.py（那边会真跑 shell 函数）

沙箱运行：不碰真实配置、不执行 nftables / nginx、不联网。
"""
import importlib
import io
import json
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print('\n== ' + title)


APP_SRC = io.open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
GW_SRC = io.open(os.path.join(BACKEND, 'auth_gateway.py'), encoding='utf-8').read()
INDEX_HTML = io.open(os.path.join(ROOT, 'frontend', 'index.html'), encoding='utf-8').read()
APP_JS = io.open(os.path.join(ROOT, 'frontend', 'app.js'), encoding='utf-8').read()
STYLES = io.open(os.path.join(ROOT, 'frontend', 'styles.css'), encoding='utf-8').read()


def fn_src(src, name):
    m = re.search(rf'^def {re.escape(name)}\(.*?(?=\n@app\.route|\ndef |\nclass |\n# ═)',
                  src, re.S | re.M)
    return m.group(0) if m else ''


def strip_py_comments(src):
    """剥掉 Python 注释（保留字符串里的 #）。

    为什么需要：源码里到处是「解释性注释」，而注释里常常**正好包含**
    被断言的关键字 —— 比如 apk 函数的注释里写着 `--timeout`，
    于是「函数体里有 --timeout」这个断言即使把**代码**删了也照样通过。
    ⇒ 断言「这个东西不该出现/该出现」必须基于去注释后的源码。
    """
    out = []
    for line in src.splitlines():
        res = ''
        in_s = in_d = False
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '#' and not in_s and not in_d:
                break
            if ch == "'" and not in_d:
                in_s = not in_s
            elif ch == '"' and not in_s:
                in_d = not in_d
            res += ch
            i += 1
        out.append(res)
    return '\n'.join(out)


# ─────────────────────────────────────────────────────────────
sec('CB-1  router_ip4 自愈（机器换过 IP）')

TD = tempfile.mkdtemp(prefix='cbatch-')
CFG = os.path.join(TD, 'cfg.json')

sys.modules.pop('app', None)
app = importlib.import_module('app')
app.CONFIG_PATH = CFG
app._NETS_CACHE.update(mtime=None, nets=None)

with open(CFG, 'w', encoding='utf-8') as f:
    json.dump({'router_ip4': '192.168.100.146', 'lan_if': 'br-lan'}, f)

msg = app._sync_router_ip4('192.168.100.238')
with open(CFG, encoding='utf-8') as f:
    after = json.load(f)

check('探测到的地址与配置不同时会同步',
      after.get('router_ip4') == '192.168.100.238',
      '配置现值=%s' % after.get('router_ip4'))
check('同步时会说明改了什么（给人看日志）',
      bool(msg) and '192.168.100.146' in msg and '192.168.100.238' in msg, msg or '(空)')

before = after.get('router_ip4')
msg2 = app._sync_router_ip4('192.168.100.238')
with open(CFG, encoding='utf-8') as f:
    after2 = json.load(f)
check('地址一致时不动配置（不重复写盘）',
      after2.get('router_ip4') == before and msg2 == '',
      'msg=%r' % msg2)

check('非法地址直接忽略（不把垃圾写进配置）',
      app._sync_router_ip4('not-an-ip') == '')
with open(CFG, encoding='utf-8') as f:
    after3 = json.load(f)
check('非法地址没有污染配置',
      after3.get('router_ip4') == '192.168.100.238', after3.get('router_ip4'))

check('空地址直接忽略', app._sync_router_ip4('') == '')

# 启动顺序：同步必须发生在生成证书**之前**（证书 CN 用 router_ip4）
_start = APP_SRC[APP_SRC.index('def _start_servers('):] if 'def _start_servers(' in APP_SRC else ''
_i_sync = _start.find('_sync_router_ip4(')
_i_cert = _start.find('cert_files = _ensure_https_cert()')
check('启动时先同步 router_ip4、再生成证书（顺序反了证书 CN 还是旧 IP）',
      _i_sync != -1 and _i_cert != -1 and _i_sync < _i_cert,
      'sync@%d cert@%d' % (_i_sync, _i_cert))
check('同步失败不会阻断启动（只是告警）',
      re.search(r'_sync_router_ip4\(.*?\n.*?except Exception as e', _start, re.S) is not None)

# ⚠️ 运行时断言：同步**只写配置**，绝不能触发防火墙重下发。
# 启动阶段重下发风险太大（规则集还在恢复链上，一发就可能把机器网络打断）。
# 这条必须真跑 —— 静态文本断言钉不住「顺手加一句 apply_rules()」。
_sync_calls = []
_orig_save = app.save_config


def _spy_save(cfg):
    _sync_calls.append('save_config')
    return _orig_save(cfg)


app.save_config = _spy_save
_deploy_seen = []
_DEPLOY_FNS = ('apply_rules', '_apply_ruleset', '_apply_ruleset_locked', '_deploy_all_rules')
_saved_fns = {}
for _fn in _DEPLOY_FNS:
    if hasattr(app, _fn):
        _saved_fns[_fn] = getattr(app, _fn)

        def _mk(name, orig):
            def _wrapper(*a, **kw):
                _deploy_seen.append(name)
                return orig(*a, **kw)
            return _wrapper
        setattr(app, _fn, _mk(_fn, _saved_fns[_fn]))
try:
    with open(CFG, 'w', encoding='utf-8') as f:
        json.dump({'router_ip4': '192.168.100.146', 'lan_if': 'br-lan'}, f)
    app._sync_router_ip4('192.168.100.238')
finally:
    app.save_config = _orig_save
    for _fn, _orig_fn in _saved_fns.items():
        setattr(app, _fn, _orig_fn)
check('同步只写配置，不触发防火墙重下发（启动阶段重下发可能打断网络）',
      len(_deploy_seen) == 0,
      '触发了下发: %s' % (_deploy_seen or '无'))

# 非法地址：不但返回值要为空，**配置也不能被污染**
with open(CFG, 'w', encoding='utf-8') as f:
    json.dump({'router_ip4': '192.168.100.238', 'lan_if': 'br-lan'}, f)
app._sync_router_ip4('999.999.999.999')
with open(CFG, encoding='utf-8') as f:
    _after_bad = json.load(f)
check('非法地址没有污染配置（999.999.999.999 也不行）',
      _after_bad.get('router_ip4') == '192.168.100.238', _after_bad.get('router_ip4'))

# ⚠️ 运行时断言：同步**失败时不能抛异常**。
#   静态正则（_sync_router_ip4(...) 后面跟着 except Exception）只能证明
#   「调用点被 try 包着」—— 真正的风险在**函数内部**：
#   save_config 失败时如果直接 raise，异常会一路冒到 _start_servers 的
#   except 里被吞掉（启动照常，但配置永远同步不上，且日志看不出原因）。
#   ⇒ 必须真跑一次「save_config 抛异常」看看 _sync_router_ip4 自己怎么反应。
def _boom_save(cfg):
    raise OSError('模拟写盘失败')


_app_save = app.save_config
app.save_config = _boom_save
try:
    with open(CFG, 'w', encoding='utf-8') as f:
        json.dump({'router_ip4': '192.168.100.146'}, f)
    _raised = None
    _ret = None
    try:
        _ret = app._sync_router_ip4('192.168.100.238')
    except Exception as e:                  # noqa: BLE001
        _raised = e
finally:
    app.save_config = _app_save
check('写盘失败时 _sync_router_ip4 不抛异常（返回说明，不阻断启动）',
      _raised is None, '抛了 %s: %s' % (type(_raised).__name__, _raised) if _raised else '')
check('写盘失败时返回的说明里写了失败原因',
      bool(_ret) and ('失败' in _ret), repr(_ret)[:120] if _ret else '(空)')
with open(CFG, encoding='utf-8') as f:
    check('写盘失败时配置没被改坏（老值还在）',
          json.load(f).get('router_ip4') == '192.168.100.146')

# ─────────────────────────────────────────────────────────────
sec('CB-2  网关令牌密钥：进程内缓存 + 明确告警（P1-9）')

sys.modules.pop('auth_gateway', None)
gw = importlib.import_module('auth_gateway')

_gw_td = tempfile.mkdtemp(prefix='cbsecret-')
gw.SECRET_FILE = os.path.join(_gw_td, 'secret')


def _cache_defaults_from_src():
    """从源码里读出 _SECRET_CACHE 的初始结构（键名 + 初值）。

    为什么不能用 `gw._SECRET_CACHE.update(key=None)` 重置：
    那个写法会把 `key` 这个键**又加回**字典里 ——
    于是「缓存字典的键被改名」这种变异被测试自己补好了现场，测不出来。
    ⇒ 必须按**源码里的定义**重建：定义改了键名，重置后函数访问旧键就 KeyError。
    """
    m = re.search(r'_SECRET_CACHE\s*=\s*\{(.*?)\}', GW_SRC, re.S)
    if not m:
        return {}
    body = m.group(1)
    out = {}
    for k in re.findall(r'["\'](\w+)["\']\s*:\s*(\w+)', body):
        out[k[0]] = None
    return out


def _reset_gw_cache():
    gw._SECRET_CACHE.clear()
    gw._SECRET_CACHE.update(_cache_defaults_from_src())


def _load_secret_safe():
    """调 _load_secret()，把异常接住，返回 (值, 错误信息)。

    ⚠ 为什么必须接住（2026-11-11 审查 M8）
    -----------------------------------
    这条链路的两个变异都会让它**抛异常**：
      · D-06（缓存键名改了）⇒ `_SECRET_CACHE["key"]` 抛 KeyError；
      · D-02（读盘失败时覆盖原文件）⇒ 错误处理分支里那次写又抛 PermissionError。
    异常直接冒到测试脚本 ⇒ **脚本崩溃** ⇒ 变异被误记成「没抓住」
    ⇒ 判据必须**断言**「这条路径不得抛异常」，而不是崩掉。
    """
    try:
        return gw._load_secret(), None
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)


_reset_gw_cache()

k1, e1 = _load_secret_safe()
k2, e2 = _load_secret_safe()
check('取密钥**不得抛异常**（错误路径也要能返回临时密钥）', e1 is None, str(e1))
check('连续两次取到的密钥**相同**（原来每次都是一把新的随机密钥）',
      e1 is None and e2 is None and k1 == k2 and len(k1) >= 16,
      'err=%s/%s' % (e1, e2))
check('文件不存在时也不抛异常', e1 is None and isinstance(k1, bytes))

# 文件存在 → 读它
_reset_gw_cache()
with open(gw.SECRET_FILE, 'w', encoding='utf-8') as f:
    f.write('a-fixed-secret-value')
k3, e3 = _load_secret_safe()
check('文件存在时用文件里的密钥',
      e3 is None and k3 == b'a-fixed-secret-value', 'err=%s val=%r' % (e3, k3))
k3b, e3b = _load_secret_safe()
check('读到的密钥也被缓存（第二次不再读盘）',
      e3b is None and k3b == k3, 'err=%s' % e3b)

# 读不到（权限坏）⇒ 用临时密钥 + 告警 + **不覆盖原文件**
_reset_gw_cache()
os.chmod(gw.SECRET_FILE, 0o000)
_read_failed = False
try:
    with open(gw.SECRET_FILE, 'r') as f:
        f.read()
except OSError:
    _read_failed = True
if _read_failed:
    k4, e4 = _load_secret_safe()
    check('读盘失败时**不得抛异常**（错误处理分支自己不能再炸）', e4 is None, str(e4))
    check('文件读不到时退回临时密钥（而不是崩溃）',
          e4 is None and isinstance(k4, bytes) and len(k4) >= 16, 'err=%s' % e4)
    k4b, e4b = _load_secret_safe()
    check('读不到时进程内仍然自洽（前后两次一致）',
          e4b is None and k4b == k4, 'err=%s' % e4b)
    # ⚠️ 000 权限下连 root 之外的用户都读不了 ⇒ 先恢复权限再核对内容
    os.chmod(gw.SECRET_FILE, 0o600)
    with open(gw.SECRET_FILE, 'r') as f:
        check('读不到时**不覆盖**原文件（唯一那份密钥不能被毁掉）',
              f.read() == 'a-fixed-secret-value')
else:
    # 当前用户是 root ⇒ 000 也能读；这条退化成静态断言
    check('（当前用户能读 000 文件，跳过运行时校验）', True)
os.chmod(gw.SECRET_FILE, 0o600)

check('_load_secret 里有进程内缓存（_SECRET_CACHE）',
      '_SECRET_CACHE' in fn_src(GW_SRC, '_load_secret'))
check('缓存字典的键名与函数体访问的键名一致（键名对不上 ⇒ 缓存形同虚设）',
      set(_cache_defaults_from_src()) == {'key'}
      and set(re.findall(r'_SECRET_CACHE\[["\']([\w]+)["\']\]',
                         fn_src(GW_SRC, '_load_secret'))) <= set(_cache_defaults_from_src()),
      '定义键=%s，函数体访问键=%s'
      % (sorted(_cache_defaults_from_src()),
         sorted(set(re.findall(r'_SECRET_CACHE\[["\']([\w]+)["\']\]',
                               fn_src(GW_SRC, '_load_secret'))))))
check('读不到 / 文件缺失时都有明确告警（不是一声不吭）',
      fn_src(GW_SRC, '_load_secret').count('[WARNING]') >= 2,
      'WARNING 出现 %d 次' % fn_src(GW_SRC, '_load_secret').count('[WARNING]'))
check('网关不再自己写令牌密钥文件（属主/权限由 init 脚本以 root 播种）',
      'open(SECRET_FILE, "w")' not in fn_src(GW_SRC, '_load_secret')
      and 'os.open(SECRET_FILE' not in fn_src(GW_SRC, '_load_secret'))
# ⚠️ 同理：告警关键字在**注释**里也写着「[WARNING]」——
#   只看正文的话，把两处 print 删掉、注释留着，断言照样通过。
#   ⇒ 断言必须基于去注释后的源码。
_gw_nocom = strip_py_comments(fn_src(GW_SRC, '_load_secret'))
check('告警是**真的打印**的，不是只写在注释里',
      _gw_nocom.count('[WARNING]') >= 2,
      '去注释后 WARNING 出现 %d 次' % _gw_nocom.count('[WARNING]'))
check('去注释后仍确认网关不写令牌密钥文件',
      'open(SECRET_FILE, "w")' not in _gw_nocom
      and 'os.open(SECRET_FILE' not in _gw_nocom)

# ─────────────────────────────────────────────────────────────
sec('CB-3  访问边界降级要能在界面上看见（P1-26）')

check('后端有降级状态的记录函数', '_set_access_boundary_degraded' in APP_SRC)
check('有对外的读取函数', 'def access_boundary_warning()' in APP_SRC)
check('/api/auth/status 带上了 access_boundary_warning',
      re.search(r"'access_boundary_warning'\s*:\s*access_boundary_warning\(\)",
                APP_SRC) is not None)
check('配置损坏 / 缺失两条路径都会记录降级原因',
      APP_SRC.count('_set_access_boundary_degraded(') >= 3,
      '出现 %d 次' % APP_SRC.count('_set_access_boundary_degraded('))
check('降级原因里写清了后果（已拒绝所有来源访问）',
      '已拒绝所有来源访问' in APP_SRC)
check('降级原因里带上了修复步骤（fail-closed 后面板打不开，告警是唯一入口）',
      'SSH 到本机' in APP_SRC and '重启面板服务' in APP_SRC)
# ⚠️ 2026-11-08（P1-26 改 fail-closed）：降级时必须给**非空**网段。
#    调用点是 `if _allow_nets and not _ip_in_nets(...)`，
#    空列表是 falsy ⇒ 会被当成「不限制」⇒ 表达不了 fail-closed。
check('调用点是「非空才判定」（所以降级必须给非空网段）',
      re.search(r'if\s+_allow_nets\s+and\s+not\s+_ip_in_nets\(', APP_SRC) is not None)
check('代码里有「拒绝一切」的哨兵网段',
      '_DENY_ALL_NETS' in APP_SRC
      and re.search(r'_DENY_ALL_NETS\s*=\s*\(ipaddress\.ip_network\(\'0\.0\.0\.0/32\'\),\)',
                    APP_SRC) is not None)
check('前端把告警读进了状态',
      'access_boundary_warning' in APP_JS and 'auth.accessWarning' in APP_JS)
check('页面里有告警条', 'nf-access-warn' in INDEX_HTML)
check('告警条绑定的是 auth.accessWarning',
      re.search(r'x-show="auth\.accessWarning"', INDEX_HTML) is not None)
_m = re.search(r'\.nf-access-warn\s*\{([^}]*)\}', STYLES)
check('告警条有样式规则', _m is not None)
if _m:
    check('告警条 z-index 高于登录遮罩（登录页也要看得见）',
          re.search(r'z-index:\s*1(?:0[5-9]|[1-9]\d)', _m.group(1)) is not None,
          _m.group(1).replace('\n', ' ')[:120])

# ⚠️ 运行时断言（这一段才是关键）：
#   静态文本只证明「代码里写了那句话」，不证明「真降级时那句会被设上」。
#   静态断言最危险的退化：把 `_set_access_boundary_degraded(...)` 的**实参**
#   换成空串、或把调用挪进一个永远不走的分支 —— 文本都在，行为没了。
_deg_td = tempfile.mkdtemp(prefix='cbdeg-')
_deg_cfg = os.path.join(_deg_td, 'cfg.json')
app.CONFIG_PATH = _deg_cfg
app._NETS_CACHE.update(mtime=None, nets=None)

# (a) 配置文件缺失 ⇒ fail-closed：拒绝所有来源，且必须记下原因
if os.path.exists(_deg_cfg):
    os.unlink(_deg_cfg)
app._NETS_CACHE.update(mtime=None, nets=None)
_nets_missing = app._panel_allowed_networks()
_r_missing = app.access_boundary_warning()
check('配置缺失时降级原因被真的记下来了（运行时）',
      bool(_r_missing), repr(_r_missing[:80]))
check('配置缺失时的原因写清了「已拒绝所有来源访问」（运行时）',
      '已拒绝所有来源访问' in _r_missing, repr(_r_missing[:80]))
# ⚠️ 行为级断言（2026-11-08 加）：光看文案不够 ——
#    降级时如果给的是空列表，调用方的 `if _allow_nets and ...` 会短路
#    ⇒ 等于「不限制」，fail-closed 根本没生效（退化还不容易被看出来）。
check('配置缺失时给的是非空网段（空列表在调用方等于「不限制」）',
      bool(_nets_missing), '实际=%r' % (_nets_missing,))
check('配置缺失时真实来源 IP 一律不在允许网段内（fail-closed 真生效）',
      not app._ip_in_nets('192.168.100.5', _nets_missing)
      and not app._ip_in_nets('127.0.0.1', _nets_missing),
      '实际允许网段=%r' % (_nets_missing,))

# (a2) 逃生口：环境变量放行的网段在降级期间**仍然有效**
#      （它是进程启动时就有的、不依赖配置文件的可信信息）
app.PANEL_ALLOWED_NETS_ENV = '10.0.0.0/8'
app._NETS_CACHE.update(mtime=None, nets=None)
_nets_env = app._panel_allowed_networks()
check('降级期间环境变量放行的网段仍然有效（运维逃生口）',
      app._ip_in_nets('10.1.2.3', _nets_env),
      '实际允许网段=%r' % (_nets_env,))
app.PANEL_ALLOWED_NETS_ENV = ''
app._NETS_CACHE.update(mtime=None, nets=None)

# (b) 配置损坏 ⇒ 同上（fail-closed）
with open(_deg_cfg, 'w', encoding='utf-8') as f:
    f.write('{ broken json ')
app._NETS_CACHE.update(mtime=None, nets=None)
_nets_bad = app._panel_allowed_networks()
_r_bad = app.access_boundary_warning()
check('配置损坏时降级原因被真的记下来了（运行时）',
      bool(_r_bad), repr(_r_bad[:80]))
check('配置损坏时的原因写清了「已拒绝所有来源访问」（运行时）',
      '已拒绝所有来源访问' in _r_bad, repr(_r_bad[:80]))
check('配置损坏时给的是非空网段（否则等于「不限制」）',
      bool(_nets_bad), '实际=%r' % (_nets_bad,))
check('配置损坏时真实来源 IP 一律不在允许网段内（fail-closed 真生效）',
      not app._ip_in_nets('192.168.100.5', _nets_bad),
      '实际允许网段=%r' % (_nets_bad,))

# (b2) 配置**读取抛异常** ⇒ 第三条降级路径，同样必须 fail-closed
#      这条路径以前没有任何覆盖 ⇒ 把 `nets = []` 改回去测试也不会红（漏网）。
#      注意：文件必须存在，否则会先命中 (a) 的「配置不存在」分支。
with open(_deg_cfg, 'w', encoding='utf-8') as f:
    json.dump({'panel_allowed_nets': '192.168.100.0/24',
               'lan_subnet4': '192.168.100.0/24'}, f)
app._NETS_CACHE.update(mtime=None, nets=None)
_orig_load = app.load_config


def _boom_load(*_a, **_k):
    raise RuntimeError('模拟配置读取失败')


app.load_config = _boom_load
try:
    _nets_exc = app._panel_allowed_networks()
finally:
    app.load_config = _orig_load
check('配置读取抛异常时降级原因被记下来了（运行时）',
      '已拒绝所有来源访问' in app.access_boundary_warning(),
      repr(app.access_boundary_warning()[:80]))
check('配置读取抛异常时给的是非空网段（否则等于「不限制」）',
      bool(_nets_exc), '实际=%r' % (_nets_exc,))
check('配置读取抛异常时真实来源 IP 一律不在允许网段内（fail-closed 真生效）',
      not app._ip_in_nets('192.168.100.5', _nets_exc),
      '实际允许网段=%r' % (_nets_exc,))

# (c) 配置恢复正常 ⇒ 降级原因必须**清掉**
#     （否则管理员修好配置后还一直挂着告警 ⇒ 狼来了 ⇒ 真告警没人看）
with open(_deg_cfg, 'w', encoding='utf-8') as f:
    json.dump({'panel_allowed_nets': '192.168.100.0/24',
               'lan_subnet4': '192.168.100.0/24'}, f)
app._NETS_CACHE.update(mtime=None, nets=None)
app._panel_allowed_networks()
check('配置恢复正常后降级原因被清掉（否则告警会变成狼来了）',
      app.access_boundary_warning() == '',
      repr(app.access_boundary_warning()[:80]))

# (d) /api/auth/status 真的把这个字段带出去（跑一次 Flask 测试客户端）
#     ⚠️ 面板自己的访问边界会拦非白名单来源 ⇒ 测试客户端从 127.0.0.1 来，
#     必须在允许网段里放行回环，否则拿到的是 403 而不是字段。
try:
    with open(_deg_cfg, 'w', encoding='utf-8') as f:
        json.dump({'panel_allowed_nets': '192.168.100.0/24,127.0.0.1/32',
                   'lan_subnet4': '192.168.100.0/24'}, f)
    app._NETS_CACHE.update(mtime=None, nets=None)
    app.app.config['TESTING'] = True
    _cl = app.app.test_client()
    _resp = _cl.get('/api/auth/status')
    _data = (_resp.get_json() or {}).get('data') or {}
    check('/api/auth/status 运行时真的带上了 access_boundary_warning 字段',
          'access_boundary_warning' in _data,
          'HTTP %s，字段=%s' % (_resp.status_code,
                               sorted(_data.keys()) if _data else '(空)'))
except Exception as e:                      # noqa: BLE001
    check('/api/auth/status 运行时真的带上了 access_boundary_warning 字段',
          False, '%s: %s' % (type(e).__name__, e))

print()
if FAIL:
    print(f'失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
