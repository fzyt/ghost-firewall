"""安全复验发现的 3 个缺陷的回归测试。

运行:  python3 tests/test_security_fixes.py

每条测试都写成「旧代码必然失败」的形式 —— 否则测了等于没测：
  SEC-1  域名型 target 解析不通必须 400，且不得污染配置
  SEC-2  网关部署失败时规则不得落盘（旧代码是「先保存后部署」）
  SEC-3  重新登录必须吊销旧令牌（旧代码不吊销，实测旧 token 仍可用 1800s）
  SEC-4  /auth/status 有限流（旧代码 30 次连打全 200）
  SEC-5  认证方式标记不再出现在响应里

沙箱运行：只 import 模块并打补丁，不碰真实路径、不执行 nft/nginx。
"""
import importlib
import json
import re
import os
import sys
import tempfile

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def fresh(cfg=True):
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    if cfg:
        app.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'cfg.json')
        app.LISTS_PATH = os.path.join(tempfile.mkdtemp(), 'lists.json')
        app.RULES_PATH = os.path.join(tempfile.mkdtemp(), 'rules.nft')
    return app


def base_cfg():
    return json.loads(json.dumps(importlib.import_module('app').DEFAULT_CONFIG))


def sec(title):
    print(f'\n=== {title} ===')


# ─────────────────────────────────────────────────────────────
sec('SEC-1  域名型 target 必须先验解析')

app = fresh()
# 字面量 IP 不该触发解析检查
check('IP 型 target 不做 DNS 检查（直接判可解析）',
      app._host_resolvable('127.0.0.1') is True
      and app._host_resolvable('192.168.100.50') is True)
check('IPv6 字面量同样直接放行', app._host_resolvable('::1') is True)

# 明确解析不到的域名必须判 False（这是旧代码完全没有的判定）
check('解析不到的域名判 False',
      app._host_resolvable('this-host-does-not-exist-nf-test.invalid') is False)

# 校验入口必须因此拒绝
app._host_resolvable = lambda h, timeout=3.0: (
    True if h in ('127.0.0.1', 'nas.local') else False)
clean, err = app._validate_rp_service({
    'name': 'x', 'path_prefix': '/a', 'target_address': 'dead.example.invalid:80',
    'target_protocol': 'http'})
check('解析不通的域名被 _validate_rp_service 拒绝（400）', err is not None,
      (err or '')[:60])
check('拒绝时错误信息点名了主机名',
      bool(err) and 'dead.example.invalid' in err)

# 可解析的域名仍然要放行，不能一刀切
clean, err = app._validate_rp_service({
    'name': 'x', 'path_prefix': '/a', 'target_address': 'nas.local:5000',
    'target_protocol': 'http'})
check('能解析的域名照常放行（不误伤）', err is None, (err or '')[:60])

# 注入类载荷不能借 DNS 检查绕过格式校验
app._host_resolvable = lambda h, timeout=3.0: True
for bad in ['1.1.1.1:80;\n} server {', '1.1.1.1', 'evil.example:abc']:
    _, e = app._validate_rp_service({
        'name': 'x', 'path_prefix': '/a', 'target_address': bad,
        'target_protocol': 'http'})
    check(f'格式非法的 target 仍被拒：{bad[:24]!r}', e is not None)


# ─────────────────────────────────────────────────────────────
sec('SEC-2  部署失败不得落盘（旧代码是「先保存后部署」）')

app = fresh()
app.NGINX_CONF_DIR = tempfile.mkdtemp()
saved = []
app._save_rp_config = lambda c: saved.append(json.loads(json.dumps(c)))
app._nginx_test = lambda: (True, 'ok')
app._nginx_reload = lambda: (True, 'stub')
app._apply_ruleset = lambda c: (True, 'ok')

# 模拟 nginx 生成失败（域名不通就是真实触发路径）
# SEC-2 要测的是「部署失败」这条路径，所以 DNS 桩必须放行，
# 否则规则在校验阶段就被挡掉，根本走不到部署，报的也是 DNS 的错。
app._host_resolvable = lambda h, timeout=3.0: True
app._deploy_all_rules = lambda config=None: (False, 'nginx -t 失败: host not found in upstream')

# 面板的接口都要登录态，先把认证钩子摘掉再打桩省事
app.app.before_request_funcs[None] = []
app.app.config['TESTING'] = True
c = app.app.test_client()

r = c.post('/api/reverse-proxy/rules', json={
    'name': '毒规则', 'path_prefix': '/poison',
    'target_address': 'dead.example.invalid:80', 'target_protocol': 'http'})
check('部署失败时返回非 2xx', r.status_code >= 400, f'HTTP {r.status_code}')
check('部署失败时 **没有** 调用 _save_rp_config', saved == [], f'保存了 {len(saved)} 次')

# 关键：落盘的配置里不能留下这条毒规则
on_disk = {}
if os.path.exists(app.CONFIG_PATH):
    on_disk = json.load(open(app.CONFIG_PATH))
rules = ((on_disk.get('reverse_proxy') or {}).get('rules')) or []
check('配置文件中不含毒规则（持久化 DoS 已消除）',
      not any(r_['path_prefix'] == '/poison' for r_ in rules),
      f'落盘规则={[r_["path_prefix"] for r_ in rules]}')

# 错误文案不能再骗人说「已保存」
body = r.get_json() or {}
msg = body.get('message', '')
check('错误信息不再声称「服务已保存」', '已保存' not in msg, msg[:70])
check('错误信息说明了规则已被丢弃', ('丢弃' in msg) or ('未生效' in msg), msg[:70])

# 部署成功时仍然必须落盘（不能矫枉过正成「永远不保存」)
app._deploy_all_rules = lambda config=None: (True, 'ok')
saved.clear()
r = c.post('/api/reverse-proxy/rules', json={
    'name': '好规则', 'path_prefix': '/good',
    'target_address': '127.0.0.1:15000', 'target_protocol': 'http'})
check('部署成功时正常落盘', r.status_code < 400 and len(saved) == 1,
      f'HTTP {r.status_code}, 保存 {len(saved)} 次')


# ─────────────────────────────────────────────────────────────
sec('SEC-3  重新登录必须吊销旧令牌')

gw = importlib.import_module('auth_gateway')
import inspect
src = inspect.getsource(gw.auth_login)
check('登录路径里有 revoke_jti 调用', 'revoke_jti(' in src)
check('吊销发生在 issue_token 之前（顺序不能反）',
      src.find('revoke_jti(') < src.find('issue_token('),
      f"revoke@{src.find('revoke_jti(')} issue@{src.find('issue_token(')}")

# 行为验证：用打桩的 issue_token / revoke_jti 跑一遍登录
calls = []
gw.issue_token = lambda *a, **k: calls.append(('issue', a)) or 'faketoken'
gw.revoke_jti = lambda jti, exp: calls.append(('revoke', jti))
gw._password_hash = lambda: 'pbkdf2_sha256$1000$aa$bb'
gw._verify_password = lambda p, s: True
gw._mutate_ratelimit = lambda ip, on_fail: (0, 0)
gw._set_cookies = lambda resp, tok, did: resp
gw.audit = lambda *a, **k: None
gw.load_gateway_config = lambda: {'auth_lan_bypass': False, 'auth_session_timeout': 1800}
gw.fingerprint = lambda: ''

class _Req:
    remote_addr = '192.168.100.249'
    headers = {}
    def __init__(self, cookies=None):
        self.cookies = cookies if cookies is not None else {}
    def get_json(self, silent=True):
        return {'password': 'TestPass123'}

gw.request = _Req({'gw_token': 'oldtok', 'gw_device': 'dev1'})
gw.parse_token = lambda t: ({'jti': 'OLDJTI', 'exp': 9999999999}
                            if t == 'oldtok' else None)

with gw.app.test_request_context():
    gw.auth_login()

kinds = [c[0] for c in calls]
check('登录时确实吊销了旧令牌', 'revoke' in kinds, str(kinds))
if 'revoke' in kinds:
    jti = [c[1] for c in calls if c[0] == 'revoke'][0]
    check('吊销的是旧令牌的 jti', jti == 'OLDJTI', str(jti))
check('吊销早于签发', kinds.index('revoke') < kinds.index('issue')
      if 'revoke' in kinds and 'issue' in kinds else False, str(kinds))

# 没有旧令牌时不能因为缺字段而崩
calls.clear()
gw.parse_token = lambda t: None
with gw.app.test_request_context():
    gw.auth_login()
check('没有旧令牌时登录仍正常（不报错）',
          [c[0] for c in calls].count('issue') == 1)


# ─────────────────────────────────────────────────────────────
sec('SEC-4  /auth/status 必须限流')

check('_status_rate_ok 存在', hasattr(gw, '_status_rate_ok'))

# 路由表绑定检查。
# 这一条是被真机 500 逼出来的：把 _status_rate_ok 插到了
# @app.route("/auth/status") 装饰器底下，Flask 于是把限流函数本身
# 当成视图，拿到一个 bool 当响应，直接 500。
# 而前面的断言全是直接调函数、绕过路由表，所以单测一片绿。
def _view_for(rule):
    for r in gw.app.url_map.iter_rules():
        if str(r) == rule:
            return gw.app.view_functions.get(r.endpoint)
    return None


v = _view_for('/auth/status')
check('路由 /auth/status 绑定的是 auth_status（不是限流函数）',
      v is not None and v.__name__ == 'auth_status',
      '实际绑定: %s' % (getattr(v, '__name__', None)))
check('绑定正确时两者是同一个函数对象', v is gw.auth_status)

# 真正走一次 HTTP，而不是直接调函数
gw._STATUS_HITS.clear()
_real_ip3 = gw.client_ip
gw.client_ip = lambda: '6.6.6.6'
gw.load_gateway_config = lambda: {'auth_lan_bypass': False}
gw.parse_token = lambda t: None
gw.app.config['TESTING'] = True
_http = gw.app.test_client()
try:
    _rc = _http.get('/auth/status').status_code
    check('经 HTTP 访问 /auth/status 返回 200（不是 500）', _rc == 200, f'HTTP {_rc}')
except Exception as _e:
    # 路由绑错时 Flask 会直接抛 TypeError，TESTING 模式下不吞异常。
    # 不接住的话整份测试会在这里中断，后面所有条目都跑不到。
    check('经 HTTP 访问 /auth/status 返回 200（不是 500）', False,
          '请求直接抛异常: %s' % str(_e)[:80])
gw.client_ip = _real_ip3

gw._STATUS_HITS.clear()
ok_n = sum(1 for _ in range(120) if gw._status_rate_ok())
check('限额内全部放行', ok_n == 120, f'放行 {ok_n}/120')
check('超额被限流', gw._status_rate_ok() is False)
blocked = sum(1 for _ in range(50) if gw._status_rate_ok() is False)
check('持续超额持续被拦（不是只拦一次）', blocked == 50, f'拦了 {blocked}/50')

# 不同源 IP 互不影响
gw._STATUS_HITS.clear()
gw._STATUS_RATE_LOCK = __import__('threading').Lock()
_real_ip = gw.client_ip
seq = ['1.1.1.1'] * 200 + ['2.2.2.2']
gw.client_ip = lambda: seq.pop(0) if seq else '3.3.3.3'
first_ip = sum(1 for _ in range(200) if gw._status_rate_ok())
check('A IP 被限流后 B IP 仍可用（不共用计数器）',
      first_ip == 120 and gw._status_rate_ok() is True,
      f'A 放行 {first_ip}')
gw.client_ip = _real_ip

# 限流不能误伤登录：登录限流器是独立的
check('status 限流不复用登录的锁库',
      '_STATUS_HITS' not in inspect.getsource(gw._mutate_ratelimit))

# 端点级：只看限流器函数不够。把 auth_status 里的调用摘掉的话，
# 限流器本身照样工作，测试却全绿 —— 变异验证已经抓到过这个漏网。
gw._STATUS_HITS.clear()
gw._STATUS_RATE_LOCK = __import__('threading').Lock()
_real_ip2 = gw.client_ip
gw.client_ip = lambda: '5.5.5.5'
gw.load_gateway_config = lambda: {'auth_lan_bypass': False, 'auth_session_timeout': 1800}
gw.parse_token = lambda t: None
codes = []
for _ in range(200):
    with gw.app.test_request_context():
        r = gw.auth_status()
    # `return jsonify(...), 429` 返回的是 (Response, 429) 元组，
    # 不是带 status_code 的 Response —— 直接取属性会永远拿到默认 200。
    if isinstance(r, tuple):
        codes.append(r[-1] if isinstance(r[-1], int) else 200)
    else:
        codes.append(getattr(r, 'status_code', 200))
gw.client_ip = _real_ip2
check('端点级：超限后 auth_status 真的返回 429', 429 in codes,
      '出现的状态码=%s' % sorted(set(codes)))
check('端点级：限额内仍是 200（没有误伤）', 200 in codes)


# ─────────────────────────────────────────────────────────────
sec('SEC-5  认证方式标记不再出现在响应里')

# 只看代码不看注释：解释「为什么移除 lan-bypass」的注释里本来就有这个串，
# 直接 grep 全文会把注释当成残留。
def strip_py_comments(src):
    out = []
    for line in src.split('\n'):
        # 粗略但对本文件够用：不在字符串里的 # 之后都是注释
        buf, in_s, in_d = [], False, False
        i = 0
        while i < len(line):
            c = line[i]
            if c == '"' and not in_d:
                in_s = not in_s
            elif c == "'" and not in_s:
                in_d = not in_d
            elif c == '#' and not in_s and not in_d:
                break
            buf.append(c)
            i += 1
        out.append(''.join(buf))
    return '\n'.join(out)


def strip_js_comments(src):
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    src = re.sub(r'(?m)^\s*//.*$', '', src)
    return src


st = strip_py_comments(inspect.getsource(gw.auth_status))
check('auth_status 代码里不再出现 lan-bypass', 'lan-bypass' not in st,
      st[st.find('lan-bypass') - 40:st.find('lan-bypass') + 20]
      if 'lan-bypass' in st else '')
check('内网豁免分支仍能正常放行', '"authenticated": True' in st)

# 前端不得再依赖 via
import re
for fn in ('login.js', 'portal.js'):
    p = os.path.join(BACKEND, 'static', fn)
    txt = strip_js_comments(open(p).read())
    check(f'{fn} 代码里不再引用 lan-bypass', 'lan-bypass' not in txt)
portal_raw = open(os.path.join(BACKEND, 'static', 'portal.js')).read()
portal = strip_js_comments(portal_raw)
# 光断言「expires_in 出现过」太弱 —— 它在分支体里也出现，
# 变异把条件从 expires_in 换回 d.via 时这条照样绿。必须盯住判别式本身。
cond = re.findall(r'if\s*\(([^)]*expires_in[^)]*)\)', portal)
cond += re.findall(r'if\s*\(([^)]*\.via[^)]*)\)', portal)
check('portal 的判别式条件用了 expires_in',
      any('expires_in' in c for c in cond), str(cond))
check('portal 的判别式条件不再用 d.via',
      not any('.via' in c for c in cond), str(cond))
check('portal 全文没有 d.via 引用', '.via' not in portal)

# 响应体实测
gw.load_gateway_config = lambda: {'auth_lan_bypass': True, 'lan_subnet4': '192.168.100.0/24'}
gw.request = _Req()
gw.request.cookies = {}
with gw.app.test_request_context():
    resp = gw.auth_status()
body = resp.get_json()
check('内网豁免响应里没有 via 字段', 'via' not in body, str(body.keys()))
check('内网豁免仍返回 authenticated=true', body.get('authenticated') is True)
check('内网豁免不返回 expires_in（门户据此显示免认证文案）',
      'expires_in' not in body)


# ─────────────────────────────────────────────────────────────
sec('SEC-6  路由绑定不能挂到辅助函数上')

# 这一类 bug 已经踩了两次：
#   1) /auth/status    —— @app.route 挂到了 _status_rate_ok 上（今天新引入又修掉）
#   2) /api/rules/health —— @app.route 挂到了 _ruleset_is_functional 上
#      （2026-09-14 引入，一直 500，因为前端从来不调它，没人发现）
# 两次都是同一个形态：装饰器挂错函数，Flask 拿到裸 bool / 非法元组当响应。
#
# 本项目里 Flask 视图一律是不带下划线的公开函数（下划线是模块内辅助函数的
# 约定），所以「路由绑到下划线函数上」可以直接判定为 bug。

app3 = fresh()
app3.app.config['TESTING'] = True
misbound = []
for _r in app3.app.url_map.iter_rules():
    _fn = app3.app.view_functions.get(_r.endpoint)
    if _fn is not None and _fn.__name__.startswith('_'):
        misbound.append((str(_r), _fn.__name__))
check('没有路由绑到下划线开头的辅助函数上', not misbound,
      '; '.join('%s -> %s' % x for x in misbound))

_h = app3.app.view_functions.get('rules_health')
check('/api/rules/health 绑定的是 rules_health',
      _h is not None and _h.__name__ == 'rules_health',
      getattr(_h, '__name__', None))

# 真打一次：这个接口坏了近一个月，必须真的能返回 JSON
app3.app.before_request_funcs[None] = []
# rules_health 函数体里还有一道 _is_authenticated() 校验，
# 光摘 before_request 钩子不够，这里一并打桩。
app3._is_authenticated = lambda: True
app3._ruleset_is_empty = lambda: False
_c3 = app3.app.test_client()
_r3 = _c3.get('/api/rules/health')
check('/api/rules/health 不再 500', _r3.status_code < 500, f'HTTP {_r3.status_code}')
try:
    _j3 = _r3.get_json() or {}
    check('/api/rules/health 返回健康字段',
          'ruleset_functional' in (_j3.get('data') or {}),
          str(list((_j3.get('data') or {}).keys()))[:80])
except Exception as _e:
    check('/api/rules/health 返回健康字段', False, str(_e)[:60])

# 辅助函数本身必须仍然是「返回元组」，不能被改成视图
app4 = fresh()
_fn4 = app4._ruleset_is_functional
_r4 = _fn4()
check('_ruleset_is_functional 仍是 (bool, str) 辅助函数，不是视图',
      isinstance(_r4, tuple) and isinstance(_r4[0], bool) and isinstance(_r4[1], str),
      str(type(_r4)))


# ─────────────────────────────────────────────────────────────
print('\n' + '═' * 52)
print(f'通过 {len(PASS)} / {len(PASS) + len(FAIL)}')
if FAIL:
    print('失败：')
    for f in FAIL:
        print('  - ' + f)
    sys.exit(1)
print('全部通过')
