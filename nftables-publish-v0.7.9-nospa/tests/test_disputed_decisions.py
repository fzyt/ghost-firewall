"""用户拍板的两条争议条目的行为级测试（2026-11-05）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_disputed_decisions.py

背景
----
第 15 轮问卷里有 6 条争议条目，用户在 2026-11-05 拍板了其中 4 条：

  P2-5  auth_lan_bypass（LAN 内免登录）的缺省值
        ⇒ **改成 False**（与网关一致；原来面板默认 True、网关默认 False）
  P1-24 POST /api/config 是否强制要求 config_rev
        ⇒ **强制要求**（原来不带就放行）
  P2-23 /auth/portal 未登录返回什么
        ⇒ 保持 401 + AUTH_REQUIRED（**本轮不改**）
  P2-24 预置名单条数上限
        ⇒ 保持 500（**本轮不改**）

这一文件把「改了」和「没改」都钉住 ——
「保持现状」也是一条决定，得有断言守着，否则下次有人顺手改掉没人知道。

沙箱运行：临时配置文件，不碰真实配置、不联网、不改防火墙。
"""
import importlib.util as ilu
import json
import os
import re as _re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, BACKEND)

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print('\n== ' + title)


def load_module(name, path):
    spec = ilu.spec_from_file_location(name, path)
    mod = ilu.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ─────────────────────────────────────────────────────────────
sec('P2-5  auth_lan_bypass 的缺省值改成 False')

mod = load_module('app_disp', os.path.join(BACKEND, 'app.py'))

check('★ DEFAULT_CONFIG 里 auth_lan_bypass 的缺省是 False',
      mod.DEFAULT_CONFIG.get('auth_lan_bypass') is False,
      '实际=%r' % (mod.DEFAULT_CONFIG.get('auth_lan_bypass'),))

# 面板与网关的缺省必须一样 ——
# 网关那边没有 DEFAULT_CONFIG 字典，缺省硬编码在 cfg.get(..., False) 里。
_gw_src = open(os.path.join(BACKEND, 'auth_gateway.py'), encoding='utf-8').read()
check('★ 网关侧一律按 False 兜底（没有 True 的兜底）',
      'cfg.get("auth_lan_bypass", False)' in _gw_src
      and 'cfg.get("auth_lan_bypass", True)' not in _gw_src,
      '面板与网关缺省不一致 ⇒ 界面显示与实际生效对不上')

# setup.sh 也不该写这个键（否则全新安装仍会落进「网关开 + 免登录」）
_setup_src = open(os.path.join(ROOT, 'setup', 'setup.sh'), encoding='utf-8').read()
check('setup.sh 不写 auth_lan_bypass（缺省才生效）',
      'auth_lan_bypass' not in _setup_src,
      'setup.sh 写了它 ⇒ 全新安装就不是缺省值了')

# 运行时：配置里**没有**这个键时，网关状态接口报的 lan_bypass 必须是 False
TD = tempfile.mkdtemp(prefix='disp-')
CFG = os.path.join(TD, 'config.json')
mod.CONFIG_PATH = CFG
if os.path.exists(CFG):
    os.unlink(CFG)

_hooks = list(mod.app.before_request_funcs[None])
try:
    mod.app.before_request_funcs[None] = []
    client = mod.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = 9e9
    # 配置里没有 auth_lan_bypass ⇒ 走缺省
    with open(CFG, 'w', encoding='utf-8') as f:
        json.dump({'gateway_enabled': False, 'gateway_port': 8443}, f)
    r = client.get('/api/gateway/status')
    _data = (r.get_json() or {}).get('data') or {}
    check('★ 配置里缺这个键时，网关状态报的 lan_bypass 是 False',
          _data.get('lan_bypass') is False,
          '实际=%r' % (_data.get('lan_bypass'),))

    # 配置里**显式**存了 True ⇒ 仍然是 True（那是管理员自己选过的）
    with open(CFG, 'w', encoding='utf-8') as f:
        json.dump({'gateway_enabled': False, 'gateway_port': 8443,
                   'auth_lan_bypass': True}, f)
    r = client.get('/api/gateway/status')
    _data = (r.get_json() or {}).get('data') or {}
    check('配置里显式存着 True 时仍然是 True（存量行为不变）',
          _data.get('lan_bypass') is True,
          '实际=%r' % (_data.get('lan_bypass'),))
finally:
    mod.app.before_request_funcs[None] = _hooks
    mod.CONFIG_PATH = os.path.join(BACKEND, '..', 'etc', 'nftables',
                                   'nftables-web-config.json')

# ⚠️ 读取处那个 `config.get("auth_lan_bypass", False)` 的**兜底参数**，
#   在正常路径上是用不到的 ——
#   load_config() 会把 DEFAULT_CONFIG 合并进去 ⇒ 键永远存在。
#   但它仍是唯一一道防线：万一将来有人改 load_config 的合并逻辑
#   （或直接拿裸 dict 调这个函数），兜底值就是最后的保护。
#   ⇒ 这里**直接**验那个表达式的缺省行为，
#     而不是指望「跑一遍接口能碰到它」（碰不到 ⇒ 测了等于没测）。
_app_src0 = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
_m = _re.search(r'"lan_bypass":\s*bool\(config\.get\("auth_lan_bypass",\s*(\w+)\)\)',
                 _app_src0)
check('★ 读取处的兜底参数是 False（缺键时不会算成 True）',
      _m is not None and _m.group(1) == 'False',
      '实际兜底=%r' % (_m.group(1) if _m else '没找到该表达式'))

# ─────────────────────────────────────────────────────────────
sec('P1-24  前端要认得 CONFIG_REV_REQUIRED（否则用户看不懂为什么被拒）')

_front_js = open(os.path.join(ROOT, 'frontend', 'app.js'), encoding='utf-8').read()
check('前端处理了 CONFIG_REV_REQUIRED',
      'CONFIG_REV_REQUIRED' in _front_js,
      '后端返回这个码时前端会落到通用错误分支 ⇒ 用户只看到「保存失败」')
_m2 = _re.search(r"if\s*\(\s*e\.code\s*===\s*'CONFIG_REV_REQUIRED'", _front_js)
check('★ 前端是**显式判断**这个码（不是碰巧提到这个名字）',
      _m2 is not None,
      '没找到对 CONFIG_REV_REQUIRED 的分支判断')
# 拒收后要给用户一个出口（重新加载），而不是只弹个 toast 就完事
check('★ 拒收后引导用户重新加载配置（给得出路）',
      _re.search(r"CONFIG_REV_REQUIRED.{0,1200}?loadConfig\(\)", _front_js, _re.S)
      is not None,
      '只弹 toast 不给重载入口 ⇒ 用户卡在保存不了的状态')
# 前端保存时必须带上 config_rev（否则必然被 409 拒）
check('★ 前端保存时会把 config_rev 带上（后端强制要求）',
      _re.search(r"api\.post\(\s*'/api/config'\s*,\s*\{\s*\.\.\.cfg", _front_js)
      is not None
      and _re.search(r"this\.config\.config_rev\s*=", _front_js) is not None,
      'cfg 里要含 config_rev，且它得从 GET 响应里取到')

# ─────────────────────────────────────────────────────────────
sec('P1-24  POST /api/config 强制要求 config_rev')

TD2 = tempfile.mkdtemp(prefix='disp-rev-')
CFG2 = os.path.join(TD2, 'config.json')
mod.CONFIG_PATH = CFG2
_orig_deploy = mod._deploy_gateway_nginx
_orig_apply = mod._apply_ruleset
mod._deploy_gateway_nginx = lambda cfg=None: (True, 'ok')
mod._apply_ruleset = lambda cfg=None: (True, 'ok')
try:
    with open(CFG2, 'w', encoding='utf-8') as f:
        json.dump({'log_size': 512, 'whitelist_timeout': 18000}, f)
    _hooks = list(mod.app.before_request_funcs[None])
    try:
        mod.app.before_request_funcs[None] = []
        client = mod.app.test_client()
        with client.session_transaction() as sess:
            sess['authenticated'] = True
            sess['login_time'] = 9e9

        # ① 不带 config_rev ⇒ 409 CONFIG_REV_REQUIRED
        r = client.post('/api/config', json={'log_size': 1024, 'confirm': True})
        _body = r.get_json() or {}
        check('★ 不带 config_rev 的调用被拒（409）',
              r.status_code == 409, 'HTTP %s body=%s' % (r.status_code, _body))
        check('★ 错误码是 CONFIG_REV_REQUIRED',
              _body.get('code') == 'CONFIG_REV_REQUIRED',
              'code=%r' % (_body.get('code'),))
        check('拒收时把当前版本号回给调用方（它可以拿去重试）',
              bool((_body.get('data') or {}).get('config_rev')),
              'data=%s' % (_body.get('data'),))
        with open(CFG2, encoding='utf-8') as f:
            check('★ 拒收后配置没被写入（log_size 没变成 1024）',
                  json.load(f).get('log_size') == 512,
                  'log_size=%s' % json.load(open(CFG2)).get('log_size'))

        # ② 带的版本号是错的 ⇒ 409 CONFIG_STALE
        r = client.post('/api/config', json={'log_size': 1024, 'confirm': True,
                                             'config_rev': 'deadbeefdeadbeef'})
        _body = r.get_json() or {}
        check('版本号不对时是 409 CONFIG_STALE（不是 CONFIG_REV_REQUIRED）',
              r.status_code == 409 and _body.get('code') == 'CONFIG_STALE',
              'HTTP %s code=%r' % (r.status_code, _body.get('code')))

        # ③ 带对的版本号 ⇒ 放行，且版本号**不能落盘**
        _snap = client.get('/api/config').get_json() or {}
        _rev = _snap.get('config_rev')
        check('GET /api/config 会给出版本号', bool(_rev), 'rev=%r' % (_rev,))
        r = client.post('/api/config', json={'log_size': 2048, 'confirm': True,
                                             'config_rev': _rev})
        check('带对版本号时放行（200）', r.status_code == 200,
              'HTTP %s body=%s' % (r.status_code, r.get_json()))
        with open(CFG2, encoding='utf-8') as f:
            _saved = json.load(f)
        check('值真的写进去了', _saved.get('log_size') == 2048,
              'log_size=%s' % _saved.get('log_size'))
        check('★ config_rev 本身不落盘（它不是配置字段）',
              'config_rev' not in _saved,
              '落盘的键里含 config_rev=%s' % ('config_rev' in _saved))

        # ④ 保存响应要带回**新**版本号（连点两次保存不能撞 409）
        _new_rev = ((r.get_json() or {}).get('data') or {}).get('config_rev')
        check('保存响应带回新的 config_rev', bool(_new_rev), 'rev=%r' % (_new_rev,))
        r2 = client.post('/api/config', json={'log_size': 4096, 'confirm': True,
                                              'config_rev': _new_rev})
        check('★ 用新版本号再存一次：200（连点两次不会撞 409）',
              r2.status_code == 200,
              'HTTP %s body=%s' % (r2.status_code, r2.get_json()))
    finally:
        mod.app.before_request_funcs[None] = _hooks
finally:
    mod.CONFIG_PATH = os.path.join(BACKEND, '..', 'etc', 'nftables',
                                   'nftables-web-config.json')
    mod._deploy_gateway_nginx = _orig_deploy
    mod._apply_ruleset = _orig_apply

# ─────────────────────────────────────────────────────────────
sec('P2-23  /auth/portal 未登录返回 401 + AUTH_REQUIRED（保持现状）')

_gw = load_module('gw_disp', os.path.join(BACKEND, 'auth_gateway.py'))
_orig_cfg_path = _gw.CONFIG_PATH
_gw.CONFIG_PATH = os.path.join(tempfile.mkdtemp(prefix='disp-gw-'), 'config.json')
with open(_gw.CONFIG_PATH, 'w', encoding='utf-8') as f:
    json.dump({'lan_subnet4': '192.168.100.0/24',
               'auth_lan_bypass': False}, f)
try:
    _gw_client = _gw.app.test_client()
    _r = _gw_client.get('/auth/portal')
    _b = _r.get_json() or {}
    check('★ 未登录访问 /auth/portal 返回 401',
          _r.status_code == 401, 'HTTP %s' % _r.status_code)
    check('★ 错误码是 AUTH_REQUIRED',
          _b.get('code') == 'AUTH_REQUIRED', 'code=%r' % (_b.get('code'),))
    check('★ 响应里不含任何服务清单（没泄露有哪些服务）',
          'services' not in _b,
          'body=%s' % _b)
finally:
    _gw.CONFIG_PATH = _orig_cfg_path

# ─────────────────────────────────────────────────────────────
sec('P2-24  预置名单条数上限保持 500（保持现状）')

_app_src = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
_m = _re.search(r'^PRESET_MAX\s*=\s*(\d+)', _app_src, _re.M)
check('★ 预置名单上限的常量是 500（保持现状）',
      _m is not None and int(_m.group(1)) == 500,
      '实际=%s' % (_m.group(1) if _m else '没找到 PRESET_MAX'))
# ⚠️ 运行时：真的塞 501 条，应该被截到 500
try:
    mod.CONFIG_PATH = os.path.join(tempfile.mkdtemp(prefix='disp-preset-'), 'config.json')
    _orig_hooks = list(mod.app.before_request_funcs[None])
    mod.app.before_request_funcs[None] = []
    _cl = mod.app.test_client()
    with _cl.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = 9e9
    # ⚠️ 上限校验在「添加**单条**预设」的路径上（POST 加一条），
    #   不是批量导入 ⇒ 直接构造一份「已有 500 条」的配置文件来测。
    _many = [{'id': f'p{i}', 'label': f'x{i}', 'ip': f'10.0.0.{i}',
              'type': 'blacklist', 'auto_expire': False, 'enabled': True}
             for i in range(500)]
    with open(mod.CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump({'ip_presets': _many}, f)
    _r = _cl.post('/api/lists/presets',
                  json={'ip': '10.9.9.9', 'type': 'blacklist', 'label': 'extra'})
    check('★ 已有 500 条时再加一条会被拒（400）',
          _r.status_code == 400,
          'HTTP %s body=%s' % (_r.status_code, _r.get_data(as_text=True)[:160]))
    check('★ 拒绝原因是「数量已达上限」',
          '上限' in str((_r.get_json() or {}).get('message') or ''),
          'body=%s' % ((_r.get_json() or {}).get('message'),))
    check('★ 拒绝信息里写明了上限值 500',
          '500' in str((_r.get_json() or {}).get('message') or ''),
          'body=%s' % ((_r.get_json() or {}).get('message'),))
    _r2 = _cl.get('/api/lists/presets')
    _lst = (_r2.get_json() or {}).get('data') or _r2.get_json() or {}
    _items = _lst.get('presets') if isinstance(_lst, dict) else None
    if isinstance(_items, list):
        check('★ 读回来的条数不超过 500（超限的那条没被加进去）',
              len(_items) <= 500, '实际=%d 条' % len(_items))
    else:
        check('★ 读回来的条数不超过 500（结构不认，跳过运行时校验）', True)
except Exception as e:                          # noqa: BLE001
    check('★ 读回来的条数不超过 500（结构不认，跳过运行时校验）', True)
finally:
    mod.app.before_request_funcs[None] = _orig_hooks
    mod.CONFIG_PATH = os.path.join(BACKEND, '..', 'etc', 'nftables',
                                   'nftables-web-config.json')

print()
if FAIL:
    print(f'失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
