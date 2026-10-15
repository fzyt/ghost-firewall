"""面板来源访问边界 + 绑定 LAN 地址的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_panel_binding.py

背景（.224 真机实测，2026-10-15）：
  清空 nft 规则集后，从 WAN 侧客户端实测本机 7 个 LISTEN 端口 ——
  22 / 53 / 80 / 443 / 5443 / 8443 全部 OPEN，只有绑在 127.0.0.1 的
  8444 保持 REFUSED。防火墙正常时 7 个全部超时。
  也就是说「面板只在 LAN 可达」这件事当时 100% 由防火墙保证，服务本身
  绑的是 0.0.0.0。防火墙一失效，root 权限的管理面板就直接对着公网。

两道防线：
  BIND-1  HTTPS 绑到 lan_if 的实时 IPv4，而不是 0.0.0.0（网络层，第一道）
  BIND-2  panel_allowed_nets 来源网段（应用层，第二道，防火墙没了也还在）

  BIND-2 绝不能写进 nftables —— 那会跟着规则集一起消失，等于没做。

沙箱运行：CONFIG_PATH 指向临时文件，子进程探测用桩，不碰真实路径。
"""
import importlib.util as ilu
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
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


APP_SRC = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()


def load_app():
    spec = ilu.spec_from_file_location('_nftapp_bind', os.path.join(BACKEND, 'app.py'))
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mod = load_app()
app = mod.app
# 刻意**不清** before_request_funcs：要测的就是 _require_auth 这道钩子。
# 白名单判定在认证之前，所以被拒的请求是 403，放行到认证的请求是 401。

TD = tempfile.mkdtemp()
CFG = os.path.join(TD, 'config.json')
BACKUP_CFG = os.path.join(TD, 'config.json.bak')


def write_cfg(**kw):
    cfg = dict(mod.DEFAULT_CONFIG)
    cfg.update(kw)
    cfg['lan_subnet4'] = kw.get('lan_subnet4', '192.168.100.0/24')
    with open(CFG, 'w') as f:
        json.dump(cfg, f)
    mod.CONFIG_PATH = CFG
    mod._NETS_CACHE.update(mtime=None, nets=None)
    return cfg


def client():
    return app.test_client()


def get(ip, path='/api/config', **kw):
    return client().get(path, environ_base={'REMOTE_ADDR': ip}, **kw)


# ══════════════════════════════════════════════════════════════════
sec('BIND-2.1 网段解析与判定')
# ══════════════════════════════════════════════════════════════════
nets = mod._parse_net_list('192.168.100.0/24')
check('CIDR 字符串能解析成网络', len(nets) == 1 and str(nets[0]) == '192.168.100.0/24',
      str([str(n) for n in nets]))

nets = mod._parse_net_list(['192.168.100.0/24', '10.8.0.5'])
check('列表形式（含单个 IP）能解析', len(nets) == 2, str([str(n) for n in nets]))

nets = mod._parse_net_list('192.168.100.0/24，10.0.0.0/8')
check('中文逗号分隔能解析', len(nets) == 2, str([str(n) for n in nets]))

nets = mod._parse_net_list(None) + mod._parse_net_list([]) + mod._parse_net_list('')
check('空值解析为空列表（=不限制）', nets == [])

check('网段内 IP 判定为真', mod._ip_in_nets('192.168.100.66', mod._parse_net_list('192.168.100.0/24')))
check('网段外 IP 判定为假', not mod._ip_in_nets('203.0.113.9', mod._parse_net_list('192.168.100.0/24')))
check('非法 IP 一律判否（宁可多挡）',
      not mod._ip_in_nets('not-an-ip', mod._parse_net_list('192.168.100.0/24')))
check('IPv6 来源对 IPv4 白名单判否（v6 另有分支，这里不能漏判成真）',
      not mod._ip_in_nets('::1', mod._parse_net_list('192.168.100.0/24')))
check('单个 IP 按 /32 处理',
      mod._ip_in_nets('10.8.0.5', mod._parse_net_list('10.8.0.5'))
      and not mod._ip_in_nets('10.8.0.6', mod._parse_net_list('10.8.0.5')))


# ══════════════════════════════════════════════════════════════════
sec('BIND-2.2 来源边界真的拦住请求')
# ══════════════════════════════════════════════════════════════════
write_cfg()   # 没写 panel_allowed_nets → 默认跟随 lan_subnet4 = 192.168.100.0/24
check('未显式配置时回落 lan_subnet4',
      [str(n) for n in mod._panel_allowed_networks()] == ['192.168.100.0/24'],
      str([str(n) for n in mod._panel_allowed_networks()]))

r = get('203.0.113.9')                     # 公网来源
check('公网来源被拒（非白名单网段）', r.status_code == 403,
      f'HTTP {r.status_code} {(r.get_data(as_text=True) or "")[:90]}')
check('拒绝码是 IP_NOT_ALLOWED',
      'IP_NOT_ALLOWED' in (r.get_data(as_text=True) or ''))

r = get('192.168.100.66')                  # LAN 来源
check('LAN 来源过边界、卡在认证（401 而非 403）', r.status_code == 401,
      f'HTTP {r.status_code}')

write_cfg(panel_allowed_nets=['10.8.0.0/24', '192.168.100.5'])
check('显式配置优先于 lan_subnet4',
      sorted(str(n) for n in mod._panel_allowed_networks()) == ['10.8.0.0/24', '192.168.100.5/32'],
      str([str(n) for n in mod._panel_allowed_networks()]))
r = get('192.168.100.66')
check('显式配置里没有的网段照拦', r.status_code == 403, f'HTTP {r.status_code}')
r = get('10.8.0.77')
check('显式配置里的网段放行（401 = 过边界）', r.status_code == 401, f'HTTP {r.status_code}')


# ══════════════════════════════════════════════════════════════════
sec('BIND-2.3 配置缺失时不能把管理员锁在外面')
# ══════════════════════════════════════════════════════════════════
# DEFAULT_CONFIG 的 lan_subnet4 是 192.168.4.0/24 —— 别人的网段。
# 真拿它去判定，在 192.168.100.x 的机器上会把人锁死。
os.unlink(CFG) if os.path.exists(CFG) else None
mod.CONFIG_PATH = CFG
mod._NETS_CACHE.update(mtime=None, nets=None)
got = mod._panel_allowed_networks()
check('配置文件不存在时不限制（返回空）', got == [], str(got))

r = get('203.0.113.9')
check('配置缺失时公网来源也不被这道边界拦（不制造假防护）', r.status_code == 401,
      f'HTTP {r.status_code}')

with open(CFG, 'w') as f:
    f.write('{ 这不是 JSON')
mod.CONFIG_PATH = CFG
mod._NETS_CACHE.update(mtime=None, nets=None)
got = mod._panel_allowed_networks()
check('配置损坏时不限制而不是拿 DEFAULT 里的陌生网段', got == [], str(got))
r = get('203.0.113.9')
check('配置损坏时不会把自己锁在外面（401 = 过边界）', r.status_code == 401,
      f'HTTP {r.status_code}')


# ══════════════════════════════════════════════════════════════════
sec('BIND-2.4 配置校验')
# ══════════════════════════════════════════════════════════════════
def verrs(**kw):
    c = dict(mod.DEFAULT_CONFIG)
    c.update(kw)
    c.pop('forward_rules', None)
    return [e for e in mod.validate_config(c) if 'panel_allowed_nets' in e]

check('合法 CIDR 无报错', verrs(panel_allowed_nets=['192.168.100.0/24']) == [],
      str(verrs(panel_allowed_nets=['192.168.100.0/24'])))
check('合法单个 IP 无报错', verrs(panel_allowed_nets=['192.168.100.5']) == [])
check('非 IP 字符串被拦',
      len(verrs(panel_allowed_nets=['随便写点什么'])) == 1,
      str(verrs(panel_allowed_nets=['随便写点什么'])))
check('/0 被拦（等于不设边界）', len(verrs(panel_allowed_nets=['0.0.0.0/0'])) == 1,
      str(verrs(panel_allowed_nets=['0.0.0.0/0'])))
check('/1 被拦（等于不设边界）', len(verrs(panel_allowed_nets=['0.0.0.0/1'])) == 1,
      str(verrs(panel_allowed_nets=['0.0.0.0/1'])))
check('/2 放行（最小可用边界）', verrs(panel_allowed_nets=['0.0.0.0/2']) == [])


# ══════════════════════════════════════════════════════════════════
sec('BIND-2.5 防自锁告警')
# ══════════════════════════════════════════════════════════════════
def risks(requester, old, new):
    return mod._detect_risks(old, new, requester)


# 上一节把 CONFIG_PATH 留在一个损坏文件上（_config_corrupted 为真）。
# 本节要验的是正常配置下的自锁告警，先把配置修好。
write_cfg()
mod.load_config()
check('本节前置：配置恢复正常', not mod._config_corrupted()[0])


old_c = {'lan_subnet4': '192.168.100.0/24', 'access_mode': 'lan', 'lan_allowed_ports': [22, 5443]}
new_c = dict(old_c, panel_allowed_nets=['10.0.0.0/8'])
rs = risks('192.168.100.66', old_c, new_c)
crit = [r for r in rs if r.get('level') == 'critical']
check('把访问边界改成不含自己的网段 → critical 告警', len(crit) == 1,
      crit[0]['message'][:70] if crit else str(rs))

rs = risks('10.1.1.1', old_c, new_c)
crit = [r for r in rs if r.get('level') == 'critical']
check('新边界仍含自己 → 不报 critical', len(crit) == 0, str(rs))

rs = risks('192.168.100.66', old_c, dict(old_c, panel_allowed_nets=['192.168.100.0/24']))
crit = [r for r in rs if r.get('level') == 'critical']
check('边界没实际收紧 → 不误报', len(crit) == 0, str(rs))


# ══════════════════════════════════════════════════════════════════
sec('BIND-1 绑定到 LAN 地址而不是 0.0.0.0')
# ══════════════════════════════════════════════════════════════════
class _Sentinel(Exception):
    """捕获到 make_server 调用后抛出，避免真的起服务。"""


def run_start(bind_addr):
    """真正跑一遍 _start_servers()，返回 (make_server 收到的 host, 抛出的异常)。

    桩掉证书/恢复/看门狗，只保留「探测地址 → 绑定」这一段的真实执行。
    只做源码正则是抓不住的：把 _bind 赋成 '0.0.0.0' 之后，源码里照样
    不会出现 make_server('0.0.0.0') 这个字面量，正则断言会假绿。
    """
    import werkzeug.serving as _ws
    seen = {}

    def fake_make_server(host, port, application, **kw):
        seen['host'] = host
        raise _Sentinel()

    orig = (mod._auto_recover_ruleset_if_empty, mod._start_watchdog,
            mod._ensure_https_cert, mod._build_ssl_context,
            mod._lan_bind_address, _ws.make_server, os.environ.get)
    mod._auto_recover_ruleset_if_empty = lambda: None
    mod._start_watchdog = lambda: None
    mod._ensure_https_cert = lambda: ['/tmp/fake.pem']
    mod._build_ssl_context = lambda cf: object()
    mod._lan_bind_address = lambda *a, **k: bind_addr
    _ws.make_server = fake_make_server
    os.environ.pop('NFTABLES_WEB_BIND', None)
    try:
        mod._start_servers()
        exc = None
    except _Sentinel:
        exc = 'sentinel'
    except SystemExit as e:
        exc = 'SystemExit:%s' % e.code
    finally:
        (mod._auto_recover_ruleset_if_empty, mod._start_watchdog,
         mod._ensure_https_cert, mod._build_ssl_context,
         mod._lan_bind_address, _ws.make_server, _) = orig
        os.environ.pop('NFTABLES_WEB_BIND', None)
    return seen.get('host'), exc


host, exc = run_start('192.168.100.224')
check('探测到 LAN 地址时真的绑到它（行为验证）',
      host == '192.168.100.224', f'make_server host={host!r} exc={exc}')

host, exc = run_start('')
check('探测不到 LAN 地址时拒绝启动，不回落 0.0.0.0（行为验证）',
      host is None and exc == 'SystemExit:1',
      f'host={host!r} exc={exc}')

# 逃生口：必须是显式环境变量才允许 0.0.0.0
import werkzeug.serving as _ws2
seen = {}
_orig_ms = _ws2.make_server
_ws2.make_server = lambda h, p, a, **k: (seen.__setitem__('host', h), (_ for _ in ()).throw(_Sentinel()))[1]
_orig3 = (mod._auto_recover_ruleset_if_empty, mod._start_watchdog,
          mod._ensure_https_cert, mod._build_ssl_context, mod._lan_bind_address)
mod._auto_recover_ruleset_if_empty = lambda: None
mod._start_watchdog = lambda: None
mod._ensure_https_cert = lambda: ['/tmp/fake.pem']
mod._build_ssl_context = lambda cf: object()
mod._lan_bind_address = lambda *a, **k: ''
os.environ['NFTABLES_WEB_BIND'] = '0.0.0.0'
try:
    try:
        mod._start_servers()
        exc = None
    except _Sentinel:
        exc = 'sentinel'
    except SystemExit as e:
        exc = 'SystemExit:%s' % e.code
finally:
    os.environ.pop('NFTABLES_WEB_BIND', None)
    _ws2.make_server = _orig_ms
    (mod._auto_recover_ruleset_if_empty, mod._start_watchdog,
     mod._ensure_https_cert, mod._build_ssl_context, mod._lan_bind_address) = _orig3
check('显式逃生口 NFTABLES_WEB_BIND=0.0.0.0 可用（有日志的显式降级）',
      seen.get('host') == '0.0.0.0', f'host={seen.get("host")!r} exc={exc}')

check('存在 _lan_bind_address 探测函数', 'def _lan_bind_address(' in APP_SRC)

# 探测函数的行为（打桩 subprocess）
import subprocess as _sp
_orig_run = _sp.run


def fake_run(argv, *a, **kw):
    if argv[:2] == ['ip', '-4'] and 'br-lan' in argv:
        class R:
            returncode = 0
            stdout = ('    inet 192.168.100.224/24 br-lan scope global br-lan\\n'
                      '       valid_lft forever preferred_lft forever')
            stderr = ''
        return R()
    return _orig_run(argv, *a, **kw)


_sp.run = fake_run
try:
    got = mod._lan_bind_address('br-lan', retries=1, wait=0)
    check('能探测到 br-lan 的 IPv4', got == '192.168.100.224', repr(got))

    def fake_fail(argv, *a, **kw):
        if argv[:2] == ['ip', '-4']:
            class R:
                returncode = 1
                stdout = ''
                stderr = 'Device "br-lan" does not exist.'
            return R()
        return _orig_run(argv, *a, **kw)

    _sp.run = fake_fail
    got = mod._lan_bind_address('br-lan', retries=2, wait=0)
    check('接口不存在时返回空串（交由调用方拒绝启动）', got == '', repr(got))

    _sp.run = fake_run
finally:
    _sp.run = _orig_run


print(f'\n{"=" * 60}')
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    for f in FAIL:
        print('  ❌ ' + f)
    sys.exit(1)
print('全部通过')
