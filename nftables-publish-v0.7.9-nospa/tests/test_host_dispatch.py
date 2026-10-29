"""host 分发（按域名分发到不同服务）的回归测试。

运行:  python3 tests/test_host_dispatch.py

覆盖 2026-10-28 做的整条链路，每条都写成「老代码必然失败」的形式：

  HD-1  对外域名校验器 _sanitize_rp_host（纯主机名、不放通配）
  HD-2  反代目标主机校验器 _sanitize_domain **没有**被顺手放宽
  HD-3  规则校验接受 host、拒重复域名、拒非法域名
  HD-4  规则迁移白名单保住 host 字段
  HD-5  nginx 生成：host 入口多出一个 server 块，带 server_name
  HD-6  host 入口同样有 auth_request + 401 跳登录（**认证不打折**）
  HD-7  host 模式**不**生成 sub_filter / 路径前缀改写
  HD-8  路径前缀模式的既有行为一字未变（回归护栏）
  HD-9  每个 server 块都有登录端点（host 入口的登录页必须能打开）
  HD-10 落盘的脏 host 不会污染生成的 nginx 配置
  HD-11 base_domain 从默认证书 SAN 推导
  HD-12 cookie 共享域推导
  HD-13 cookie 的 Domain 属性：子域带、IP 不带、外域不带
  HD-14 门户接口返回 host 与带端口的绝对地址
  HD-15 门户页优先用服务端给的 url
  HD-16 前端表单有「访问域名」输入与自动生成

沙箱运行：不碰真实路径、不执行 openssl/nft/nginx（需要外部命令的分支打桩）。
"""
import importlib
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


def fresh():
    """独立加载一份 app 模块，避免模块级状态互相污染"""
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    app.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'cfg.json')
    app.LISTS_PATH = os.path.join(tempfile.mkdtemp(), 'lists.json')
    app.RULES_PATH = os.path.join(tempfile.mkdtemp(), 'rules.nft')
    return app


APP_SRC = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
AG_SRC = open(os.path.join(BACKEND, 'auth_gateway.py'), encoding='utf-8').read()
PORTALJS_SRC = open(os.path.join(BACKEND, 'static', 'portal.js'), encoding='utf-8').read()
APPJS_SRC = open(os.path.join(ROOT, 'frontend', 'app.js'), encoding='utf-8').read()
INDEX_SRC = open(os.path.join(ROOT, 'frontend', 'index.html'), encoding='utf-8').read()


def base_config(**over):
    """一份带网关 + 一条带 host 的规则的配置"""
    cfg = {
        'gateway_enabled': True,
        'gateway_port': 8443,
        'auth_api_port': 8444,
        'lan_subnet4': '192.168.100.0/24',
        'reverse_proxy': {
            'settings': {
                'default_cert_id': 'cert_001',
                'tls_min_version': 'TLSv1.2',
                'base_domain': 'fzyto.top',
                'cookie_domain': '.fzyto.top',
            },
            'certificates': [{
                'id': 'cert_001',
                'cert_path': '/etc/nginx/ssl/fzyto.top/fullchain.pem',
                'key_path': '/etc/nginx/ssl/fzyto.top/privkey.pem',
            }],
            'rules': [{
                'id': 'rp_001', 'name': '思源', 'enabled': True,
                'path_prefix': '/siy', 'host': 'siyuan.fzyto.top',
                'target_address': '192.168.100.218:6807', 'target_protocol': 'http',
                'public_access': True, 'client_max_body_size': '10M',
                'api_path_prefix': '', 'rewrite_root_paths': False,
                'websocket_enabled': True, 'icon': 'S',
            }],
        },
    }
    cfg['reverse_proxy'].update(over)
    return cfg


# ─────────────────────────────────────────────────────────────
sec('HD-1  对外域名校验器 _sanitize_rp_host')

app = fresh()
sh = app._sanitize_rp_host
check('正常多段域名原样返回', sh('siyuan.fzyto.top') == 'siyuan.fzyto.top')
check('大写归一化小写', sh('SiYuan.Fzyto.Top') == 'siyuan.fzyto.top')
check('前后空格被裁掉', sh('  siyuan.fzyto.top  ') == 'siyuan.fzyto.top')
check('结尾的点被去掉（FQDN 写法）', sh('siyuan.fzyto.top.') == 'siyuan.fzyto.top')
check('单段主机名允许', sh('router') == 'router')
check('空串 = 不开 host 分发', sh('') == '')
check('纯空白 = 不开 host 分发', sh('   ') == '')

for bad, why in (
    ('*.fzyto.top', '通配是证书概念，不是路由概念'),
    ('*', '裸星号'),
    ('http://siyuan.fzyto.top', '带 scheme'),
    ('siyuan.fzyto.top:8443', '带端口'),
    ('siyuan.fzyto.top/x', '带路径'),
    ('siyuan fzyto.top', '带空格'),
    ('siyuan.fzyto.top;return 200', '带分号（指令注入）'),
    ('siyuan.fzyto.top#x', '带井号'),
    ('siyuan..fzyto.top', '空标签'),
    ('-siyuan.fzyto.top', '标签以连字符开头'),
    ('siyuan-.fzyto.top', '标签以连字符结尾'),
    ('siyuan.fzyto.top\nX-Evil: 1', '带换行'),
    ('a' * 300 + '.top', '超长'),
):
    try:
        sh(bad)
        check(f'非法输入 {bad[:28]!r} 被拒', False, f'竟然通过了 —— {why}')
    except ValueError:
        check(f'非法输入 {bad[:28]!r} 被拒', True)

# ─────────────────────────────────────────────────────────────
sec('HD-2  反代目标主机校验器没有被放宽')

# _sanitize_domain 是 _sanitize_target_address 用的（proxy_pass 的目标主机）。
# 放行 * 等于允许把 *.evil.com 写进 proxy_pass —— nginx 解析时当字面主机名，
# 这是开一个注入面。host 分发用的是**另一套**校验器（_sanitize_rp_host），
# 两者绝不能混。
for bad in ('*.fzyto.top', '*', 'a*b.com'):
    try:
        app._sanitize_domain(bad)
        check(f'_sanitize_domain 仍拒 {bad!r}', False, '被放行了 —— 注入面开了')
    except ValueError:
        check(f'_sanitize_domain 仍拒 {bad!r}', True)
check('_sanitize_domain 仍接受正常域名',
      app._sanitize_domain('example.com') == 'example.com')

# ─────────────────────────────────────────────────────────────
sec('HD-3  规则校验接受 host、拒重复、拒非法')

clean, err = app._validate_rp_service({
    'name': '思源', 'path_prefix': '/siy', 'host': 'siyuan.fzyto.top',
    'target_address': '192.168.100.218:6807',
})
check('合法 host 被接受', err is None, str(err))
check('clean 里带上了 host', err is None and clean.get('host') == 'siyuan.fzyto.top')
check('host 大小写被归一', err is None and
      app._validate_rp_service({
          'name': 'x', 'path_prefix': '/x', 'host': 'SiYuan.Fzyto.Top',
          'target_address': '192.168.100.218:6807'})[0].get('host') == 'siyuan.fzyto.top')

clean2, err2 = app._validate_rp_service({
    'name': 'NAS', 'path_prefix': '/nas', 'host': '',
    'target_address': '192.168.100.10:5000',
})
check('空 host = 不开 host 分发（合法）', err2 is None and clean2.get('host') == '')

_, err3 = app._validate_rp_service({
    'name': '坏', 'path_prefix': '/bad', 'host': 'http://evil.com',
    'target_address': '192.168.100.10:5000',
})
check('带 scheme 的 host 被拒', err3 is not None, str(err3))

_, err4 = app._validate_rp_service({
    'name': '坏', 'path_prefix': '/bad', 'host': '*.fzyto.top',
    'target_address': '192.168.100.10:5000',
})
check('带通配的 host 被拒', err4 is not None, str(err4))

_, err5 = app._validate_rp_service({
    'name': '重复', 'path_prefix': '/dup', 'host': 'siyuan.fzyto.top',
    'target_address': '192.168.100.10:5000',
}, existing={}, all_rules=[{'id': 'rp_x', 'name': '思源', 'host': 'siyuan.fzyto.top'}])
check('与其它规则域名重复被拒', err5 is not None and '重复' in err5, str(err5))

# ─────────────────────────────────────────────────────────────
sec('HD-4  规则迁移白名单保住 host 字段')

cfg = {'reverse_proxy': {'rules': [{
    'id': 'rp_001', 'name': '思源', 'enabled': True, 'path_prefix': '/siy',
    'host': 'siyuan.fzyto.top', 'target_address': '192.168.100.218:6807',
    'target_protocol': 'http', 'public_access': True,
}]}}
app._migrate_rp_rules(cfg)
got = cfg['reverse_proxy']['rules'][0].get('host')
check('迁移后 host 还在', got == 'siyuan.fzyto.top', repr(got))

# 落盘的脏值不能让整个迁移崩掉
cfg2 = {'reverse_proxy': {'rules': [{
    'id': 'rp_002', 'name': '脏', 'enabled': True, 'path_prefix': '/dirty',
    'host': 'http://evil.com', 'target_address': '192.168.100.10:5000',
}]}}
try:
    app._migrate_rp_rules(cfg2)
    got2 = cfg2['reverse_proxy']['rules'][0].get('host')
    check('脏 host 被降级成空（而不是抛异常）', got2 == '', repr(got2))
except Exception as e:
    check('脏 host 被降级成空（而不是抛异常）', False, repr(e))

# ─────────────────────────────────────────────────────────────
sec('HD-5  nginx 生成：host 入口多出一个 server 块')

conf = app._generate_gateway_nginx_conf(base_config())
check('生成了配置', bool(conf))
check('出现 server_name siyuan.fzyto.top',
      'server_name siyuan.fzyto.top;' in conf)
check('server 块数量 = 2（默认块 + host 块）', conf.count('\nserver {') == 2,
      str(conf.count('\nserver {')))

blocks = conf.split('\nserver {')
host_block = ''
for b in blocks[1:]:
    if 'server_name siyuan.fzyto.top;' in b:
        host_block = b
check('找到 host 块', bool(host_block))

# ─────────────────────────────────────────────────────────────
sec('HD-6  host 入口同样有 auth_request + 401 跳登录（认证不打折）')

check('host 块有 auth_request /_auth', 'auth_request /_auth;' in host_block)
check('host 块有 401 跳登录', 'error_page 401 = @to_login;' in host_block)
check('host 块有 @to_login 命名位置', 'location @to_login {' in host_block)
check('host 块回跳带网关端口',
      'https://$host:8443/auth/login?next=$request_uri;' in host_block)
check('host 块带 auth_request_set（审计要拿到身份）',
      'auth_request_set $auth_user $upstream_http_x_auth_user;' in host_block)
check('host 块的 location 是根路径 /',
      re.search(r'\n\s*location / \{', host_block) is not None)

# ─────────────────────────────────────────────────────────────
sec('HD-7  host 模式不生成路径改写补丁')

check('host 块里没有 sub_filter', 'sub_filter' not in host_block)
check('host 块里没有 proxy_redirect 补前缀', 'proxy_redirect' not in host_block)
check('host 块里没有 sub_filter_types', 'sub_filter_types' not in host_block)
check('host 块保留了 WebSocket 透传',
      'proxy_set_header Upgrade $http_upgrade;' in host_block)

# ─────────────────────────────────────────────────────────────
sec('HD-8  路径前缀模式的既有行为一字未变')

default_block = blocks[1] if len(blocks) > 1 else ''
check('默认块里还有路径前缀 location',
      'location /siy/ {' in default_block)
check('默认块里没有 host 的 server_name',
      'server_name' not in default_block)

# 带 api_path_prefix 的规则仍要生成 sub_filter（窄模式）
cfg_p = base_config()
cfg_p['reverse_proxy']['rules'][0]['api_path_prefix'] = '/api/'
conf_p = app._generate_gateway_nginx_conf(cfg_p)
check('窄模式仍生成 sub_filter', 'sub_filter "' in conf_p)
check('窄模式仍生成 sub_filter_types', 'sub_filter_types' in conf_p)
check('窄模式仍生成 Location 补前缀', 'proxy_redirect' in conf_p)

# 宽模式
cfg_w = base_config()
cfg_w['reverse_proxy']['rules'][0]['rewrite_root_paths'] = True
conf_w = app._generate_gateway_nginx_conf(cfg_w)
check('宽模式仍生成 href/src/action 改写',
      'sub_filter "href=\\"/"' in conf_w and 'sub_filter "src=\\"/"' in conf_w)

# ─────────────────────────────────────────────────────────────
sec('HD-9  每个 server 块都有登录端点')

for i, b in enumerate(blocks[1:]):
    label = '默认块' if i == 0 else f'host 块{i}'
    check(f'{label} 有 /auth/login',
          'location = /auth/login {' in b)
    check(f'{label} 有 /auth/status', 'location = /auth/status {' in b)
    check(f'{label} 有 /auth/portal', 'location = /auth/portal {' in b)
    check(f'{label} 有认证子请求入口', 'location = /_auth {' in b)
    check(f'{label} 把内部认证端点挡住', 'location /auth/ {' in b)

# ─────────────────────────────────────────────────────────────
sec('HD-10 落盘的脏 host 不会污染生成的 nginx 配置')

cfg_dirty = base_config()
cfg_dirty['reverse_proxy']['rules'][0]['host'] = 'evil.com; return 200;'
conf_dirty = app._generate_gateway_nginx_conf(cfg_dirty)
check('脏 host 没有进 server_name',
      'server_name evil.com' not in conf_dirty)
check('脏 host 下整条服务仍在（路径入口不受影响）',
      'location /siy/ {' in conf_dirty)
check('没有多出可执行的 nginx 指令',
      'return 200;' not in conf_dirty)

# ─────────────────────────────────────────────────────────────
sec('HD-11 base_domain 从默认证书 SAN 推导')

app2 = fresh()
app2._get_cert_san = lambda p: ['*.fzyto.top', 'fzyto.top']
cfg_no_bd = {
    'reverse_proxy': {
        'settings': {'default_cert_id': 'cert_001'},
        'certificates': [{'id': 'cert_001', 'cert_path': '/x/fullchain.pem'}],
        'rules': [],
    },
}
check('通配 SAN → 基础域名 fzyto.top',
      app2._rp_base_domain(cfg_no_bd) == 'fzyto.top',
      app2._rp_base_domain(cfg_no_bd))

app2._get_cert_san = lambda p: ['fzyto.top', 'www.fzyto.top']
check('无通配但有多段 SAN → 取第一个',
      app2._rp_base_domain(cfg_no_bd) == 'fzyto.top')

app2._get_cert_san = lambda p: []
check('没有 SAN → 基础域名为空', app2._rp_base_domain(cfg_no_bd) == '')

# 显式设置优先于推导
cfg_expl = {'reverse_proxy': {
    'settings': {'default_cert_id': 'cert_001', 'base_domain': 'my.domain'},
    'certificates': [{'id': 'cert_001', 'cert_path': '/x/fullchain.pem'}],
    'rules': [],
}}
app2._get_cert_san = lambda p: ['*.fzyto.top']
check('显式 base_domain 优先于证书推导',
      app2._rp_base_domain(cfg_expl) == 'my.domain')

# 自动补齐（_rp_sync_base_domain）：只在没设过时补
cfg_sync = {'reverse_proxy': {
    'settings': {'default_cert_id': 'cert_001'},
    'certificates': [{'id': 'cert_001', 'cert_path': '/x/fullchain.pem'}],
    'rules': [],
}}
app2._get_cert_san = lambda p: ['*.fzyto.top', 'fzyto.top']
app2._rp_sync_base_domain(cfg_sync)
check('未设过时自动补出 base_domain',
      cfg_sync['reverse_proxy']['settings'].get('base_domain') == 'fzyto.top')
check('同时补出 cookie 共享域',
      cfg_sync['reverse_proxy']['settings'].get('cookie_domain') == '.fzyto.top')

# 用户手动清空后不该被自动改回来
cfg_keep = {'reverse_proxy': {
    'settings': {'default_cert_id': 'cert_001', 'base_domain': '', 'cookie_domain': ''},
    'certificates': [{'id': 'cert_001', 'cert_path': '/x/fullchain.pem'}],
    'rules': [],
}}
app2._rp_sync_base_domain(cfg_keep)
check('用户清空后不被自动改回',
      cfg_keep['reverse_proxy']['settings'].get('base_domain') == '')

# ⚠️ 落盘断言（真机踩过的坑）：认证服务是**另一个进程**，只读这份 JSON，
# 不会去解析证书。所以派生值必须**已经写进文件**——
# 只在面板内存里现算的话，接口返回看着正常，认证服务却读到空的，
# 结果是 cookie 不带 Domain → 跨子域每换一个域名就要重登一次，
# 而且面板上完全看不出来。
app4 = fresh()
app4._get_cert_san = lambda p: ['*.fzyto.top', 'fzyto.top']
app4.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'savecfg.json')
with open(app4.CONFIG_PATH, 'w', encoding='utf-8') as f:
    json.dump({'reverse_proxy': {
        'settings': {'default_cert_id': 'cert_001'},
        'certificates': [{'id': 'cert_001', 'cert_path': '/x/fullchain.pem'}],
        'rules': [],
    }}, f)
app4._save_rp_config(app4.load_config())
with open(app4.CONFIG_PATH, encoding='utf-8') as f:
    on_disk = json.load(f)
disk_settings = (on_disk.get('reverse_proxy') or {}).get('settings') or {}
check('落盘的配置里有 base_domain（认证服务靠它算共享域）',
      disk_settings.get('base_domain') == 'fzyto.top', repr(disk_settings))
check('落盘的配置里有 cookie_domain',
      disk_settings.get('cookie_domain') == '.fzyto.top', repr(disk_settings))

# ─────────────────────────────────────────────────────────────
sec('HD-12 cookie 共享域推导')

app3 = fresh()
app3._get_cert_san = lambda p: ['*.fzyto.top']
cfg_cd = {'reverse_proxy': {
    'settings': {'default_cert_id': 'cert_001', 'base_domain': 'fzyto.top'},
    'certificates': [{'id': 'cert_001', 'cert_path': '/x/fullchain.pem'}],
    'rules': [],
}}
check('cookie_domain 缺省 → . + base_domain',
      app3._rp_cookie_domain(cfg_cd) == '.fzyto.top')

cfg_cd2 = {'reverse_proxy': {
    'settings': {'default_cert_id': 'cert_001', 'base_domain': 'fzyto.top',
                 'cookie_domain': '.custom.top'},
    'certificates': [{'id': 'cert_001', 'cert_path': '/x/fullchain.pem'}],
    'rules': [],
}}
check('显式 cookie_domain 优先',
      app3._rp_cookie_domain(cfg_cd2) == '.custom.top')

cfg_cd3 = {'reverse_proxy': {'settings': {}, 'certificates': [], 'rules': []}}
check('什么都没配 → 空（cookie 按 host 各自存）',
      app3._rp_cookie_domain(cfg_cd3) == '')

# ─────────────────────────────────────────────────────────────
sec('HD-13 cookie 的 Domain 属性：子域带、IP 不带、外域不带')

sys.modules.pop('auth_gateway', None)
ag = importlib.import_module('auth_gateway')
ag.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'agcfg.json')
with open(ag.CONFIG_PATH, 'w', encoding='utf-8') as f:
    json.dump({'reverse_proxy': {'settings': {'cookie_domain': '.fzyto.top'}}}, f)

from flask import Response  # noqa: E402


def cookie_domain_for(host):
    with ag.app.test_request_context('/', headers={'Host': host}):
        return ag._effective_cookie_domain()


check('子域 → 带 Domain=.fzyto.top',
      cookie_domain_for('siyuan.fzyto.top:8443') == '.fzyto.top')
check('父域本身 → 带 Domain',
      cookie_domain_for('fzyto.top:8443') == '.fzyto.top')
check('更深一层子域 → 带 Domain',
      cookie_domain_for('a.b.fzyto.top') == '.fzyto.top')
check('IPv4 主机名 → 不带 Domain（浏览器会整条拒收）',
      cookie_domain_for('192.168.100.233:8443') == '',
      '带 Domain 的 cookie 会被浏览器整条丢弃，登录会静默失败')
check('IPv6 主机名 → 不带 Domain',
      cookie_domain_for('[::1]:8443') == '')
check('无关域名 → 不带 Domain',
      cookie_domain_for('other.example.com') == '')

# 响应级验证：Set-Cookie 头里确实带上了 Domain
with ag.app.test_request_context('/', headers={'Host': 'siyuan.fzyto.top:8443'}):
    resp = Response('ok')
    ag._set_cookies(resp, 'tok', 'dev')
    sc = resp.headers.get('Set-Cookie', '')
# Flask 会把前导点去掉（Set-Cookie 里写成 Domain=fzyto.top），
# 语义一样：浏览器按 RFC 6265 忽略前导点，父域 + 全部子域都会带上。
check('Set-Cookie 带 Domain=fzyto.top', 'Domain=fzyto.top' in sc, sc)

# 键不存在 → 从 base_domain 推导（与面板 app.py 的语义必须一致）
ag.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'agcfg_bd.json')
with open(ag.CONFIG_PATH, 'w', encoding='utf-8') as f:
    json.dump({'reverse_proxy': {'settings': {'base_domain': 'fzyto.top'}}}, f)
ag._config_cache['mtime'] = None
ag._config_cache['data'] = None
with ag.app.test_request_context('/', headers={'Host': 'siyuan.fzyto.top:8443'}):
    check('只给 base_domain 也能推出共享域（键不存在 → 推导）',
          ag._effective_cookie_domain() == '.fzyto.top',
          ag._effective_cookie_domain())

# 键存在但值为空 = 用户明确清空 → 不共享
ag.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'agcfg_cd.json')
with open(ag.CONFIG_PATH, 'w', encoding='utf-8') as f:
    json.dump({'reverse_proxy': {'settings': {
        'base_domain': 'fzyto.top', 'cookie_domain': ''}}}, f)
ag._config_cache['mtime'] = None
ag._config_cache['data'] = None
with ag.app.test_request_context('/', headers={'Host': 'siyuan.fzyto.top:8443'}):
    check('cookie_domain 键存在且为空 = 用户清空 → 不共享',
          ag._effective_cookie_domain() == '',
          ag._effective_cookie_domain())

# 落盘的脏 cookie_domain 不能进 Set-Cookie
ag.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'agcfg_dirty.json')
with open(ag.CONFIG_PATH, 'w', encoding='utf-8') as f:
    json.dump({'reverse_proxy': {'settings': {
        'cookie_domain': '.fzyto.top; Domain=evil.com'}}}, f)
ag._config_cache['mtime'] = None
ag._config_cache['data'] = None
with ag.app.test_request_context('/', headers={'Host': 'siyuan.fzyto.top:8443'}):
    check('脏 cookie_domain 被净化掉（不会拼进 Set-Cookie）',
          ag._effective_cookie_domain() == '',
          repr(ag._effective_cookie_domain()))


with ag.app.test_request_context('/', headers={'Host': '192.168.100.233:8443'}):
    resp = Response('ok')
    ag._set_cookies(resp, 'tok', 'dev')
    sc2 = resp.headers.get('Set-Cookie', '')
check('IP 访问时 Set-Cookie 不带 Domain', 'Domain=' not in sc2, sc2)

# ─────────────────────────────────────────────────────────────
sec('HD-14 门户接口返回 host 与带端口的绝对地址')

ag.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'agcfg2.json')
with open(ag.CONFIG_PATH, 'w', encoding='utf-8') as f:
    json.dump({
        'gateway_port': 8443,
        'reverse_proxy': {'rules': [{
            'id': 'rp_001', 'name': '思源', 'enabled': True,
            'path_prefix': '/siy', 'host': 'siyuan.fzyto.top',
            'public_access': True, 'icon': 'S',
        }]},
    }, f)

ag.load_gateway_config.cache_clear() if hasattr(ag.load_gateway_config, 'cache_clear') else None
ag._config_cache['mtime'] = None
ag._config_cache['data'] = None

# 直接调 auth_portal 需要已认证；这里打桩 _authenticated 与 is_lan_source
orig_auth = ag._authenticated
orig_lan = ag.is_lan_source
ag._authenticated = lambda: True
ag.is_lan_source = lambda cfg: True
try:
    with ag.app.test_request_context('/', headers={'Host': 'fzyto.top:8443'}):
        data = json.loads(ag.auth_portal().get_data(as_text=True))
finally:
    ag._authenticated = orig_auth
    ag.is_lan_source = orig_lan

svc = (data.get('services') or [{}])[0]
check('门户服务里带 host', svc.get('host') == 'siyuan.fzyto.top', repr(svc.get('host')))
check('门户服务里带绝对地址（含端口）',
      svc.get('url') == 'https://siyuan.fzyto.top:8443/', repr(svc.get('url')))
check('门户服务里仍带 path 前缀（老入口没丢）', svc.get('path') == '/siy')

# 没有 host 的规则 → url 退回路径前缀
ag.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'agcfg3.json')
with open(ag.CONFIG_PATH, 'w', encoding='utf-8') as f:
    json.dump({
        'gateway_port': 8443,
        'reverse_proxy': {'rules': [{
            'id': 'rp_002', 'name': 'NAS', 'enabled': True,
            'path_prefix': '/nas', 'host': '',
            'public_access': False, 'icon': 'N',
        }]},
    }, f)
ag._config_cache['mtime'] = None
ag._config_cache['data'] = None
ag._authenticated = lambda: True
ag.is_lan_source = lambda cfg: True
try:
    with ag.app.test_request_context('/', headers={'Host': 'fzyto.top:8443'}):
        data2 = json.loads(ag.auth_portal().get_data(as_text=True))
finally:
    ag._authenticated = orig_auth
    ag.is_lan_source = orig_lan
svc2 = (data2.get('services') or [{}])[0]
check('无 host 的规则 url 是路径前缀', svc2.get('url') == '/nas/', repr(svc2.get('url')))

# ─────────────────────────────────────────────────────────────
sec('HD-15 门户页优先用服务端给的 url')

check('portal.js 用 s.url', re.search(r"a\.href\s*=\s*s\.url\s*\|\|", PORTALJS_SRC) is not None)
check('portal.js 副标题显示 host', 's.host || s.path' in PORTALJS_SRC)
check('portal.js 没有自己拼协议（URL 只来自服务端）',
      "'https://' +" not in PORTALJS_SRC)

# ─────────────────────────────────────────────────────────────
sec('HD-16 前端表单有「访问域名」输入与自动生成')

check('index.html 有 host 输入框', 'x-model="rpEditingRule.host"' in INDEX_SRC)
check('index.html 有自动生成按钮', '@click="rpAutoHost()"' in INDEX_SRC)
check('index.html 显示基础域名提示', 'rp.hostBaseDomain' in INDEX_SRC)
check('index.html 列表显示域名入口', 'rule.host' in INDEX_SRC)
check('app.js 有 rpHostConflict 校验', 'rpHostConflict(rule)' in APPJS_SRC)
check('app.js 有 rpAutoHost', 'rpAutoHost()' in APPJS_SRC)
check('app.js 保存时归一 host', re.search(
    r"rule\.host\s*=\s*String\(rule\.host\s*\|\|\s*''\)\.trim\(\)\.toLowerCase\(\)", APPJS_SRC) is not None)
check('app.js 把 host 纳入表单有效性判断',
      'rpHostConflict(r)' in APPJS_SRC)
check('app.js 新建规则时 host 默认为空',
      re.search(r"host:\s*''", APPJS_SRC) is not None)
check('app.js 编辑规则时补 host 字段',
      re.search(r"r\.host\s*=\s*r\.host\s*\|\|\s*''", APPJS_SRC) is not None)

print()
if FAIL:
    print(f'❌ 失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
