"""「防火墙控制入口」开放到门户的回归测试。

运行:  python3 tests/test_fw_console.py

覆盖 2026-11-04 落地的一批改动：

  FW-1  一键添加的规则字段全对（路径前缀 / 协议 / 仅内网 / 路径改写）
  FW-2  幂等：已有 /fw 规则时不重复创建
  FW-3  面板不知道自己的地址时明确报错（不静默建一条坏规则）
  FW-4  反代后面板认得**真实**客户端 IP（不再把所有人都当本机）
  FW-5  面板自己的网段限制在反代后仍然有效（公网用户点进来仍被挡）
  FW-6  门户卡片用规则自带的图标；前端有「添加防火墙控制入口」按钮
  FW-7  暴露面：这条入口是**仅内网**的（面板 v0.8.0 起的设计不变）

沙箱运行：不碰真实配置、不执行 nginx / nftables（相关动作打桩）。
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
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print('\n== ' + title)


TD = tempfile.mkdtemp(prefix='fwconsole-')
CFG = os.path.join(TD, 'cfg.json')
RULES = os.path.join(TD, 'rules.nft')

sys.modules.pop('app', None)
mod = importlib.import_module('app')

deploy_calls = []
ruleset_calls = []


def fake_deploy(config=None):
    deploy_calls.append(config)
    return True, 'ok'


def fake_ruleset(config=None):
    ruleset_calls.append(config)
    return True, 'ok'


mod.CONFIG_PATH = CFG
mod.RULES_PATH = RULES
mod._deploy_all_rules = fake_deploy
mod._apply_ruleset = fake_ruleset
# 认证拦截器在测试里一律放行（认证本身有专门的测试文件管）
mod.app.before_request_funcs[None] = []
# 面板自己的绑定地址（启动时探测的值）：定死，测试才可预期
mod.PANEL_BIND_ADDR = '192.168.100.232'


def base_config(**extra):
    cfg = dict(mod.DEFAULT_CONFIG)
    cfg['router_ip4'] = '192.168.100.232'
    cfg['lan_subnet4'] = '192.168.100.0/24'
    cfg['trusted_ip4'] = '192.168.100.2'
    cfg['luci_enabled'] = False
    cfg.update(extra)
    return cfg


def write_config(cfg):
    with open(CFG, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False)


def read_config():
    with open(CFG, encoding='utf-8') as f:
        return json.load(f)


def make_client():
    c = mod.app.test_client()
    with c.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = 9e9
    return c


def add_fw(client):
    return client.post('/api/reverse-proxy/fw-console', json={})


# ─────────────────────────────────────────────────────────────
sec('FW-1 一键添加的规则字段全对')

write_config(base_config())
c = make_client()
r = add_fw(c)
body = r.get_json() or {}
check('接口返回成功', r.status_code == 200 and body.get('success') is True,
      f'status={r.status_code} body={body}')
rules = (read_config().get('reverse_proxy') or {}).get('rules') or []
check('规则已落盘', len(rules) == 1, f'条数={len(rules)}')
if rules:
    ru = rules[0]
    check('路径前缀是 /fw', ru.get('path_prefix') == '/fw', ru.get('path_prefix'))
    check('名称是「防火墙控制」', ru.get('name') == '防火墙控制', ru.get('name'))
    check('上游是面板自己的地址 + 面板端口',
          ru.get('target_address') == '192.168.100.232:5443', ru.get('target_address'))
    check('协议是 https', ru.get('target_protocol') == 'https', ru.get('target_protocol'))
    check('仅内网（public_access=false）',
          ru.get('public_access') is False, ru.get('public_access'))
    check('默认启用', ru.get('enabled') is True, ru.get('enabled'))
    check('开了 API 路径改写（面板的 /api 是根绝对路径）',
          # ⚠ 落盘值是 '/api/' 不是 '/api'：_sanitize_api_path_prefix 统一补尾斜杠
          #   （生成的 sub_filter 替换的是 "'/api/" 这一段字面量，带斜杠才对得上）
          ru.get('api_path_prefix') == '/api/', ru.get('api_path_prefix'))
    check('开了根绝对路径改写（面板的静态资源是根绝对路径）',
          ru.get('rewrite_root_paths') is True, ru.get('rewrite_root_paths'))
    check('带图标（门户卡片用）', ru.get('icon') == 'FW', ru.get('icon'))
check('网关配置已下发', len(deploy_calls) > 0)
check('防火墙规则集已应用', len(ruleset_calls) > 0)

# ─────────────────────────────────────────────────────────────
sec('FW-2 幂等：已有 /fw 规则时不重复创建')

r2 = add_fw(c)
b2 = r2.get_json() or {}
rules2 = (read_config().get('reverse_proxy') or {}).get('rules') or []
check('第二次调用仍返回成功', r2.status_code == 200 and b2.get('success') is True)
check('没有多出第二条规则', len(rules2) == 1, f'条数={len(rules2)}')
check('提示是「已存在」', b2.get('data', {}).get('created') is False,
      json.dumps(b2.get('data', {}), ensure_ascii=False))

# ─────────────────────────────────────────────────────────────
sec('FW-3 面板不知道自己的地址时明确报错')

mod.PANEL_BIND_ADDR = ''
write_config(base_config(router_ip4=''))
c3 = make_client()
r3 = add_fw(c3)
b3 = r3.get_json() or {}
check('返回 400', r3.status_code == 400, f'status={r3.status_code}')
check('没有静默建一条坏规则',
      len((read_config().get('reverse_proxy') or {}).get('rules') or []) == 0)
check('错误文案说清了要做什么', 'router_ip4' in (b3.get('message') or ''),
      b3.get('message'))
mod.PANEL_BIND_ADDR = '192.168.100.232'

# ─────────────────────────────────────────────────────────────
sec('FW-4 反代后面板认得真实客户端 IP')

with mod.app.test_request_context('/', environ_base={'REMOTE_ADDR': '192.168.100.5'}):
    check('直连：就是内核给的对端地址', mod._client_ip() == '192.168.100.5',
          mod._client_ip())
with mod.app.test_request_context('/', environ_base={'REMOTE_ADDR': '192.168.100.5'},
                                  headers={'X-Real-IP': '203.0.113.9'}):
    check('直连时伪造的 X-Real-IP 不被采信（对端不是回环）',
          mod._client_ip() == '192.168.100.5', mod._client_ip())
with mod.app.test_request_context('/', environ_base={'REMOTE_ADDR': '127.0.0.1'},
                                  headers={'X-Real-IP': '203.0.113.9'}):
    check('经本机网关反代：用 X-Real-IP 里的真实地址',
          mod._client_ip() == '203.0.113.9', mod._client_ip())
with mod.app.test_request_context('/', environ_base={'REMOTE_ADDR': '127.0.0.1'}):
    check('回环但没有 X-Real-IP：退回回环地址',
          mod._client_ip() == '127.0.0.1', mod._client_ip())

# ─────────────────────────────────────────────────────────────
sec('FW-5 面板的网段限制在反代后仍然有效')

# 面板只放行 192.168.100.0/24（内网）。
write_config(base_config())
mod._NETS_CACHE.update(mtime=None, nets=[])
with mod.app.test_request_context('/', environ_base={'REMOTE_ADDR': '127.0.0.1'},
                                  headers={'X-Real-IP': '203.0.113.9'}):
    check('公网来源经网关反代进来 → 判为非内网（被挡）',
          mod._client_is_lan(mod._client_ip()) is False)
with mod.app.test_request_context('/', environ_base={'REMOTE_ADDR': '127.0.0.1'},
                                  headers={'X-Real-IP': '192.168.100.7'}):
    check('内网来源经网关反代进来 → 判为内网（放行）',
          mod._client_is_lan(mod._client_ip()) is True)

# ─────────────────────────────────────────────────────────────
sec('FW-6 门户卡片用规则图标；前端有添加按钮')

PORTALJS = open(os.path.join(BACKEND, 'static', 'portal.js'), encoding='utf-8').read()
APPJS = open(os.path.join(ROOT, 'frontend', 'app.js'), encoding='utf-8').read()
INDEX = open(os.path.join(ROOT, 'frontend', 'index.html'), encoding='utf-8').read()
APPSRC = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()

check('portal.js 优先用规则自带的 icon',
      re.search(r"ico\.textContent\s*=\s*\(s\.icon", PORTALJS) is not None)
check('portal.js 没有丢掉老的路径首字母兜底',
      'glyph(s, used)' in PORTALJS)
check('前端有 addFwConsole 方法', 'async addFwConsole()' in APPJS)
check('前端调的是新增的预设接口',
      "/api/reverse-proxy/fw-console" in APPJS)
check('界面上有「添加防火墙控制入口」按钮',
      '添加防火墙控制入口' in INDEX and 'addFwConsole()' in INDEX)
check('面板接口只接受 POST（不误开 GET）',
      "@app.route('/api/reverse-proxy/fw-console', methods=['POST'])" in APPSRC)
check('上游地址不是 127.0.0.1（面板只绑 LAN IP，127.0.0.1 连不上）',
      "PANEL_BIND_ADDR or str(config.get('router_ip4')" in APPSRC)

# ─────────────────────────────────────────────────────────────
sec('FW-7 暴露面：这条入口是仅内网的')

write_config(base_config())
c7 = make_client()
add_fw(c7)
ru = ((read_config().get('reverse_proxy') or {}).get('rules') or [{}])[0]
check('规则是仅内网', ru.get('public_access') is False)
check('启用后门户才会收录它（门户只收 enabled 的规则）',
      ru.get('enabled') is True)
check('生成器对仅内网的规则写 allow/deny（网关侧第二道防线）',
      re.search(r"public_access=false：仅内网", APPSRC) is not None)

# ─────────────────────────────────────────────────────────────
sec('FW-8 上游协议以 target_protocol 为准（生成器不再一律 http）')

# 这是本轮实测踩出来的缺口：界面上有「协议」这一项、校验也只认它，
# 但 path 模式的生成器从来没读过它 —— 上游是 HTTPS 时生成的是
# proxy_pass http://… ⇒ 502，而界面上看不出任何异常。
gw_cfg = base_config(gateway_enabled=True, gateway_port=8443, auth_api_port=8444)
gw_cfg['reverse_proxy'] = {
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
    'rules': [
        {'id': 'rp_001', 'name': '思源', 'enabled': True,
         'path_prefix': '/siy', 'host': '', 'target_address': '192.168.100.218:6806',
         'target_protocol': 'http', 'public_access': False,
         'client_max_body_size': '1M', 'api_path_prefix': '',
         'rewrite_root_paths': False, 'websocket_enabled': True, 'icon': ''},
        {'id': 'rp_002', 'name': '防火墙控制', 'enabled': True,
         'path_prefix': '/fw', 'host': '', 'target_address': '192.168.100.232:5443',
         'target_protocol': 'https', 'public_access': False,
         'client_max_body_size': '1M', 'api_path_prefix': '/api/',
         'rewrite_root_paths': True, 'websocket_enabled': True, 'icon': 'FW'},
    ],
}
conf = mod._generate_gateway_nginx_conf(gw_cfg)
check('https 上游生成 proxy_pass https://',
      'proxy_pass https://192.168.100.232:5443/;' in conf)
check('http 上游仍然是 http://（既有行为不变）',
      'proxy_pass http://192.168.100.218:6806/;' in conf)
check('https 上游不会退化成 http',
      'proxy_pass http://192.168.100.232:5443/;' not in conf)

# ─────────────────────────────────────────────────────────────
sec('FW-9 路径改写覆盖 JS 正文与 CSS 里的 url()（真机实测补的两个洞）')

check('sub_filter_types 含 text/javascript',
      'sub_filter_types application/javascript text/javascript text/css;' in conf,
      'JS 正文没进改写范围 ⇒ app.js 里的 /api/xxx 不会被改写')
check("CSS 里的 url('/x') 也会被改写（@font-face 的字体）",
      """sub_filter "url('/" "url('/fw/";""" in conf,
      'CSS 里的字体 url() 没被改写 ⇒ 跑出 location ⇒ 404')
check('CSS 里的 url("/x") 也会被改写',
      """sub_filter "url(\\"/" "url(\\"/fw/";""" in conf)
check('API 路径（窄模式）仍然改写成带前缀的',
      """sub_filter "'/api/" "'/fw/api/";""" in conf)

print()
if FAIL:
    print(f'失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')