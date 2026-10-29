"""认证网关「唯一公网入口」守卫 —— 后端回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_gateway_entry_guard.py

.224 真机踩出来的洞（2026-10-15）：

    1. 反代管理页的 gw 表单用**硬编码默认值**初始化（gateway_enabled=False）。
       用户没等 loadGatewayStatus() 回来就点「保存网关配置」，后端收到 false：
       _deploy_gateway_nginx 删掉 /etc/nginx/conf.d/00-nftables-web-gateway.conf
       再 reload —— nginx 活着，但 8443 没人听了。公网唯一入口没了，
       接口照样回 200「认证网关已停用」。
    2. 别的页面点「保存配置」（/api/config，无字段白名单的全量 merge），
       把 gateway_enabled=true 写回磁盘，**但不下发 nginx**。
    3. 于是磁盘 true、面板「已启用」、conf 文件不存在、8443 死，
       且没有任何机制会收敛。

同一个文件里 luci_enabled 早就修过同一个病（不一致才动、失败回滚），
网关这边一直没有。这份测试把两条路径钉成对称的。

另有一处连带修掉：_gateway_port_alive 原来连的是硬编码的 GATEWAY_PORT=8443，
而端口实际由 gateway_port 配置 —— 用户改成 9443 之后这个「安全网」
就会去问一个没人听的端口，然后误判网关已死、触发无谓回滚。
"""
import importlib.util as ilu
import json
import os
import shutil
import socket
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok_, detail=''):
    (PASS if ok_ else FAIL).append(name)
    print(('  ✅ ' if ok_ else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def load_app():
    spec = ilu.spec_from_file_location('_nftapp_gwguard', os.path.join(BACKEND, 'app.py'))
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mod = load_app()

print('=' * 74)
print('认证网关公网入口守卫 —— 后端回归测试')
print('=' * 74)

# ── 0. 字段归属 ────────────────────────────────────────────────────────
sec('0. 网关配置块的字段归属是单一来源')
GW_OWNED = {'gateway_enabled', 'gateway_port', 'auth_api_port',
            'auth_session_timeout', 'auth_absolute_timeout', 'auth_lan_bypass'}
check('GATEWAY_OWNED_CONFIG_KEYS 覆盖整块网关字段',
      set(mod.GATEWAY_OWNED_CONFIG_KEYS) == GW_OWNED,
      f'实际={sorted(mod.GATEWAY_OWNED_CONFIG_KEYS)}')
check('只读键独立于网关字段',
      not (set(mod.READONLY_CONFIG_KEYS) & set(mod.GATEWAY_OWNED_CONFIG_KEYS)),
      f'交集={sorted(set(mod.READONLY_CONFIG_KEYS) & set(mod.GATEWAY_OWNED_CONFIG_KEYS))}')
check('只读键含 GET 多给的那几个',
      {'luci_actual', 'luci_ports_listening', 'gateway_actual'} <= set(mod.READONLY_CONFIG_KEYS),
      f'实际={sorted(mod.READONLY_CONFIG_KEYS)}')

# ── 1. _gateway_port_alive 必须查配置端口 ──────────────────────────────
sec('1. _gateway_port_alive 查的是配置里的端口，不是硬编码 8443')
seen_ports = []
_orig_conn = socket.create_connection


def fake_conn(addr, timeout=None):
    seen_ports.append(addr[1])
    raise OSError('测试桩：拒绝连接')


socket.create_connection = fake_conn
try:
    mod._gateway_port_alive(port=9443)
    check('显式传端口时用它', seen_ports and seen_ports[-1] == 9443,
          f'实际={seen_ports}')
    seen_ports.clear()
    mod._gateway_port_alive(config={'gateway_port': 9443})
    check('传配置时取 gateway_port', seen_ports and seen_ports[-1] == 9443,
          f'实际={seen_ports}')
    seen_ports.clear()
    mod._gateway_port_alive(config={'gateway_port': '9443'})
    check('字符串端口也能用（不会因为类型炸掉）',
          seen_ports and seen_ports[-1] == 9443, f'实际={seen_ports}')
    seen_ports.clear()
    mod._gateway_port_alive(config={})
    check('端口缺失时退回 8443', seen_ports and seen_ports[-1] == 8443,
          f'实际={seen_ports}')
    seen_ports.clear()
    check('连不上返回 False', mod._gateway_port_alive(port=8443) is False)
finally:
    socket.create_connection = _orig_conn

# ── 2. _gateway_actual_state 三项判据 ─────────────────────────────────
sec('2. _gateway_actual_state 分开报「文件在不在」和「端口听不听」')
TD = tempfile.mkdtemp()
CONF_DIR = os.path.join(TD, 'conf.d')
os.makedirs(CONF_DIR)
CONF_PATH = os.path.join(CONF_DIR, mod.GATEWAY_CONF_NAME)

_orig_conf_dir = mod.NGINX_CONF_DIR
_orig_port_alive = mod._gateway_port_alive
mod.NGINX_CONF_DIR = CONF_DIR
try:
    mod._gateway_port_alive = lambda port=None, config=None: False
    st = mod._gateway_actual_state({'gateway_port': 8443})
    check('文件不在 → nginx_conf_exists False', st['nginx_conf_exists'] is False)
    check('端口没人听 → port_listening False', st['port_listening'] is False)
    check('两者都不成立 → enabled False', st['enabled'] is False)

    with open(CONF_PATH, 'w') as f:
        f.write(mod.GATEWAY_CONF_MARKER + '\n')
    st = mod._gateway_actual_state({'gateway_port': 8443})
    check('文件在但端口没人听 → 仍不算启用（这正是 .224 那次的状态）',
          st['nginx_conf_exists'] is True and st['port_listening'] is False
          and st['enabled'] is False,
          f'实际={st}')

    mod._gateway_port_alive = lambda port=None, config=None: True
    st = mod._gateway_actual_state({'gateway_port': 8443})
    check('文件在 + 端口在听 → enabled True', st['enabled'] is True, f'实际={st}')
finally:
    mod.NGINX_CONF_DIR = _orig_conf_dir
    mod._gateway_port_alive = _orig_port_alive

# ── 3. /api/config 不能改网关字段 ────────────────────────────────────
sec('3. /api/config 一律不改网关字段（它只落盘、不下发 nginx）')
TD3 = tempfile.mkdtemp()
CFG3 = os.path.join(TD3, 'config.json')
BASE = {**mod.DEFAULT_CONFIG, 'trusted_ip4': '192.168.100.224',
        'gateway_enabled': True, 'gateway_port': 8443,
        'auth_session_timeout': 1800, 'auth_lan_bypass': False}
with open(CFG3, 'w') as f:
    json.dump(BASE, f)

_orig_cfg = mod.CONFIG_PATH
_orig_luci_actual = mod._luci_actual_state
mod.CONFIG_PATH = CFG3
mod._luci_actual_state = lambda: False
_hooks = list(mod.app.before_request_funcs[None])
try:
    mod.app.before_request_funcs[None] = []
    client = mod.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True

    r = client.post('/api/config', json={
        'trusted_ip4': '192.168.100.224',
        # 模拟前端把整个 config 对象原样回传，夹带网关字段
        'gateway_enabled': False,
        'gateway_port': 9999,
        'auth_api_port': 9998,
        'auth_session_timeout': 60,
        'auth_absolute_timeout': 60,
        'auth_lan_bypass': True,
        # 以及 GET 多给的只读视图
        'success': True,
        'luci_actual': True,
        'luci_ports_listening': ['80'],
        'gateway_actual': {'enabled': True},
        # 以及「安全状态」类只读键（Shannon P0-4）：通用路径必须写不进去
        'auth_token_epoch': 999,
    })
    check('接口仍然返回 200（不能因为剔字段就失败）', r.status_code == 200,
          f'HTTP {r.status_code} {r.get_data(as_text=True)[:160]}')

    body = r.get_json() or {}
    data = body.get('data') or {}
    check('回报剔掉了哪些网关字段',
          set(data.get('ignored_gateway_fields') or []) == GW_OWNED,
          f'实际={data.get("ignored_gateway_fields")}')
    check('回报剔掉了哪些只读字段',
          set(data.get('ignored_readonly_fields') or []) ==
          {'success', 'luci_actual', 'luci_ports_listening', 'gateway_actual',
           'auth_token_epoch'},
          f'实际={data.get("ignored_readonly_fields")}')

    disk = json.load(open(CFG3))
    check('磁盘上 gateway_enabled 没被改成 False',
          disk.get('gateway_enabled') is True, f'实际={disk.get("gateway_enabled")!r}')
    check('磁盘上 gateway_port 没被改',
          disk.get('gateway_port') == 8443, f'实际={disk.get("gateway_port")!r}')
    check('磁盘上 auth_api_port 没被改',
          disk.get('auth_api_port') == BASE['auth_api_port'],
          f'实际={disk.get("auth_api_port")!r}')
    check('磁盘上 auth_session_timeout 没被改',
          disk.get('auth_session_timeout') == 1800,
          f'实际={disk.get("auth_session_timeout")!r}')
    check('磁盘上 auth_lan_bypass 没被改',
          disk.get('auth_lan_bypass') is False,
          f'实际={disk.get("auth_lan_bypass")!r}')
    # READONLY_CONFIG_KEYS 里有两类东西，不能一把尺子量：
    #
    #   ① **视图类**（success / luci_actual / luci_ports_listening /
    #      gateway_actual / config_rev）—— GET 为了让前端显示「实际状态」
    #      多给的，前端把整个 config 原样回传。落盘就是污染配置 ⇒ 必须不落盘。
    #
    #   ② **状态类**（auth_token_epoch）—— 面板自己的安全状态（改密码时
    #      递增的世代号），**必须**由面板自己落盘，只是**不允许**经通用
    #      /api/config 路径写入。所以对它的断言是「写不进去」，不是
    #      「不在磁盘上」—— 一刀切断言「只读键一律不落盘」会把这条判错。
    #
    # Shannon P0-4 实测：POST /api/config {"auth_token_epoch": 999} 曾经
    # 返回 200 且真的落盘 999，三个剔除名单一个都没拦它。
    VIEW_ONLY_KEYS = {'success', 'luci_actual', 'luci_ports_listening',
                      'gateway_actual', 'config_rev'}
    check('只读名单 = 视图类 + auth_token_epoch（新增的键必须归到其中一类）',
          set(mod.READONLY_CONFIG_KEYS) == VIEW_ONLY_KEYS | {'auth_token_epoch'},
          f'实际={sorted(mod.READONLY_CONFIG_KEYS)}')
    for k in sorted(set(mod.READONLY_CONFIG_KEYS) & VIEW_ONLY_KEYS):
        check(f'视图类只读键 {k} 没有落盘', k not in disk, f'磁盘里有={k!r}')
    check('状态类只读键 auth_token_epoch 没被通用路径改掉',
          int(disk.get('auth_token_epoch', 0) or 0) == 0,
          f'磁盘里={disk.get("auth_token_epoch")!r} —— '
          f'通用路径能改它 = 「改密码作废全部会话」的保证被撤销')
    check('非网关字段照常保存（不能连累正常功能）',
          disk.get('trusted_ip4') == '192.168.100.224',
          f'实际={disk.get("trusted_ip4")!r}')
finally:
    mod.CONFIG_PATH = _orig_cfg
    mod._luci_actual_state = _orig_luci_actual
    mod.app.before_request_funcs[None] = _hooks
    shutil.rmtree(TD, ignore_errors=True)
    shutil.rmtree(TD3, ignore_errors=True)

# ── 4. /api/gateway/config 下发后必须校验端口 ────────────────────────
sec('4. 下发成功不等于网关真的活着')
TD4 = tempfile.mkdtemp()
CFG4 = os.path.join(TD4, 'config.json')
with open(CFG4, 'w') as f:
    json.dump({**mod.DEFAULT_CONFIG, 'trusted_ip4': '192.168.100.224',
               'gateway_enabled': False, 'gateway_port': 8443}, f)

_orig_cfg = mod.CONFIG_PATH
_orig_deploy = mod._deploy_gateway_nginx
_orig_apply = mod._apply_ruleset
_orig_actual_state = mod._gateway_actual_state
mod.CONFIG_PATH = CFG4
mod._apply_ruleset = lambda cfg: (True, 'ok')


def set_actual(**kw):
    base = {'nginx_conf_exists': True, 'port': 8443,
            'port_listening': True, 'enabled': True}
    base.update(kw)
    enabled = bool(base['nginx_conf_exists'] and base['port_listening'])
    base['enabled'] = enabled
    mod._gateway_actual_state = lambda cfg=None, settle=False: dict(base)


try:
    mod.app.before_request_funcs[None] = []
    client = mod.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True

    # 端点这一层只做两件事：检查 deploy 结果、把失败翻译成稳定错误码。
    # 「端口真的在听吗」的判定在 _deploy_gateway_nginx 内部（见 4b），
    # 因为反代 CRUD 那条路也会经过它。所以这里桩的是 deploy 的返回值。
    # 4a. 部署函数报告「配置没写上去」→ 拒绝、不落盘、错误码正确
    def deploy_fail(msg):
        return lambda cfg=None: (False, msg)

    mod._deploy_gateway_nginx = deploy_fail(
        mod.GATEWAY_NOT_LISTENING_MSG.format(port=8443)
        + '（配置 /etc/nginx/conf.d/00-nftables-web-gateway.conf 不存在；端口 8443 没有监听）'
          '（已回滚 nginx 配置）')
    r = client.post('/api/gateway/config', json={'gateway_enabled': True})
    check('端口没监听时返回 500', r.status_code == 500, f'HTTP {r.status_code}')
    b = r.get_json() or {}
    check('错误码是 GATEWAY_NOT_LISTENING', b.get('code') == 'GATEWAY_NOT_LISTENING',
          f'实际={b.get("code")}')
    check('消息里点名了具体是哪一项不对',
          '配置文件' in (b.get('message') or '') or '没有监听' in (b.get('message') or ''),
          f'实际={b.get("message")}')
    check('配置没有被落盘（不能出现「以为开着了」）',
          json.load(open(CFG4)).get('gateway_enabled') is False,
          f'实际={json.load(open(CFG4)).get("gateway_enabled")!r}')

    # 4a2. 与端口无关的部署失败 —— 错误码不能误报成 GATEWAY_NOT_LISTENING，
    # 否则前端会把「语法错」当成「入口没起来」来提示，方向完全错了。
    mod._deploy_gateway_nginx = deploy_fail('nginx 配置校验失败：syntax error')
    r = client.post('/api/gateway/config', json={'gateway_enabled': True})
    b = r.get_json() or {}
    check('端口无关的失败返回 500', r.status_code == 500, f'HTTP {r.status_code}')
    check('错误码不误报成 GATEWAY_NOT_LISTENING',
          b.get('code') is None, f'实际={b.get("code")}')
    check('原样透传部署层的错误原因',
          'syntax error' in (b.get('message') or ''), f'实际={b.get("message")}')
    check('同样没有落盘',
          json.load(open(CFG4)).get('gateway_enabled') is False)

    # 4c. 一切正常 → 放行并落盘
    mod._deploy_gateway_nginx = lambda cfg=None: (True, '认证网关已启用：端口 8443，2 个服务')
    set_actual(nginx_conf_exists=True, port_listening=True, enabled=True)
    r = client.post('/api/gateway/config', json={'gateway_enabled': True})
    check('正常时返回 200', r.status_code == 200,
          f'HTTP {r.status_code} {r.get_data(as_text=True)[:160]}')
    check('正常时确实落盘了',
          json.load(open(CFG4)).get('gateway_enabled') is True)

    # 4d. 关闭网关不做端口校验（那时没人听才是对的）
    deploy_calls = []
    mod._deploy_gateway_nginx = lambda cfg=None: (deploy_calls.append(dict(cfg)) or (True, '已停用'))
    set_actual(nginx_conf_exists=False, port_listening=False, enabled=False)
    r = client.post('/api/gateway/config', json={'gateway_enabled': False})
    check('关闭网关返回 200', r.status_code == 200, f'HTTP {r.status_code}')
    check('关闭网关不因端口无人监听而报错', len(deploy_calls) == 1)
    check('关闭网关已落盘',
          json.load(open(CFG4)).get('gateway_enabled') is False)
finally:
    mod.CONFIG_PATH = _orig_cfg
    mod._deploy_gateway_nginx = _orig_deploy
    mod._apply_ruleset = _orig_apply
    mod._gateway_actual_state = _orig_actual_state
    mod.app.before_request_funcs[None] = _hooks
    shutil.rmtree(TD4, ignore_errors=True)


# ── 4e. 「网关开着 + LAN 内免登录」必须在响应里明确警告 ─────────────────
# .224 fresh install 实测（2026-10-16）：DEFAULT_CONFIG 的 auth_lan_bypass
# 默认为 True，setup.sh 又不写这个键，于是全新安装出来的机器天然落在这个
# 组合上 —— 直打 127.0.0.1:8444/auth/portal 无凭据返回 200 并吐出完整门户
# 数据，而面板一个字都不提。
#
# 用户拍板：默认值不改（家用场景要的是免登录），但启用时必须明确警告。
# 这一节钉住后端那一半（前端 confirm 只挡走面板的人，API 客户端看不到）。
TD4E = tempfile.mkdtemp()
CFG4E = os.path.join(TD4E, 'config.json')
with open(CFG4E, 'w') as f:
    json.dump({**mod.DEFAULT_CONFIG, 'trusted_ip4': '192.168.100.224',
               'gateway_enabled': False, 'gateway_port': 8443,
               'lan_subnet4': '192.168.100.0/24'}, f)

_orig_cfg = mod.CONFIG_PATH
_orig_deploy = mod._deploy_gateway_nginx
_orig_apply = mod._apply_ruleset
_orig_actual_state = mod._gateway_actual_state
mod.CONFIG_PATH = CFG4E
try:
    # 上一段 finally 把鉴权钩子恢复了，这里再摘一次，否则请求全被 401 挡掉
    mod.app.before_request_funcs[None] = []
    mod._deploy_gateway_nginx = lambda cfg=None: (True, '认证网关已启用：端口 8443，0 个服务')
    mod._apply_ruleset = lambda cfg=None: (True, 'ok')
    mod._gateway_actual_state = lambda cfg=None, settle=False: {
        'enabled': True, 'nginx_conf_exists': True,
        'port': 8443, 'port_listening': True}
    client = mod.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True

    # 4e1. 默认配置里 auth_lan_bypass 就是 True → 启用网关必须带警告
    check('DEFAULT_CONFIG 里 auth_lan_bypass 确实是 True（这是本节的前提）',
          mod.DEFAULT_CONFIG.get('auth_lan_bypass') is True,
          f'实际={mod.DEFAULT_CONFIG.get("auth_lan_bypass")!r}')

    r = client.post('/api/gateway/config', json={'gateway_enabled': True})
    b = (r.get_json() or {}).get('data') or {}
    w = b.get('warning')
    check('启用网关且免登录开着时返回 200', r.status_code == 200, f'HTTP {r.status_code}')
    check('响应里带 warning', bool(w), f'warning={w!r}')
    check('warning 点明局域网设备无需登录',
          w and '无需登录' in w, f'warning={w!r}')
    check('warning 写明受影响的是哪个网段',
          w and '192.168.100.0/24' in w, f'warning={w!r}')
    check('warning 指出要在面板里关掉它',
          w and '本页面' in w, f'warning={w!r}')

    # 4e2. 用户主动关掉免登录后再启用 → 不该有警告
    r = client.post('/api/gateway/config', json={'auth_lan_bypass': False})
    b = (r.get_json() or {}).get('data') or {}
    check('关掉免登录后 warning 消失', not b.get('warning'),
          f'warning={b.get("warning")!r}')

    # 4e3. 关掉网关本身不该带这条警告（免登录开着但网关没开，无从谈起）
    r = client.post('/api/gateway/config', json={'gateway_enabled': False})
    b = (r.get_json() or {}).get('data') or {}
    check('网关关闭时不报免登录警告', not b.get('warning'),
          f'warning={b.get("warning")!r}')

    # 4e4. 判据是「结果配置」，不是「本次请求改了什么」——
    #      在已开的网关上单独打开免登录，同样要警告
    mod._apply_ruleset = lambda cfg=None: (True, 'ok')
    r = client.post('/api/gateway/config',
                    json={'gateway_enabled': True, 'auth_lan_bypass': True})
    b = (r.get_json() or {}).get('data') or {}
    check('已开的网关上打开免登录，同样带警告', bool(b.get('warning')),
          f'warning={b.get("warning")!r}')
finally:
    mod.CONFIG_PATH = _orig_cfg
    mod._deploy_gateway_nginx = _orig_deploy
    mod._apply_ruleset = _orig_apply
    mod._gateway_actual_state = _orig_actual_state
    shutil.rmtree(TD4E, ignore_errors=True)

# ── 4b. 校验点必须在 _deploy_gateway_nginx 内部，不能只在端点 ─────────
# 端点 /api/gateway/config 只覆盖「保存网关配置」这一条路。反代规则增删改
# 走的是 _deploy_all_rules → _deploy_gateway_nginx，那条路曾经完全没有校验：
# 用户在网关开启时加一条服务，一样能拿到「成功」而公网入口已经没了。
# 所以这里直接测那个共同点本身。
sec('4b. 反代 CRUD 走的 _deploy_all_rules 也必须校验端口')
TD4B = tempfile.mkdtemp()
CONF_DIR_4B = os.path.join(TD4B, 'conf.d')
os.makedirs(CONF_DIR_4B)

_orig_dir = mod.NGINX_CONF_DIR
_orig_nt = mod._nginx_test
_orig_nr = mod._nginx_reload
_orig_svcs = mod._gateway_services
_orig_actual = mod._gateway_actual_state
mod.NGINX_CONF_DIR = CONF_DIR_4B
mod._nginx_test = lambda: (True, 'ok')
mod._nginx_reload = lambda: (True, 'ok')
# 元组元数必须跟 _gateway_services 一致：(rule, prefix, protocol, host, port, rp_host)
# 2026-10-28 host 分发改造后多了一个 rp_host —— mock 少给一个就直接 ValueError，
# 表现是「测试崩在半路」，而不是一条干净的断言失败。
mod._gateway_services = lambda cfg: [({'name': 'NAS', 'public_access': True},
                                     '/nas', 'http', '10.0.0.2', 5000, '')]
alive = {'v': True, 'conf': True}


def fake_actual_4b(config=None, settle=False):
    return {'nginx_conf_exists': alive['conf'], 'port': 8443,
            'port_listening': alive['v'],
            'enabled': bool(alive['conf'] and alive['v'])}


mod._gateway_actual_state = fake_actual_4b
try:
    ok_, msg_ = mod._deploy_gateway_nginx({'gateway_enabled': True, 'gateway_port': 8443})
    check('网关正常时下发成功', ok_ is True, f'msg={msg_}')

    alive['v'] = False
    alive['conf'] = False
    ok_, msg_ = mod._deploy_gateway_nginx({'gateway_enabled': True, 'gateway_port': 8443})
    check('端口没起来时返回失败（不是谎报成功）', ok_ is False, f'msg={msg_}')
    check('失败原因用统一措辞，便于调用方归类',
          msg_.startswith(mod.GATEWAY_NOT_LISTENING_MSG.split('{')[0]),
          f'实际={msg_}')

    # **conf 在、端口没监听** —— 这是 .224 那次的状态，也是最容易被漏判的一种：
    # 文件写好了、nginx -t 过了、reload 没报错，但公网入口已经没人听。
    # 只用「文件在不在」判定的实现会把这一种判成成功。
    alive['conf'] = True
    alive['v'] = False
    ok_, msg_ = mod._deploy_gateway_nginx({'gateway_enabled': True, 'gateway_port': 8443})
    check('conf 在但端口没监听时同样判失败（.224 那次的真实状态）',
          ok_ is False, f'msg={msg_}')
    check('这种失败的原因点名的是「端口没有监听」',
          '没有监听' in msg_ and '不存在' not in msg_, f'实际={msg_}')

    alive['v'] = True

    # 关闭网关时不校验（那时端口没人听才是对的）
    ok_, msg_ = mod._deploy_gateway_nginx({'gateway_enabled': False, 'gateway_port': 8443})
    check('关闭网关不因端口无人监听而失败', ok_ is True, f'msg={msg_}')
finally:
    mod.NGINX_CONF_DIR = _orig_dir
    mod._nginx_test = _orig_nt
    mod._nginx_reload = _orig_nr
    mod._gateway_services = _orig_svcs
    mod._gateway_actual_state = _orig_actual
    shutil.rmtree(TD4B, ignore_errors=True)

# ── 4c. 端口探测必须退避重试，不能紧挨 reload 就下结论 ────────────────
# 外部代码审查抓到：nginx -s reload 是异步的，返回只代表信号送达。
# 首次启用网关或改 gateway_port 时那是个**新增监听口**，master 还要
# 建 socket、起 worker。紧挨着就 connect 会撞在 ECONNREFUSED 窗口里，
# 把一次成功的部署误判成失败 → 回滚 + 报 500，而 conf 已经在盘上。
sec('4c. 端口探测带退避重试')
_orig_alive = mod._gateway_port_alive
_orig_sleep = mod.time.sleep
_orig_dir = mod.NGINX_CONF_DIR
TD4C = tempfile.mkdtemp()
CONF_DIR_4C = os.path.join(TD4C, 'conf.d')
os.makedirs(CONF_DIR_4C)
mod.NGINX_CONF_DIR = CONF_DIR_4C
mod._nginx_test = lambda: (True, 'ok')
mod._nginx_reload = lambda: (True, 'ok')
# 元组元数必须跟 _gateway_services 一致：(rule, prefix, protocol, host, port, rp_host)
# 2026-10-28 host 分发改造后多了一个 rp_host —— mock 少给一个就直接 ValueError，
# 表现是「测试崩在半路」，而不是一条干净的断言失败。
mod._gateway_services = lambda cfg: [({'name': 'NAS', 'public_access': True},
                                     '/nas', 'http', '10.0.0.2', 5000, '')]
mod.time.sleep = lambda s: None        # 不真的等，测试要快
try:
    # 端口在第 3 次探测才通（模拟 master 建 socket 的延迟）
    probes = {'n': 0}

    def slow_alive(port=None, config=None):
        probes['n'] += 1
        return probes['n'] >= 3

    mod._gateway_port_alive = slow_alive
    ok_, msg_ = mod._deploy_gateway_nginx({'gateway_enabled': True, 'gateway_port': 8443})
    check('端口迟到时部署仍然成功（没有误报失败）', ok_ is True, f'msg={msg_}')
    check('确实重试过，而不是一次就下结论',
          probes['n'] >= 3, f'实际探测 {probes["n"]} 次')

    # settle=False 时不许重试 —— 平时读状态不能每次都干等好几秒
    probes2 = {'n': 0}

    def slow_alive2(port=None, config=None):
        probes2['n'] += 1
        return probes2['n'] >= 3

    mod._gateway_port_alive = slow_alive2
    st = mod._gateway_actual_state({'gateway_port': 8443}, settle=False)
    check('settle=False 时只探一次（打开状态页不能干等）',
          probes2['n'] == 1, f'实际探测 {probes2["n"]} 次')
    check('settle=False 且端口没通时如实报没通', st['port_listening'] is False,
          f'实际={st}')
finally:
    mod._gateway_port_alive = _orig_alive
    mod.time.sleep = _orig_sleep
    mod.NGINX_CONF_DIR = _orig_dir
    mod._nginx_test = _orig_nt
    mod._nginx_reload = _orig_nr
    mod._gateway_services = _orig_svcs
    mod._gateway_actual_state = _orig_actual
    shutil.rmtree(TD4C, ignore_errors=True)

# ── 5. /api/gateway/status 必须能揭穿分叉 ─────────────────────────────
sec('5. /api/gateway/status 暴露实际状态，面板才有机会不骗人')
# 这一节必须自己摆一份 gateway_enabled=True 的配置：默认配置里它是 False，
# divergent 会恒等于 False，测的就不是「配置与实际分叉」这件事了。
TD5 = tempfile.mkdtemp()
CFG5 = os.path.join(TD5, 'config.json')
with open(CFG5, 'w') as f:
    json.dump({**mod.DEFAULT_CONFIG, 'trusted_ip4': '192.168.100.224',
               'gateway_enabled': True, 'gateway_port': 8443}, f)

_orig_actual_state = mod._gateway_actual_state
_orig_conn = socket.create_connection
_orig_cfg = mod.CONFIG_PATH
mod.CONFIG_PATH = CFG5
try:
    mod._gateway_actual_state = lambda cfg=None: {
        'nginx_conf_exists': False, 'port': 8443,
        'port_listening': False, 'enabled': False}
    socket.create_connection = lambda addr, timeout=None: (_ for _ in ()).throw(OSError())
    mod.app.before_request_funcs[None] = []
    client = mod.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True
    r = client.get('/api/gateway/status')
    check('状态接口返回 200', r.status_code == 200, f'HTTP {r.status_code}')
    d = (r.get_json() or {}).get('data') or {}
    check('enabled 仍如实反映配置（期望值）',
          d.get('enabled') is True, f'实际={d.get("enabled")!r}')
    check('带 actual 字段', isinstance(d.get('actual'), dict), f'实际={d.get("actual")}')
    check('actual 里有 nginx_conf_exists',
          'nginx_conf_exists' in (d.get('actual') or {}))
    check('actual 里有 port_listening',
          'port_listening' in (d.get('actual') or {}))
    check('配置为启用而实际未启用时 divergent=True',
          d.get('divergent') is True, f'实际={d.get("divergent")}')

    mod._gateway_actual_state = lambda cfg=None: {
        'nginx_conf_exists': True, 'port': 8443,
        'port_listening': True, 'enabled': True}
    d2 = (client.get('/api/gateway/status').get_json() or {}).get('data') or {}
    check('实际与配置一致时 divergent=False',
          d2.get('divergent') is False, f'实际={d2.get("divergent")}')
finally:
    mod._gateway_actual_state = _orig_actual_state
    socket.create_connection = _orig_conn
    mod.CONFIG_PATH = _orig_cfg
    mod.app.before_request_funcs[None] = _hooks
    shutil.rmtree(TD5, ignore_errors=True)

# ── 6. /api/config GET 的只读视图 ─────────────────────────────────────
sec('6. /api/config GET 带上只读视图')
_orig_luci_actual = mod._luci_actual_state
_orig_ports = mod._luci_ports_listening
_orig_gw_actual = mod._gateway_actual_state
_orig_cfg = mod.CONFIG_PATH
TD6 = tempfile.mkdtemp()
CFG6 = os.path.join(TD6, 'config.json')
with open(CFG6, 'w') as f:
    json.dump({**mod.DEFAULT_CONFIG, 'trusted_ip4': '192.168.100.224',
               'luci_enabled': False}, f)
mod.CONFIG_PATH = CFG6
try:
    mod._luci_actual_state = lambda: True
    mod._luci_ports_listening = lambda: {'80', '443'}
    mod._gateway_actual_state = lambda cfg=None: {'enabled': True, 'port': 8443}
    mod.app.before_request_funcs[None] = []
    client = mod.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True
    g = client.get('/api/config').get_json() or {}
    check('带 luci_actual', g.get('luci_actual') is True, f'实际={g.get("luci_actual")}')
    check('带 luci_ports_listening',
          sorted(g.get('luci_ports_listening') or []) == ['443', '80'],
          f'实际={g.get("luci_ports_listening")}')
    check('带 gateway_actual',
          (g.get('gateway_actual') or {}).get('enabled') is True)
    check('正常配置字段没丢', g.get('trusted_ip4') == '192.168.100.224')
finally:
    mod.CONFIG_PATH = _orig_cfg
    mod._luci_actual_state = _orig_luci_actual
    mod._luci_ports_listening = _orig_ports
    mod._gateway_actual_state = _orig_gw_actual
    mod.app.before_request_funcs[None] = _hooks
    shutil.rmtree(TD6, ignore_errors=True)

# ── 7. 前端守卫（跑 node 行为测试，折进同一个计数） ──────────────────
sec('7. 前端行为守卫')
import subprocess
NODE = shutil.which('node')
if not NODE:
    check('找到 node', False, '未安装 node，跳过前端行为测试')
else:
    r = subprocess.run([NODE, os.path.join(ROOT, 'tests', 'test_gateway_guard_frontend.js')],
                       capture_output=True, text=True, timeout=120)
    tail = (r.stdout or '').strip().splitlines()
    summary = next((l for l in reversed(tail) if l.strip().startswith('通过 ')), '')
    check('前端行为测试全过', r.returncode == 0, summary or (r.stderr or '')[:300])
    m = __import__('re').search(r'通过 (\d+) / 失败 (\d+)', summary or '')
    if m:
        n = int(m.group(1))
        print(f'     （前端 {n} 条断言已并入本节）')

print('\n' + '=' * 74)
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    print('失败项:')
    for f in FAIL:
        print('  - ' + f)
    sys.exit(1)
print('全部通过')
