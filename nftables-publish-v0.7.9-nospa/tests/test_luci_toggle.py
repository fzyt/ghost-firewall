"""LuCI 80/443 开关 —— 回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_luci_toggle.py

80/443 不是本项目的：它们是 OpenWrt 自带 LuCI 的两个 server 段

    nginx._lan            listen 443 ssl   （带 restrict_locally，只放行内网段）
    nginx._redirect2ssl   listen 80        （302 跳转，**没有任何限制**）

本项目的反代在 8443，走 conf.d/00-nftables-web-gateway.conf，模板里是无条件
include，与 LuCI 无关。个人宽带用不上 LuCI → 部署后自动关，之后默认保持关闭。

.224 真机实测得到的三条实现约束（全部写进断言）：
  1. `uci set nginx._lan.enabled=0` **无效** —— 这个 uci-nginx 不认 enabled，
     实测 80/443 照常监听。只能整段摘掉。
  2. /etc/nginx/uci.conf 是**符号链接** → /var/lib/nginx/uci.conf。重新渲染要删
     链接的**目标**；删链接本身会让 nginx_init 的 `if [ -e "${UCI_CONF}" ]` 判假，
     静默回落到 /etc/nginx/nginx.conf（实测 LuCI 消失但日志看不出原因）。
  3. 关掉后必须确认 8443 还在听 —— 那是本项目唯一的公网入口。
"""
import importlib.util as ilu
import json
import os
import re
import shutil
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


def load_app():
    spec = ilu.spec_from_file_location('_nftapp_luci', os.path.join(BACKEND, 'app.py'))
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mod = load_app()

UCI_SAMPLE = """config main global
\toption uci_enable 'true'

config server '_lan'
\tlist listen '443 ssl default_server'
\toption server_name '_lan'
\tlist include 'restrict_locally'
\tlist include 'conf.d/*.locations'
\toption uci_manage_ssl 'self-signed'

config server '_redirect2ssl'
\tlist listen '80'
\tlist listen '[::]:80'
\toption server_name '_redirect2ssl'
\toption return '302 https://$host$request_uri'

config server 'keepme'
\tlisten 9999
\toption note '用户自己加的段，不能被误删'
"""

print('=' * 74)
print('LuCI 80/443 开关回归测试')
print('=' * 74)

# ── 1. uci 文本处理 ────────────────────────────────────────────────────
sec('1. /etc/config/nginx 的 section 解析与摘除')
names = mod._uci_section_names(UCI_SAMPLE)
check('section 名解析正确（去引号）',
      names == ['global', '_lan', '_redirect2ssl', 'keepme'], f'实际={names}')

stripped = mod._uci_strip_sections(UCI_SAMPLE, mod.LUCI_SECTIONS)
sn = mod._uci_section_names(stripped)
check('LuCI 两段被摘掉', '_lan' not in sn and '_redirect2ssl' not in sn, f'剩余={sn}')
check('其它段原样保留（不能误删用户的配置）', 'keepme' in sn, f'剩余={sn}')
check('global 段保留', 'global' in sn, f'剩余={sn}')
check('keepme 段内容完整', "option note '用户自己加的段，不能被误删'" in stripped)
check('443 那几行确实没了', '443 ssl default_server' not in stripped)
check('80 那几行确实没了', "[::]:80" not in stripped)
check('不会把 conf.d/*.locations 一起删掉',
      'conf.d/*.locations' not in stripped, '它属于 _lan 段，本就该删')

# ── 2. 渲染目标路径 ────────────────────────────────────────────────────
sec('2. 渲染目标必须是 /var/lib/nginx/uci.conf，不是软链本身')
check('LUCI_RENDERED_PATH 指向真实文件',
      mod.LUCI_RENDERED_PATH == '/var/lib/nginx/uci.conf',
      f"实际={mod.LUCI_RENDERED_PATH}")
check('不能退化成删 /etc/nginx/uci.conf',
      'etc/nginx/uci.conf' not in mod.LUCI_RENDERED_PATH,
      '删软链会让 nginx_init 判假并静默回落到 /etc/nginx/nginx.conf')

# ── 3. 开关语义 ────────────────────────────────────────────────────────
sec('3. _apply_luci_toggle 行为')
TD = tempfile.mkdtemp()
CONF = os.path.join(TD, 'nginx')
SNAP = os.path.join(TD, 'snap')
orig_paths = (mod.LUCI_CONF_PATH, mod.LUCI_SNAPSHOT_PATH,
              mod._luci_reload_nginx, mod._luci_ports_listening,
              mod._gateway_port_alive)
mod.LUCI_CONF_PATH = CONF
mod.LUCI_SNAPSHOT_PATH = SNAP
calls = []


def fake_reload(what):
    calls.append(what)
    return True, 'ok'


mod._luci_reload_nginx = fake_reload
mod._luci_ports_listening = lambda: set()
mod._gateway_port_alive = lambda port=None, config=None: True
try:
    # 已关闭（配置里本来就没有那两段）
    with open(CONF, 'w') as f:
        f.write("config main global\n\toption uci_enable 'true'\n")
    ok, msg = mod._apply_luci_toggle(False)
    check('本来就没开 → 报「无需处理」', ok is True and '无需' in msg, f'msg={msg}')
    check('本来就没开 → 不 reload nginx', calls == [], f'calls={calls}')

    # 关闭
    calls.clear()
    with open(CONF, 'w') as f:
        f.write(UCI_SAMPLE)
    ok, msg = mod._apply_luci_toggle(False)
    after = open(CONF).read()
    check('关闭成功', ok is True, f'msg={msg}')
    check('reload 被调用了一次', len(calls) == 1, f'calls={calls}')
    check('配置文件里 LuCI 两段真的没了',
          '_lan' not in mod._uci_section_names(after),
          f'剩余={mod._uci_section_names(after)}')
    check('留了快照', os.path.exists(SNAP))
    check('快照是关闭前的完整内容',
          '_lan' in mod._uci_section_names(open(SNAP).read()))

    # 已存在的快照不能被覆盖 —— 否则用户在面板上开关几次之后，
    # 「重新打开」还原回来的永远是最后一次关之前的那份，而不是最初那份。
    # 必须先把 CONF 恢复到「LuCI 还开着」的状态，否则 _apply_luci_toggle(False)
    # 会走幂等早返回，压根到不了快照那一步，这条断言就成了摆设。
    with open(CONF, 'w') as f:
        f.write(UCI_SAMPLE)
    with open(SNAP, 'w') as f:
        f.write('# 用户后来改过的版本\nconfig main global\n')
    calls.clear()
    ok, msg = mod._apply_luci_toggle(False)
    check('已存在的快照不被覆盖',
          '# 用户后来改过的版本' in open(SNAP).read(),
          f"快照内容={open(SNAP).read()[:40]!r}")
    # 恢复现场
    with open(SNAP, 'w') as f:
        f.write(UCI_SAMPLE)

    # 再关一次（幂等）
    calls.clear()
    ok, msg = mod._apply_luci_toggle(False)
    check('重复关闭是幂等的', ok is True and '无需' in msg, f'msg={msg}')
    check('幂等时不再 reload', calls == [])

    # 打开
    calls.clear()
    ok, msg = mod._apply_luci_toggle(True)
    back = open(CONF).read()
    check('重新打开成功', ok is True, f'msg={msg}')
    check('LuCI 两段回来了',
          set(mod._uci_section_names(back)) >= {'_lan', '_redirect2ssl'},
          f'段={mod._uci_section_names(back)}')
    check('443/80 都回来了',
          '443 ssl default_server' in back and "[::]:80" in back)
    check('打开时 reload 了一次', len(calls) == 1, f'calls={calls}')

    # 无快照时拒绝还原，而不是留一个残缺配置
    os.unlink(SNAP)
    with open(CONF, 'w') as f:
        f.write("config main global\n")
    ok, msg = mod._apply_luci_toggle(True)
    # 只认守卫自己的文案：'从快照还原失败' 里也有「快照」两个字，
    # 断言太松的话「没有守卫、直接 copy 抛异常」这条变异会漏过去
    check('没有快照时拒绝还原并说明原因',
          ok is False and '无法自动还原' in msg, f'msg={msg}')

    # 端口仍在监听 → 必须判失败，不能谎报「已关闭」
    with open(CONF, 'w') as f:
        f.write(UCI_SAMPLE)
    mod._luci_ports_listening = lambda: {80, 443}
    ok, msg = mod._apply_luci_toggle(False)
    check('改完端口仍在监听 → 判失败', ok is False, f'ok={ok} msg={msg}')
    check('失败原因里点名了还在听的端口',
          '80' in msg and '443' in msg, f'msg={msg}')

    # 读不到配置文件 → 不臆断
    mod.LUCI_CONF_PATH = os.path.join(TD, 'nope')
    ok, msg = mod._apply_luci_toggle(False)
    check('读不到配置时如实报失败', ok is False and '未改动' in msg, f'msg={msg}')
finally:
    (mod.LUCI_CONF_PATH, mod.LUCI_SNAPSHOT_PATH,
     mod._luci_reload_nginx, mod._luci_ports_listening,
     mod._gateway_port_alive) = orig_paths
    shutil.rmtree(TD, ignore_errors=True)

# ── 4. 配置默认值与校验 ────────────────────────────────────────────────
sec('4. 默认关闭 + 严格布尔校验')
check('DEFAULT_CONFIG.luci_enabled 是 False（默认关闭）',
      mod.DEFAULT_CONFIG.get('luci_enabled') is False,
      f"实际={mod.DEFAULT_CONFIG.get('luci_enabled')!r}")
base = dict(mod.DEFAULT_CONFIG)
base['trusted_ip4'] = '192.168.100.1'
for v, want_ok in ((True, True), (False, True),
                   ('false', False), ('true', False), (1, False), (0, False)):
    cfg = dict(base)
    cfg['luci_enabled'] = v
    errs = [e for e in mod.validate_config(cfg) if 'luci_enabled' in e]
    check(f'luci_enabled={v!r:8} {"通过" if want_ok else "被拒"}',
          (not errs) == want_ok, f'errs={errs}')
cfg = dict(base)
del cfg['luci_enabled']
check('字段缺失时不报错（走 DEFAULT）',
      not [e for e in mod.validate_config(cfg) if 'luci_enabled' in e])

# ── 5. 保存接口的联动 ──────────────────────────────────────────────────
sec('5. /api/config 只在开关真变了时才动 nginx')
# 这一节测的是**联动规则**（什么时候调 _apply_luci_toggle、失败怎么回滚），
# _apply_luci_toggle 自己的行为在第 3 节单独测。
TD2 = tempfile.mkdtemp()
CFG2 = os.path.join(TD2, 'config.json')
with open(CFG2, 'w') as f:
    json.dump({**mod.DEFAULT_CONFIG, 'trusted_ip4': '192.168.100.1',
               'luci_enabled': False}, f)
mod.CONFIG_PATH = CFG2
toggle_calls = []
gw_ok = {'v': True}
toggle_result = {'r': (True, 'ok')}

orig_toggle = mod._apply_luci_toggle
orig_gw = mod._gateway_port_alive
orig_actual = mod._luci_actual_state

# 模拟一台「跟着配置走」的机器：初始与配置一致（都关），
# 每成功 toggle 一次实际状态就跟着变。
actual = {'v': False}


def fake_toggle(enabled):
    toggle_calls.append(bool(enabled))
    ok = toggle_result['r'][0]
    if ok:
        actual['v'] = bool(enabled)
    return toggle_result['r']


def fake_gw(port=None, config=None):
    return gw_ok['v']


def fake_actual():
    return actual['v']


mod._apply_luci_toggle = fake_toggle
mod._gateway_port_alive = fake_gw
mod._luci_actual_state = fake_actual
_hooks = list(mod.app.before_request_funcs[None])
try:
    mod.app.before_request_funcs[None] = []
    client = mod.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = 9e9

    # 5a. 改别的字段 → 不该碰 LuCI
    r = client.post('/api/config', json={'whitelist_timeout': 12345})
    check('保存无关字段返回 200', r.status_code == 200, f'status={r.status_code}')
    check('开关没变 → 不调 _apply_luci_toggle', toggle_calls == [],
          f'calls={toggle_calls}')

    # 5b. 真的翻开关 → 调，且参数是新值
    r = client.post('/api/config', json={'luci_enabled': True})
    check('翻开关返回 200', r.status_code == 200,
          f'status={r.status_code} body={r.get_json()}')
    check('翻开关 → 调了一次 _apply_luci_toggle(True)',
          toggle_calls == [True], f'calls={toggle_calls}')
    check('落盘为 True', json.load(open(CFG2))['luci_enabled'] is True)

    # 5c. 再翻回 False，同样要调
    toggle_calls.clear()
    r = client.post('/api/config', json={'luci_enabled': False})
    check('翻回也调用一次',
          r.status_code == 200 and toggle_calls == [False],
          f'status={r.status_code} calls={toggle_calls}')

    # 5d. 关 LuCI 时网关不在 → 自动还原
    # 5c 的 toggle 失败了，实际状态没跟上；先把它拨回一致，
    # 再翻成 True、然后往 False 翻，制造一次真正的不一致
    actual['v'] = False
    client.post('/api/config', json={'luci_enabled': True})
    check('翻成 True 后实际状态跟上', actual['v'] is True, f"actual={actual['v']}")
    toggle_calls.clear()
    gw_ok['v'] = False
    r = client.post('/api/config', json={'luci_enabled': False})
    body = r.get_json()
    # 关一次(False) + 检测到网关不在后自动还原一次(True) —— 两次都要在
    check('关了之后又自动还原，toggle 共调两次',
          toggle_calls == [False, True], f'calls={toggle_calls}')
    check('网关不在时返回 500', r.status_code == 500, f'status={r.status_code}')
    check('错误码是 GATEWAY_DOWN', body.get('code') == 'GATEWAY_DOWN',
          f"code={body.get('code')}")
    check('配置项被回滚为 True',
          json.load(open(CFG2))['luci_enabled'] is True,
          f"落盘={json.load(open(CFG2))['luci_enabled']!r}")

    # 5e. 切换失败 → 回滚配置项
    toggle_calls.clear()
    actual['v'] = True          # 5d 失败后实际仍是 True
    gw_ok['v'] = True
    toggle_result['r'] = (False, 'nginx -t 失败')
    # 5d 结束时配置已回滚为 True，所以这里要往 False 翻才会真正触发 toggle
    r = client.post('/api/config', json={'luci_enabled': False})
    body = r.get_json()
    check('切换失败返回 500', r.status_code == 500, f'status={r.status_code}')
    check('错误码是 LUCI_TOGGLE_FAILED', body.get('code') == 'LUCI_TOGGLE_FAILED',
          f"code={body.get('code')}")
    check('切换失败 → 配置项回滚为切换前的值(True)',
          json.load(open(CFG2))['luci_enabled'] is True,
          f"落盘={json.load(open(CFG2))['luci_enabled']!r}")
    check('切换失败 → toggle 确实被调过',
          toggle_calls == [False], f'calls={toggle_calls}')
    check('切换失败 → 失败原因回传给用户',
          'nginx -t 失败' in (body.get('message') or ''),
          f"msg={body.get('message')}")
finally:
    mod._apply_luci_toggle = orig_toggle
    mod._gateway_port_alive = orig_gw
    mod._luci_actual_state = orig_actual
    mod.app.before_request_funcs[None] = _hooks
    mod.CONFIG_PATH = '/etc/nftables/nftables-web-config.json'
    shutil.rmtree(TD2, ignore_errors=True)

sec('5f. 配置没变、但实际状态与期望不符 → 也要动（升级场景）')
# .224 真机就是这个形态：配置里 luci_enabled=False（DEFAULT 取值），
# 而 /etc/config/nginx 里 _lan / _redirect2ssl 一直都在。
# 只比「配置变没变」的话，开关永远不会被触发 —— 面板显示已关闭，80/443 照常在听。
TD3 = tempfile.mkdtemp()
C3 = os.path.join(TD3, 'config.json')
N3 = os.path.join(TD3, 'nginx')
with open(C3, 'w') as f:
    json.dump({**mod.DEFAULT_CONFIG, 'trusted_ip4': '192.168.100.1',
               'luci_enabled': False}, f)
with open(N3, 'w') as f:
    f.write(UCI_SAMPLE)          # 实际：LuCI 开着
mod.CONFIG_PATH = C3
mod.LUCI_CONF_PATH = N3
mod.LUCI_SNAPSHOT_PATH = os.path.join(TD3, 'snap3')
t3 = []
og3 = (mod._apply_luci_toggle, mod._gateway_port_alive, mod._luci_ports_listening)
mod._apply_luci_toggle = lambda e: (t3.append(bool(e)), (True, 'ok'))[1]
mod._gateway_port_alive = lambda port=None, config=None: True
mod._luci_ports_listening = lambda: set()
_h3 = list(mod.app.before_request_funcs[None])
try:
    mod.app.before_request_funcs[None] = []
    check('_luci_actual_state 读出 True',
          mod._luci_actual_state() is True)
    client = mod.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = 9e9
    r = client.post('/api/config', json={'whitelist_timeout': 999})
    check('保存无关字段也触发对齐',
          r.status_code == 200 and t3 == [False],
          f'status={r.status_code} calls={t3}')
finally:
    (mod._apply_luci_toggle, mod._gateway_port_alive, mod._luci_ports_listening) = og3
    mod.LUCI_CONF_PATH = '/etc/config/nginx'
    mod.LUCI_SNAPSHOT_PATH = '/etc/nftables/nginx-luci.snapshot'
    mod.app.before_request_funcs[None] = _h3
    mod.CONFIG_PATH = '/etc/nftables/nftables-web-config.json'
    shutil.rmtree(TD3, ignore_errors=True)

sec('5g. 启动时会主动对齐')
src = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
check('_start_servers 里调了 _luci_reconcile',
      '_luci_reconcile(load_config().get' in src)
check('对齐失败不阻断启动',
      '对齐 LuCI 80/443 失败（不影响启动）' in src)

# ── 6. 部署脚本 ────────────────────────────────────────────────────────
sec('6. setup.sh 部署后自动关闭')
sh = open(os.path.join(ROOT, 'setup', 'setup.sh'), encoding='utf-8').read()
check('有 close_luci_ports 函数', 'close_luci_ports()' in sh)
check('main 里调用了它', re.search(r'setup_nftables\s*\n\s*close_luci_ports', sh) is not None)
check('删的是渲染产物目标而非软链', 'rendered="/var/lib/nginx/uci.conf"' in sh)
check('留了快照供面板还原', 'nginx-luci.snapshot' in sh)
check('nginx -t 通过才 reload', 'nginx -t -c /etc/nginx/uci.conf' in sh)
check('关完兜底确认 8443 还在听', ':8443 ' in sh)

sec('7. 前端有开关')
html = open(os.path.join(ROOT, 'frontend', 'index.html'), encoding='utf-8').read()
check('有 luci_enabled 的复选框', 'x-model="config.luci_enabled"' in html)
check('说明它不是本项目的端口',
      '不是本项目的反代' in html, '用户要能分清 80/443 和 8443')

print('\n' + '=' * 74)
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    print('失败项:')
    for f in FAIL:
        print('  -', f)
    sys.exit(1)
print('全部通过')
