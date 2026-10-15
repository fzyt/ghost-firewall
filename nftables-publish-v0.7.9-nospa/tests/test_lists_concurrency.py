"""P0-A / P0-B 的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_lists_concurrency.py

  P0-A  /api/gateway/config 不得拒绝合法布尔字段
        原写法 `isinstance(v, bool) or (k.endswith(...) and ...)` 把 isinstance 放在
        or 左边、不受字段名约束，于是 gateway_enabled / auth_lan_bypass 一律 400。
        「保存网关配置」按钮从 v0.8.0 落地起就没成功过（f2dfa43 引入）。

  P0-B  名单落盘的并发安全
        save_lists 用固定 tmp 路径 + 无锁，而「全部清空」是前端 Promise.all 并发发
        allowed4 / allowed6 两个请求。实测真机 2/2 稳定 400，本地 300 轮复现
        186 次 FileNotFoundError、150 次清空后残留、偶发残缺 JSON。

  P0-C  e2e_buttons.js 的错误归因
        runClick 读 report.errors，而它在 runClick 返回之后才被赋值 → 恒为空 →
        任何 HTTP>=400 都不算失败。上一轮 20 个真实 400 全被记成 91 个 ✅。

每条断言都写成「旧代码必然失败」。沙箱运行：名单路径重定向到 tmpdir，
网关的 nginx 下发与 nft 下发全部打桩，不碰真实路径、不执行外部命令。
"""
import importlib.util as ilu
import json
import os
import re
import sys
import tempfile
import threading

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
E2E_SRC = open(os.path.join(ROOT, 'tests', 'e2e_buttons.js'), encoding='utf-8').read()


def load_app():
    spec = ilu.spec_from_file_location('_nftapp_lists', os.path.join(BACKEND, 'app.py'))
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ══════════════════════════════════════════════════════════════════
# P0-A  网关布尔字段
# ══════════════════════════════════════════════════════════════════
sec('P0-A /api/gateway/config 必须接受合法布尔字段')

mod = load_app()
app = mod.app
# 全局认证拦截器会让 test_client 直接 401，这里只测校验逻辑，摘掉它
app.before_request_funcs = {}
# nginx 下发 / nft 下发全部打桩，避免碰真实系统
_deploy = mod._deploy_gateway_nginx
_apply = mod._apply_ruleset
_saved = mod.save_config
mod._deploy_gateway_nginx = lambda cfg: (True, 'stub')
mod._apply_ruleset = lambda cfg: (True, 'stub')
mod.save_config = lambda cfg, **kw: None
# 开启网关时后端会校验端口**真的在听**（.224 上出现过「回 200 但 8443 已死」）。
# 这里要断言的是字段校验，所以把实际状态打桩成"网关健在"。
_gw_actual = mod._gateway_actual_state
mod._gateway_actual_state = lambda cfg=None: {
    'nginx_conf_exists': True, 'port': 8443,
    'port_listening': True, 'enabled': True,
}
client = app.test_client()

# 1) 关网关：前端 saveGatewayConfig 恒发 gateway_enabled（app.js:1556）
r = client.post('/api/gateway/config', json={'gateway_enabled': False})
check('gateway_enabled=false 可保存（旧代码此处 400）',
      r.status_code == 200, f'HTTP {r.status_code} {r.get_data(as_text=True)[:90]}')

# 2) 开网关
r = client.post('/api/gateway/config', json={'gateway_enabled': True})
check('gateway_enabled=true 可保存',
      r.status_code == 200, f'HTTP {r.status_code} {r.get_data(as_text=True)[:90]}')

# 3) 另一个合法布尔项
r = client.post('/api/gateway/config', json={'auth_lan_bypass': True})
check('auth_lan_bypass=true 可保存',
      r.status_code == 200, f'HTTP {r.status_code} {r.get_data(as_text=True)[:90]}')

# 4) 数字字段仍然必须挡住 bool —— 这是原写法的本意，不能顺手放掉
r = client.post('/api/gateway/config', json={'gateway_port': True})
check('gateway_port=true 仍被拒（bool 不能冒充数字）',
      r.status_code == 400, f'HTTP {r.status_code} {r.get_data(as_text=True)[:90]}')

r = client.post('/api/gateway/config', json={'gateway_port': 'abc'})
check("gateway_port='abc' 仍被拒（类型非数字）",
      r.status_code == 400, f'HTTP {r.status_code} {r.get_data(as_text=True)[:90]}')

r = client.post('/api/gateway/config', json={'gateway_port': 8443})
check('gateway_port=8443 正常放行',
      r.status_code == 200, f'HTTP {r.status_code} {r.get_data(as_text=True)[:90]}')

# 5) 白名单外的字段仍然拒绝
r = client.post('/api/gateway/config', json={'router_ip4': '1.1.1.1'})
check('白名单外字段仍被拒', r.status_code == 400, f'HTTP {r.status_code}')

mod._deploy_gateway_nginx = _deploy
mod._apply_ruleset = _apply
mod.save_config = _saved
mod._gateway_actual_state = _gw_actual


# ══════════════════════════════════════════════════════════════════
# P0-B  名单并发
# ══════════════════════════════════════════════════════════════════
sec('P0-B 名单落盘并发安全（真实并发，非源码正则）')

ROUNDS = 150


def run_race_round(mod, path, lock_path, action):
    """action(set_name) -> None，在两个线程里并发调用，返回 (异常列表, 最终文件内容)"""
    mod.LISTS_PATH = path
    mod.LISTS_LOCK_PATH = lock_path
    errs = []
    barrier = threading.Barrier(2)

    def worker(name):
        try:
            barrier.wait(timeout=5)   # 尽量让两个线程真正撞在一起
            action(name)
        except Exception as e:      # noqa: BLE001
            errs.append(f'{type(e).__name__}: {e}')

    ts = [threading.Thread(target=worker, args=(n,)) for n in ('allowed4', 'allowed6')]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=15)
    with open(path) as f:
        raw = f.read()
    return errs, raw


with tempfile.TemporaryDirectory() as td:
    path = os.path.join(td, 'lists.json')
    lock_path = path + '.lock'
    seed = {n: [] for n in sorted(mod.VALID_SET_NAMES)}
    seed['allowed4'] = ['203.0.113.66']

    # --- 场景 1：并发清空（= 前端「全部清空」的 Promise.all）
    errors_seen, corrupt_seen, residue_seen = {}, 0, 0
    for _ in range(ROUNDS):
        with open(path, 'w') as f:
            json.dump(seed, f)
        errs, raw = run_race_round(
            mod, path, lock_path,
            lambda n: mod._mutate_lists(n, clear=True))
        for e in errs:
            key = e.split(':')[0]
            errors_seen[key] = errors_seen.get(key, 0) + 1
        try:
            d = json.loads(raw)
            if d['allowed4'] or d['allowed6']:
                residue_seen += 1
        except json.JSONDecodeError:
            corrupt_seen += 1

    check(f'并发清空 {ROUNDS} 轮无一抛异常（旧代码 FileNotFoundError）',
          not errors_seen, f'出现 {errors_seen}' if errors_seen else '0 次')
    check(f'并发清空 {ROUNDS} 轮文件始终是合法 JSON',
          corrupt_seen == 0, f'损坏 {corrupt_seen} 轮')
    check(f'并发清空 {ROUNDS} 轮磁盘无残留',
          residue_seen == 0, f'残留 {residue_seen} 轮')

    # --- 场景 2：并发加不同 IP 到不同 set，不能丢更新
    lost = 0
    for _ in range(ROUNDS):
        with open(path, 'w') as f:
            json.dump({n: [] for n in sorted(mod.VALID_SET_NAMES)}, f)
        ips = {'allowed4': '198.51.100.10', 'allowed6': '2001:db8::10'}
        errs, raw = run_race_round(
            mod, path, lock_path,
            lambda n: mod._mutate_lists(n, add=[ips[n]]))
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            lost += 1
            continue
        if '198.51.100.10' not in d['allowed4'] or '2001:db8::10' not in d['allowed6']:
            lost += 1
    check(f'并发写入 {ROUNDS} 轮无丢失更新',
          lost == 0, f'丢失/损坏 {lost} 轮')


# ══════════════════════════════════════════════════════════════════
# P0-C  e2e 归因
# ══════════════════════════════════════════════════════════════════
sec('P0-C e2e_buttons.js 必须把 HTTP>=400 算作失败')

m = re.search(r'async function runClick\([^)]*\)', E2E_SRC)
check('runClick 签名接收 errors 参数', bool(m) and 'errors' in m.group(0),
      m.group(0) if m else '未找到')
check('runClick 内部不再读 report.errors（那是恒空的死数组）',
      not re.search(r'const before = report\.errors', E2E_SRC),
      'report.errors 归因已清除' if not re.search(r'const before = report\.errors', E2E_SRC)
      else '仍从 report.errors 取归因窗口')
check('点击调用已传入共享 errors 数组',
      bool(re.search(r'runClick\(page,\s*errors\)', E2E_SRC)))
check('>=400 监听会补响应体（报告能直接看出是哪个校验拦的）',
      bool(re.search(r'entry\.body', E2E_SRC)))

# ══════════════════════════════════════════════════════════════════
# P0-D  网关设置表单必须真能从 status 端点载入
# ══════════════════════════════════════════════════════════════════
sec('P0-D loadGatewayStatus 的字段名必须和 /api/gateway/status 对得上')

FE_JS = open(os.path.join(ROOT, 'frontend', 'app.js'), encoding='utf-8').read()
m = re.search(r'async loadGatewayStatus\(\) \{.*?\n    \},', FE_JS, re.S)
fn = m.group(0) if m else ''
check('能定位到 loadGatewayStatus 函数体', bool(fn), f'{len(fn)} 字符')

# 后端实际返回的键（行为验证：真的打一次端点）
r = client.get('/api/gateway/status')
body = r.get_json() or {}
data = body.get('data') or body
keys = set(data) if isinstance(data, dict) else set()
check('/api/gateway/status 可用且返回 data', r.status_code == 200 and bool(keys),
      f'HTTP {r.status_code} keys={sorted(keys)}')

# 后端有的每个设置键，前端都必须认得（否则表单停在默认值）
NEEDED = {
    'enabled': 'gw.gateway_enabled',
    'gateway_port': 'gw.gateway_port',
    'session_timeout': 'gw.auth_session_timeout',
    'absolute_timeout': 'gw.auth_absolute_timeout',
    'lan_bypass': 'gw.auth_lan_bypass',
}
for backend_key, frontend_field in NEEDED.items():
    if backend_key not in keys:
        continue
    # 键可以以 g.<key> 点号访问，也可以出现在 pick('<key>', ...) 的候选名里
    hit = (f'.{backend_key}' in fn) or (f"'{backend_key}'" in fn)
    check(f'前端能识别后端键 {backend_key!r} → {frontend_field}',
          hit,
          '已识别' if hit else 'loadGatewayStatus 完全没引用该键')

# 旧前端读的四个错配键名不该再被单独使用
check('不再裸读 g.gateway_enabled（后端没有这个键）',
      'g.gateway_enabled !== undefined' not in fn)
check('不再裸读 g.auth_session_timeout（后端没有这个键）',
      'g.auth_session_timeout !== undefined' not in fn)
check('不再裸读 g.auth_absolute_timeout（后端没有这个键）',
      'g.auth_absolute_timeout !== undefined' not in fn)

# 端点键名与前端引用必须真的对得上，而不是各写各的
check('后端 status 的键名集合已记录（防再次漂移）',
      keys >= {'enabled', 'gateway_port', 'session_timeout', 'absolute_timeout', 'lan_bypass'},
      f'实际 {sorted(keys)}')

print(f'\n{"=" * 60}')
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    for f in FAIL:
        print('  ❌ ' + f)
    sys.exit(1)
print('全部通过')
