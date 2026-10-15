"""trusted_ip4 单值语义 —— 回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_trusted_ip_single.py

背景（.224 真机实测，2026-10-15）：

    配置   trusted_ip4 = ['192.168.100.224', '192.168.100.1', '192.168.100.249']
    规则   define TRUSTED_IP4 = 192.168.100.224          ← 只剩第一个
    前端   <input x-model="config.trusted_ip4">          ← 单值输入框

三处口径不一致，而且**没有任何东西提醒用户**：

  · build_rules 走 _safe_ip(..., strict=True)，数组取第一个合法项
  · _detect_risks 走 _ip_set()，按**集合**算 —— 3 个都算「在白名单里」
  · validate_config 逐项校验，3 个都判合法

于是：自锁告警说「你还在白名单里」，而生成的规则里可能根本没有你，
critical 拦不住；另外两个管理机在 policy drop 下被挡在外面且无提示。

断言用行为方式：**拿 config_to_variables 真实展开出来的 TRUSTED_IP4
去比对风险检测用的口径**。两者必须永远一致 —— 这才是这个 bug 的本质。
"""
import importlib.util as ilu
import json
import os
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
    spec = ilu.spec_from_file_location('_nftapp_trust', os.path.join(BACKEND, 'app.py'))
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mod = load_app()


def rules_trusted(cfg_value):
    """真跑 config_to_variables，拿规则里实际展开的 TRUSTED_IP4。"""
    cfg = dict(mod.DEFAULT_CONFIG)
    cfg['trusted_ip4'] = cfg_value
    return mod.config_to_variables(cfg).get('TRUSTED_IP4', '').strip('"')


print('=' * 74)
print('trusted_ip4 单值语义回归测试')
print('=' * 74)

# ── 1. 风险检测口径必须 == 规则实际展开 ─────────────────────────────────
sec('1. _trusted_ip_single 与 build_rules 口径逐项一致')
cases = [
    ('192.168.100.224', '单串'),
    (['192.168.100.224', '192.168.100.1', '192.168.100.249'], '三元素数组（.224 现场）'),
    (['bogus', '192.168.100.9'], '首项非法'),
    (['', '10.0.0.5'], '首项空串'),
    ('192.168.1.1,192.168.1.2', '逗号串（会被 validate_config 400，但口径也要一致）'),
    (None, 'None'),
    ([], '空数组'),
    ('not-an-ip', '非 IP'),
    (['1.2.3.4', '5.6.7.8', '9.10.11.12'], '三元素数组（另一个网段）'),
]
for val, desc in cases:
    eff, _ignored = mod._trusted_ip_single(val)
    got = rules_trusted(val)
    check(f'{desc:24s} 规则={got or "(空)":16s} 单值={eff or "(空)"}',
          got == (eff or ''), f'输入={val!r}')

# ── 2. 多值必须被如实报出来 ────────────────────────────────────────────
sec('2. 多余项被识别（不静默丢弃）')
eff, ign = mod._trusted_ip_single(['192.168.100.224', '192.168.100.1', '192.168.100.249'])
check('生效的是第 1 个', eff == '192.168.100.224', f'实际={eff}')
check('另外两个被列为丢弃',
      ign == ['192.168.100.1', '192.168.100.249'], f'实际={ign}')

sec('3. 风险检测把「多值被丢弃」报成 high')
old = dict(mod.DEFAULT_CONFIG)
old['trusted_ip4'] = ['192.168.100.224', '192.168.100.1', '192.168.100.249']
new = dict(old)
risks = mod._detect_risks(old, new, '192.168.100.224')
multi = [r for r in risks if '只支持一个 IP' in r.get('message', '')]
check('有多值告警', len(multi) == 1, f'risks={[r.get("message") for r in risks]}')
if multi:
    check('等级是 high（不阻止保存，但要让人看见）',
          multi[0].get('level') == 'high', f"level={multi[0].get('level')}")
    check('告警里点名了生效的是哪个',
          '192.168.100.224' in multi[0]['message'])
    check('告警里点名了被丢弃的是哪几个',
          '192.168.100.1' in multi[0]['message']
          and '192.168.100.249' in multi[0]['message'],
          f"msg={multi[0]['message']}")

sec('4. 单值不报多值告警')
one = dict(mod.DEFAULT_CONFIG)
one['trusted_ip4'] = '192.168.100.224'
risks = mod._detect_risks(one, one, '192.168.100.224')
check('没有多值告警',
      not [r for r in risks if '只支持一个 IP' in r.get('message', '')],
      f'risks={[r.get("message") for r in risks]}')

# ── 3. 自锁告警必须按「实际生效的那个」算 ────────────────────────────────
sec('5. 自锁告警：把自己从生效位上挪走才算 critical')
# 旧配置第 1 个是请求者，新配置第 1 个换人 → 真实自锁，必须报 critical
old5 = dict(mod.DEFAULT_CONFIG)
old5['trusted_ip4'] = ['192.168.100.224', '192.168.100.249']
new5 = dict(mod.DEFAULT_CONFIG)
new5['trusted_ip4'] = ['192.168.100.249', '192.168.100.224']
risks = mod._detect_risks(old5, new5, '192.168.100.224')
crit = [r for r in risks if r.get('level') == 'critical']
check('换掉生效位时报 critical 自锁', len(crit) >= 1,
      f'risks={[r.get("message") for r in risks]}')

sec('6. 没换生效位就不该误报自锁（哪怕集合里还有自己）')
old6 = dict(mod.DEFAULT_CONFIG)
old6['trusted_ip4'] = ['192.168.100.249', '192.168.100.224']
new6 = dict(mod.DEFAULT_CONFIG)
new6['trusted_ip4'] = ['192.168.100.224', '192.168.100.249']
risks = mod._detect_risks(old6, new6, '192.168.100.224')
crit = [r for r in risks if r.get('level') == 'critical']
check('集合里虽然还有自己，但生效位没变 → 不报自锁', len(crit) == 0,
      f'risks={[r.get("message") for r in risks]}')
multi6 = [r for r in risks if '只支持一个 IP' in r.get('message', '')]
check('但仍报多值被丢弃', len(multi6) == 1,
      f'risks={[r.get("message") for r in risks]}')

# ── 4. 保存时归一化 ────────────────────────────────────────────────────
sec('7. POST /api/config 保存后落盘是单值字符串')
TD = tempfile.mkdtemp()
CFG = os.path.join(TD, 'config.json')
BACKUP = os.path.join(TD, 'config.json.bak')
base = dict(mod.DEFAULT_CONFIG)
base['wan_if'] = 'eth1'
base['lan_if'] = 'br-lan'
with open(CFG, 'w') as f:
    json.dump(base, f)
with open(BACKUP, 'w') as f:
    json.dump(base, f)
mod.CONFIG_PATH = CFG
_hooks = list(mod.app.before_request_funcs[None])
try:
    mod.app.before_request_funcs[None] = []
    client = mod.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = 9e9
    r = client.post('/api/config', json={
        'trusted_ip4': ['192.168.100.224', '192.168.100.1', '192.168.100.249']})
    body = r.get_json()
    saved = json.load(open(CFG))
    check('保存返回 200', r.status_code == 200, f'status={r.status_code} body={body}')
    check('落盘的 trusted_ip4 是单值字符串',
          saved.get('trusted_ip4') == '192.168.100.224',
          f"落盘={saved.get('trusted_ip4')!r}（类型 {type(saved.get('trusted_ip4')).__name__}）")
    resp_risks = (body.get('data') or {}).get('risks') or body.get('risks') or []
    check('响应里带出了多值告警',
          any('只支持一个 IP' in x.get('message', '') for x in resp_risks),
          f"risks={resp_risks}")
    check('保存后 load_config 读出来也是单值',
          mod.load_config().get('trusted_ip4') == '192.168.100.224')
finally:
    mod.app.before_request_funcs[None] = _hooks
    mod.CONFIG_PATH = '/etc/nftables/nftables-web-config.json'
    # save_config 还会留下 .lock / .tmp，直接 rmtree
    shutil.rmtree(TD, ignore_errors=True)

sec('8. 前端明确写了只支持一个 IP')
html = open(os.path.join(ROOT, 'frontend', 'index.html'), encoding='utf-8').read()
check('输入框附近有「只支持一个 IP」提示',
      '只支持一个 IP' in html)
check('提示说明了多填无效',
      '不会多放行' in html or '只认第一个' in html)

print('\n' + '=' * 74)
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    print('失败项:')
    for f in FAIL:
        print('  -', f)
    sys.exit(1)
print('全部通过')
