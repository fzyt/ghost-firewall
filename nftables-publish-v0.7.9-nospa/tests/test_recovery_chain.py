"""恢复链：坏规则文件必须重建 + basic lockdown 必须能自愈回切。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_recovery_chain.py

背景（.224 真机实测，2026-10-15）：

**问题 1 —— 守卫只看「文件在不在」**

    优先级 1  nft -f RULES_PATH
    优先级 2  按当前配置重新生成   ← 守卫 if not os.path.exists(RULES_PATH)
    优先级 3  nft -f .backup
    优先级 4  basic lockdown

规则文件被截断 / 语法错 / 磁盘满写残时：优先级 1 装不上，优先级 2 的守卫
看到「文件在」→ 整个重建块被跳过 → 直落优先级 3。而 .backup 不是规则文件的
副本，是首次 apply 时 `nft list ruleset` 的快照：

    99-custom-rules.nft           586 行  2026-10-15  limit 1/minute  2 处
    99-custom-rules.nft.backup    257 行  2026-10-11  limit 1/minute  8 处

那 8 处正是 78a8fb3（敲门限流 burst 必须容得下一整轮序列）修掉的老 bug
——落回 backup 等于把「敲门从来没敲通过」又装回去。

**问题 2 —— 降级态是单向门**

`_ruleset_is_functional()` 的判据：表在 + 有 hook input + 有 policy drop +
是 filter hook。`_apply_basic_lockdown()` 生成的规则**四条全满足**。
所以 basic lockdown 一生效，看门狗就认为「防火墙正常」，永远不再切回 ——
敲门没了、端口转发没了、黑名单没了，只能人工点「应用规则」或重启。

断言一律用行为断言（真调函数、把桩的调用记录抓下来看），不用源码正则。
"""
import importlib.util as ilu
import json
import os
import shutil
import subprocess
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
    spec = ilu.spec_from_file_location('_nftapp_recov', os.path.join(BACKEND, 'app.py'))
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mod = load_app()


class _Proc:
    def __init__(self, stdout='', rc=0):
        self.stdout = stdout
        self.stderr = ''
        self.returncode = rc


FULL_TABLE = '''table inet fw4 {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tiifname "br-lan" jump input_lan
\t\tiifname "eth1" jump input_wan
\t\tlimit rate 2/minute burst 5 packets drop
\t}
\tchain input_lan {
\t\taccept
\t}
\tchain input_wan {
\t\tiifname "eth1" log prefix "[X] " drop
\t\tmeta nfproto ipv4 drop
\t}
}
'''

# 降级后的真实形态：input_wan 链仍然存在（nft 追加语义，孤儿链留着），
# 但 input 链里已经没有 jump input_wan 了 —— 这才是判别标志。
LOCKDOWN_TABLE = '''table inet fw4 {
\tchain input {
\t\ttype filter hook input priority 0; policy drop;
\t\tiifname "lo" accept
\t\tct state established,related accept
\t\tiifname "br-lan" tcp dport { 22, 5443 } accept
\t\tiifname "br-lan" accept
\t}
\tchain input_wan {
\t\tiifname "eth1" log prefix "[X] " drop
\t}
\tchain forward {
\t}
\tchain output {
\t}
}
'''


def with_ntable(mod_obj, table_text, rc=0):
    """让 `nft list table inet fw4` 返回指定内容。"""
    def fake_run(cmd, *a, **kw):
        if isinstance(cmd, (list, tuple)) and 'fw4' in [str(x) for x in cmd]:
            return _Proc(table_text, rc)
        return _Proc('')
    orig = mod_obj.subprocess.run
    mod_obj.subprocess.run = fake_run
    return orig


print('=' * 74)
print('恢复链回归测试')
print('=' * 74)

# ═══════════════════ 问题 1：坏文件必须重建 ═══════════════════
sec('1. 规则文件存在但装不上 → 必须走「按配置重建」，不能落 .backup')

TD = tempfile.mkdtemp()
RULES = os.path.join(TD, '99-custom-rules.nft')
BACKUP = RULES + '.backup'
CFG = os.path.join(TD, 'config.json')
with open(RULES, 'w') as f:
    f.write('table inet fw4 { chain input { type filter hook input pr')  # 被截断
with open(BACKUP, 'w') as f:
    f.write('table inet fw4 { chain input { type filter hook input priority filter; policy drop; } }')
with open(CFG, 'w') as f:
    json.dump(dict(mod.DEFAULT_CONFIG, wan_if='eth1', lan_if='br-lan'), f)

calls = {'apply_ruleset': 0, 'tried': [], 'lockdown': 0}
orig = (mod.RULES_PATH, mod.CONFIG_PATH, mod._ruleset_is_empty,
        mod._try_apply_rules_file, mod._apply_ruleset,
        mod._config_corrupted, mod.load_config, mod._apply_basic_lockdown)
mod.RULES_PATH = RULES
mod.CONFIG_PATH = CFG
mod._ruleset_is_empty = lambda: True
mod._try_apply_rules_file = lambda p: (calls['tried'].append(p), False)[1]
mod._apply_ruleset = lambda cfg: (calls.__setitem__('apply_ruleset',
                                                     calls['apply_ruleset'] + 1),
                                  (True, '规则已应用'))[1]
mod._config_corrupted = lambda: (False, '')
mod.load_config = lambda *a, **kw: dict(mod.DEFAULT_CONFIG)
mod._apply_basic_lockdown = lambda *a, **kw: (calls.__setitem__('lockdown',
                                                               calls['lockdown'] + 1),
                                              True)[1]
try:
    mod._auto_recover_ruleset_if_empty()
finally:
    (mod.RULES_PATH, mod.CONFIG_PATH, mod._ruleset_is_empty,
     mod._try_apply_rules_file, mod._apply_ruleset,
     mod._config_corrupted, mod.load_config, mod._apply_basic_lockdown) = orig

check('规则文件坏掉时确实尝试过装它', RULES in calls['tried'], f"tried={calls['tried']}")
check('坏掉后按当前配置重建被调用了一次',
      calls['apply_ruleset'] == 1, f"_apply_ruleset 调用 {calls['apply_ruleset']} 次")
check('没有落回 .backup（那会带回 4 天前的规则和已修的敲门 bug）',
      BACKUP not in calls['tried'], f"tried={calls['tried']}")
check('坏文件被留存为 .corrupted 供事后排查',
      os.path.exists(RULES + '.corrupted'),
      '重建会覆盖 RULES_PATH，不留证据就查不出是被谁改坏的')

sec('2. 规则文件坏掉 + 配置也坏 → 拒绝重建，但不能落 .backup')
TD2 = tempfile.mkdtemp()
RULES2 = os.path.join(TD2, 'r.nft')
BACKUP2 = RULES2 + '.backup'
CFG2 = os.path.join(TD2, 'c.json')
with open(RULES2, 'w') as f:
    f.write('garbage')
with open(BACKUP2, 'w') as f:
    f.write(FULL_TABLE)
with open(CFG2, 'w') as f:
    f.write('{ this is not json')

calls2 = {'apply_ruleset': 0, 'tried': []}
orig = (mod.RULES_PATH, mod.CONFIG_PATH, mod._ruleset_is_empty,
        mod._try_apply_rules_file, mod._apply_ruleset,
        mod._config_corrupted, mod.load_config)
mod.RULES_PATH = RULES2
mod.CONFIG_PATH = CFG2
mod._ruleset_is_empty = lambda: True
mod._try_apply_rules_file = lambda p: (calls2['tried'].append(p), p == BACKUP2)[1]
mod._apply_ruleset = lambda cfg: (calls2.__setitem__('apply_ruleset', 1), (True, ''))[1]
mod._config_corrupted = lambda: (True, 'JSON 解析失败')
mod.load_config = lambda *a, **kw: dict(mod.DEFAULT_CONFIG)
try:
    mod._auto_recover_ruleset_if_empty()
finally:
    (mod.RULES_PATH, mod.CONFIG_PATH, mod._ruleset_is_empty,
     mod._try_apply_rules_file, mod._apply_ruleset,
     mod._config_corrupted, mod.load_config) = orig
check('配置损坏时没有拿 DEFAULT_CONFIG 重建',
      calls2['apply_ruleset'] == 0, f"调用 {calls2['apply_ruleset']} 次")
check('配置损坏时退到 .backup', BACKUP2 in calls2['tried'], f"tried={calls2['tried']}")

sec('3. 配置文件整个不在 → 仍然绝不按配置重建')
TD3 = tempfile.mkdtemp()
RULES3 = os.path.join(TD3, 'r.nft')
BACKUP3 = RULES3 + '.backup'
with open(RULES3, 'w') as f:
    f.write('garbage')
with open(BACKUP3, 'w') as f:
    f.write(FULL_TABLE)
calls3 = {'apply_ruleset': 0}
orig = (mod.RULES_PATH, mod.CONFIG_PATH, mod._ruleset_is_empty,
        mod._try_apply_rules_file, mod._apply_ruleset, mod._config_corrupted)
mod.RULES_PATH = RULES3
mod.CONFIG_PATH = os.path.join(TD3, 'nope.json')
mod._ruleset_is_empty = lambda: True
mod._try_apply_rules_file = lambda p: p == BACKUP3
mod._apply_ruleset = lambda cfg: (calls3.__setitem__('apply_ruleset', 1), (True, ''))[1]
mod._config_corrupted = lambda: (False, '')
try:
    mod._auto_recover_ruleset_if_empty()
finally:
    (mod.RULES_PATH, mod.CONFIG_PATH, mod._ruleset_is_empty,
     mod._try_apply_rules_file, mod._apply_ruleset, mod._config_corrupted) = orig
check('配置缺失时没有按 DEFAULT_CONFIG 重建',
      calls3['apply_ruleset'] == 0)

# ═══════════════════ 问题 2：降级态必须能自愈 ═══════════════════
sec('4. _ruleset_is_degraded 能区分完整规则集与 basic lockdown')

orig = with_ntable(mod, FULL_TABLE)
try:
    d, det = mod._ruleset_is_degraded()
finally:
    mod.subprocess.run = orig
check('input 链仍 jump input_wan → 不是降级态', d is False, f'detail={det}')

orig = with_ntable(mod, LOCKDOWN_TABLE)
try:
    d, det = mod._ruleset_is_degraded()
finally:
    mod.subprocess.run = orig
check('input 链已无 jump input_wan → 是降级态（哪怕 input_wan 链还在）',
      d is True, f'detail={det}')

orig = with_ntable(mod, '', rc=1)
try:
    d, det = mod._ruleset_is_degraded()
finally:
    mod.subprocess.run = orig
check('表不存在 → 不算降级（那是「空」，走四级恢复链）', d is False, f'detail={det}')

sec('5. basic lockdown 生效时 _ruleset_is_functional 仍然是 True（这正是问题根源）')
orig = with_ntable(mod, LOCKDOWN_TABLE)
try:
    f, fd = mod._ruleset_is_functional()
finally:
    mod.subprocess.run = orig
check('functional=True', f is True, f'detail={fd}')
check('→ 所以光靠 functional 判断会漏掉降级态', f is True,
      '这正是必须补 degraded 判据的原因')

sec('6. 降级态下 _recover_ruleset_if_unhealthy 会尝试切回完整规则集')
state = {'degraded': True}
tried6 = []
orig = (mod._ruleset_is_functional, mod._ruleset_is_degraded,
        mod._try_apply_rules_file, mod._FW_APPLY_LOCK,
        mod._WATCHDOG, mod.os.path.exists)


def _fake_apply6(p):
    """装上完整规则集后，degraded 状态必须跟着翻转"""
    tried6.append(p)
    state['degraded'] = False
    return True


mod._ruleset_is_functional = lambda: (True, '正常')
mod._ruleset_is_degraded = lambda: (
    (True, 'basic lockdown') if state['degraded'] else (False, '完整规则集'))
mod._try_apply_rules_file = _fake_apply6
_wd = dict(mod._WATCHDOG)
_wd['promote_fails'] = 0
mod._WATCHDOG = _wd
mod.os.path.exists = lambda p: True
try:
    acted, msg = mod._recover_ruleset_if_unhealthy()
finally:
    (mod._ruleset_is_functional, mod._ruleset_is_degraded,
     mod._try_apply_rules_file, mod._FW_APPLY_LOCK,
     mod._WATCHDOG, mod.os.path.exists) = orig
check('尝试加载了 RULES_PATH',
      mod.RULES_PATH in tried6, f'tried={tried6}')
check('没有去动 .lastgood（第一个就成功了）', '.lastgood' not in ' '.join(tried6))
check('报告为已切回', acted is True and '切回' in msg, f'acted={acted} msg={msg}')

sec('7. 完整规则集时不打扰（不重复 nft -f）')
tried7 = []
orig = (mod._ruleset_is_functional, mod._ruleset_is_degraded,
        mod._try_apply_rules_file, mod._WATCHDOG)
mod._ruleset_is_functional = lambda: (True, '正常')
mod._ruleset_is_degraded = lambda: (False, '完整规则集')
mod._try_apply_rules_file = lambda p: (tried7.append(p), True)[1]
try:
    acted, msg = mod._recover_ruleset_if_unhealthy()
finally:
    (mod._ruleset_is_functional, mod._ruleset_is_degraded,
     mod._try_apply_rules_file, mod._WATCHDOG) = orig
check('不加载任何规则文件', tried7 == [], f'tried={tried7}')
check('返回「正常」且未动手', acted is False and msg == '正常', f'msg={msg}')

sec('8. 规则文件连续装不上 → 到上限就停手，不无限抖动')
fails8 = []
orig = (mod._ruleset_is_functional, mod._ruleset_is_degraded,
        mod._try_apply_rules_file, mod._WATCHDOG, mod.os.path.exists,
        mod.FW_WATCHDOG_COOLDOWN)
mod._ruleset_is_functional = lambda: (True, '正常')
mod._ruleset_is_degraded = lambda: (True, 'basic lockdown')
mod._try_apply_rules_file = lambda p: (fails8.append(p), False)[1]
_wd8 = dict(mod._WATCHDOG)
_wd8['promote_fails'] = 0
mod._WATCHDOG = _wd8
mod.os.path.exists = lambda p: True
try:
    msgs = []
    MAXF = mod._PROMOTE_MAX_FAILS
    for i in range(MAXF + 2):
        acted, msg = mod._recover_ruleset_if_unhealthy()
        msgs.append(msg)
finally:
    (mod._ruleset_is_functional, mod._ruleset_is_degraded,
     mod._try_apply_rules_file, mod._WATCHDOG, mod.os.path.exists,
     mod.FW_WATCHDOG_COOLDOWN) = orig
check(f'前 {MAXF} 次确实在重试',
      len([m for m in msgs if '规则文件不可用' in m]) == MAXF,
      f'消息={msgs}')
check('超过上限后停止重试',
      any('已停止自动重试' in m for m in msgs), f'消息={msgs}')
check('上限确实是 3', MAXF == 3)

sec('9. _watchdog_tick 在降级态下会走切回逻辑')
wd9 = dict(mod._WATCHDOG)
wd9['promote_fails'] = 0
hit9 = []
st9 = {'degraded': True}
orig = (mod._ruleset_is_functional, mod._ruleset_is_degraded,
        mod._try_apply_rules_file, mod._WATCHDOG, mod.os.path.exists,
        mod._fw_watchdog_settings)


def _fake_apply9(p):
    hit9.append(p)
    st9['degraded'] = False
    return True


mod._ruleset_is_functional = lambda: (True, '正常')
mod._ruleset_is_degraded = lambda: (
    (True, 'basic lockdown') if st9['degraded'] else (False, '完整规则集'))
mod._try_apply_rules_file = _fake_apply9
mod._WATCHDOG = wd9
mod.os.path.exists = lambda p: True
mod._fw_watchdog_settings = lambda: (True, 300)
try:
    acted = mod._watchdog_tick()
    last = mod._WATCHDOG['last_result']
finally:
    (mod._ruleset_is_functional, mod._ruleset_is_degraded,
     mod._try_apply_rules_file, mod._WATCHDOG, mod.os.path.exists,
     mod._fw_watchdog_settings) = orig
check('tick 触发了切回', acted is True, f'last_result={last}')
check('tick 的 last_result 反映切回而不是「正常」',
      '切回' in last, f'last_result={last}')

sec('10. /api/rules/health 会暴露降级态')
health_src = None
with_ntable(mod, LOCKDOWN_TABLE)
_hooks_saved = list(mod.app.before_request_funcs[None])
try:
    mod.app.before_request_funcs[None] = []      # 全局鉴权钩子放行（与 test_fw_recovery 同法）
    client = mod.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = 9e9
    r = client.get('/api/rules/health')
    check('健康接口返回 200', r.status_code == 200, f'status={r.status_code}')
    health_src = r.get_json()
except Exception as e:
    check('健康接口可调用', False, repr(e))
finally:
    mod.app.before_request_funcs[None] = _hooks_saved
    mod.subprocess.run = subprocess.run
if health_src:
    data = health_src.get('data', {})
    check('接口返回 ruleset_degraded=True',
          data.get('ruleset_degraded') is True, f'data.degraded={data.get("ruleset_degraded")}')
    check('接口返回降级原因', 'input_wan' in str(data.get('degraded_detail', '')),
          f'detail={data.get("degraded_detail")}')
    check('watchdog 块带 promote_fails',
          'promote_fails' in data.get('watchdog', {}),
          f"watchdog keys={sorted(data.get('watchdog', {}).keys())}")

sec('11. basic lockdown 真的先 flush 再装（追加语义下不 flush 等于没降级）')
# .224 真机实测：nft -f 的 `table X { chain Y { ... } }` 块是**追加**语义。
# 完整规则集已经生效时装 lockdown，input 链从 30 条变 31 条，原有 30 条一条
# 没少，`jump input_wan` 还在 —— 所谓降级什么都没降，优先级 4 形同虚设。
# 项目自己的规则文件开头就是 `flush ruleset`，同一个道理。
calls11 = []
orig = (mod.subprocess.run, mod._ruleset_is_empty, mod.load_config,
        mod._interface_exists, mod._input_chain_still_references_wan)


def _fake_run11(cmd, *a, **kw):
    calls11.append(list(cmd) if isinstance(cmd, (list, tuple)) else cmd)
    return _Proc('')


mod.subprocess.run = _fake_run11
mod._ruleset_is_empty = lambda: False
mod._interface_exists = lambda n: True
mod._input_chain_still_references_wan = lambda: False
mod.load_config = lambda *a, **kw: dict(mod.DEFAULT_CONFIG, lan_if='br-lan')
try:
    ok11 = mod._apply_basic_lockdown()
finally:
    (mod.subprocess.run, mod._ruleset_is_empty, mod.load_config,
     mod._interface_exists, mod._input_chain_still_references_wan) = orig

flush_idx = next((i for i, c in enumerate(calls11)
                  if c[:3] == ['nft', 'flush', 'table']), -1)
apply_idx = next((i for i, c in enumerate(calls11)
                  if c[:2] == ['nft', '-f']), -1)
check('确实执行了 nft flush table ...',
      flush_idx >= 0, f'调用序列={calls11}')
check('flush 排在 nft -f 之前',
      flush_idx >= 0 and apply_idx > flush_idx,
      f'flush@{flush_idx} apply@{apply_idx}')
check('flush 的是 inet fw4（不掀掉 nat 等别人的表）',
      calls11[flush_idx][:5] == ['nft', 'flush', 'table', 'inet', 'fw4'] if flush_idx >= 0 else False,
      f'实际={calls11[flush_idx] if flush_idx >= 0 else "（没执行）"}')
check('降级成功返回 True', ok11 is True)

sec('12. 装完 input 链仍引用 input_wan → 判失败（不能谎报「已降级」）')
calls12 = []
orig = (mod.subprocess.run, mod._ruleset_is_empty, mod.load_config,
        mod._interface_exists, mod._input_chain_still_references_wan)
mod.subprocess.run = lambda cmd, *a, **kw: (
    calls12.append(list(cmd) if isinstance(cmd, (list, tuple)) else cmd), _Proc(''))[1]
mod._ruleset_is_empty = lambda: False
mod._interface_exists = lambda n: True
mod._input_chain_still_references_wan = lambda: True      # 装完仍在引用
mod.load_config = lambda *a, **kw: dict(mod.DEFAULT_CONFIG, lan_if='br-lan')
try:
    ok12 = mod._apply_basic_lockdown()
finally:
    (mod.subprocess.run, mod._ruleset_is_empty, mod.load_config,
     mod._interface_exists, mod._input_chain_still_references_wan) = orig
check('判为失败而不是谎报成功', ok12 is False, f'返回={ok12}')

for d in (TD, TD2, TD3):
    shutil.rmtree(d, ignore_errors=True)

print('\n' + '=' * 74)
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    print('失败项:')
    for f in FAIL:
        print('  -', f)
    sys.exit(1)
print('全部通过')
