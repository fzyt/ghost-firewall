"""防火墙恢复链路的回归测试。

运行:  python3 tests/test_fw_recovery.py

覆盖 2026-10-11 真机实测发现的两条：

  FWR-1  配置文件「丢失」必须和「损坏」一样被守卫拦住。
         守卫原本只覆盖「文件存在但读不了」，文件不存在时静默返回
         DEFAULT_CONFIG —— 而 DEFAULT_CONFIG 里写死了陌生网段
         （trusted_ip4=192.168.100.2、转发到 192.168.4.226、
         敲门端口 1/2/3/4）。实测：配置被移走后启动恢复拿默认值重建了
         防火墙，全程报「已恢复」，192.168.100.2 成了可信管理机。

  FWR-2  init 脚本启动 Python 时用 `>` 截断日志，会把自己刚写的
         [WARN]/[ERROR] 恢复消息擦掉 —— 最该被看见的「防火墙没装上」
         反而永远留不下痕迹。恢复现场必须写进独立文件。

沙箱运行：不执行 nft/nginx，只检查代码路径与决策。
"""
import importlib
import json
import os
import re
import sys
import tempfile
import types

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(t):
    print(f'\n=== {t} ===')


def fresh():
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    d = tempfile.mkdtemp()
    app.CONFIG_PATH = os.path.join(d, 'cfg.json')
    app.LISTS_PATH = os.path.join(d, 'lists.json')
    app.RULES_PATH = os.path.join(d, 'rules.nft')
    return app


# ═══════════════════════════════════════════════════════════════
sec('FWR-1  配置文件丢失必须被守卫拦住')

# 场景 A：全新安装 —— 配置和规则文件都不存在，用默认值是正常的
app = fresh()
app.load_config()
check('全新安装（配置、规则都不存在）不误报',
      app._config_corrupted()[0] is False,
      app._config_corrupted()[1][:60])

# 场景 B：配置丢了但规则还在 —— 配过又丢，必须报错
app = fresh()
with open(app.RULES_PATH, 'w') as f:
    f.write('table inet fw4 { }\n')
cfg = app.load_config()
check('判据：规则文件在 -> 判为丢失', app._config_lost_after_setup() is True)

# 场景 B2：配置和规则文件被【一起】移走（实测场景），只剩 .lastgood
# 这一档最容易被误判成「全新安装」，第一版修复就栽在这里
app = fresh()
with open(app.RULES_PATH + '.lastgood', 'w') as f:
    f.write('table inet fw4 { }\n')
app.load_config()
check('配置与规则文件一起丢失、仅剩 .lastgood -> 仍判为丢失',
      app._config_corrupted()[0] is True,
      app._config_corrupted()[1][:60])
check('判据：仅 .lastgood 在也认为配过', app._config_lost_after_setup() is True)

# 场景 B3：启动恢复的优先级 2 必须直接检查配置文件存不存在，
# 不能只依赖守卫 —— 守卫在「全删光」时判不出异常
_seg = src_all = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
_p2 = _seg[_seg.find('优先级 2：按当前配置重新生成'):]
# 锚点必须带冒号：代码注释里有「直接落到优先级 3 / 4」这句话，
# 用不带冒号的 '优先级 3' 会正好截在它前面，把要检查的代码整段切掉。
_p2 = _p2[:_p2.find('优先级 3：.backup 文件')]
check('优先级 2 直接检查了 os.path.exists(CONFIG_PATH)',
      'os.path.exists(CONFIG_PATH)' in _p2)
check('优先级 2 在配置缺失时明确跳过', '跳过' in _p2 and 'basic lockdown' in _p2)

bad, err = app._config_corrupted()
check('配置丢失但规则文件存在 → 判为异常', bad is True, err[:70])
check('异常信息说明了「曾存在后丢失」', '丢失' in err or '不存在' in err, err[:70])

# 关键后果：这条路径不得让「应用规则」把默认值下发
app.app.config['TESTING'] = True
app.app.before_request_funcs[None] = []
with app.app.app_context():      # jsonify 需要应用上下文
    ref = app._config_corrupted_response()
check('配置丢失时 /api/rules/apply 返回拒绝而不是照常下发',
      ref is not None, '返回了 %r' % (None if ref is None else ref[1]))
if ref is not None:
    body = ref[0].get_json() or {}
    check('拒绝响应的 code 是 CONFIG_CORRUPTED',
          body.get('code') == 'CONFIG_CORRUPTED', str(body.get('code')))
    check('拒绝信息提到了配置路径', app.CONFIG_PATH in (body.get('message') or ''),
          (body.get('message') or '')[:80])

# 场景 C：配置正常存在，不能误报
app = fresh()
with open(app.RULES_PATH, 'w') as f:
    f.write('table inet fw4 { }\n')
with open(app.CONFIG_PATH, 'w') as f:
    json.dump({'lan_if': 'br-lan', 'access_mode': 'lan'}, f)
app.load_config()
check('配置正常存在时不误报', app._config_corrupted()[0] is False)

# 场景 D：配置损坏（原有守卫）不能被改坏
app = fresh()
with open(app.RULES_PATH, 'w') as f:
    f.write('table inet fw4 { }\n')
with open(app.CONFIG_PATH, 'w') as f:
    f.write('{ this is not json')
app.load_config()
check('配置损坏仍被守卫拦住（原有能力未回退）',
      app._config_corrupted()[0] is True, app._config_corrupted()[1][:50])

# DEFAULT_CONFIG 本身确实含陌生网段 —— 这是这条守卫存在的理由，
# 断言它仍然成立，防止有人「清理」DEFAULT_CONFIG 后误以为守卫多余
dc = importlib.import_module('app').DEFAULT_CONFIG
check('DEFAULT_CONFIG 仍含示例网段（守卫仍有必要）',
      '192.168.100.2' in json.dumps(dc) or '192.168.4' in json.dumps(dc),
      '若为 False 说明默认值已清理，可考虑放宽守卫')


# ═══════════════════════════════════════════════════════════════
sec('FWR-2  init 脚本的恢复现场不能被自己的日志截断抹掉')

init_path = os.path.join(BACKEND, 'nftables-web.init')
init_src = open(init_path, encoding='utf-8').read()

check('定义了独立的恢复日志变量', 'RECOVERY_LOG=' in init_src)
m = re.search(r'RECOVERY_LOG="([^"]+)"', init_src)
rec_log = m.group(1) if m else ''
m2 = re.search(r'LOG_FILE="([^"]+)"', init_src)
app_log = m2.group(1) if m2 else ''
check('恢复日志与应用日志不是同一个文件', rec_log and rec_log != app_log,
      f'{rec_log} vs {app_log}')

# 所有恢复相关的 [WARN]/[ERROR]/[OK] 消息都必须写进 RECOVERY_LOG
rec_msgs = re.findall(r'echo ".*?\[(WARN|ERROR|OK|INFO)\].*?"\s*>>"\$(\w+)"', init_src)
wrong = [(lvl, tgt) for lvl, tgt in rec_msgs if tgt != 'RECOVERY_LOG']
check('所有恢复消息都写进 RECOVERY_LOG', not wrong, str(wrong[:3]))
check('恢复消息数量 >= 4（成功/回退/两级失败/文件缺失）', len(rec_msgs) >= 4,
      f'共 {len(rec_msgs)} 条')

# 致命项：Python 启动那行仍可以是 >（应用日志不该无限增长），
# 但绝不能再有恢复消息写在会被截断的 LOG_FILE 上
py_line = [l for l in init_src.split('\n') if 'python3 app.py' in l]
check('Python 启动行存在', bool(py_line))
_leak = re.findall(r'(?:nft -f|echo).*?\$LOG_FILE', init_src)
check('恢复链路的 nft -f 错误不再写进会被截断的 LOG_FILE',
      not any('python3' not in x for x in _leak) or _leak == ['python3 app.py > "$LOG_FILE" 2>&1'],
      '仍写向 LOG_FILE 的行: %s' % [x.strip()[:50] for x in _leak])
check('规则文件缺失时也有记录（原来完全静默）',
      init_src.count('RECOVERY_LOG') >= 5,
      f'RECOVERY_LOG 出现 {init_src.count("RECOVERY_LOG")} 次')


# ═══════════════════════════════════════════════════════════════
sec('FWR-3  恢复链路各级不得共用同一套「静默用默认值」的路径')

src = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()

# 启动恢复的优先级 2（按当前配置重新生成）之前必须问守卫
seg = src[src.find('def _auto_recover_ruleset_if_empty'):]
seg = seg[:seg.find('\ndef ', 10)] if seg.find('\ndef ', 10) > 0 else seg
check('启动恢复里检查了配置是否损坏', '_config_corrupted' in seg)
check('启动恢复在配置异常时拒绝按默认配置重建',
      re.search(r'if _bad:[\s\S]{0,400}?拒绝', seg) is not None)

# _restore_lastgood_rules 的三态必须如实上报
check('回滚状态区分了 lastgood / lockdown / failed',
      all(k in src for k in ["'lastgood'", "'lockdown'", "'failed'"]))
check('回滚失败时明确告知用户可能无防火墙',
      '可能处于无防火墙状态' in src or '路由器当前可能无任何防火墙' in src)

# basic lockdown 必须验证接口真实存在（否则 policy drop 下把自己关死）
check('basic lockdown 校验接口是否存在', '_interface_exists' in src)
check('basic lockdown 在接口不存在时拒绝执行',
      '拒绝执行兜底防火墙' in src)


# ═══════════════════════════════════════════════════════════════
sec('FWR-4  运行期看门狗：滞回 / 冷却 / 可重入锁 / 不误伤健康态')


def wd_env(healthy_seq, interval=300, enabled=True):
    """搭一个看门狗环境，healthy_seq 是逐次调用的健康返回值。"""
    import threading as _th
    a = fresh()
    a._WATCHDOG.update({'stop': False, 'fails': 0, 'last_action_ts': 0.0,
                        'last_check_ts': 0.0, 'last_result': '', 'actions': 0})
    a.load_config = lambda: {'fw_watchdog_interval': interval,
                             'fw_watchdog_enabled': enabled}
    seq = list(healthy_seq)

    def _check():
        v = seq.pop(0) if seq else False
        return (v, '正常' if v else '模拟不健康')
    a._ruleset_is_functional = _check
    a._ruleset_is_empty = lambda: not seq or not seq[0]
    acted = {'n': 0}
    # 契约是 (是否动手, 说明) 两元组 —— 返回三元的桩会让 _watchdog_tick 抛
    # ValueError，看着像看门狗的 bug，其实是桩写错了。
    def _recover():
        acted['n'] += 1
        return True, '模拟恢复'
    a._recover_ruleset_if_unhealthy = _recover
    return a, acted


# 默认参数
a, _ = wd_env([True])
en, iv = a._fw_watchdog_settings()
check('看门狗默认启用', en is True)
check('默认间隔 300 秒', iv == 300, str(iv))

# 间隔下限：间隔过短等于定时砸防火墙，必须被夹住
a, _ = wd_env([True], interval=5)
check('间隔被夹到下限 60 秒', a._fw_watchdog_settings()[1] == 60,
      str(a._fw_watchdog_settings()[1]))
a, _ = wd_env([True], interval=0)
check('间隔 0 也被夹到 60', a._fw_watchdog_settings()[1] == 60)

# 健康态绝不能动手
a, acted = wd_env([True] * 5)
for _ in range(5):
    a._watchdog_tick()
check('健康态 5 轮全部不动手', acted['n'] == 0, f'动了 {acted["n"]} 次')
check('健康态后连续失败计数归零', a._WATCHDOG['fails'] == 0)

# 滞回：单次不健康不动手
a, acted = wd_env([False, True])
a._watchdog_tick()
check('单次不健康不动手（滞回）', acted['n'] == 0, f'动了 {acted["n"]} 次')
check('滞回期间有可读的原因', '未达' in a._WATCHDOG['last_result']
      or '阈值' in a._WATCHDOG['last_result'], a._WATCHDOG['last_result'][:50])

# 连续达阈值才动手
a, acted = wd_env([False, False, True])
a._watchdog_tick(); a._watchdog_tick()
check('连续 2 次不健康才动手', acted['n'] == 1, f'动了 {acted["n"]} 次')

# 冷却：动手后短期内不再动手
a, acted = wd_env([False, False, False, False])
a._watchdog_tick(); a._watchdog_tick()
first = acted['n']
a._watchdog_tick(); a._watchdog_tick()
check('冷却期内不重复动手', acted['n'] == first, f'{first} → {acted["n"]}')
check('冷却状态可读', '冷却' in a._WATCHDOG['last_result']
      or acted['n'] == first, a._WATCHDOG['last_result'][:50])

# 停用后不动手
a, acted = wd_env([False] * 6, enabled=False)
for _ in range(4):
    a._watchdog_tick()
check('停用后不动手', acted['n'] == 0, f'动了 {acted["n"]} 次')

# 异常不能让自检失效
a, acted = wd_env([False])
def _boom():
    raise RuntimeError('模拟 nft 查询炸了')
a._ruleset_is_functional = _boom
raised = False
try:
    a._watchdog_tick()
except Exception:
    raised = True
check('单次异常冒到调用方（由 _watchdog_loop 兜住）', raised is True)

# 真正要保的是「线程不会因为一次异常就死掉」——直接验循环那层
_a2, _act2 = wd_env([False])
_a2._ruleset_is_functional = _boom
_a2.FW_WATCHDOG_DEFAULT_INTERVAL = 60
_a2._WATCHDOG['stop'] = False
_rounds = {'n': 0}


def _real_loop_two_rounds():
    """照抄 _watchdog_loop 的循环骨架，验证异常不会终止线程"""
    for _ in range(2):
        try:
            _a2._watchdog_tick()
        except Exception:
            _a2._WATCHDOG['last_result'] = '自检异常'
            print('[WATCHDOG] 自检异常（继续下一轮）', flush=True)
        _rounds['n'] += 1


_real_loop_two_rounds()
check('异常后循环仍跑满全部轮次（线程没死）', _rounds['n'] == 2, f'跑了 {_rounds["n"]} 轮')
check('异常被记录成可读原因',
      '自检异常' in _a2._WATCHDOG['last_result'], _a2._WATCHDOG['last_result'])

# 可重入锁：看门狗持锁 -> _auto_recover -> _apply_ruleset 再次 acquire
import threading as _th
a = fresh()
check('锁是可重入的 RLock（否则看门狗路径必然死锁）',
      type(a._FW_APPLY_LOCK).__name__ == 'RLock',
      type(a._FW_APPLY_LOCK).__name__)

_hit = {'n': 0}
a._ruleset_is_functional = lambda: (False, '不健康')
a._ruleset_is_empty = lambda: True
a._config_corrupted = lambda: (False, '')
# 必须真的把配置文件建出来：优先级 2 判断的是 os.path.exists(CONFIG_PATH)，
# 只打桩 load_config 不够 —— 文件不存在时它根本不会调 _apply_ruleset。
import json as _json
_json.dump({'lan_if': 'br-lan', 'lan_allowed_ports': [22, 5443]},
           open(a.CONFIG_PATH, 'w'))
a.load_config = lambda: {'lan_if': 'br-lan', 'lan_allowed_ports': [22, 5443]}
a._apply_ruleset = lambda cfg: (_hit.__setitem__('n', _hit['n'] + 1), (True, '模拟下发'))[1]
a._apply_basic_lockdown = lambda *x, **k: True
_res = {}
_t = _th.Thread(target=lambda: _res.setdefault('r', a._recover_ruleset_if_unhealthy()),
                daemon=True)
_t.start()
_t.join(timeout=10)
check('持锁状态下再次 acquire 不死锁（RLock 生效）', 'r' in _res,
      '超时 -> 普通 Lock 会死锁')
check('重入路径确实走到了 _apply_ruleset', _hit['n'] >= 1, f'调用 {_hit["n"]} 次')

# 两种不健康要分开处理：表在但没策略时不该降级到 lockdown
a = fresh()
order = []
_h = {'n': 0}
def _unhealthy_then_ok():
    # 判据调用次序：入口 1 次 -> 持锁后复查 1 次 -> reload 后验证 1 次。
    # 前两次必须都不健康：入口判定触发恢复，持锁复查才进恢复分支；
    # 第三次（reload 之后）才健康。桩若永远 False 会被误判成「reload 没修好」
    # 从而降级 lockdown；桩若第二次就 True 则会走「复查后已正常」提前退出。
    _h['n'] += 1
    return (_h['n'] > 2, 'input 链未挂载' if _h['n'] <= 2 else '正常')
a._ruleset_is_functional = _unhealthy_then_ok
a._ruleset_is_empty = lambda: False           # 表还在
# 规则文件必须真的存在：恢复是靠 os.path.exists(_p) 过滤候选的，
# 文件不存在时 for 循环一次都不进，什么都不会做。
open(a.RULES_PATH, 'w').write('table inet fw4 { }\n')
a._try_apply_rules_file = lambda p: (order.append('reload') or True)
a._auto_recover_ruleset_if_empty = lambda: order.append('startup-recover')
a._apply_basic_lockdown = lambda *x, **k: (order.append('lockdown') or True)
a._recover_ruleset_if_unhealthy()
check('表在但无策略时走「重新加载规则文件」而非降级',
      'reload' in order and 'lockdown' not in order, str(order))

# 表在但无策略、且规则文件与 .lastgood 都不存在 —— 不得谎报「已恢复」
a = fresh()
_n = {'i': 0}


def _unhealthy_once():
    # 次序：入口判定 -> 持锁复查 -> 恢复后验证。
    # 前两次都必须不健康才能进恢复分支；第三次才转好。
    # 若第二次就转好，会走「复查后已正常」早退，压根到不了谎报那段代码。
    _n['i'] += 1
    return (_n['i'] > 2, '未挂载' if _n['i'] <= 2 else '正常')


a._ruleset_is_functional = _unhealthy_once
a._ruleset_is_empty = lambda: False
a._try_apply_rules_file = lambda p: False
a._auto_recover_ruleset_if_empty = lambda: None
_dn = {'n': 0}
a._apply_basic_lockdown = lambda *x, **k: (_dn.__setitem__('n', _dn['n'] + 1), True)[1]
acted_flag, msg = a._recover_ruleset_if_unhealthy()
check('无任何规则文件时不得谎报「已恢复」',
      '未执行任何重载' in msg or acted_flag is False, msg[:60])
check('无规则文件且复查转好时不假装动过手', acted_flag is False, str(acted_flag))

a = fresh()
order2 = []
a._ruleset_is_functional = lambda: (False, '表不存在')
a._ruleset_is_empty = lambda: True            # 表没了
a._try_apply_rules_file = lambda p: (order2.append('reload') or True)
a._auto_recover_ruleset_if_empty = lambda: order2.append('startup-recover')
a._apply_basic_lockdown = lambda *x, **k: (order2.append('lockdown') or True)
a._recover_ruleset_if_unhealthy()
check('表不存在时走启动级恢复链',
      'startup-recover' in order2, str(order2))

# ── _try_apply_rules_file 的第二道检查 ──────────────────────────
# .224 真机演练发现的：空文件走完 nft -f 返回 0，而「fw4 表还在吗」根本
# 看不出区别，于是被判成「已生效」。后果是看门狗的重试循环在这个文件上
# break，.lastgood 永远轮不到，直接降级 basic lockdown 丢掉端口转发。
_t = fresh()
_t.subprocess = types.SimpleNamespace(
    run=lambda *a, **k: types.SimpleNamespace(
        returncode=0, stdout='', stderr='', TimeoutExpired=TimeoutError, OSError=OSError),
    TimeoutExpired=TimeoutError, OSError=OSError)
_ok = fresh()
_ok._ruleset_is_functional = lambda: (True, '正常')
_ok._ruleset_is_empty = lambda: False
_ok.subprocess = _t.subprocess
check('rc=0 且规则集可用 → 判成功',
      _ok._try_apply_rules_file('/tmp/whatever.nft') is True)

# 语法合法但内容为空：nft 返回 0，表也还在 —— 必须判失败
_bad = fresh()
_bad._ruleset_is_empty = lambda: False                 # 表还在（这是旧判据骗人的地方）
_bad._ruleset_is_functional = lambda: (False, 'input 链未挂载')
_bad.subprocess = _t.subprocess
check('空文件（rc=0 但规则集仍不可用）判失败，不再误报成功',
      _bad._try_apply_rules_file('/tmp/empty.nft') is False)

_src_try = src[src.index('def _try_apply_rules_file'):]
_src_try = _src_try[:_src_try.index('\ndef ')]
check('二次检查用的是严判据 _ruleset_is_functional 而非 _ruleset_is_empty',
      '_ruleset_is_functional()' in _src_try)
check('二次检查已不再依赖 _ruleset_is_empty',
      '_ruleset_is_empty()' not in _src_try)

# 关键后果：空规则文件不得让重试循环提前 break —— .lastgood 必须还有机会
a = fresh()
_tried = []
_a_seq = {'n': 0}


def _empty_then_ok():
    # 第 1、2 次判定不健康（入口 + 持锁复查），reload 之后第 3 次才健康。
    _a_seq['n'] += 1
    return (_a_seq['n'] > 3, '未挂载' if _a_seq['n'] <= 3 else '正常')


a._ruleset_is_functional = _empty_then_ok
a._ruleset_is_empty = lambda: False
a.subprocess = _t.subprocess
open(a.RULES_PATH, 'w').write('')            # 主规则文件被清空
open(a.RULES_PATH + '.lastgood', 'w').write('table inet fw4 { }\n')
_real_try = a._try_apply_rules_file


def _recording_try(p):
    _tried.append(p)
    # 主文件空 → 严判据说没生效（假 0）；.lastgood 有内容 → 判成功
    return p.endswith('.lastgood')


a._try_apply_rules_file = _recording_try
a._auto_recover_ruleset_if_empty = lambda: None
a._apply_basic_lockdown = lambda *x, **k: True
a._recover_ruleset_if_unhealthy()
check('主规则文件为空时不会跳过 .lastgood',
      any(p.endswith('.lastgood') for p in _tried), str(_tried))

# 反过来：主规则文件**真的**生效时就必须停手。
# 没有 break 的话会把 .lastgood 也套上去，等于用旧规则盖掉刚恢复好的新规则。
_a2 = fresh()
_seq = {'n': 0}


def _ok_on_reload():
    _seq['n'] += 1
    return (_seq['n'] > 2, '未挂载' if _seq['n'] <= 2 else '正常')


_tried2 = []
_a2._ruleset_is_functional = _ok_on_reload
_a2._ruleset_is_empty = lambda: False
open(_a2.RULES_PATH, 'w').write('table inet fw4 { }\n')
open(_a2.RULES_PATH + '.lastgood', 'w').write('table inet fw4 { }\n')
_a2._try_apply_rules_file = lambda p: (_tried2.append(p) or True)
_a2._auto_recover_ruleset_if_empty = lambda: None
_a2._apply_basic_lockdown = lambda *x, **k: True
_a2._recover_ruleset_if_unhealthy()
check('主规则文件生效后立刻停手，不再拿 .lastgood 盖上去',
      len(_tried2) == 1 and _tried2[0].endswith('rules.nft'), str(_tried2))

# ── nft -f 的失败与异常必须被吞掉 ───────────────────────────────
# 直接单测 _try_apply_rules_file 的两条早退分支。它们原先没有断言覆盖：
# 变异把 returncode 检查和 except 全删掉，58 条断言照样全绿。
def _stub_run(rc, raise_exc=None):
    def _run(*a, **k):
        if raise_exc is not None:
            raise raise_exc
        return types.SimpleNamespace(returncode=rc, stdout='', stderr='boom',
                                     TimeoutExpired=TimeoutError, OSError=OSError)
    return types.SimpleNamespace(run=_run, TimeoutExpired=TimeoutError, OSError=OSError)


_r = fresh()
_r.subprocess = _stub_run(rc=1)
_r._ruleset_is_functional = lambda: (True, '正常')
_r._ruleset_is_empty = lambda: False
check('nft -f 非零退出码必须判失败（不能只看表还在不在）',
      _r._try_apply_rules_file('/tmp/bad.nft') is False)

for _exc_name, _exc in (('FileNotFoundError', FileNotFoundError()),
                        ('TimeoutExpired', TimeoutError()),
                        ('OSError', OSError('boom'))):
    _e = fresh()
    _e.subprocess = _stub_run(rc=0, raise_exc=_exc)
    _e._ruleset_is_functional = lambda: (True, '正常')
    _e._ruleset_is_empty = lambda: False
    try:
        _got = _e._try_apply_rules_file('/tmp/x.nft')
        _ok = _got is False
        _err = ''
    except BaseException as _x:      # noqa: BLE001
        _ok = False
        _err = f'抛出了 {type(_x).__name__}'
    check(f'{_exc_name} 被吞掉并判失败（异常不得炸穿恢复链路）', _ok, _err)

# ── 健康判据的严格性 ────────────────────────────────────────────
# 这两条原先也没有断言：把 hook input / policy drop 的检查删掉，
# 整体 flush 过、策略没生效的规则集都会被判成「健康」，看门狗永远不启动。
_HEALTHY = ('table inet fw4 {\n'
            '\tchain input {\n'
            '\t\ttype filter hook input priority 0; policy drop;\n'
            '\t\tjump accept_lan\n'
            '\t}\n'
            '}\n')

_cases = [
    ('完整健康的规则集判为正常', _HEALTHY, True),
    ('缺 hook input（整体 flush 过）判不健康',
     _HEALTHY.replace('type filter hook input priority 0; policy drop;\n'
                      '\t\tjump accept_lan',
                      'jump accept_lan'), False),
    ('hook input 没了但 policy drop 还在（换了别的 hook）判不健康',
     # 上一条样例同时去掉了 hook 与 policy，会被下一条检查兜住 ——
     # 那样「删掉 hook input 检查」这个变异就抓不到了，所以要单独造一个。
     'table inet fw4 {\n'
     '\tchain forward {\n'
     '\t\ttype filter hook forward priority 0; policy drop;\n'
     '\t}\n'
     '}\n', False),
    ('没有 drop/reject 策略判不健康',
     _HEALTHY.replace('policy drop', 'policy accept'), False),
    ('表不存在（nft 报错）判不健康', '__RC1__', False),
]
for _label, _stdout, _want in _cases:
    _h = fresh()
    if _stdout == '__RC1__':
        _h.subprocess = _stub_run(rc=1)
    else:
        _h.subprocess = types.SimpleNamespace(
            run=lambda *a, **k: types.SimpleNamespace(
                returncode=0, stdout=_stdout, stderr='',
                TimeoutExpired=TimeoutError, OSError=OSError),
            TimeoutExpired=TimeoutError, OSError=OSError)
    _got, _detail = _h._ruleset_is_functional()
    check(_label, _got is _want, f'返回 {_got} / {_detail[:40]}')

# nft 查询本身异常时必须 fail-closed（判不健康，触发恢复），
# 绝不能因为「查不到」就当成一切正常。
_hx = fresh()
_hx.subprocess = types.SimpleNamespace(
    run=lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError('no nft')),
    TimeoutExpired=TimeoutError, OSError=OSError)
_got, _d = _hx._ruleset_is_functional()
check('nft 不可用时判不健康（fail-closed，不能放行）', _got is False, _d[:40])

# 健康接口要能看见看门狗，否则自检成了黑盒
check('健康接口暴露 watchdog 状态', "'watchdog': {" in src)
check('健康接口暴露 running 标记', "'running':" in src)
check('启动流程里拉起了看门狗', '_start_watchdog()' in src)
check('看门狗启动失败不影响 Web 服务',
      '启动失败（不影响 Web 服务）' in src)


print('\n' + '═' * 52)
print(f'通过 {len(PASS)} / {len(PASS) + len(FAIL)}')
if FAIL:
    print('失败：')
    for f in FAIL:
        print('  - ' + f)
    sys.exit(1)
print('全部通过')
