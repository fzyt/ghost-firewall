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


print('\n' + '═' * 52)
print(f'通过 {len(PASS)} / {len(PASS) + len(FAIL)}')
if FAIL:
    print('失败：')
    for f in FAIL:
        print('  - ' + f)
    sys.exit(1)
print('全部通过')
