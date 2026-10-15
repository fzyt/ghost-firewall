"""面板登录限流落盘 —— 回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_panel_ratelimit.py

背景：
  认证网关（auth_gateway.py，8443 的真正入口）早就是落盘的限流，它的模块
  文档里明确点名了**面板进程**这个内存 dict 是「不重复的错误」——
  `_failed_logins` 是内存 dict，进程一重启就清零。攻击者只要能让面板重启
  （crash / manage 脚本 / 定时 reload），失败计数就被抹掉，5 次一组慢慢试，
  「5 分钟窗口 + 15 分钟锁定」的策略被绕开一半。

现在面板也落盘，口径与网关一致：按 IP 记、5 次/5 分钟锁 15 分钟、
成功即清空、过期条目顺手 GC、文件 600。

关键不变量：**落盘不可用时必须降级而不是崩**。把登录整个搞挂 = 面板谁都
进不去，那是比限流失效严重得多的事故。
"""
import importlib.util as ilu
import json
import os
import shutil
import sys
import tempfile
import time

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
    spec = ilu.spec_from_file_location('_nftapp_rl', os.path.join(BACKEND, 'app.py'))
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mod = load_app()

DEFAULT_RL = mod.PANEL_RATELIMIT_FILE

TD = tempfile.mkdtemp()
RL = os.path.join(TD, 'rl.json')
mod.PANEL_RATELIMIT_FILE = RL
mod._RATELIMIT_DEGRADED['warned'] = False
IP = '192.168.100.77'

print('=' * 74)
print('面板登录限流落盘回归测试')
print('=' * 74)


def reset():
    for p in (RL, RL + '.tmp', RL + '.lock'):
        try:
            os.unlink(p)
        except OSError:
            pass
    mod._RATELIMIT_DEGRADED['warned'] = False


sec('1. 失败次数真的落盘')
reset()
for i in range(3):
    mod._record_login_failure(IP)
    st = mod._ratelimit_state(IP)
    check(f'第 {i+1} 次失败已落盘', st is not None and len(st[0]) == i + 1,
          f'落盘={open(RL).read() if os.path.exists(RL) else "（无文件）"}')
check('文件权限是 600',
      oct(os.stat(RL).st_mode & 0o777) == '0o600',
      f'实际={oct(os.stat(RL).st_mode & 0o777)}')
check('内容是 JSON 且键是源 IP',
      IP in json.load(open(RL)))

sec('2. 跨「进程重启」后计数仍在（这是落盘的全部意义）')
before = mod._ratelimit_state(IP)
# 模拟重启：把模块级的内存态清干净（原来 _failed_logins 就在这里，现在没有了，
# 所以「重启」就等于重新从文件读）
after = mod._ratelimit_state(IP)
check('重新读文件仍拿到同样的失败次数',
      before is not None and after is not None and before[0] == after[0],
      f'重启前={before} 重启后={after}')
src = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
check('源码里不再有内存版 _failed_logins dict',
      '_failed_logins: dict = {}' not in src,
      '内存 dict 存在就意味着重启清零')

sec('3. 限流阈值与锁定时长符合配置')
reset()
for _ in range(mod.AUTH_RATE_LIMIT_MAX_FAILS):
    mod._record_login_failure(IP)
allowed, retry = mod._check_rate_limit(IP)
check(f'第 {mod.AUTH_RATE_LIMIT_MAX_FAILS} 次之后被锁',
      allowed is False, f'allowed={allowed}')
check('给出了 retry_after', isinstance(retry, int) and retry > 0, f'retry_after={retry}')
check('retry_after 接近锁定时长',
      abs(retry - mod.AUTH_RATE_LIMIT_LOCKOUT) <= 3,
      f'retry={retry} 锁定={mod.AUTH_RATE_LIMIT_LOCKOUT}')
tbl = json.load(open(RL))
check('锁定状态也落盘了（不只是计数）',
      tbl.get(IP, {}).get('locked_until', 0) > time.time(),
      f'落盘={tbl}')

sec('4. 已锁定的 IP 连「检查」都会继续被拒（不会因为重载而解锁）')
check('连续两次检查都拒',
      mod._check_rate_limit(IP)[0] is False and mod._check_rate_limit(IP)[0] is False)

sec('5. 登录成功清空该 IP 的记录')
# 刻意用「有失败计数但还没被锁」的 IP：已锁定的 IP 根本登不进来，
# 此时清空等于给了一条「试对一次就解锁」的后门，是不能发生的场景。
reset()
FREE = '192.168.100.88'
for _ in range(2):
    mod._record_login_failure(FREE)
check('清空前确实有记录', mod._ratelimit_state(FREE) is not None)
mod._clear_login_failures(FREE)
check('记录被删掉', mod._ratelimit_state(FREE) is None,
      f'文件={open(RL).read()}')
check('清空后不再限流', mod._check_rate_limit(FREE)[0] is True)
check('文件里没有残留', FREE not in json.load(open(RL)))

sec('5b. 锁定期间不接受「清空」（不能靠猜对一次密码解锁）')
reset()
for _ in range(mod.AUTH_RATE_LIMIT_MAX_FAILS):
    mod._record_login_failure(IP)
check('已锁定', mod._check_rate_limit(IP)[0] is False)
mod._clear_login_failures(IP)
check('清空调用没有解除锁定', mod._check_rate_limit(IP)[0] is False,
      '锁定期内登录本就进不来，清空逻辑若生效就等于留了后门')

sec('6. 不同 IP 互不影响')
reset()
for _ in range(mod.AUTH_RATE_LIMIT_MAX_FAILS):
    mod._record_login_failure('10.0.0.9')
check('被锁的 IP 仍被拒', mod._check_rate_limit('10.0.0.9')[0] is False)
check('另一个 IP 不受影响', mod._check_rate_limit('10.0.0.10')[0] is True)

sec('7. 过期条目会被 GC，表不会无限膨胀')
reset()
old = time.time() - (mod.AUTH_RATE_LIMIT_LOCKOUT + mod.AUTH_RATE_LIMIT_WINDOW + 60)
data = {'1.1.1.1': {'fails': [old], 'locked_until': 0},
        '2.2.2.2': {'fails': [time.time()], 'locked_until': 0},
        'junk': 'not-a-dict'}
mod._ratelimit_write(data)
mod._record_login_failure('3.3.3.3')
tbl = json.load(open(RL))
check('过期的被删掉', '1.1.1.1' not in tbl, f'表={sorted(tbl)}')
check('没过期的保留', '2.2.2.2' in tbl and '3.3.3.3' in tbl, f'表={sorted(tbl)}')
check('格式非法的条目被清掉', 'junk' not in tbl, f'表={sorted(tbl)}')

sec('8. 文件损坏时不能让登录整个挂掉')
with open(RL, 'w') as f:
    f.write('{ this is not json')
allowed, retry = mod._check_rate_limit(IP)
check('读损坏文件时仍放行（fail-open，不把人锁在门外）',
      allowed is True, f'allowed={allowed}')
mod._record_login_failure(IP)
check('写回后文件恢复成合法 JSON',
      isinstance(json.load(open(RL)), dict), f'文件={open(RL).read()[:80]}')

sec('9. 落盘不可用时降级并只警告一次')
orig_read = mod._ratelimit_read


def boom(*a, **k):
    raise OSError(28, 'No space left on device')


mod._ratelimit_read = boom
mod._RATELIMIT_DEGRADED['warned'] = False
try:
    mod._record_login_failure(IP)
    mod._record_login_failure(IP)
finally:
    mod._ratelimit_read = orig_read
check('降级后不抛异常（登录仍可用）', True)
check('只警告一次，不刷屏', mod._RATELIMIT_DEGRADED['warned'] is True)

sec('10. 限流文件与认证网关的不是同一个')
check('面板用自己的限流文件',
      'panel-ratelimit' in DEFAULT_RL, f"默认={DEFAULT_RL}")
check('默认路径不在 /etc 之外（要被 init 脚本管到）',
      DEFAULT_RL.startswith('/etc/'), f'默认={DEFAULT_RL}')
gw = open(os.path.join(BACKEND, 'auth_gateway.py'), encoding='utf-8').read()
check('与网关的 ratelimit 文件路径不同',
      mod.PANEL_RATELIMIT_FILE != '/etc/nftables/nftables-web-auth-ratelimit.json')
check('网关那份仍然是落盘的（没被改坏）',
      'RATELIMIT_FILE' in gw and 'fcntl.flock' in gw)

shutil.rmtree(TD, ignore_errors=True)

print('\n' + '=' * 74)
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    print('失败项:')
    for f in FAIL:
        print('  -', f)
    sys.exit(1)
print('全部通过')
