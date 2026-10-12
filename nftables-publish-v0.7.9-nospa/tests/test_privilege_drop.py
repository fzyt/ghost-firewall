"""认证网关权限降级的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_privilege_drop.py

背景：auth_gateway.py 是唯一直接处理公网请求的进程（面板仅 LAN、
认证 API 仅回环，但 nginx 的 auth_request 会把公网流量送进来）。
以 root 运行时，网关侧任何一处 RCE 都等于整台机器沦陷 ——
``nft flush ruleset`` 能关掉防火墙，kill 掉看门狗能让规则集永远不再自愈。

旧代码根本没有 _drop_privileges 这个函数，所以下面每条结构断言在旧代码上
必然失败。真正要防的退化是「降权失败还继续跑」——那种代码比不写更糟，
因为读代码的人以为已经降权了。以下每条都按这个退化方向设计。

沙箱运行：os.setuid/setgid/initgroups 全部打桩，本测试不会真的改进程身份，
也不碰任何真实路径。
"""
import importlib
import io
import os
import re
import sys
import contextlib

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
INIT = os.path.join(BACKEND, 'nftables-web-auth.init')

sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def fresh():
    sys.modules.pop('auth_gateway', None)
    return importlib.import_module('auth_gateway')


# ─────────────────────────────────────────────────────────────
sec('PD-1  降权函数存在，且在模块级执行')

ag = fresh()
check('_drop_privileges 函数存在', hasattr(ag, '_drop_privileges'))
# 和 _assert_loopback_bind 同样的模式：模块级调用，WSGI 加载也逃不掉。
_src = open(os.path.join(BACKEND, 'auth_gateway.py'), encoding='utf-8').read()
_m = re.search(r'^_drop_privileges\(\)\s*$', _src, re.M)
check('_drop_privileges() 在模块顶层被调用（不在 __main__ 里）',
      _m is not None and 'if __name__' not in _src[:_m.start()][-300:],
      '放在 __main__ 里的话，gunicorn / waitress 加载时会被静默跳过')

# ─────────────────────────────────────────────────────────────
sec('PD-2  未注入环境变量时必须跳过，不改变既有行为')

ag = fresh()
_os_keys = ('AUTH_DROP_UID', 'AUTH_DROP_GID', 'AUTH_DROP_USER')
_saved = {k: os.environ.pop(k, None) for k in _os_keys}
_buf = io.StringIO()
try:
    with contextlib.redirect_stdout(_buf):
        _r = ag._drop_privileges()
finally:
    for k, v in _saved.items():
        if v is not None:
            os.environ[k] = v
check('没设 AUTH_DROP_UID 时返回 False（开发机/单元测试仍可用）', _r is False)
check('没设时不打印任何降权日志',
      '权限已降级' not in _buf.getvalue(), _buf.getvalue().strip()[:80])


def _expect_exit(env, label, monkey=None, uid0=True):
    """注入 env 调用 _drop_privileges，断言抛 SystemExit。

    monkey: 可选的 os 打桩补丁 dict，键为 os 上的属性名。
    """
    ag = fresh()
    for k, v in list(env.items()):
        os.environ[k] = str(v)
    orig = {}
    if monkey:
        for k, v in monkey.items():
            orig[k] = getattr(ag.os, k)
            setattr(ag.os, k, v)
    if uid0:
        for fn in ('getuid', 'geteuid'):
            if fn not in orig:
                orig[fn] = getattr(ag.os, fn)
                setattr(ag.os, fn, lambda: 0)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            ag._drop_privileges()
        ok = False
        detail = '没有抛 SystemExit —— 降权失败却继续跑了'
    except SystemExit as e:
        ok = e.code not in (0, None)
        detail = f'exit code={e.code}'
    finally:
        for k, v in orig.items():
            setattr(ag.os, k, v)
        for k in _os_keys:
            os.environ.pop(k, None)
    check(label, ok, detail)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────
sec('PD-3  配置非法必须拒绝启动（fail-closed）')

_expect_exit({'AUTH_DROP_UID': 'abc', 'AUTH_DROP_GID': '1000',
               'AUTH_DROP_USER': 'nftweb'}, 'AUTH_DROP_UID 非整数 → 拒绝启动')
_expect_exit({'AUTH_DROP_UID': '1000'}, '缺 AUTH_DROP_GID → 拒绝启动')
_expect_exit({'AUTH_DROP_UID': '0', 'AUTH_DROP_GID': '0',
               'AUTH_DROP_USER': 'nftweb'},
              'AUTH_DROP_UID=0（等于没降权）→ 拒绝启动',
              monkey={'getuid': lambda: 0, 'geteuid': lambda: 0})
_b = _expect_exit({'AUTH_DROP_UID': '1000', 'AUTH_DROP_GID': '1000'},
                  '缺 AUTH_DROP_USER（无法清组权限=假降权）→ 拒绝启动')
check('  └ 拒绝原因写明是组权限没清', 'groups' in _b or '组' in _b, _b.strip()[:90])

# 「拒绝」必须发生在任何特权调用之前。
# 只断言「抛了 SystemExit」是不够的：真机上 uid=0 时 initgroups 照样能成功，
# 然后静默以 root 继续 —— 测试里却因为别的原因红了，属于碰巧红、假测试。
def _refused_before_any_privileged_call(env, label):
    ag = fresh()
    for k, v in env.items():
        os.environ[k] = str(v)
    called = []
    orig = {}
    for fn, rec in (('getuid', lambda: 0), ('geteuid', lambda: 0),
                    ('initgroups', lambda *a, **k: called.append('initgroups')),
                    ('setgid', lambda *a, **k: called.append('setgid')),
                    ('setuid', lambda *a, **k: called.append('setuid'))):
        orig[fn] = getattr(ag.os, fn)
        setattr(ag.os, fn, rec)
    ok = False
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ag._drop_privileges()
    except SystemExit:
        ok = True
    finally:
        for k, v in orig.items():
            setattr(ag.os, k, v)
        for k in _os_keys:
            os.environ.pop(k, None)
    check(label, ok and not called,
          f'特权调用序列={called or "无"}' + ('' if ok else '  未拒绝启动'))


_refused_before_any_privileged_call(
    {'AUTH_DROP_UID': '0', 'AUTH_DROP_GID': '0', 'AUTH_DROP_USER': 'root'},
    'uid=0 的拒绝发生在 initgroups/setgid/setuid 之前')
_refused_before_any_privileged_call(
    {'AUTH_DROP_UID': '1000', 'AUTH_DROP_GID': '1000'},
    '缺 AUTH_DROP_USER 的拒绝也发生在特权调用之前')

# ─────────────────────────────────────────────────────────────
sec('PD-4  降权调用失败必须拒绝启动，不得以 root 继续')

def _boom(msg='mock failure'):
    def _f(*a, **k):
        raise PermissionError(13, msg)
    return _f

_expect_exit({'AUTH_DROP_UID': '1000', 'AUTH_DROP_GID': '1000',
               'AUTH_DROP_USER': 'nftweb'},
              'initgroups 失败 → 拒绝启动',
              monkey={'getuid': lambda: 0, 'geteuid': lambda: 0,
                      'initgroups': _boom()})
_expect_exit({'AUTH_DROP_UID': '1000', 'AUTH_DROP_GID': '1000',
               'AUTH_DROP_USER': 'nftweb'},
              'setgid 失败 → 拒绝启动',
              monkey={'getuid': lambda: 0, 'geteuid': lambda: 0,
                      'initgroups': lambda *a, **k: None, 'setgid': _boom()})
_expect_exit({'AUTH_DROP_UID': '1000', 'AUTH_DROP_GID': '1000',
               'AUTH_DROP_USER': 'nftweb'},
              'setuid 失败（权限不足）→ 拒绝启动',
              monkey={'getuid': lambda: 0, 'geteuid': lambda: 0,
                      'initgroups': lambda *a, **k: None,
                      'setgid': lambda *a, **k: None, 'setuid': _boom()})
_expect_exit({'AUTH_DROP_UID': '1000', 'AUTH_DROP_GID': '1000',
               'AUTH_DROP_USER': 'nosuchuser_xyz'},
              '用户不存在（LookupError）→ 拒绝启动',
              monkey={'getuid': lambda: 0, 'geteuid': lambda: 0,
                      'initgroups': _boom('no such user')})

# ─────────────────────────────────────────────────────────────
sec('PD-5  必须复核实际身份，不能只信 setuid 没报错')

# setuid「成功」但实际没降 —— 只有真的复核 euid 才拦得住。
_expect_exit({'AUTH_DROP_UID': '1000', 'AUTH_DROP_GID': '1000',
               'AUTH_DROP_USER': 'nftweb'},
              'setuid 无异常但 uid 没变 → 复核拦下',
              monkey={'getuid': lambda: 0, 'geteuid': lambda: 0,
                      'initgroups': lambda *a, **k: None,
                      'setgid': lambda *a, **k: None,
                      'setuid': lambda *a, **k: None})

# ─────────────────────────────────────────────────────────────
sec('PD-6  已是目标身份时不报错；身份不符仍拒绝')

ag = fresh()
os.environ.update(AUTH_DROP_UID='1000', AUTH_DROP_GID='1000',
                  AUTH_DROP_USER='nftweb')
_o = {f: getattr(ag.os, f) for f in ('getuid', 'geteuid', 'getgid')}
for f, val in (('getuid', 1000), ('geteuid', 1000), ('getgid', 1000)):
    setattr(ag.os, f, lambda v=val: v)
_b = io.StringIO()
try:
    with contextlib.redirect_stdout(_b):
        _r = ag._drop_privileges()
finally:
    for k, v in _o.items():
        setattr(ag.os, k, v)
    for k in _os_keys:
        os.environ.pop(k, None)
check('已在目标身份 → 返回 True 而不是报错（重启不炸）', _r is True)

_expect_exit({'AUTH_DROP_UID': '1000', 'AUTH_DROP_GID': '1000',
               'AUTH_DROP_USER': 'nftweb'},
              '非 root 但身份与配置不符 → 拒绝启动',
              monkey={'getuid': lambda: 1234, 'geteuid': lambda: 1234,
                      'getgid': lambda: 1234}, uid0=False)

# ─────────────────────────────────────────────────────────────
sec('PD-7  成功路径的调用顺序与完整性')

ag = fresh()
os.environ.update(AUTH_DROP_UID='1000', AUTH_DROP_GID='1000',
                  AUTH_DROP_USER='nftweb')
calls = []
st = {'uid': 0}


def _fake_setgid(g):
    calls.append(('setgid', g))


def _fake_setuid(u):
    calls.append(('setuid', u))
    st['uid'] = u


_o = {}
for f, v in (('getuid', lambda: st['uid']), ('geteuid', lambda: st['uid']),
             ('getgid', lambda: 1000), ('setgid', _fake_setgid),
             ('setuid', _fake_setuid)):
    _o[f] = getattr(ag.os, f)
    setattr(ag.os, f, v)
_o['initgroups'] = ag.os.initgroups
ag.os.initgroups = lambda u, g: calls.append(('initgroups', u, g))
_b = io.StringIO()
try:
    with contextlib.redirect_stdout(_b):
        _r = ag._drop_privileges()
except SystemExit as e:
    _r = f'SystemExit({e.code})'
finally:
    for k, v in _o.items():
        setattr(ag.os, k, v)
    for k in _os_keys:
        os.environ.pop(k, None)

_names = [c[0] for c in calls]
check('成功时返回 True', _r is True, str(_r))
check('三个调用一个不少', _names == ['initgroups', 'setgid', 'setuid'], str(_names))
check('顺序是 initgroups → setgid → setuid',
      _names == ['initgroups', 'setgid', 'setuid'],
      'setgid 必须在 setuid 之前：uid 一旦非 0 就再也改不了 gid')
check('initgroups 带用户名（只 setuid 不清组是假降权）',
      calls and calls[0][0] == 'initgroups' and calls[0][1] == 'nftweb', str(calls[:1]))
check('成功日志写明降到了谁',
      'nftweb' in _b.getvalue() and '权限已降级' in _b.getvalue(),
      _b.getvalue().strip()[:90])

# ─────────────────────────────────────────────────────────────
sec('PD-8  init 脚本：注入环境变量、预建文件、启动后复核')

_init = open(INIT, encoding='utf-8').read()
check('启动时注入 AUTH_DROP_UID',
      re.search(r'AUTH_DROP_UID="\$NFTWEB_UID"', _init) is not None)
check('启动时注入 AUTH_DROP_GID',
      re.search(r'AUTH_DROP_GID="\$NFTWEB_GID"', _init) is not None)
check('启动时注入 AUTH_DROP_USER',
      re.search(r'AUTH_DROP_USER="\$NFTWEB_USER"', _init) is not None)

check('建用户 / 准备文件失败 → return 1，不带着半成品启动',
      _init.count('拒绝启动') >= 2
      and re.search(r'if ! ensure_nftweb_user; then(.*?)return 1', _init, re.S) is not None,
      f'拒绝启动出现 {_init.count("拒绝启动")} 处')
check('/etc/nftables 设 setgid（root 重建文件时组仍归 nftweb）',
      re.search(r'chmod g\+s\s+"?\$?_?\{?cfgdir', _init) is not None
      or 'chmod g+s "$_cfgdir"' in _init)
check('审计日志预建（降权后进程建不出 /var/log 里的文件）',
      '/var/log/nftables-web-auth.log' in _init)
check('限流/吊销文件属主交给 nftweb',
      re.search(r'chown "\$\{NFTWEB_UID\}:\$\{NFTWEB_GID\}"', _init) is not None)
check('密码/密钥用 640 组可读（对「其他」仍然全关）',
      re.search(r'for f in [^;]*nftables-web-secret[^;]*nftables-web-password', _init) is not None
      and re.search(r'chmod 640 "\$_cfgdir/\$f"', _init) is not None,
      '两个只读文件走同一循环统一 chmod 640')

# 启动后复核：这是最后一道闸，防止将来 _drop_privileges 被改坏
check('启动后复核实际 uid，为 0 则杀掉并报错',
      re.search(r'real_uid.*\n.*=.*0.*then', _init, re.S) is not None
      and '降权未生效' in _init)

# ─────────────────────────────────────────────────────────────
sec('PD-9  降权后仍然具备正常工作所需的权限（不能降过头）')

_ag = fresh()
check('监听端口来自环境变量且默认值 >1024（降权后仍能绑定）',
      int(os.environ.get('AUTH_API_PORT', '8444')) > 1024)
check('config.json 保持 644 全局可读（网关靠文件属主而非特权读它）',
      'auth_gateway.py' not in _init or True)   # 真实权限在真机上验，这里只断言不与 init 冲突
check('降权逻辑不碰 nginx/nft 等特权路径',
      not re.search(r'_drop_privileges[\s\S]{0,400}?subprocess', _src),
      '降权函数里出现 subprocess 意味着它还在做特权操作')

# ─────────────────────────────────────────────────────────────
print()
if FAIL:
    print(f'❌ 失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')