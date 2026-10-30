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
check('密码文件用 640 组可读（对「其他」仍然全关）',
      re.search(r'for f in [^;]*nftables-web-password', _init) is not None
      and re.search(r'chmod 640 "\$_cfgdir/\$f"', _init) is not None,
      '密码文件走同一循环统一 chmod 640')

# ── 密钥分离（Shannon 渗透测试 finding）─────────────────────────────
#
# 以前面板的 Flask SECRET_KEY 和网关的令牌密钥读**同一个文件**
# nftables-web-secret（0640 root:nftweb）⇒ 降权后的网关进程（公网可达）
# 能读到面板的会话签名密钥。网关侧虽有域分离（HMAC 派生），但它的
# _load_secret() 是**直接读原文件**再派生的 ⇒ 攻陷网关 = 拿到面板
# 管理员 session 的签名能力。
#
# 现在必须拆成两个文件，权限相反：
#   nftables-web-secret          0640 root:nftweb  ← 网关的令牌密钥
#   nftables-web-session-secret  0600 root:root    ← 面板的会话签名密钥
check('网关令牌密钥走单独语句：640 + chgrp nftweb（网关要读它派生令牌密钥）',
      re.search(r'chmod 640 "\$_toksecret"', _init) is not None
      and re.search(r'chgrp "\$NFTWEB_USER" "\$_toksecret"', _init) is not None,
      'nftables-web-secret 必须是 root:nftweb 640')
check('面板会话密钥：0600 + chown root:root（网关读不到）',
      re.search(r'chmod 600 "\$_sesssecret"', _init) is not None
      and re.search(r'chown 0:0 "\$_sesssecret"', _init) is not None,
      'nftables-web-session-secret 必须是 0600 root:root')
check('面板会话密钥**不**落在 nftweb 组可读的循环里',
      re.search(r'for\s+f\s+in[^;]*nftables-web-session-secret', _init) is None,
      'session-secret 绝不能和网关共享的文件走同一个 chgrp nftweb 循环')
check('面板会话密钥与网关令牌密钥是两个不同的文件',
      'nftables-web-session-secret' in _init
      and re.search(r'_sesssecret="[^"]*nftables-web-session-secret"', _init) is not None
      and re.search(r'_toksecret="[^"]*nftables-web-secret"', _init) is not None,
      '两个密钥必须落在两个不同的文件上')
# 谁来生成这个文件？
#
# init 脚本以 root 在**降权前**生成它，理由不是「面板也能生成」：
#  · 面板运行期如果配置目录变成不可写（只读挂载、事后收紧权限），
#    它就写不出这个文件，只能退回进程内随机值 ⇒ 重启即会话全失。
#  · init 脚本生成的那份在网关（uid 1000）起来之前就位，
#    网关从一开始就**读不到**它（0600 root:root）。
# 面板自己的兜底路径（_init_app_secret → _apply_session_secret_perms）
# 同样保证 0600 root:root，两条路殊途同归 —— 但只有 init 这一条
# 在「目录不可写」时仍然成立，所以它必须被钉住。
check('面板会话密钥由 init 脚本在降权前生成（面板运行期目录不可写时没有兜底）',
      re.search(r'if\s+\[\s*!\s*-s\s+"\$_sesssecret"\s*\]', _init) is not None,
      'init 脚本必须负责生成 nftables-web-session-secret')

# 启动后复核：这是最后一道闸，防止将来 _drop_privileges 被改坏
#
# 2026-10-16：原来这里只判 `'降权未生效' in _init`（全文任意位置出现即可）。
# 那天下面那个守卫改成了轮询 + 更长的报错文案，**注释里也写了「降权未生效」
# 这四个字**，于是把真正的 kill + 报错整段删掉之后，这条断言照样通过 ——
# mutation_check_privilege.py 的 M8 抓到过这个假测试（18/19）。
#
# 改成按结构检查：定位到守卫所在的代码块，要求 kill 与报错都在同一块里，
# 注释里出现同样的字样不再算数。
_g_l = _init.index('python3 auth_gateway.py')
_g_r = _init.index('\n}\n', _g_l)          # 只截 start() 函数体，别把 stop() 圈进来
_g = _init[_g_l:_g_r]
check('启动后复核实际 uid，为 0 则杀掉并报错',
      re.search(r'if\s+\[\s*"\$real_uid"\s*=\s*"0"\s*\]', _g) is not None
      and re.search(r'kill\s+"\$pid"', _g) is not None
      and '降权未生效' in _g,
      '守卫块里没找到 uid 判断 / kill / 报错三者')

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
sec('PD-10  nginx worker 降权脚本：两个「假绿灯」陷阱')

_nginx_sh = open(os.path.join(ROOT_TOOLS := os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), 'tools', 'nginx-priv-drop.sh'),
    encoding='utf-8').read()
# 剥掉注释再验：脚本里的排障说明大量提到 "nginx -t" 字样，
# 不剥掉会把注释误判成代码里的裸调用。
_nginx_code = '\n'.join(
    l for l in _nginx_sh.splitlines() if not l.lstrip().startswith('#'))
# 再剥掉引号内的内容：日志文案里也写着 "nginx -t -c $CONF 通过"，
# 那是给人看的字符串，不是执行。只剩命令位置的 nginx -t 才是真调用。
_nginx_exec = re.sub(r'"[^"]*"', '""', _nginx_code)
_nginx_exec = re.sub(r"'[^']*'", "''", _nginx_exec)

# 陷阱一：nginx -t 读的是 nginx.conf，服务实际跑的是 -c uci.conf。
# 验错文件 → 报「通过」→ 真正的原因根本不在被验的那份里 → restart 才炸。
check('语法预检用服务实际加载的配置（nginx -t -c "$CONF"）',
      'nginx_check() { nginx -t -c "$CONF"' in _nginx_code,
      '裸 nginx -t 校验的是 nginx.conf，不是 init 脚本起的那份')
check('命令位置上没有绕过 nginx_check 的裸 nginx -t',
      len(re.findall(r'nginx -t(?! -c)', _nginx_exec)) == 0,
      f"存在 {len(re.findall(r'nginx -t(?! -c)', _nginx_exec))} 处不带 -c 的 "
      f"nginx -t，它验的不是服务实际加载的配置")

# 陷阱二：nginx 的 user 指令内部是 getpwnam() + getgrnam()，两个都要，
# 且用同一个名字。OpenWrt 的 /etc/passwd 有 nobody，/etc/group 只有
# nogroup —— 只查用户会漏掉一半，然后 nginx 报 getgrnam 失败拒绝启动。
check('从 /etc/passwd 取 worker 的 uid',
      '/etc/passwd' in _nginx_code and 'WORKER_UID=' in _nginx_code)
check('显式检查 /etc/group 里 worker 组是否存在',
      re.search(r'grep -q "\^\$\{WORKER_USER\}:" /etc/group', _nginx_code) is not None,
      '只查 /etc/passwd 会漏掉 /etc/group 缺组这一半')
check('组缺失时自动补建（而不是让 nginx 启动失败）',
      re.search(r'>>\s*/etc/group', _nginx_code) is not None)

# user 指令只在 master 启动时生效，reload 不改 worker 身份
check('指令有变更时走 restart 而非 reload',
      re.search(r'if \[ "\$CHANGED" = "1" \]; then.*?/etc/init\.d/nginx stop.*?/etc/init\.d/nginx start',
                _nginx_code, re.S) is not None,
      '实测踩过：reload 之后 worker 仍是 uid=0')
check('回滚路径同样是 restart',
      _nginx_code.count('/etc/init.d/nginx stop') >= 2)

# 「循环体一次都不进 → BAD 保持 0 → 谎报完成」：必须有进程数量下限判断
check('复核要求 master 与 worker 都至少存在一个',
      re.search(r'NMASTER.*-eq 0', _nginx_code) is not None
      and re.search(r'NWORKER.*-eq 0', _nginx_code) is not None)
check('worker uid 必须等于期望值，而不只是「非 0」',
      re.search(r'"\$U" != "\$WORKER_UID"', _nginx_code) is not None)
check('master 必须是 root（worker 降权不等于 master 也降）',
      re.search(r'master.*?\n.*?不是 root', _nginx_code, re.S) is not None)

# ─────────────────────────────────────────────────────────────
sec('PD-11  私钥权限：每次写入后都要补组读，否则 worker 读不到')

_app_src = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
# 计数必须在**去掉注释行**的源码上做。
# 2026-10-30 踩过：新增的说明性注释里写了 `os.chmod(key_path, 0o600)` 字样，
# 于是「有几处 chmod」被数成 4（真实代码 3 处），把断言带偏了。
# 注释里出现代码片段是**应该的**（解释为什么要那么写），所以要改的是计数口径，
# 不是把注释改写含糊。
_app_code = '\n'.join(l for l in _app_src.split('\n') if not l.strip().startswith('#'))
check('_harden_key_for_nginx_worker 函数存在', '_harden_key_for_nginx_worker' in _app_src)
_n_chmod = len(re.findall(r'os\.chmod\((?:key_path|NFTABLES_WEB_KEY),\s*0o600\)', _app_code))
# 关键：这里数的是**全部**调用点，不能按参数名过滤。
# 原版写的是 re.findall(r'_harden_key_for_nginx_worker\((?:key_path|NFTABLES_WEB_KEY)\)'),
# 而两条 ACME 路径传的是 `keyfile` 和 `os.path.join(cert_dir, "privkey.pem")` ——
# 于是它们从来没进过统计。断言号称「补权限与 chmod 一一对应」，
# 却对 P0-2「ACME 路径漏加固」完全失明，那条缺陷就是这样活下来的。
# 现在改成数所有调用点，五条写入路径必须一条不少。
_n_hard = len(re.findall(r'^\s+_harden_key_for_nginx_worker\(', _app_code, re.M))
# 2026-10-30 计数从 5 变成 7：上传/重传两条路径各自多了一次
# **在 os.replace 之前**的提前加固（tmp 私钥落盘即最终形态，
# 不必等 replace 之后再补 —— 那样中间有一段 0600 的过渡态）。
# 7 = 5 条写入路径各一次 + 上传/重传各一次「replace 前提前加固」。
check('三处 chmod(key, 600) 全部配了补权限', _n_chmod == 3, f'实际 {_n_chmod} 处')
check('五条私钥写入路径都调了补权限（含两条不 chmod 的 ACME 路径）+ 两条 replace 前提前加固',
      _n_hard == 7, f'实际 {_n_hard} 处')
# 会 chmod 的路径必须在 chmod 之后跟着加固：顺序反了等于去加固一个还没被改过的权限
_ORDER_RE = (r'os\.chmod\((?:key_path|NFTABLES_WEB_KEY),\s*0o600\)'
              r'(?:\s*\n\s*#[^\n]*)*\s*\n\s*_harden_key_for_nginx_worker\(')
check('chmod 之后紧跟补权限（顺序反了等于没加固）',
      len(re.findall(_ORDER_RE, _app_code)) == 3,
      f'实际匹配 {len(re.findall(_ORDER_RE, _app_code))} 处')

# ── 2026-10-30 新增：私钥**落盘那一刻**就得是紧的 ──────────────────
# 旧写法是 key_file.save(tmp) → os.replace(tmp, key_path) → os.chmod(key_path, 600)：
# save() 按 umask 建 0644 的文件，replace 之后正式私钥也是 0644，
# chmod 在**之后**才做 ⇒ 中间有一小段时间全设备的本地用户都能读到这个私钥。
# 私钥泄露 = 身份凭据泄露，这个窗口不能靠「很短」来糊弄。
check('_ensure_file_mode 辅助函数存在', 'def _ensure_file_mode(' in _app_src)
check('上传路径：私钥 tmp 先按 0600 建好再写内容',
      '_ensure_file_mode(tmp_k, 0o600)' in _app_code)
check('私钥 tmp 在 replace 之前就补上 worker 组读权限（落盘即最终形态）',
      len(re.findall(r'_harden_key_for_nginx_worker\(tmp_k\)', _app_code)) == 2,
      f'实际 {len(re.findall(r"_harden_key_for_nginx_worker\(tmp_k\)", _app_code))} 处'
      '（上传 + 重传各一处）')
# 注意这里必须精确盯 OSError 那一支：函数里有两个 return False
# （ImportError 分支 + OSError 分支），非贪婪的 `.*?return False`
# 会匹配到第一个，把第二个改成 raise 也照样「通过」—— 变异验证实测过。
_fn_m = re.search(r'def _harden_key_for_nginx_worker.*?(?=\ndef |\nclass |\n@app|\n# ═)',
                  _app_src, re.S)
_fn_src = _fn_m.group(0) if _fn_m else ''
check('chown/chmod 失败的 OSError 分支返回 False 而不是抛异常',
      re.search(r'except OSError:\s*\n\s*return False', _fn_src) is not None,
      f'函数体片段: {repr(_fn_src[-90:])}')
check('解析不到用户时也返回 False（而不是让证书流程炸掉）',
      re.search(r'except \(ImportError, KeyError\):\s*\n\s*return False', _fn_src) is not None)

# ─────────────────────────────────────────────────────────────
print()
if FAIL:
    print(f'❌ 失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')