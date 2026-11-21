#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三批修复的行为级判据（条目 43 / 14 / 55）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/test_batch3_fixes.py

测三件
------
43  规则集所在目录与规则集文件的权限/属主守卫
    —— nft 是**以 root 读** RULES_PATH 并加载的；文件或目录能被低权用户
       写/替换 ⇒ 本地低权用户能让 root 执行自己的内容（提权）。

14  审计日志轮转时不能把 login_ok / logout 挤掉
    —— 未认证者能灌 verify_denied；限流是每 IP 120/60 秒，换几十个源 IP
       就能在一分钟内灌满 2 MiB 触发轮转 ⇒ 只留尾部的话，
       「谁登录过」就彻底查不到。

55  改了认证服务内部端口必须提示重启
    —— 认证服务是独立进程、监听端口在 import 时固定；而 nginx 的
       auth_request 地址是按新端口生成的 ⇒ 不提示就是「所有登录 502」。

为什么必须是行为级判据
----------------------
43  判据是**真的调守卫函数**看它收不收紧、拒不拒绝 ——
    只看源码里有没有 chmod 字样，证明不了「过宽的目录真被收紧了」。
14  判据是**真的造一个灌满的日志文件**再轮转，然后检查 login_ok 还在不在。
55  判据是**真的 POST 一次 /api/gateway/config**，看应答里有没有那条提示。

本文件只读仓库里的源码、只在临时目录里写东西：
不碰 /etc/nftables、/var/log、/opt/nftables-web-v2。
"""
import importlib.util as ilu
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(HERE, '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name
          + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


# ── 沙箱：环境变量必须在 import app / auth_gateway 之前设好 ──────────
TD = tempfile.mkdtemp(prefix='batch3-')
CFG = os.path.join(TD, 'config.json')
PWD = os.path.join(TD, 'password')
SECRET = os.path.join(TD, 'secret')
RL = os.path.join(TD, 'ratelimit.json')
LOG = os.path.join(TD, 'audit.log')
for _p in (PWD, SECRET):
    with open(_p, 'w', encoding='utf-8') as _f:
        _f.write('x')
with open(CFG, 'w', encoding='utf-8') as _f:
    json.dump({
        "access_mode": "trusted",
        "lan_subnet4": "192.168.100.0/24",
        "gateway_enabled": False,
        "gateway_port": 8443,
        "auth_api_port": 8444,
        "auth_lan_bypass": False,
        "trusted_ip4": "192.168.100.224",
        "reverse_proxy": {"rules": []},
    }, _f)

# ⚠ AUTH_CONFIG_PATH 是 app.py 与 auth_gateway.py **共用**的配置路径变量
#   （两个文件读的是同一个环境变量名）⇒ 设一次即可隔离两者。
os.environ.update({
    "AUTH_CONFIG_PATH": CFG,
    "AUTH_PASSWORD_FILE": PWD,
    "AUTH_SECRET_FILE": SECRET,
    "AUTH_RATELIMIT_FILE": RL,
    "AUTH_AUDIT_LOG": LOG,
    "AUTH_API_PORT": "18445",
})

import auth_gateway as ag  # noqa: E402

_spec = ilu.spec_from_file_location('_nftapp_batch3', os.path.join(BACKEND, 'app.py'))
panel = ilu.module_from_spec(_spec)
_spec.loader.exec_module(panel)


# ============================================================
# 条目 43：规则集目录与文件的权限/属主守卫
# ============================================================

sec('条目 43：规则集目录与文件的权限/属主守卫')

_rules_dir = os.path.join(TD, 'rulesdir')
os.makedirs(_rules_dir, exist_ok=True)
_rules_file = os.path.join(_rules_dir, '99-custom-rules.nft')
with open(_rules_file, 'w', encoding='utf-8') as _f:
    _f.write('# 沙箱里的假规则集\n')

_orig_rules_path = panel.RULES_PATH
panel.RULES_PATH = _rules_file
try:
    # ① 目录权限过宽 ⇒ 收紧（自愈），不拒绝
    os.chmod(_rules_dir, 0o777)
    ok, msg = panel._ruleset_perm_guard()
    check('目录权限过宽时仍然放行（自愈而不是拒绝）', ok, msg)
    check('目录权限被收紧到 0755',
          (os.stat(_rules_dir).st_mode & 0o777) == 0o755,
          oct(os.stat(_rules_dir).st_mode & 0o777))

    # ② 规则集文件属主不是 root ⇒ 拒绝加载（fail-closed）
    #
    # ⚠ 为什么用 mock 而不是真的 chown：
    #   ① 守卫只在「当前进程是 root」时才查属主（见 _ruleset_perm_guard 的注释）——
    #      开发机/CI 上通常不是 root ⇒ 真跑会直接跳过这条分支，
    #      变异脚本改坏它就**测不出来**（漏网）。
    #   ② 非 root 也改不了文件属主（chown 需要 root）。
    #   ⇒ 把「进程是 root」与「文件属主」两个输入都做成可控的，
    #      直接测判定分支本身。
    import unittest.mock as _mock
    _real_stat = os.stat

    def _fake_stat(path, *a, **kw):
        st = _real_stat(path, *a, **kw)
        if os.path.abspath(str(path)) == os.path.abspath(_rules_file):
            return _mock.Mock(st_mode=st.st_mode, st_uid=65534, st_gid=st.st_gid)
        return st

    with _mock.patch.object(panel.os, 'stat', _fake_stat), \
            _mock.patch.object(panel.os, 'geteuid', return_value=0):
        ok, msg = panel._ruleset_perm_guard()
    check('规则集文件属主不是 root 时**拒绝**加载', not ok, msg)
    check('拒绝理由里点名了属主',
          '属主' in msg or 'uid' in msg, msg[:160])

    # 同一套输入下，属主是 root ⇒ 放行（证明拒绝不是被别的条件挡住的）
    def _fake_stat_root(path, *a, **kw):
        st = _real_stat(path, *a, **kw)
        if os.path.abspath(str(path)) == os.path.abspath(_rules_file):
            return _mock.Mock(st_mode=st.st_mode, st_uid=0, st_gid=st.st_gid)
        return st

    with _mock.patch.object(panel.os, 'stat', _fake_stat_root), \
            _mock.patch.object(panel.os, 'geteuid', return_value=0):
        ok, msg = panel._ruleset_perm_guard()
    check('属主是 root 时同样放行（拒绝确实由属主触发）', ok, msg)

    # ③ 备份材料权限收口（老版本建的 .backup 是 0644 world-readable）
    _bak = _rules_file + '.backup'
    with open(_bak, 'w', encoding='utf-8') as _f:
        _f.write('x')
    os.chmod(_bak, 0o644)
    ok, msg = panel._ruleset_perm_guard()
    check('备份材料被收口到 0600',
          (os.stat(_bak).st_mode & 0o777) == 0o600,
          oct(os.stat(_bak).st_mode & 0o777))

    # ④ 正常情况：目录 0755、文件 0600 ⇒ 放行
    os.chmod(_rules_dir, 0o755)
    os.chmod(_rules_file, 0o600)
    ok, msg = panel._ruleset_perm_guard()
    check('正常情况放行', ok, msg)

    # ⑤ 调用点必须**真的用上**守卫的结果
    #    （只测守卫函数本身不够：守卫写得再好，调用点不调它就等于没写）
    _cfg = panel.load_config()
    with _mock.patch.object(panel.os, 'stat', _fake_stat), \
            _mock.patch.object(panel.os, 'geteuid', return_value=0):
        try:
            _ok, _msg = panel._apply_ruleset_locked(_cfg)
        except Exception as _e:                   # noqa: BLE001
            _ok, _msg = False, f'{type(_e).__name__}: {_e}'
    check('权限不安全时，规则应用路径会拒绝加载', not _ok, str(_msg)[:160])
    check('拒绝理由来自权限守卫（不是 nft 之类的其它原因）',
          '属主' in str(_msg) or '权限' in str(_msg), str(_msg)[:160])
finally:
    panel.RULES_PATH = _orig_rules_path


# ============================================================
# 条目 14：审计日志轮转不能把 login_ok 挤掉
# ============================================================

sec('条目 14：审计日志轮转不能把 login_ok 挤掉')


def _audit_line(event, ts):
    return json.dumps({
        "ts": ts, "event": event, "ip": "10.0.0.7",
        "device": None, "fp": None, "user": None,
        "ua": "Mozilla/5.0 " + "x" * 120, "uri": "/auth/verify",
    }, ensure_ascii=False) + "\n"


_orig_max_bytes = ag.AUDIT_LOG_MAX_BYTES
try:
    # 用小预算把逻辑测透（轮转按字节预算裁剪，与文件大小无关）
    ag.AUDIT_LOG_MAX_BYTES = 8000
    _p = os.path.join(TD, 'rotate-small.log')
    _lines = [_audit_line('login_ok', '2026-11-21T10:00:00')]
    _lines.append(_audit_line('logout', '2026-11-21T10:00:30'))
    # 后面全是未认证者可触发的灌水记录，总量远超预算
    for _i in range(400):
        _lines.append(_audit_line('verify_denied', '2026-11-21T10:%02d:%02d'
                                   % (_i // 60 % 60, _i % 60)))
    with open(_p, 'w', encoding='utf-8') as _f:
        _f.write(''.join(_lines))

    ag._audit_rotate_in_place(_p)
    with open(_p, encoding='utf-8') as _f:
        _kept = _f.readlines()

    check('login_ok 没被灌水的记录挤掉',
          any('"login_ok"' in _l for _l in _kept),
          f'剩 {len(_kept)} 行')
    check('logout 也没被挤掉',
          any('"logout"' in _l for _l in _kept))
    check('轮转后大小不超过预算（上限的一半）',
          os.path.getsize(_p) <= ag.AUDIT_LOG_MAX_BYTES // 2 + 1024,
          f'{os.path.getsize(_p)} 字节')
    check('时间顺序没被打乱（login_ok 仍在最前）',
          bool(_kept) and '"login_ok"' in _kept[0],
          (_kept[0][:80] if _kept else '空'))

    # 坏 JSON 行不能让轮转崩掉
    _p2 = os.path.join(TD, 'rotate-broken.log')
    with open(_p2, 'w', encoding='utf-8') as _f:
        _f.write('这不是 JSON\n')
        _f.write(_audit_line('login_ok', '2026-11-21T10:00:00'))
        for _i in range(400):
            _f.write(_audit_line('verify_denied', '2026-11-21T10:%02d:%02d'
                                  % (_i // 60 % 60, _i % 60)))
    try:
        ag._audit_rotate_in_place(_p2)
        _broken_ok = True
        _broken_detail = ''
    except Exception as _e:                      # noqa: BLE001
        _broken_ok = False
        _broken_detail = f'{type(_e).__name__}: {_e}'
    check('坏 JSON 行不会让轮转崩掉', _broken_ok, _broken_detail)
    if _broken_ok:
        with open(_p2, encoding='utf-8') as _f:
            _k2 = _f.readlines()
        check('坏行存在时 login_ok 仍然保住',
              any('"login_ok"' in _l for _l in _k2), f'剩 {len(_k2)} 行')

    # 生产默认值下也成立（真实 2 MiB 预算）
    ag.AUDIT_LOG_MAX_BYTES = _orig_max_bytes
    _p3 = os.path.join(TD, 'rotate-real.log')
    with open(_p3, 'w', encoding='utf-8') as _f:
        _f.write(_audit_line('login_ok', '2026-11-21T10:00:00'))
        _n = 0
        while _f.tell() < _orig_max_bytes + 4096:
            _f.write(_audit_line('verify_denied',
                                  '2026-11-21T10:%02d:%02d' % (_n // 60 % 60, _n % 60)))
            _n += 1
    ag._audit_rotate_in_place(_p3)
    with open(_p3, encoding='utf-8') as _f:
        _k3 = _f.readlines()
    check('真实 2 MiB 预算下 login_ok 也保住',
          any('"login_ok"' in _l for _l in _k3), f'剩 {len(_k3)} 行')
finally:
    ag.AUDIT_LOG_MAX_BYTES = _orig_max_bytes


# ============================================================
# 条目 55：改了认证服务内部端口必须提示重启
# ============================================================

sec('条目 55：改了认证服务内部端口必须提示重启')

_orig_deploy = panel._deploy_gateway_nginx
_orig_apply = panel._apply_ruleset
try:
    panel._deploy_gateway_nginx = lambda cfg=None: (True, 'ok')
    panel._apply_ruleset = lambda cfg: (True, 'ok')
    panel.app.before_request_funcs[None] = []
    client = panel.app.test_client()
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = 9e9
        # ⚠ last_active 缺省 0 会被当成 1970 年空闲 ⇒ 401 AUTH_EXPIRED
        sess['last_active'] = time.time()

    r = client.post('/api/gateway/config', json={'auth_api_port': 8555})
    b = r.get_json() or {}
    warn = str((b.get('data') or {}).get('warning') or '')
    check('返回 200', r.status_code == 200,
          f'HTTP {r.status_code} {str(b)[:160]}')
    check('warning 里明确提示必须重启认证服务',
          '必须重启认证服务' in warn, warn[:200])
    check('warning 里点出了新旧两个端口',
          '8444' in warn and '8555' in warn, warn[:200])
    check('配置确实落盘了',
          json.load(open(CFG, encoding='utf-8')).get('auth_api_port') == 8555)

    # 端口没变 ⇒ 不该再提示重启
    r = client.post('/api/gateway/config', json={'auth_api_port': 8555})
    b2 = r.get_json() or {}
    warn2 = str((b2.get('data') or {}).get('warning') or '')
    check('端口没变时不再提示重启',
          '必须重启认证服务' not in warn2, warn2[:200])

    # LAN 内免登录的原有提醒不能被挤掉（不回归）
    r = client.post('/api/gateway/config',
                    json={'gateway_enabled': True, 'auth_lan_bypass': True})
    b3 = r.get_json() or {}
    warn3 = str((b3.get('data') or {}).get('warning') or '')
    check('LAN 内免登录的原有提醒仍然保留',
          'LAN 内免登录' in warn3, warn3[:200])
finally:
    panel._deploy_gateway_nginx = _orig_deploy
    panel._apply_ruleset = _orig_apply


# ============================================================
print('\n' + '=' * 60)
print(f'通过 {len(PASS)} 条，失败 {len(FAIL)} 条')
if FAIL:
    for _f in FAIL:
        print('  [FAIL] ' + _f)
    sys.exit(1)
print('[OK] 全部通过')
sys.exit(0)
