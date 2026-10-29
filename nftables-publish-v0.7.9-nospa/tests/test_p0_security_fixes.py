"""Shannon 渗透测试 P0 缺陷的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_p0_security_fixes.py

覆盖的 7 条（每条都写成「旧代码必然失败」的形式 —— 否则测了等于没测）：

  P0-4   auth_token_epoch 不能经通用 POST /api/config 落盘
  P0-5   触发锁定的那次登录必须返 429 且 remaining=0
  P0-6   PBKDF2 dummy 路径必须不慢于真实路径（计时 oracle）
  P0-7   共享配置不能是 world-readable（0644）
  P0-9   DDNS ipv6_source 必须白名单（路径穿越 + 命令注入）
  P0-10  crontab -l 失败时必须 fail-closed（不能覆盖整个 crontab）
  P0-11  反代 test 端点的错误信息必须归一化（内网端口扫描 oracle）

P0-1 / P0-2 / P0-3 的回归在 test_auth_session_lifecycle.py、
test_gateway_ui_safety.py、test_privilege_drop.py 里。

沙箱运行：只 import 模块并打补丁，不碰真实路径、不执行 nft/nginx/uci/crontab。
"""
import importlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import builtins

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def strip_comments(src):
    """去掉 Python 注释（保留字符串字面量里的 #）。

    为什么需要：修复时为了说明「原来怎么错的」，注释里**引用了旧代码原文**
    （例如 `lines = result.stdout.splitlines() if result.returncode == 0
    else []`）。源码级断言直接搜原文会把注释当成代码 → 误判。
    断言「旧写法已经不在了」必须只看**真正的代码**。
    """
    out = []
    for line in src.splitlines():
        buf = []
        quote = None
        i = 0
        while i < len(line):
            c = line[i]
            if quote:
                buf.append(c)
                if c == '\\' and i + 1 < len(line):
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if c == quote:
                    quote = None
                i += 1
                continue
            if c in ('"', "'"):
                quote = c
                buf.append(c)
                i += 1
                continue
            if c == '#':
                break
            buf.append(c)
            i += 1
        out.append(''.join(buf))
    return '\n'.join(out)


def func_body(src, name):
    """取出 `def name(...)` 的函数体（到下一个顶层 def/@ 之前）。

    比裸正则可靠：函数体里出现 `def` 子定义、或装饰器换行都不会截错。
    返回的是**去掉注释后**的代码。
    """
    m = re.search(r'^def\s+' + re.escape(name) + r'\s*\(', src, re.M)
    if not m:
        return ''
    rest = src[m.end():]
    nxt = re.search(r'^(?:@|def\s|class\s)', rest, re.M)
    body = rest[:nxt.start()] if nxt else rest
    return strip_comments(body)


def fresh_app():
    """加载一个面板模块副本，配置文件指向临时目录。"""
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    app.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'cfg.json')
    app.LISTS_PATH = os.path.join(tempfile.mkdtemp(), 'lists.json')
    app.RULES_PATH = os.path.join(tempfile.mkdtemp(), 'rules.nft')
    return app


_SRC_APP = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
_SRC_GW = open(os.path.join(BACKEND, 'auth_gateway.py'), encoding='utf-8').read()
# 去掉注释后的「纯代码」版本 —— 用来断言「旧写法已经不在代码里」。
_SRC_APP_CODE = strip_comments(_SRC_APP)
_SRC_GW_CODE = strip_comments(_SRC_GW)


# ═════════════════════════════════════════════════════════════════════
sec('P0-4  auth_token_epoch 不能经通用 POST /api/config 落盘')

app = fresh_app()

check('auth_token_epoch 在 READONLY_CONFIG_KEYS 里',
      'auth_token_epoch' in app.READONLY_CONFIG_KEYS,
      f'名单={sorted(app.READONLY_CONFIG_KEYS)}')
check('auth_token_epoch **不**在 RP_OWNED / GATEWAY_OWNED 里（那两个是另一套语义）',
      'auth_token_epoch' not in app.RP_OWNED_CONFIG_KEYS
      and 'auth_token_epoch' not in app.GATEWAY_OWNED_CONFIG_KEYS)

# 真打一次 POST /api/config：带 auth_token_epoch，看落盘有没有变。
_cfg = json.loads(json.dumps(app.DEFAULT_CONFIG))
_cfg['auth_token_epoch'] = 0
app.save_config(_cfg)
_pc = app.app.test_client()
_post = _pc.post('/api/config', json={'auth_token_epoch': 999})
check('未认证的 POST /api/config 被拒（鉴权没被绕过）',
      _post.status_code in (401, 403),
      f'HTTP {_post.status_code}')
_saved = json.load(open(app.CONFIG_PATH, encoding='utf-8'))
check('落盘配置里的 auth_token_epoch 没被改成 999',
      int(_saved.get('auth_token_epoch', 0) or 0) == 0,
      f'落盘={_saved.get("auth_token_epoch")}')

# 剔除逻辑本身：auth_token_epoch 必须被从 incoming 里去掉
_incoming = {'auth_token_epoch': 999, 'gateway_port': 8443}
for _k in app.READONLY_CONFIG_KEYS:
    _incoming.pop(_k, None)
check('剔除逻辑会把 auth_token_epoch 从 incoming 里去掉',
      'auth_token_epoch' not in _incoming,
      f'剩余={sorted(_incoming)}')

# 源码级：/api/config 必须真的调用了剔除
_pc_body = func_body(_SRC_APP, 'post_config')
check('post_config 里对 READONLY_CONFIG_KEYS 做了剔除',
      'readonly_hits' in _pc_body and 'for k in READONLY_CONFIG_KEYS' in _pc_body,
      '读不到剔除逻辑，测试需要更新')

# 改密码路径必须**能**写 epoch（否则改密码就作废不了会话）
_cp_body = func_body(_SRC_APP, 'auth_change_password')
check('改密码路径仍然写 auth_token_epoch（没被误伤）',
      'auth_token_epoch' in _cp_body,
      '改密码必须能递增世代号')

# ── 端到端：拿管理员会话真打一次 POST /api/config ──────────────────
#
# 为什么必须补这一段：
#   上面那条「落盘没被改成 999」用的是**未认证**请求 —— 它在鉴权那一步
#   就被拒了（401），**压根没走到剔除逻辑**。所以它证明的是「鉴权没被
#   绕过」，证明不了「剔除逻辑真的生效」。
#   而源码级断言（post_config 里有没有 `for k in READONLY_CONFIG_KEYS`）
#   是**文本**层面的：谁把那个循环换成 pass，文本断言会红；但谁把剔除
#   挪到别处、只改了一半、或换了个键名，文本断言看不出来。
#
# Shannon P0-4 的原始实测就是这样打穿的：管理员会话
# POST /api/config {"auth_token_epoch": 999} → 200「配置已保存」，
# 落盘真的变成 999，三个剔除名单一个都没拦它。
app2 = fresh_app()
_cfg3 = json.loads(json.dumps(app2.DEFAULT_CONFIG))
_cfg3['auth_token_epoch'] = 0
app2.save_config(_cfg3)
_hooks2 = list(app2.app.before_request_funcs[None])
app2.app.before_request_funcs[None] = []      # 去掉全局拦截器（含 CSRF），改用会话认证
try:
    _pc2 = app2.app.test_client()
    with _pc2.session_transaction() as sess:
        sess['authenticated'] = True
    _post2 = _pc2.post('/api/config', json={'auth_token_epoch': 999,
                                           'trusted_ip4': '192.168.100.224'})
    check('管理员会话 POST /api/config 仍然 200（剔除字段不能把接口搞失败）',
          _post2.status_code == 200,
          f'HTTP {_post2.status_code} {_post2.get_data(as_text=True)[:160]}')
    _d2 = (_post2.get_json() or {}).get('data') or {}
    check('管理员会话 POST 时 auth_token_epoch 被列入 ignored_readonly_fields',
          'auth_token_epoch' in (_d2.get('ignored_readonly_fields') or []),
          f'实际={_d2.get("ignored_readonly_fields")}')
    _saved2 = json.load(open(app2.CONFIG_PATH, encoding='utf-8'))
    check('**管理员会话也改不掉 auth_token_epoch**（通用路径彻底写不进去）',
          int(_saved2.get('auth_token_epoch', 0) or 0) == 0,
          f'落盘={_saved2.get("auth_token_epoch")} —— 世代号能被通用路径改 = '
          f'「改密码作废全部会话」的保证被撤销')
    check('同一请求里的正常字段照常保存（剔除不能连累正常功能）',
          _saved2.get('trusted_ip4') == '192.168.100.224',
          f'实际={_saved2.get("trusted_ip4")!r}')
finally:
    app2.app.before_request_funcs[None] = _hooks2


# ═════════════════════════════════════════════════════════════════════
sec('P0-5  触发锁定的那次登录必须返 429 且 remaining=0')

app = fresh_app()

# ① 锁定时**不能**清空 fails —— 否则 fail_count=0 → remaining 被算成 5
check('_mutate_ratelimit 锁定时不再清空 fails',
      not re.search(r'rec\["locked_until"\]\s*=\s*now\s*\+\s*RATE_LIMIT_LOCKOUT\s*\n\s*rec\["fails"\]\s*=\s*\[\]',
                    _SRC_GW_CODE),
      '清空 fails 会让 remaining 被算成 MAX-0=5（实测序列 4→3→2→1→5→429）')
check('降级路径同样不清空 fails',
      not re.search(r'"locked_until":\s*now\s*\+\s*RATE_LIMIT_LOCKOUT,\s*"fails":\s*\[\]',
                    _SRC_GW_CODE),
      '内存兜底路径有同样的 bug')

# ② auth_login 必须认 locked → 429
_al_body = func_body(_SRC_GW, 'auth_login')
check('auth_login 读到了 locked 标志', 'locked, fails = _mutate_ratelimit' in _al_body)
check('auth_login 在 locked 时返 429', 'RATE_LIMITED' in _al_body and '429' in _al_body)
check('auth_login 在 locked 时 remaining 归 0', 'remaining = 0' in _al_body)

# ③ _is_locked 读端必须拿共享锁（否则可能读到半截 JSON → 当成没锁）
_il_body = func_body(_SRC_GW, '_is_locked')
check('_is_locked 读端持 flock(LOCK_SH)',
      'LOCK_SH' in _il_body,
      '不拿共享锁就可能读到 truncate 后的半截 JSON → 当作未锁定 → 防护被绕过')

# ④ 行为验证：真的连打错密码，第 N 次必须返 429 且 remaining=0
_td = tempfile.mkdtemp()
sys.modules.pop('auth_gateway', None)
_gw = importlib.import_module('auth_gateway')
_gw.RATELIMIT_FILE = os.path.join(_td, 'rl.json')
_gw._RATE_FALLBACK.clear()
_gw.PBKDF2_ITERATIONS_MIN = 1000          # 沙箱里跑得快一点
_stored = "pbkdf2_sha256$1000$salt$" + "0" * 64
_real_hash = _gw._password_hash
_gw._password_hash = lambda: _stored
_gc = _gw.app.test_client()
_codes = []
for _i in range(6):
    _r = _gc.post('/auth/login', json={'password': 'wrong'},
                  headers={'X-Real-IP': '9.9.9.9'})
    _codes.append((_r.status_code, (_r.get_json() or {}).get('remaining')))
_gw._password_hash = _real_hash
check('连打 6 次错密码：最后两次是 429',
      _codes[-2][0] == 429 and _codes[-1][0] == 429,
      f'序列={_codes}')
check('触发锁定的那次 remaining=0（不是 5）',
      _codes[4][1] == 0, f'第 5 次={_codes[4]}')
check('锁定前 remaining 递减（4→3→2→1）',
      [_c[1] for _c in _codes[:4]] == [4, 3, 2, 1],
      f'序列={_codes[:4]}')


# ═════════════════════════════════════════════════════════════════════
sec('P0-6  PBKDF2 dummy 路径必须不慢于真实路径')

app = fresh_app()
sys.modules.pop('auth_gateway', None)
_gw2 = importlib.import_module('auth_gateway')
_gw2.PBKDF2_ITERATIONS_MIN = 1000

check('定义了 dummy 基准迭代数（≥ 面板默认 200000）',
      getattr(_gw2, 'PBKDF2_ITERATIONS_DUMMY', 0) >= 200000,
      f'实际={getattr(_gw2, "PBKDF2_ITERATIONS_DUMMY", "未定义")}')

# dummy 路径（stored 损坏）用的迭代数 ≥ 真实路径
_vp_body = func_body(_SRC_GW, '_verify_password')
check('dummy 路径取 max(存储 iters, MIN, 基准)',
      'max(' in _vp_body and 'PBKDF2_ITERATIONS_DUMMY' in _vp_body,
      f'dummy 迭代数={_vp_body[-400:]}')

# 行为验证：dummy 路径耗时 ≥ 真实路径耗时
# （每条测两次取 min，抵消调度抖动；旧代码 dummy=100000 轮 vs 真实=200000 轮
#   → 比值约 0.5，稳定低于 0.85 阈值）
def _timeit(fn, *a):
    _best = 1e9
    for _ in range(2):
        _t0 = time.perf_counter()
        fn(*a)
        _best = min(_best, time.perf_counter() - _t0)
    return _best


_real = "pbkdf2_sha256$200000$salt$" + "0" * 64
_bad = "pbkdf2_sha256$notanumber$salt$deadbeef"
_t_real = _timeit(_gw2._verify_password, "x", _real)
_t_dummy = _timeit(_gw2._verify_password, "x", _bad)
check('dummy 路径耗时 ≥ 真实路径（不能再用响应时间区分状态）',
      _t_dummy >= _t_real * 0.85,
      f'真实={_t_real * 1000:.1f}ms，dummy={_t_dummy * 1000:.1f}ms，'
      f'比值={_t_dummy / max(_t_real, 1e-9):.2f}x')
check('dummy 路径确实跑了真活（不是 0ms 直接返回）',
      _t_dummy >= 0.02, f'dummy={_t_dummy * 1000:.1f}ms')


# ═════════════════════════════════════════════════════════════════════
sec('P0-7  共享配置不能是 world-readable')

app = fresh_app()
check('定义了配置目标权限 0640',
      getattr(app, '_CONFIG_FILE_MODE', None) == 0o640,
      f'实际={getattr(app, "_CONFIG_FILE_MODE", "未定义")}')

# 真跑两次 save_config：第一次建文件，第二次才会产生 .backup
_cfg2 = json.loads(json.dumps(app.DEFAULT_CONFIG))
_cfg2['auth_token_epoch'] = 0
app.save_config(_cfg2)
app.save_config(_cfg2)
_m = os.stat(app.CONFIG_PATH).st_mode & 0o777
check('save_config 写出的配置是 0640（对「其他」关闭）',
      _m == 0o640, f'实际={_m:o}')
check('配置对「其他」用户完全不可读',
      (_m & 0o007) == 0, f'其他用户权限={_m & 0o007:o}')
check('.backup 存在', os.path.exists(app.CONFIG_PATH + '.backup'))
if os.path.exists(app.CONFIG_PATH + '.backup'):
    _mb = os.stat(app.CONFIG_PATH + '.backup').st_mode & 0o777
    check('.backup 同样是 0640（shutil.copy 不复制权限位）',
          _mb == 0o640, f'实际={_mb:o}')

_sc_body = func_body(_SRC_APP, 'save_config')
check('save_config 在 os.replace 之前 chmod 了临时文件',
      'os.chmod(tmp_path, _CONFIG_FILE_MODE)' in _sc_body,
      '少了 chmod 的话 open() 出来的就是 umask 默认值（0644）')


# ═════════════════════════════════════════════════════════════════════
sec('P0-9  DDNS ipv6_source 必须白名单（路径穿越 + 命令注入）')

app = fresh_app()
check('存在 _validate_ddns_services 预校验函数',
      hasattr(app, '_validate_ddns_services'))
if not hasattr(app, '_validate_ddns_services'):
    # 旧代码没有这个函数 —— 后面几条直接调用它会抛异常。这里挡住，
    # 让整套测试能跑完并把「旧代码缺了什么」完整列出来，而不是第一处
    # AttributeError 就中断。
    _val = lambda _svc: (True, '（未实现 _validate_ddns_services，跳过）')
else:
    _val = app._validate_ddns_services

_ok, _msg = _val([
    {'name': 'a', 'ipv6_source': 'router'},
    {'name': 'b', 'ipv6_source': 'rule_1'},
    {'name': 'c', 'ipv6_source': 'rule_12'},
    {'name': 'd', 'ipv6_source': ''},
])
check('合法值放行（router / rule_<数字> / 空）', _ok, _msg)

for _bad_val in ('../../etc/hostname', 'x;id', 'rule_', 'rule_1;id',
                 'rule_../../etc', '/etc/shadow', 'rule_1x', 'router;id'):
    _ok2, _msg2 = _val([{'name': 'z', 'ipv6_source': _bad_val}])
    check(f'非法 ipv6_source 被拒: {_bad_val!r}', not _ok2, _msg2)

# 预校验必须在「删除现有 service」之前
_sd_body = func_body(_SRC_APP, 'save_ddns_config')
_i_val = _sd_body.find('_validate_ddns_services(services)')
_i_del = _sd_body.find('_parse_ddns_config()')
check('预校验发生在删除现有 service 之前（否则会留半成品配置）',
      _i_val >= 0 and _i_del >= 0 and _i_val < _i_del,
      f'校验位置={_i_val}，删除位置={_i_del}')

# 拼装处必须用白名单推导 idx，不能再 replace('rule_','')
_i_use = _sd_body.find("if svc.get('use_ipv6') and ipv6_source:")
_i_set = _sd_body.find("_uci_set(f'ddns.{uci_name}.ip_script'")
_seg = _sd_body[_i_use:_i_set] if (_i_use >= 0 and _i_set > _i_use) else ''
check('拼装 ip_script 时用 fullmatch 推导 idx（不再用 replace 拼路径）',
      'fullmatch' in _seg and '_m.group(1)' in _seg,
      'idx 必须来自白名单推导')
check("源码里不再有 ipv6_source.replace('rule_', '') 这种直接拼路径的写法",
      "ipv6_source.replace('rule_', '')" not in _SRC_APP_CODE)
check("源码里不再有 .replace('rule_', '') 这种裸 replace 拼 idx 的写法",
      ".replace('rule_', '')" not in _SRC_APP_CODE)


# ═════════════════════════════════════════════════════════════════════
sec('P0-10  crontab -l 失败时必须 fail-closed')

app = fresh_app()

# ① _upsert_cron_for：读取失败 → 返回 False，且**不能**调 `crontab -`
_ups_body = func_body(_SRC_APP, '_upsert_cron_for')
check('_upsert_cron_for 检查 crontab -l 的 returncode',
      'returncode != 0' in _ups_body,
      '原来查了 returncode 但失败时仍用空列表继续 → 覆盖整个 crontab')
check('_upsert_cron_for 读取失败时直接返回错误（不再用空列表继续）',
      'splitlines() if result.returncode == 0 else []' not in _ups_body
      and re.search(r'return\s+False', _ups_body) is not None,
      '失败必须是 fail-closed')

# 行为验证：mock 一个 `crontab -l` 返回非 0 的 subprocess.run
#
# ⚠️ mock 必须**拦掉所有** crontab 调用，不能只拦 `-l`：
# 只拦 `-l` 的话，一旦被测代码（修复前）继续往下走到 `crontab -`，
# 那条命令会**真的执行**，把本机的 root crontab 覆盖掉 —— 这正是
# P0-10 描述的那个故障，而测试自己就成了故障源。
# 所以 `-` 一律抛异常：测试失败，但绝不动真 crontab。
_calls = []
_real_run = subprocess.run


def _fake_run(cmd, *a, **kw):
    _calls.append(cmd)
    if isinstance(cmd, (list, tuple)) and 'crontab' in cmd:
        if '-l' in cmd:
            class _R:
                returncode = 1
                stdout = ''
                stderr = "crontab: can't open 'root': No such file or directory"
            return _R()
        # 写入类调用：绝不放行到真实 crontab
        raise AssertionError(f'测试不允许真正写 crontab：{cmd!r}')
    return _real_run(cmd, *a, **kw)


subprocess.run = _fake_run
try:
    _ok3, _msg3 = app._upsert_cron_for('/opt/x/update.sh', '* * * * * /opt/x/update.sh')
except AssertionError as e:
    # 被测代码在读不到 crontab 时仍然往下走到了写入 → 正是 P0-10 那个故障。
    # mock 把它拦下来了（没有真的动本机 crontab），这里记成失败。
    _ok3, _msg3 = True, f'读失败后仍然尝试写 crontab（已被 mock 拦下）: {e}'
finally:
    subprocess.run = _real_run
check('crontab -l 失败时 _upsert_cron_for 返回失败', not _ok3, _msg3)
check('crontab -l 失败时**没有**执行 `crontab -`（不会覆盖 crontab）',
      ['crontab', '-'] not in _calls,
      f'调用={_calls}')

# ② install_china_ips 同样必须 fail-closed
#
# 这里原来只有一条**源码文本**断言（'returncode != 0' 出现在函数体里），
# 但 install_china_ips 里有**两处** returncode 检查：一处是读 crontab -l
# （这才是要 fail-closed 的那处），另一处是写 crontab -。
# 「函数体里出现过 returncode != 0」这种粗断言，把**读**的那一处变异掉
# 照样能通过 —— 变异脚本第一轮就抓到了这个洞（漏网 1 条）。
#
# 所以拆成两件事：
#   ① **精确**断言：crontab -l 读取点与 existing= 之间必须有 returncode 闸门
#   ② **行为**断言：真的打一次端点，看它有没有执行 `crontab -`
_iic_body = func_body(_SRC_APP, 'install_china_ips')
_i_l = _iic_body.find("'crontab', '-l'")
_i_e = _iic_body.find('existing =', _i_l) if _i_l >= 0 else -1
_iic_gate = _iic_body[_i_l:_i_e] if (_i_l >= 0 and _i_e > _i_l) else ''
check('install_china_ips 在 crontab -l 读取点后有 returncode 闸门（fail-closed）',
      'returncode != 0' in _iic_gate,
      f'读取点与 existing= 之间={_iic_gate[:200]!r}')
check('install_china_ips 读取失败时返回错误且不做任何修改',
      re.search(r'returncode\s*!=\s*0.*?return jsonify', _iic_gate, re.S) is not None,
      f'闸门段={_iic_gate[:200]!r}')

# 行为级：crontab -l 失败时端点必须中止，且**绝不**执行 `crontab -`
#
# 端点会往 /opt/nftables-web-v2/update-china-ips.sh 写脚本（本机没权限），
# 所以把「建目录 / 写脚本 / chmod」都 mock 掉，只留被测的那段判断逻辑。
_iic_calls = []
_real_open2 = builtins.open
_real_makedirs = os.makedirs
_real_chmod = os.chmod


def _iic_fake_run(cmd, *a, **kw):
    _iic_calls.append(cmd)
    if isinstance(cmd, (list, tuple)) and 'crontab' in cmd:
        if '-l' in cmd:
            class _R2:
                returncode = 1
                stdout = ''
                stderr = "crontab: can't open 'root': No such file or directory"
            return _R2()
        # 写入类调用：绝不放行到真实 crontab（这正是 P0-10 描述的故障）
        raise AssertionError(f'测试不允许真正写 crontab：{cmd!r}')
    return _real_run(cmd, *a, **kw)


def _iic_fake_open(path, mode='r', *a, **kw):
    if str(path).endswith('update-china-ips.sh'):
        return io.StringIO()
    return _real_open2(path, mode, *a, **kw)


subprocess.run = _iic_fake_run
os.makedirs = lambda *a, **k: None
os.chmod = lambda *a, **k: None
builtins.open = _iic_fake_open
try:
    _cfg_ici = json.loads(json.dumps(app.DEFAULT_CONFIG))
    _cfg_ici['china_ip_block'] = True
    app.save_config(_cfg_ici)
    with app.app.test_request_context('/api/firewall/install-china-ips', method='POST'):
        _resp_ici = app.install_china_ips()
    try:
        _ici_ok = bool(_resp_ici[0].get_json().get('success'))
    except Exception:
        _ici_ok = False
finally:
    subprocess.run = _real_run
    os.makedirs = _real_makedirs
    os.chmod = _real_chmod
    builtins.open = _real_open2
check('crontab -l 失败时 install_china_ips 返回失败', not _ici_ok,
      f'实际={_resp_ici!r}')
check('crontab -l 失败时**没有**执行 `crontab -`（不会覆盖整个 root crontab）',
      ['crontab', '-'] not in _iic_calls,
      f'调用={_iic_calls}')


# ═════════════════════════════════════════════════════════════════════
sec('P0-11  反代 test 端点的错误信息必须归一化（内网端口扫描 oracle）')

_rp_body = func_body(_SRC_APP, 'rp_test_rule')
check('不再把原始异常文本回显给请求方',
      '连接失败: {str(e)}' not in _rp_body and 'f"连接失败: {str(e)}"' not in _rp_body,
      'Connection refused / timed out / DNS 失败原本三者可区分 → 就是 oracle 的信息源')
check('不可达时也等满最小时间（消除时间侧信道）',
      '_RP_TEST_MIN_WAIT_MS' in _rp_body and 'time.sleep' in _rp_body,
      'refused 立刻返回 vs 超时等 5 秒，耗时本身就是 oracle')
check('每次探测都记审计（谁、何时、探测了哪个 host:port）',
      '[AUDIT] rp_test_rule' in _rp_body)
check('不可达时 ssl_valid 也归一化（不再恒为 True）',
      '"ssl_valid": reachable' in _rp_body,
      '原来不可达时也返回 ssl_valid=true → 同样能区分')


print()
print(f'  合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
if FAIL:
    for name in FAIL:
        print(f'  ❌ {name}')
    sys.exit(1)
print('  全部通过')
