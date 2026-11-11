#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
面板「系统信息页开关」与「访问边界缓存」的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_panel_switches.py

测什么有效
----------
这一批改了两处：

  1. `/api/system/info` 新增 `data.panel` —— 面板自身的开关与计数。
  2. `_NETS_CACHE` 的缓存键从「只有 mtime」改成「路径 + mtime」。

两处的风险都不是「报错」，而是「**显示错的东西**」：

  · 面板开关那一块最容易出的错是**读到了不该读的**：
    ① 用 load_config() 读配置 ⇒ 配置损坏时它会把配置文件 `os.replace`
       **移走**（load_config 的 1048~1053 行）。
       系统信息页是最"无害"的页面，点开看一眼不该把配置搞没。
    ② 用 `bool(cfg.get(key))` 判开关 ⇒ `bool('yes')` / `bool('false')`
       都是 True ⇒ 手工改坏的配置会让页面显示成「开」。
    ③ 不跑 _migrate_forward_rules ⇒ 老配置（tcp_services/dsm_ip4）
       的转发规则条数显示成 0，而面板实际是生效的。
    ④ 名单只算 v4 不算 v6 ⇒ 白名单/黑名单条数少一半。
  · 缓存键那一处：只用 mtime 的话，「配置从备份恢复、mtime 被保留」
    会命中旧缓存 ⇒ 面板继续按**旧的**访问边界放行/拒绝。
    实测 tmpfs 上连续创建的两个文件 st_mtime_ns **完全相同**
    （粗时钟粒度，不是纳秒级）⇒ 换配置文件也可能命中旧缓存。

对应关系
--------
  F1  只读读配置被换成 load_config()（配置文件会被移走）
  F2  开关判定退回 bool()（非布尔值被当成「开」）
  F3  白名单只算 IPv4（漏掉 allowed6）
  F4  黑名单只算 IPv4（漏掉 blacklist6）
  F5  不跑 _migrate_forward_rules（旧配置的转发规则显示成 0 条）
  F6  反代规则不滤掉非对象元素（条数比实际生效的多）
  F7  缓存键去掉路径（换配置路径会命中旧缓存）
  F8  config 不是 dict 时返回 {} 而不是 None
  F9  cert_ready 只看证书不看私钥
  F10 ddns_configured 恒为 False

保险丝：只备份 / 还原**我自己会改的那一个文件**（backend/app.py）。
还原后逐个比对 sha256 —— 源码没还原干净时**必须**当成失败，
不能把「测试假红」误报成「变异被捕获」。

锚点
----
每条变异用成对的精确字符串，且必须在源码里**唯一**。
匹配不上就当场报错并算作漏网。
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, 'backend', 'app.py')
# 这一批涉及两个文件：接口测试（开关）与边界测试（缓存键）
TESTS = [
    os.path.join(ROOT, 'tests', 'test_system_info_endpoint.py'),
    os.path.join(ROOT, 'tests', 'test_panel_binding.py'),
]

# 我独占、也只有我会改的那一个文件。
ORIG = {TARGET: open(TARGET, encoding='utf-8').read()}
ORIG_SHA = {p: hashlib.sha256(c.encode('utf-8')).hexdigest()
            for p, c in ORIG.items()}


def _judge_capture(rc, out):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」
      （2026-11-11 审查 M8：崩了也被记成「捕获」⇒ 那个捕获是假的）。
    ⇒ 只有输出里真的出现**断言失败**的标记行才算捕获；
      只有崩溃、没有失败行的 ⇒ 算漏网（宁可漏判，不可假捕获）。
    """
    if rc == 0:
        return False
    for line in out.splitlines():
        s = line.strip()
        # 失败标记用 Unicode 转义写：源码里不出现符号本身（AGENTS.md 禁 emoji）
        if ('[FAIL]' in s and '[PASS]' not in s) or \
                ('\u274c' in s and '\u2705' not in s):
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    """把 app.py 还原成脚本启动时的内容。幂等，可反复调用。"""
    for path, content in ORIG.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    for path, want in ORIG_SHA.items():
        try:
            with open(path, 'rb') as f:
                got = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            got = None
        if got != want:
            return False, '%s 还原后 sha256 不一致（%s != %s）' % (
                os.path.basename(path), got, want)
    return True, '源码已还原，sha256 一致'


def _restore_and_exit(signum, frame):
    restore()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    try:
        signal.signal(_sig, _restore_and_exit)
    except (ValueError, OSError):
        pass

atexit.register(restore)


def run_tests():
    """跑全部相关测试文件。任何一个红就算变异被捕获。"""
    out = []
    rc_all = 0
    for t in TESTS:
        r = subprocess.run([sys.executable, t], capture_output=True, text=True,
                           cwd=ROOT, timeout=900,
                           env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        out.append(r.stdout + r.stderr)
        if r.returncode != 0:
            rc_all = 1
    return rc_all, '\n'.join(out)


# ─────────────────────────────────────────────────────────────
# 变异定义：(名称, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

# ⚠️ 锚点必须**整块**替换，不能只换 `with open(...)` 那几行。
#   之前锚点从 `        with open(...)` 起、到 `    return data ...` 止，
#   把外层的 `    try:` 留在原地 —— 替换后变成
#       try:
#       data = load_config()
#   ⇒ IndentationError ⇒ 整个 app.py 语法错误 ⇒ 测试**崩了**而不是**断言失败**。
#   崩溃被旧的「rc != 0 即算捕获」口径记成假捕获（2026-11-11 审查 M8）。
#   ⇒ 语法错误的变异不是行为变异，必须把 `try:` 一起纳入锚点。
_RO_OLD = """    try:
        with open(CONFIG_PATH, 'r') as f:
            data = json.load(f)
    except (OSError, IOError, ValueError):
        # ValueError 覆盖 json.JSONDecodeError
        return None
    return data if isinstance(data, dict) else None"""

_RO_NEW = """    data = load_config()
    return data if isinstance(data, dict) else None"""

MUTATIONS = [
    ('F1  只读读配置被换成 load_config()（配置文件损坏时会被移走）',
     [(_RO_OLD, _RO_NEW)]),

    ('F2  开关判定退回 bool()（非布尔值被当成「开」）',
     [("            'on': raw if isinstance(raw, bool) else False,",
       "            'on': bool(raw),")]),

    ('F3  白名单只算 IPv4（漏掉 allowed6）',
     [("    whitelist = len(lists.get('allowed4', []) or []) + len(lists.get('allowed6', []) or [])",
       "    whitelist = len(lists.get('allowed4', []) or [])")]),

    ('F4  黑名单只算 IPv4（漏掉 blacklist6）',
     [("    blacklist = len(lists.get('blacklist4', []) or []) + len(lists.get('blacklist6', []) or [])",
       "    blacklist = len(lists.get('blacklist4', []) or [])")]),

    ('F5  不跑 _migrate_forward_rules（旧配置的转发规则显示成 0 条）',
     [("    raw = _migrate_forward_rules(dict(config))",
       "    raw = dict(config)")]),

    ('F6  反代规则不滤掉非对象元素（条数比实际生效的多）',
     [("    rp_rules = [r for r in rp_rules if isinstance(r, dict)]",
       "    rp_rules = list(rp_rules)")]),

    ('F7  缓存键去掉路径（换配置路径会命中旧缓存）',
     [("""        if (_NETS_CACHE['path'] == CONFIG_PATH
                and _NETS_CACHE['mtime'] is not None
                and _NETS_CACHE['mtime'] == stamp):""",
       """        if (_NETS_CACHE['mtime'] is not None
                and _NETS_CACHE['mtime'] == stamp):""")]),

    ('F8  config 不是 dict 时返回 {} 而不是 None',
     [("""    if not isinstance(config, dict):
        return None""",
       """    if not isinstance(config, dict):
        return {}""")]),

    ('F9  cert_ready 只看证书不看私钥',
     [("        'cert_ready': os.path.exists(NFTABLES_WEB_CERT) and os.path.exists(NFTABLES_WEB_KEY),",
       "        'cert_ready': os.path.exists(NFTABLES_WEB_CERT),")]),

    ('F10 ddns_configured 恒为 False',
     [("        'ddns_configured': os.path.exists(ALIYUN_DDNS_CONFIG_PATH),",
       "        'ddns_configured': False,")]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    ok, detail = restore_verified()
    if not ok:
        print('[FAIL] %s —— 变异验证无意义' % detail)
        return 1
    rc, out = run_tests()
    if rc != 0:
        print('[FAIL] 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-3000:])
        return 1
    print('  [PASS] 基线通过\n')

    caught = missed = 0
    for name, edits in MUTATIONS:
        src = ORIG[TARGET]
        bad = [old for old, _ in edits if old not in src]
        dup = [old for old, _ in edits if src.count(old) != 1]
        if bad or dup:
            why = []
            if bad:
                why.append('锚点没匹配上（源码变了？）')
            if dup:
                why.append('锚点出现 %d 次，不是唯一' % src.count(dup[0]))
            print('  [FAIL] %s  —— ' % name + '；'.join(why) + ' ⇒ 算漏网')
            missed += 1
            continue
        try:
            mutated = src
            for old, new in edits:
                mutated = mutated.replace(old, new, 1)
            with open(TARGET, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if _judge_capture(rc, out):
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l and '[PASS]' not in l), '')
                if not first:
                    first = next((l.strip() for l in out.splitlines()
                                  if '❌' in l), '')
                print('  [PASS] %s  —— 被捕获' % name)
                if first:
                    print('      ↓ %s' % first)
                caught += 1
            else:
                print('  [FAIL] %s  —— 漏网！测试没抓住' % name)
                missed += 1
        finally:
            ok, detail = restore_verified()
            if not ok:
                print('  [FAIL] %s  —— %s ⇒ 后续变异全部作废' % (name, detail))
                print('=' * 60)
                print('  捕获 %d / %d（本次中止：源码没还原干净）'
                      % (caught, caught + missed + 1))
                return 1

    print()
    print('=' * 60)
    print('  捕获 %d / %d' % (caught, caught + missed))
    if missed:
        print('  源码已全部还原，但有漏网项 —— 上面标 [FAIL] 的测试是假测试')
    else:
        print('  源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
