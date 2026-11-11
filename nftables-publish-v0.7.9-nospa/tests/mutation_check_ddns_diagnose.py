#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""取证脚本（tools/ddns-aliyun-diagnose.py）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_ddns_diagnose.py

测什么有效
----------
这个脚本是**要拿到用户真机上跑**的取证工具，出错的代价不对称：
判据误报会让排查方向整个跑偏，而用户只有一次机会去现场取这个证。

所以本脚本盯两类退化：

  **一、只读红线（写操作）**
    取证脚本一旦能删 DNS 记录，就是帮倒忙。
    · Action 换成 DeleteDomainRecord
    · Action 用拼接绕过字面量匹配
    · 用 curl 发写请求（subprocess 绕过 urlopen 的 AST 白名单）
    · 通用 API 入口 _api() 复活（随手就能加写操作）

  **二、脱敏与落盘（泄露面）**
    脚本的输出会被贴进工单、截图、聊天记录 —— 传播范围不受控。
    · 掩码退回 4+4（比面板侧宽一倍）
    · 掩码直接存明文 secret
    · 快照文件不设 0600（明文 AccessKeyId 与域名全设备可读）
    · 快照文件权限收紧那行被删（老版本留下的 0644 文件不会被收紧）
    · 时间戳退回 naive utcnow()

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。所以这里直接把未命中记成漏网。

⚠️ 语法错误的变异不是行为变异
------------------------------
改出来的代码必须**能跑**，否则测试脚本会崩，而崩溃不等于断言失败
（2026-11-11 审查 M8）。所以每条变异落地后先 py_compile 一次，
语法不过直接记成漏网。

保险丝：只备份 / 还原 tools/ddns-aliyun-diagnose.py 一个文件。
还原后比对 sha256 —— 源码没还原干净时**必须**当成失败。
"""
import atexit
import hashlib
import os
import py_compile
import signal
import subprocess
import sys
import tempfile

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'tools', 'ddns-aliyun-diagnose.py')
TEST = os.path.join(ROOT, 'tests', 'test_ddns_diagnose_script.py')

ORIG = open(SCRIPT, encoding='utf-8').read()
ORIG_SHA = hashlib.sha256(ORIG.encode('utf-8')).hexdigest()


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
                ('❌' in s and '✅' not in s):
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    """把取证脚本还原成启动时的内容。幂等，可反复调用。"""
    try:
        with open(SCRIPT, 'w', encoding='utf-8') as f:
            f.write(ORIG)
    except OSError:
        pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    try:
        with open(SCRIPT, 'rb') as f:
            got = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        got = None
    if got != ORIG_SHA:
        return False, '%s 还原后 sha256 不一致（%s != %s）' % (
            os.path.basename(SCRIPT), got, ORIG_SHA)
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
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=900,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


def apply_edits(src, edits):
    """按顺序应用编辑。锚点必须在源码里**唯一**，否则报错（不静默跳过）。"""
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点出现 %d 次（要求唯一）: %r' % (n, old[:70]))
        src = src.replace(old, new)
    return src


# ─────────────────────────────────────────────────────────────
# 变异定义：(名称, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

MUTATIONS = [
    # ── 一、只读红线 ────────────────────────────────────────
    ('R1  Action 换成 DeleteDomainRecord（取证脚本会删记录）',
     [('"Action": "DescribeDomainRecords",',
       '"Action": "DeleteDomainRecord",')]),

    ('R2  Action 用拼接绕过字面量匹配',
     [('"Action": "DescribeDomainRecords",',
       '"Action": "Delete" + "DomainRecord",')]),

    ('R3  用 curl 发写请求（subprocess 绕过 urlopen 白名单）',
     [('def aliyun_describe(ak_id, ak_secret, region, domain):',
       'def aliyun_describe(ak_id, ak_secret, region, domain):\n'
       '    import subprocess as _sp\n'
       '    _sp.run(["curl", "-X", "POST", "https://example.invalid/x"])')]),

    # ── 二、脱敏 ───────────────────────────────────────────
    ('L4a 掩码退回 4+4（比面板侧宽一倍）',
     [('    return s[:2] + "****" + s[-2:]',
       '    return s[:4] + "****" + s[-4:]')]),

    ('L4b 掩码直接返回明文',
     [('    return s[:2] + "****" + s[-2:]',
       '    return s')]),

    # ── 三、快照落盘权限 ───────────────────────────────────
    #
    # ⚠️ L5a 必须**同时**去掉 chmod 兜底 ——
    #   只把 os.open 的 mode 从 0600 改成 0644 的话，后面那行
    #   `os.chmod(SNAPSHOT_PATH, 0o600)` 会把权限兜回 0600
    #   ⇒ **行为完全不变** ⇒ 这条是等价变异，测不出任何东西。
    #   真实的退化场景是「有人图省事把收紧逻辑整段删掉，只留下宽松的创建」。
    ('L5a 快照文件按 0644 建且不收紧（明文 AccessKeyId 全设备可读）',
     [('        fd = os.open(SNAPSHOT_PATH,\n'
       '                     os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)',
       '        fd = os.open(SNAPSHOT_PATH,\n'
       '                     os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)'),
      ('            try:\n'
       '                os.chmod(SNAPSHOT_PATH, 0o600)\n'
       '            except OSError:\n'
       '                pass\n',
       '')]),

    ('L5b 快照权限收紧那行被删（老版本留下的 0644 不会被收紧）',
     [('            try:\n'
       '                os.chmod(SNAPSHOT_PATH, 0o600)\n'
       '            except OSError:\n'
       '                pass\n',
       '')]),

    # ── 四、时间戳时区 ─────────────────────────────────────
    ('L6  时间戳退回 naive utcnow()',
     [('datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")',
       'datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")')]),
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
        src = ORIG
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
            mutated = apply_edits(src, edits)
            with open(SCRIPT, 'w', encoding='utf-8') as f:
                f.write(mutated)
            # ⚠ 语法错误的变异不是行为变异 —— 测试会崩，而崩溃不等于断言失败。
            #   先编译一次，不通过就记成漏网（并还原）。
            try:
                py_compile.compile(SCRIPT, cfile=os.path.join(
                    tempfile.gettempdir(), 'ddns_diag_mut_check.pyc'),
                    doraise=True)
            except py_compile.PyCompileError as e:
                print('  [FAIL] %s  —— 变异后语法错误（不是行为变异）⇒ 算漏网' % name)
                print('      ↓ %s' % str(e).splitlines()[-1][:100])
                missed += 1
                continue
            rc, out = run_tests()
            if _judge_capture(rc, out):
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l and '[PASS]' not in l), '')
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
