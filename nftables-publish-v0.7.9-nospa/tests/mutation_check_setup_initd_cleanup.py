#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup.sh「遗留备份归位」这一步的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_setup_initd_cleanup.py

测什么有效
----------
这一步的风险全在「动错东西」上：
  · 把正常的服务脚本当备份挪走 ⇒ 服务起不来；
  · 把软链或目录挪走 ⇒ 直接把机器弄坏（软链可能是别的服务的开关）；
  · 挪到系统目录而不是项目自己的目录 ⇒ 问题原地不动；
  · 根本没被调用 ⇒ 清理等于没做。

文本匹配测不出这些（脚本照样「包含那个函数」），所以
`tests/test_setup_initd_cleanup.py` 是**真跑**那个 shell 函数的 ——
把 setup.sh 拷进沙箱、去掉 main 调用、把路径换成临时目录，
然后真的执行它、看目录里最后剩了什么。

这一份变异脚本就是反过来：把上面的判据逐条拆掉，看测试会不会红。

对应关系
--------
  H1  不检查软链（软链被挪走 ⇒ 别的服务的开关被拆了）
  H2  不检查普通文件/目录（目录被挪走）
  H3  挪到硬编码的系统目录而不是 ${CONFIG_DIR}/backup
  H4  main 流程里不调用这一步（清理等于没做）

保险丝：只备份 / 还原**我自己会改的那一个文件**（setup/setup.sh）。
还原后比对 sha256 —— 源码没还原干净时**必须**当成失败。
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, 'setup', 'setup.sh')
TEST = os.path.join(ROOT, 'tests', 'test_setup_initd_cleanup.py')

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
    for path, content in ORIG.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass


def restore_verified():
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
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=300,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


MUTATIONS = [
    ('H1  不检查软链（软链被挪走 ⇒ 别的服务的开关被拆了）',
     [('        if [ ! -f "$f" ] || [ -L "$f" ]; then',
       '        if [ ! -f "$f" ]; then')]),

    ('H2  不检查普通文件/目录（目录被挪走）',
     [('        if [ ! -f "$f" ] || [ -L "$f" ]; then',
       '        if [ -L "$f" ]; then')]),

    ('H3  挪到硬编码的系统目录而不是 ${CONFIG_DIR}/backup',
     [('        if mv "$f" "${CONFIG_DIR}/backup/" 2>/dev/null; then',
       '        if mv "$f" "/etc/nftables/" 2>/dev/null; then')]),

    ('H4  main 流程里不调用这一步（清理等于没做）',
     [('    relocate_initd_backups\n', '')]),
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
