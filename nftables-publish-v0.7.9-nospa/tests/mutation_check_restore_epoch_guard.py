#!/usr/bin/env python3
"""「恢复配置」世代号防线的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_restore_epoch_guard.py

测什么有效
----------
2026-11-08 .232 真机 e2e 实测：面板点「恢复配置」后，落盘配置里的
``auth_token_epoch`` 从 1 变成 0 —— 全体会话当场失效（所有 API 401、
按钮全 disabled），而且「改密码作废全部会话」的保证被撤销（旧令牌复活）。

修法是「恢复时继承当前配置的世代号」。这类修复最容易的退化是
**看起来还在、其实已经不生效**：

  · 那行赋值被删掉 ⇒ 又从 backup 取 epoch（= 原缺陷）
  · 赋值改成用 backup 里的值 ⇒ 同上，只是换了个写法
  · 继承源算错（写死 0 / 多加 1）⇒ 强制登人或作废全部会话
  · 备份不是配置对象时的拒绝分支被摘掉 ⇒ 损坏备份能覆盖正式配置

对应关系
--------
  R1  世代号赋值整行删掉            R2  继承源写死 0
  R3  赋值改成取 backup 的值        R4  继承源多加 1
  R5  非 dict 备份的拒绝分支被摘掉  R6  赋值写成别的键名

保险丝：只备份 / 还原**我自己会改的那一个文件**（backend/app.py），
不扫描 /tmp/mutguard-*，不碰别人的文件。

锚点
----
每条变异用成对的精确字符串，且必须在源码里**唯一**。
匹配不上就当场报错并算作漏网 —— 「锚点没命中」不等于「变异没生效」，
那比漏网更糟。
"""
import atexit
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_restore_epoch_guard.py')

# 我独占、也只有我会改的那一个文件。
ORIG = {APP: open(APP, encoding='utf-8').read()}


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


# ─────────────────────────────────────────────────────────────
# 变异定义：(名称, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

MUTATIONS = [
    ('R1  世代号赋值整行删掉（又从 backup 取 epoch = 原缺陷回来）',
     [("        restored['auth_token_epoch'] = current_epoch\n", '')]),

    ('R2  继承源写死 0（当前配置里有世代号也被忽略）',
     [('        current_epoch = _current_token_epoch()',
       '        current_epoch = 0')]),

    ('R3  赋值改成取 backup 里的值（换个写法绕过继承）',
     [("        restored['auth_token_epoch'] = current_epoch",
       "        restored['auth_token_epoch'] = restored.get('auth_token_epoch', 0)")]),

    ('R4  继承源多加 1（恢复一次就作废一次全部会话）',
     [('        current_epoch = _current_token_epoch()',
       '        current_epoch = _current_token_epoch() + 1')]),

    ('R5  非 dict 备份的拒绝分支被摘掉（损坏备份能覆盖正式配置）',
     [('        if not isinstance(restored, dict):',
       '        if False:')]),

    ('R6  赋值写成别的键名（世代号没被接管，但看着像改了）',
     [("        restored['auth_token_epoch'] = current_epoch",
       "        restored['auth_epoch'] = current_epoch")]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    restore()
    rc, out = run_tests()
    if rc != 0:
        print('[FAIL] 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-3000:])
        return 1
    print('  [PASS] 基线通过\n')

    caught = missed = 0
    for name, edits in MUTATIONS:
        src = ORIG[APP]
        bad = [old for old, _ in edits if old not in src]
        dup = [old for old, _ in edits if src.count(old) != 1]
        if bad or dup:
            # 锚点未命中的原因必须写进**同一行**：
            # 全仓扫描器按「每条变异恰好一行报告」统计，
            # 拆成两行会让这条既不算捕获也不算漏网 ⇒ 总数被少算。
            why = []
            if bad:
                why.append('锚点没匹配上（源码变了？）')
            if dup:
                why.append(f'锚点出现 {src.count(dup[0])} 次，不是唯一')
            print(f'  [FAIL] {name}  —— ' + '；'.join(why) + ' ⇒ 算漏网')
            missed += 1
            continue
        try:
            mutated = src
            for old, new in edits:
                mutated = mutated.replace(old, new, 1)
            with open(APP, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if _judge_capture(rc, out):
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l), '')
                print(f'  [PASS] {name}  —— 被捕获')
                if first:
                    print(f'      ↓ {first}')
                caught += 1
            else:
                print(f'  [FAIL] {name}  —— 漏网！测试没抓住')
                missed += 1
        finally:
            # 无条件还原 —— 哪怕测试抛了异常，源码也不能停在变异态。
            restore()

    print()
    print('=' * 60)
    print(f'  捕获 {caught} / {caught + missed}')
    if missed:
        print('  源码已全部还原，但有漏网项 —— 上面标 [FAIL] 的测试是假测试')
    else:
        print('  源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
