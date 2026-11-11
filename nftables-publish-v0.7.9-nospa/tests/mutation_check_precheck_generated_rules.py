#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破坏性操作安全闸（tests/precheck_generated_rules.py）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_precheck_generated_rules.py

测什么有效
----------
安全闸的**误判 PASS** 是最危险的退化：在没有带外通道的机器上，它说「有保障」
而实际没有 ⇒ 跑完 applyRules 就再也连不上设备。
这类退化读起来完全正常、好路径也确实工作，只有把检查项真的拆掉才会暴露。

所以下面每条变异都往「让安全闸漏判」的方向改；抓不住就说明测试是假测试。

对应关系
--------
  P1  摘掉「input 链要跳到 LAN 链」的检查
  P2  摘掉「放行全部管理端口」的检查
  P3  摘掉「放行要排在丢弃规则之前」的检查
  P4  摘掉「define LAN_IF 要与设备网卡名一致」的检查
  P5  结论恒为 PASS
  P6  端口匹配用子串（220 命中 22 ⇒ 没放行 22 也算放行了）
  P7  退回「任一管理端口被放行就算过」（只放行 22、面板进不去也判 PASS）
  P8  链解析只取第一行（后面的规则根本读不到）
  P9  摘掉「LAN 侧整片放行」（形态B）的识别
  P10 形态B 把 IPv6 整片放行也当成覆盖 IPv4
  P11 丢弃规则只认「行首就是 meta nfproto ipv4 drop」（漏掉带日志的 drop）
  P12 源地址受限的放行也算整片放行
  P13 「跳到 LAN 链」的检查被放宽（跳到别的链也算数）

P9~P13 是 2026-11-09 加的：那天发现安全闸只认形态A（显式 dport 放行），
而 .232 真机跑的是形态B（LAN 侧整片放行）⇒ 闸门对默认配置的机器永远判 FAIL。
修好之后，必须用变异证明「这次不是把闸门改松了」——
上面每一条都是往「误判 PASS」的方向改。

保险丝：只备份 / 还原**我自己会改的那一个文件**
（tests/precheck_generated_rules.py），不碰别人的文件。

锚点
----
每条变异用成对的精确字符串，且必须在源码里**唯一**。
匹配不上就当场报错并算作漏网。
"""
import atexit
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, 'tests', 'precheck_generated_rules.py')
TEST = os.path.join(ROOT, 'tests', 'test_precheck_generated_rules.py')

# 我独占、也只有我会改的那一个文件。
ORIG = {GATE: open(GATE, encoding='utf-8').read()}


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
    """把安全闸还原成脚本启动时的内容。幂等，可反复调用。"""
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
                       cwd=ROOT, timeout=600,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


# ─────────────────────────────────────────────────────────────
# 变异定义：(名称, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

MUTATIONS = [
    ('P1  摘掉「input 链要跳到 LAN 链」的检查',
     [('    jump_ok = bool(jumps)', '    jump_ok = True')]),

    ('P2  摘掉「放行全部管理端口」的检查',
     [('    allow_ok = bool(blanket) or (covered == set(MGMT_PORTS))',
       '    allow_ok = True')]),

    ('P3  摘掉「放行要排在丢弃规则之前」的检查',
     [('        order_ok = min(i for i, _ in blanket) < drop_at',
       '        order_ok = True'),
      ('        order_ok = max(i for i, _, _ in mgmt_allow) < drop_at',
       '        order_ok = True')]),

    ('P4  摘掉「define LAN_IF 要与设备网卡名一致」的检查',
     [('        lanif_ok = (lan_define == args.lan_if)',
       '        lanif_ok = True')]),

    ('P5  结论恒为 PASS',
     [('    ok = jump_ok and allow_ok and order_ok and lanif_ok',
       '    ok = True')]),

    ('P6  端口匹配用子串（220 命中 22）',
     [(r"    return re.search(r'\b%d\b' % port, line) is not None",
       r"    return re.search(r'%d' % port, line) is not None")]),

    ('P7  退回「任一管理端口被放行就算过」',
     [('    allow_ok = bool(blanket) or (covered == set(MGMT_PORTS))',
       '    allow_ok = bool(covered)')]),

    ('P8  链解析只取第一行',
     [('        if depth == 0 and len(out) > 1:\n            break',
       '        if len(out) > 1:\n            break')]),

    ('P9  摘掉「LAN 侧整片放行」（形态B）的识别',
     [(r"re.compile(r'^meta\s+nfproto\s+ipv4\s+accept$')",
       r"re.compile(r'^__never_matches__$')")]),

    ('P10 形态B 把 IPv6 整片放行误当成覆盖 IPv4',
     [(r"re.compile(r'^meta\s+nfproto\s+ipv4\s+accept$')",
       r"re.compile(r'^meta\s+nfproto\s+ipv6\s+accept$')")]),

    ('P11 丢弃规则只认「行首就是 meta nfproto ipv4 drop」',
     [("    drop_at = None\n    for i, c in lan_code:\n        if DROP_RE.search(c):",
       "    drop_at = None\n    for i, c in lan_code:\n        if c.startswith('meta nfproto ipv4 drop'):")]),

    ('P12 源地址受限的放行也算整片放行',
     [(r"re.compile(r'^meta\s+nfproto\s+ipv4\s+accept$')",
       r"re.compile(r'^meta\s+nfproto\s+ipv4\s+accept$')\n    "
       r"re.compile(r'^ip\s+saddr\s+.*\s+accept$')")]),

    ('P13 「跳到 LAN 链」的检查被放宽（跳到别的链也算数）',
     [("    jumps = [l.strip() for l in input_chain if 'jump' in l and 'LAN_IF' in l]",
       "    jumps = [l.strip() for l in input_chain if 'jump' in l]")]),
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
        src = ORIG[GATE]
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
                why.append('锚点出现 %d 次，不是唯一' % src.count(dup[0]))
            print('  [FAIL] %s  —— ' % name + '；'.join(why) + ' ⇒ 算漏网')
            missed += 1
            continue
        try:
            mutated = src
            for old, new in edits:
                mutated = mutated.replace(old, new, 1)
            with open(GATE, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if _judge_capture(rc, out):
                # 证据行只取**真的失败**的断言行：
                # 测试的用例名里本身就带 '[FAIL]' 字样（例如「输出里没有 [FAIL]」），
                # 只按 '[FAIL] in line' 找会把这种**通过**的行当成失败证据打印出来。
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
            restore()

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
