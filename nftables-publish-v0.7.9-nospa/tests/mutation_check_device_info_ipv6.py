#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备信息采集器 IPv6 解析（backend/device_info.py）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_device_info_ipv6.py

测什么有效
----------
`/proc/net/if_inet6` 的列是「地址 / ifindex / 前缀长度 / scope / flags / 接口名」
（Linux v6.12 `net/ipv6/addrconf.c` 的 `if6_seq_show`）。

2026-11-09 在 .232 真机上做「系统信息页逐项对照」时抓到两处错：

  1. 第 4 列是 **scope**，代码却拿它当 **flags** 读
     ⇒ 链路本地地址的 scope=0x20（RT_SCOPE_LINK）被当成「临时地址标志」
     ⇒ fe80:: 被整条丢弃 ⇒ 面板 IPv6 一栏永远空。
  2. 临时地址的位是 **0x01**（IFA_F_TEMPORARY），代码用的是 0x20
     （0x20 是 IFA_F_DEPRECATED「已弃用」）
     ⇒ 已弃用的地址被丢弃、真正的隐私地址反而留着。

这两处都是「**静默少报**」：页面照常渲染，只是内容缺一块 ——
不盯着真机逐项对照根本发现不了。所以下面每条变异都往「让解析退化」的方向改。

对应关系
--------
  D1  flags 列改回 scope 列（第 4 列）—— 复现原 bug
  D2  临时地址的位改回 0x20 —— 复现原 bug
  D3  不再跳过任何地址（隐私地址也展示）
  D4  跳过所有地址（一个都不展示）
  D5  列数下限从 6 提到 7 —— 现代内核的 6 列格式整行被跳过

保险丝：只备份 / 还原**我自己会改的那一个文件**
（backend/device_info.py），不碰别人的文件。

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
TARGET = os.path.join(ROOT, 'backend', 'device_info.py')
TEST = os.path.join(ROOT, 'tests', 'test_device_info.py')

# 我独占、也只有我会改的那一个文件。
ORIG = {TARGET: open(TARGET, encoding='utf-8').read()}


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
    """把采集器还原成脚本启动时的内容。幂等，可反复调用。"""
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
    ('D1  flags 列改回 scope 列（第 4 列）—— 复现原 bug',
     [('        hex_addr, _ifindex, _prefix_len, _scope, flags, iface = parts[:6]',
       '        hex_addr, _ifindex, _prefix_len, flags, iface = parts[0], parts[1], parts[2], parts[3], parts[5]')]),

    ('D2  临时地址的位改回 0x20 —— 复现原 bug',
     [('            if int(flags, 16) & 0x01:', '            if int(flags, 16) & 0x20:')]),

    ('D3  不再跳过任何地址（隐私地址也展示）',
     [('            if int(flags, 16) & 0x01:', '            if False:')]),

    ('D4  跳过所有地址（一个都不展示）',
     [('            if int(flags, 16) & 0x01:', '            if True:')]),

    ('D5  列数下限从 6 提到 7 —— 现代内核的 6 列格式整行被跳过',
     [('        if len(parts) < 6:', '        if len(parts) < 7:')]),
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
        src = ORIG[TARGET]
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
