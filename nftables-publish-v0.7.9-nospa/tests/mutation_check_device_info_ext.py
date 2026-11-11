#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备信息采集器「系统信息页数据面扩充」的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_device_info_ext.py

测什么有效
----------
这一轮给采集器加了三块新东西：接口的 sysfs 全字段、两次采样的速率、
设备侧服务与包清单。三块的共同风险是「**静默少报/错报**」：

  · `/proc/net/dev` 的 16 列按**下标**映射，列名收发两段还不一样
    （收的第 6 列是 frame，发的第 6 列是 colls，发段还多一个 carrier）
    ⇒ 下标错一位不会报错，只会少报/错报一个计数。
  · sysfs 的三个「看着像数其实不是」：
    `speed = -1`（没有链路速率概念）、`duplex = unknown`（同上）、
    `carrier` 链路断开时是**空文件**（空 ≠ 0）。
  · `master` 是指向**目录**的符号链接 —— `cat` 会报 "Is a directory"，
    必须 readlink + basename。
  · 速率是两次采样的差值 ⇒ 间隔太短时噪声大于信号，
    字节数变小时是计数器回绕 —— 两种情况都必须「不给数」，不能给个假的。
  · 设备侧服务：「enabled」（rc.d 有 S 软链）≠「running」，
    而且 pid 文件会残留 ⇒ 必须查 pid 还活着。
  · 包清单：apk 的 ADB 格式里 `P:` 才是包名；world 里的
    `busybox><hash`、`base-files=版本` 只有前半截是包名。

对应关系
--------
  E1  /proc/net/dev 的列映射错位（rx_packets ↔ rx_errs）
  E2  列数下限从 16 降到 8 —— 残缺行不再被跳过
  E3  不再把 speed = -1 归一成 None（页面会显示 -1 Mbps）
  E4  不再把 duplex = unknown 归一成 None
  E5  carrier 读不到时返回 0（空文件被当成「没载波」而不是「未知」）
  E6  master 不取 basename（返回整条链接路径）
  E7  速率的最小间隔下限取消（0.2 秒的采样也出数）
  E8  速率不再防计数器回绕（字节数变小也算出负速率）
  E9  判定 pid 存活时不再查 /proc/<pid>（残留 pid 也报「运行中」）
  E10 备份副本的过滤被去掉（`nftables-web.bak.<时间戳>` 被当成服务）
  E11 apk 包计数认错行（数 `C:` 行而不是 `P:` 行）
  E12 world 里的版本/来源约束后缀不剥（包名带着 hash 显示）

保险丝：只备份 / 还原**我自己会改的那一个文件**
（backend/device_info.py），不碰别人的文件。
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
TARGET = os.path.join(ROOT, 'backend', 'device_info.py')
TEST = os.path.join(ROOT, 'tests', 'test_device_info.py')

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
    """把采集器还原成脚本启动时的内容。幂等，可反复调用。"""
    for path, content in ORIG.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass


def source_sha():
    """当前源码的 sha256（用来验证「还原干净了」）。"""
    out = {}
    for path in ORIG:
        try:
            with open(path, 'rb') as f:
                out[path] = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            out[path] = None
    return out


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    now = source_sha()
    for path, want in ORIG_SHA.items():
        got = now.get(path)
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
                       cwd=ROOT, timeout=600,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


# ─────────────────────────────────────────────────────────────
# 变异定义：(名称, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

MUTATIONS = [
    ('E1  /proc/net/dev 的列映射错位（rx_packets ↔ rx_errs）',
     [("    'rx_bytes', 'rx_packets', 'rx_errs', 'rx_drop', 'rx_fifo',",
       "    'rx_bytes', 'rx_errs', 'rx_packets', 'rx_drop', 'rx_fifo',")]),

    ('E2  列数下限从 16 降到 8 —— 残缺行不再被跳过',
     [('        if len(fields) < 16:', '        if len(fields) < 8:')]),

    ('E3  不再把 speed = -1 归一成 None（页面会显示 -1 Mbps）',
     [('    if speed is not None and speed < 0:', '    if False:')]),

    ('E4  不再把 duplex = unknown 归一成 None',
     [("    if duplex in (None, '', 'unknown'):", "    if duplex in (None, ''):")]),

    ('E5  carrier 读不到时返回 0（空文件被当成「没载波」而不是「未知」）',
     [("        'carrier': _read_int(base + '/carrier'),",
       "        'carrier': _read_int(base + '/carrier') or 0,")]),

    ('E6  master 不取 basename（返回整条链接路径）',
     [("    base = os.path.basename(target.rstrip('/'))",
       "    base = target.rstrip('/')")]),

    ('E7  速率的最小间隔下限取消（0.2 秒的采样也出数）',
     [('            if dt >= _RATE_MIN_INTERVAL:', '            if dt > 0:')]),

    ('E8  速率不再防计数器回绕（字节数变小也算出负速率）',
     [("                if rx is not None and prev['rx'] is not None and rx >= prev['rx']:",
       "                if rx is not None and prev['rx'] is not None:")]),

    ('E9  判定 pid 存活时不再查 /proc/<pid>（残留 pid 也报「运行中」）',
     [("    return pid if os.path.isdir('/proc/%d' % pid) else None",
       "    return pid")]),

    ('E10 备份副本的过滤被去掉（`nftables-web.bak.<时间戳>` 被当成服务）',
     [('        if _BACKUP_NAME_RE.search(name):', '        if False:')]),

    ('E11 apk 包计数认错行（数 `C:` 行而不是 `P:` 行）',
     [("        n = len([ln for ln in txt.splitlines() if ln.startswith('P:')])",
       "        n = len([ln for ln in txt.splitlines() if ln.startswith('C:')])")]),

    ('E12 world 里的版本/来源约束后缀不剥（包名带着 hash 显示）',
     [("            world.append(line.split('<')[0].split('=')[0].split('>')[0])",
       "            world.append(line)")]),
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
            # 还原后必须校验 sha256 —— 源码没还原干净时，
            # 后面几条变异是在**改坏了的源码**上跑的，结果不可信。
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
