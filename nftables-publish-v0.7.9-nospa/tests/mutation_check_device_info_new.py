#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""系统信息页新增采集器（backend/device_info.py）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_device_info_new.py

测什么有效
----------
这批采集器的共同风险是「**页面照常显示，但显示的是错的东西**」——
没有报错、没有白屏，只是数字不对。这类退化单测很容易全绿。

盯的是六类：

  **一、连接表**
    · 状态判断反了（把 LISTEN 当成已建立的连接）
    · 取了**本端**地址而不是对端（页面上显示的是自己）
    · IPv4 字节序搞反（/proc/net/tcp 是**小端**）
    · 同 IP 多端口时保留错了端口

  **二、ARP 在线表**
    · 有效位过滤失效（把「没解析出来」的条目也显示成在线）
    · 全零 MAC 也收（那是「没解析出来」不是「真这个 MAC」）
    · 按字符串排序（192.168.100.9 排在 192.168.100.100 前面）

  **三、DHCP 绑定解析**
    · 没有 option name 时不回退到段名（面板上一列空白）
    · 不还原 uci 的转义（名字显示成 O'\\''Brien）

  **四、主机名**
    · 读错文件（读不到就显示「未知」）

  **五、公网 IP**
    · 默认就采（每 5 秒问一次外网）
    · with_public_ip 参数被忽略（形同虚设）

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。

⚠️ 语法错误的变异不是行为变异
------------------------------
落地后先 py_compile 一次，语法不过直接算漏网（2026-11-11 审查 M8）。

保险丝：只备份 / 还原 backend/device_info.py 一个文件。
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
SCRIPT = os.path.join(ROOT, 'backend', 'device_info.py')
TEST = os.path.join(ROOT, 'tests', 'test_device_info_collectors.py')

ORIG = open(SCRIPT, encoding='utf-8').read()
ORIG_SHA = hashlib.sha256(ORIG.encode('utf-8')).hexdigest()


def _judge_capture(rc, out):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 崩了不等于断言失败（2026-11-11 审查 M8）。
    """
    if rc == 0:
        return False
    for line in out.splitlines():
        s = line.strip()
        if ('[FAIL]' in s and '[PASS]' not in s):
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    try:
        with open(SCRIPT, 'w', encoding='utf-8') as f:
            f.write(ORIG)
    except OSError:
        pass


def restore_verified():
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
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点出现 %d 次（要求唯一）: %r' % (n, old[:70]))
        src = src.replace(old, new)
    return src


MUTATIONS = [
    # ── 一、连接表 ────────────────────────────────────────────
    ('C1  状态判断反了（把 LISTEN 当成已建立的连接）',
     [("            if parts[3] != '01':\n                continue",
       "            if parts[3] != '0A':\n                continue")]),

    ('C2  取了本端地址而不是对端',
     [('            rem = parts[2]\n', '            rem = parts[1]\n')]),

    ('C3  IPv4 字节序搞反（/proc/net/tcp 是小端）',
     [('                    ip = socket_inet_ntoa(hex_ip, little=True)',
       '                    ip = socket_inet_ntoa(hex_ip, little=False)')]),

    ('C4  同 IP 多端口时保留错了端口',
     [("            if prev is None or port < prev['port']:",
       "            if prev is None or port > prev['port']:")]),

    # ── 二、ARP 在线表 ────────────────────────────────────────
    ('C5  有效位过滤失效（没解析出来的条目也显示成在线）',
     [("        if flags not in ('0x2', '0x1'):\n            continue",
       "        if False:\n            continue")]),

    ('C6  全零 MAC 也收（那是「没解析出来」不是「真这个 MAC」）',
     [("        if mac in ('00:00:00:00:00:00', ''):\n            continue",
       "        if mac == '':\n            continue")]),

    ('C7  按字符串排序（9 排在 100 前面）',
     [("    out.sort(key=lambda r: _ip_sort_key(r['ip']))",
       "    out.sort(key=lambda r: r['ip'])")]),

    # ── 三、DHCP 绑定解析 ─────────────────────────────────────
    ('C8  没有 option name 时不回退到段名（面板上一列空白）',
     [('    for h in out:\n'
       '        if not h[\'name\']:\n'
       '            h[\'name\'] = h[\'section\']\n',
       '')]),

    ('C9  不还原 uci 的转义（名字显示成 O\'\\\'\'Brien）',
     [('            val = _uci_unquote(parts[2])',
       '            val = parts[2].strip()')]),

    # ── 四、主机名 ────────────────────────────────────────────
    ('C10 主机名读错文件（读不到就显示「未知」）',
     [("    name = _read_first_line('/proc/sys/kernel/hostname')",
       "    name = _read_first_line('/etc/hostname')")]),

    # ── 五、公网 IP ───────────────────────────────────────────
    ('C11 默认就采公网 IP（每 5 秒问一次外网）',
     [('def collect_all(with_public_ip=False):',
       'def collect_all(with_public_ip=True):')]),

    ('C12 with_public_ip 参数被忽略（形同虚设）',
     [('    public_ip = None\n    if with_public_ip:',
       '    public_ip = None\n    if True:')]),

    # ── 六、ARP 的列数下限 ────────────────────────────────────
    #
    # ⚠️ 这条与 IPv6 脚本的 D5 是**同一类**退化：
    #   /proc/net/arp 是 6 列，下限写成 7 ⇒ 整行被跳过 ⇒ ARP 表全空。
    #   IPv6 那边已经有一条 D5 盯着 ⇒ 这边也得有。
    ('C13 ARP 的列数下限从 6 提到 7（整行被跳过，表全空）',
     [('        parts = ln.split()\n        if len(parts) < 6:',
       '        parts = ln.split()\n        if len(parts) < 7:')]),
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
            try:
                py_compile.compile(SCRIPT, cfile=os.path.join(
                    tempfile.gettempdir(), 'device_info_new_mut_check.pyc'),
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
