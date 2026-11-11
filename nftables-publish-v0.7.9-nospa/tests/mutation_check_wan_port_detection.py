#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""「WAN 口自动检测」的变异验证。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_wan_port_detection.py

测什么有效
----------
这块代码的失败模式是「**整机失联**」，不是「配置不对」：
挑错一个 WAN 口 = 把 LAN 桥的成员抢走 = 桥塌 = 设备当场失联。
2026-10-06 在 x86 单网卡 OpenWrt 上实测踩中过一次（ARP FAILED）。

这类退化的特点是「**看起来完全正常**」：
选出来的口确实是个物理网卡、确实能写进配置、面板也不会报错 ——
只有真的把桥成员抢走，设备才会失联。所以单测很容易全绿，
必须靠变异把修复拆掉、看测试会不会变红。

每条变异都往「退化」方向改
--------------------------
  W1  list ports 只认带引号的写法（回到 2026-11-10 之前的实现）
      ⇒ 无引号写法漏解析 ⇒ 桥成员被当成 WAN 候选
  W2  双引号写法漏解析
  W3  不看 sysfs 的 master（丢掉比文本解析更硬的那份证据）
  W4  master 判据用 exists 而不是 islink（普通文件也会被当成桥成员）
  W5  VLAN 子接口（eth0.10）也算独立物理口
  W6  lan 的 option ifname 不算占用（swconfig 老写法漏掉）
  W7  报错文案写死「本机只有一张物理网卡」（多口机上说错话）
  W8  报错文案不报实际口数

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。所以这里直接把未命中记成漏网。

保险丝：只备份 / 还原 **backend/app.py 一个文件**，一个字节都不碰别的。
还原后逐个比对 sha256 —— 源码没还原干净时**必须**当成失败，
不能把「测试假红」误报成「变异被捕获」。
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_wan_port_detection.py')

ORIG = open(APP_PY, encoding='utf-8').read()
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
                ('\u274c' in s and '\u2705' not in s):
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    """把 app.py 还原成脚本启动时的内容。幂等，可反复调用。"""
    try:
        with open(APP_PY, 'w', encoding='utf-8') as f:
            f.write(ORIG)
    except OSError:
        pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    with open(APP_PY, 'rb') as f:
        got = hashlib.sha256(f.read()).hexdigest()
    if got != ORIG_SHA:
        return False, '%s 还原后 sha256 不一致（%s != %s）' % (
            os.path.basename(APP_PY), got, ORIG_SHA)
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


def apply_edits(src, edits):
    """按顺序应用编辑。锚点必须在源码里**唯一**，否则报错（不静默跳过）。"""
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError(f'锚点出现 {n} 次（要求唯一）: {old[:70]!r}')
        src = src.replace(old, new)
    return src


# 每条变异只改 backend/app.py
# 格式：(说明, [(原文, 变异后), ...])
MUTATIONS = [
    # ── W1：list ports 只认带引号的写法（回到修复前的实现）────────────
    ('W1  list ports 只认带引号的写法（无引号写法漏解析 ⇒ 桥成员被当 WAN）',
     [("""            val = m.group(1).strip()
            # 剥掉可能存在的外层引号（单引号 / 双引号都认）
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]""",
       """            val = m.group(1).strip()
            # 【变异】只认单引号 —— 无引号写法整条漏掉
            if "'" in val:
                val = val.split("'")[-2]
            else:
                val = ''""")]),

    # ── W2：双引号写法漏解析 ────────────────────────────────────────
    ('W2  双引号的 list ports 漏解析',
     [("""            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):""",
       """            if len(val) >= 2 and val[0] == val[-1] and val[0] == "'":""")]),

    # ── W3：丢掉 sysfs master 这份更硬的证据 ────────────────────────
    ('W3  不看 sysfs 的 master（丢掉比文本解析更硬的证据）',
     [("""    for n in names:
        if os.path.islink(os.path.join(root, n, 'master')):
            excluded.add(n)""",
       """    for n in names:
        pass""")]),

    # ── W4：master 判据用错（exists 会把普通文件也算成桥成员）────────
    ('W4  master 判据用 exists 而不是 islink',
     [("        if os.path.islink(os.path.join(root, n, 'master')):",
       "        if os.path.exists(os.path.join(root, n, 'master')):")]),

    # ── W5：VLAN 子接口被当成独立物理口 ─────────────────────────────
    ('W5  VLAN 子接口（eth0.10）也被当成独立物理口',
     [("""    if '.' in name:
        return False
    return bool(_PHY_IFACE_RE.match(name))""",
       """    return bool(_PHY_IFACE_RE.match(name))""")]),

    # ── W6：swconfig 老写法（lan 的 option ifname）漏掉 ──────────────
    ('W6  lan 的 option ifname 不算占用（swconfig 老写法漏掉）',
     [("    excluded |= _uci_lan_ifname_ports(network_text)",
       "    pass  # 【变异】不看 lan 的 option ifname")]),

    # ── W7：报错文案写死「本机只有一张物理网卡」──────────────────────
    ('W7  报错文案写死「本机只有一张物理网卡」（多口机上说错话）',
     [("""    elif len(physical) == 1:
        why = f"本机只有一张物理网卡（{physical[0]}），无法同时做 LAN 和 PPPoE WAN"
    else:
        why = (f"本机共 {len(physical)} 张物理网卡（{'、'.join(physical)}），"
               f"它们已全部被占用，没有独立的口可用于 WAN")""",
       '''    elif len(physical) == 1:
        why = "本机只有一张物理网卡，无法同时做 LAN 和 PPPoE WAN"
    else:
        why = "本机只有一张物理网卡，无法同时做 LAN 和 PPPoE WAN"''')]),

    # ── W8：报错文案不报实际口数 ────────────────────────────────────
    ('W8  报错文案不报实际口数',
     [('''        why = (f"本机共 {len(physical)} 张物理网卡（{'、'.join(physical)}），"
               f"它们已全部被占用，没有独立的口可用于 WAN")''',
       '''        why = "它们已全部被占用，没有独立的口可用于 WAN"''')]),
]


def main():
    print('=' * 74)
    print('变异验证：WAN 口自动检测（多 eth 接入 br-lan 的前置条件）')
    print('=' * 74)

    rc, out = run_tests()
    if rc != 0:
        print('[FAIL] 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-3000:])
        return 1
    base_pass = out.count('[PASS]')
    print(f'基线通过 {base_pass} 条断言\n')

    caught, missed = 0, 0
    for name, edits in MUTATIONS:
        try:
            mutated = apply_edits(ORIG, edits)
        except ValueError as e:
            print(f'  [FAIL] {name}')
            print(f'      锚点没命中（源码变了？）：{e}')
            missed += 1
            continue
        with open(APP_PY, 'w', encoding='utf-8') as f:
            f.write(mutated)
        try:
            rc, out = run_tests()
            if _judge_capture(rc, out):
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l), '')
                print(f'  [PASS] {name}  —— 被捕获')
                print(f'      首个失败断言: {first[:100]}')
                caught += 1
            else:
                print(f'  [FAIL] {name}  —— 漏网！测试没抓住')
                missed += 1
        finally:
            ok, detail = restore_verified()
            if not ok:
                print(f'      [FAIL] {detail}')
                missed += 1
                return 1

    print()
    print('=' * 74)
    print(f'变异 {len(MUTATIONS)} 处  捕获 {caught}  漏网 {missed}')
    if missed:
        print('源码已全部还原，但有漏网项 —— 上面标 [FAIL] 的测试是假测试')
        return 1
    print('全部变异均被捕获')
    return 0


if __name__ == '__main__':
    sys.exit(main())
