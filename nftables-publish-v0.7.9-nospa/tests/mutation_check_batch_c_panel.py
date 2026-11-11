#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批 C（面板可用性）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_batch_c_panel.py

测什么有效
----------
这批缺陷的失败模式**全都是「界面上看着正常」**：

  · CNAME / TXT 的测试按钮传空 value ⇒ 后端恒 400 ⇒ 按钮点了没反应；
  · 「获取记录」把 localRecords 清空 ⇒ 界面照样显示记录列表，
    但用户配的 enabled / ipv6_source 已经没了 ⇒ 自动更新静默不生效；
  · 归一化少一条规则 ⇒ 值被误判成「变了」⇒ 每轮都触发更新；
  · 探测源写死 ⇒ 测试打桩成 lambda ⇒ 真实实现从未被测到。

所以判据必须落在**行为**上：真的发出去的那个请求体、
真的被清空的那个数组、真的跑起来的那个归一化函数。

每条变异都往「退化」方向改
--------------------------
  G1  后端去掉 CNAME/TXT 的兜底查询（恒 400 回归）
  G2  兜底查询不按 RR/Type 匹配（可能取到别的记录 ⇒ 白写一次）
  H1  前端对所有类型都传空 value（CNAME/TXT 恒 400 回归）
  I1  /records 不传 PageSize（又只回前 20 条）
  I2  /records 不返回 localRecords（前端清空回归）
  I3  localRecords 只取阿里云上有的（本地多出来的那些丢了）
  J1  前端把 localRecords 无条件清空
  K1  面板侧归一化不去 TXT 外层引号
  K2  cron 侧归一化不去 CNAME 尾点（两侧规则分叉）
  K3  面板侧归一化不做 IPv6 压缩
  L1  面板侧探测源写死（不可注入）
  L2  面板侧默认源与 cron 侧不一致（运维改一边就分叉）

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。所以这里直接把未命中记成漏网。

⚠️ 「测试脚本崩溃」不算捕获（2026-11-11 审查 M8）
----------------------------------------------
判定条件不能只是 `rc != 0` —— 那分不清「断言失败」和「测试自己 traceback」。
⇒ 必须 rc != 0 **且**输出里真的有 [FAIL] 行才算捕获；
   只有崩溃、没有失败行的 ⇒ 单独记成「崩溃（不算捕获）」。

保险丝：只备份 / 还原 **backend/app.py 与 frontend/app.js** 两个文件，
一个字节都不碰别的。还原后逐个比对 sha256 —— 源码没还原干净时
**必须**当成失败，不能把「测试假红」误报成「变异被捕获」。
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
APP_JS = os.path.join(ROOT, 'frontend', 'app.js')
TEST_PY = os.path.join(ROOT, 'tests', 'test_panel_usability_batch_c.py')
TEST_JS = os.path.join(ROOT, 'tests', 'test_frontend_aliyun_batch_c.js')

TARGETS = {APP_PY: open(APP_PY, encoding='utf-8').read(),
           APP_JS: open(APP_JS, encoding='utf-8').read()}
ORIG_SHA = {p: hashlib.sha256(s.encode('utf-8')).hexdigest()
            for p, s in TARGETS.items()}


def restore():
    """把两个文件还原成脚本启动时的内容。幂等，可反复调用。"""
    for path, src in TARGETS.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(src)
        except OSError:
            pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    for path, want in ORIG_SHA.items():
        with open(path, 'rb') as f:
            got = hashlib.sha256(f.read()).hexdigest()
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
    """跑批 C 的两个判据文件（后端 Python + 前端 Node）。

    返回 (是否被捕获, 详情)。**被捕获**要求：至少一个判据文件失败，
    且失败是**断言失败**（输出里有 [FAIL] 行），而不是脚本自己崩了。
    """
    outs = []
    r1 = subprocess.run([sys.executable, TEST_PY], capture_output=True, text=True,
                        cwd=ROOT, timeout=1800,
                        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    outs.append(('python', r1.returncode, r1.stdout + r1.stderr))
    try:
        r2 = subprocess.run(['node', TEST_JS], capture_output=True, text=True,
                            cwd=ROOT, timeout=600)
        outs.append(('node', r2.returncode, r2.stdout + r2.stderr))
    except FileNotFoundError:
        outs.append(('node', 0, '（没有 node，跳过前端判据）'))

    crashed = []
    failed = []
    for name, rc, out in outs:
        has_fail = any('[FAIL]' in l for l in out.splitlines())
        if rc != 0 and has_fail:
            failed.append((name, out))
        elif rc != 0:
            crashed.append((name, out))
    if failed:
        name, out = failed[0]
        first = next((l.strip() for l in out.splitlines()
                      if '[FAIL]' in l and '[PASS]' not in l), '')
        return True, '断言失败（%s）: %s' % (name, first)
    if crashed:
        name, out = crashed[0]
        tail = out.strip().splitlines()[-1] if out.strip() else ''
        return False, '只有崩溃没有断言失败（%s）: %s' % (name, tail)
    return False, '判据全绿'


def apply_edits(src, edits):
    """按顺序应用编辑。锚点必须在源码里**唯一**，否则报错（不静默跳过）。"""
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点出现 %d 次（要求唯一）: %r' % (n, old[:70]))
        src = src.replace(old, new)
    return src


# ── 锚点原文（改动生产代码时必须同步更新这里，否则会被记成漏网）──────

_PY_FALLBACK = ('    if not value and rtype.upper() in ("CNAME", "TXT"):\n')

_PY_RR_MATCH = ('                    if str(r.get(\'RR\', \'\')).lower() != str(rr or \'\').lower():\n'
                '                        continue\n')

_JS_VALUE = ("          value: (rtypeU === 'A' || rtypeU === 'AAAA')\n"
             "            ? ''\n"
             "            : (rec.Value || rec.value || ''),\n")

_PY_PAGESIZE = ('                             {"DomainName": domain, "PageSize": 500})\n')

_PY_LOCALRET = ('            "localRecords": local_records,\n')

_PY_LOCALLOOP = ("        local_records = []\n"
                 "        for lr in config.get('records', []):\n")

_JS_LOCAL = ('      if (Array.isArray(data.localRecords)) {\n'
             '        this.aliyun.localRecords = data.localRecords;\n'
             '      }\n')

_PY_NORM_TXT = ('    if len(s) >= 2 and s.startswith(\'"\') and s.endswith(\'"\'):\n'
                '        s = s[1:-1].strip()\n'
                '    try:\n'
                '        import ipaddress\n')

_PY_NORM_IPV6 = ('    try:\n'
                 '        import ipaddress\n'
                 '        return ipaddress.ip_address(s).compressed.lower()\n')

_PY_NORM_DOT = ("    # CNAME：去掉末尾的点\n"
                "    if s.endswith('.'):\n"
                "        s = s[:-1]\n")

_PY_IPV4_BLOCK = ('# 面板侧取公网 IPv4 的探测源。与 cron 脚本里的 `IPV4_SOURCES` **保持一致**。\n'
                  '#\n'
                  '# 为什么做成可注入（逗号分隔的环境变量）：\n'
                  '#   ① 运维改了源，两侧必须一起改 —— 否则面板测的和 cron 跑的不是同一条路，\n'
                  '#      「面板上测试通过」完全不能代表 cron 那边也通；\n'
                  '#   ② 测试若真出网，结果会随时间变、网络不通就假失败 —— 那样的测试等于没有。\n'
                  '#      注入本地假源后，测试能真的跑「取 IP → 比对 → 更新」整条链路。\n'
                  'IPV4_SOURCES = [u.strip() for u in os.environ.get(\n'
                  '    "NFTW_IPV4_SOURCES",\n'
                  '    "https://ipv4.icanhazip.com,https://api.ipify.org").split(",") if u.strip()]\n')


MUTATIONS = [
    # ── M5：CNAME / TXT 的测试 ─────────────────────────────
    ('G1  后端去掉 CNAME/TXT 的兜底查询（恒 400 回归）',
     APP_PY,
     [(_PY_FALLBACK, '    if False and not value and rtype.upper() in ("CNAME", "TXT"):\n')]),

    ('G2  兜底查询不按 RR 匹配（可能取到别的记录 ⇒ 白写一次）',
     APP_PY,
     [(_PY_RR_MATCH, '')]),

    ('H1  前端对所有类型都传空 value（CNAME/TXT 恒 400 回归）',
     APP_JS,
     [(_JS_VALUE, "          value: '',\n")]),

    # ── L8：PageSize 与 localRecords ───────────────────────
    ('I1  /records 不传 PageSize（又只回前 20 条）',
     APP_PY,
     [(_PY_PAGESIZE, '                             {"DomainName": domain})\n')]),

    ('I2  /records 不返回 localRecords（前端清空回归）',
     APP_PY,
     [(_PY_LOCALRET, '')]),

    ('I3  localRecords 只取阿里云上有的（本地多出来的那些丢了）',
     APP_PY,
     [(_PY_LOCALLOOP,
       "        local_records = []\n"
       "        for lr in records:\n")]),

    ('J1  前端把 localRecords 无条件清空',
     APP_JS,
     [(_JS_LOCAL, '      this.aliyun.localRecords = data.localRecords || [];\n')]),

    # ── L12：归一化 ────────────────────────────────────────
    ('K1  面板侧归一化不去 TXT 外层引号',
     APP_PY,
     [(_PY_NORM_TXT, '    try:\n        import ipaddress\n')]),

    ('K2  cron 侧归一化不去 CNAME 尾点（两侧规则分叉）',
     APP_PY,
     [('''    if s.endswith("."):
        s = s[:-1]
    return s''',
       '''    return s''')]),

    ('K3  面板侧归一化不做 IPv6 压缩',
     APP_PY,
     [(_PY_NORM_IPV6,
       '    try:\n'
       '        import ipaddress\n'
       '        return s\n')]),

    # ── L13 / L9：探测源可注入 ─────────────────────────────
    ('L1  面板侧探测源写死（不可注入）',
     APP_PY,
     [(_PY_IPV4_BLOCK,
       'IPV4_SOURCES = ["https://ipv4.icanhazip.com", "https://api.ipify.org"]\n')]),

    ('L2  面板侧默认源与 cron 侧不一致（运维改一边就分叉）',
     APP_PY,
     [(_PY_IPV4_BLOCK,
       '# 面板侧取公网 IPv4 的探测源。\n'
       'IPV4_SOURCES = [u.strip() for u in os.environ.get(\n'
       '    "NFTW_IPV4_SOURCES",\n'
       '    "https://ipv4.icanhazip.com").split(",") if u.strip()]\n')]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    ok, detail = restore_verified()
    if not ok:
        print('[FAIL] %s —— 变异验证无意义' % detail)
        return 1
    caught, detail = run_tests()
    if caught:
        print('[FAIL] 基线就不绿，变异验证无意义 —— 先修测试')
        print(detail)
        return 1
    print('  [PASS] 基线通过\n')

    caught = missed = 0
    for name, target, edits in MUTATIONS:
        src = TARGETS[target]
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
            with open(target, 'w', encoding='utf-8') as f:
                f.write(mutated)
            ok, detail = run_tests()
            if ok:
                print('  [PASS] %s  —— 被捕获' % name)
                print('      ↓ %s' % detail)
                caught += 1
            else:
                print('  [FAIL] %s  —— 漏网！%s' % (name, detail))
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
