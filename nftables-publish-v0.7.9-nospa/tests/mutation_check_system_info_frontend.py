#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
「系统信息」页前端（frontend/app.js + frontend/index.html）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_system_info_frontend.py

测什么有效
----------
这一批给系统信息页加了：接口明细与速率、面板开关徽章、设备服务表、包清单。
它们的共同风险是「**页面照常显示，但显示的是错的东西**」——
没有报错、没有白屏，只是数字不对。这类退化单测很容易全绿。

所以每条变异都往「让显示退化」的方向改：

  · 读不到的值显示成 0（「采样中」变成「0 B/s」）
  · 0 这种合法值被当成「读不到」（计数 0 条显示成「未知」）
  · 明细行把「没有丢包」也显示成「丢包 0」
  · 「交换」列少算一半（只算发不算收）
  · 速率列其实显示的是累计字节（字段名写错，页面看着完全正常）
  · 自动刷新停不下来（离开页面还在打接口）

对应关系
--------
  G1  fmtRate 读不到时返回 0（「采样中」被改成「0 B/s」—— 撒谎）
  G2  panelCount 用 falsy 判断（0 条被显示成「未知」）
  G3  svcPriority 用 falsy 判断（序号 0 被显示成「—」）
  G4  ifaceDetail 无条件显示丢包/错误（含 0）
  G5  ifaceDetail 读不到时显示「未知」而不是不显示
  G6  自动刷新不再判断当前页（离开系统信息页还在打接口）
  G7  速率列引用错字段（显示成累计字节）
  G8  计数列拿不到 panel（恒显示「未知」）
  G9  「交换」列少算一半（只算发）
  G10 「交换」列表头被删

保险丝：只备份 / 还原**本脚本会动的那两个文件**
（frontend/app.js、frontend/index.html），一个字节都不碰别的。
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
APP_JS = os.path.join(ROOT, 'frontend', 'app.js')
INDEX_HTML = os.path.join(ROOT, 'frontend', 'index.html')
TESTS = [
    os.path.join(ROOT, 'tests', 'test_frontend_system_info.js'),
    os.path.join(ROOT, 'tests', 'test_frontend_system_info_render.js'),
]

# 我独占、也只有我会改的那两个文件。
ORIG = {p: open(p, encoding='utf-8').read() for p in (APP_JS, INDEX_HTML)}
ORIG_SHA = {p: hashlib.sha256(c.encode('utf-8')).hexdigest()
            for p, c in ORIG.items()}


def restore():
    """把两个文件还原成脚本启动时的内容。幂等，可反复调用。"""
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
        r = subprocess.run(['node', t], capture_output=True, text=True,
                           cwd=ROOT, timeout=300,
                           env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        out.append(r.stdout + r.stderr)
        if r.returncode != 0:
            rc_all = 1
    return rc_all, '\n'.join(out)


# ─────────────────────────────────────────────────────────────
# 变异定义：(名称, 文件, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

MUTATIONS = [
    ('G1  fmtRate 读不到时返回 0（「采样中」被改成「0 B/s」—— 撒谎）',
     APP_JS,
     [("      if (bps === null || bps === undefined || isNaN(bps)) return '采样中';",
       "      if (bps === null || bps === undefined || isNaN(bps)) return '0 B/s';")]),

    ('G2  panelCount 用 falsy 判断（0 条被显示成「未知」）',
     APP_JS,
     [("""      const v = panel.counts[key];
      if (v === null || v === undefined) return '未知';""",
       """      const v = panel.counts[key];
      if (!v) return '未知';""")]),

    ('G3  svcPriority 用 falsy 判断（序号 0 被显示成「—」）',
     APP_JS,
     [("      if (!svc || svc.priority === null || svc.priority === undefined) return '—';",
       "      if (!svc || !svc.priority) return '—';")]),

    ('G4  ifaceDetail 无条件显示丢包/错误（含 0）',
     APP_JS,
     [("""      const dropped = (iface.rx_dropped || 0) + (iface.tx_dropped || 0);
      const errs = (iface.rx_errors || 0) + (iface.tx_errors || 0);
      if (dropped) bits.push('丢包 ' + dropped);
      if (errs) bits.push('错误 ' + errs);""",
       """      const dropped = (iface.rx_dropped || 0) + (iface.tx_dropped || 0);
      const errs = (iface.rx_errors || 0) + (iface.tx_errors || 0);
      bits.push('丢包 ' + dropped);
      bits.push('错误 ' + errs);""")]),

    ('G5  ifaceDetail 读不到时显示「未知」而不是不显示',
     APP_JS,
     [("      if (!iface) return '';",
       "      if (!iface) return '未知';")]),

    ('G6  自动刷新不再判断当前页（离开系统信息页还在打接口）',
     APP_JS,
     [("      if (this.currentNav !== 'system-info') return;",
       "      // （判断被去掉）")]),

    ('G7  速率列引用错字段（显示成累计字节，页面看着完全正常）',
     INDEX_HTML,
     [("""                          <div class="text-xs text-gray-400" x-text="'↓ ' + fmtRate(iface.rx_bps)"></div>""",
       """                          <div class="text-xs text-gray-400" x-text="'↓ ' + fmtRate(iface.rx_bytes)"></div>""")]),

    ('G8  计数列拿不到 panel（恒显示「未知」）',
     INDEX_HTML,
     [("panelCount(deviceInfo.data.panel, 'forward_rules')",
       "panelCount(null, 'forward_rules')")]),

    ('G9  「交换」列少算一半（只算发不算收）',
     INDEX_HTML,
     [("x-text=\"fmtBytes((iface.rx_bytes || 0) + (iface.tx_bytes || 0))\"",
       "x-text=\"fmtBytes(iface.tx_bytes || 0)\"")]),

    ('G10 「交换」列表头被删',
     INDEX_HTML,
     [("""                      <th class="py-2 font-normal text-right">交换</th>""",
       """                      <th class="py-2 font-normal text-right"></th>""")]),
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
    for name, target, edits in MUTATIONS:
        src = ORIG[target]
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
            with open(target, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if rc != 0:
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l and '[PASS]' not in l), '')
                if not first:
                    first = next((l.strip() for l in out.splitlines()
                                  if '失败项' in l), '')
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
