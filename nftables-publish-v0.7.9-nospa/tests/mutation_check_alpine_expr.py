#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Alpine 求值语义判据（tests/test_frontend_alpine_expr.js）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_alpine_expr.py

测什么有效
----------
这一批修的是一个**静默退化**：Alpine 求值器把「以 if 开头」的表达式
当成语句包起来，于是**表达式的值被丢掉**，页面那一格永远是空的。

最阴险的地方在于它**什么错都不报**：
  · 不报错、不白屏、控制台干净
  · 所有文本层面的测试全绿（它们用的是自己的求值器 new Function，
    不是 Alpine 的）
  · 页面上其它部分完全正常，只有那一格是空的

所以「测试全绿」根本不能证明这批改动是对的 ——
必须有一个判据**用 Alpine 自己的规则**去检查模板。

判据本身也可能被写错。所以这个脚本验证的是**判据会不会被绕过**：

  A1  把方法名改回 ifaceDetail      ⇒ 值位表达式 + 方法名 两处都要中招
  A2  模板里新增一条 if 开头的值位表达式 ⇒ 值位检查要中招
  A3  app.js 里新增一个 if 开头的方法   ⇒ 方法名检查要中招
  A4  alpine.js 的正则被换成宽松版      ⇒ 「从 alpine.js 抽正则」要失败
  A5  alpine.js 的正则被删掉            ⇒ 同上，且不能静默通过

⚠️ A4/A5 改的是 **frontend/assets/alpine.js** ——
   那是第三方压缩产物，不是我们的代码。改它只为验证判据与 Alpine 实际
   行为**同步**（判据的正则必须来自 Alpine 源码，不能手抄）。
   ⇒ 还原时按**字节**校验（sha256），不能按行。

保险丝：只备份 / 还原**本脚本会动的那三个文件**，一个字节都不碰别的。
还原后逐个比对 sha256 —— 源码没还原干净时**必须**当成失败。
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
ALPINE_JS = os.path.join(ROOT, 'frontend', 'assets', 'alpine.js')

TESTS = [
    os.path.join(ROOT, 'tests', 'test_frontend_alpine_expr.js'),
]

# 我独占、也只有我会改的那三个文件。
ORIG = {p: open(p, encoding='utf-8').read() for p in (APP_JS, INDEX_HTML, ALPINE_JS)}
ORIG_SHA = {p: hashlib.sha256(c.encode('utf-8')).hexdigest()
            for p, c in ORIG.items()}


def restore():
    """把三个文件还原成脚本启动时的内容。幂等，可反复调用。"""
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
    """跑判据文件。红了就算变异被捕获。"""
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

# Alpine 压缩源码里那条正则的**唯一**上下文片段。
# 用它做锚点：出现 3 次，所以锚点必须带上前后文才能唯一。
ALPINE_IF_CTX = (
    'n=/^[\\n\\s]*if.*\\(.*\\)/.test(t.trim())||/^(let|const)\\s/.test(t.trim())?'
    '`(async()=>{ ${t} })()`:t'
)

MUTATIONS = [
    ('A1  方法名改回 ifaceDetail（值位 + 方法名 两处中招）',
     APP_JS,
     [("    detailOf(iface) {", "    ifaceDetail(iface) {")]),

    ('A1b 模板里的调用点也改回 ifaceDetail',
     INDEX_HTML,
     [('x-text="detailOf(iface)"', 'x-text="ifaceDetail(iface)"')]),

    # ⚠️ 必须落在**已知值位属性**上（x-text），才能真正验证「值位检查」这条路径。
    #   第一版这里用的是 x-data-x（一个模板里没有的新属性），
    #   结果它是被「属性分类完备性」那条兜底抓住的 ——
    #   兜底能兜住只是一次运气，报告出来的原因跟「表达式踩坑」完全是两回事。
    ('A2  已知的值位属性（x-text）里换成 if 开头的表达式',
     INDEX_HTML,
     [('x-text="detailOf(iface)"',
       'x-text="ifBogus(iface)"')]),

    ('A3  app.js 里新增一个 if 开头的方法',
     APP_JS,
     [("    detailOf(iface) {",
       "    ifBogus(iface) { return ''; },\n\n    detailOf(iface) {")]),

    ('A4  alpine.js 的正则被换成宽松版（判据必须发现它不再是原来那条）',
     ALPINE_JS,
     [(ALPINE_IF_CTX,
       'n=/^\\s*if\\s/.test(t.trim())||/^(let|const)\\s/.test(t.trim())?'
       '`(async()=>{ ${t} })()`:t')]),

    ('A5  alpine.js 的正则被删掉（判据必须失败，不能静默通过）',
     ALPINE_JS,
     [(ALPINE_IF_CTX,
       'n=false?`(async()=>{ ${t} })()`:t')]),
]


def main():
    print('=== 基线：未变异时判据必须全绿 ===')
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
                print('  [FAIL] %s  —— 漏网！判据没抓住' % name)
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
        print('  源码已全部还原，但有漏网项 —— 上面标 [FAIL] 的判据是假判据')
    else:
        print('  源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
