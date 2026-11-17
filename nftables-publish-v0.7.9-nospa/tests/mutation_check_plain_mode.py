#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""极简模式开关的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_plain_mode.py

测什么有效
----------
这个开关的失败模式全是「**看起来还在、其实已经不生效**」：

  · 开关切了但没记住（刷新就丢 ⇒ 用户以为开关坏了）
  · 记住了但不生效（class 没摆上 ⇒ 页面还是老样子）
  · 页面变简单了但像素场还在跑（**藏起来 ≠ 不跑**：
    rAF 照样每帧 putImageData，CPU 一分没省 ⇒ 等于白做）
  · 磨砂关了一半（还剩几个元素在糊）
  · 动效压到 .001ms 但无限循环没停（`nf-drift` 26s 那个还在转）
  · 用 `transition: none` 而不是压时长（transitionend 永远不触发
    ⇒ Alpine 的 x-transition 认为没结束 ⇒ 元素卡在起始态 opacity:0 ＝ 看不见）
  · 开关脚本 defer 了 / 排在样式后面（首屏先闪一帧动效）
  · 勾选框没跟着初始化（页面已经是极简了、勾却没勾）

所以每条变异都往「让这条链退化」的方向改。

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。

⚠️ 语法错误的变异不是行为变异
------------------------------
改出来的代码必须**能跑**，否则测试脚本会崩，而崩溃不等于断言失败
（判定只看输出里有没有真正的断言失败行）。

保险丝：备份 / 还原本脚本会动的那几个文件。
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
FILES = {
    'plain': os.path.join(ROOT, 'frontend', 'plainmode.js'),
    'pixel': os.path.join(ROOT, 'frontend', 'pixelbg.js'),
    'styles': os.path.join(ROOT, 'frontend', 'styles.css'),
    'index': os.path.join(ROOT, 'frontend', 'index.html'),
    'appjs': os.path.join(ROOT, 'frontend', 'app.js'),
    'backend': os.path.join(ROOT, 'backend', 'app.py'),
}
TESTS = [
    os.path.join(ROOT, 'tests', 'test_plain_mode.js'),     # 行为级（node）
    os.path.join(ROOT, 'tests', 'test_plain_mode.py'),     # 接线（python）
]

ORIG = {k: open(v, encoding='utf-8').read() for k, v in FILES.items()}
ORIG_SHA = {k: hashlib.sha256(s.encode('utf-8')).hexdigest()
            for k, s in ORIG.items()}

# (描述, 文件键, [(旧文本, 新文本), ...])
MUTATIONS = [
    # ── 开关本体：记住 / 生效 ─────────────────────────────────
    ('PM-1 切开关不记住（刷新就丢）', 'plain',
     [("      window.localStorage.setItem(KEY, on ? '1' : '0');",
       "      /* 变异：不记了 */")]),

    ('PM-2 不摆 class（页面根本没变简单）', 'plain',
     [("    if (on) el.classList.add(CLASS);\n    else el.classList.remove(CLASS);",
       "    /* 变异：什么都不做 */")]),

    ('PM-3 只加不删 class（切回去没反应）', 'plain',
     [("    if (on) el.classList.add(CLASS);\n    else el.classList.remove(CLASS);",
       "    if (on) el.classList.add(CLASS);")]),

    ('PM-4 不通知像素场（背景还在跑）', 'plain',
     [("      if (window.__panelPixelBg && window.__panelPixelBg.apply) {\n"
       "        window.__panelPixelBg.apply(on);\n"
       "      }",
       "      /* 变异：不通知 */")]),

    ('PM-5 存不了时不兜（隐私模式下直接崩）', 'plain',
     [("    try {\n"
       "      window.localStorage.setItem(KEY, on ? '1' : '0');\n"
       "    } catch (e) {\n"
       "      /* 存不了就只在本次会话生效 */\n"
       "    }",
       "    window.localStorage.setItem(KEY, on ? '1' : '0');")]),

    ('PM-6 读状态时不兜（页面加载就崩）', 'plain',
     [("    try {\n"
       "      return window.localStorage.getItem(KEY) === '1';\n"
       "    } catch (e) {\n"
       "      return false;\n"
       "    }",
       "    return window.localStorage.getItem(KEY) === '1';")]),

    # ── 像素场：藏起来 ≠ 不跑 ─────────────────────────────────
    ('PM-7 极简模式下照样挂载像素场', 'pixel',
     [("    if (plainOn()) {\n"
       "      /* 极简模式：**不挂载**像素场，不是「藏起来」。\n"
       "         藏起来 rAF 还在跑，每帧照样 putImageData（实测每帧约 14ms JS），\n"
       "         CPU 一分都不省。 */\n"
       "      canvas.style.display = 'none';\n"
       "      return;\n"
       "    }",
       "    /* 变异：照样挂载 */")]),

    ('PM-8 极简模式只藏画布不停引擎（CPU 白跑）', 'pixel',
     [("    if (plainOn()) {\n"
       "      /* 极简模式：**不挂载**像素场，不是「藏起来」。\n"
       "         藏起来 rAF 还在跑，每帧照样 putImageData（实测每帧约 14ms JS），\n"
       "         CPU 一分都不省。 */\n"
       "      canvas.style.display = 'none';\n"
       "      return;\n"
       "    }",
       "    if (plainOn()) {\n"
       "      canvas.style.display = 'none';\n"
       "    }")]),

    ('PM-9 切到极简不停引擎（每帧还在重绘）', 'pixel',
     [("    if (on) {\n"
       "      if (instance && instance.stop) {\n"
       "        try { instance.stop(); } catch (e) { /* 停不掉就算了 */ }\n"
       "      }\n"
       "      return;\n"
       "    }",
       "    if (on) {\n"
       "      return;\n"
       "    }")]),

    ('PM-10 切回普通不恢复引擎（背景再也不动了）', 'pixel',
     [("    if (!instance) {\n"
       "      mountField();\n"
       "    } else if (instance.start) {\n"
       "      try { instance.start(); } catch (e) { /* 起不来就算了 */ }\n"
       "    }",
       "    /* 变异：不恢复 */")]),

    ('PM-11 切回普通不把画布显示回来', 'pixel',
     [("    if (canvas) canvas.style.display = on ? 'none' : '';",
       "    if (canvas) canvas.style.display = 'none';")]),

    # ── 样式：磨砂与动效 ─────────────────────────────────────
    ('PM-12 不关磨砂（页面还是糊的）', 'styles',
     [("  backdrop-filter: none !important;\n"
       "  -webkit-backdrop-filter: none !important;\n"
       "  animation-duration: .001ms !important;",
       "  animation-duration: .001ms !important;")]),

    ('PM-13 不压动画时长（动效照旧）', 'styles',
     [("  animation-duration: .001ms !important;\n"
       "  animation-iteration-count: 1 !important;",
       "  animation-iteration-count: 1 !important;")]),

    ('PM-14 无限动画仍然无限（26s 漂移还在转）', 'styles',
     [("  animation-duration: .001ms !important;\n"
       "  animation-iteration-count: 1 !important;",
       "  animation-duration: .001ms !important;")]),

    ('PM-15 用 transition:none 代替压时长（Alpine 会卡在起始态）', 'styles',
     [("  transition-duration: .001ms !important;\n"
       "  transition-delay: 0ms !important;",
       "  transition: none !important;")]),

    ('PM-16 不藏像素场画布', 'styles',
     [("html.nf-plain .nf-pix { display: none !important; }",
       "/* 变异：不藏 */")]),

    # ── 接线：index.html ─────────────────────────────────────
    ('PM-17 开关脚本 defer（首屏先闪一帧动效）', 'index',
     [('  <script src="/plainmode.js"></script>',
       '  <script defer src="/plainmode.js"></script>')]),

    ('PM-18 开关脚本排在样式之后（首屏先闪一帧动效）', 'index',
     [('  <script src="/plainmode.js"></script>\n'
       '  <link rel="stylesheet" href="styles.css">',
       '  <link rel="stylesheet" href="styles.css">\n'
       '  <script src="/plainmode.js"></script>')]),

    ('PM-19 侧栏没有开关（功能够不着）', 'index',
     [('        <label x-show="!loading"\n'
       '          class="nf-plain-switch">\n'
       '          <input type="checkbox"\n'
       '            :checked="plainMode"\n'
       '            @change="setPlainMode($event.target.checked)">\n'
       '          <span>极简模式（无磨砂无动效）</span>\n'
       '        </label>\n',
       '')]),

    # ── 接线：app.js ─────────────────────────────────────────
    ('PM-20 不初始化 plainMode（勾选框与实际不符）', 'appjs',
     [("        this.plainMode = !!(window.NfPlain && window.NfPlain.isOn());",
       "        /* 变异：不读 */")]),

    ('PM-21 切换时不管开关本体（点了没反应）', 'appjs',
     [("        if (window.NfPlain) window.NfPlain.set(this.plainMode);",
       "        /* 变异：不调 */")]),

    ('PM-22 没有 plainMode 状态字段', 'appjs',
     [("    plainMode: false,\n", "")]),

    # ── 接线：后端静态服务 ───────────────────────────────────
    ('PM-23 静态白名单去掉 js（/plainmode.js 会 404）', 'backend',
     [("_STATIC_EXTENSIONS = ('js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', "
       "'ico', 'woff', 'woff2', 'ttf', 'map')",
       "_STATIC_EXTENSIONS = ('css', 'png', 'jpg', 'jpeg', 'gif', 'svg', "
       "'ico', 'woff', 'woff2', 'ttf', 'map')")]),
]


def _judge_capture(rc, out):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」
      ⇒ 只有输出里真的出现**断言失败**的标记行才算捕获。
    """
    if rc == 0:
        return False
    for line in out.splitlines():
        s = line.strip()
        if '[FAIL]' in s and '[PASS]' not in s:
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    """把源码还原成启动时的内容。幂等，可反复调用。"""
    for key, path in FILES.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(ORIG[key])
        except OSError:
            pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    for key, path in FILES.items():
        try:
            with open(path, 'rb') as f:
                got = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            got = None
        if got != ORIG_SHA[key]:
            return False, '%s 还原后 sha256 不一致（%s != %s）' % (
                os.path.basename(path), got, ORIG_SHA[key])
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
    """跑本批的两个判据（node 行为级 + python 接线），输出合并。"""
    outs = []
    rc_all = 0
    for t in TESTS:
        if t.endswith('.js'):
            cmd = ['node', t]
        else:
            cmd = [sys.executable, t]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                           cwd=ROOT)
        outs.append(r.stdout + r.stderr)
        if r.returncode != 0:
            rc_all = r.returncode
    return rc_all, '\n'.join(outs)


def apply_edits(key, edits):
    """edits: [(old, new)]，每条都必须**唯一**匹配 —— 匹配不上就报错。

    为什么必须唯一：变异脚本按「第一个匹配」替换；
    old 片段不唯一 ⇒ 改到哪一处全看运气 ⇒ 「漏网」被伪装成「捕获」。
    """
    src = ORIG[key]
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点出现 %d 次，必须唯一：%r' % (n, old[:70]))
        src = src.replace(old, new, 1)
    with open(FILES[key], 'w', encoding='utf-8') as f:
        f.write(src)


def main():
    print('=== 变异验证：极简模式开关 ===')
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

    caught, missed = 0, []
    for desc, key, edits in MUTATIONS:
        restore()
        try:
            apply_edits(key, edits)
        except ValueError as e:
            print('  [脚本错] %s' % desc)
            print('      ↓ %s' % e)
            missed.append('%s（变异脚本自身的错）' % desc)
            continue
        rc, out = run_tests()
        if _judge_capture(rc, out):
            caught += 1
            first = ''
            for line in out.splitlines():
                s = line.strip()
                if '[FAIL]' in s and '[PASS]' not in s:
                    first = s
                    break
            print('  [捕获] %s' % desc)
            if first:
                print('      ↓ %s' % first[:150])
        else:
            missed.append(desc)
            print('  [漏网] %s  ← 测试没变红！' % desc)

    restore()
    ok, detail = restore_verified()
    print()
    print('=' * 60)
    print('  变异 %d 条，捕获 %d 条，漏网 %d 条' %
          (len(MUTATIONS), caught, len(missed)))
    if missed:
        print('  漏网的变异：')
        for m in missed:
            print('    - ' + m)
        print('=' * 60)
        return 1
    if not ok:
        print('  [FAIL] %s' % detail)
        print('=' * 60)
        return 1
    print('  全部捕获')
    print('=' * 60)
    return 0


if __name__ == '__main__':
    sys.exit(main())
