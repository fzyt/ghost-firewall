#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""极简模式开关的**接线**判据（2026-11-17）

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/test_plain_mode.py

测什么
------
行为那一半在 tests/test_plain_mode.js（node，真跑 plainmode.js 与
pixelbg.js）。这个文件只管**接线**——三处接线错了，行为判据照样全绿：

  1. index.html  —— 开关脚本必须**同步加载**且排在 styles.css **之前**
     （排在后面 ⇒ 极简模式的用户每次打开面板先闪一帧动效）
  2. styles.css  —— 极简模式的规则块：磨砂关掉、动效压到 .001ms
  3. app.js      —— 界面上那个勾选框与开关本体对上

⚠️ 「不该出现」类断言必须用**去注释版**源码：
   styles.css 的注释里就写着 `transition: none` / `animation: none`
   （解释为什么不能这么写）—— 不去注释就会把自己骂成失败。
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

PASS = []
FAIL = []


def check(name, cond, detail=''):
    if cond:
        PASS.append(name)
        print('  [PASS] %s%s' % (name, (' — ' + detail) if detail else ''))
    else:
        FAIL.append(name)
        print('  [FAIL] %s%s' % (name, (' — ' + detail) if detail else ''))


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


def strip_css_comments(src):
    """去掉 CSS 块注释 /* ... */（CSS 里没有 // 行注释）。"""
    return re.sub(r'/\*.*?\*/', '', src, flags=re.S)


def strip_html_comments(src):
    """去掉 HTML 注释 <!-- ... -->。"""
    return re.sub(r'<!--.*?-->', '', src, flags=re.S)


def main():
    index_raw = read('frontend/index.html')
    styles_raw = read('frontend/styles.css')
    app_js = read('frontend/app.js')
    pixel_js = read('frontend/pixelbg.js')
    backend = read('backend/app.py')

    index = strip_html_comments(index_raw)
    styles = strip_css_comments(styles_raw)

    # ── PM-W1 index.html：脚本必须同步加载且排在样式之前 ──────
    print('\n== PM-W1 index.html 的接线')

    tag = '<script src="/plainmode.js"></script>'
    check('引用了 /plainmode.js', tag in index)
    if tag in index:
        pos = index.index(tag)
        css_pos = index.find('<link rel="stylesheet" href="styles.css">')
        check('排在 styles.css **之前**（否则首屏会闪一帧动效）',
              css_pos >= 0 and pos < css_pos,
              'script@%d css@%d' % (pos, css_pos))
        # ⚠️ 只看**这个标签自身**的属性 ——
        #    往前看 60 字符会扫到 pixelbg.js 那行的 defer（那是另一回事）。
        m2 = re.search(r'<script[^>]*src="/plainmode\.js"[^>]*>', index)
        check('这个标签没有 defer（defer 就晚了）',
              m2 is not None and 'defer' not in m2.group(0),
              m2.group(0) if m2 else '没找到标签')
    check('侧栏有开关的勾选框',
          re.search(r'<input\s+type="checkbox"', index) is not None)
    check('勾选框接到了 setPlainMode',
          'setPlainMode($event.target.checked)' in index)
    check('勾选框绑的是 plainMode 状态',
          ':checked="plainMode"' in index)

    # ── PM-W2 styles.css：极简模式的规则块 ──────────────────
    print('\n== PM-W2 styles.css 的极简规则')

    m = re.search(r'(html\.nf-plain[^{]*)\{([^}]*)\}', styles, flags=re.S)
    check('有 html.nf-plain 规则块', m is not None)
    if m:
        block = m.group(2)
        check('磨砂被关掉', 'backdrop-filter: none' in block)
        check('-webkit- 版本也关掉', '-webkit-backdrop-filter: none' in block)
        check('动画时长被压到 .001ms', 'animation-duration: .001ms' in block)
        check('动画只放一遍（无限循环停掉）',
              'animation-iteration-count: 1' in block)
        check('过渡时长被压到 .001ms', 'transition-duration: .001ms' in block)
        check('过渡延迟归零', 'transition-delay: 0ms' in block)
        # ⚠️ 不能用 transition: none / animation: none ——
        #    transitionend 永远不触发 ⇒ Alpine 的 x-transition 认为没结束，
        #    元素卡在起始态（opacity:0）＝看不见。
        check('**没有**用 transition: none（会让 Alpine 卡在起始态）',
              'transition: none' not in block)
        check('**没有**用 animation: none（会让无限动画停在错误的态）',
              'animation: none' not in block)

    check('像素场画布在极简模式下被藏起来',
          re.search(r'html\.nf-plain\s+\.nf-pix\s*\{[^}]*display:\s*none', styles)
          is not None)

    # ── PM-W3 app.js：界面与开关本体对上 ───────────────────
    print('\n== PM-W3 app.js 的接线')

    check('有 plainMode 状态字段',
          re.search(r'^\s*plainMode:\s*false\s*,?\s*$', app_js, flags=re.M)
          is not None)
    check('有 setPlainMode 方法',
          re.search(r'^\s*setPlainMode\(on\)\s*\{', app_js, flags=re.M)
          is not None)
    check('初始化时从开关本体读状态（否则勾选框与实际不符）',
          'window.NfPlain && window.NfPlain.isOn()' in app_js)
    check('切换时调开关本体',
          'window.NfPlain.set(' in app_js)

    # ── PM-W4 pixelbg.js：极简模式不挂载像素场 ─────────────
    print('\n== PM-W4 pixelbg.js 的接线')

    check('有 plainOn()（读极简状态）',
          re.search(r'function\s+plainOn\s*\(\s*\)', pixel_js) is not None)
    check('有 applyPlain()（切换时停/起像素场）',
          re.search(r'function\s+applyPlain\s*\(\s*on\s*\)', pixel_js) is not None)
    check('挂载前先问极简状态',
          re.search(r'if\s*\(\s*plainOn\(\)\s*\)', pixel_js) is not None)
    check('把 apply 暴露出去给开关调用',
          re.search(r'apply\s*:\s*applyPlain', pixel_js) is not None)

    # ── PM-W5 静态服务能取到新文件 ─────────────────────────
    print('\n== PM-W5 静态服务')

    check("静态扩展名白名单含 'js'（否则 /plainmode.js 会 404）",
          re.search(r"_STATIC_EXTENSIONS\s*=\s*\([^)]*'js'", backend)
          is not None)
    check('静态服务从 frontend/ 取文件',
          "send_from_directory('../frontend', filename)" in backend)

    print()
    if FAIL:
        print('[FAIL] 失败 %d 项：' % len(FAIL))
        for f in FAIL:
            print('   - ' + f)
        sys.exit(1)
    print('[PASS] 通过 %d / %d' % (len(PASS), len(PASS)))
    print('全部通过')


if __name__ == '__main__':
    main()
