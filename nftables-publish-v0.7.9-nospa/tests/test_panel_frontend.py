"""面板（5443）像素场背景接线的静态回归测试。

运行:  python3 tests/test_panel_frontend.py

覆盖 2026-11-04 落地的一批改动（面板接上与服务门户同一套像素场）：

  PP-1  引擎源码**只有一份**（面板从 backend/static 取，不在 frontend/ 留拷贝）
  PP-2  面板页面引了引擎与引导脚本，画布在环境光**之前**（垫底）
  PP-3  画布样式：铺满、不吃点击、z-index 与其它背景层一致
  PP-4  面板 CSP 允许同源外链脚本
  PP-5  引导脚本的候选表就是「原版 / TRAE 原版」两档

不碰网络、不碰真实配置：全部是源码文本解析。
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND = os.path.join(ROOT, 'frontend')
BACKEND = os.path.join(ROOT, 'backend')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print('\n== ' + title)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


def strip_html_comments(src):
    return re.sub(r'<!--.*?-->', '', src, flags=re.S)


def strip_js_comments(src):
    """去掉 JS 行注释与块注释（字符串里的内容原样保留，够用即可）。"""
    src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    out = []
    for line in src.split('\n'):
        # 只在不在字符串里的地方砍行注释：粗略但对本文件够用
        q = None
        cut = len(line)
        for i, ch in enumerate(line):
            if q:
                if ch == q:
                    q = None
                continue
            if ch in ('"', "'", '`'):
                q = ch
                continue
            if ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
                cut = i
                break
        out.append(line[:cut])
    return '\n'.join(out)


INDEX = read(os.path.join('frontend', 'index.html'))
INDEX_CODE = strip_html_comments(INDEX)
STYLES = read(os.path.join('frontend', 'styles.css'))
PIXELBG = read(os.path.join('frontend', 'pixelbg.js'))
PIXELBG_CODE = strip_js_comments(PIXELBG)
APP_PY = read(os.path.join('backend', 'app.py'))

# ─────────────────────────────────────────────────────────────
sec('PP-1 引擎源码只有一份（面板不在 frontend/ 留拷贝）')

# ⚠ 这条是本批改动里**最容易退化**的一条：
#   谁在 frontend/ 里拷一份 pixelfield.js，两边就会各自漂移，
#   而且**页面上完全看不出来**（两套画面都"正常"，只是不一样了）。
check('frontend/ 里没有 pixelfield.js 的拷贝',
      not os.path.isfile(os.path.join(FRONTEND, 'pixelfield.js')))
check('backend/static/pixelfield.js 还在（唯一真源）',
      os.path.isfile(os.path.join(ROOT, 'backend', 'static', 'pixelfield.js')))
check('app.py 有共享文件白名单 SHARED_STATIC_FILES',
      'SHARED_STATIC_FILES' in APP_PY)
check('共享白名单里含 pixelfield.js',
      re.search(r"SHARED_STATIC_FILES\s*=\s*frozenset\(\{[^}]*pixelfield\.js",
                APP_PY, re.S) is not None)
check('面板的静态服务有回退分支（先 frontend/，再共享目录）',
      re.search(r"if filename in SHARED_STATIC_FILES:\s*\n\s*return send_from_directory\('static', filename\)",
                APP_PY) is not None)
check('回退只放行白名单文件（不是整个目录）',
      'send_from_directory(\'static\', filename)' in APP_PY and
      "filename in SHARED_STATIC_FILES" in APP_PY)

# ─────────────────────────────────────────────────────────────
sec('PP-2 面板页面引了引擎与引导脚本')

check('页面里有像素场画布 nf-pix',
      re.search(r'<canvas[^>]*id="nf-pix"', INDEX_CODE) is not None)
check('画布带 nf-pix 类（样式靠类名挂）',
      re.search(r'<canvas[^>]*class="[^"]*nf-pix[^"]*"', INDEX_CODE) is not None)
check('画布在环境光层**之前**（DOM 序 ⇒ 垫底）',
      INDEX_CODE.find('id="nf-pix"') > 0 and
      INDEX_CODE.find('id="nf-pix"') < INDEX_CODE.find('class="nf-ambience"'))
check('页面引了共享引擎脚本',
      re.search(r'<script[^>]*src="/pixelfield\.js"', INDEX_CODE) is not None)
check('页面引了面板自己的引导脚本',
      re.search(r'<script[^>]*src="/pixelbg\.js"', INDEX_CODE) is not None)
check('引擎脚本排在引导脚本之前（引导脚本要用 window.GhostPixelField）',
      INDEX_CODE.find('/pixelfield.js') < INDEX_CODE.find('/pixelbg.js'))
check('两个脚本都是 defer（DOM 解析完再跑，画布已存在）',
      re.search(r'<script[^>]*defer[^>]*src="/pixelfield\.js"', INDEX_CODE) is not None and
      re.search(r'<script[^>]*defer[^>]*src="/pixelbg\.js"', INDEX_CODE) is not None)
check('页面没有内联 <script> 块（CSP 与项目风格都禁）',
      re.search(r'<script(?![^>]*\bsrc=)[^>]*>\s*\S', INDEX_CODE) is None)

# ─────────────────────────────────────────────────────────────
sec('PP-3 画布样式：铺满 / 不吃点击 / 层级与其它背景层一致')

m_nf_pix = re.search(r'\.nf-pix\s*\{([^}]*)\}', STYLES)
check('styles.css 里有 .nf-pix 规则', m_nf_pix is not None)
if m_nf_pix:
    blk = m_nf_pix.group(1)
    check('画布铺满视口（position: fixed + inset: 0）',
          'position: fixed' in blk and 'inset: 0' in blk)
    check('画布不吃点击（pointer-events: none）',
          'pointer-events: none' in blk)
    check('画布 z-index 为 0（与 .nf-ambience / .nf-grid 同层，靠 DOM 序叠放）',
          re.search(r'z-index:\s*0\s*;', blk) is not None)
for sel in ('.nf-ambience', '.nf-grid'):
    m = re.search(re.escape(sel) + r'\s*\{([^}]*)\}', STYLES)
    check(sel + ' 也是 z-index: 0（与画布同层）',
          m is not None and re.search(r'z-index:\s*0\s*;', m.group(1)) is not None)

# ─────────────────────────────────────────────────────────────
sec('PP-4 面板 CSP 允许同源外链脚本')

m_csp = re.search(r"Content-Security-Policy',\s*\((.*?)\)\)", APP_PY, re.S)
check('面板设了 CSP', m_csp is not None)
if m_csp:
    csp = m_csp.group(1)
    check("CSP 的 script-src 含 'self'（同源外链脚本放行）",
          "'self'" in csp and 'script-src' in csp)
    check("CSP 的 style-src 含 'self'", 'style-src' in csp and "'self'" in csp)

# ─────────────────────────────────────────────────────────────
sec('PP-5 引导脚本的候选表就是「原版 / TRAE 原版」两档')

check("候选表是 ['moonstone', 'trae']",
      re.search(r"CANDIDATES\s*=\s*\['moonstone',\s*'trae'\]", PIXELBG_CODE) is not None)
check('候选表里不含被否掉的混合方案',
      'trae-orig' not in PIXELBG_CODE and 'moonstone-trae' not in PIXELBG_CODE)
check('用的是真随机（Math.random）',
      'Math.random()' in PIXELBG_CODE)
check('支持 ?pfstyle= 钉死某一档',
      "queryParam('pfstyle')" in PIXELBG_CODE)
check('档名不在候选里就回退随机（不给引擎传不存在的档）',
      re.search(r"if \(CANDIDATES\[i\] === want\) return want;", PIXELBG_CODE) is not None)
check('尊重 prefers-reduced-motion（引擎静态模式）',
      "prefers-reduced-motion" in PIXELBG_CODE and 'static: reduce' in PIXELBG_CODE)
check('引擎不存在/抛异常时不外溢（自己 try 住）',
      'catch (e)' in PIXELBG_CODE)

# ─────────────────────────────────────────────────────────────
sec('PP-6 登录页要看得见背景（遮罩调淡 + 遮罩下面的面板藏起来）')

# ⚠️ 2026-11-04 第十五轮，用户要求「登录页也要看得见背景」。
#   这件事有**两半**，缺一半等于没做：
#     ① 遮罩别那么黑（.88 → .58）
#     ② 遮罩下面的侧栏与主内容**藏起来**
#   只做①不做② ⇒ 58% 的遮罩会把「半个面板」透出来：实拍里能看清
#   「底层内容」四个字和底部模糊的表格块，看着像渲染坏了（用户会当成 bug）。
m_login = re.search(r'\.nf-login\s*\{([^}]*)\}', STYLES)
check('styles.css 里有 .nf-login 规则', m_login is not None)
_alpha = None
if m_login:
    blk = m_login.group(1)
    # ⚠️ rgba() 有四个分量，别用 [^)]+ 直接抓尾巴 ——
    #   那会把 "16, .58" 整段抓成 alpha，float() 直接抛异常。
    #   正确做法：先把 rgba(...) 整段抠出来，再按逗号切，取**最后一段**。
    m_a = re.search(r'background:\s*rgba\(([^)]*)\)', blk)
    if m_a:
        parts = m_a.group(1).split(',')
        try:
            _alpha = float(parts[-1].strip())
        except ValueError:
            _alpha = None
    check('登录遮罩的不透明度不高于 0.65（再黑背景就等于被遮死了）',
          _alpha is not None and _alpha <= 0.65,
          '实测 alpha=%s' % _alpha)
    check('遮罩仍然有底（不能全透明：背景与卡片会叠在一起）',
          _alpha is not None and _alpha > 0,
          '实测 alpha=%s' % _alpha)
    check('遮罩仍然带 backdrop-filter（背景要糊开，不能是硬边色块）',
          'backdrop-filter' in blk)

# 遮罩下面的面板内容必须藏起来（否则调淡遮罩就会把半个面板透出来）
#
# ⚠️ nf-sidebar / nf-main 是**类名**不是标签名 ——
#   <aside x-show="auth.authenticated" class="nf-sidebar">
#   ⇒ 不能拿 <nf-sidebar ...> 去匹配。
# 而且属性顺序不固定（x-show 可能在 class 前也可能在后），
# 所以按「整条标签」扫一遍再分别判属性。
_ALL_TAGS = re.findall(r'<[a-zA-Z][^>]*>', INDEX_CODE)


def _auth_show_with_class(cls):
    """有没有一个标签，同时带 x-show="auth.authenticated" 和这个类。"""
    for t in _ALL_TAGS:
        if 'x-show="auth.authenticated"' not in t:
            continue
        if re.search(r'class="[^"]*\b' + re.escape(cls) + r'\b', t):
            return True
    return False


for sel in ('nf-sidebar', 'nf-main'):
    check('%s 未认证时隐藏（x-show="auth.authenticated"）' % sel,
          _auth_show_with_class(sel))
check('登录遮罩仍然是「未认证且不在检查中才显示」',
      '!auth.authenticated && !auth.checking' in INDEX_CODE)
check('登录卡片在遮罩之内（不是被藏起来了）',
      re.search(r'class="nf-login__card[^"]*"', INDEX_CODE) is not None)

print()
if FAIL:
    print(f'失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
