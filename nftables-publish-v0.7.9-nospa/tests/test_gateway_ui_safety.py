"""认证网关前端的安全性质 —— 回归测试。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/test_gateway_ui_safety.py

2026-10-21 认证网关界面做视觉重做（登录页 + 服务门户 + 门转场动效），
用户问了一句很关键的话：**「这个元素动效改动不影响原来的端点安全性对吧」**。

这个文件把那个答案**变成可执行的断言**，以后谁想在前端里偷偷引入
CDN 脚本、内联样式、innerHTML、开放重定向口子，都会被挡下来。

守的四条红线：

  1. **端点集合不变** —— 认证网关的 9 个路由一个不多一个不少，
     方法也不变。前端再怎么做都不该动它。
  2. **CSP 不放松** —— `default-src 'none'`，没有 `unsafe-inline`、
     没有 `unsafe-eval`。这意味着前端**不可能**用内联 `<script>`、
     内联 `style="..."` 或任何 CDN 资源。
  3. **前端不自己拼 URL** —— 不许出现 innerHTML / eval / document.write，
     也不许出现任何外部 http(s) 资源引用。跳转目标只能来自服务端的
     `safeNext()`（拒绝 `//`、带 scheme 的、反斜杠）。
  4. **静态文件白名单一一对应** —— `STATIC_ALLOWED` 是白名单，
     多一个文件就可能被 `/auth/static/` 直达。

新增静态文件（比如拆一个 motion.css）**必须**同步改 `STATIC_ALLOWED`，
这个测试会提醒你。
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
STATIC = os.path.join(BACKEND, 'static')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    # 注意：不能用 `(ok and PASS or FAIL)` ——
    # PASS 还没攒够条目时是空列表，空列表是假值，会把 True 判成 False。
    if ok:
        PASS.append(name)
    else:
        FAIL.append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(t):
    print(f'\n=== {t} ===')


def read(p):
    with open(p, encoding='utf-8') as f:
        return f.read()


gw = read(os.path.join(BACKEND, 'auth_gateway.py'))
js_files = {n: read(os.path.join(STATIC, n))
            for n in sorted(os.listdir(STATIC)) if n.endswith('.js')}
html_files = {n: read(os.path.join(STATIC, n))
              for n in sorted(os.listdir(STATIC)) if n.endswith('.html')}
css_files = {n: read(os.path.join(STATIC, n))
             for n in sorted(os.listdir(STATIC)) if n.endswith('.css')}

print('=' * 74)
print('认证网关前端安全性质回归（端点 / CSP / 无外链 / 无 innerHTML）')
print('=' * 74)

# ── 1. 端点集合 ───────────────────────────────────────────────────────
sec('1. 认证网关端点集合不变')

EXPECTED_ROUTES = {
    ('/auth/health', None),
    ('/auth/static/<path:filename>', None),
    ('/', None),
    ('/auth/login', 'GET'),
    ('/auth/status', 'GET'),
    ('/auth/login', 'POST'),
    ('/auth/logout', 'POST'),
    ('/auth/verify', 'GET'),
    ('/auth/portal', 'GET'),
}

found = set()
for m in re.finditer(r'@app\.route\("([^"]+)"(?:,\s*methods=\[([^\]]*)\])?\)', gw):
    path, methods = m.group(1), m.group(2)
    if methods is None:
        found.add((path, None))
    else:
        for mm in re.findall(r'"([A-Z]+)"', methods):
            found.add((path, mm))

check('端点集合与基线完全一致',
      found == EXPECTED_ROUTES,
      f'实际={sorted(found)}')
check('端点数量是 9', len(found) == 9, f'实际={len(found)}')
check('没有新增 /auth/* 端点',
      not any(p.startswith('/auth/') and p not in
              {e[0] for e in EXPECTED_ROUTES} for p, _ in found))

# ── 2. CSP ────────────────────────────────────────────────────────────
sec('2. CSP 不放松')

csp_block = '\n'.join(re.findall(r'CSP_\w+_HTML = \((.*?)\)\n', gw, re.S))
check('找到了两处 CSP 常量', bool(csp_block))
check("CSP 含 default-src 'none'", "default-src 'none'" in csp_block)
check('CSP 不含 unsafe-inline', 'unsafe-inline' not in csp_block)
check('CSP 不含 unsafe-eval', 'unsafe-eval' not in csp_block)
check("CSP 含 script-src 'self'", "script-src 'self'" in csp_block)
check("CSP 含 style-src 'self'", "style-src 'self'" in csp_block)
check("CSP 含 frame-ancestors 'none'", "frame-ancestors 'none'" in csp_block)
check('CSP 不含任何 http(s) 来源白名单',
      not re.search(r"https?://", csp_block))

# ── 3. 前端不自己拼 URL / 不执行动态代码 ─────────────────────────────
sec('3. 前端无危险 API、无外链')

DANGER = [
    (r'\binnerHTML\b', 'innerHTML'),
    (r'\bouterHTML\b', 'outerHTML'),
    (r'\beval\s*\(', 'eval('),
    (r'\bdocument\.write\b', 'document.write'),
    (r'\binsertAdjacentHTML\b', 'insertAdjacentHTML'),
    (r'\bnew\s+Function\b', 'new Function'),
    (r'javascript:', 'javascript: 协议'),
]

for fname, src in list(js_files.items()):
    # 注释里提到「不拼 innerHTML」是合规说明，要排除掉
    code = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
    code = re.sub(r'//.*', '', code)
    for pat, label in DANGER:
        check(f'{fname} 未使用 {label}',
              not re.search(pat, code),
              '' if not re.search(pat, code) else '命中')

for fname, src in list(html_files.items()) + list(css_files.items()):
    ext = re.findall(r'https?://[^\s"\'<>)]+', src)
    check(f'{fname} 无外部资源 URL', not ext, '；'.join(ext[:2]))
    if fname.endswith('.css'):
        check(f'{fname} 无 @import', '@import' not in src)
        check(f'{fname} 无 url(http',
              not re.search(r'url\(\s*[\'"]?https?://', src))

# ── 4. HTML 里没有内联脚本 / 内联样式 ────────────────────────────────
sec('4. HTML 无内联脚本与内联样式（与 CSP 严格一致）')

for fname, src in html_files.items():
    scripts = re.findall(r'<script\b([^>]*)>(.*?)</script>', src, re.S | re.I)
    bad_script = [(a, b) for a, b in scripts
                  if not re.search(r'src\s*=', a) or b.strip()]
    check(f'{fname} 无内联脚本', not bad_script,
          '' if not bad_script else f'{len(bad_script)} 处')
    check(f'{fname} 无 style="..." 属性',
          not re.search(r'\sstyle\s*=', src, re.I))
    check(f'{fname} 无 <style> 块',
          not re.search(r'<style\b', src, re.I))
    check(f'{fname} 无 on* 事件属性',
          not re.search(r'\son[a-z]+\s*=\s*["\']', src, re.I))
    check(f'{fname} 无 http-equiv refresh',
          not re.search(r'http-equiv', src, re.I))

# ── 5. 静态文件白名单一一对应 ─────────────────────────────────────────
sec('5. STATIC_ALLOWED 与实际文件一一对应')

m = re.search(r'STATIC_ALLOWED = frozenset\(\{(.*?)\}\)', gw, re.S)
allowed = set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()
actual = set(os.listdir(STATIC))
check('白名单与实际文件完全一致', allowed == actual,
      f'多={sorted(actual - allowed)} 缺={sorted(allowed - actual)}')
check('白名单里没有目录穿越风险项',
      all('/' not in a and '..' not in a for a in allowed))

# ── 6. 跳转安全：safeNext 与 tile 目标 ───────────────────────────────
sec('6. 跳转目标仍然受控')

login_js = js_files.get('login.js', '')
check('login.js 里有 safeNext()', 'function safeNext' in login_js)
for rule, desc in [
    ("raw.charAt(0) !== '/'", '拒绝非绝对路径'),
    ("raw.charAt(1) === '/'", '拒绝协议相对 //evil.com'),
    ("raw.indexOf('\\\\') !== -1", '拒绝反斜杠'),
    ("/^[a-z][a-z0-9+.-]*:/i.test(raw)", '拒绝带 scheme 的绝对 URL'),
]:
    check(f'safeNext 保留规则：{desc}', rule in login_js)

portal_js = js_files.get('portal.js', '')
check('portal.js 拼 DOM 用 textContent',
      'textContent' in portal_js)
check('portal.js 没有 innerHTML 赋值', not re.search(r'\.innerHTML\s*=', portal_js))
# 2026-10-28 host 分发改造后，服务可能挂在**另一个域名**上
# （https://siyuan.fzyto.top:8443/），光有 path 前缀拼不出那个地址 ——
# 所以链接改由服务端下发 s.url（没有 host 的老规则退回 s.path）。
#
# 这里要守的是「href 只来自服务端下发的字段」，而不是某个具体字段名 ——
# 字段名可以变，但**绝不能**由页面上的文字拼出来。
check('门户 tile 的 href 来自服务端下发的字段（s.url / s.path）',
      re.search(r"a\.href\s*=\s*s\.url\s*\|\|\s*\(?\s*s\.path", portal_js) is not None)
check('门户 tile 的 href 不是由页面上的文字拼出来的',
      re.search(r"a\.href\s*=\s*[^;;]*?(innerText|textContent)", portal_js) is None)

# ── 7. 动效不得成为流程的必经环节 ────────────────────────────────────
sec('7. 动效是装饰性的（坏了也得能登录）')

for fname, src in js_files.items():
    # 只有**带动效**的脚本才需要有降级判断。
    # fingerprint.js 是设备指纹采集，跟动效无关，不该被要求。
    if 'gate' in src or 'prefers-reduced-motion' in src or fname in ('login.js', 'portal.js'):
        check(f'{fname} 有 prefers-reduced-motion 降级判断',
              'prefers-reduced-motion' in src)

check('login.js 播放动效前仍会走 safeNext 跳转',
      re.search(r'location\.replace\(safeNext\(\)\)', login_js) is not None)


def _fallback_jump(src, cond, marker):
    """条件里含 cond 的那个 if，函数体里是否有 marker（= 直接跳）。

    不用正则去抠 if 的括号 —— 条件里同时挂多个理由时
    （reduced-motion || !gateEnabled()）括号套括号，正则很容易扣错。
    这里只问一个结构问题：**同一个 if 里是不是直接跳**。
    注意 cond 第一次出现可能是**函数定义**（function reducedMotion()），
    所以要逐个出现位置找，找到真正在 if 条件里的那个。
    """
    start = 0
    while True:
        i = src.find(cond, start)
        if i < 0:
            return False
        start = i + 1
        head = src.rfind('if (', 0, i)
        if head < 0:
            continue
        seg = src[head:i]
        if ';' in seg or '}' in seg:
            continue          # 那是别的 if，不是在这个条件里
        j = src.find('{', i)
        k = src.find('}', j) if j > 0 else -1
        if j < 0 or k < 0:
            continue
        if marker in src[j:k]:
            return True
    return False


check('动效失败有兜底（reduced-motion 时直接跳）',
      _fallback_jump(login_js, 'reducedMotion()', 'location.replace'))
check('门被 data-gate="off" 关掉时也直接跳（不等动画）',
      _fallback_jump(portal_js, '!gateEnabled()', 'then()')
      and _fallback_jump(login_js, '!gateEnabled()', 'location.replace'))
check('gate.css 支持 html[data-gate="off"] 关掉整个门',
      re.search(r'html\[data-gate="off"\][^{]*\.gate\s*\{[^}]*display:\s*none',
                css_files.get('gate.css', ''), re.S) is not None)
check('base.css 有 reduced-motion 降级块',
      'prefers-reduced-motion' in (css_files.get('base.css', '')))
check('base.css 降级块里 .gate 被 display:none',
      re.search(r'@media\s*\(prefers-reduced-motion:\s*reduce\)(.*?)\.gate\s*\{\s*display:\s*none',
                css_files.get('base.css', ''), re.S) is not None)

# ── 8. 光之门：门脸页与产品页共用同一份动画 ────────────────────────
# 这一版把「黑幕合拢」换成了「光迎面冲来、占满屏幕」（用户要求）。
# 动画体拆到独立的 gate.css —— 门脸页（demo）与产品页演的是同一道门，
# 共用一份文件才不会各写一份然后慢慢漂移。
sec('8. 光之门动画（gate.css 单份源码）')

gate_css = css_files.get('gate.css', '')
check('gate.css 存在且非空', bool(gate_css.strip()))
check('gate.css 用的是光之门的新结构',
      all(k in gate_css for k in ('.gate__plane', '.gate__wash', '.gate__flash')))
check('旧的「黑幕合拢」结构已从 gate.css 移除',
      '.gate__panel' not in gate_css and '.gate__seam' not in gate_css)
check('base.css 里也不再留旧门转场规则',
      '.gate__panel' not in css_files.get('base.css', ''))
check('gate.css 降级块里 .gate 被 display:none',
      re.search(r'@media\s*\(prefers-reduced-motion:\s*reduce\)(.*?)\.gate\s*\{\s*display:\s*none',
                gate_css, re.S) is not None)
check('gate.css 的门缝是「加速」展开的（朝镜头冲，而不是退远）',
      re.search(r'cubic-bezier\([^)]*\.8[0-9][^)]*\)', gate_css) is not None)

for _fname in ('portal.html', 'login.html'):
    _src = html_files.get(_fname, '')
    check(f'{_fname} 引用了 gate.css', '/auth/static/gate.css' in _src)
    check(f'{_fname} 的门层用新结构',
          all(k in _src for k in ('gate__plane', 'gate__wash', 'gate__flash'))
          and 'gate__panel' not in _src and 'gate__seam' not in _src)


def _func_body(src, marker, nxt):
    """取某个函数体 —— 只为做时序断言，不做解析。"""
    i = src.find(marker)
    if i < 0:
        return ''
    j = src.find(nxt, i)
    return src[i:j] if j > 0 else src[i:i + 1200]


_pb = _func_body(portal_js, 'function gateClose', 'function gateOpen')
_lb = _func_body(login_js, 'function playGate', 'function say')


def _gate_ms(name):
    """从 gate.css 读一个时序变量（毫秒）。读不到返回 -1。"""
    m = re.search(r'--gate-%s:\s*([0-9]+)ms' % name, gate_css)
    return int(m.group(1)) if m else -1


# ── 门时序：唯一真源在 CSS 变量上，JS 只读不写 ────────────────────
# 2026-10-25 实测踩过的坑：早先是 CSS 写一份 transition、JS 写一份
# 430/100，改 CSS 的 transition 忘了改 JS ⇒ 门缝只张开 54% 就被闪白
# 吞掉，光潮没灌满，提示字只亮 100ms，「光冲过来」根本没冲过来。
# 所以现在断言的是**结构**：时序数字必须来自 CSS 变量，JS 里不许再写死。
_hold, _total = _gate_ms('hold'), _gate_ms('total')
_open, _wash = _gate_ms('open'), _gate_ms('wash')
_lbl_d, _lbl_f = _gate_ms('label-delay'), _gate_ms('label-fade')

check('gate.css 用 CSS 变量定义了门时序（--gate-hold / --gate-total）',
      _hold > 0 and _total > 0)
check('gate.css 门时序：hold < total（先落定闪白，再跳转）', 0 < _hold < _total)
check('gate.css 门时序：门缝张开 ≥ 400ms（要看得见「冲过来」）', _open >= 400)
check('gate.css 门时序：提示字在闪白之前就全亮（label-delay + fade ≤ hold）',
      0 < _lbl_d and 0 < _lbl_f and (_lbl_d + _lbl_f) <= _hold)
check('gate.css 门时序：提示字全亮后还留 ≥ 300ms 供阅读',
      _hold - (_lbl_d + _lbl_f) >= 300)

for _fname, _js, _body in (('portal.js', portal_js, _pb),
                           ('login.js', login_js, _lb)):
    check(f'{_fname} 门时序：settled 落定 + 时序取自 CSS 变量（不再写死 430）',
          "'settled'" in _body
          and 'gateHold()' in _body and 'gateTotal()' in _body
          and ', 430)' not in _body)
    check(f'{_fname} 读的是 gate.css 的 --gate-hold / --gate-total',
          '--gate-hold' in _js and '--gate-total' in _js)

# ── 9. 门脸页登录页：结构契约 ──────────────────────────────────
# 2026-10-25 登录页换成了门脸页（demo 的零构建手写移植）。
# 换的是**皮**，不是**骨**：端点、载荷、跳转防护一个字没动。
# 所以这里断言两件事：骨架还在（门脸页没退化回旧卡片），
# 以及该关着的还关着（流光不许溢出框外、状态不许写成内联样式）。
sec('9. 门脸页登录页结构契约')

login_html = html_files.get('login.html', '')
_base_css = css_files.get('base.css', '')

for _key, _desc in (
    ('df-brand', '品牌条'),
    ('df-ornament', '几何饰件（缓转的菱）'),
    ('pw-frame', '密码框边框盒'),
    ('pw-levels', '电平刻度'),
    ('pw-corner', '四角定位角标'),
    ('pw-sweep', '上沿流光'),
    ('pw-energy', '底沿能量条'),
):
    check(f'login.html 有{_desc}（.{_key}）', _key in login_html)

check('login.html 不再挂旧的卡片结构（.card / .brand）',
      'class="card"' not in login_html and 'class="brand"' not in login_html)
check('密码框仍是 type=password + autocomplete=current-password',
      'type="password"' in login_html
      and 'autocomplete="current-password"' in login_html)
check('电平刻度是 8 格', login_html.count('class="pw-lv"') == 8,
      f'实际 {login_html.count("class=\"pw-lv\"")} 格')
check('品牌条端口有默认值 :8443（真实网关默认端口）', ':8443' in login_html)
check('login.js 按实际端口改写端口号（location.port）',
      'location.port' in login_js)

# 门脸页的样式确实落在 base.css 里（而不是内联样式 —— CSP 也不允许）
for _key, _desc in (
    ('.pw-frame', '密码框边框盒'),
    ('.pw-sweep', '上沿流光'),
    ('.pw-energy', '底沿能量条'),
    ('.pw-corner', '四角角标'),
    ('.pw-lv', '电平刻度'),
    ('.df-ornament__gem', '几何饰件'),
):
    check(f'base.css 有{_desc}样式（{_key}）', _key in _base_css)

# ── 这一条是踩过的坑 ──────────────────────────────────────────
# 上沿流光是从框外扫进来的，不裁就会被画到框外面去（实测很丑）。
# 所以边框盒必须 overflow:hidden，而角标要留在**外层**才探得出边框。
check('边框盒裁切内容（上沿流光不许溢出框外）',
      re.search(r'\.pw-frame\s*\{[^}]*overflow:\s*hidden', _base_css) is not None)
check('聚焦态走 CSS 的 :focus-within（JS 不参与，JS 挂了也能用）',
      '.pw-field:focus-within' in _base_css)
check('角标在边框盒外层（.pw-field 里、.pw-frame 外）',
      re.search(r'\.pw-field:focus-within \.pw-corner', _base_css) is not None)

# ── 状态不许写成内联样式 ──────────────────────────────────────
# 判定前先剥掉注释：login.js 的注释里本身就写着「不依赖 querySelectorAll」，
# 不剥注释的话这条断言会被自己的说明文字绊倒（跟第 3 节处理 innerHTML 同理）。
_login_code = re.sub(r'/\*.*?\*/', '', login_js, flags=re.S)
_login_code = re.sub(r'//.*', '', _login_code)

check('login.js 不写内联样式（状态一律走 class）',
      not re.search(r'\.style\s*[.=]', _login_code)
      and 'setProperty' not in _login_code)
check('login.js 用 class 驱动校验中 / 出错 / 抖动三个态',
      all(k in login_js for k in ('is-busy', 'is-bad', 'is-shake')))
check('login.js 只用 getElementById + children（最小 DOM 桩里没有 querySelectorAll）',
      'querySelector' not in _login_code and 'getElementById' in _login_code)

print()
print(f'  合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
if FAIL:
    for name in FAIL:
        print(f'  ❌ {name}')
    sys.exit(1)
print('  全部通过')
