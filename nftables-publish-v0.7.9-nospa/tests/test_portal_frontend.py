"""门户改版（背景变体引擎 + 网格重排）的静态回归测试。

运行:  python3 tests/test_portal_frontend.py

覆盖 2026-11-02 落地的这一批前端改版，每条都写成「改回原样就必然失败」的形式：

  PF-1  门户页引用的静态文件都在 auth_gateway 的白名单里（**硬闸**）
  PF-2  白名单里的文件都真实存在（没有僵尸条目）
  PF-3  门户页引用的文件都真实存在
  PF-4  网格固定两列 + 窄屏单列（不是 auto-fill）
  PF-5  间距走 4px 基数 token
  PF-6  卡片内部改「名称与入口上下叠 + 状态右列」
  PF-7  登录页那一档背景参数一字未动（改版不外溢）
  PF-8  门户那一档背景参数齐（波速 / 晶向 / 快慢）
  PF-9  新增的方向参数默认值全为 0（不传时逐位一致）
  PF-10 变体引擎注册了 15 套方案，且 order 与变体表一致
  PF-11 每个变体都有生成逻辑；生长类变体都有 warm 预热
  PF-12 「白度渐变」钩子缺省仍是二值（不破坏先前的变体）
  PF-13 变体引擎接管背景时，原生引擎不再自己挂一次
  PF-14 脚本加载顺序正确
  PF-15 CSP 没有被放宽，页面不引外部资源
  PF-16 四个 JS 文件语法正确

不碰网络、不碰真实配置：全部是源码文本解析 + node --check 语法校验。
"""
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, 'backend', 'static')
BACKEND = os.path.join(ROOT, 'backend')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print('\n== ' + title)


def read(name, base=STATIC):
    with open(os.path.join(base, name), encoding='utf-8') as f:
        return f.read()


def has_file(name, base=STATIC):
    return os.path.isfile(os.path.join(base, name))


PORTAL_HTML = read('portal.html')
BASE_CSS = read('base.css')
PIXELFIELD = read('pixelfield.js')
PORTAL_JS = read('portal.js')
FX_JS = read('fx.js') if has_file('fx.js') else ''
SWITCHER_JS = read('switcher.js') if has_file('switcher.js') else ''
SWITCHER_CSS = read('switcher.css') if has_file('switcher.css') else ''
GATEWAY_PY = read('auth_gateway.py', base=BACKEND)


def table_body(src, var_name):
    """取出 `var X = { ... }` 这个表的**内部**内容。

    为什么不用正则找 `\n};` 收尾：JS 表里嵌着函数，函数体结尾也是 `};`，
    正则会在第一个嵌套函数处就截断，拿到的表只有半张
    （实测 VARIANTS 表被截在第 1 个变体里）。
    ⇒ 这里做**括号配平**，并跳过注释和字符串 ——
      否则注释里的「⇒」和字符串里的 '{' 都会把配平算歪。
    """
    m = re.search(r'var ' + re.escape(var_name) + r'\s*=\s*\{', src)
    if not m:
        return ''
    i = m.end() - 1          # 指向 '{'
    depth = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            i = n if j < 0 else j
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in ('"', "'", '`'):
            q = c
            i += 1
            while i < n:
                if src[i] == '\\':
                    i += 2
                    continue
                if src[i] == q:
                    break
                i += 1
            i += 1
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return src[m.end():i]
        i += 1
    return ''


def entry_block(body, key):
    """取出表里某个键的整段定义（到下一个同级键为止）。"""
    m = re.search(r"^[ \t]{4}['\"]?" + re.escape(key) + r"['\"]?[ \t]*:[ \t]*\{", body, re.M)
    if not m:
        return ''
    nxt = re.search(r"^[ \t]{4}['\"]?[\w-]+['\"]?[ \t]*:[ \t]*\{", body[m.end():], re.M)
    end = m.end() + (nxt.start() if nxt else len(body) - m.end())
    return body[m.start():end]


STYLES_BODY = table_body(PIXELFIELD, 'STYLES')
PARAMS_BODY = table_body(PIXELFIELD, 'P')
# 变体分两张表：VARIANTS 是第一批（7 个「有语义的界面元素」），
# GEN_VARIANTS 是第二批（8 个「像素生成方案」），运行时并进 VARIANTS。
# 断言要两张表一起看 —— 只看其中一张会以为变体少了 8 个。
VARIANTS_BODY = table_body(FX_JS, 'VARIANTS') + '\n' + table_body(FX_JS, 'GEN_VARIANTS')

# ─────────────────────────────────────────────────────────────
sec('PF-1  门户页引用的静态文件都在认证网关白名单里')

refs = re.findall(r'(?:href|src)="\{\{STATIC_BASE\}\}([^"]+)"', PORTAL_HTML)
m = re.search(r'STATIC_ALLOWED\s*=\s*frozenset\(\{(.*?)\}\)', GATEWAY_PY, re.S)
allowed = set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()

check('门户页确实引用了静态文件（否则这一节没意义）',
      len(refs) >= 4, f'共 {len(refs)} 处引用')
check('白名单能被解析出来', bool(allowed), f'{len(allowed)} 个条目')
hrefs = re.findall(r'(?:href|src)="([^"]+)"', PORTAL_HTML)
hardcoded = [h for h in hrefs if h.startswith('/auth/static/') or h.startswith('/static/')]
check('门户页用的是静态基址占位符（谁提供页面谁注入前缀）',
      all(h.startswith('{{STATIC_BASE}}') for h in hrefs) and not hardcoded,
      '写死了前缀: ' + ', '.join(hardcoded) if hardcoded
      else f'{len(hrefs)} 处引用全部走占位符')

missing = [r for r in sorted(set(refs)) if r not in allowed]
check('门户页引用的每个文件都在 STATIC_ALLOWED 里',
      not missing,
      '缺白名单: ' + ', '.join(missing) if missing else f'{len(set(refs))} 个引用全部有白名单')

check('新增的三个文件都在白名单里',
      all(f in allowed for f in ('fx.js', 'switcher.css', 'switcher.js')),
      'fx.js / switcher.css / switcher.js')

# ─────────────────────────────────────────────────────────────
sec('PF-2  白名单里没有僵尸条目（列了但文件不在）')

zombies = [a for a in sorted(allowed) if not has_file(a)]
check('白名单里的每个文件都真实存在', not zombies,
      '僵尸条目: ' + ', '.join(zombies) if zombies else f'{len(allowed)} 个条目全部有对应文件')

# ─────────────────────────────────────────────────────────────
sec('PF-3  门户页引用的文件都真实存在')

gone = [r for r in sorted(set(refs)) if not has_file(r)]
check('门户页引用的每个文件都在 static 目录里', not gone,
      '缺文件: ' + ', '.join(gone) if gone else f'{len(set(refs))} 个引用全部存在')

# ─────────────────────────────────────────────────────────────
sec('PF-3b 认证服务会把占位符换成真实前缀')

check('auth_gateway 里定义了占位符常量',
      re.search(r"PORTAL_STATIC_BASE\s*=\s*'\{\{STATIC_BASE\}\}'", GATEWAY_PY) is not None)
check('有把占位符替换掉的逻辑',
      re.search(r'\.replace\(\s*PORTAL_STATIC_BASE', GATEWAY_PY) is not None)
check('认证服务这一侧注入的是 /auth/static/',
      re.search(r"_read_portal_html\('/auth/static/'\)", GATEWAY_PY) is not None,
      '认证服务提供的门户页，资源必须走 /auth/static/（白名单同源）')
check('_read_portal_html 的**默认**基址也是 /auth/static/',
      re.search(r"def _read_portal_html\(static_base='/auth/static/'\)", GATEWAY_PY) is not None,
      '默认参数走的是 /auth/static/portal.html 直达路径 —— 改成 /static/ '
      '会让那条路径上的资源全变死链')
pm = re.search(r'def portal_page\(\):(.*?)(?=\n@app\.route|\ndef )', GATEWAY_PY, re.S)
check('门户页路由不再直接发原文件（否则占位符不会被替换）',
      pm is not None and 'send_from_directory' not in pm.group(1),
      '门户页必须经 _read_portal_html() 注入前缀')

# ─────────────────────────────────────────────────────────────
sec('PF-4  网格固定两列 + 窄屏单列')

grid_block = re.search(r'\.grid\s*\{(.*?)\}', BASE_CSS, re.S)
check('.grid 规则能定位到', grid_block is not None)
gb = grid_block.group(1) if grid_block else ''
check('桌面端是固定两列 repeat(2, minmax(0, 1fr))',
      'repeat(2, minmax(0, 1fr))' in gb, gb.strip()[:80])
check('不再用 auto-fill 自动列（那会把名字截断成「思源…」）',
      'auto-fill' not in gb)
check('网格间距走间距 token', 'gap: var(--sp-4)' in gb)

mq = re.search(r'@media \(max-width: 640px\)\s*\{(.*?)\n\}', BASE_CSS, re.S)
check('有 640px 窄屏断点', mq is not None)
mbody = mq.group(1) if mq else ''
check('窄屏改单列 minmax(0, 1fr)', 'grid-template-columns: minmax(0, 1fr)' in mbody)
check('窄屏网格间距走 token', 'gap: var(--sp-3)' in mbody)

# ─────────────────────────────────────────────────────────────
sec('PF-5  间距走 4px 基数 token')

for i in (1, 2, 3, 4, 5, 6, 8, 10, 12):
    check(f'--sp-{i} 已定义', re.search(r'--sp-%d:\s*\d+px' % i, BASE_CSS) is not None)
check('间距刻度是 4 的倍数',
      all(int(x) % 4 == 0 for x in re.findall(r'--sp-\d+:\s*(\d+)px', BASE_CSS)))

# ─────────────────────────────────────────────────────────────
sec('PF-6  卡片内部：名称与入口上下叠 + 状态右列')

tile_block = re.search(r'\.tile\s*\{(.*?)\n\}', BASE_CSS, re.S)
tb = tile_block.group(1) if tile_block else ''
check('网格区域是「ico nm tag / ico pt .」',
      '"ico nm tag"' in tb and '"ico pt ."' in tb)
check('状态徽章右对齐（justify-self: end）',
      re.search(r'\.tag\s*\{[^}]*justify-self:\s*end', BASE_CSS) is not None)
check('入口路径不再被 max-width 砍成「/…」',
      re.search(r'\.tile\s+\.pt\s*\{[^}]*max-width', BASE_CSS) is None)

# ─────────────────────────────────────────────────────────────
sec('PF-7  登录页那一档背景参数一字未动（改版不外溢）')

moon = entry_block(STYLES_BODY, 'moonstone')
check('moonstone 档存在（且取的是 STYLES 表里的那一档）', bool(moon))
oms = re.findall(r'om:\s*([0-9.]+)', moon)
check('moonstone 的波速仍是原版（登录页视觉零变化）',
      oms[:3] == ['0.504', '0.563', '0.454'], f'实测 {oms[:3]}')
check('moonstone 档没有被塞进方向随机化参数',
      'patchRot1' not in moon and 'patchSpin' not in moon)

# ─────────────────────────────────────────────────────────────
sec('PF-8  门户那一档背景参数齐')

swirl = entry_block(STYLES_BODY, 'moonstone-swirl')
check('moonstone-swirl 档存在', bool(swirl))
for name, val in (('patchRot1', '0.22'), ('patchRot2', '0.88'), ('patchSpin', '0.020'),
                  ('dirSwing', '0.13'), ('dirSwingFreq', '0.065'),
                  ('patchDrift', '0.030'), ('trail', '0.72'), ('hyst', '0.05'),
                  ('lit', '0.15')):
    check(f'moonstone-swirl 的 {name} = {val}',
          re.search(re.escape(name) + r':\s*' + re.escape(val), swirl) is not None)
soms = re.findall(r'om:\s*([0-9.]+)', swirl)
check('门户这一档波速约 ×1.9（0.504 → 0.958）',
      soms[:3] == ['0.958', '1.070', '0.863'], f'实测 {soms[:3]}')

# ─────────────────────────────────────────────────────────────
sec('PF-9  新增的方向参数默认值全为 0（不传时逐位一致）')

for name in ('patchRot1', 'patchRot2', 'patchSpin', 'dirSwing', 'dirSwingFreq'):
    m2 = re.search(r'^\s+' + name + r':\s*([0-9.]+),', PARAMS_BODY, re.M)
    check(f'引擎默认参数 {name} = 0', m2 is not None and float(m2.group(1)) == 0.0,
          f'实测 {m2.group(1) if m2 else "没找到"}')

check('方向摆动的 sin/cos 用双精度存（Float32 会丢末位 ⇒ 破坏「逐位一致」）',
      'new Float64Array(8)' in PIXELFIELD and 'new Float32Array(8)' not in PIXELFIELD)

# ─────────────────────────────────────────────────────────────
sec('PF-10 变体引擎注册了 15 套方案')

check('fx.js 存在', bool(FX_JS))
check('VARIANTS 表能定位到', bool(VARIANTS_BODY))
keys = re.findall(r"^[ \t]{4}['\"]?([\w-]+)['\"]?[ \t]*:[ \t]*\{", VARIANTS_BODY, re.M)
check('变体数量是 15', len(keys) == 15, f'实测 {len(keys)}：{keys}')
check('变体 key 不重复', len(keys) == len(set(keys)))

om = re.search(r'order:\s*\[(.*?)\]', FX_JS, re.S)
order = re.findall(r"'([^']+)'", om.group(1)) if om else []
check('order 数组长度与变体数一致', len(order) == len(keys), f'order {len(order)} 个')
check('order 覆盖全部变体', set(order) == set(keys),
      '差集: ' + str(set(order) ^ set(keys)))

# ─────────────────────────────────────────────────────────────
sec('PF-11 每个变体都有生成逻辑；生长类变体有 warm 预热')

for k in keys:
    if k == 'pixelfield':
        continue
    check(f'变体 {k} 有 update 逻辑', 'update:' in entry_block(VARIANTS_BODY, k))

warm_defs = re.findall(r'warm:\s*(\d+)', VARIANTS_BODY)
check('生长类变体定义了 warm 预热帧数', len(warm_defs) >= 8, f'{len(warm_defs)} 个变体有 warm')
check('预热是真的空跑了 update',
      re.search(r'for \(var i = 0; i < warm; i\+\+\)\s*def\.update', FX_JS) is not None,
      '降级动效只画一帧，没有预热 ⇒ 像素还没长出来就是黑屏')

# ─────────────────────────────────────────────────────────────
sec('PF-12 「白度渐变」钩子缺省仍是二值')

check('paint 里有 tint 钩子', 'def.tint' in FX_JS)
check('没有 tint 时走二值分支（浪身/浪尖）',
      re.search(r'var w = tint \? tint\(.*\) : \(this\.crest\[i\] \? 1 : 0\);', FX_JS) is not None)

# ─────────────────────────────────────────────────────────────
sec('PF-13 变体引擎接管时，原生引擎不再自己挂一次')

check('portal.js 有 GhostFX 守卫',
      re.search(r'if \(window\.GhostFX\)\s*return;', PORTAL_JS) is not None,
      '两个引擎抢同一个 canvas 会互相覆盖')
check('portal.js 的降级路径用 moonstone-swirl（与变体引擎同一档）',
      "'moonstone-swirl'" in PORTAL_JS)
check('portal.js 不再单独用 moonstone 那档',
      re.search(r"createStyle\(canvas,\s*'moonstone'", PORTAL_JS) is None)

# ─────────────────────────────────────────────────────────────
sec('PF-14 脚本加载顺序正确')

i_fx = PORTAL_HTML.find('{{STATIC_BASE}}fx.js')
i_pj = PORTAL_HTML.find('{{STATIC_BASE}}portal.js')
i_sw = PORTAL_HTML.find('{{STATIC_BASE}}switcher.js')
check('三个脚本都引用了', -1 not in (i_fx, i_pj, i_sw))
check('fx.js 在 portal.js 之前（portal.js 要看到 window.GhostFX）',
      0 <= i_fx < i_pj, f'fx {i_fx} / portal {i_pj}')
check('switcher.js 在 portal.js 之后（它要接管挂载）',
      0 <= i_pj < i_sw, f'portal {i_pj} / switcher {i_sw}')

# ─────────────────────────────────────────────────────────────
sec('PF-15 CSP 没被放宽，页面不引外部资源')

m3 = re.search(r'CSP_PORTAL_HTML\s*=\s*\((.*?)\)\n', GATEWAY_PY, re.S)
csp = m3.group(1) if m3 else ''
# CSP 在源码里是几段字符串字面量拼接的，要拼起来才是**实际生效的头值**。
csp_value = ''.join(re.findall(r'"([^"]*)"', csp))
check('CSP 仍是 default-src \'none\'', "default-src 'none'" in csp)
check('CSP 仍只允许同源脚本', "script-src 'self'" in csp)
check('CSP 仍只允许同源样式', "style-src 'self'" in csp)
check('门户页不引外部资源',
      'http://' not in PORTAL_HTML and 'https://' not in PORTAL_HTML)
for f in ('fx.js', 'switcher.js', 'switcher.css'):
    src = read(f)
    check(f'{f} 不引外部资源',
          'http://' not in src and 'https://' not in src)

# ⚠️ 上面几条只查「包含」，CSP 被**放宽**（比如加上 'unsafe-inline'）
#    之后这三条依然成立 —— 所以下面必须**逐字比对**，
#    否则「CSP 被放宽」这个退化没人守。
EXPECTED_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; "
    "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
)
check('门户页 CSP 与预期**逐字一致**（任何放宽都会红）',
      ' '.join(csp_value.split()) == EXPECTED_CSP,
      '实测: ' + ' '.join(csp_value.split()))
check('CSP 不含 unsafe-inline', 'unsafe-inline' not in csp_value)
check('CSP 不含 unsafe-eval', 'unsafe-eval' not in csp_value)

# ─────────────────────────────────────────────────────────────
sec('PF-16 四个 JS 文件语法正确')

node = shutil.which('node') or '/tmp/node-v22.23.4-linux-x64/bin/node'
if os.path.isfile(node) or shutil.which(node):
    for f in ('fx.js', 'switcher.js', 'portal.js', 'pixelfield.js'):
        r = subprocess.run([node, '--check', os.path.join(STATIC, f)],
                           capture_output=True, text=True)
        check(f'{f} 通过 node --check', r.returncode == 0,
              (r.stderr or '').strip().splitlines()[0] if r.returncode else '')
else:
    print('  [跳过] 没找到 node，语法检查未执行')

# ─────────────────────────────────────────────────────────────
sec('PF-17 页面里没有内联脚本 / 内联样式 / on* 事件属性')

# 真机 CSP 是 script-src 'self'; style-src 'self' —— 内联脚本和内联样式
# 都会被浏览器直接拦掉（表现为「按钮没反应」「样式没生效」），
# 而且 'unsafe-inline' 一旦被加进 CSP 就是 XSS 的口子。
check('门户页没有内联 <script> 块',
      re.search(r'<script(?![^>]*\bsrc=)', PORTAL_HTML, re.I) is None)
check('门户页没有 style= 属性',
      re.search(r'\sstyle\s*=', PORTAL_HTML, re.I) is None)
check('门户页没有 on* 事件属性',
      re.search(r'\son[a-z]+\s*=', PORTAL_HTML, re.I) is None)
for f in ('fx.js', 'switcher.js', 'portal.js'):
    src = read(f)
    check(f'{f} 不拼 innerHTML（防 XSS）',
          not re.search(r'\.innerHTML\s*=', src) and
          not re.search(r'\.outerHTML\s*=', src))
    check(f'{f} 不写内联 style 属性（用 class 驱动）',
          not re.search(r'\.style\s*\.\s*(?!setProperty)', src) and
          not re.search(r'\.setAttribute\(\s*[\'"]style', src))

# ─────────────────────────────────────────────────────────────
sec('PF-18 门户页该引的都引了')

for need in ('base.css', 'gate.css', 'switcher.css',
             'fingerprint.js', 'pixelfield.js', 'fx.js', 'portal.js', 'switcher.js'):
    check(f'门户页引用了 {need}', need in refs,
          '漏引 ⇒ 那部分功能直接消失，而且页面还能正常打开（很难一眼看出）')

print()
if FAIL:
    print(f'失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
