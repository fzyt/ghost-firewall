"""门户改版（网格重排 + 像素场随机方向波浪）的静态回归测试。

运行:  python3 tests/test_portal_frontend.py

覆盖 2026-11-02 落地的这一批前端改版，每条都写成「改回原样就必然失败」的形式：

  PF-1  门户页引用的静态文件都在 auth_gateway 的白名单里（**硬闸**）
  PF-2  白名单里的文件都真实存在（没有僵尸条目）
  PF-3  门户页引用的文件都真实存在
  PF-4  网格固定两列 + 窄屏单列（不是 auto-fill）
  PF-5  间距走 4px 基数 token
  PF-6  卡片内部改「名称与入口上下叠 + 状态右列」
  PF-7  登录页那一档背景参数一字未动（改版不外溢）
  PF-8  门户那一档（moonstone-flow）背景参数齐
  PF-8b moonstone-flow 与原版 moonstone 的差别**只有方向**
  PF-9  新增的方向参数默认值全为 0（不传时逐位一致）
  PF-10 随机方向波浪：方向场是**共享**的一张（不是每道波一张）
  PF-11 分片遮罩晶向跟随局部波向（亮块沿波前拉成长条）
  PF-12 像素块尺寸可配（0 = 原版 2px/3px，新档用 9×9 方块）
  PF-13 14 套变体引擎与切换器**已彻底删除**（文件、引用、白名单、守卫）
  PF-14 门户页的脚本加载顺序正确
  PF-15 CSP 没有被放宽，页面不引外部资源
  PF-16 JS 文件语法正确
  PF-17 页面里没有内联脚本 / 内联样式 / on* 事件属性
  PF-18 门户页该引的都引了
  PF-19 方向游走走「平滑解析式」（不是噪声切片）
  PF-20 方向场绕画布中心转（不是绕左上角）

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


# ─────────────────────────────────────────────────────────────
# 注释剥离器
#
# 为什么需要（实测踩坑）：
#   本项目的风格是「注释密度高」——注释里写满了 'moonstone-swirl'、
#   'fx.js'、'https://siyuan.fzyto.top:8443/' 这类词条。
#   如果「某东西不该出现」这类断言直接对**原文**做子串判断，
#   注释会把它假红掉：
#     · portal.html 注释写着「（fx.js + switcher.*）已按用户要求全部删掉」
#       ⇒ 「门户页不再引用 fx.js」误报失败
#     · portal.js 注释写着「'moonstone-swirl'（旧那档）仍在引擎里」
#       ⇒ 「portal.js 不再用 moonstone-swirl」误报失败
#     · portal.js 注释举了个跨域例子 https://siyuan.fzyto.top:8443/
#       ⇒ 「portal.js 不引外部资源」误报失败
#
# ⇒ 凡是「这个东西不该出现」的判断，一律先剥注释再比对。
#
# ⚠️ 剥注释**必须区分注释和字符串字面量**：
#   字符串里的 'https://x' 是真的外链（要红），
#   注释里的 'https://x' 只是说明文字（要忽略）。
#   所以下面用状态机逐字符走，遇到引号就整段原样保留。
# ─────────────────────────────────────────────────────────────


def strip_html_comments(src):
    """去掉 HTML 注释（<!-- ... -->），其余原样保留。"""
    return re.sub(r'<!--.*?-->', '', src, flags=re.S)


# 正则字面量可能出现在「= ( 」等字符之后 —— 见到这种 '/' 不能当除号，
# 更不能当注释起始。portal.js 里就有 path.match(/[A-Za-z0-9一-龥]/) 这种。
_REGEX_PREV = set('(,=:[!&|?{};+-*%~^<>\n')


def strip_js_comments(src):
    """去掉 JS 注释，保留字符串/模板串/正则字面量的**原文**。

    状态机逐字符走：
      · //  → 行注释，直接跳到行尾
      · /*  → 块注释，跳到 */
      · 引号 → 整段字符串原样输出（含转义）
      · '/' 且前一个非空白字符像正则起始 → 当正则字面量，整段原样输出
    """
    out = []
    i, n = 0, len(src)
    prev = ''          # 上一个**非空白**的输出字符
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
        if c == '/' and (prev == '' or prev in _REGEX_PREV):
            # 正则字面量：找到未转义且不在 [...] 内的 '/' 作为结束
            j = i + 1
            in_cls = False
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src[j] == '[':
                    in_cls = True
                elif src[j] == ']':
                    in_cls = False
                elif src[j] == '/' and not in_cls:
                    break
                elif src[j] == '\n':
                    break
                j += 1
            seg = src[i:min(j + 1, n)]
            out.append(seg)
            prev = '/'
            i = min(j + 1, n)
            continue
        if c in ('"', "'", '`'):
            q = c
            out.append(c)
            i += 1
            while i < n:
                if src[i] == '\\' and i + 1 < n:
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                out.append(src[i])
                if src[i] == q:
                    i += 1
                    break
                i += 1
            prev = q
            continue
        out.append(c)
        if not c.isspace():
            prev = c
        i += 1
    return ''.join(out)


PORTAL_HTML = read('portal.html')
BASE_CSS = read('base.css')
PIXELFIELD = read('pixelfield.js')
PORTAL_JS = read('portal.js')
FINGERPRINT_JS = read('fingerprint.js')
GATEWAY_PY = read('auth_gateway.py', base=BACKEND)

# 「这东西不该出现」类断言一律用剥掉注释的版本（见上面 strip_js_comments 的说明）
PORTAL_HTML_CODE = strip_html_comments(PORTAL_HTML)
PORTAL_JS_CODE = strip_js_comments(PORTAL_JS)
PIXELFIELD_CODE = strip_js_comments(PIXELFIELD)
FINGERPRINT_JS_CODE = strip_js_comments(FINGERPRINT_JS)

# 2026-11-02：14 套变体引擎 + 切换器已删除。
# 这里**故意不读** fx.js / switcher.* ——
# 文件要是还在，下面 PF-13 会直接红（那才是真正的守门）。
REMOVED_FILES = ('fx.js', 'switcher.css', 'switcher.js')


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

check('白名单里**没有**已删除的变体文件（列了但文件没了 ⇒ 僵尸条目）',
      not any(f in allowed for f in REMOVED_FILES),
      '仍在白名单: ' + ', '.join(f for f in REMOVED_FILES if f in allowed)
      if any(f in allowed for f in REMOVED_FILES) else 'fx.js / switcher.* 已不在白名单')

check('白名单只包含门户页真正需要的文件（不多不少）',
      allowed == {'base.css', 'fingerprint.js', 'login.html', 'login.js',
                  'portal.html', 'portal.js', 'pixelfield.js', 'gate.css'},
      '实际: ' + ', '.join(sorted(allowed)))
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
sec('PF-8  门户那一档（moonstone-flow）背景参数齐')

flow = entry_block(STYLES_BODY, 'moonstone-flow')
check('moonstone-flow 档存在', bool(flow))
for name, val in (('dirField', '1'), ('dirFieldBase', '-0.30'),
                  ('dirFieldRange', '1.50'), ('dirWalkFreq', '0.010'),
                  ('dirWalkSmooth', '1'), ('dirPivot', '1'),
                  ('distortAmp', '0.85'), ('lit', '0.12')):
    check(f'moonstone-flow 的 {name} = {val}',
          re.search(re.escape(name) + r':\s*' + re.escape(val), flow) is not None)

# ⚠️ 该守的不是单个值，是**乘积**。
#   ω 峰值 ≈ 摆幅 × 2π × 频率（rad/s）——
#   摆幅翻倍会把转速也带上，只看其中一个数就会被骗：
#     · 只看摆幅上限 ⇒ 允许「摆幅大 + 频率高」⇒ 画面在抖不是在流；
#     · 只看频率上限 ⇒ 允许「摆幅巨大 + 频率低」⇒ 方向半天转一下，像卡顿。
#   原版 dirSwing 的 ω 峰值 = 0.053 rad/s、平均 0.037 rad/s，
#   实测本档 120 秒平均 0.032 rad/s ⇒ **比原版还慢**，但方向偏得远得多
#   （60 秒偏 34°、120 秒偏 111°；原版 dirSwing 一共才 ±7.4° 往复）。
dwf = re.search(r'dirWalkFreq:\s*([0-9.]+)', flow)
dfr = re.search(r'dirFieldRange:\s*([0-9.]+)', flow)
check('moonstone-flow 写了 dirWalkFreq 与 dirFieldRange',
      dwf is not None and dfr is not None,
      f'实测 freq={dwf.group(1) if dwf else "没找到"} / range={dfr.group(1) if dfr else "没找到"}')
if dwf and dfr:
    prod = float(dfr.group(1)) * float(dwf.group(1))
    check('moonstone-flow 的 摆幅 × 频率 ≤ 0.016（角速度不能超过原版的 ~1.8 倍）',
          prod <= 0.016, f'实测乘积 {prod:.5f} ⇒ ω 峰值 {prod * 6.2831853:.4f} rad/s')
    check('moonstone-flow 的 dirFieldRange ≥ 1.2（方向必须真的在换，才不是原版）',
          float(dfr.group(1)) >= 1.2, f'实测 {dfr.group(1)}')
else:
    check('moonstone-flow 的 摆幅 × 频率 ≤ 0.016（角速度不能超过原版的 ~1.8 倍）', False)
    check('moonstone-flow 的 dirFieldRange ≥ 1.2（方向必须真的在换，才不是原版）', False)

# ─────────────────────────────────────────────────────────────
sec('PF-8b moonstone-flow 与原版 moonstone 的差别**只有方向**')

# 这一批改动的全部意义就在这一条上：
#   用户要的是「原版那种固定方向流动的**随机版**」——
#   所以几何（波速、波长、相位、扭曲、遮罩、余晖、像素尺寸、密度）
#   必须与原版 moonstone **逐条一致**，只有「方向」这一项变了。
# 任何一项被顺手改掉，观感就会滑回「被否掉的那一版」。
WAVE_RE = re.compile(r'\{\s*k:\s*([0-9.]+),\s*om:\s*([0-9.]+),\s*off:\s*([0-9.]+),'
                      r'\s*dir:\s*(-?[0-9.]+),\s*w:\s*([0-9.]+)\s*\}')

moon_waves = WAVE_RE.findall(moon)
flow_waves = WAVE_RE.findall(flow)
check('两档都是 3 道波', len(moon_waves) == 3 and len(flow_waves) == 3,
      f'原版 {len(moon_waves)} 道 / 新档 {len(flow_waves)} 道')
if len(moon_waves) == 3 and len(flow_waves) == 3:
    for i, (a, b) in enumerate(zip(moon_waves, flow_waves)):
        check(f'第 {i+1} 道波的 k / om / off / w 与原版逐条一致',
              a[0] == b[0] and a[1] == b[1] and a[2] == b[2] and a[4] == b[4],
              f'原版 {a} / 新档 {b}')
        # dir 的语义变了：原版是绝对角，新档是「相对基准角 -0.30 的偏角」。
        # 两者必须严格差一个基准角 ⇒ 换向时几道波的相对夹角一字未改。
        check(f'第 {i+1} 道波的 dir 正好是原版绝对角减去基准角',
              abs((float(a[3]) - (-0.30)) - float(b[3])) < 1e-9,
              f'原版 {a[3]} → 应为 {float(a[3]) + 0.30:.2f}，实测 {b[3]}')

# 不得带进任何「让画面变成一块块纹理」的参数 —— 那些正是被否掉的那一版的成因。
for bad in ('patchFollow', 'pxBody', 'pxCrest', 'pickBlock',
            'patchRot1', 'patchRot2', 'patchSpin', 'dirSwing'):
    check(f'moonstone-flow 不带 {bad}（那是被否掉的「一块一块生成」的成因）',
          re.search(r'^\s+' + bad + r':', flow, re.M) is None)

# 遮罩漂移 / 余晖 / 迟滞必须保持引擎原值（**不写** = 用默认，写了就等于改了原版）。
for inherited in ('patchDrift', 'trail', 'hyst', 'patchScale',
                  'patchA1', 'patchA2', 'edge0', 'edge1'):
    check(f'moonstone-flow 不覆盖 {inherited}（保持引擎原版默认值）',
          re.search(r'^\s+' + inherited + r':', flow, re.M) is None)

# 门户页不该再传 lit —— opt.params 会**盖掉**样式里的同名参数，
# 两边都写就会出现「改了样式没生效」这类查不出来的坑。
check('portal.js 不再自己传 lit（lit 由档位说了算）',
      'lit:' not in PORTAL_JS_CODE)
check('moonstone-flow 的 lit = 0.12（与改版前的 moonstone 一致）',
      re.search(r'lit:\s*0\.12', flow) is not None)

sec('PF-9  新增的方向参数默认值全为 0（不传时逐位一致）')

for name in ('patchRot1', 'patchRot2', 'patchSpin', 'dirSwing', 'dirSwingFreq',
             'dirField', 'dirFieldBase', 'dirFieldScale', 'dirFieldRange',
             'dirFieldDrift', 'dirWalkFreq', 'dirWalkSmooth', 'dirPivot',
             'patchFollow', 'pxBody', 'pxCrest', 'pickBlock'):
    m2 = re.search(r'^\s+' + name + r':\s*([0-9.]+),', PARAMS_BODY, re.M)
    check(f'引擎默认参数 {name} = 0', m2 is not None and float(m2.group(1)) == 0.0,
          f'实测 {m2.group(1) if m2 else "没找到"}')

# 这几个是**倍率**，1.0 才是中性值（0 会把遮罩压成一条线）
for name in ('patchTangent', 'patchNormal', 'patchTangent2', 'patchNormal2'):
    m2 = re.search(r'^\s+' + name + r':\s*([0-9.]+),', PARAMS_BODY, re.M)
    check(f'引擎默认参数 {name} = 1.0（中性倍率）',
          m2 is not None and float(m2.group(1)) == 1.0,
          f'实测 {m2.group(1) if m2 else "没找到"}')

check('方向摆动的 sin/cos 用双精度存（Float32 会丢末位 ⇒ 破坏「逐位一致」）',
      'new Float64Array(8)' in PIXELFIELD and 'new Float32Array(8)' not in PIXELFIELD)

# 方向场的**步长**不是开关 —— 它没有「关闭」语义（关开关的是 dirField）。
# 所以它的默认值不能是 0：0 会让粗网格退化成 1×1，方向场变成常数。
m2 = re.search(r'^\s+dirFieldStep:\s*([0-9.]+),', PARAMS_BODY, re.M)
check('引擎默认参数 dirFieldStep = 24（步长不是开关，不能是 0）',
      m2 is not None and float(m2.group(1)) == 24.0,
      f'实测 {m2.group(1) if m2 else "没找到"}')

# ─────────────────────────────────────────────────────────────
sec('PF-10 随机方向波浪：方向场是**共享**的一张')

check('有 ensureDirField()（方向场按需分配）',
      'function ensureDirField()' in PIXELFIELD)
check('方向场只按网格大小分配一次（dirFW * dirFH，不是 × 波数）',
      re.search(r'dirSin\s*=\s*new Float32Array\(dirFW \* dirFH\);', PIXELFIELD) is not None,
      '每道波各一张 ⇒ 遮罩拉长方向在相邻格跳变 ⇒ 拉长互相抵消 ⇒ 又是散点')
check('方向场是共享的（每波只带一个偏角）',
      'wOffC' in PIXELFIELD and 'wOffS' in PIXELFIELD)
check('逐格按偏角旋转共享方向',
      re.search(r'wsn\s*=\s*fs\s*\*\s*wOffC\[wi2\]\s*\+\s*fc\s*\*\s*wOffS\[wi2\]',
                PIXELFIELD) is not None)
check('方向场分量插值后归一化（不归一化 ⇒ 模长随插值位置变 ⇒ 方向会飘）',
      re.search(r'var mm = Math\.sqrt\(sA \* sA \+ cA \* cA\);', PIXELFIELD) is not None)

# ─────────────────────────────────────────────────────────────
sec('PF-11 分片遮罩晶向跟随局部波向')

check('引擎里有 patchFollow 开关', 'p.patchFollow > 0' in PIXELFIELD)
check('遮罩采样坐标转进了波帧（切向 / 法向）',
      re.search(r'var tanX = px \* fc - py \* fs;', PIXELFIELD) is not None and
      re.search(r'var norX = px \* fs \+ py \* fc;', PIXELFIELD) is not None)
check('切向低频 / 法向高频（沿波前拉长）',
      re.search(r'tanX \* p\.patchScale \* p\.patchTangent', PIXELFIELD) is not None and
      re.search(r'norX \* p\.patchScale \* p\.patchNormal', PIXELFIELD) is not None)
check('关掉时走原来的屏幕空间路径（逐位一致）',
      re.search(r'u1x \* c1 - u1y \* s1 \+ tq \* p\.patchDrift', PIXELFIELD) is not None)

# ─────────────────────────────────────────────────────────────
sec('PF-12 像素块尺寸可配')

check('有 pxBody / pxCrest 两个参数',
      re.search(r'^\s+pxBody:\s*0,', PARAMS_BODY, re.M) is not None and
      re.search(r'^\s+pxCrest:\s*0,', PARAMS_BODY, re.M) is not None)
check('渲染层用参数决定方块边长（0 = 原版 2/3）',
      re.search(r'var b1s = p\.pxBody > 0 \? Math\.min\(SS, p\.pxBody \| 0\) : 2;',
                PIXELFIELD) is not None and
      re.search(r'var b2s = p\.pxCrest > 0 \? Math\.min\(SS, p\.pxCrest \| 0\) : 3;',
                PIXELFIELD) is not None)

# ─────────────────────────────────────────────────────────────
sec('PF-12b 块状选取（亮区是实心小方块，不是雪花点）')

# 为什么需要它（2026-11-02 实测，踩了三次坑才定位到）：
#   原版的选取门槛 rSel 是**每格独立**的随机数 ⇒ 任何一条光带
#   都被打成等密度的雪花点 ⇒ 屏幕上根本读不出「一条浪」，
#   只剩「一块一块各自生成」。
#   试过三条路，全都无效：
#     ① 调 pickSoft（软门宽度）—— 无效，pickGain 是**自适应**的
#        （引擎按 lit 目标自动增减），pickSoft 抬高多少它压回去多少；
#     ② 调遮罩阈值 patchA1/A2 —— 无效，只会把点阵变得更均匀（电视雪花）；
#     ③ 调波参数 —— 无效，点阵密度由选取机制决定，跟波无关。
#   ⇒ 唯一出路是让**相邻格的亮灭决策相关**：同一块共用一个门槛。
check('引擎有 pickBlock 开关',
      re.search(r'^\s+pickBlock:\s*0,', PARAMS_BODY, re.M) is not None)
check('门槛按块共享（si = 块索引，而不是逐格索引）',
      re.search(r'var pb = p\.pickBlock \| 0;', PIXELFIELD) is not None and
      re.search(r'si = bx \* 8191 \+ by;', PIXELFIELD) is not None)
check('pickBlock=0 时走逐格随机分支（逐位一致的保证没被破坏）',
      re.search(r'if \(pb > 0\) \{', PIXELFIELD) is not None and
      'rSel[i] = rnd(si, 1013904223);' in PIXELFIELD)
check('块索引用素数行距 8191（避免 (bx,by) 撞成同一个索引）',
      re.search(r'bx \* 8191 \+ by', PIXELFIELD) is not None)

# ─────────────────────────────────────────────────────────────
sec('PF-13 14 套变体引擎与切换器已彻底删除')

for f in REMOVED_FILES:
    check(f'{f} 文件已删除', not has_file(f), '还在 ⇒ 变体方案没砍干净')
    # ⚠️ 用剥掉注释的 HTML 判：注释里写「已删掉 fx.js」是说明，
    #    不等于还在引用它 —— 直接对原文做子串判断会假红。
    check(f'门户页不再引用 {f}', f not in PORTAL_HTML_CODE)
    check(f'白名单不再列 {f}', f not in allowed)
check('portal.js 不再有 GhostFX 守卫（变体引擎没了，守卫是死代码）',
      'GhostFX' not in PORTAL_JS_CODE)
check('portal.js 用的是 moonstone-flow（随机方向流动那一档）',
      "'moonstone-flow'" in PORTAL_JS_CODE)
check('portal.js 不再用 moonstone-swirl（那一档已不是门户默认）',
      "'moonstone-swirl'" not in PORTAL_JS_CODE)
# 已被用户否掉的两档（月白·乱潮 / 月白·转潮）必须从引擎里删干净 ——
# 留着就是死代码：没人会切回去，但它们会被变异脚本当成「活代码」反复维护。
check('引擎里 moonstone-tide 已删干净（用户否掉的那一档）',
      "'moonstone-tide':" not in STYLES_BODY)
check('引擎里 moonstone-swing 已删干净（用户否掉的那一档）',
      "'moonstone-swing':" not in STYLES_BODY)
# 更早那档 swirl 留着当回退 —— 改 portal.js 一行就能切回去。
check('引擎里 moonstone-swirl 仍保留（可一键切回更早那档）',
      bool(entry_block(STYLES_BODY, 'moonstone-swirl')))
check('登录页那一档 moonstone 仍然在（不能被删）',
      bool(entry_block(STYLES_BODY, 'moonstone')))

# ─────────────────────────────────────────────────────────────
sec('PF-14 门户页的脚本加载顺序正确')

i_fp = PORTAL_HTML.find('{{STATIC_BASE}}fingerprint.js')
i_pf = PORTAL_HTML.find('{{STATIC_BASE}}pixelfield.js')
i_pj = PORTAL_HTML.find('{{STATIC_BASE}}portal.js')
check('三个脚本都引用了', -1 not in (i_fp, i_pf, i_pj))
check('pixelfield.js 在 portal.js 之前（portal.js 要用 window.GhostPixelField）',
      0 <= i_pf < i_pj, f'pixelfield {i_pf} / portal {i_pj}')

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
      'http://' not in PORTAL_HTML_CODE and 'https://' not in PORTAL_HTML_CODE)
for f, code in (('portal.js', PORTAL_JS_CODE),
                ('pixelfield.js', PIXELFIELD_CODE),
                ('fingerprint.js', FINGERPRINT_JS_CODE)):
    check(f'{f} 不引外部资源',
          'http://' not in code and 'https://' not in code)

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
sec('PF-16 三个 JS 文件语法正确')

node = shutil.which('node') or '/tmp/node-v22.23.4-linux-x64/bin/node'
if os.path.isfile(node) or shutil.which(node):
    for f in ('portal.js', 'pixelfield.js', 'fingerprint.js'):
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
      re.search(r'<script(?![^>]*\bsrc=)', PORTAL_HTML_CODE, re.I) is None)
check('门户页没有 style= 属性',
      re.search(r'\sstyle\s*=', PORTAL_HTML_CODE, re.I) is None)
check('门户页没有 on* 事件属性',
      re.search(r'\son[a-z]+\s*=', PORTAL_HTML_CODE, re.I) is None)
for f, code in (('portal.js', PORTAL_JS_CODE), ('pixelfield.js', PIXELFIELD_CODE)):
    check(f'{f} 不拼 innerHTML（防 XSS）',
          not re.search(r'\.innerHTML\s*=', code) and
          not re.search(r'\.outerHTML\s*=', code))
    check(f'{f} 不写内联 style 属性（用 class 驱动）',
          not re.search(r'\.style\s*\.\s*(?!setProperty)', code) and
          not re.search(r'\.setAttribute\(\s*[\'"]style', code))

# ─────────────────────────────────────────────────────────────
sec('PF-18 门户页该引的都引了')

for need in ('base.css', 'gate.css', 'fingerprint.js', 'pixelfield.js', 'portal.js'):
    check(f'门户页引用了 {need}', need in refs,
          '漏引 ⇒ 那部分功能直接消失，而且页面还能正常打开（很难一眼看出）')

for f in REMOVED_FILES:
    check(f'门户页**没有**再引用 {f}', f not in refs,
          '变体方案已砍干净，引用就是死链')

# ─────────────────────────────────────────────────────────────
sec('PF-19 方向游走走「平滑解析式」（不是噪声切片）')

# 为什么不用噪声切片（2026-11-03 实测，不是猜的）：
#   噪声是三个倍频（4/9/21）叠加，沿时间轴走一刀必然带进高频抖动。
#   实测（240 秒窗口，dirFieldRange=0.9）：
#     dirWalkFreq=0.03 ⇒ 角速度峰值 0.43 rad/s、角加速度 5.3 rad/s²
#     dirWalkFreq=0.05 ⇒ 角速度峰值 0.62 rad/s、角加速度 4.9 rad/s²
#     dirWalkFreq=0.01 ⇒ 角速度峰值 0.15 rad/s、角加速度 1.2 rad/s²
#   而原版 dirSwing（幅 0.13rad × 0.065Hz）的角速度峰值只有 0.053 rad/s
#   ⇒ 就算把频率压到最低，噪声切片也比原版快 2~3 倍
#   ⇒ 那不是「洋流拐弯」，是**抖**。噪声的高频倍频没法靠调频率消掉，
#     只能换信号源。
check('引擎有 dirWalkSignal（平滑解析式方向游走）',
      'function dirWalkSignal(' in PIXELFIELD)
check('方向场取值按 dirWalkSmooth 二选一（平滑解析式 / 噪声切片）',
      re.search(r'dn = p\.dirWalkSmooth > 0\s*\?\s*dirWalkSignal\(tq, dwf\)',
                PIXELFIELD) is not None)
check('噪声切片那条老路径还在（不传 dirWalkSmooth 时走它 ⇒ 逐位一致）',
      'sample(tex, NOISE_N, tq * dwf, 0.37)' in PIXELFIELD)
# 三组频率必须**不可公度**，否则合成波形会看出周期（像钟摆，不像随机游走）。
check('方向游走用三组不可公度的频率（合成波形几分钟内不重复）',
      re.search(r'0\.55 \* Math\.sin\(a \* 0\.55 \* t \+ 0\.7\)', PIXELFIELD) is not None and
      re.search(r'0\.30 \* Math\.sin\(a \* 1\.15 \* t \+ 2\.3\)', PIXELFIELD) is not None and
      re.search(r'0\.15 \* Math\.sin\(a \* 2\.35 \* t \+ 4\.1\)', PIXELFIELD) is not None)
check('方向游走三组权重之和为 1（值域 [-1,1]，不超范围）',
      re.search(r'0\.55 \* Math\.sin', PIXELFIELD) is not None and
      re.search(r'0\.30 \* Math\.sin', PIXELFIELD) is not None and
      re.search(r'0\.15 \* Math\.sin', PIXELFIELD) is not None)
check('引擎默认参数 dirWalkSmooth = 0（默认走老路径 ⇒ 逐位一致）',
      re.search(r'^\s+dirWalkSmooth:\s*0,', PARAMS_BODY, re.M) is not None)

# debug() 必须报出**引擎自己算出来的**当前方向角。
# 为什么：方向对比图的箭头如果由外部脚本另算一份公式，
# 就有「图上画的角 ≠ 引擎实际用的角」的风险 —— 2026-11-03 实测踩到了，
# 脚本没读档位参数，三行箭头画成了同一个角度，证据图直接是错的。
check('debug() 报出引擎自己算出的当前方向角（证据图的箭头不另算公式）',
      'dirAngle: dirAngleNow' in PIXELFIELD and 'dirAngleDeg' in PIXELFIELD)
check('当前方向角在每个几何步更新（不是初始值）',
      re.search(r'dirAngleNow = dang;', PIXELFIELD) is not None)

# ─────────────────────────────────────────────────────────────
sec('PF-20 方向场绕画布中心转（不是绕左上角）')

# 波前法线坐标 uy = px·sin(d) + py·cos(d) ⇒ 亮带是**一组过原点的平行线**。
# 方向 d 一旦随时间变，这组线就绕原点转 ⇒ 离原点越远转得越快
# ⇒ 左上角几乎不动、右下角飞快扫 ⇒ 整屏流速严重不均匀。
check('引擎有 dirPivot 开关',
      re.search(r'^\s+dirPivot:\s*0,', PARAMS_BODY, re.M) is not None)
check('旋转中心默认取画布原点（= 原版行为）',
      re.search(r'var pivX = 0, pivY = 0;', PIXELFIELD) is not None)
check('dirPivot=1 时旋转中心挪到画布中心',
      re.search(r'pivX = w \* 0\.5; pivY = h \* 0\.5;', PIXELFIELD) is not None)
check('旋转中心只在方向场生效时才偏移（否则原路径被改 ⇒ 破坏逐位一致）',
      re.search(r'if \(useField && p\.dirPivot > 0\)', PIXELFIELD) is not None)
check('法线坐标带上了旋转中心',
      re.search(r'var uy = \(px - pivX\) \* wsn \+ \(py - pivY\) \* wcn;', PIXELFIELD) is not None)

print()
if FAIL:
    print(f'失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
