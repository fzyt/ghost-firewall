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
  PF-21 规整量化点阵（借鉴 TRAE 首页：连续场硬阈值 + 按块随机绿白二选一）
  PF-22 pixel-flow 新档独立存在，现有各档一字未动
  PF-23 硬边改造（要么亮要么不亮：alpha 斜坡 / 余晖 / 迟滞三处同改）
  PF-24 TRAE 式显式取样位移（点位规律逆向：点不动、内容错位）
  PF-25 压暗层改 TRAE 纯纵向渐变 + 保留开关

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
                  ('dirTurnPeriod', '8'), ('dirTurnRate', '0.16'),
                  ('speedTurnPeriod', '6'), ('speedTurnRate', '0.18'),
                  ('speedRange', '0.55'), ('dirPivot', '0'),
                  ('distortAmp', '0.85'), ('lit', '0.12')):
    check(f'moonstone-flow 的 {name} = {val}',
          re.search(re.escape(name) + r':\s*' + re.escape(val), flow) is not None)

# ⚠️ 这一批改动的三个硬指标（2026-11-03 实测，不是猜的）：
#
#   ① 方向必须能覆盖**整圈**。
#      上一版（dirFieldRange + 噪声切片/三正弦游走）实测 48 秒里方向角只在
#      +23.7° ~ -10.3° 之间晃，运动方向 cos d 恒为 0.90~0.98
#      ⇒ **永远朝下、从不向上、从不横向** ⇒ 用户的投诉客观成立。
#      现在改成「随机目标角 + 限速逼近」，目标角在整圈上均匀抽样。
#
#   ② 转向角速度不能快到变成「甩」。dirTurnRate 是**上限**，
#      一个换向周期最多转 dirTurnRate × dirTurnPeriod 弧度。
#
#   ③ 变速率与幅度都要有界：幅度太小看不出在变速，太大像抽搐；
#      变速率太大 ⇒ 一秒内从极慢跳到极快。
dtp = re.search(r'dirTurnPeriod:\s*([0-9.]+)', flow)
dtr = re.search(r'dirTurnRate:\s*([0-9.]+)', flow)
stp = re.search(r'speedTurnPeriod:\s*([0-9.]+)', flow)
strate = re.search(r'speedTurnRate:\s*([0-9.]+)', flow)
srg = re.search(r'speedRange:\s*([0-9.]+)', flow)
check('moonstone-flow 写了 dirTurnPeriod / dirTurnRate / speed* 四个参数',
      all(x is not None for x in (dtp, dtr, stp, strate, srg)),
      '实测 period=%s rate=%s spdPeriod=%s spdRate=%s spdRange=%s' % (
          dtp.group(1) if dtp else '没找到', dtr.group(1) if dtr else '没找到',
          stp.group(1) if stp else '没找到', strate.group(1) if strate else '没找到',
          srg.group(1) if srg else '没找到'))
if dtp and dtr and stp and strate and srg:
    per = float(dtp.group(1))
    rate = float(dtr.group(1))
    check('moonstone-flow 一个换向周期最多转 ≤ 90°（再快就是「甩」不是「流」）',
          rate * per <= 6.2831853 * 0.25,
          f'实测 {rate}×{per} = {rate * per * 180 / 3.14159265:.1f}°/周期')
    check('moonstone-flow 换向角速度 ≤ 0.30 rad/s（原版 dirSwing 峰值 0.053）',
          rate <= 0.30, f'实测 {rate}')
    check('moonstone-flow 速度倍率幅度在 0.30~0.80 之间（太小看不出、大了像抽搐）',
          0.30 <= float(srg.group(1)) <= 0.80, f'实测 {srg.group(1)}')
    check('moonstone-flow 变速率 ≤ 0.50 倍/秒（一秒内从极慢跳到极快就是抽搐）',
          float(strate.group(1)) <= 0.50, f'实测 {strate.group(1)}')
else:
    check('moonstone-flow 一个换向周期最多转 ≤ 90°（再快就是「甩」不是「流」）', False)
    check('moonstone-flow 换向角速度 ≤ 0.30 rad/s（原版 dirSwing 峰值 0.053）', False)
    check('moonstone-flow 速度倍率幅度在 0.30~0.80 之间（太小看不出、大了像抽搐）', False)
    check('moonstone-flow 变速率 ≤ 0.50 倍/秒（一秒内从极慢跳到极快就是抽搐）', False)

# ─────────────────────────────────────────────────────────────
sec('PF-8b moonstone-flow 与原版 moonstone 的差别**只有方向与速度**')

# 这一批改动的全部意义就在这一条上：
#   用户要的是「原版那种固定方向流动的**随机版**」——
#   所以几何（波速、波长、相位、扭曲、遮罩、余晖、像素尺寸、密度）
#   必须与原版 moonstone **逐条一致**，只有「方向」和「速度」这两项变了。
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
             'dirFieldDrift', 'dirWalkFreq', 'dirPivot',
             'dirTurnPeriod', 'dirTurnRate',
             'speedTurnPeriod', 'speedTurnRate', 'speedRange',
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
sec('PF-19 方向走「随机目标角 + 限速逼近」（能覆盖整圈）')

# 为什么不用噪声切片、也不用三正弦叠加（2026-11-03 实测，不是猜的）：
#   噪声切片：角速度是原版的 3~12 倍 ⇒ 那是在抖不是在流；
#   三正弦叠加：合成信号的实际值域只有 ±0.45，
#     要摆满 360° 就得把角速度拉到 0.4 rad/s（原版的 8 倍）⇒ 在甩不是流。
#   而且两者的方向区间都挤在「偏下」那一小段：
#     实测 48 秒里方向角只在 +23.7° ~ -10.3° 之间晃，
#     运动方向 cos d 恒为 0.90~0.98 ⇒ **永远朝下、从不向上、从不横向**。
check('引擎有 dirTurnPeriod / dirTurnRate 两个参数（默认 0 ⇒ 走老路）',
      re.search(r'^\s+dirTurnPeriod:\s*0,', PARAMS_BODY, re.M) is not None and
      re.search(r'^\s+dirTurnRate:\s*0\.0,', PARAMS_BODY, re.M) is not None)
check('目标角在**整圈**上均匀抽样（不是挤在一小段弧里）',
      re.search(r'dirTarget = rnd\([^)]*\) \* 6\.2831853;', PIXELFIELD) is not None)
check('转向走短弧（否则为了 350° 的差别会绕远路）',
      'while (tdiff > Math.PI) tdiff -= 6.2831853;' in PIXELFIELD and
      'while (tdiff < -Math.PI) tdiff += 6.2831853;' in PIXELFIELD)
check('转向角速度有上限，0 = 不限速（一步到位 = 「突然拐一下」）',
      re.search(r'var tmax = p\.dirTurnRate > 0 \? p\.dirTurnRate \* geoDt : 1e9;',
                PIXELFIELD) is not None)
check('方向起始角对齐原版基准角（第一帧与原版一致，不一上来就跳到随机角）',
      re.search(r'dirAng = p\.dirFieldBase \|\| 0;', PIXELFIELD) is not None)
# 噪声切片那条老路径还在（不传 dirTurnPeriod 时走它 ⇒ 逐位一致）
check('噪声切片那条老路径还在（不传 dirTurnPeriod 时走它 ⇒ 逐位一致）',
      'sample(tex, NOISE_N, tq * dwf, 0.37)' in PIXELFIELD)
check('两条路径二选一：随机换向 vs 噪声切片老路径',
      'dang = dirAng + p.dirSwing * Math.sin(swingT);' in PIXELFIELD)
check('已否决的「三正弦叠加」方向游走函数已删除（不该留在引擎里）',
      'dirWalkSignal' not in PIXELFIELD)
check('已否决的 dirWalkSmooth 参数已删除（默认参数表里不该再有）',
      'dirWalkSmooth' not in PIXELFIELD)

# debug() 必须报出**引擎自己算出来的**当前方向角。
# 为什么：方向对比图的箭头如果由外部脚本另算一份公式，
# 就有「图上画的角 ≠ 引擎实际用的角」的风险 —— 2026-11-03 实测踩到了，
# 脚本没读档位参数，三行箭头画成了同一个角度，证据图直接是错的。
check('debug() 报出引擎自己算出的当前方向角（证据图的箭头不另算公式）',
      'dirAngle: dirAngleNow' in PIXELFIELD and 'dirAngleDeg' in PIXELFIELD)
check('当前方向角在每个几何步更新（不是初始值）',
      re.search(r'dirAngleNow = dang;', PIXELFIELD) is not None)

# ─────────────────────────────────────────────────────────────
sec('PF-19b 随机变速走「累计相位」（变速时波前不跳变）')

# 用户原话：「速度快慢也可以加入随机，目前看好像是始终一个速度的，
#           也就是流动可能突然提速降速，也可能慢慢提速降速」。
check('引擎有 speedTurnPeriod / speedTurnRate / speedRange 三个参数（默认 0）',
      re.search(r'^\s+speedTurnPeriod:\s*0,', PARAMS_BODY, re.M) is not None and
      re.search(r'^\s+speedTurnRate:\s*0\.0,', PARAMS_BODY, re.M) is not None and
      re.search(r'^\s+speedRange:\s*0\.0,', PARAMS_BODY, re.M) is not None)
check('速度倍率有上下限（speedRange 是 ± 幅度，基准是 1.0）',
      re.search(r'spdTarget = 1 \+ \(rnd\([^)]*\) \* 2 - 1\) \* p\.speedRange;',
                PIXELFIELD) is not None)
check('变速率有上限，0 = 不限速（瞬间换挡 = 「突然提速降速」）',
      re.search(r'var smax = p\.speedTurnRate > 0 \? p\.speedTurnRate \* geoDt : 1e9;',
                PIXELFIELD) is not None)
# ★ 关键：相位必须用**累计量**，不能是闭式的 om*t。
#   闭式的话速度一变，波前位置会跳一下（画面「闪」一下）。
check('波相位走累计量 wPh（不是闭式 om*t）⇒ 变速时波前不跳变',
      re.search(r'var ph = wv\.k \* uy - \(useSpeedWalk \? wPh\[wi2\] : wv\.om \* tq\)',
                PIXELFIELD) is not None)
check('累计相位按「速度倍率 × 实际 dt」推进',
      re.search(r'wPh\[spi\] \+= waves\[spi\]\.om \* spdF \* geoDt;', PIXELFIELD) is not None)
check('累计相位初始化对齐闭式 om*t（启用瞬间不跳变）',
      re.search(r'wPh\[sgi\] = waves\[sgi\]\.om \* tq;', PIXELFIELD) is not None)
# dt 必须用**实际几何步间隔**，不能用 p.step：
#   标签页隐藏时 rAF 会停、几何步被跳过 ⇒ 按 p.step 累加会慢一大截。
check('推进用实际几何步间隔 geoDt（不是 p.step）',
      re.search(r'var geoDt = tq - lastGeomT;', PIXELFIELD) is not None and
      'lastGeomT = tq;' in PIXELFIELD)
check('debug() 报出当前速度倍率（证据图不另算公式）',
      'speedFactor: spdF' in PIXELFIELD)
check('累计相位用双精度存（Float32 会丢末位 ⇒ 破坏「逐位一致」）',
      re.search(r'var wPh = new Float64Array\(8\);', PIXELFIELD) is not None)

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

# ─────────────────────────────────────────────────────────────
sec('PF-21 规整量化点阵（借鉴 TRAE 首页，2026-11-03）')

# 这一批做的是「**独立一档**」：moonstone / gate / moonstone-swirl / moonstone-flow
# 一个字节都没动，新增的参数默认值全为 0 ⇒ 不传时逐位一致。
check('引擎新增 pixelQuant 参数（默认 0 ⇒ 走老路，逐位一致）',
      re.search(r'^\s+pixelQuant:\s*0,', PARAMS_BODY, re.M) is not None)
check('引擎新增 pixelThresh 参数（默认 0）',
      re.search(r'^\s+pixelThresh:\s*0\.0,', PARAMS_BODY, re.M) is not None)
check('引擎新增 pixelBlend 参数（默认 0）',
      re.search(r'^\s+pixelBlend:\s*0,', PARAMS_BODY, re.M) is not None)
check('引擎新增 pixelGreen 参数（默认 0）',
      re.search(r'^\s+pixelGreen:\s*0,', PARAMS_BODY, re.M) is not None)
check('引擎新增 pixelJitter 参数（默认 0）',
      re.search(r'^\s+pixelJitter:\s*0,', PARAMS_BODY, re.M) is not None)
check('引擎新增 columns 参数（默认 0 ⇒ 用 opt.columns）',
      re.search(r'^\s+columns:\s*0,', PARAMS_BODY, re.M) is not None)
check('引擎新增 flowDensity / flowWarp / flowSpeed 三个流场参数（默认全 0）',
      re.search(r'^\s+flowDensity:\s*0,', PARAMS_BODY, re.M) is not None and
      re.search(r'^\s+flowWarp:\s*0,', PARAMS_BODY, re.M) is not None and
      re.search(r'^\s+flowSpeed:\s*0,', PARAMS_BODY, re.M) is not None)

# 网格密度：p.columns 优先于 opt.columns。
# ⚠ 这条踩过坑：cell = SS * max(2, round(w / COLUMNS / SS))，
#   在 800px 画布上 COLUMNS=118 与 190 都 round 到 cell=8 ⇒ 网格一模一样。
#   探针曾据此报出「columns 没生效」的假结论 ⇒ 用例必须在 1440 宽上验。
check('网格密度由 p.columns 决定（档位可以覆盖 opt.columns）',
      re.search(r'var COLUMNS = p\.columns > 0 \? \(p\.columns \| 0\) : \(opt\.columns \|\| 112\);',
                PIXELFIELD) is not None)

# 量化模式的三条机制（照 TRAE 的 e1MainImage 着色器真值）：
#   ① 不用每格随机门槛 ⇒ 点的存在由连续场 > 阈值决定
#   ② 阈值按块随机抖动（dynamicThreshold = e1Threshold - 0.08 * rand）
#   ③ 颜色按块随机二选一（绿/白），不是按场值连续插值
check('量化模式下点由「连续场 > 阈值」决定（不是每格随机门槛 rSel）',
      re.search(r'var qth = \(p\.pixelThresh > 0 \? p\.pixelThresh : 0\.5\) \* 2 - 1;',
                PIXELFIELD) is not None and
      'if (qf > qth) {' in PIXELFIELD)
check('阈值按块随机抖动（TRAE 的 dynamicThreshold = e1Threshold - 0.08 * rand）',
      re.search(r'if \(p\.pixelJitter > 0\) qth -= p\.pixelJitter \* rSel\[idx\];',
                PIXELFIELD) is not None)
check('颜色按块随机二选一（绿/白），用每格稳定的 rSel 当 rand',
      re.search(r'if \(rSel\[idx\] < p\.pixelGreen\) \{', PIXELFIELD) is not None)
check('量化模式只画一层（两档叠加会把插值/二选一冲掉）',
      re.search(r'if \(!blend && !greenBin && a2 > 0\.002\) \{', PIXELFIELD) is not None)
check('量化模式下伺服不参与（选点不吃 pickGain，伺服是空转）',
      re.search(r'if \(p\.pixelQuant > 0\) return 0;', PIXELFIELD) is not None)
check('量化模式关掉每格抖动偏移（off = 0，否则点阵还是随机疏密）',
      re.search(r'var off = quant \? 0', PIXELFIELD) is not None)

# 域扭曲流场：TRAE 的观感真正来源。
# 不用它 ⇒ 值噪声的轴对齐晶格 ⇒ 亮点连成方块簇（2026-11-03 实测）。
check('流场走 TRAE 同款的域扭曲（q 两条通道先采样再掰坐标）',
      'var qxq = sample(tex, NOISE_N, uf, vf + 0.05 * ftq);' in PIXELFIELD and
      'var qyq = sample(tex, NOISE_N, uf + 0.30, vf - 0.0375 * ftq);' in PIXELFIELD and
      'qf = sample(tex, NOISE_N, uf + qxq * p.flowWarp, vf + qyq * p.flowWarp);' in PIXELFIELD)
check('流场开关提到逐格循环外（每步只取决于参数）',
      re.search(r'var useFlow = p\.pixelQuant > 0 && p\.flowDensity > 0;', PIXELFIELD) is not None)

# ─────────────────────────────────────────────────────────────
sec('PF-22 pixel-flow 新档（借鉴 TRAE，独立于现有各档）')

pix = entry_block(STYLES_BODY, 'pixel-flow')
check('pixel-flow 档存在', bool(pix))
check('pixel-flow 用的是新调的色板 mint（不是复用 gate / moonstone）',
      re.search(r"palette:\s*'mint'", pix) is not None and
      "mint:" in PIXELFIELD)
check('mint 色板的取色直接来自 TRAE 的 uniform 真值（青绿 #32F08C）',
      re.search(r'accent:\s*\[50,\s*240,\s*140\]', PIXELFIELD) is not None)
check('pixel-flow 开了规整量化', re.search(r'pixelQuant:\s*1,', pix) is not None)
check('pixel-flow 开了 TRAE 同款绿白二选一（绿占 56%）',
      re.search(r'pixelGreen:\s*0\.56,', pix) is not None)
# ⚠ 这条是踩过坑才补的：变异脚本按「第一个匹配」替换，
#   而 pixelBlend: 0, 在**档位**和**默认参数表**里各有一处（档位在前）
#   ⇒ 之前那条变异改到的是档位，而档位级没有断言 ⇒ 漏网。
#   语义上也要钉死：TRAE 的颜色是「按块随机二选一」，
#   连续插值只是保留的备选开关（pixelBlend=1），不是这一档的默认。
check('pixel-flow 默认用「按块随机二选一」而不是连续插值（pixelBlend = 0）',
      re.search(r'pixelBlend:\s*0,', pix) is not None)
check('pixel-flow 开了阈值按块抖动（0.36 = TRAE 0.08 在亮度域的等价幅度）',
      re.search(r'pixelJitter:\s*0\.36,', pix) is not None)
check('pixel-flow 开了域扭曲流场', re.search(r'flowDensity:\s*0\.375,', pix) is not None)
check('pixel-flow 的域扭曲强度与漂移速度定档',
      re.search(r'flowWarp:\s*0\.50,', pix) is not None and
      re.search(r'flowSpeed:\s*0\.020,', pix) is not None)
check('pixel-flow 的阈值定档 0.88（TRAE 0.87 在亮度域换算过来是 0.70，'
      '实测按同口径指标调到 0.88）',
      re.search(r'pixelThresh:\s*0\.88,', pix) is not None)
check('pixel-flow 把点提前到满亮度（TRAE 的像素块是满亮度的）',
      re.search(r'accentT:\s*0\.08,', pix) is not None)
check('pixel-flow 加密了网格（columns=190 ⇒ 1440 宽下 cell = 8px）',
      re.search(r'columns:\s*190,', pix) is not None)
check('pixel-flow 沿用 moonstone-flow 的随机换向与随机变速',
      re.search(r'dirTurnPeriod:\s*8,', pix) is not None and
      re.search(r'speedTurnPeriod:\s*6,', pix) is not None)
# 现有各档必须一字不动 —— 新档是「另外一份」，不是把老档改了。
check('moonstone 档没被这一批动过（登录页视觉零变化）',
      entry_block(STYLES_BODY, 'moonstone') != '' and
      'pixelQuant' not in entry_block(STYLES_BODY, 'moonstone'))
check('moonstone-flow 档没被这一批动过（现有门户档保持原样）',
      'pixelQuant' not in entry_block(STYLES_BODY, 'moonstone-flow'))
check('moonstone-swirl 档没被这一批动过（回退档保持原样）',
      'pixelQuant' not in entry_block(STYLES_BODY, 'moonstone-swirl'))
check('gate 档没被这一批动过',
      'pixelQuant' not in entry_block(STYLES_BODY, 'gate'))

# ─────────────────────────────────────────────────────────────
sec('PF-23 硬边改造：要么亮，要么不亮（2026-11-03 用户要求）')

# 用户原话：「我看目前有一些灰度和亮的交接，类似于水打上去的印记一样，
#           我想要么亮，要么不亮，分界明显一点」。
#
# 柔边是三件套叠出来的，量化模式下必须**三件全关**，缺一件就露馅：
#   ① alpha 斜坡：a1 = (vv - tLo1) / fade ⇒ 值域 0..1 ⇒ 中间灰
#   ② 余晖衰减  ：peak 留着旧值慢慢衰减 ⇒ 刚熄灭的点还亮着 ⇒ 拖尾是渐变
#   ③ 迟滞限速  ：alpha 下降按帧限速 ⇒ 1 → 0.965 → … ⇒ 又变灰度
#
# ⚠ 只关 ① 不够：余晖会把已经熄灭的格继续顶在阈值之上，硬边做不出来。
#   这三条断言一起钉住「三处同改」这个事实。
# ⚠ 这层是**静态**断言（代码写了什么）；真正的「画面有没有中间灰」
#   由 tests/test_pixelfield_hardedge.js 真跑引擎读像素来验。
check('量化模式下 alpha 是硬开关（不是连续斜坡）',
      re.search(r'a1 = vv > tLo1 \? 1 : 0;', PIXELFIELD) is not None)
check('量化模式下不出辉光层（TRAE 那边同样没有辉光）',
      re.search(r'a2 = 0;\n\s+\} else \{', PIXELFIELD) is not None)
check('量化模式不留余晖（peak 直接取 band，不做衰减）',
      re.search(r'var e = quant \? band : \(band > prev \? band : prev \* p\.trail\);',
                PIXELFIELD) is not None)
check('量化模式整段跳过迟滞（迟滞会把 1→0 压成渐变）',
      re.search(r'if \(!quant\) \{\n\s+if \(a1 < aPrev\[idx\]\) \{', PIXELFIELD) is not None)
# 硬边模式没有「半亮」这一态 ⇒ 迟滞的载体 aPrev/wPrev 在量化模式下
# 只会拿到 0 或 1，两处赋值必须都还在（否则迟滞块被误删成空壳）。
check('迟滞被跳过时 aPrev / wPrev 仍照常落值（不是死代码）',
      re.search(r'aPrev\[idx\] = a1;\n\s+wPrev\[idx\] = a2;', PIXELFIELD) is not None)
# 硬边改造**不能**外溢到现有各档：那几个档没开 pixelQuant，
# 走的是 else 分支 ⇒ 行为逐位不变。
check('硬边改造只挂在 quant 分支上（老档走的 else 分支一字未动）',
      re.search(r'if \(quant\) \{\n\s+/\* ⚠ 量化模式是\*\*硬开关\*\*', PIXELFIELD) is not None)
# 切点语义变了：硬边下 accentT 不再管「亮度」，只管「从哪儿开始算亮」。
check('硬边模式的切点取 tLo1（accentT - fade/2，落在原斜坡刚满亮处）',
      re.search(r'var tLo1 = p\.accentT - half, tLo2 = p\.whiteT - half;',
                PIXELFIELD) is not None)

# ─────────────────────────────────────────────────────────────
sec('PF-24 TRAE 式显式取样位移（2026-11-03 点位规律逆向）')

# ★ 这一批的起因：实测证明 TRAE 的点**从来不移动**。
#   探针 /tmp/portal-preview/trae-lattice.js：把 TRAE 首页背景裁一块，
#   按 (x mod 7) / (y mod 7) 给亮像素分桶 ⇒
#     残差 0 与 6 **恒为 0**、残差 1..5 计数几乎完全相等
#     ⇒ 100% 的亮像素落在 7px 晶格的 5×5 格实体内
#     6 帧的最优相位**恒为 (1,3)** ⇒ 晶格相位从未变过
#   ⇒ 动的是「每格去哪儿取色」，不是点的位置。
check('引擎新增 fieldDensity 参数（颜色场尺度，默认 0 ⇒ 沿用 flowDensity）',
      re.search(r'^\s+fieldDensity:\s*0,', PARAMS_BODY, re.M) is not None)
check('引擎新增 flowDispX / flowDispY 参数（取样位移 px，默认全 0）',
      re.search(r'^\s+flowDispX:\s*0,', PARAMS_BODY, re.M) is not None and
      re.search(r'^\s+flowDispY:\s*0,', PARAMS_BODY, re.M) is not None)
# 位移是**单向**的：TRAE 的 q ∈ [0.06,0.94] 恒正 ⇒ 位移恒正（拖曳，不是抖动）。
check('取样位移把噪声从 [-1,1] 映射到 [0,1]（+1 再 /2 ⇒ 恒正，像 TRAE）',
      re.search(r'du = \(dbx \+ 1\) \* 0\.5 \* p\.flowDispX / w;', PIXELFIELD) is not None and
      re.search(r'dv = \(dby \+ 1\) \* 0\.5 \* p\.flowDispY / h;', PIXELFIELD) is not None)
# 位移场与颜色场必须**尺度不同**（TRAE: density 1.5 vs 0.5），
# 否则两层采到同一片噪声、互相抵消。
check('颜色场尺度与位移场尺度解耦（fieldDensity 独立于 flowDensity）',
      re.search(r'var Df = p\.fieldDensity > 0 \? p\.fieldDensity : p\.flowDensity;',
                PIXELFIELD) is not None)
check('位移场用自己的 flowDensity 采样（不是拿颜色场的尺度）',
      re.search(r'var ub = sxq \* p\.flowDensity, vb = syq \* p\.flowDensity;',
                PIXELFIELD) is not None)
# 位移后的位置再求颜色场 —— 这就是 TRAE「点不动、内容错位」的核心。
check('颜色场在**位移后**的位置求值（点不动、内容错位）',
      re.search(r'var uf = \(sxq - du\) \* Df, vf = \(syq - dv\) \* Df;',
                PIXELFIELD) is not None)
# ⚠ 位移没开时必须整段跳过 ⇒ 逐位一致。
check('位移默认关闭（flowDispX/Y 全 0 ⇒ 整段跳过 ⇒ 逐位一致）',
      re.search(r'if \(useDisp\) \{', PIXELFIELD) is not None and
      re.search(r'var useDisp = \(p\.flowDispX > 0 \|\| p\.flowDispY > 0\);',
                PIXELFIELD) is not None)
# 单位换算：TRAE density=d ↔ 本引擎 D = 0.25×d（噪声贴图基频周期 0.25 贴图单位）
check('pixel-flow 的 flowDensity 定档 0.375（TRAE density 1.5 ⇒ 0.25×1.5）',
      re.search(r'flowDensity:\s*0\.375,', pix) is not None)
check('pixel-flow 的 fieldDensity 定档 0.125（TRAE density 0.5 ⇒ 0.25×0.5）',
      re.search(r'fieldDensity:\s*0\.125,', pix) is not None)
check('pixel-flow 开了 TRAE 式取样位移（横向 10px / 纵向 70px）',
      re.search(r'flowDispX:\s*10,', pix) is not None and
      re.search(r'flowDispY:\s*70,', pix) is not None)
# 阈值与绿占比：2026-11-03 按实测同口径指标重新定档
# （TRAE 实测 lit 5.4~7.2% / 绿 27~31.5%）。
check('pixel-flow 的阈值定档 0.88（实测与 TRAE 的亮区密度对上）',
      re.search(r'pixelThresh:\s*0\.88,', pix) is not None)
check('pixel-flow 的绿占比定档 0.56（实测绿占比与 TRAE 的 27~31.5% 对上）',
      re.search(r'pixelGreen:\s*0\.56,', pix) is not None)

# ─────────────────────────────────────────────────────────────
sec('PF-25 压暗层改 TRAE 纯纵向渐变 + 保留开关')

# TRAE 的压暗层是从浏览器计算样式里读出来的原文：
#   linear-gradient(rgb(12,12,12) 0%, rgba(12,12,12,.6) 30%,
#                   rgba(12,12,12,.6) 60%, rgb(12,12,12) 100%)
CSS = read('base.css')
check('压暗层用的是 TRAE 的纵向渐变（上下全封、中间 30%~60% 段 60% 不透明）',
      re.search(r'linear-gradient\(\s*var\(--scrim-c\) var\(--scrim-a\),\s*'
                r'var\(--scrim-m\) var\(--scrim-b\),\s*'
                r'var\(--scrim-m\) var\(--scrim-d\),\s*'
                r'var\(--scrim-c\) 100%\)', CSS) is not None)
check('压暗层的停靠点做成了 CSS 变量（可调深浅/位置而不用改规则）',
      re.search(r'--scrim-c:\s*rgb\(12, 12, 12\);', CSS) is not None and
      re.search(r'--scrim-m:\s*rgba\(12, 12, 12, \.6\);', CSS) is not None)
check('旧版压暗层保留在 body.pix-scrim-legacy 下（能切回去）',
      re.search(r'body\.pix-scrim-legacy \.pix-scrim \{', CSS) is not None and
      'radial-gradient(58% 48% at 34% 20%' in CSS)


print()
if FAIL:
    print(f'失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
