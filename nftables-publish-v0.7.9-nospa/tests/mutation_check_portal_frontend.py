"""门户改版批次（随机方向波浪 + 砍掉 14 套变体）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_portal_frontend.py

测什么有效：这一批改版最危险的退化不是「写错了」，而是**改回原来的样子**。
原来的方向场是三道几乎平行的全局常量波、原来的分片遮罩是屏幕空间的
各向异性噪声、原来的每格只画 2px 的点 —— 那些代码读起来完全正常、
前端照样工作，单测很容易全绿。只有真的把改动拆掉，测试才会变红。

所以每条变异都是「把这次改版撤回」，分七组：

  A  白名单 / 引用一致性 —— 少一个文件就白屏，多一个文件就是死链
  B  网格改造撤回
  C  新参数默认值被改 —— 破坏「不传时与改版前逐位一致」这条保证
  D  随机方向波浪的结构 —— 共享方向场 / 遮罩跟随波向 / 像素块
  E  新档（moonstone-tide / moonstone-swing）参数被改
  F  改版外溢到登录页
  G  安全面 / 加载顺序 / 占位符

每条变异都独立重写源文件，并强制 PYTHONDONTWRITEBYTECODE=1：否则连续写入时
Python 只按 mtime+size 判过期，两条大小相近的变异会复用上一条的 .pyc，
把「漏网」伪装成「捕获」。

只备份 / 还原**本脚本会动的那几个文件**，一个字节都不碰别的。

⚠️ 2026-11-02 重写：上一版有 32 条变异，其中绝大多数作用在
   fx.js / switcher.css / switcher.js 上 —— 那三个文件已经按用户要求
   删除，变异全部失效（脚本会自己报「找不到待替换的片段」）。
   新版把变异重排到**新架构**上：
     · 原来「白名单漏掉 fx.js」→ 改成「白名单漏掉 portal.js」
     · 原来「变体引擎少注册一个变体」→ 改成「方向场改成每波一张」
       （这个退化最隐蔽：代码照样跑，只是画面退回一堆散点）
     · 另外补了「已删文件被复活」这一类（白名单/引用/守卫三处复活点）
"""
import atexit
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, 'backend', 'static')
BACKEND = os.path.join(ROOT, 'backend')
TEST_PY = os.path.join(ROOT, 'tests', 'test_portal_frontend.py')

# 本脚本会动的文件（只这些）
REL_FILES = [
    os.path.join('backend', 'static', 'base.css'),
    os.path.join('backend', 'static', 'pixelfield.js'),
    os.path.join('backend', 'static', 'portal.js'),
    os.path.join('backend', 'static', 'portal.html'),
    os.path.join('backend', 'auth_gateway.py'),
]
ORIG = {}
for rel in REL_FILES:
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        ORIG[os.path.join(ROOT, rel)] = f.read()


def restore():
    """整体还原（保险丝用）。只碰上面那几个文件。"""
    for path, content in ORIG.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass


atexit.register(restore)
for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, lambda *a: (restore(), sys.exit(130)))
    except (ValueError, OSError):
        pass


def run_tests():
    """跑本批次的测试文件。返回 (rc, 输出)。"""
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    r = subprocess.run([sys.executable, TEST_PY],
                       capture_output=True, text=True, cwd=ROOT,
                       timeout=300, env=env)
    return r.returncode, r.stdout + r.stderr


def mutate(rel, old, new):
    """按路径改一个文件。找不到 old 就直接失败（变异脚本自己写错了）。"""
    path = os.path.join(ROOT, rel)
    with open(path, encoding='utf-8') as f:
        src = f.read()
    if old not in src:
        raise SystemExit(f'[变异脚本自身的错] 在 {rel} 里找不到待替换的片段:\n{old[:120]}')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src.replace(old, new, 1))


# ── 变异清单 ───────────────────────────────────────────────
# (编号, 说明, 相对路径, 旧片段, 新片段)
CSS = os.path.join('backend', 'static', 'base.css')
PIX = os.path.join('backend', 'static', 'pixelfield.js')
PJS = os.path.join('backend', 'static', 'portal.js')
PHT = os.path.join('backend', 'static', 'portal.html')
GW = os.path.join('backend', 'auth_gateway.py')

# 白名单那一行（auth_gateway.py:211-212）
WL = ('    "base.css", "fingerprint.js", "login.html", "login.js",\n'
      '    "portal.html", "portal.js", "pixelfield.js", "gate.css",')
WL_OLD = ('    "portal.html", "portal.js", "pixelfield.js", "gate.css",')

MUTATIONS = [
    # ── A. 白名单 / 引用一致性（真机上会白屏或死链的那一类）──────────
    ('N-01', '白名单漏掉 portal.js（页面能打开，脚本全挂）', GW,
     WL_OLD, '    "portal.html", "pixelfield.js", "gate.css",'),
    ('N-02', '白名单漏掉 pixelfield.js（背景整块消失）', GW,
     WL_OLD, '    "portal.html", "portal.js", "gate.css",'),
    ('N-03', '白名单留了不存在的文件（僵尸条目）', GW,
     WL_OLD, WL_OLD + ' "not-exist.js",'),
    ('N-04', '白名单把已删的 fx.js 复活', GW,
     WL_OLD, WL_OLD + ' "fx.js",'),
    ('N-05', '白名单把已删的 switcher.css 复活', GW,
     WL_OLD, WL_OLD + ' "switcher.css",'),
    ('N-06', '白名单把已删的 switcher.js 复活', GW,
     WL_OLD, WL_OLD + ' "switcher.js",'),
    ('N-07', '门户页漏引 portal.js', PHT,
     '<script src="{{STATIC_BASE}}portal.js"></script>\n', ''),
    ('N-08', '门户页漏引 pixelfield.js（背景没了但页面照常打开）', PHT,
     '<script src="{{STATIC_BASE}}pixelfield.js"></script>\n', ''),
    ('N-09', '门户页把 fx.js 引用加回来（已删文件复活 ⇒ 死链）', PHT,
     '<script src="{{STATIC_BASE}}fingerprint.js"></script>',
     '<script src="{{STATIC_BASE}}fingerprint.js"></script>\n'
     '<script src="{{STATIC_BASE}}fx.js"></script>'),
    ('N-10', '门户页把 switcher.css 引用加回来（死链）', PHT,
     '<link rel="stylesheet" href="{{STATIC_BASE}}gate.css">',
     '<link rel="stylesheet" href="{{STATIC_BASE}}gate.css">\n'
     '<link rel="stylesheet" href="{{STATIC_BASE}}switcher.css">'),
    ('N-11', '门户页写死静态前缀（部署到别的提供方就全是死链）', PHT,
     '<link rel="stylesheet" href="{{STATIC_BASE}}base.css">',
     '<link rel="stylesheet" href="/auth/static/base.css">'),

    # ── B. 网格改造撤回 ──
    ('N-12', '网格改回 auto-fill 自动列（名字又被截成「思源…」）', CSS,
     'grid-template-columns: repeat(2, minmax(0, 1fr));',
     'grid-template-columns: repeat(auto-fill, minmax(198px, 1fr));'),
    ('N-13', '删掉 640px 窄屏单列断点', CSS,
     '@media (max-width: 640px) {\n'
     '  .grid {\n'
     '    grid-template-columns: minmax(0, 1fr);\n'
     '    gap: var(--sp-3);\n'
     '  }\n'
     '}\n', ''),
    ('N-14', '删掉 --sp-4 间距 token', CSS,
     '  --sp-4:  16px;\n', ''),
    ('N-15', '卡片内部改回「名称与路径同一行」', CSS,
     '    "ico nm tag"\n    "ico pt .";',
     '    "ico nm pt"\n    "ico tag tag";'),
    ('N-16', '入口路径又被 max-width 砍断', CSS,
     '.tile .pt {\n  grid-area: pt;\n',
     '.tile .pt {\n  grid-area: pt;\n  max-width: 84px;\n'),

    # ── C. 新参数默认值被改（破坏「不传时逐位一致」）─────────────────
    ('N-17', 'dirField 默认值从 0 改成 1（不传也会走方向场）', PIX,
     '    dirField: 0,', '    dirField: 1,'),
    ('N-18', 'dirFieldBase 默认值从 0 改成 -0.30', PIX,
     '    dirFieldBase: 0.0,', '    dirFieldBase: -0.30,'),
    ('N-19', 'dirFieldScale 默认值从 0 改成 0.0026', PIX,
     '    dirFieldScale: 0.0,', '    dirFieldScale: 0.0026,'),
    ('N-20', 'dirFieldRange 默认值从 0 改成 1.05', PIX,
     '    dirFieldRange: 0.0,', '    dirFieldRange: 1.05,'),
    ('N-21', 'dirFieldDrift 默认值从 0 改成 0.012', PIX,
     '    dirFieldDrift: 0.0,', '    dirFieldDrift: 0.012,'),
    ('N-22', 'dirWalkFreq 默认值从 0 改成 0.085', PIX,
     '    dirWalkFreq: 0.0,', '    dirWalkFreq: 0.085,'),
    ('N-23', 'patchFollow 默认值从 0 改成 1（不传也会拉长）', PIX,
     '    patchFollow: 0,', '    patchFollow: 1,'),
    ('N-24', 'patchTangent 默认值从 1.0 改成 0.13', PIX,
     '    patchTangent: 1.0,', '    patchTangent: 0.13,'),
    ('N-25', 'patchNormal 默认值从 1.0 改成 1.50', PIX,
     '    patchNormal: 1.0,', '    patchNormal: 1.50,'),
    ('N-26', 'patchTangent2 默认值从 1.0 改成 0.42', PIX,
     '    patchTangent2: 1.0,', '    patchTangent2: 0.42,'),
    ('N-27', 'patchNormal2 默认值从 1.0 改成 0.95', PIX,
     '    patchNormal2: 1.0,', '    patchNormal2: 0.95,'),
    ('N-28', 'pxBody 默认值从 0 改成 3（不传时像素块就变大了）', PIX,
     '    pxBody: 0,', '    pxBody: 3,'),
    ('N-29', 'pxCrest 默认值从 0 改成 3', PIX,
     '    pxCrest: 0,', '    pxCrest: 3,'),
    ('N-30', 'dirFieldStep 默认值从 24 改成 0（步长归零 ⇒ 方向场退化）', PIX,
     '    dirFieldStep: 24,', '    dirFieldStep: 0,'),
    ('N-31', '旧参数 patchRot1 默认值从 0 改成 0.22', PIX,
     '    patchRot1: 0.0,', '    patchRot1: 0.22,'),
    ('N-32', '旧参数 patchSpin 默认值从 0 改成 0.020', PIX,
     '    patchSpin: 0.0,', '    patchSpin: 0.020,'),
    ('N-33', '旧参数 dirSwingFreq 默认值从 0 改成 0.5', PIX,
     '    dirSwingFreq: 0.0,', '    dirSwingFreq: 0.5,'),
    ('N-34', '方向向量改回单精度（末位精度丢失 ⇒ 破坏「逐位一致」）', PIX,
     'new Float64Array(8)', 'new Float32Array(8)'),

    # ── D. 随机方向波浪的结构（最隐蔽的一类：代码照样跑，只是画面退化）──
    ('N-35', '方向场改成每道波各一张（拉长方向在相邻格跳变 ⇒ 互相抵消）', PIX,
     'dirSin = new Float32Array(dirFW * dirFH);',
     'dirSin = new Float32Array(dirFW * dirFH * nw);'),
    ('N-36', 'ensureDirField 被删（方向场根本不分配）', PIX,
     'function ensureDirField() {', 'function ensureDirFieldX() {'),
    ('N-37', '逐格退回绝对角（不用共享方向 ⇒ 几道波各自乱转）', PIX,
     'wsn = fs * wOffC[wi2] + fc * wOffS[wi2];',
     'wsn = wSin[wi2];'),
    ('N-38', '方向场插值后不归一化（模长随位置变 ⇒ 方向会飘）', PIX,
     'var mm = Math.sqrt(sA * sA + cA * cA);', 'var mm = 1;'),
    ('N-39', '遮罩采样坐标不再转进波帧（亮块不沿波前拉长）', PIX,
     'var tanX = px * fc - py * fs;', 'var tanX = px;'),
    ('N-40', '关掉时走的原屏幕空间路径被破坏（逐位一致的保证没了）', PIX,
     'u1x * c1 - u1y * s1 + tq * p.patchDrift',
     'u1x + u1y + tq * p.patchDrift'),
    ('N-41', '像素块边长写死 2（pxBody 参数失效）', PIX,
     'var b1s = p.pxBody > 0 ? Math.min(SS, p.pxBody | 0) : 2;',
     'var b1s = 2;'),
    ('N-42', '浪尖方块边长写死 3（pxCrest 参数失效）', PIX,
     'var b2s = p.pxCrest > 0 ? Math.min(SS, p.pxCrest | 0) : 3;',
     'var b2s = 3;'),

    # ── E. 新档参数被改（观感直接变）───────────────────────────
    ('N-43', 'moonstone-tide 的 dirField 改成 0（方向场被关掉）', PIX,
     '        dirField: 2,', '        dirField: 0,'),
    ('N-44', 'moonstone-tide 的 dirFieldBase 改成 0.00', PIX,
     '        dirFieldBase: -0.30,', '        dirFieldBase: 0.00,'),
    ('N-45', 'moonstone-tide 的 dirFieldRange 改成 1.00（方向偏离太小）', PIX,
     '        dirFieldRange: 1.35,', '        dirFieldRange: 1.00,'),
    ('N-46', 'moonstone-tide 的 dirFieldDrift 改成 0.000（不漂移了）', PIX,
     '        dirFieldDrift: 0.012,', '        dirFieldDrift: 0.000,'),
    ('N-47', 'moonstone-tide 的 dirFieldStep 改成 24', PIX,
     '        dirFieldStep: 40,', '        dirFieldStep: 24,'),
    ('N-48', 'moonstone-tide 的 patchFollow 改成 0（遮罩不跟随波向）', PIX,
     '        patchFollow: 1,', '        patchFollow: 0,'),
    ('N-49', 'moonstone-tide 的 patchTangent 改成 1.00（不再沿波前拉长）', PIX,
     '        patchTangent: 0.13,', '        patchTangent: 1.00,'),
    ('N-50', 'moonstone-tide 的 patchNormal 改成 1.00', PIX,
     '        patchNormal: 0.85,', '        patchNormal: 1.00,'),
    ('N-51', 'moonstone-tide 的 pxBody 改成 0（退回 2px 噪点）', PIX,
     '        pxBody: 3,', '        pxBody: 0,'),
    ('N-52', 'moonstone-tide 的 pxCrest 改成 0', PIX,
     '        pxCrest: 3,', '        pxCrest: 0,'),
    ('N-53', 'moonstone-tide 的 lit 改成 0.15（亮度退回旧档）', PIX,
     '        lit: 0.21,', '        lit: 0.15,'),
    ('N-54', 'moonstone-tide 少一道波（4 道 → 3 道）', PIX,
     '          { k: 0.00760, om: 0.74, off: 1.30, dir:  0.33, w: 0.60 },\n',
     ''),
    ('N-55', 'moonstone-tide 的 dir 写成绝对角（0.33 → 0.93）', PIX,
     'dir:  0.33,', 'dir:  0.93,'),
    ('N-56', 'moonstone-swing 档被删（备选档没了）', PIX,
     "    'moonstone-swing': {", "    'moonstone-sw1ng': {"),
    # ↓ 这三条守的是「本轮实测才定下来的参数」，不是随手填的默认值。
    #   它们对应的退化最阴险：代码照样跑、fps 照样正常，
    #   只是画面悄悄从「弯曲的波浪」退回「一堆随机斑点」。
    ('N-74', '方向场变化变快（dirFieldScale 调大 ⇒ 采样坐标跳变 ⇒ 遮罩被打散）', PIX,
     '        dirFieldScale: 0.0011,', '        dirFieldScale: 0.0026,'),
    ('N-75', '法向噪声波长与波带同尺度（patchNormal2 调大 ⇒ 波带被切碎）', PIX,
     '        patchNormal2: 0.80,', '        patchNormal2: 1.20,'),
    ('N-76', '切向频率调大（patchTangent2 ⇒ 沿波前拉不开 ⇒ 亮块又变孤点）', PIX,
     '        patchTangent2: 0.42,', '        patchTangent2: 0.90,'),
    # ↓ 块状选取这三条：守的是「亮区是实心方块而不是雪花点」这条不变量。
    #   对应的退化最阴险：fps、亮格占比全都正常，
    #   只是画面从「一条条弯曲的浪」退回「等密度雪花点」。
    ('N-77', 'pickBlock 默认值从 0 改成 3（原版逐格随机被破坏 ⇒ 不传时行为变了）', PIX,
     '    pickBlock: 0,', '    pickBlock: 3,'),
    ('N-78', '块共享门槛被拆掉（si 恒等于逐格索引 ⇒ 退回雪花点）', PIX,
     'si = bx * 8191 + by;', 'si = i;'),
    ('N-79', 'moonstone-tide 的 pickBlock 改成 0（退回逐格随机 ⇒ 亮区成点阵）', PIX,
     '        pickBlock: 3,', '        pickBlock: 0,'),

    # ── F. 改版外溢到登录页 ──
    ('N-57', '登录页那一档的波速被改成门户参数（改版外溢）', PIX,
     '{ k: 0.00580, om: 0.504, off: 0.00, dir: -0.30, w: 1.00 }',
     '{ k: 0.00580, om: 0.958, off: 0.00, dir: -0.30, w: 1.00 }'),
    ('N-58', '登录页那一档被塞进晶向随机化参数', PIX,
     '        distortAmp: 0.85,\n',
     '        distortAmp: 0.85,\n        patchRot1: 0.22,\n'),

    # ── G. 接线 / 加载顺序 / 安全面 / 占位符 ──
    ('N-59', '门户退回 moonstone-swirl（用户点名否掉的那一档）', PJS,
     "createStyle(canvas, 'moonstone-tide', opt)",
     "createStyle(canvas, 'moonstone-swirl', opt)"),
    ('N-60', 'GhostFX 守卫被复活（变体引擎没了，守卫是死代码）', PJS,
     "  (function mountField() {\n    var canvas = document.getElementById('pix');",
     "  (function mountField() {\n    var canvas = document.getElementById('pix');\n"
     "    if (window.GhostFX) return;"),
    ('N-61', '门户传的亮度覆盖值与档位不一致', PJS,
     'params: { lit: 0.21 },', 'params: { lit: 0.15 },'),
    ('N-62', '脚本加载顺序对调（pixelfield.js 排到 portal.js 后面）', PHT,
     '<script src="{{STATIC_BASE}}pixelfield.js"></script>\n'
     '<script src="{{STATIC_BASE}}portal.js"></script>',
     '<script src="{{STATIC_BASE}}portal.js"></script>\n'
     '<script src="{{STATIC_BASE}}pixelfield.js"></script>'),
    ('N-63', 'CSP 被放宽（default-src 改 self）', GW,
     'CSP_PORTAL_HTML = (\n    "default-src \'none\';',
     'CSP_PORTAL_HTML = (\n    "default-src \'self\';'),
    ('N-64', 'CSP 被放宽（加 unsafe-inline）', GW,
     'CSP_PORTAL_HTML = (\n    "default-src \'none\'; script-src \'self\';',
     'CSP_PORTAL_HTML = (\n    "default-src \'none\'; script-src \'self\' \'unsafe-inline\';'),
    ('N-65', '门户页引入外部资源', PHT,
     '<title>服务门户 · Ghost Firewall</title>',
     '<title>服务门户 · Ghost Firewall</title>\n'
     '<script src="https://example.com/x.js"></script>'),
    ('N-66', '门户页塞进内联脚本', PHT,
     '<script src="{{STATIC_BASE}}fingerprint.js"></script>',
     '<script>alert(1)</script>\n'
     '<script src="{{STATIC_BASE}}fingerprint.js"></script>'),
    ('N-67', '门户页塞进内联样式属性', PHT,
     '<canvas class="pixfield" id="pix" aria-hidden="true"></canvas>',
     '<canvas class="pixfield" id="pix" aria-hidden="true" '
     'style="opacity:.5"></canvas>'),
    ('N-68', 'portal.js 拼 innerHTML（XSS）', PJS,
     "  (function mountField() {",
     "  (function mountField() {\n    var _x = ''; _x.innerHTML = 'x';"),
    ('N-69', 'pixelfield.js 语法错误', PIX,
     '(function (global) {', '(function (global {'),
    ('N-70', '不替换占位符（页面里的资源地址全是死链）', GW,
     'return html.replace(PORTAL_STATIC_BASE, static_base)',
     'return html'),
    ('N-71', '占位符常量与页面里写的不一致', GW,
     "PORTAL_STATIC_BASE = '{{STATIC_BASE}}'",
     "PORTAL_STATIC_BASE = '{{STATIC_ROOT}}'"),
    ('N-72', '认证服务注入的前缀不对', GW,
     "_read_portal_html('/auth/static/')",
     "_read_portal_html('/static/')"),
    ('N-73', '_read_portal_html 的默认基址被改（白名单直达路径会变死链）', GW,
     "def _read_portal_html(static_base='/auth/static/'):",
     "def _read_portal_html(static_base='/static/'):"),
]


def main():
    if not os.path.isfile(TEST_PY):
        print(f'!! 找不到测试文件 {TEST_PY}')
        return 2

    # 先确认原始状态下测试是绿的 —— 否则「变异被抓住」没有意义
    rc, out = run_tests()
    if rc != 0:
        print('!! 原始状态下测试就是红的，先修测试再跑变异：')
        print(out[-3000:])
        return 2
    print('原始状态：测试通过（%d 项）' % out.count('[PASS]'))

    caught, missed = 0, []
    for mid, desc, rel, old, new in MUTATIONS:
        restore()
        try:
            mutate(rel, old, new)
        except SystemExit as e:
            print(f'[脚本错] {mid} {desc}: {e}')
            missed.append(f'{mid} {desc}（变异脚本自身的错）')
            continue
        rc, out = run_tests()
        if rc != 0:
            caught += 1
            first = ''
            for line in out.splitlines():
                if '[FAIL]' in line:
                    first = line.strip()
                    break
            print(f'[捕获] {mid} {desc}  →  {first[:110]}')
        else:
            missed.append(f'{mid} {desc}')
            print(f'[漏网] {mid} {desc}  ← 测试没变红！')

    restore()

    print()
    print('=' * 60)
    print(f'  变异 {len(MUTATIONS)} 条，捕获 {caught} 条，漏网 {len(missed)} 条')
    if missed:
        print('  漏网的变异：')
        for m in missed:
            print('    - ' + m)
        return 1
    print('  全部捕获')
    return 0


if __name__ == '__main__':
    sys.exit(main())
