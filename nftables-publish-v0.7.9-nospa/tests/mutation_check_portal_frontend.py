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
  E  新档（moonstone-flow）参数被改 —— 几何必须与原版逐条一致
  E2 随机换向的机制（整圈目标角 / 短弧 / 限速）被拆掉
  E3 随机变速的机制（累计相位 / 变速率上限）被拆掉
  H  规整量化点阵被撤回（默认值被改 / 连续场判据 / 阈值抖动 / 绿白二选一 / 域扭曲）
  I  pixel-flow 新档被改或外溢到现有各档
  J  硬边改造被撤回（alpha 斜坡 / 余晖 / 迟滞 —— 必须三处同时改才有效）
  K  TRAE 式显式取样位移被撤回（默认值被改 / 位移拆掉 / 两层同尺度）
  L  压暗层被撤回（TRAE 纵向渐变 / 旧版开关 / 中间段不透明度）
  F  改版外溢到登录页
  G  安全面 / 加载顺序 / 占位符
  P  门户背景「原版 / TRAE 原版」随机两档（写死 / 少一档 / 覆盖失效）
  Q  面板（5443）像素场接线（引擎只有一份 / 画布 / 脚本 / 层级 / 候选表）

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
import shutil
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, 'backend', 'static')
BACKEND = os.path.join(ROOT, 'backend')
TEST_PY = os.path.join(ROOT, 'tests', 'test_portal_frontend.py')
TEST_JS = os.path.join(ROOT, 'tests', 'test_pixelfield_hardedge.js')
TEST_JS2 = os.path.join(ROOT, 'tests', 'test_pixelfield_trae.js')
TEST_JS3 = os.path.join(ROOT, 'tests', 'test_pixelfield_moonstone_trae.js')
TEST_JS4 = os.path.join(ROOT, 'tests', 'test_pixelfield_trae_orig.js')
TEST_JS5 = os.path.join(ROOT, 'tests', 'test_portal_bgstyle.js')
TEST_JS6 = os.path.join(ROOT, 'tests', 'test_panel_pixelbg.js')
TEST_PY2 = os.path.join(ROOT, 'tests', 'test_panel_frontend.py')
TEST_PY3 = os.path.join(ROOT, 'tests', 'test_fw_console.py')

# 本脚本会动的文件（只这些）
REL_FILES = [
    os.path.join('backend', 'static', 'base.css'),
    os.path.join('backend', 'static', 'pixelfield.js'),
    os.path.join('backend', 'static', 'portal.js'),
    os.path.join('backend', 'static', 'portal.html'),
    os.path.join('backend', 'auth_gateway.py'),
    # 面板侧（2026-11-04 第十三轮：面板也做一套像素场）
    os.path.join('backend', 'app.py'),
    os.path.join('frontend', 'index.html'),
    os.path.join('frontend', 'styles.css'),
    os.path.join('frontend', 'pixelbg.js'),
    os.path.join('frontend', 'app.js'),
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
    """跑本批次的测试文件（静态断言 + 行为级渲染断言）。

    两个都要跑：
      · test_portal_frontend.py     —— 源码文本断言（静态）
      · test_pixelfield_hardedge.js —— 真跑引擎、把画布像素读出来（行为级）
      · test_pixelfield_trae.js     —— 同上，专测 TRAE 原版复刻档的
                                        几何 / 颜色 / 密度

    ⚠ 行为级那个是这一批的关键（2026-11-03）：
      硬边是**渲染行为**（alpha 到底是不是两态、颜色到底几种），
      源码文本断言钉不住「画面有没有中间灰」——
      哪怕把斜坡改回另一个分支，文本断言照样全绿。
      ⇒ 变异必须能被**行为级**测试抓住才算数。

    返回 (rc, 输出)。

    ⚠️ 2026-11-04：各测试的超时从 300s 放宽到 600s（最慢那条从 600s 到 900s）。
       原因：全扫是**分片并行**跑的，6 核机器上 4~6 个分片同时扛 CPU，
       墙钟时间会被拉长 —— 上一轮就有 2 个分片因为「跑得慢被超时杀掉」
       而**整片退出**，剩下的变异一条没跑（当成「跑完了」其实没跑）。
       超时杀进程是把「慢」误判成「挂」；宁可多等，也别把没跑完的当跑完了。
    """
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    node = shutil.which('node')
    if not node:
        print('!! 找不到 node —— 行为级测试跑不了，变异无法验证')
        return 2, 'node not found in PATH'
    r = subprocess.run([sys.executable, TEST_PY],
                       capture_output=True, text=True, cwd=ROOT,
                       timeout=600, env=env)
    rc = r.returncode
    out = r.stdout + r.stderr
    if rc != 0:
        return rc, out
    r2 = subprocess.run([node, TEST_JS],
                        capture_output=True, text=True, cwd=ROOT,
                        timeout=600, env=env)
    if r2.returncode != 0:
        return r2.returncode, out + r2.stdout + r2.stderr
    r3 = subprocess.run([node, TEST_JS2],
                        capture_output=True, text=True, cwd=ROOT,
                        timeout=600, env=env)
    if r3.returncode != 0:
        return r3.returncode, out + r2.stdout + r2.stderr + r3.stdout + r3.stderr
    r4 = subprocess.run([node, TEST_JS3],
                        capture_output=True, text=True, cwd=ROOT,
                        timeout=600, env=env)
    if r4.returncode != 0:
        return r4.returncode, (out + r2.stdout + r2.stderr
                               + r3.stdout + r3.stderr + r4.stdout + r4.stderr)
    r5 = subprocess.run([node, TEST_JS4],
                        capture_output=True, text=True, cwd=ROOT,
                        timeout=900, env=env)
    if r5.returncode != 0:
        return r5.returncode, (out + r2.stdout + r2.stderr
                               + r3.stdout + r3.stderr + r4.stdout + r4.stderr
                               + r5.stdout + r5.stderr)
    # 门户背景「原版 / TRAE 原版」随机两档（2026-11-04 第十二轮）
    r6 = subprocess.run([node, TEST_JS5],
                        capture_output=True, text=True, cwd=ROOT,
                        timeout=600, env=env)
    if r6.returncode != 0:
        return r6.returncode, (out + r2.stdout + r2.stderr
                               + r3.stdout + r3.stderr + r4.stdout + r4.stderr
                               + r5.stdout + r5.stderr + r6.stdout + r6.stderr)
    # 面板侧像素场（2026-11-04 第十三轮）
    r7 = subprocess.run([node, TEST_JS6],
                        capture_output=True, text=True, cwd=ROOT,
                        timeout=600, env=env)
    if r7.returncode != 0:
        return r7.returncode, (out + r2.stdout + r2.stderr
                               + r3.stdout + r3.stderr + r4.stdout + r4.stderr
                               + r5.stdout + r5.stderr + r6.stdout + r6.stderr
                               + r7.stdout + r7.stderr)
    r8 = subprocess.run([sys.executable, TEST_PY2],
                        capture_output=True, text=True, cwd=ROOT,
                        timeout=600, env=env)
    if r8.returncode != 0:
        return r8.returncode, (out + r2.stdout + r2.stderr
                               + r3.stdout + r3.stderr + r4.stdout + r4.stderr
                               + r5.stdout + r5.stderr + r6.stdout + r6.stderr
                               + r7.stdout + r7.stderr + r8.stdout + r8.stderr)
    # ⚠️ 防火墙控制入口（2026-11-04 第十四轮 R 组）——
    #   R 组变异改的是 backend/app.py 里的「防火墙控制」预设与生成器，
    #   而覆盖它们的测试是 tests/test_fw_console.py。
    #   2026-11-04 实测：这一段**漏接** ⇒ R-02 / R-04 / R-06 / R-09 四条
    #   变异全部「漏网」（改了代码，测试照样全绿）。
    #   教训跟「东西不该出现」那类断言一样：
    #   **跑了什么测试，决定了哪些变异抓得到** ——
    #   变异清单里加了新组，就必须把对应的新测试接进 runner。
    r9 = subprocess.run([sys.executable, TEST_PY3],
                        capture_output=True, text=True, cwd=ROOT,
                        timeout=600, env=env)
    return r9.returncode, (out + r2.stdout + r2.stderr
                           + r3.stdout + r3.stderr + r4.stdout + r4.stderr
                           + r5.stdout + r5.stderr + r6.stdout + r6.stderr
                           + r7.stdout + r7.stderr + r8.stdout + r8.stderr
                           + r9.stdout + r9.stderr)


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
# 面板侧（2026-11-04 第十三轮）
APP = os.path.join('backend', 'app.py')
FINX = os.path.join('frontend', 'index.html')
FCSS = os.path.join('frontend', 'styles.css')
FPIX = os.path.join('frontend', 'pixelbg.js')
CSSF = os.path.join('backend', 'static', 'base.css')

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

    # ↓ 下面三条守的是「本轮实测才定下来的参数」，不是随手填的默认值。
    #   它们对应的退化最阴险：代码照样跑、fps 照样正常，
    #   只是画面悄悄从「一条条流动的浪」退回「一堆随机斑点」。
    ('N-74', '像素块边长被写死（pxBody 参数失效）', PIX,
     'var b1s = p.pxBody > 0 ? Math.min(SS, p.pxBody | 0) : 2;',
     'var b1s = 2;'),
    ('N-75', '块共享门槛被拆掉（si 恒等于逐格索引 ⇒ 退回雪花点）', PIX,
     'si = bx * 8191 + by;', 'si = i;'),
    ('N-76', '遮罩采样坐标不再转进波帧（亮块不沿波前拉长）', PIX,
     'var tanX = px * fc - py * fs;', 'var tanX = px;'),

    # ── E. 新档（moonstone-flow）参数被改（观感直接变）────────────────
    ('N-43', 'moonstone-flow 的 dirField 改成 0（方向场被关掉 ⇒ 退回固定方向）', PIX,
     '        dirField: 1,', '        dirField: 0,'),
    ('N-44', 'moonstone-flow 的 dirFieldBase 改成 0.00', PIX,
     '        dirFieldBase: -0.30,', '        dirFieldBase: 0.00,'),
    ('N-45', 'moonstone-flow 的 dirTurnPeriod 改成 0（关掉换向 ⇒ 退回固定方向）', PIX,
     '        dirTurnPeriod: 8,', '        dirTurnPeriod: 0,'),
    ('N-46', 'moonstone-flow 的 dirTurnRate 改成 0.60（转向太快 ⇒ 在甩不是在流）', PIX,
     '        dirTurnRate: 0.16,', '        dirTurnRate: 0.60,'),
    ('N-91', '换向周期拉长到 60 秒（换向太慢 ⇒ 等于没有随机方向）', PIX,
     '        dirTurnPeriod: 8,', '        dirTurnPeriod: 60,'),
    ('N-47', 'moonstone-flow 的 speedTurnPeriod 改成 0（关掉变速 ⇒ 恒定速度）', PIX,
     '        speedTurnPeriod: 6,', '        speedTurnPeriod: 0,'),
    ('N-48', 'moonstone-flow 的 speedRange 改成 0.00（幅度为 0 ⇒ 等于没随机速度）', PIX,
     '        speedRange: 0.55,', '        speedRange: 0.00,'),
    ('N-92', '变速率飙到 1.20 倍/秒（一秒内从极慢跳到极快 ⇒ 抽搐）', PIX,
     '        speedTurnRate: 0.18,', '        speedTurnRate: 1.20,'),
    ('N-49', 'moonstone-flow 的 lit 改成 0.21（密度翻倍 ⇒ 又变回一块块的纹理）', PIX,
     '        lit: 0.12,', '        lit: 0.21,'),
    ('N-50', 'moonstone-flow 少一道波（3 道 → 2 道）', PIX,
     '          { k: 0.00545, om: 0.454, off: 4.20, dir: -0.05, w: 0.78 },\n',
     ''),
    ('N-51', 'moonstone-flow 的 dir 写成绝对角（0.05 → 0.95）', PIX,
     'dir:  0.05,', 'dir:  0.95,'),
    ('N-52', 'moonstone-flow 档被删（门户背景没了）', PIX,
     "    'moonstone-flow': {", "    'moonstone-fl0w': {"),
    ('N-53', 'moonstone-flow 的 distortAmp 改成 1.25（扭曲变了 ⇒ 几何不再是原版）', PIX,
     '        distortAmp: 0.85,\n        dirField: 1,',
     '        distortAmp: 1.25,\n        dirField: 1,'),
    ('N-54', 'moonstone-flow 的波速改成 swirl 那一档（0.504 → 0.958）', PIX,
     '{ k: 0.00580, om: 0.504, off: 0.00, dir:  0.00, w: 1.00 }',
     '{ k: 0.00580, om: 0.958, off: 0.00, dir:  0.00, w: 1.00 }'),
    # ↓ 下面三条最关键：它们把「原版几何逐条照抄」这条保证从三个方向各打一次。
    ('N-55', 'moonstone-flow 被塞进 pxBody: 3（把「一块一块生成」的成因带回来）', PIX,
     '        dirPivot: 0,', '        dirPivot: 0,\n        pxBody: 3,'),
    ('N-56', 'moonstone-flow 被塞进 pickBlock: 3（亮区变实心方块 ⇒ 纹理感）', PIX,
     '        dirPivot: 0,', '        dirPivot: 0,\n        pickBlock: 3,'),
    ('N-79', 'moonstone-flow 被塞进 patchFollow: 1（遮罩跟波向 ⇒ 不再是原版观感）', PIX,
     '        dirPivot: 0,', '        dirPivot: 0,\n        patchFollow: 1,'),

    # ── E2. 随机换向 / 随机变速的机制（2026-11-03）─────────────────
    ('N-80', '目标角不再在整圈上均匀抽样（缩到一小段弧 ⇒ 又变回只朝一个方向）',
     PIX,
     'dirTarget = rnd(did * 7919 + 13, 1013904223) * 6.2831853;',
     'dirTarget = rnd(did * 7919 + 13, 1013904223) * 0.9 - 0.45;'),
    ('N-81', '转向不再走短弧（为了 350° 的差别会绕远路 ⇒ 转得又慢又别扭）', PIX,
     'while (tdiff > Math.PI) tdiff -= 6.2831853;',
     'while (tdiff > Math.PI * 3) tdiff -= 6.2831853;'),
    ('N-82', '转向限速失效（dirTurnRate 不再是上限 ⇒ 一步到位 ⇒ 画面硬拐）', PIX,
     'var tmax = p.dirTurnRate > 0 ? p.dirTurnRate * geoDt : 1e9;',
     'var tmax = 1e9;'),
    ('N-83', '随机换向路径被删（只剩噪声切片老路径 ⇒ 方向又挤在一小段）', PIX,
     'dang = dirAng + p.dirSwing * Math.sin(swingT);',
     'dang = dbase + dn * drg;'),
    ('N-84', '旋转中心从画布中心挪到四分之一处（转心不对 ⇒ 流速不均）', PIX,
     'pivX = w * 0.5; pivY = h * 0.5;', 'pivX = w * 0.25; pivY = h * 0.25;'),
    ('N-85', '旋转中心不再受 useField 约束（dirField=0 的档也被改 ⇒ 破坏逐位一致）', PIX,
     'if (useField && p.dirPivot > 0) { pivX = w * 0.5; pivY = h * 0.5; }',
     'if (p.dirPivot > 0) { pivX = w * 0.5; pivY = h * 0.5; }'),
    ('N-86', '法线坐标里的旋转中心被丢掉（dirPivot 参数失效）', PIX,
     'var uy = (px - pivX) * wsn + (py - pivY) * wcn;',
     'var uy = px * wsn + py * wcn;'),
    ('N-87', 'dirTurnPeriod 默认值从 0 改成 8（不传时行为变了 ⇒ 破坏逐位一致）', PIX,
     '    dirTurnPeriod: 0,', '    dirTurnPeriod: 8,'),
    ('N-93', 'speedTurnPeriod 默认值从 0 改成 6（不传时行为变了 ⇒ 破坏逐位一致）', PIX,
     '    speedTurnPeriod: 0,', '    speedTurnPeriod: 6,'),
    ('N-88', 'dirPivot 默认值从 0 改成 1（不传时行为变了 ⇒ 破坏逐位一致）', PIX,
     '    dirPivot: 0,\n    /* ── 遮罩跟随波向',
     '    dirPivot: 1,\n    /* ── 遮罩跟随波向'),
    ('N-89', 'debug() 不再报引擎真值方向角（证据图只能另算公式 ⇒ 会与实际不符）', PIX,
     'dirAngle: dirAngleNow, dirAngleDeg: dirAngleNow * 180 / Math.PI,',
     'dirAngle: 0, dirAngleDeg: 0,'),
    ('N-90', '当前方向角不再每个几何步更新（一直停在初始值）', PIX,
     'dirAngleNow = dang;', '/* dirAngleNow 不更新 */'),

    # ── E3. 随机变速的机制（累计相位）────────────────────────────
    ('N-94', '累计相位退化成闭式 om*t（速度一变波前就跳 ⇒ 画面闪一下）', PIX,
     'var ph = wv.k * uy - (useSpeedWalk ? wPh[wi2] : wv.om * tq)',
     'var ph = wv.k * uy - wv.om * tq'),
    ('N-95', '累计相位推进时丢掉了速度倍率（变速完全不起作用）', PIX,
     'wPh[spi] += waves[spi].om * spdF * geoDt;',
     'wPh[spi] += waves[spi].om * geoDt;'),
    ('N-96', '累计相位初始化不对齐闭式 om*t（启用瞬间波前跳一下）', PIX,
     'wPh[sgi] = waves[sgi].om * tq;', 'wPh[sgi] = 0;'),
    ('N-97', '推进间隔改用 p.step（标签页隐藏后相位会慢一大截）', PIX,
     'var geoDt = tq - lastGeomT;', 'var geoDt = p.step;'),
    ('N-98', '变速限速失效（speedTurnRate 不再是上限 ⇒ 一秒内极慢↔极快）', PIX,
     'var smax = p.speedTurnRate > 0 ? p.speedTurnRate * geoDt : 1e9;',
     'var smax = 1e9;'),
    ('N-99', '速度目标幅度被忽略（speedRange 失效 ⇒ 速度恒为 1.0）', PIX,
     'spdTarget = 1 + (rnd(sid * 104729 + 13, 22695477) * 2 - 1) * p.speedRange;',
     'spdTarget = 1;'),
    ('N-100', 'debug() 不再报速度倍率（证据图只能另算公式）', PIX,
     'speedFactor: spdF, dirTarget: dirTarget,',
     'speedFactor: 1, dirTarget: dirTarget,'),
    ('N-101', '累计相位用单精度存（Float32 丢末位 ⇒ 破坏「逐位一致」）', PIX,
     'var wPh = new Float64Array(8);', 'var wPh = new Float32Array(8);'),

    # ── H. 规整量化点阵被撤回（借鉴 TRAE 那一批，2026-11-03）──────
    # 这一批做的是「独立一档 + 若干新参数」，危险退化跟上一批同型：
    # 把新参数默认值改成非 0 ⇒ 破坏「不传时逐位一致」；
    # 把新机制拆掉 ⇒ 画面悄悄退回「一堆随机散点」，代码照样跑、单测容易全绿。
    ('N-102', 'pixelQuant 默认值从 0 改成 1（不传也走量化 ⇒ 破坏逐位一致）', PIX,
     '    pixelQuant: 0,', '    pixelQuant: 1,'),
    ('N-103', 'pixelThresh 默认值从 0 改成 0.76（不传也套 TRAE 的阈值）', PIX,
     '    pixelThresh: 0.0,', '    pixelThresh: 0.76,'),
    ('N-104', 'pixelBlend 默认值从 0 改成 1（不传也走连续插值）', PIX,
     '    pixelBlend: 0,          /* 0 = 两档色叠加',
     '    pixelBlend: 1,          /* 0 = 两档色叠加'),
    ('N-105', 'pixelGreen 默认值从 0 改成 0.49（不传也做绿白二选一）', PIX,
     '    pixelGreen: 0,', '    pixelGreen: 0.49,'),
    ('N-106', 'pixelJitter 默认值从 0 改成 0.36（不传也抖阈值）', PIX,
     '    pixelJitter: 0,', '    pixelJitter: 0.36,'),
    ('N-107', 'columns 默认值从 0 改成 190（不传就加密网格 ⇒ 破坏逐位一致）', PIX,
     '    columns: 0,', '    columns: 190,'),
    ('N-108', 'flowDensity 默认值从 0 改成 0.25（不传也启用流场）', PIX,
     '    flowDensity: 0,', '    flowDensity: 0.25,'),
    ('N-109', 'flowWarp 默认值从 0 改成 0.50（不传就域扭曲）', PIX,
     '    flowWarp: 0,', '    flowWarp: 0.50,'),
    ('N-110', 'flowSpeed 默认值从 0 改成 0.020（不传就漂移）', PIX,
     '    flowSpeed: 0,', '    flowSpeed: 0.020,'),
    ('N-111', '网格密度忽略 p.columns（档位定不动密度了）', PIX,
     'var COLUMNS = p.columns > 0 ? (p.columns | 0) : (opt.columns || 112);',
     'var COLUMNS = opt.columns || 112;'),
    ('N-112', '量化判据退回每格随机门槛（亮点变回随机散点）', PIX,
     'if (qf > qth) {', 'if (mask > qth) {'),
    ('N-113', '阈值的按块随机抖动被删（边缘变成一刀切的光滑轮廓）', PIX,
     'if (p.pixelJitter > 0) qth -= p.pixelJitter * rSel[idx];',
     '/* 抖动被删 */'),
    ('N-114', '绿白二选一改成永远绿（白块消失，绿占比 100%）', PIX,
     'if (rSel[idx] < p.pixelGreen) {', 'if (true) {'),
    ('N-115', '量化模式又画两层（把二选一的颜色冲成白色）', PIX,
     'if (!blend && !greenBin && a2 > 0.002) {', 'if (!blend && a2 > 0.002) {'),
    ('N-116', '量化模式下伺服不再跳过（伺服空转，把 pickGain 顶到上限）', PIX,
     'if (p.pixelQuant > 0) return 0;', '/* 不再跳过 */'),
    ('N-117', '量化模式下仍保留每格抖动偏移（点阵又变回随机疏密）', PIX,
     'var off = quant ? 0\n'
     '            : (Math.sin(t * dRate + dphase[idx]) * dth + rJit[idx] * jitAmp);',
     'var off = (Math.sin(t * dRate + dphase[idx]) * dth + rJit[idx] * jitAmp);'),
    # ⚠ 2026-11-03 第十轮：流场计算被抽成共用函数 flowValAt（量化档与合档共用），
    #   锚点跟着改。
    ('N-118', '域扭曲被拆掉（流场退化成轴对齐的方块簇）', PIX,
     'return sample(tex, NOISE_N, uf + qxq * p.flowWarp, vf + qyq * p.flowWarp);',
     'return sample(tex, NOISE_N, uf, vf);'),
    ('N-119', '流场开关恒为假（流场代码成了死代码）', PIX,
     'var useFlow = p.flowDensity > 0 && (p.pixelQuant > 0 || p.flowMask > 0);',
     'var useFlow = false;'),
    ('N-120', 'pixel-flow 档被改掉名字（整档找不到了）', PIX,
     "    'pixel-flow': {", "    'pixel-flowX': {"),
    ('N-121', 'pixel-flow 用了 gate 色板（青绿↔白双色没了）', PIX,
     "      palette: 'mint',", "      palette: 'gate',"),
    ('N-122', 'mint 色板的强调色被改（不再是 TRAE 的 #32F08C）', PIX,
     'accent: [50, 240, 140]', 'accent: [50, 200, 140]'),
    ('N-123', 'pixel-flow 的阈值被改（密度对不上 TRAE）', PIX,
     'pixelThresh: 0.88,', 'pixelThresh: 0.87,'),
    ('N-124', 'pixel-flow 的域扭曲强度被改（形状退回方块簇）', PIX,
     'flowWarp: 0.50,', 'flowWarp: 0.10,'),
    ('N-125', 'pixel-flow 的阈值抖动被改（绿白比完全对不上 TRAE）', PIX,
     'pixelJitter: 0.36,', 'pixelJitter: 0.12,'),
    ('N-126', 'pixel-flow 的 accentT 被改（点又变暗）', PIX,
     'accentT: 0.08,', 'accentT: 0.30,'),
    ('N-127', '量化外溢到 moonstone 档（登录页背景被顺带改了）', PIX,
     '        distortAmp: 0.85,\n      },',
     '        distortAmp: 0.85,\n        pixelQuant: 1,\n      },'),
    ('N-128', '量化外溢到 moonstone-flow 档（现有门户档被顺带改了）', PIX,
     '        lit: 0.12,\n      },', '        lit: 0.12,\n        pixelQuant: 1,\n      },'),
    ('N-129', '量化外溢到 moonstone-swirl 档（回退档被顺带改了）', PIX,
     '        patchRot1: 0.22,', '        patchRot1: 0.22,\n        pixelQuant: 1,'),
    ('N-130', '量化外溢到 gate 档（产品默认档被顺带改了）', PIX,
     "      palette: 'gate',\n      params: {},",
     "      palette: 'gate',\n      params: { pixelQuant: 1 },"),
    ('N-131', 'pixel-flow 档默认改用连续插值（TRAE 的按块二选一被换掉）', PIX,
     '        pixelBlend: 0,\n', '        pixelBlend: 1,\n'),

    # ── J. 硬边改造被撤回（2026-11-03，用户要求「要么亮，要么不亮」）──
    # 用户原话：「我看目前有一些灰度和亮的交接，类似于水打上去的印记一样，
    #           我想要么亮，要么不亮，分界明显一点」。
    #
    # 这一批把柔边三件套在**量化模式**下全部关掉：
    #   ① alpha 斜坡 → 硬开关 a1 = vv > tLo1 ? 1 : 0
    #   ② 余晖衰减   → 不留痕  e = quant ? band : ...
    #   ③ 迟滞限速   → 整段跳过 if (!quant)
    #
    # ⚠ 这三处**必须同时改**：只改 ① 的话余晖会把刚熄灭的点继续顶在
    #   阈值之上 ⇒ 硬边做不出来。所以每一条单独撤回都要能被抓到。
    #   ①③ 靠行为级测试抓（alpha 集合里冒出中间灰）；
    #   ② 不改 alpha 的取值域，只改「哪一格亮着」⇒ 靠不变性抓
    #      （量化模式下改 trail 后画面必须一字节不差）。
    ('N-132', '量化模式又留起余晖（熄灭的点被顶在阈值之上 ⇒ 硬边做不出来）', PIX,
     'var e = quant ? band : (band > prev ? band : prev * p.trail);',
     'var e = (band > prev ? band : prev * p.trail);'),
    ('N-133', '量化模式又用回 alpha 斜坡（灰度过渡回来 ⇒ 水印记重现）', PIX,
     'a1 = vv > tLo1 ? 1 : 0;',
     'a1 = (vv - tLo1) / fade;\n'
     '            if (a1 < 0) a1 = 0; else if (a1 > 1) a1 = 1;'),
    ('N-134', '量化模式又用回迟滞（1→0 被压成 1→0.965 ⇒ 又变灰度）', PIX,
     'if (!quant) {', 'if (true) {'),

    # ── K. TRAE 式显式取样位移被撤回（2026-11-03 点位规律逆向）──────
    # 起因：实测证明 TRAE 的点**从来不移动**（trae-lattice.js：亮像素 100%
    # 落在 7px 晶格的 5×5 格实体内、6 帧相位恒为 (1,3)）。
    # 动的是「每格去哪儿取色」⇒ 引擎必须拆成「颜色场 + 位移场」两层。
    #
    # 危险退化同型：把新参数默认值改成非 0 ⇒ 破坏「不传时逐位一致」；
    # 把位移拆掉 ⇒ 画面悄悄退回「一层场」，代码照样跑、单测容易全绿。
    ('N-135', 'fieldDensity 默认值从 0 改成 0.125（不传就改颜色场尺度）', PIX,
     '    fieldDensity: 0,', '    fieldDensity: 0.125,'),
    ('N-136', 'flowDispX 默认值从 0 改成 10（不传就有横向位移）', PIX,
     '    flowDispX: 0,', '    flowDispX: 10,'),
    ('N-137', 'flowDispY 默认值从 0 改成 70（不传就有纵向位移）', PIX,
     '    flowDispY: 0,', '    flowDispY: 70,'),
    ('N-138', '位移改成双向抖动（去掉 +1 再 /2 ⇒ 抖动，不是 TRAE 的单向拖曳）', PIX,
     'du = (dbx + 1) * 0.5 * p.flowDispX / w;',
     'du = dbx * p.flowDispX / w;'),
    ('N-139', '位移场改用颜色场的尺度（两层同尺度 ⇒ 采到同一片噪声、互相抵消）', PIX,
     'var ub = sxq * p.flowDensity, vb = syq * p.flowDensity;',
     'var ub = sxq * Df, vb = syq * Df;'),
    ('N-140', '颜色场不在位移后的位置求值（点就跟着内容一起动了 ⇒ 不是 TRAE）', PIX,
     'var uf = (sxq - du) * Df, vf = (syq - dv) * Df;',
     'var uf = sxq * Df, vf = syq * Df;'),
    ('N-141', '位移分支整个跳过（位移成了死代码）', PIX,
     'var useDisp = (p.flowDispX > 0 || p.flowDispY > 0);',
     'var useDisp = false;'),
    ('N-142', 'pixel-flow 的 flowDensity 被改（0.375 是 TRAE density 1.5 的换算值）', PIX,
     'flowDensity: 0.375,', 'flowDensity: 0.25,'),
    ('N-143', 'pixel-flow 的 fieldDensity 被改（两层尺度必须不同）', PIX,
     'fieldDensity: 0.125,', 'fieldDensity: 0.375,'),
    ('N-144', 'pixel-flow 的横向位移被关掉', PIX,
     'flowDispX: 10,', 'flowDispX: 0,'),
    ('N-145', 'pixel-flow 的纵向位移被关掉', PIX,
     'flowDispY: 70,', 'flowDispY: 0,'),

    # ── L. 压暗层被撤回（TRAE 纵向渐变 + 开关）───────────────────
    ('N-146', '压暗层退回旧版的 radial 叠加（TRAE 的纵向渐变被换掉）', CSSF,
     '  background: linear-gradient(\n'
     '    var(--scrim-c) var(--scrim-a),\n'
     '    var(--scrim-m) var(--scrim-b),\n'
     '    var(--scrim-m) var(--scrim-d),\n'
     '    var(--scrim-c) 100%);',
     '  background: radial-gradient(58% 48% at 34% 20%,\n'
     '    rgba(10, 10, 11, .94) 0%, rgba(10, 10, 11, .22) 100%);'),
    ('N-147', '压暗层的旧版开关被删（切不回去了）', CSSF,
     'body.pix-scrim-legacy .pix-scrim {', 'body.pix-scrim-legacy2 .pix-scrim {'),
    ('N-148', '压暗层中间段的不透明度被改（不再是 TRAE 的 60%）', CSSF,
     '  --scrim-m: rgba(12, 12, 12, .6);', '  --scrim-m: rgba(12, 12, 12, .9);'),

    # ── F. 改版外溢到登录页 ──
    ('N-57', '登录页那一档的波速被改成门户参数（改版外溢）', PIX,
     '{ k: 0.00580, om: 0.504, off: 0.00, dir: -0.30, w: 1.00 }',
     '{ k: 0.00580, om: 0.958, off: 0.00, dir: -0.30, w: 1.00 }'),
    ('N-58', '登录页那一档被塞进晶向随机化参数', PIX,
     '        distortAmp: 0.85,\n      },',
     '        distortAmp: 0.85,\n        patchRot1: 0.22,\n      },'),

    # ── G. 接线 / 加载顺序 / 安全面 / 占位符 ──
    # ⚠ 2026-11-03 第十轮：门户切到「月白·TRAE」合档，锚点跟着改。
    # ⚠ 2026-11-04 第十二轮：门户改成「原版 / TRAE 原版」随机两档，
    #   锚点跟着改（不再有写死的档名可替换）。
    ('N-59', '门户退回 moonstone-swirl（用户点名否掉的那一档）', PJS,
     "createStyle(canvas, pickBgStyle(), opt)",
     "createStyle(canvas, 'moonstone-swirl', opt)"),
    ('N-60', 'GhostFX 守卫被复活（变体引擎没了，守卫是死代码）', PJS,
     "  (function mountField() {\n    var canvas = document.getElementById('pix');",
     "  (function mountField() {\n    var canvas = document.getElementById('pix');\n"
     "    if (window.GhostFX) return;"),
    ('N-61', '门户自己传 lit（opt.params 会盖掉档位里的值）', PJS,
     '      var opt = {\n        static: reduce,\n      };',
     '      var opt = {\n        params: { lit: 0.21 },\n'
     '        static: reduce,\n      };'),
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

    # ── M. TRAE 原版复刻被撤回（2026-11-03）────────────────────
    # 这一批是「把 TRAE 首页背景的两段 GLSL 逐行移植进引擎」。
    # 最危险的退化是**看起来还像那么回事**的：晶格差 1px、阈值差 0.01、
    # 颜色少做一次 sRGB 编码 —— 画面照样有形状，肉眼未必立刻发现。
    ('M-01', 'traeMode 默认值被改成 1（破坏「不传时逐位一致」）', PIX,
     'traeMode: 0,', 'traeMode: 1,'),
    ('M-02', '晶格周期 7 改成 6（TRAE 是 5px 点 + 2px 间隙 = 7px）', PIX,
     'var TR_CELL = 7;', 'var TR_CELL = 6;'),
    ('M-03', '方块边长 5 改成 4（TRAE 的 pixelSize 是 5）', PIX,
     'var TR_DOT = 5;', 'var TR_DOT = 4;'),
    ('M-04', '阈值 0.87 改成 0.5（密度会暴涨）', PIX,
     'var TR_THR = 0.87;', 'var TR_THR = 0.5;'),
    ('M-05', '绿占比 0.49 改成 0.9（几乎全绿）', PIX,
     'var TR_GREEN = 0.49;', 'var TR_GREEN = 0.9;'),
    ('M-06', '阈值抖动 0.08 改成 0（TRAE 用同一个 rand 两处用）', PIX,
     'var TR_JIT = 0.08;', 'var TR_JIT = 0;'),
    ('M-07', '亮度公式改成 0.5 + 0.5*n（颜色空间错了 ⇒ 密度与颜色都偏）', PIX,
     'var bright = 0.562 + 0.438 * nAt;', 'var bright = 0.5 + 0.5 * nAt;'),
    ('M-08', '输出不做过 sRGB 编码（绿会变成 50,240,140 ⇒ 整体暗一档）', PIX,
     'var R = TRAE.enc(cr), G = TRAE.enc(cg), B = TRAE.enc(cb);',
     'var R = (cr * 255) | 0, G = (cg * 255) | 0, B = (cb * 255) | 0;'),
    ('M-09', 'v 轴翻转被去掉（画面上下颠倒）', PIX,
     'v = 1 - (tGy0 + gy * tGrid) / h;', 'v = (tGy0 + gy * tGrid) / h;'),
    ('M-10', 'blockId.y 方向反了（点阵上下颠倒）', PIX,
     'var by = tRows - 1 - cy;', 'var by = cy;'),
    ('M-11', 'rand 公式被改（绿白分布不再是 TRAE 那套）', PIX,
     'var r = TRAE.fract(Math.sin(cx * 12.9898 + by * 78.233) * 43758.5453123);',
     'var r = TRAE.fract(Math.sin(cx * 7.1 + by * 3.3) * 43758.5453123);'),
    ('M-12', '两条时间轴被合成一条（像素化层速度翻倍）', PIX,
     'var s = t * 0.5 * TR_FSPEED;', 'var s = t * TR_FSPEED;'),
    ('M-13', '位移场 ×35 改成 ×1（取样位置不对 ⇒ 形状完全变了）', PIX,
     'var TR_FSCALE = 35;', 'var TR_FSCALE = 1;'),
    ('M-14', 'traeMouse 默认值被改成 1（老档也会挂指针监听）', PIX,
     'traeMouse: 0,', 'traeMouse: 1,'),
    ('M-15', 'trae 档的 traeMode 被关掉（门户背景退回旧算法）', PIX,
     '        traeMode: 1,\n        traeGrid: 16,',
     '        traeMode: 0,\n        traeGrid: 16,'),
    ('M-16', 'trae 配色的绿被改成 50,240,140（编码前的值 ⇒ 整体暗一档）', PIX,
     'trae:      { bg: [0, 0, 0],       accent: [122, 248, 196], white: [255, 255, 255], bloom: [70, 200, 140] },',
     'trae:      { bg: [0, 0, 0],       accent: [50, 240, 140], white: [255, 255, 255], bloom: [70, 200, 140] },'),
        # ⚠ 2026-11-03 第十轮：门户已切到「月白·TRAE」合档 ⇒
    #   「门户不用 trae 档」这条的前提没了（M-27 覆盖「门户不用合档」）。
    #   这条改成守另一种综合方式：独当构图（波带不参与）。
    ('M-17', '合档改成独当构图（flowSolo 0 → 1，波带不参与）', PIX,
     '        flowSolo: 0,', '        flowSolo: 1,'),
    ('M-18', 'TRAE 分支的渲染被绕过（门户背景变成一片空白）', PIX,
     'if (p.traeMode > 0) { renderTrae(t); return; }',
     'if (false) { renderTrae(t); return; }'),
    ('M-19', 'TRAE 分支的几何被绕过（退回老路径 ⇒ 不是 TRAE 的画面）', PIX,
     'if (p.traeMode > 0) { renderTrae(t); return; }',
     'if (p.traeMode > 0) { computeTrae(stepIdx * p.step); return; }'),
    # ⚠ 2026-11-04 第十一轮：鼠标影响因子被抽成了共用函数 tMouseFactor()
    #   （TRAE 原版与新档共用一段）⇒ 锚点跟着改。
    ('M-20', '鼠标影响因子被拆掉（指针附近不再泛绿）', PIX,
     '      return (1 - stt * stt * (3 - 2 * stt)) * TR_MS;', '      return 0;'),
    # ── S. 月白·TRAE 合档（2026-11-03 第十轮）────────────────────
    # 用户原话：「方块使用我们现在网关用的方案（原方案），
    #   然后流动保留trae的流动方案」
    ('M-21', '合档的 flowMask 被关掉（遮罩源退回原方案两层噪声 ⇒ 没有 TRAE 的流动）',
     PIX, '        flowMask: 1,', '        flowMask: 0,'),
    ('M-22', '合档的流场切点被改（0.68 → 0.30 ⇒ 亮区糊成一大片）',
     PIX, '        flowThresh: 0.68,', '        flowThresh: 0.30,'),
    ('M-23', '合档的流场软边被改（0.30 → 0.02 ⇒ 硬切 ⇒ 方块变成实心团）',
     PIX, '        flowSoft: 0.30,', '        flowSoft: 0.02,'),
    ('M-24', '流场开关又被锁回量化档（合档拿不到流体场）',
     PIX,
     'var useFlow = p.flowDensity > 0 && (p.pixelQuant > 0 || p.flowMask > 0);',
     'var useFlow = p.pixelQuant > 0 && p.flowDensity > 0;'),
    ('M-25', '合档的遮罩切换整段被删（退回两层旋转值噪声）',
     PIX,
     'mask = sstep(fmTh - fmSf, fmTh + fmSf, fv);',
     'mask = m1 * m2;'),
    ('M-26', '独当模式的 band = 1 被删（flowSolo 不起作用）',
     PIX, '            if (solo) band = 1;', '            if (false) band = 1;'),
    ('M-27', '门户退回被否掉的合档 moonstone-trae', PJS,
     "createStyle(canvas, pickBgStyle(), opt)",
     "createStyle(canvas, 'moonstone-trae', opt)"),
    # ⚠ 锚点必须**唯一**：裸 'palette: \'moonstone\'' 在 moonstone-flow 里也有，
    #   而 mutate() 替换的是**第一个**匹配 ⇒ 会改错档。带上 label 才唯一。
    ('M-28', '合档被改成 TRAE 的绿白配色（不是月白了）', PIX,
     "      label: '月白·TRAE',\n      note: '原方案的方块（随机疏密/明暗参差/尾部渐隐）+ TRAE 的域扭曲流动。月白银白。',\n      palette: 'moonstone',",
     "      label: '月白·TRAE',\n      note: '原方案的方块（随机疏密/明暗参差/尾部渐隐）+ TRAE 的域扭曲流动。月白银白。',\n      palette: 'trae',"),
    # ── T. 「TRAE·原版方块」新档（2026-11-04 第十一轮）──────────
    # 用户原话：「以 trae 原版为基础……里面的方块方案改一下，
    #   改成我们原版方案，其他一律不动」
    # ⇒ 这批最危险的退化是「改回原样」：底座悄悄换回原方案、
    #   或者方块悄悄换回 TRAE 的硬边 ⇒ 画面看着差不多，其实不是那一档。
    ('T-01', '新档的方块层开关被关掉（退回 TRAE 原版的绿白硬边）', PIX,
     '        traeBlocks: 1,', '        traeBlocks: 0,'),
    ('T-02', '新档的配色被换成 TRAE 的绿白（不是月白银白）', PIX,
     "      palette: 'moonstone-trae',", "      palette: 'trae',"),
    ('T-03', '引擎的方块模式分支被跳过（又画成 TRAE 原版）', PIX,
     '      if (tBlocks) { renderTraeBlocks(t); return; }',
     '      if (tBlocks) { renderTrae(t); return; }'),
    ('T-04', '方块模式的晶格被换回 TRAE 的 7px（不是原方案的 12px）', PIX,
     '        tCell = SS * Math.max(2, Math.round(w / COLUMNS / SS));',
     '        tCell = TR_CELL;'),
    ('T-05', '方块模式的余晖被删（尾巴不褪了）', PIX,
     '          var e = band > prev ? band : prev * p.trail;',
     '          var e = band;'),
    ('T-06', '方块模式的迟滞被删（卡在阈值上的格子会闪）', PIX,
     '          if (a1 < tA1Prev[idx]) {', '          if (false) {'),
    ('T-07', '方块模式的软门被换成硬切（点会「啪」地蹦出来）', PIX,
     '            var sel = (pOn + psoft - tSel[idx]) / psoft;',
     '            var sel = pOn > 0 ? 1 : 0;'),
    ('T-08', '方块模式每格的随机亮度被去掉（明暗参差没了）', PIX,
     '            if (sel > 0) band = sel * ((1 - p.jitterAmp) + p.jitterAmp * tAmp[idx]);',
     '            if (sel > 0) band = sel;'),
    ('T-09', '方块模式的亮度来源被换掉（不再是 TRAE 的 0.562+0.438n）', PIX,
     '          var bright = 0.562 + 0.438 * nAt;', '          var bright = nAt;'),
    ('T-10', '方块模式的密度伺服被摘掉（密度钉死在初始值）', PIX,
     '        servoStep(stats.litInBand, false);\n      }\n\n'
     '      /* 清单换成这一帧画过的格（下一帧拿它擦旧点） */',
     '      }\n\n'
     '      /* 清单换成这一帧画过的格（下一帧拿它擦旧点） */'),
    ('T-11', '新档的余晖参数被改（原方案是 0.80）', PIX,
     '        trail: 0.80,', '        trail: 0.40,'),
    ('T-12', '新档的密度目标被改（原方案是 0.10）', PIX,
     '        lit: 0.10,', '        lit: 0.30,'),

    # ── P. 「原版 / TRAE 原版」随机两档（2026-11-04 第十二轮）──
    # 用户原话：「我们就按照原版和原版trae打开随机显示吧」
    # ⇒ 这批最危险的退化是「随机看着在、其实没随机」：
    #   写死第一个、写死最后一个、候选表少一档、两档对调、URL 覆盖失效 ——
    #   这些退化**页面上完全看不出异常**（背景照常画、照常动），
    #   只有行为级测试（tests/test_portal_bgstyle.js）能抓住。
    #   ⇒ 这组变异就是给那个测试的「杀虫剂」。
    ('P-01', '随机被写死成第一个（永远显示原版）', PJS,
     'return BG_STYLES[Math.floor(Math.random() * BG_STYLES.length)];',
     'return BG_STYLES[0];'),
    ('P-02', '随机被写死成最后一个（永远显示 TRAE 原版）', PJS,
     'return BG_STYLES[Math.floor(Math.random() * BG_STYLES.length)];',
     'return BG_STYLES[BG_STYLES.length - 1];'),
    ('P-03', '候选表少一档（只剩原版 ⇒ 随机名存实亡）', PJS,
     "var BG_STYLES = ['moonstone', 'trae'];",
     "var BG_STYLES = ['moonstone'];"),
    ('P-04', '候选表少一档（只剩 TRAE 原版）', PJS,
     "var BG_STYLES = ['moonstone', 'trae'];",
     "var BG_STYLES = ['trae'];"),
    ('P-05', 'URL 覆盖被忽略（?pfstyle= 钉不住某一档）', PJS,
     "    var want = queryParam('pfstyle');\n    if (want) {",
     "    var want = '';\n    if (want) {"),
    ('P-06', 'URL 里写错档名也不回退（把不存在的档位传给引擎）', PJS,
     '      for (var i = 0; i < BG_STYLES.length; i++) {\n'
     '        if (BG_STYLES[i] === want) return want;\n'
     '      }',
     '      return want;'),
    ('P-07', '挑出来的档位没传给引擎（永远用原版）', PJS,
     'window.GhostPixelField.createStyle(canvas, pickBgStyle(), opt);',
     "window.GhostPixelField.createStyle(canvas, 'moonstone', opt);"),
    ('P-08', '两档顺序被对调（random=0 与 random≈1 落反了）', PJS,
     "var BG_STYLES = ['moonstone', 'trae'];",
     "var BG_STYLES = ['trae', 'moonstone'];"),

    # ── R. 防火墙控制入口（2026-11-04 第十四轮）────────────────
    # 用户原话：「5443 能不能以一种开关的形式，开放到门户里？
    #   也就是 8443 里面登录后，可以直接进入防火墙控制」
    # ⇒ 复用反代规则（enabled 就是开关）+ 网关内反代 /fw/ + 仅内网。
    #
    # 这批最危险的退化全是**静默**的：
    #   · 面板判来源 IP 时不信 X-Real-IP ⇒ 面板自己的网段限制被绕过，
    #     而界面上看不出任何异常（规则照样「已启用」）
    #   · 预设规则的 public_access 变 true ⇒ 面板从「无公网入口」变成公网可达
    #   · 两处路径改写被摘掉 ⇒ 页面能开、数据与字体全 404
    #   · 生成器忽略 target_protocol ⇒ 上游 HTTPS 被代理成 http:// ⇒ 502
    ('R-01', '面板不再信任 X-Real-IP（反代后所有来源都被当成本机）', APP,
     "        fwd = (request.headers.get('X-Real-IP') or '').strip()\n"
     "        if fwd:\n            return fwd",
     "        fwd = ''\n        if fwd:\n            return fwd"),
    # ⚠️ 与 R-01 方向相反、但**危险得多**的那条：
    #   「谁来都采信 X-Real-IP」⇒ 局域网里任何机器直连面板时，
    #   伪造一个 X-Real-IP 就能伪装成内网地址 ⇒ 面板自己的网段白名单形同虚设。
    #   R-01（完全不信任）只是让反代后的来源认不出来（功能退化），
    #   R-11（无脑信任）才是**可被利用的越权面** —— 之前没人测这一条。
    ('R-11', '面板对任何来源都采信 X-Real-IP（伪造头即可绕过网段白名单）', APP,
     "    remote = (request.remote_addr or '').strip()\n"
     "    if remote in _LOOPBACK_V4 or remote.startswith('127.'):\n"
     "        fwd = (request.headers.get('X-Real-IP') or '').strip()\n"
     "        if fwd:\n"
     "            return fwd\n"
     "    return remote",
     "    remote = (request.remote_addr or '').strip()\n"
     "    fwd = (request.headers.get('X-Real-IP') or '').strip()\n"
     "    if fwd:\n"
     "        return fwd\n"
     "    return remote"),
    ('R-02', '防火墙控制入口被设成公网可达（面板多了一个公网入口）', APP,
     '        "public_access": False,\n        "enabled": True,',
     '        "public_access": True,\n        "enabled": True,'),
    ('R-03', '预设规则不开了 API 路径改写（面板的接口全 404）', APP,
     '        "api_path_prefix": "/api",\n        "rewrite_root_paths": True,',
     '        "api_path_prefix": "",\n        "rewrite_root_paths": True,'),
    ('R-04', '预设规则不开了根绝对路径改写（字体与图片全 404）', APP,
     '        "api_path_prefix": "/api",\n        "rewrite_root_paths": True,',
     '        "api_path_prefix": "/api",\n        "rewrite_root_paths": False,'),
    ('R-06', '生成器又忽略 target_protocol（https 上游被代理成 http）', APP,
     "            proto = str(r.get(\"target_protocol\", \"\") or \"\").strip().lower()\n"
     "            if proto in (\"http\", \"https\"):\n"
     "                protocol = proto",
     "            proto = ''\n"
     "            if proto in (\"http\", \"https\"):\n"
     "                protocol = proto"),
    ('R-07', 'sub_filter 不再处理 text/javascript（JS 里的 API 路径不改写）', APP,
     '        L.append("        sub_filter_types application/javascript text/javascript text/css;")',
     '        L.append("        sub_filter_types application/javascript text/css;")'),
    ('R-08', 'CSS 里的 url() 不再改写（字体 404，页面悄悄掉回系统字体）', APP,
     '        for _q in ("\'", \'"\'):\n'
     '            sf_rules.append((f\'url({_q}/\', f\'url({_q}{prefix}/\'))',
     '        pass'),
    ('R-09', '预设入口不查幂等（每点一次就多一条 /fw 规则）', APP,
     '    for r in rules:\n'
     '        if _safe_path_prefix(r.get("path_prefix", "")) == FW_CONSOLE_PREFIX:',
     '    for r in []:\n'
     '        if _safe_path_prefix(r.get("path_prefix", "")) == FW_CONSOLE_PREFIX:'),
    ('R-10', '门户卡片不再用规则自带的图标（防火墙控制显示成路径首字母）', PJS,
     "    ico.textContent = (s.icon && String(s.icon).trim())\n"
     "      ? String(s.icon).trim()\n"
     "      : glyph(s, used);",
     "    ico.textContent = glyph(s, used);"),

    # ── Q. 面板（5443）也做一套像素场（2026-11-04 第十三轮）────
    # 用户原话：「这个5443界面你要么也做一套」
    # ⇒ 面板接上与服务门户**同一份**引擎源码（backend/static/pixelfield.js，
    #   面板从那里取，不在 frontend/ 留拷贝），背景同样是两档原版随机。
    #
    # 这批最危险的退化：
    #   · 引擎在 frontend/ 留了一份拷贝 ⇒ 两边从此各改各的，画面越走越远
    #     （而且**页面上完全看不出来**，两套画面都"正常"）
    #   · 静态服务的回退分支被删 / 白名单漏了 pixelfield.js ⇒ 面板 404
    #   · 画布或脚本引用被删 ⇒ 背景整层消失，页面照常（不报错）
    #   · 画布被挪到环境光之后 ⇒ 层级反了，被环境光压住
    ('Q-01', '面板的共享静态回退被删（面板拿不到引擎 → 404）', APP,
     "    if filename in SHARED_STATIC_FILES:\n"
     "        return send_from_directory('static', filename)\n",
     ''),
    ('Q-02', '共享白名单漏了 pixelfield.js（回退分支形同虚设）', APP,
     "    'pixelfield.js',\n", ''),
    ('Q-03', '面板页面不引引擎脚本了（背景整层消失）', FINX,
     '  <script defer src="/pixelfield.js"></script>\n', ''),
    ('Q-04', '面板页面的像素场画布被删了', FINX,
     '  <canvas id="nf-pix" class="nf-pix" aria-hidden="true"></canvas>\n\n', ''),
    ('Q-05', '面板页面不引引导脚本了（选档与挂载没人做）', FINX,
     '  <script defer src="/pixelbg.js"></script>\n', ''),
    ('Q-06', '画布的样式规则被删（画布不铺满 / 层级乱）', FCSS,
     '.nf-pix {\n  position: fixed;', '.nf-pix-disabled {\n  position: fixed;'),
    ('Q-07', '画布被挪到环境光之后（层级反了，被环境光压住）', FINX,
     '  <canvas id="nf-pix" class="nf-pix" aria-hidden="true"></canvas>\n\n'
     '  <!-- 环境光：两盏跟随指针的光源 + 一层细网格。',
     '  <!-- 环境光：两盏跟随指针的光源 + 一层细网格。'),
    ('Q-08', '面板引导脚本的候选表少一档（只剩原版）', FPIX,
     "var CANDIDATES = ['moonstone', 'trae'];",
     "var CANDIDATES = ['moonstone'];"),
    ('Q-09', '面板引导脚本的随机被写死成第一个', FPIX,
     'return CANDIDATES[Math.floor(r * CANDIDATES.length)];',
     'return CANDIDATES[0];'),
    ('Q-10', '面板引导脚本不再支持 ?pfstyle= 钉死某一档', FPIX,
     "    var want = queryParam('pfstyle');", "    var want = '';"),
]


def main():
    # ── 分片并行（2026-11-04 第十一轮补）──────────────────────
    # 为什么要分片：这一批的变异条数已经 186 条，而每条都要跑
    # 「静态断言 + 4 个行为级测试」＝ 约 2 分钟 ⇒ 单进程要 6 小时。
    # ⇒ 支持 `--shard I/N`：把变异按序号取模分给 N 个进程，
    #   每个进程在**自己的仓库副本**里跑（副本互不干扰）。
    #   用法: python3 tests/mutation_check_portal_frontend.py --shard 1/6
    # ⚠ 不带参数时行为与从前完全一样（跑全部）⇒ 不影响既有用法。
    muts = MUTATIONS
    if len(sys.argv) >= 3 and sys.argv[1] == '--shard':
        try:
            si, sn = (int(x) for x in sys.argv[2].split('/'))
        except ValueError:
            print('!! --shard 的参数格式是 I/N（I 从 0 开始）')
            return 2
        if sn < 1 or si < 0 or si >= sn:
            print('!! --shard 参数越界：I=%d N=%d' % (si, sn))
            return 2
        muts = [m for k, m in enumerate(MUTATIONS) if k % sn == si]
        print('分片 %d/%d：本次只跑 %d 条' % (si, sn, len(muts)))

    if not os.path.isfile(TEST_PY):
        print(f'!! 找不到测试文件 {TEST_PY}')
        return 2

    # 先确认原始状态下测试是绿的 —— 否则「变异被抓住」没有意义
    rc, out = run_tests()
    if rc != 0:
        print('!! 原始状态下测试就是红的，先修测试再跑变异：')
        print(out[-3000:])
        return 2
    print('原始状态：测试通过（静态 %d 项 + 行为级 %d 项）'
          % (out.count('[PASS]'), out.count('✅') + out.count('[PASS]')))

    caught, missed = 0, []
    for mid, desc, rel, old, new in muts:
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
                # ⚠ 必须**行首**匹配：原来用「行内包含」⇒ 断言名里带
                #   ❌ / [FAIL] 的 [PASS] 行会被当成失败行（实测 M-18/M-19
                #   报出来的失败原因行是「[PASS] …认 ❌ 与 [FAIL]…」）。
                st = line.strip()
                if st.startswith('[FAIL]') or st.startswith('❌'):
                    first = line.strip()
                    break
            print(f'[捕获] {mid} {desc}  →  {first[:110]}')
        else:
            missed.append(f'{mid} {desc}')
            print(f'[漏网] {mid} {desc}  ← 测试没变红！')

    restore()

    print()
    print('=' * 60)
    print(f'  变异 {len(muts)} 条，捕获 {caught} 条，漏网 {len(missed)} 条')
    if missed:
        print('  漏网的变异：')
        for m in missed:
            print('    - ' + m)
        return 1
    print('  全部捕获')
    return 0


if __name__ == '__main__':
    sys.exit(main())
