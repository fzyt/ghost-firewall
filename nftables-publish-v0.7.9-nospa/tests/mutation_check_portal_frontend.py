"""门户改版批次（背景变体引擎 + 网格重排）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_portal_frontend.py

测什么有效：这一批改版最危险的退化不是「写错了」，而是**改回原来的样子**。
原来的网格是 auto-fill 自动列、原来的背景是固定晶向、
原来的白名单是 8 个文件 —— 那些代码读起来完全正常、前端照样工作，
单测很容易全绿。只有真的把改动拆掉，测试才会变红。

所以每条变异都是「把这次改版撤回」：
  · 把两列网格改回 auto-fill
  · 把 640px 断点删掉
  · 把间距 token 删掉
  · 把登录页那一档的参数改成门户那一档（改版外溢）
  · 把新参数的默认值从 0 改回非 0
  · 从白名单里删掉新文件 / 删掉 portal.html 的引用
  · 把「变体引擎接管时不再自挂载」这条守卫拆掉
  · 把脚本加载顺序对调
  · 把 CSP 放宽
  · 制造语法错误

每条变异都独立重写源文件，并强制 PYTHONDONTWRITEBYTECODE=1：否则连续写入时
Python 只按 mtime+size 判过期，两条大小相近的变异会复用上一条的 .pyc，
把「漏网」伪装成「捕获」。

只备份 / 还原**本脚本会动的那几个文件**，一个字节都不碰别的。
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
    os.path.join('backend', 'static', 'fx.js'),
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
FXS = os.path.join('backend', 'static', 'fx.js')
GW = os.path.join('backend', 'auth_gateway.py')

MUTATIONS = [
    # ── 白名单 / 引用一致性（这是真机上会白屏的那一类）──
    ('M-01', '白名单漏掉 fx.js', GW,
     '"fx.js", "switcher.css", "switcher.js",',
     '"switcher.css", "switcher.js",'),
    ('M-02', '白名单漏掉 switcher.js', GW,
     '"fx.js", "switcher.css", "switcher.js",',
     '"fx.js", "switcher.css",'),
    ('M-03', '白名单留了不存在的文件（僵尸条目）', GW,
     '"fx.js", "switcher.css", "switcher.js",',
     '"fx.js", "switcher.css", "switcher.js", "not-exist.js",'),
    ('M-04', '门户页不再引用 fx.js', PHT,
     '<script src="{{STATIC_BASE}}fx.js"></script>\n', ''),
    ('M-05', '门户页不再引用 switcher.js', PHT,
     '<script src="{{STATIC_BASE}}switcher.js"></script>\n', ''),

    # ── 网格改造撤回 ──
    ('M-06', '网格改回 auto-fill 自动列', CSS,
     'grid-template-columns: repeat(2, minmax(0, 1fr));',
     'grid-template-columns: repeat(auto-fill, minmax(198px, 1fr));'),
    ('M-07', '删掉 640px 窄屏单列断点', CSS,
     '@media (max-width: 640px) {\n'
     '  .grid {\n'
     '    grid-template-columns: minmax(0, 1fr);\n'
     '    gap: var(--sp-3);\n'
     '  }\n'
     '}\n', ''),
    ('M-08', '删掉 --sp-4 间距 token', CSS,
     '  --sp-4:  16px;\n', ''),
    ('M-09', '卡片内部改回「名称与路径同一行」', CSS,
     '    "ico nm tag"\n    "ico pt .";',
     '    "ico nm pt"\n    "ico tag tag";'),
    ('M-10', '入口路径又被 max-width 砍断', CSS,
     '.tile .pt {\n  grid-area: pt;\n',
     '.tile .pt {\n  grid-area: pt;\n  max-width: 84px;\n'),

    # ── 背景参数：改版外溢 + 默认值被改 ──
    ('M-11', '登录页那一档被改成门户参数（改版外溢）', PIX,
     '{ k: 0.00580, om: 0.504, off: 0.00, dir: -0.30, w: 1.00 }',
     '{ k: 0.00580, om: 0.958, off: 0.00, dir: -0.30, w: 1.00 }'),
    ('M-12', '门户那一档删掉晶向随机化参数', PIX,
     '        patchRot1: 0.22,\n', ''),
    ('M-13', '新参数默认值从 0 改成 0.22（不传时行为会变）', PIX,
     '    patchRot1: 0.0,', '    patchRot1: 0.22,'),
    ('M-14', '新参数默认值从 0 改成 0.020', PIX,
     '    patchSpin: 0.0,', '    patchSpin: 0.020,'),

    # ── 变体引擎 ──
    ('M-15', '少注册一个变体', FXS,
     "    growth: {", "    growthX: {"),
    ('M-16', '变体没有 update 逻辑', FXS,
     "      update: function (f, st, dt) {\n"
     "        var W = f.cols, H = f.rows, n = W * H, rng = f.rng;\n"
     "        if (!st.seeded) {\n"
     "          st.seeded = true;\n"
     "          var k = 11;\n",
     "      step: function (f, st, dt) {\n"
     "        var W = f.cols, H = f.rows, n = W * H, rng = f.rng;\n"
     "        if (!st.seeded) {\n"
     "          st.seeded = true;\n"
     "          var k = 11;\n"),
    ('M-17', '降级动效没有预热（会黑屏）', FXS,
     'for (var i = 0; i < warm; i++) def.update(this, this.state, 0.016);', ''),
    ('M-18', '白度钩子缺省不再是二值', FXS,
     'var w = tint ? tint(this, this.state, i, v) : (this.crest[i] ? 1 : 0);',
     'var w = tint ? tint(this, this.state, i, v) : 1;'),

    # ── 双挂载防护 / 加载顺序 ──
    ('M-19', '拆掉「变体引擎接管时不自挂载」的守卫', PJS,
     '    if (window.GhostFX) return;\n', ''),
    ('M-20', '门户降级路径用回登录页那一档', PJS,
     "createStyle(canvas, 'moonstone-swirl', opt)",
     "createStyle(canvas, 'moonstone', opt)"),
    ('M-21', '脚本加载顺序对调（fx.js 排到 portal.js 后面）', PHT,
     '<script src="{{STATIC_BASE}}fx.js"></script>\n'
     '<script src="{{STATIC_BASE}}portal.js"></script>',
     '<script src="{{STATIC_BASE}}portal.js"></script>\n'
     '<script src="{{STATIC_BASE}}fx.js"></script>'),

    # ── 安全面 ──
    ('M-22', 'CSP 被放宽', GW,
     'CSP_PORTAL_HTML = (\n    "default-src \'none\';',
     'CSP_PORTAL_HTML = (\n    "default-src \'self\';'),
    ('M-23', '引入外部资源', PHT,
     '<title>服务门户 · Ghost Firewall</title>',
     '<title>服务门户 · Ghost Firewall</title>\n'
     '<script src="https://example.com/x.js"></script>'),
    ('M-24', 'JS 语法错误', FXS,
     '(function (global) {', '(function (global {'),

    # ── 静态基址占位符 ──
    ('M-25', '不替换占位符（页面里的资源地址全是死链）', GW,
     'return html.replace(PORTAL_STATIC_BASE, static_base)',
     'return html'),
    ('M-26', '占位符常量与页面里写的不一致', GW,
     "PORTAL_STATIC_BASE = '{{STATIC_BASE}}'",
     "PORTAL_STATIC_BASE = '{{STATIC_ROOT}}'"),
    ('M-27', '认证服务注入的前缀不对', GW,
     "_read_portal_html('/auth/static/')",
     "_read_portal_html('/static/')"),
    ('M-28', '门户页里写死静态前缀', PHT,
     '<link rel="stylesheet" href="{{STATIC_BASE}}base.css">',
     '<link rel="stylesheet" href="/auth/static/base.css">'),

    # ── 独立审查补上的盲区（2026-11-02）──────────────────────────
    # 前 28 条只覆盖了「把改版撤回」这一类退化；
    # 审查发现另外几类退化没人守，补在这里。
    ('M-29', 'CSP 被放宽（加 unsafe-inline）', GW,
     'CSP_PORTAL_HTML = (\n    "default-src \'none\'; script-src \'self\';',
     'CSP_PORTAL_HTML = (\n    "default-src \'none\'; script-src \'self\' \'unsafe-inline\';'),
    ('M-30', '门户页塞进内联脚本', PHT,
     '<script src="{{STATIC_BASE}}fingerprint.js"></script>',
     '<script>alert(1)</script>\n'
     '<script src="{{STATIC_BASE}}fingerprint.js"></script>'),
    ('M-31', '门户页塞进内联样式属性', PHT,
     '<canvas class="pixfield" id="pix" aria-hidden="true"></canvas>',
     '<canvas class="pixfield" id="pix" aria-hidden="true" '
     'style="opacity:.5"></canvas>'),
    ('M-32', '_read_portal_html 的默认基址被改（白名单直达路径会变死链）', GW,
     "def _read_portal_html(static_base='/auth/static/'):",
     "def _read_portal_html(static_base='/static/'):"),
    ('M-33', '门户页漏引 switcher.css（切换器样式全丢但页面照常打开）', PHT,
     '<link rel="stylesheet" href="{{STATIC_BASE}}switcher.css">\n', ''),
    ('M-34', 'fx.js 拼 innerHTML（XSS）', FXS,
     '  var DPR_MAX = 1.5;',
     "  var DPR_MAX = 1.5;\n  var _x = ''; _x.innerHTML = 'x';"),
    ('M-35', '方向摆动频率默认值不再是 0（「默认全 0」的保证被破坏）', PIX,
     '    dirSwingFreq: 0.0,', '    dirSwingFreq: 0.5,'),
    ('M-36', '方向向量改回单精度（末位精度丢失 ⇒ 破坏「逐位一致」）', PIX,
     'new Float64Array(8)', 'new Float32Array(8)'),
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
