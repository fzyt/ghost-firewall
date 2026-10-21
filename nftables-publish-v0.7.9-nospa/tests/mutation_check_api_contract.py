#!/usr/bin/env python3
"""变异验证：前端解包契约（预设列表不显示那一类 bug）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_api_contract.py

改的是 backend/app.py + frontend/app.js。
判定标准只有一条：**旧代码必然让断言失败**。
断言如果改个变量名就绕过，等于没测。

**这个脚本会改写并还原源码，运行期间不能编辑源码、不能部署。**
"""
import os
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
JS = os.path.join(ROOT, 'frontend', 'app.js')

PY_TEST = os.path.join(ROOT, 'tests', 'test_api_contract.py')
JS_TEST = os.path.join(ROOT, 'tests', 'test_api_contract_frontend.js')

SRC = open(APP, encoding='utf-8').read()
JSRC = open(JS, encoding='utf-8').read()

PY = 'py'
JS_KEY = 'js'

# ── 前端变异：把 unwrap(...) 改回直接读（= 第十七节的老代码）──────────
JS_MUTANTS = [
    # ── 扫描器盲区：代码**照常能跑**，但扫描器看不见这个调用点 ──
    #
    # 这是最危险的一类：2026-10-20 实测踩过 —— 前端把 api.get 包进了
    # `loadOne('/api/lists/xxx', fallback)` 这种包装函数，扫描器的
    # CALL_RE（只认 `api.get('/api/...')` 字面量）就看不见那 4 个调用点了。
    # 而端点覆盖集**没变**（loadListPresets 里还有同一个端点），
    # 所以「覆盖到 /api/lists/presets」那条自我证明照样全绿 ——
    # 「读错一层」重新变成零不匹配的**假绿**。
    #
    # 这里用 `api['get'](...)` 制造同样的效果，但代码**仍然能跑** ——
    # 于是失败只可能来自「扫描器自己报了盲区」这一条断言。
    # 换句话说：这条变异证明的是**盲区检测器真的会响**，
    # 而不是"代码坏了当然会红"这种假证明。
    ('扫描器盲区：api[\'get\'] 形式（代码能跑，扫描器看不见）',
     "          api.get('/api/lists/presets')\n"
     "            .catch(guard('presets', { presets: [] })),",
     "          api['get']('/api/lists/presets')\n"
     "            .catch(guard('presets', { presets: [] })),"),

    # ── 预设列表：用户报的原始 bug ────────────────────────────────
    ('预设列表少读一层（loadLists 里的 presets）',
     'this.ipPresets = unwrap(presets).presets || [];',
     'this.ipPresets = presets.presets || [];'),
    ('预设列表少读一层（loadListPresets 里的 data）',
     'this.ipPresets = unwrap(data).presets || [];',
     'this.ipPresets = data.presets || [];'),
    ('最近操作少读一层（loadLists 里的 history）',
     'this.listHistory = unwrap(history).history || [];',
     'this.listHistory = history.history || [];'),
    ('最近操作少读一层（loadListHistory 里的 data）',
     'this.listHistory = unwrap(data).history || [];',
     'this.listHistory = data.history || [];'),

    # ── 规则集健康：7 个字段全部读成 false/空 ─────────────────────
    ('规则健康少读一层（整个 h）',
     'const h = unwrap(d);',
     'const h = d;'),

    # ── 反代规则新建：后端分配的 id 拿不到 ────────────────────────
    ('反代规则 rule_id 少读一层',
     'const created = unwrap(resp);',
     'const created = resp;'),

    # ── 被 || 'xxx' 兜底掩盖的那几个：文案退化 ─────────────────────
    ('改密码的提示文案读不到',
     "this.showToast(unwrap(r).message || '密码已修改', 'success');",
     "this.showToast(r.message || '密码已修改', 'success');"),
    ('规则连通性测试的提示文案读不到',
     "this.showToast(unwrap(data).message || '连通性测试成功', 'success');",
     "this.showToast(data.message || '连通性测试成功', 'success');"),
    ('Nginx 配置测试的提示文案读不到',
     "this.showToast(unwrap(data).message || 'Nginx 配置测试通过', 'success');",
     "this.showToast(data.message || 'Nginx 配置测试通过', 'success');"),
    ('Nginx 重载的提示文案读不到',
     "this.showToast(unwrap(data).message || 'Nginx 已重载', 'success');",
     "this.showToast(data.message || 'Nginx 已重载', 'success');"),
    ('证书申请的提示文案读不到',
     "this.showToast(unwrap(data).message || '证书申请成功', 'success');",
     "this.showToast(data.message || '证书申请成功', 'success');"),
    ('证书续期的提示文案读不到',
     "this.showToast(unwrap(data).message || '证书续期成功', 'success');",
     "this.showToast(data.message || '证书续期成功', 'success');"),

    # ── unwrap 本身 ──────────────────────────────────────────────
    # 这几条静态对账抓不到（它只管"前端写了 unwrap(...)"这个形式），
    # 必须靠 tests/test_api_contract_frontend.js 的**行为**断言。
    ('unwrap 变成空操作（解包彻底失效）',
     "const unwrap = (r) => {\n"
     "  if (r && typeof r === 'object' && r.data !== undefined && r.data !== null\n"
     "      && typeof r.data === 'object') {\n"
     "    return r.data;\n"
     "  }\n"
     "  return r || {};\n"
     "};",
     "const unwrap = (r) => (r || {});"),
    ('unwrap 不处理 data 为 null（调用方会炸在 undefined 上）',
     "  if (r && typeof r === 'object' && r.data !== undefined && r.data !== null\n"
     "      && typeof r.data === 'object') {",
     "  if (r && typeof r === 'object' && r.data !== undefined\n"
     "      && typeof r.data === 'object') {"),
    ('unwrap 把平铺式也当成信封（平铺端点的字段全丢）',
     "  if (r && typeof r === 'object' && r.data !== undefined && r.data !== null\n"
     "      && typeof r.data === 'object') {\n"
     "    return r.data;\n"
     "  }\n"
     "  return r || {};",
     "  if (r && typeof r === 'object' && r.data !== undefined) {\n"
     "    return r.data || {};\n"
     "  }\n"
     "  return r || {};"),
]

# ── 后端变异：把返回从信封式改成平铺式 ────────────────────────────────
# 改的是前端**硬编码** `.data.` 的那几个端点（:1540 / :1751 / :2030）——
# 前端用了 unwrap 的地方对形状不敏感，静态对账也判不出来；
# 只有硬编码的那几处会真炸，所以变异必须落在它们身上。
APP_MUTANTS = [
    ('dns-providers 改成平铺式（前端 data.data.providers 读不到）',
     'return jsonify({"success": True, "data": {"providers": providers_out}})',
     'return jsonify({"success": True, "providers": providers_out})'),
    ('detect-api-prefix 改成平铺式（前端 res.data.prefixes 读不到）',
     'return jsonify({"success": True,\n'
     '                    "data": {"prefixes": prefixes, "error": err}})',
     'return jsonify({"success": True,\n'
     '                    "prefixes": prefixes, "error": err})'),
    # 2026-10-21：set-default 的返回多了 nginx_reloaded、message 变成变量
    # （证书部署失败时要如实说），**envelope 形状没变** —— 前端仍读
    # data.data.message，所以这个变异依然成立。
    ('证书设默认改成平铺式（前端 data.data.message 读不到）',
     'return jsonify({"success": True, "data": {"message": msg, "default_cert_id": cert_id, "nginx_reloaded": nginx_reloaded}})',
     'return jsonify({"success": True, "message": msg, "default_cert_id": cert_id, "nginx_reloaded": nginx_reloaded})'),
]


def run_py():
    return subprocess.run([sys.executable, PY_TEST], capture_output=True, text=True,
                          timeout=120, cwd=ROOT)


def run_js():
    return subprocess.run(['node', JS_TEST], capture_output=True, text=True,
                          timeout=120, cwd=ROOT)


RUNNERS = {PY: run_py, JS_KEY: run_js}


def report(name, results):
    """results = [(label, CompletedProcess), ...]"""
    caught = False
    detail = ''
    for label, r in results:
        fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
        # 变异让代码自己崩掉也算抓到 —— 崩掉正是要防的事。
        if r.returncode != 0 and (fails or r.stderr.strip()):
            caught = True
            detail = (fails[0][:86] if fails
                      else ('测试崩溃: ' + r.stderr.strip().splitlines()[-1][:70]))
            break
    if caught:
        print(f'  ✅ 抓住 {name}')
        print(f'        首个失败: {detail}')
    else:
        print(f'  ❌ 漏过 {name}')
    return caught


def main():
    guard = MutationGuard(ROOT)
    guard.snapshot()
    try:
        base_py = run_py()
        base_js = run_js()
        if base_py.returncode != 0:
            print('❌ 基线就不过（契约测试），先修基线')
            print(base_py.stdout[-3000:])
            if base_py.stderr:
                print(base_py.stderr[-1500:])
            return 1
        if base_js.returncode != 0:
            print('❌ 基线就不过（前端行为测试），先修基线')
            print(base_js.stdout[-3000:])
            if base_js.stderr:
                print(base_js.stderr[-1500:])
            return 1
        print(f'基线通过  契约对账 {base_py.stdout.count("✅")} 条  '
              f'解包行为 {base_js.stdout.count("✅")} 条\n')

        caught, noanchor = 0, []
        try:
            for label, path, src, mutants, which in (
                ('前端 JS', JS, JSRC, JS_MUTANTS, (PY, JS_KEY)),
                ('后端', APP, SRC, APP_MUTANTS, (PY,)),
            ):
                for name, old, new in mutants:
                    if old not in src:
                        print(f'  ⚠️  锚点未命中 [{label}]: {name}')
                        noanchor.append(name)
                        continue
                    mutated = src.replace(old, new, 1)
                    if mutated == src:
                        print(f'  ⚠️  变异没改到内容 [{label}]: {name}')
                        noanchor.append(name)
                        continue
                    open(path, 'w', encoding='utf-8').write(mutated)
                    # 闸：变异必须真的落到这个文件上（写完立刻回读比对）
                    on_disk = open(path, encoding='utf-8').read()
                    if on_disk != mutated:
                        print(f'  ❌ 变异没落到 [{label}]: {name}')
                        noanchor.append(name)
                        open(path, 'w', encoding='utf-8').write(src)
                        continue
                    try:
                        results = [(w, RUNNERS[w]()) for w in which]
                    finally:
                        open(path, 'w', encoding='utf-8').write(src)
                    caught += report(name, results)
        finally:
            open(APP, 'w', encoding='utf-8').write(SRC)
            open(JS, 'w', encoding='utf-8').write(JSRC)

        total = len(APP_MUTANTS) + len(JS_MUTANTS)
        print('\n' + '=' * 74)
        print(f'变异 {total} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
        if noanchor:
            for m in noanchor:
                print('  锚点未命中:', m)
            return 1
        print('全部变异均被捕获' if caught == total else '有变异漏过')
        return 0 if caught == total else 1
    finally:
        guard.restore()


if __name__ == '__main__':
    sys.exit(main())
