#!/usr/bin/env python3
"""变异验证：第七批 —— 反代「路径改写」改为保存时自动探测。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_batch7_autodetect.py

改的是 backend/app.py + frontend/app.js + frontend/index.html。
判定标准只有一条：**变异必须让断言真的红**（有真正的 [FAIL] 行）。

⚠️ 口径（踩过的坑）：
  · rc≠0 但一条失败行都没有 = 测试自己崩了，**不算捕获**；
  · 汇总行自带失败标记（「合计: 通过 N 失败 M」）必须排除，
    否则「什么都没抓也报抓住」—— 指标自己骗自己。

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
HTML = os.path.join(ROOT, 'frontend', 'index.html')

PY_TEST = os.path.join(ROOT, 'tests', 'test_batch7_autodetect.py')
JS_TEST = os.path.join(ROOT, 'tests', 'test_api_prefix_frontend.js')

SRC = open(APP, encoding='utf-8').read()
JSRC = open(JS, encoding='utf-8').read()
HSRC = open(HTML, encoding='utf-8').read()

# ── 变异清单 ────────────────────────────────────────────────────────
# 每条 = (说明, 原文, 变异后)
#
# ⚠️ 锚点必须**唯一**：`replace(old, new, 1)` 只换第一处，
#    锚点不唯一就会「改到了别的地方」，断言照样绿 ⇒ 变异白做。

APP_MUTANTS = [
    # ── API 前缀候选的排序 ────────────────────────────────────────
    ('API 前缀候选退回按名字排（/admin/ 会排到 /api/ 前面 ⇒ 选错前缀）',
     '    ordered = sorted(segs.items(), key=lambda kv: (-kv[1], kv[0]))',
     '    ordered = sorted(segs.items(), key=lambda kv: kv[0])'),

    # ── 根绝对路径改写的判定 ──────────────────────────────────────
    ('协议相对 URL 的判定失效（有 // 的上游也会被开改写 ⇒ 外部资源被改坏）',
     '    elif proto_rel > 0:',
     '    elif False:'),

    ('根绝对路径计数被清零（永远判定「没有根绝对路径」⇒ 改写永远不开）',
     '    root_abs, proto_rel, _samples, err2 = _detect_upstream_path_shapes(host, port, proto)',
     '    root_abs, proto_rel, _samples, err2 = 0, 0, [], None'),

    # ── 安全边界 ──────────────────────────────────────────────────
    ('自动装配不再受 LAN 网段限制（面板变成通用抓取器，P2-9 的边界被拆掉）',
     "    if not _detect_target_allowed(host):\n"
     "        return '目标不在局域网网段内，已跳过自动检测（路径改写保持原样）'",
     "    if False:\n"
     "        return '目标不在局域网网段内，已跳过自动检测（路径改写保持原样）'"),

    # ── 装配的接线 ────────────────────────────────────────────────
    ('新建时不再自动装配（这两个字段永远保持默认 ⇒ 页面能开、接口全 404）',
     '    autofill_note = _rp_autofill_path_rewrite(clean)',
     "    autofill_note = ''"),

    ('编辑时也自动装配（会把已生效的值覆盖掉 —— 内置 /fw 规则会被改坏）',
     '    created_at = rule.get("created_at", now_iso)\n',
     '    created_at = rule.get("created_at", now_iso)\n'
     '    _rp_autofill_path_rewrite(clean)\n'),

    # ── 回传给前端的值 ────────────────────────────────────────────
    ('响应里不回传实际生效的 API 前缀（界面显示与实际生效值对不上）',
     '        "api_path_prefix": clean.get("api_path_prefix", ""),',
     '        "api_path_prefix": "",'),
]

JS_MUTANTS = [
    ('前端把探测结论写回本地对象时赋了空串（列表显示与实际生效值对不上）',
     '              this.rp.rules[i].api_path_prefix = created.api_path_prefix;',
     "              this.rp.rules[i].api_path_prefix = '';"),

    ('前端不回填根绝对路径改写的状态',
     '              this.rp.rules[i].rewrite_root_paths = !!created.rewrite_root_paths;',
     '              this.rp.rules[i].rewrite_root_paths = false;'),

    ('探测结论不再回显给用户（用户不知道系统替它做了什么决定）',
     "          + (autofillNote ? '（' + autofillNote + '）' : ''), 'success');",
     "          + '', 'success');"),
]

HTML_MUTANTS = [
    ('编辑表单里不再展示当前 API 路径前缀',
     'x-text="rpEditingRule?.api_path_prefix"',
     "x-text=\"''\""),

    ('编辑表单里不再展示根绝对路径改写状态',
     'x-show="rpEditingRule?.rewrite_root_paths"',
     'x-show="false"'),
]


def _fail_lines(stdout):
    """挑出**真正的断言失败行**（排除汇总行）。

    ⚠️ 汇总行自带失败标记（「合计: 通过 N 失败 M」「通过 N / 失败 M」），
    把它当失败就是「什么都没抓也报抓住」。
    """
    out = []
    for line in stdout.splitlines():
        s = line.strip()
        if s.startswith('合计') or s.startswith('通过'):
            continue
        if '[FAIL]' in s or '❌' in s:
            out.append(s)
    return out


def _pass_count(stdout):
    return stdout.count('[PASS]') + stdout.count('✅')


class _Result:
    def __init__(self, stdout, rc):
        self.stdout = stdout
        self.returncode = rc


def run_test():
    """后端 + 前端两份测试一起跑；任何一份崩了都算没过。"""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    py = subprocess.run([sys.executable, PY_TEST], capture_output=True,
                        text=True, timeout=600, env=env)
    js = subprocess.run(['node', JS_TEST], capture_output=True,
                        text=True, timeout=600, env=env)
    out = py.stdout + js.stdout
    if py.returncode or js.returncode:
        out += ('\n--- python stderr ---\n' + py.stderr[-800:] +
                '\n--- node stderr ---\n' + js.stderr[-800:])
    return _Result(out, py.returncode or js.returncode)


def report(name, r):
    fails = _fail_lines(r.stdout)
    # ⚠️ 必须有真正的断言失败行才算捕获：rc≠0 但一条失败行都没有
    #   = 测试自己崩了（不是被变异打红的），按项目口径不算捕获。
    if fails:
        print(f'  [OK] 抓住 {name}（{len(fails)} 条断言失败）')
        print(f'        首个失败: {fails[0][:86]}')
        return True
    if r.returncode != 0:
        print(f'  [FAIL] 漏过 {name} —— 但测试是**崩了**不是红了，不算捕获')
        tail = (r.stdout.strip().splitlines() or ['(无输出)'])
        print('        ', tail[-1][:86])
    else:
        print(f'  [FAIL] 漏过 {name}')
    return False


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print('=' * 74)
    print('变异验证：第七批（路径改写自动探测）')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('[FAIL] 基线没过：')
        print(base.stdout[-2500:])
        print(base.stdout[-1200:])
        return 1
    print(f'基线通过  {len(_fail_lines(base.stdout))} 条失败行 / '
          f'{_pass_count(base.stdout)} 条通过\n')

    caught, noanchor = 0, []
    try:
        for label, path, src, mutants in (
            ('后端', APP, SRC, APP_MUTANTS),
            ('前端 JS', JS, JSRC, JS_MUTANTS),
            ('前端 HTML', HTML, HSRC, HTML_MUTANTS),
        ):
            for name, old, new in mutants:
                if old not in src:
                    print(f'  [WARN] 锚点未命中 [{label}]: {name}')
                    noanchor.append(name)
                    continue
                if src.count(old) != 1:
                    print(f'  [WARN] 锚点不唯一（出现 {src.count(old)} 次）[{label}]: {name}')
                    noanchor.append(name)
                    continue
                mutated = src.replace(old, new, 1)
                open(path, 'w', encoding='utf-8').write(mutated)
                # 闸：变异必须真的落到这个文件上。写完立刻回读比对。
                on_disk = open(path, encoding='utf-8').read()
                if on_disk != mutated:
                    print(f'  [FAIL] 变异没落到 [{label}]: {name}')
                    noanchor.append(name)
                    open(path, 'w', encoding='utf-8').write(src)
                    continue
                try:
                    r = run_test()
                finally:
                    open(path, 'w', encoding='utf-8').write(src)
                caught += report(name, r)
    finally:
        open(APP, 'w', encoding='utf-8').write(SRC)
        open(JS, 'w', encoding='utf-8').write(JSRC)
        open(HTML, 'w', encoding='utf-8').write(HSRC)

    total = len(APP_MUTANTS) + len(JS_MUTANTS) + len(HTML_MUTANTS)
    print('\n' + '=' * 74)
    print(f'变异 {total} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
    if noanchor:
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    print('全部变异均被捕获' if caught == total else '有变异漏过')
    return 0 if caught == total else 1


if __name__ == '__main__':
    sys.exit(main())
