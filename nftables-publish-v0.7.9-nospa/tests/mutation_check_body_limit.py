#!/usr/bin/env python3
"""变异验证：反代服务「上传大小限制」的默认值（1M）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_body_limit.py

改的是 backend/app.py + frontend/app.js + frontend/index.html。
判定标准只有一条：**旧代码必然让断言失败**。

**这个脚本会改写并还原源码，运行期间不能编辑源码、不能部署。**
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
JS = os.path.join(ROOT, 'frontend', 'app.js')
HTML = os.path.join(ROOT, 'frontend', 'index.html')
TEST = os.path.join(ROOT, 'tests', 'test_rp_body_limit.py')

SRC = open(APP, encoding='utf-8').read()
JSRC = open(JS, encoding='utf-8').read()
HSRC = open(HTML, encoding='utf-8').read()

PY = 'py'

APP_MUTANTS = [
    ('默认值退回「0 = 不限」（公网入口请求体上限完全敞开）',
     'cmbs = (_sanitize_client_max_body_size(rule.get("client_max_body_size", ""))\n'
     '                    or DEFAULT_CLIENT_MAX_BODY)',
     'cmbs = (_sanitize_client_max_body_size(rule.get("client_max_body_size", ""))\n'
     '                    or "0")'),
    ('非法值分支退回「0 = 不限」',
     "            print(f'[WARN] 服务 {name} 的 client_max_body_size 非法，'\n"
     "                  f'已按默认 {DEFAULT_CLIENT_MAX_BODY} 处理', flush=True)\n"
     "            cmbs = DEFAULT_CLIENT_MAX_BODY",
     "            print(f'[WARN] 服务 {name} 的 client_max_body_size 非法', flush=True)\n"
     '            cmbs = "0"'),
    ('默认值常量被改成 8K（跟认证端点混了）',
     'DEFAULT_CLIENT_MAX_BODY = "1M"',
     'DEFAULT_CLIENT_MAX_BODY = "8K"'),
]

JS_MUTANTS = [
    ('新建规则的默认值不是 1M',
     "        client_max_body_size: '1M',",
     "        client_max_body_size: '',"),
    ('编辑老规则时不再归一化成 1M',
     "      r.client_max_body_size = r.client_max_body_size || '1M';",
     "      r.client_max_body_size = r.client_max_body_size || '';"),
]

HTML_MUTANTS = [
    ('列表里空值显示成「不限制」（跟实际生效的 1M 对不上）',
     "x-text=\"rule.client_max_body_size || '1M（默认）'\"",
     "x-text=\"rule.client_max_body_size || '不限制'\""),
    ('表单提示不再写明默认 1M',
     '默认 1M（1MB），填 0 = 不限制',
     '留空或填 0 = 不限制'),
]


def run_py():
    return subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                          timeout=120, cwd=ROOT)


RUNNERS = {PY: run_py}


def report(name, results):
    caught = False
    detail = ''
    for label, r in results:
        fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
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
        base = run_py()
        if base.returncode != 0:
            print('❌ 基线就不过，先修基线')
            print(base.stdout[-3000:])
            if base.stderr:
                print(base.stderr[-1500:])
            return 1
        print(f'基线通过  {base.stdout.count("✅")} 条\n')

        caught, noanchor = 0, []
        try:
            for label, path, src, mutants in (
                ('后端', APP, SRC, APP_MUTANTS),
                ('前端 JS', JS, JSRC, JS_MUTANTS),
                ('前端 HTML', HTML, HSRC, HTML_MUTANTS),
            ):
                for name, old, new in mutants:
                    if old not in src:
                        print(f'  ⚠️  锚点未命中 [{label}]: {name}')
                        noanchor.append(name)
                        continue
                    mutated = src.replace(old, new, 1)
                    open(path, 'w', encoding='utf-8').write(mutated)
                    on_disk = open(path, encoding='utf-8').read()
                    if on_disk != mutated:
                        print(f'  ❌ 变异没落到 [{label}]: {name}')
                        noanchor.append(name)
                        open(path, 'w', encoding='utf-8').write(src)
                        continue
                    try:
                        results = [('py', RUNNERS[PY]())]
                    finally:
                        open(path, 'w', encoding='utf-8').write(src)
                    caught += report(name, results)
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
    finally:
        guard.restore()


if __name__ == '__main__':
    sys.exit(main())
