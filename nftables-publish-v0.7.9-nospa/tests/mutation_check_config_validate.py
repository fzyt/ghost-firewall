#!/usr/bin/env python3
"""变异验证：配置语义校验（validate_config 的「拒绝非法值」能力）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_config_validate.py

改的是 tests/test_review_fixes.py。这个测试文件此前有 158 条断言却**没有任何
变异覆盖** —— 意味着 validate_config 里少一条校验，单元测试照样全绿。

判定标准只有一条：**旧代码必然让断言失败**。

第一批锚点针对 FUNC-01（.224 真机功能面测试跑出来的缺陷）：
`access_mode` 不被校验，非法值经模板那行 `else "trusted"` 静默变成
信任模式，内核里 LAN 只剩 22/5443 可达，而接口回 200「配置已保存」。
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_review_fixes.py')

SRC = open(APP, encoding='utf-8').read()

MUTANTS = [
    # ── FUNC-01：access_mode 整条校验被拿掉 ──────────────────────
    ('access_mode 不再校验（非法值静默变 trusted —— 缺陷本体）',
     "    if _am not in ('lan', 'trusted'):",
     "    if False:"),

    # 只挡了空串 / None，忘了挡 'knock' 这种「看起来像模式」的值
    ('access_mode 只挡空值，漏掉任意非法串',
     "    if _am not in ('lan', 'trusted'):",
     "    if _am in (None, ''):"),

    # 大小写不归一化：'LAN' 会被模板当 trusted
    ('access_mode 归一化大小写后放行（模板并不归一化，等于放行非法值）',
     "    if _am not in ('lan', 'trusted'):",
     "    if str(_am).lower() not in ('lan', 'trusted'):"),

    # 校验做了但没记进 errs —— 校验形同虚设
    ('access_mode 校验了却不记进 errs（拒绝信息为空）',
     "        errs.append(f'access_mode 非法: {_am!r}'",
     "        _ignored = (f'access_mode 非法: {_am!r}'"),
]


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, timeout=300, env=env)


def report(name, r):
    fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
    if r.returncode != 0 and fails:
        print(f'  ✅ 抓住 {name}（{len(fails)} 条断言失败）')
        print(f'        首个失败: {fails[0][:86]}')
        return True
    print(f'  ❌ 漏过 {name}')
    if r.returncode != 0 and r.stderr:
        print('        ', r.stderr.strip().splitlines()[-1][:86])
    return False


def main():
    print('=' * 74)
    print('变异验证：配置语义校验（validate_config）')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('❌ 基线没过：')
        print(base.stdout[-2500:])
        if base.stderr:
            print(base.stderr[-1200:])
        return 1
    print(f'基线通过 {base.stdout.count("✅")} 条断言\n')

    caught, noanchor = 0, []
    try:
        for name, old, new in MUTANTS:
            if old not in SRC:
                print(f'  ⚠️  锚点未命中: {name}')
                noanchor.append(name)
                continue
            open(APP, 'w', encoding='utf-8').write(SRC.replace(old, new, 1))
            caught += report(name, run_test())
            open(APP, 'w', encoding='utf-8').write(SRC)
    finally:
        open(APP, 'w', encoding='utf-8').write(SRC)

    print('\n' + '=' * 74)
    print(f'变异 {len(MUTANTS)} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
    if noanchor:
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    print('全部变异均被捕获' if caught == len(MUTANTS) else '有变异漏过')
    return 0 if caught == len(MUTANTS) else 1


if __name__ == '__main__':
    sys.exit(main())
