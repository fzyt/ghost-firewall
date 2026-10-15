#!/usr/bin/env python3
"""变异验证：trusted_ip4 单值语义。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_trusted_ip.py
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
HTML = os.path.join(ROOT, 'frontend', 'index.html')
TEST = os.path.join(ROOT, 'tests', 'test_trusted_ip_single.py')

SRC = open(APP, encoding='utf-8').read()
HSRC = open(HTML, encoding='utf-8').read()

MUTANTS = [
    ('_trusted_ip_single 取最后一个而不是第一个',
     "    effective = _safe_ip(v, 4, '', strict=True) or None",
     "    _l = _ip_list(v)\n"
     "    effective = next((x for x in reversed(_l) if _valid_ip(x, 4)), None)"),

    ('_trusted_ip_single 不再委托 _safe_ip，自己「智能」拆逗号串',
     "    effective = _safe_ip(v, 4, '', strict=True) or None",
     "    _l = _ip_list(v)\n"
     "    effective = next((x for x in _l if _valid_ip(x, 4)), None)"),

    ('_trusted_ip_single 永远返回 None（白名单整体失效）',
     "    effective = _safe_ip(v, 4, '', strict=True) or None",
     "    effective = None"),

    ('丢弃项不再上报（静默吞掉）',
     "    ignored = [x for x in _ip_list(v) if x != effective]",
     "    ignored = []"),

    ('_detect_risks 退回按集合算（自锁告警口径与执行不一致）',
     "    old_trusted, _old_ignored = _trusted_ip_single(old_cfg.get('trusted_ip4'))\n"
     "    new_trusted, new_ignored = _trusted_ip_single(new_cfg.get('trusted_ip4'))",
     "    old_trusted = next(iter(_ip_set(old_cfg.get('trusted_ip4'))), None)\n"
     "    new_trusted_set = _ip_set(new_cfg.get('trusted_ip4'))\n"
     "    new_trusted = next(iter(new_trusted_set), None)\n"
     "    new_ignored = []"),

    ('去掉「多值被丢弃」风险告警',
     "    if new_ignored:",
     "    if False:"),

    ('保存时不归一化成单值（配置与执行继续不一致）',
     "    _eff_trusted, _ignored_trusted = _trusted_ip_single(new_cfg.get('trusted_ip4'))\n"
     "    new_cfg['trusted_ip4'] = _eff_trusted or ''",
     "    pass"),

    ('归一化提到风险检测之前（多值告警永远不触发）',
     "    requester_ip = request.remote_addr or ''\n"
     "    risks = _detect_risks(old_cfg, new_cfg, requester_ip)\n"
     "\n"
     "    # trusted_ip4 归一化成单值再落盘。",
     "    requester_ip = request.remote_addr or ''\n"
     "    _e0, _ = _trusted_ip_single(new_cfg.get('trusted_ip4'))\n"
     "    new_cfg['trusted_ip4'] = _e0 or ''\n"
     "    risks = _detect_risks(old_cfg, new_cfg, requester_ip)\n"
     "\n"
     "    # trusted_ip4 归一化成单值再落盘。"),
]

HTML_MUTANTS = [
    ('前端删掉「只支持一个 IP」提示',
     '            <p class="text-xs text-gray-500 mt-1">只支持一个 IP。填多个不会多放行 —— 规则只认第一个，其余会被丢弃。</p>\n',
     ''),
]


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, timeout=240, env=env)


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
    print('变异验证：trusted_ip4 单值语义')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('❌ 基线没过：')
        print(base.stdout[-2500:])
        return 1
    print(f'基线通过 {base.stdout.count("✅")} 条断言\n')

    caught, missed, noanchor = 0, [], []
    try:
        for name, old, new in MUTANTS:
            if old not in SRC:
                print(f'  ⚠️  锚点未命中: {name}')
                noanchor.append(name)
                continue
            open(APP, 'w', encoding='utf-8').write(SRC.replace(old, new, 1))
            caught += report(name, run_test())
            open(APP, 'w', encoding='utf-8').write(SRC)
        for name, old, new in HTML_MUTANTS:
            if old not in HSRC:
                print(f'  ⚠️  锚点未命中: {name}')
                noanchor.append(name)
                continue
            open(HTML, 'w', encoding='utf-8').write(HSRC.replace(old, new, 1))
            caught += report(name, run_test())
            open(HTML, 'w', encoding='utf-8').write(HSRC)
    finally:
        open(APP, 'w', encoding='utf-8').write(SRC)
        open(HTML, 'w', encoding='utf-8').write(HSRC)

    total = len(MUTANTS) + len(HTML_MUTANTS)
    print('\n' + '=' * 74)
    print(f'变异 {total} 处  捕获 {caught}  漏过 {len(missed)}  锚点未命中 {len(noanchor)}')
    if noanchor:
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    return 0 if caught == total else 1


if __name__ == '__main__':
    sys.exit(main())
