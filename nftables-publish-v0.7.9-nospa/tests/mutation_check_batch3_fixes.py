#!/usr/bin/env python3
"""变异验证：第三批修复（条目 43 / 14 / 55）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_batch3_fixes.py

改的是 tests/test_batch3_fixes.py 对应的两处源码：
  · backend/app.py         —— 条目 43（规则集权限/属主守卫）、条目 55（端口变更提示）
  · backend/auth_gateway.py —— 条目 14（审计日志轮转保留 login_ok）

判定标准只有一条：**旧代码必然让断言失败**。

⚠ 捕获口径：rc≠0 但输出里**没有 [FAIL] 行不算捕获** ——
  那说明测试自己崩了（导入失败、源码语法错误），不是「测试抓到了缺陷」。
  ⇒ 测试必须「红」而不是「死」。
"""
import os
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
AUTH = os.path.join(ROOT, 'backend', 'auth_gateway.py')
TEST = os.path.join(ROOT, 'tests', 'test_batch3_fixes.py')

SRC = {
    'app': open(APP, encoding='utf-8').read(),
    'auth': open(AUTH, encoding='utf-8').read(),
}
TARGET = {'app': APP, 'auth': AUTH}

# 条目 14：ALWAYS 优先的整个循环（删掉它 = 退回「只留尾部」）
_ALWAYS_LOOP = '''    keep_idx = set()
    total = 0
    for i in range(len(lines) - 1, -1, -1):
        if not _audit_line_is_always(lines[i]):
            continue
        sz = len(lines[i].encode("utf-8"))
        if keep_idx and total + sz > budget:
            break
        keep_idx.add(i)
        total += sz
'''

MUTANTS = [
    # ── 条目 55：端口变更提示 ────────────────────────────────────────
    ('app', '端口变化检测失效（改了端口不提示重启 ⇒ 所有登录 502）',
     "    if _old_api_port != _new_api_port:",
     "    if False:"),

    ('app', '提示文案里不再点明「必须重启认证服务」',
     'f"必须重启认证服务才生效（执行 /etc/init.d/nftables-web-auth restart）。"',
     'f"端口已变更。"'),

    ('app', '提示被整个丢掉（warning 恒为空）',
     '    warning = "；".join(_notices) if _notices else None',
     '    warning = None'),

    # ── 条目 14：审计轮转保留 login_ok ───────────────────────────────
    ('auth', 'ALWAYS 判定恒为 False（退回「只留尾部」，login_ok 被挤掉）',
     '''    if not isinstance(rec, dict):
        return False
    return str(rec.get("event") or "") in _AUDIT_ALWAYS''',
     '''    if not isinstance(rec, dict):
        return False
    return False'''),

    ('auth', 'ALWAYS 判定用错集合（拿可灌水事件当「永远该留」）',
     '    return str(rec.get("event") or "") in _AUDIT_ALWAYS',
     '    return str(rec.get("event") or "") in _AUDIT_FLOODABLE'),

    ('auth', 'ALWAYS 优先的循环被删掉（整段退回原行为）',
     _ALWAYS_LOOP,
     '    keep_idx = set()\n    total = 0\n'),

    # ── 条目 43：规则集权限/属主守卫 ─────────────────────────────────
    ('app', '属主检查失效（非 root 拥有的规则集也被照常加载）',
     "        if os.geteuid() == 0 and st.st_uid != 0:",
     "        if False:"),

    ('app', '目录权限不再收紧（可写的目录继续可写）',
     "    if st.st_mode & 0o022:\n        try:\n            os.chmod(d, 0o755)",
     "    if False:\n        try:\n            os.chmod(d, 0o755)"),

    ('app', '备份材料不再收口（.backup 继续 world-readable）',
     "        if st.st_mode & 0o077:\n            _ensure_file_mode(p, 0o600)",
     "        if False:\n            _ensure_file_mode(p, 0o600)"),

    ('app', '守卫整个不调用（权限/属主检查形同虚设）',
     '''    _perm_ok, _perm_msg = _ruleset_perm_guard()
    if not _perm_ok:
        return False, _perm_msg''',
     '''    _perm_ok, _perm_msg = True, ''
    if not _perm_ok:
        return False, _perm_msg'''),
]


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, timeout=600, env=env)


def report(name, r):
    fails = [l.strip() for l in r.stdout.splitlines() if '[FAIL]' in l]
    if fails:
        print(f'  [OK] 抓住 {name}（{len(fails)} 条断言失败）')
        print(f'        首个失败: {fails[0][:86]}')
        return True
    if r.returncode != 0:
        print(f'  [FAIL] 漏过 {name} —— 但测试是**崩了**不是红了，不算捕获')
        tail = (r.stderr.strip().splitlines() or ['(无 stderr)'])
        print('        ', tail[-1][:86])
    else:
        print(f'  [FAIL] 漏过 {name}')
    return False


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print('=' * 74)
    print('变异验证：第三批修复（条目 43 / 14 / 55）')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('[FAIL] 基线没过：')
        print(base.stdout[-2500:])
        if base.stderr:
            print(base.stderr[-1200:])
        return 1
    print(f'基线通过 {base.stdout.count("[PASS]")} 条断言\n')

    caught, noanchor = 0, []
    try:
        for key, name, old, new in MUTANTS:
            src = SRC[key]
            if src.count(old) != 1:
                print(f'  [FAIL] 锚点未命中（出现 {src.count(old)} 次）: {name}')
                noanchor.append(name)
                continue
            with open(TARGET[key], 'w', encoding='utf-8') as f:
                f.write(src.replace(old, new, 1))
            caught += report(name, run_test())
            with open(TARGET[key], 'w', encoding='utf-8') as f:
                f.write(src)
    finally:
        for key, path in TARGET.items():
            with open(path, 'w', encoding='utf-8') as f:
                f.write(SRC[key])

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
