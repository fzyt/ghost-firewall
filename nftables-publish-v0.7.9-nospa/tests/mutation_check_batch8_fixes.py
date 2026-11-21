#!/usr/bin/env python3
"""变异验证：第 8 批开工前的两处修复（N1 + 供应链条目 8）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_batch8_fixes.py

改的是 tests/test_batch8_fixes.py 对应的两处源码：
  · backend/app.py   —— N1：内网分支（public_access=false）的身份标记
  · setup/setup.sh   —— 条目 8：GitHub 安装包的 sha256 校验（fail-closed）

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
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')
TEST = os.path.join(ROOT, 'tests', 'test_batch8_fixes.py')

SRC = {
    'app': open(APP, encoding='utf-8').read(),
    'setup': open(SETUP, encoding='utf-8').read(),
}
TARGET = {'app': APP, 'setup': SETUP}

# 整块删除校验时用 —— 从 if 到 fi 的完整文本
_VERIFY_BLOCK = r'''        if [ -n "$sum_url" ]; then
            info "校验安装包 sha256 ..."
            if ! curl --connect-timeout 30 --max-time 60 --retry 2 \
                 -fsSL -o "${tmp_dir}/sha256sums.txt" "$sum_url" 2>/dev/null; then
                rm -rf "$tmp_dir"
                error "取不到 sha256 清单，无法校验安装包"
                error "清单 URL: ${sum_url}"
                error "该版本可能没有发布带校验的安装包"
                warn "如需跳过校验，请改用 --local <path> 从本地安装"
                die "拒绝安装未经校验的安装包"
            fi
            local expect actual
            expect="$(awk '$2 ~ /\.tar\.gz$/ {print $1; exit}' "${tmp_dir}/sha256sums.txt" | tr -d '\r')"
            actual="$(sha256_of "${tmp_dir}/archive.tar.gz")"
            if [ -z "$expect" ] || [ "$expect" != "$actual" ]; then
                rm -rf "$tmp_dir"
                error "sha256 校验失败，拒绝安装"
                error "期望: ${expect:-<清单里没有 .tar.gz 条目>}"
                error "实际: ${actual}"
                die "安装包完整性校验未通过"
            fi
            ok "sha256 校验通过"
        else
            # main 是开发分支，没有 release 资产 ⇒ 无清单可比。
            # 开发分支本来就不保证可重现，标醒目警告而不是直接拒绝
            # （拒绝会把「装最新开发代码」这条正常路径堵死）。
            warn "main 是开发分支，没有 sha256 清单可校验"
            warn "正式安装请用 release 版本（--version <tag>）"
        fi
'''

MUTANTS = [
    # ── N1：内网分支的身份标记 ────────────────────────────────────
    ('app', '内网身份标记退回 auth_request_set（原 bug 复现：永不赋值）',
     r'''        L.append("        set $auth_user \"lan\";")''',
     r'''        L.append("        auth_request_set $auth_user \"lan\";")'''),

    ('app', '内网身份标记被清空（内网请求不再带身份）',
     r'''        L.append("        set $auth_user \"lan\";")''',
     r'''        L.append("        set $auth_user \"\";")'''),

    ('app', '内网身份标记换成客户端自称的 cookie（可伪造）',
     r'''        L.append("        set $auth_user \"lan\";")''',
     r'''        L.append("        set $auth_user $cookie_gw_device;")'''),

    ('app', '内网身份标记整行删掉',
     r'''        L.append("        set $auth_user \"lan\";")
''',
     ''),

    ('app', '公网分支的 auth_request 被摘掉（公网不再需要认证）',
     r'''        L.append("        auth_request /_auth;")''',
     r'''        L.append("        auth_request /_auth_disabled;")'''),

    ('app', '公网分支不再从认证服务取设备标识',
     r'''        L.append("        auth_request_set $auth_device $upstream_http_x_auth_device;")
''',
     ''),

    ('app', 'server 级 $auth_device 默认值被删（nginx 会报 unknown variable）',
     r'''    L.append('    set $auth_device "";')
''',
     ''),

    # ── 条目 8：安装包 sha256 校验 ─────────────────────────────────
    ('setup', '整块 sha256 校验被删除（回到「下载完直接解包」）',
     _VERIFY_BLOCK,
     '        # 变异：校验整块被删\n'),

    ('setup', 'sum_url 永远为空（tag 路径也不校验）',
     r'''        sum_url="https://github.com/${GITHUB_REPO}/releases/download/${tag}/sha256sums.txt"''',
     r'''        sum_url=""'''),

    ('setup', '校验条件反转（对不上反而放行）',
     r'''            if [ -z "$expect" ] || [ "$expect" != "$actual" ]; then''',
     r'''            if [ -z "$expect" ] || [ "$expect" = "$actual" ]; then'''),

    ('setup', '校验失败不中止（改成警告后继续装）',
     r'''                rm -rf "$tmp_dir"
                error "sha256 校验失败，拒绝安装"
                error "期望: ${expect:-<清单里没有 .tar.gz 条目>}"
                error "实际: ${actual}"
                die "安装包完整性校验未通过"''',
     r'''                error "sha256 校验失败，拒绝安装"
                error "期望: ${expect:-<清单里没有 .tar.gz 条目>}"
                error "实际: ${actual}"
                warn "安装包完整性校验未通过"'''),

    ('setup', 'sha256_of 返回固定假摘要（校验形同虚设）',
     "        sha256sum \"$1\" | awk '{print $1}'",
     r'''        printf '%s\n' "0000000000000000000000000000000000000000000000000000000000000000"'''),

    ('setup', '清单为空时当成通过（-z 判断写成 -n &&）',
     r'''            if [ -z "$expect" ] || [ "$expect" != "$actual" ]; then''',
     r'''            if [ -n "$expect" ] && [ "$expect" != "$actual" ]; then'''),
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
    # 没抓到：分清是「测不出」还是「测试自己死了」
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
    print('变异验证：第 8 批开工前的两处修复（N1 + 供应链条目 8）')
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
