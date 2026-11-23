#!/usr/bin/env python3
"""变异验证：第四批修复（LAN→WAN 的强制 DNS：去掉写死的公共 DNS）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_batch4_fixes.py

改的是 tests/test_batch4_fixes.py 对应的三处源码：
  · backend/templates/nftables.conf  —— IPv4 的两条 DNS 定向放行
  · backend/app.py                   —— IPv6 的两条 DNS 定向放行
  · backend/template_engine.py       —— 递归解析开关下的收紧规则

判定标准只有一条：**旧代码必然让断言失败**。

⚠ 捕获口径：rc≠0 但输出里**没有 [FAIL] 行不算捕获** ——
  那说明测试自己崩了（导入失败、源码语法错误），不是「测试抓到了缺陷」。
  ⇒ 测试必须「红」而不是「死」。

⚠ 为什么必须变异这三个文件，而不只是模板：
  「强制 DNS」这条链路上有三个独立的失守点 ——
  ① 模板里那两条 IPv4 accept 写死了公共 DNS；
  ② app.py 里那两条 IPv6 accept 写死了公共 DNS；
  ③ template_engine 里那条收紧规则（`ip daddr != $ROUTER_IP4 drop`）与
     「开关判断」本身。少变异一个，就等于有一类缺陷测不出来。
"""
import os
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
TPL = os.path.join(ROOT, 'backend', 'templates', 'nftables.conf')
ENG = os.path.join(ROOT, 'backend', 'template_engine.py')
TEST = os.path.join(ROOT, 'tests', 'test_batch4_fixes.py')

SRC = {
    'app': open(APP, encoding='utf-8').read(),
    'tpl': open(TPL, encoding='utf-8').read(),
    'eng': open(ENG, encoding='utf-8').read(),
}
TARGET = {'app': APP, 'tpl': TPL, 'eng': ENG}

# 模板里那两条 IPv4 的 DNS 放行（udp / tcp 各一条）
_TPL_V4_UDP = ('        iifname $LAN_IF oifname $WAN_IF meta nfproto ipv4 '
               'udp dport 53 ip daddr { $ROUTER_IP4 } accept')
_TPL_V4_TCP = ('        iifname $LAN_IF oifname $WAN_IF meta nfproto ipv4 '
               'tcp dport 53 ip daddr { $ROUTER_IP4 } accept')

# app.py 里那两条 IPv6 的 DNS 放行
_APP_V6_UDP = 'ip6 daddr {{ {router_ip6} }} accept\\n"'
_APP_V6_TCP = 'ip6 daddr {{ {router_ip6} }} accept"'
_APP_V6_BLOCK = (
    '        variables["IPV6_LAN_WAN_DNS_BLOCK"] = (\n'
    '            f"        iifname $LAN_IF oifname $WAN_IF meta nfproto ipv6 '
    'udp dport 53 ip6 daddr {{ {router_ip6} }} accept\\n"\n'
    '            f"        iifname $LAN_IF oifname $WAN_IF meta nfproto ipv6 '
    'tcp dport 53 ip6 daddr {{ {router_ip6} }} accept"\n'
    '        )'
)

MUTANTS = [
    # ── ① 把写死的公共 DNS 加回去（就是这次要修的那个缺陷本身）──────
    ('tpl', 'IPv4 允许列表里加回 114.114.114.114（强制 DNS 又漏了）',
     _TPL_V4_UDP,
     '        iifname $LAN_IF oifname $WAN_IF meta nfproto ipv4 '
     'udp dport 53 ip daddr { $ROUTER_IP4, 114.114.114.114 } accept'),

    ('tpl', 'IPv4 允许列表里加回 223.5.5.5（强制 DNS 又漏了）',
     _TPL_V4_TCP,
     '        iifname $LAN_IF oifname $WAN_IF meta nfproto ipv4 '
     'tcp dport 53 ip daddr { $ROUTER_IP4, 223.5.5.5 } accept'),

    ('app', 'IPv6 允许列表里加回 2400:3200::1（强制 DNS 又漏了）',
     _APP_V6_UDP,
     'ip6 daddr {{ {router_ip6}, 2400:3200::1 }} accept\\n"'),

    ('app', 'IPv6 允许列表里加回 2400:3200:baba::1（强制 DNS 又漏了）',
     _APP_V6_TCP,
     'ip6 daddr {{ {router_ip6}, 2400:3200:baba::1 }} accept"'),

    # ── ② 允许列表指向了别的东西（不再是路由器自己）─────────────────
    ('tpl', 'IPv4 允许列表指向广播地址而不是路由器',
     _TPL_V4_UDP,
     '        iifname $LAN_IF oifname $WAN_IF meta nfproto ipv4 '
     'udp dport 53 ip daddr { $LAN_BROADCAST4 } accept'),

    # ── ③ 放行规则整段没了 ─────────────────────────────────────────
    ('tpl', 'IPv4 的 DNS 放行规则被整段删掉',
     _TPL_V4_UDP + '\n' + _TPL_V4_TCP,
     ''),

    ('app', 'IPv6 的 DNS 放行规则整块被删掉',
     _APP_V6_BLOCK,
     '        variables["IPV6_LAN_WAN_DNS_BLOCK"] = ""'),

    # ── ④ 收紧规则本身失效 ─────────────────────────────────────────
    ('eng', '收紧规则被改成只 drop 路由器自己（等于不收紧）',
     'ip daddr != $ROUTER_IP4 drop',
     'ip daddr { $ROUTER_IP4 } drop'),

    ('eng', '递归解析开关的判断失效（开关形同虚设）',
     "if variables.get('DNS_LAN_RESOLVER_ENABLED') == 'true':",
     'if False:'),

    # ── ⑤ 内网解析被误改成出网方向（用户关心的「不影响内网解析」）──────
    # 锚点刻意只取「不含反斜杠」的那一段：这一行的结尾带 \\\n（续行+换行），
    # 在 Python 字符串里写全要层层转义，容易错一个反斜杠就锚不中。
    ('app', '内网解析的 DNS 规则被改成 LAN→WAN 方向',
     'iifname $LAN_IF oifname $LAN_IF ip daddr {srv} udp dport 53',
     'iifname $LAN_IF oifname $WAN_IF ip daddr {srv} udp dport 53'),
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
    print('变异验证：第四批修复（LAN→WAN 的强制 DNS 去掉写死的公共 DNS）')
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
