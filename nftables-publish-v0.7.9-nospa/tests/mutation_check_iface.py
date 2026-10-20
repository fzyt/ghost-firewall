#!/usr/bin/env python3
"""变异验证：每处变异都必须被 tests/test_iface_from_config.py 抓住。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_iface.py
"""
import os
import subprocess
import sys
import tempfile

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_iface_from_config.py')
SRC = open(APP, encoding='utf-8').read()

# (名称, 变异前锚点, 变异后)
MUTANTS = [
    (
        'wan_if 又写死回 pppoe-wan',
        "    wan_if = _safe_iface(cfg.get('wan_if'), 'pppoe-wan')",
        "    wan_if = 'pppoe-wan'",
    ),
    (
        'lan_if 又写死回 br-lan',
        "    lan_if = _safe_iface(cfg.get('lan_if'), 'br-lan')",
        "    lan_if = 'br-lan'",
    ),
    (
        # 刻意不列：'_client_is_lan 调用点不传 config'。
        # _client_is_lan 首行就 `if ':' in client_ip: return False`，只处理 IPv4；
        # 它唯一消费的 LAN_SUBNET4 来自 parse_uci_config('/etc/config/network')，
        # 与 lan_if / wan_if 完全无关。所以那处传不传 cfg 行为完全一致，
        # 是惰性写法而不是缺陷 —— 列进来只会造出一个「漏过」的假警报。
        '调用点不传 config（config_to_variables）',
        "    detected = _auto_detect_network(config)",
        "    detected = _auto_detect_network()",
    ),
    (
        '_ipv6_prefix 退回手工切段（旧算法第 4 组为空会左移）',
        "        return str(ipaddress.ip_interface(addr_with_plen).network)",
        "        ip, plen = str(addr_with_plen).split('/')\n"
        "        parts = [p for p in ip.split(':') if p]\n"
        "        return (':'.join(parts[:4]) + '::/' + plen) if len(parts) >= 4 else None",
    ),
    (
        '_ipv6_prefix 恒返回 None（探测静默失效）',
        "        return str(ipaddress.ip_interface(addr_with_plen).network)",
        "        return None",
    ),
    (
        '接口名白名单被去掉（注入放行）',
        "    lan_if = _safe_iface(cfg.get('lan_if'), 'br-lan')\n"
        "    wan_if = _safe_iface(cfg.get('wan_if'), 'pppoe-wan')",
        "    lan_if = str(cfg.get('lan_if') or 'br-lan')\n"
        "    wan_if = str(cfg.get('wan_if') or 'pppoe-wan')",
    ),
]


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, timeout=180, env=env)


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print('=' * 74)
    print('变异验证：接口名配置化')
    print('=' * 74)

    base = run_test()
    if base.returncode != 0:
        print('❌ 基线就没过，先修测试：')
        print(base.stdout[-2000:], base.stderr[-2000:])
        return 1
    baseline_pass = base.stdout.count('✅')
    print(f'基线通过 {baseline_pass} 条断言\n')

    caught, missed = [], []
    bak = tempfile.mkdtemp()
    backup = os.path.join(bak, 'app.py')
    with open(backup, 'w', encoding='utf-8') as f:
        f.write(SRC)

    try:
        for name, old, new in MUTANTS:
            if old not in SRC:
                print(f'  ⚠️  锚点没命中，跳过: {name}')
                missed.append(name + '（锚点未命中）')
                continue
            with open(APP, 'w', encoding='utf-8') as f:
                f.write(SRC.replace(old, new, 1))
            r = run_test()
            failed = r.returncode != 0
            detail = ''
            if failed:
                fails = [ln.strip() for ln in r.stdout.splitlines() if '❌' in ln]
                detail = f'（{len(fails)} 条断言失败）'
                caught.append(name)
            else:
                missed.append(name)
            print(('  ✅ 抓住 ' if failed else '  ❌ 漏过 ') + name + detail)
            if failed and fails:
                print(f'        首个失败断言: {fails[0][:88]}')
            with open(APP, 'w', encoding='utf-8') as f:
                f.write(SRC)
    finally:
        with open(APP, 'w', encoding='utf-8') as f:
            f.write(SRC)

    print('\n' + '=' * 74)
    print(f'变异 {len(MUTANTS)} 处  捕获 {len(caught)}  漏过 {len(missed)}')
    if missed:
        for m in missed:
            print('  -', m)
        return 1
    print('全部变异均被捕获')
    return 0


if __name__ == '__main__':
    sys.exit(main())
