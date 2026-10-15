#!/usr/bin/env python3
"""变异验证：lan_subnet4 掩码丢失这一轮的 4 处防线。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_lan_mask.py

对应测试: tests/test_lan_mask_loss.py

四道防线，每一道都要能被「单独打掉时测试立刻失败」证明有效：

  1. setup.sh detect_lan_ipv4 —— 保留掩码 + 只取第一个地址 + 算广播
  2. setup.sh init_config —— 真的调用上面那个函数（变量名映射对）
  3. _migrate_lan_subnet —— load_config 自愈已装机器的无掩码配置
  4. validate_config —— 拒绝手工填的无掩码输入（防再次引入）

第 1/2 条改的是 setup.sh：那些变异跑的是同一个 test_lan_mask_loss.py，
它会自己从 setup.sh 源码里抽函数和 init_config 的提取段来实跑，
所以变异直接生效、断言直接失败 —— 不依赖任何源码正则。
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')
TEST = os.path.join(ROOT, 'tests', 'test_lan_mask_loss.py')

SRC = open(APP, encoding='utf-8').read()
SSRC = open(SETUP, encoding='utf-8').read()

# ── app.py 侧的变异 ────────────────────────────────────────────────────
APP_MUTANTS = [
    ('迁移不补掩码（已部署机器永远自愈不了）',
     "        # IPv6 常用 /64，IPv4 默认 /24\n"
     "        default_plen = 64 if ':' in raw else 24\n"
     "        fixed = f'{raw}/{default_plen}'",
     "        # IPv6 常用 /64，IPv4 默认 /24\n"
     "        default_plen = 64 if ':' in raw else 24\n"
     "        fixed = raw"),

    ('迁移把 IPv6 也按 /24 处理',
     "        default_plen = 64 if ':' in raw else 24",
     "        default_plen = 24"),

    ('迁移改用 ip_network 判「是不是裸 IP」（带掩码的 /28 也会被覆写）',
     "            ipaddress.ip_address(raw)",
     "            ipaddress.ip_network(raw, strict=False)"),

    ('迁移把非法字符串也补掩码',
     "        try:\n"
     "            # ip_address 只认裸地址，带 /24 的会直接抛 ValueError ——\n"
     "            # 「只处理缺掩码的值」这件事就靠这一句，不要再加 '/' 判断，\n"
     "            # 那是恒等分支（两条路都 continue），加了反而看不出哪条真正生效。\n"
     "            ipaddress.ip_address(raw)\n"
     "        except ValueError:\n"
     "            continue",
     "        pass"),

    ('load_config 里不调用迁移（函数在但没接上）',
     "        result = _migrate_lan_subnet(result)\n",
     ""),

    ('validate_config 不再要求掩码（手工填的无掩码值又放行了）',
     "        if '/' not in raw:",
     "        if False:"),

    ('validate_config 把无掩码当成合法网段放过',
     "        if '/' not in raw:",
     "        if False:\n            pass\n        if False:"),
]

# ── setup.sh 侧的变异 ──────────────────────────────────────────────────
SETUP_MUTANTS = [
    # init_config 的提取段：整段换回旧管道（丢掩码 + 多行）
    ('init_config 换回丢掩码的旧管道',
     '    eval "$(detect_lan_ipv4 "$LAN_IFACE")"\n'
     '    broadcast4="$lan_broadcast4"\n'
     '    router_ip4="$lan_host4"',
     "    lan_subnet4=\"$(ip -4 addr show \"$LAN_IFACE\" 2>/dev/null | "
     "grep inet | awk '{print $2}' | cut -d/ -f1 | "
     "sed 's/\\.[0-9]*$/.0/')\"\n"
     '    broadcast4="${lan_subnet4%.*}.255"'),

    # detect_lan_ipv4 内部：把切分从 / 改成空 → 丢掉掩码
    ('探测函数里丢掉掩码（切分符改错）',
     "            host = f[1].split('/', 1)[0]\n            cidr = f[1]",
     "            host = f[1].split('/', 1)[0]\n            cidr = host"),

    # 去掉 break → 多地址 LAN 产出多行 → JSON 非法
    ('探测函数不再只取第一个地址（多地址 LAN 写出非法 JSON）',
     "            host = f[1].split('/', 1)[0]\n"
     "            cidr = f[1]\n"
     "            break\n"
     "except (OSError, subprocess.SubprocessError):\n"
     "    pass\n\n# 2)",
     "            host = f[1].split('/', 1)[0]\n"
     "            cidr = f[1]\n"
     "except (OSError, subprocess.SubprocessError):\n"
     "    pass\n\n# 2)"),

    # 广播地址用拼接而不是按掩码算
    ('广播地址退回按 /24 硬拼',
     "print('lan_broadcast4=%s' % net.broadcast_address)",
     "print('lan_broadcast4=%s' % (net.network_address + 254))"),

    # init_config 变量名映射错位（等价于没接上探测结果）
    ('init_config 把探测结果赋给了错的变量（静默退化成兜底值）',
     '    broadcast4="$lan_broadcast4"\n'
     '    router_ip4="$lan_host4"',
     '    broadcast4=""\n    router_ip4=""'),

    # 兜底值不带掩码
    ('兜底值也不带掩码（回到 /32 的老毛病）',
     '    [ -z "$lan_subnet4" ] && lan_subnet4="${LAN_SUBNET4_FALLBACK:-192.168.1.0/24}"',
     '    [ -z "$lan_subnet4" ] && lan_subnet4="${LAN_SUBNET4_FALLBACK:-192.168.1.0}"'),

    # ip addr → ip -6（IPv4 探测永远失败）
    ("探测改用 ip -6（拿不到 IPv4 网段）",
     "res = subprocess.run(['ip', '-4', 'addr', 'show', 'dev', iface],",
     "res = subprocess.run(['ip', '-6', 'addr', 'show', 'dev', iface],"),
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
        tail = r.stderr.strip().splitlines()
        if tail:
            print('        ', tail[-1][:86])
    return False


def main():
    print('=' * 74)
    print('变异验证：lan_subnet4 掩码丢失（4 处防线）')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('❌ 基线没过：')
        print(base.stdout[-3000:])
        return 1
    print(f'基线通过 {base.stdout.count("✅")} 条断言\n')

    caught, noanchor = 0, []
    try:
        for name, old, new in APP_MUTANTS:
            if old not in SRC:
                print(f'  ⚠️  锚点未命中: {name}')
                noanchor.append(name)
                continue
            open(APP, 'w', encoding='utf-8').write(SRC.replace(old, new, 1))
            caught += report(name, run_test())
            open(APP, 'w', encoding='utf-8').write(SRC)
        for name, old, new in SETUP_MUTANTS:
            if old not in SSRC:
                print(f'  ⚠️  锚点未命中: {name}')
                noanchor.append(name)
                continue
            open(SETUP, 'w', encoding='utf-8').write(SSRC.replace(old, new, 1))
            caught += report(name, run_test())
            open(SETUP, 'w', encoding='utf-8').write(SSRC)
    finally:
        open(APP, 'w', encoding='utf-8').write(SRC)
        open(SETUP, 'w', encoding='utf-8').write(SSRC)

    total = len(APP_MUTANTS) + len(SETUP_MUTANTS)
    print('\n' + '=' * 74)
    print(f'变异 {total} 处  捕获 {caught}  漏过 {total - caught}  '
          f'锚点未命中 {len(noanchor)}')
    if noanchor:
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    return 0 if caught == total else 1


if __name__ == '__main__':
    sys.exit(main())
