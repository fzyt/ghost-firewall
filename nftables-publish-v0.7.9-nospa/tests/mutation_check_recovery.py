#!/usr/bin/env python3
"""变异验证：恢复链的两处修复是否都被测试真正守住。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_recovery.py
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_recovery_chain.py')
SRC = open(APP, encoding='utf-8').read()

MUTANTS = [
    (
        '守卫退回「只判文件存不存在」',
        "    # 优先级 2：按当前配置重新生成\n"
        "    #\n"
        "    # 这一步必须排在 .backup 之前。",
        "    if os.path.exists(RULES_PATH):\n"
        "        return\n"
        "    # 优先级 2：按当前配置重新生成\n"
        "    #\n"
        "    # 这一步必须排在 .backup 之前。",
    ),
    (
        '坏文件不留 .corrupted 证据',
        "            _quarantine = RULES_PATH + '.corrupted'\n"
        "            shutil.copy(RULES_PATH, _quarantine)",
        "            _quarantine = None",
    ),
    (
        '_ruleset_is_degraded 恒返回 False（降级态又看不见了）',
        "    if 'jump input_wan' in out:\n"
        "        return False, '完整规则集'\n"
        "    return True, 'basic lockdown（input 链已不再引用 input_wan：敲门/转发/黑名单均未生效）'",
        "    return False, '完整规则集'",
    ),
    (
        '_ruleset_is_degraded 恒返回 True（完整规则集被误判成降级，无限抖动）',
        "    if 'jump input_wan' in out:\n"
        "        return False, '完整规则集'\n"
        "    return True, 'basic lockdown（input 链已不再引用 input_wan：敲门/转发/黑名单均未生效）'",
        "    return True, 'basic lockdown'",
    ),
    (
        '判别标志退回「input_wan 链存不存在」（追加语义下两种规则集都有这条链）',
        "    if 'jump input_wan' in out:",
        "    if 'chain input_wan' in out:",
    ),
    (
        'basic lockdown 不再 flush（退回追加语义，降级形同虚设）',
        "        subprocess.run(['nft', 'flush', 'table', 'inet', 'fw4'],\n"
        "                       capture_output=True, text=True, timeout=5)",
        "        pass",
    ),
    (
        'basic lockdown 去掉「装完仍引用 input_wan 就算失败」的校验',
        "    if _input_chain_still_references_wan():",
        "    if False and _input_chain_still_references_wan():",
    ),
    (
        '_recover_ruleset_if_unhealthy 去掉降级分支（退回单向门）',
        "    if functional:\n"
        "        if not _ruleset_is_degraded()[0]:\n"
        "            return False, '正常'\n"
        "        return _promote_lockdown_to_full()",
        "    if functional:\n"
        "        return False, '正常'",
    ),
    (
        '_watchdog_tick 去掉降级分支（tick 永不触发切回）',
        "        degraded, degr = _ruleset_is_degraded()\n"
        "        if not degraded:",
        "        degraded, degr = (False, '跳过')\n"
        "        if not degraded:",
    ),
    (
        '重试上限失效（每 5 分钟无限 nft -f 抖动）',
        "    if _WATCHDOG.get('promote_fails', 0) >= _PROMOTE_MAX_FAILS:",
        "    if False:",
    ),
    (
        '健康接口不暴露降级态（面板永远显示「正常」）',
        "            'ruleset_degraded': degraded,\n"
        "            'degraded_detail': degrade_detail,",
        "            'ruleset_degraded': False,\n"
        "            'degraded_detail': '',",
    ),
]


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, timeout=240, env=env)


def main():
    print('=' * 74)
    print('变异验证：恢复链')
    print('=' * 74)

    base = run_test()
    if base.returncode != 0:
        print('❌ 基线没过：')
        print(base.stdout[-2500:])
        return 1
    print(f'基线通过 {base.stdout.count("✅")} 条断言\n')

    caught, missed, noanchor = [], [], []
    try:
        for name, old, new in MUTANTS:
            if old not in SRC:
                print(f'  ⚠️  锚点未命中，跳过: {name}')
                noanchor.append(name)
                continue
            with open(APP, 'w', encoding='utf-8') as f:
                f.write(SRC.replace(old, new, 1))
            r = run_test()
            fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
            if r.returncode != 0 and fails:
                caught.append(name)
                print(f'  ✅ 抓住 {name}（{len(fails)} 条断言失败）')
                print(f'        首个失败: {fails[0][:86]}')
            else:
                missed.append(name)
                print(f'  ❌ 漏过 {name}')
            with open(APP, 'w', encoding='utf-8') as f:
                f.write(SRC)
    finally:
        with open(APP, 'w', encoding='utf-8') as f:
            f.write(SRC)

    print('\n' + '=' * 74)
    print(f'变异 {len(MUTANTS)} 处  捕获 {len(caught)}  漏过 {len(missed)}  '
          f'锚点未命中 {len(noanchor)}')
    if missed or noanchor:
        for m in missed:
            print('  漏过:', m)
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    print('全部变异均被捕获')
    return 0


if __name__ == '__main__':
    sys.exit(main())
