#!/usr/bin/env python3
"""变异验证：看门狗恢复链路。

这个脚本是补上来的 —— tests/test_fw_recovery.py 有 58 条断言，
但四个既有变异脚本没有一个覆盖它（分别对着 review/security/privilege/functional），
等于这批断言从来没被证明过「在缺陷重现时会失败」。

每条变异对应「这个保护如果没做，看门狗会退化到什么行为」。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_fw_recovery.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = {'app': os.path.join(ROOT, 'backend', 'app.py')}
TEST = os.path.join(ROOT, 'tests', 'test_fw_recovery.py')

# (描述, 文件键, 旧文本, 新文本, 期望出现次数)
MUTATIONS = [
    # ── _try_apply_rules_file 的二次检查 ──────────────────────────
    ('WDR-1 二次检查退回「表在不在」（空文件又被误判成成功）', 'app',
     '    ok, detail = _ruleset_is_functional()\n'
     '    if not ok:\n'
     "        print(f'[WARN] nft -f {path} returncode=0 但规则集仍不可用（{detail}），'\n"
     "              f'视为失败', flush=True)\n"
     '        return False',
     '    if _ruleset_is_empty():\n'
     '        return False', 1),

    ('WDR-1 二次检查整个删掉（rc=0 就当成功）', 'app',
     '    ok, detail = _ruleset_is_functional()\n'
     '    if not ok:\n'
     "        print(f'[WARN] nft -f {path} returncode=0 但规则集仍不可用（{detail}），'\n"
     "              f'视为失败', flush=True)\n"
     '        return False',
     '    pass', 1),

    # ── nft -f 的错误处理 ────────────────────────────────────────
    ('WDR-2 nft -f 非零退出码被忽略（语法错误的文件也当成功）', 'app',
     "    if res.returncode != 0:\n"
     "        print(f'[WARN] nft -f {path} returncode={res.returncode}, '\n"
     "              f'stderr={(res.stderr or res.stdout)[:200]}', flush=True)\n"
     '        return False',
     '    pass', 1),

    ('WDR-2 subprocess 异常不再吞掉（FileNotFoundError 会炸穿恢复链路）', 'app',
     '    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:\n'
     "        print(f'[WARN] nft -f {path} 异常: {type(e).__name__}: {e}', flush=True)\n"
     '        return False',
     '    except Exception as e:\n'
     '        raise e', 1),

    # ── 健康判据的严格性 ────────────────────────────────────────
    ('WDR-3 健康检查不要求 input 链挂 hook（整体 flush 过也判健康）', 'app',
     "    if 'hook input' not in out:\n"
     "        return False, 'input 链未挂载 —— 规则集不完整（可能被整体 flush 过）'",
     "    if False:\n"
     "        return False, 'never'", 1),

    ('WDR-3 健康检查不要求 drop/reject 策略（防火墙没生效也判健康）', 'app',
     "    if 'policy drop' not in out and 'policy reject' not in out:\n"
     "        return False, 'input 链没有 drop/reject 默认策略 —— 防火墙可能未生效'",
     "    if False:\n"
     "        return False, 'never'", 1),

    # ── 重试循环：必须轮得到 .lastgood ───────────────────────────
    ('WDR-4 重试循环只试 RULES_PATH，.lastgood 永远轮不到', 'app',
     '        for _p in (RULES_PATH, RULES_PATH + \'.lastgood\'):',
     '        for _p in (RULES_PATH,):', 1),

    ('WDR-4 重试循环第一个成功就 break（空文件假成功后不再回退）', 'app',
     '                if os.path.exists(_p) and _try_apply_rules_file(_p):\n'
     '                    reloaded = True\n'
     '                    break',
     '                if os.path.exists(_p) and _try_apply_rules_file(_p):\n'
     '                    reloaded = True', 1),

    # ── 恢复分级 ────────────────────────────────────────────────
    ('WDR-5 表为空时直接跳到 basic lockdown（跳过 .backup）', 'app',
     '        if _ruleset_is_empty():\n'
     "            print('[WATCHDOG] 规则集为空，触发启动级恢复链', flush=True)\n"
     '            _auto_recover_ruleset_if_empty()',
     '        if _ruleset_is_empty():\n'
     '            _apply_basic_lockdown()', 1),

    ('WDR-5 恢复后不复查（没修好也报「已恢复」）', 'app',
     '        functional, detail = _ruleset_is_functional()\n'
     '        if functional:\n'
     "            what = '已恢复' if reloaded else '复查后已正常（本次未执行任何重载）'\n"
     '            return reloaded, f\'{what}（{detail}）\'',
     '        if reloaded:\n'
     '            return True, \'已恢复\'', 1),

    ('WDR-5 持锁后不复查（可能和用户的「应用规则」抢跑）', 'app',
     '        functional, detail = _ruleset_is_functional()\n'
     '        if functional:\n'
     "            return False, '复查后已正常'",
     '        pass', 1),
]


def run_tests():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       timeout=300, env=env)
    return r.returncode, r.stdout


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    backup = tempfile.mkdtemp()
    for key, path in FILES.items():
        shutil.copy(path, os.path.join(backup, key))
    originals = {key: open(path, encoding='utf-8').read() for key, path in FILES.items()}

    def restore():
        for key, path in FILES.items():
            shutil.copy(os.path.join(backup, key), path)

    print('=== 变异验证：看门狗恢复链路 ===')
    rc, _ = run_tests()
    if rc != 0:
        print('❌ 基线就不是全绿，先修好再谈变异')
        restore()
        shutil.rmtree(backup, ignore_errors=True)
        return 1

    caught = missed = skipped = 0
    missed_list = []
    for desc, key, old, new, expect in MUTATIONS:
        src = originals[key]
        n = src.count(old)
        if n != expect:
            print(f'  ⚠️  {desc} —— 锚点出现 {n} 次（期望 {expect}），跳过')
            skipped += 1
            continue
        open(FILES[key], 'w', encoding='utf-8').write(src.replace(old, new))
        rc, out = run_tests()
        fails = out.count('❌')
        if rc != 0:
            print(f'  ✅ {desc} —— 被捕获（{fails} 条断言失败）')
            caught += 1
        else:
            print(f'  ❌ {desc} —— 测试仍然全绿（无效变异！）')
            missed += 1
            missed_list.append(desc)
        restore()

    total = caught + missed + skipped
    print(f'\n=== 结果：捕获 {caught} / {total}'
          + (f'（跳过 {skipped}）' if skipped else '') + ' ===')
    for m in missed_list:
        print('  未捕获: ' + m)
    restore()
    shutil.rmtree(backup, ignore_errors=True)
    return 0 if missed == 0 and skipped == 0 else 1


if __name__ == '__main__':
    sys.exit(main())