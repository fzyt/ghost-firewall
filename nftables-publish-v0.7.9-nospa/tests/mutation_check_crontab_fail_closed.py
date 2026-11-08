#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
「读 crontab 失败必须 fail-closed」的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_crontab_fail_closed.py

测什么有效
----------
P0-10 的原始故障读起来**完全正常**：接口返回 200「配置已保存」，
日志里什么都没有，crontab 里只是少了两条别人的任务。
代码里那句 `if result.returncode != 0: return False, ...` 长得就跟
周围一堆 return 一样，不盯着看根本看不出它是**唯一**的防线。

所以下面每条变异都往「让闸门漏判」的方向改；抓不住就说明测试是假测试。

覆盖三层
--------
  源码层   闸门是否还在读点与写点之间、是否真的 return
  行为层   读失败（三种形态）是否明确失败、是否绝不执行 `crontab -`
  写回层   写失败是否如实报错（不能报「已更新」）

对应关系
--------
  M1  摘掉 _manage_ddns_cron 的 returncode 闸门
  M2  摘掉 _upsert_cron_for 的 returncode 闸门
  M3  摘掉 install_china_ips 的 returncode 闸门
  M4  _manage_ddns_cron 读失败当成空表（回到 P0-10 原始写法）
  M5  _upsert_cron_for 读失败当成空表
  M6  闸门挪到写回之后（先覆盖再检查）
  M7  _manage_ddns_cron 写回失败不上报（报「已更新」）
  M8  闸门只 return 不带失败语义（改成 return True —— 面板报「已保存」）
  M9  闸门缩到只拦某一种异常（FileNotFoundError 之外的异常直接抛出）

保险丝：只备份 / 还原**我自己会改的那一个文件**（backend/app.py），
不碰别人的文件。

锚点
----
每条变异用成对的精确字符串，且必须在源码里**唯一**。
匹配不上就当场报错并算作漏网 —— 变异根本没跑 = 覆盖漏洞，
不是「这条不需要测」。
"""
import atexit
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_crontab_fail_closed.py')

# 我独占、也只有我会改的那一个文件。
ORIG = {APP_PY: open(APP_PY, encoding='utf-8').read()}


def restore():
    """把 app.py 还原成脚本启动时的内容。幂等，可反复调用。"""
    for path, content in ORIG.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass


def _restore_and_exit(signum, frame):
    restore()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    try:
        signal.signal(_sig, _restore_and_exit)
    except (ValueError, OSError):
        pass

atexit.register(restore)


def run_tests():
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=600,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


# ─────────────────────────────────────────────────────────────
# 变异定义：(名称, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

# M1/M4 的锚点：_manage_ddns_cron 里读 crontab 到取 current_crontab 的整块。
# 这一块在源码里**唯一**（双引号 + 那句特有的提示语），
# 别处没有同样的字串 —— 2026-11-08 实测过 count==1。
_M_DDNS_BLOCK = '''    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return False, f"读取 crontab 失败，已中止（未做任何修改）: {e}"
    if result.returncode != 0:
        return False, (f"读取 crontab 失败，已中止（未做任何修改）: "
                       f"{(result.stderr or result.stdout).strip()}"
                       f"（若本机确实一条 cron 都没有，请先手工 `crontab -` 建一条，"
                       f"再来保存）")
    current_crontab = result.stdout'''

# M2/M5 的锚点：_upsert_cron_for 里的 returncode 闸门。
# 提示语「读取 crontab 失败，已中止（未做任何修改）」是这一处独有的。
_M_UPSERT_GATE = '''        if result.returncode != 0:
            return False, (f"读取 crontab 失败，已中止（未做任何修改）: "
                           f"{(result.stderr or result.stdout).strip()}")
        lines = result.stdout.splitlines()'''

# M3 的锚点：install_china_ips 里的 returncode 闸门。
_M_CHINA_GATE = '''        if result.returncode != 0:
            return jsonify({"success": False,
                            "message": f"crontab 读取失败，已中止（未做任何修改）: "
                                       f"{(result.stderr or result.stdout).strip()}"}), 500
        existing = result.stdout.splitlines()'''

# M7 的锚点：_manage_ddns_cron 写回后的返回码检查。
_M_WRITE_CHECK = '''    if proc.returncode != 0:
        return False, f"crontab 写入失败: {(proc.stderr or proc.stdout).strip()}"
    return True, "crontab 已更新"'''


MUTATIONS = [
    ('M1  摘掉 _manage_ddns_cron 的 returncode 闸门',
     [(_M_DDNS_BLOCK,
       '''    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return False, f"读取 crontab 失败，已中止（未做任何修改）: {e}"
    current_crontab = result.stdout''')]),

    ('M2  摘掉 _upsert_cron_for 的 returncode 闸门',
     [(_M_UPSERT_GATE,
       '''        lines = result.stdout.splitlines()''')]),

    ('M3  摘掉 install_china_ips 的 returncode 闸门',
     [(_M_CHINA_GATE,
       '''        existing = result.stdout.splitlines()''')]),

    ('M4  _manage_ddns_cron 读失败当成空表（P0-10 原始写法）',
     [(_M_DDNS_BLOCK,
       '''    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
        current_crontab = result.stdout if result.returncode == 0 else ""
    except Exception:
        current_crontab = ""''')]),

    ('M5  _upsert_cron_for 读失败当成空表',
     [(_M_UPSERT_GATE,
       '''        lines = result.stdout.splitlines() if result.returncode == 0 else []''')]),

    ('M6  闸门挪到写回之后（先覆盖再检查）',
     [(_M_DDNS_BLOCK,
       '''    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return False, f"读取 crontab 失败，已中止（未做任何修改）: {e}"
    current_crontab = result.stdout'''),
      # 把闸门从读点后面挪到**写回之后**：先 `crontab -` 覆盖掉，
      # 再检查读是否失败 —— 报告再准也已经晚了（数据没了）。
      ('''    # 必须检查返回码：原来忽略失败，导致自动更新静默不生效
    if proc.returncode != 0:''',
       '''    if result.returncode != 0:
        return False, (f"读取 crontab 失败，已中止（未做任何修改）: "
                       f"{(result.stderr or result.stdout).strip()}"
                       f"（若本机确实一条 cron 都没有，请先手工 `crontab -` 建一条，"
                       f"再来保存）")
    # 必须检查返回码：原来忽略失败，导致自动更新静默不生效
    if proc.returncode != 0:''')]),

    ('M7  _manage_ddns_cron 写回失败不上报（报「已更新」）',
     [(_M_WRITE_CHECK,
       '''    return True, "crontab 已更新"''')]),

    ('M8  闸门只 return 不带失败语义（return True ⇒ 面板报「已保存」）',
     [('''    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return False, f"读取 crontab 失败，已中止（未做任何修改）: {e}"''',
       '''    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return True, f"读取 crontab 失败，已中止（未做任何修改）: {e}"''')]),

    ('M9  闸门缩到只拦 FileNotFoundError（其它异常直接抛出）',
     [('''    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return False, f"读取 crontab 失败，已中止（未做任何修改）: {e}"''',
       '''    except FileNotFoundError as e:
        return False, f"读取 crontab 失败，已中止（未做任何修改）: {e}"''')]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    restore()
    rc, out = run_tests()
    if rc != 0:
        print('[FAIL] 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-3000:])
        return 1
    print('  [PASS] 基线通过\n')

    caught = missed = 0
    for name, edits in MUTATIONS:
        src = ORIG[APP_PY]
        bad = [old for old, _ in edits if old not in src]
        dup = [old for old, _ in edits if src.count(old) != 1]
        if bad or dup:
            # 锚点未命中的原因必须写进**同一行**：
            # 全仓扫描器按「每条变异恰好一行报告」统计，
            # 拆成两行会让这条既不算捕获也不算漏网 ⇒ 总数被少算。
            why = []
            if bad:
                why.append('锚点没匹配上（源码变了？）')
            if dup:
                why.append('锚点出现 %d 次，不是唯一' % src.count(dup[0]))
            print('  [FAIL] %s  —— ' % name + '；'.join(why) + ' ⇒ 算漏网')
            missed += 1
            continue
        try:
            mutated = src
            for old, new in edits:
                mutated = mutated.replace(old, new, 1)
            with open(APP_PY, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if rc != 0:
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l), '')
                print('  [PASS] %s  —— 被捕获' % name)
                if first:
                    print('      ↓ %s' % first)
                caught += 1
            else:
                print('  [FAIL] %s  —— 漏网！测试没抓住' % name)
                missed += 1
        finally:
            restore()

    print()
    print('=' * 60)
    print('  变异 %d 条，捕获 %d 条，漏网 %d 条' % (len(MUTATIONS), caught, missed))
    if missed:
        print('  源码已全部还原，但有漏网项 —— 上面标 [FAIL] 的测试是假测试')
    else:
        print('  源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
