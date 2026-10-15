#!/usr/bin/env python3
"""变异验证：面板登录限流落盘。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_panel_rl.py
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_panel_ratelimit.py')
SRC = open(APP, encoding='utf-8').read()

MUTANTS = [
    ('退回内存 dict（重启清零，这条 bug 就回来了）',
     "PANEL_RATELIMIT_FILE = '/etc/nftables/nftables-web-panel-ratelimit.json'",
     "PANEL_RATELIMIT_FILE = '/dev/null'\n_failed_logins = {}   # 变异：内存版"),

    ('锁定状态不落盘（只存计数）',
     "                data[ip] = {'fails': [], 'locked_until': now + AUTH_RATE_LIMIT_LOCKOUT}",
     "                data[ip] = {'fails': [], 'locked_until': 0}"),

    ('达到阈值不触发锁定',
     "            if len(fails) >= AUTH_RATE_LIMIT_MAX_FAILS:",
     "            if False:"),

    ('成功登录不清空',
     "        elif ip in data:\n            data.pop(ip, None)",
     "        elif False:\n            data.pop(ip, None)"),

    ('锁定期内也接受清空（等于留了「猜对一次就解锁」的后门）',
     "        if locked_until > now:\n"
     "            return True, len(rec.get('fails', []) or [])",
     "        if False:\n"
     "            return True, len(rec.get('fails', []) or [])"),

    ('不做过期 GC（表无限膨胀）',
     "def _ratelimit_gc(data):",
     "def _ratelimit_gc(data):\n    return"),

    ('文件损坏时 fail-closed（把所有人锁在门外）',
     "    except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):\n"
     "        return {}",
     "    except OSError:\n"
     "        return {}\n"
     "    except (json.JSONDecodeError, ValueError):\n"
     "        raise"),

    ('落盘失败时异常直接冒泡（面板谁都进不去）',
     "    except OSError as e:\n        _ratelimit_degrade(e)\n\n\ndef _clear_login_failures",
     "    except OSError:\n        raise\n\n\ndef _clear_login_failures"),

    ('限流文件权限不设 600',
     "    os.chmod(tmp, 0o600)\n    os.replace(tmp, PANEL_RATELIMIT_FILE)",
     "    os.replace(tmp, PANEL_RATELIMIT_FILE)"),

    ('写文件不用原子替换（并发写会留下截断 JSON）',
     "    os.chmod(tmp, 0o600)\n    os.replace(tmp, PANEL_RATELIMIT_FILE)",
     "    with open(PANEL_RATELIMIT_FILE, 'w') as f2:\n"
     "        f2.write(json.dumps(data))\n    _unlink_quiet(tmp)"),

    ('不按 IP 隔离（所有来源共用一个计数）',
     "    data = _ratelimit_read()\n        now = time.time()\n        rec = data.get(ip)",
     "    data = _ratelimit_read()\n        now = time.time()\n        ip = '*'\n        rec = data.get(ip)"),
]


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, timeout=240, env=env)


def main():
    print('=' * 74)
    print('变异验证：面板登录限流落盘')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('❌ 基线没过：')
        print(base.stdout[-2500:])
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
            r = run_test()
            fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
            if r.returncode != 0 and fails:
                caught += 1
                print(f'  ✅ 抓住 {name}（{len(fails)} 条断言失败）')
                print(f'        首个失败: {fails[0][:84]}')
            elif r.returncode != 0:
                # 测试直接崩了也算抓到 —— 变异让代码抛异常正是要防的事
                caught += 1
                last = (r.stderr.strip().splitlines() or ['(无)'])[-1]
                print(f'  ✅ 抓住 {name}（测试崩溃）')
                print(f'        {last[:84]}')
            else:
                print(f'  ❌ 漏过 {name}')
            open(APP, 'w', encoding='utf-8').write(SRC)
    finally:
        open(APP, 'w', encoding='utf-8').write(SRC)

    print('\n' + '=' * 74)
    print(f'变异 {len(MUTANTS)} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
    if noanchor:
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    return 0 if caught == len(MUTANTS) else 1


if __name__ == '__main__':
    sys.exit(main())
