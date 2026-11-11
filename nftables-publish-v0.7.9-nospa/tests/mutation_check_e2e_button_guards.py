#!/usr/bin/env python3
"""e2e 点击器按钮档位守卫的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_e2e_button_guards.py

测什么有效
----------
2026-11-08 .232 真机 e2e 实测：``NETWORK_PAT`` / ``DESTRUCTIVE_PAT``
两条正则漏掉了本该跳过的按钮，实测真执行了四个：

  saveNetworkConfig() → POST /api/network/config 400
  installIpv6Cron()   → POST /api/network/install-ipv6-cron 200
  restartDdns()       → POST /api/ddns/restart 200
  reloadNginx()       → POST /api/reverse-proxy/nginx/reload 200

根因是**注释与代码不一致**：脚本注释里点名 2026-10-06 事故的三个元凶
「togglePppoe() / saveNetworkConfig() / restartNetwork()」，
但 saveNetworkConfig 从来没进过 NETWORK_PAT。

所以对应的测试除了逐个动作查档位，还查**注释里提到的动作是不是真的被保护**。
这类防线最容易的退化：

  · 从正则里删掉某个动作 ⇒ 又漏网
  · 正则写得太宽 ⇒ 普通保存类按钮被误跳过（看着安全，实际漏测）
  · 注释提到的动作没进正则 ⇒ 注释与代码脱节（就是这次的真实成因）

对应关系
--------
  E1  NETWORK_PAT 去掉 saveNetworkConfig      E2  NETWORK_PAT 去掉 installIpv6Cron
  E3  DESTRUCTIVE 去掉 restartDdns             E4  DESTRUCTIVE 去掉 reloadNginx
  E5  NETWORK_PAT 去掉 updateChinaIps          E6  NETWORK_PAT 去掉 togglePppoe
  E7  DESTRUCTIVE 去掉 applyRules              E8  DESTRUCTIVE 去掉 confirmSaveConfig
  E9  DESTRUCTIVE 加上 saveConfig（写太宽）     E10 NETWORK_PAT 加上 saveRpRule（写太宽）

保险丝：只备份 / 还原**我自己会改的那一个文件**（tests/e2e_buttons.js），
不扫描 /tmp/mutguard-*，不碰别人的文件。

锚点
----
每条变异用成对的精确字符串，且必须在源码里**唯一**。
匹配不上就当场报错并算作漏网。
"""
import atexit
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E2E = os.path.join(ROOT, 'tests', 'e2e_buttons.js')
TEST = os.path.join(ROOT, 'tests', 'test_e2e_button_guards.py')

# 我独占、也只有我会改的那一个文件。
ORIG = {E2E: open(E2E, encoding='utf-8').read()}


def _judge_capture(rc, out):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」
      （2026-11-11 审查 M8：崩了也被记成「捕获」⇒ 那个捕获是假的）。
    ⇒ 只有输出里真的出现**断言失败**的标记行才算捕获；
      只有崩溃、没有失败行的 ⇒ 算漏网（宁可漏判，不可假捕获）。
    """
    if rc == 0:
        return False
    for line in out.splitlines():
        s = line.strip()
        # 失败标记用 Unicode 转义写：源码里不出现符号本身（AGENTS.md 禁 emoji）
        if ('[FAIL]' in s and '[PASS]' not in s) or \
                ('\u274c' in s and '\u2705' not in s):
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    """把 e2e_buttons.js 还原成脚本启动时的内容。幂等，可反复调用。"""
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
                       cwd=ROOT, timeout=300,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


# ─────────────────────────────────────────────────────────────
# 变异定义：(名称, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

MUTATIONS = [
    ('E1  NETWORK_PAT 去掉 saveNetworkConfig（2026-10-06 元凶之一漏网）',
     [('|saveNetworkConfig|保存网络配置', '')]),

    ('E2  NETWORK_PAT 去掉 installIpv6Cron（动作名驼峰、下划线写法对不上）',
     [('|installIpv6Cron|安装定时更新', '')]),

    ('E3  DESTRUCTIVE_PAT 去掉 restartDdns（中文「重启」不匹配英文动作名）',
     [('|restartDdns|重启服务', '')]),

    ('E4  DESTRUCTIVE_PAT 去掉 reloadNginx（改 nginx 运行时状态）',
     [('|reloadNginx|重载 ?nginx', '')]),

    ('E5  NETWORK_PAT 去掉 updateChinaIps（与 installChinaIps 是两个动作）',
     [('|updateChinaIps|立即刷新中国IP', '')]),

    ('E6  NETWORK_PAT 去掉 togglePppoe（事故元凶之一）',
     [('|togglePppoe', '')]),

    ('E7  DESTRUCTIVE_PAT 去掉 applyRules（flush ruleset 的入口）',
     [('|applyRules', '')]),

    ('E8  DESTRUCTIVE_PAT 去掉 confirmSaveConfig（真正落盘并应用规则那颗）',
     [('|confirmSaveConfig|确认保存', '')]),

    ('E9  DESTRUCTIVE_PAT 加上 saveConfig（写太宽 ⇒ 普通保存被误跳过）',
     [('|重置|restartDdns', '|重置|saveConfig|restartDdns')]),

    ('E10 NETWORK_PAT 加上 saveRpRule（写太宽 ⇒ 普通保存被误跳过）',
     [('|togglePppoe', '|saveRpRule|togglePppoe')]),
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
        src = ORIG[E2E]
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
                why.append(f'锚点出现 {src.count(dup[0])} 次，不是唯一')
            print(f'  [FAIL] {name}  —— ' + '；'.join(why) + ' ⇒ 算漏网')
            missed += 1
            continue
        try:
            mutated = src
            for old, new in edits:
                mutated = mutated.replace(old, new, 1)
            with open(E2E, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if _judge_capture(rc, out):
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l), '')
                print(f'  [PASS] {name}  —— 被捕获')
                if first:
                    print(f'      ↓ {first}')
                caught += 1
            else:
                print(f'  [FAIL] {name}  —— 漏网！测试没抓住')
                missed += 1
        finally:
            restore()

    print()
    print('=' * 60)
    print(f'  捕获 {caught} / {caught + missed}')
    if missed:
        print('  源码已全部还原，但有漏网项 —— 上面标 [FAIL] 的测试是假测试')
    else:
        print('  源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
