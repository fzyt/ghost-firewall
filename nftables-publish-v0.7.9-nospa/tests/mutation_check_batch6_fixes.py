#!/usr/bin/env python3
"""变异验证：第六批修复（IPv4 一直「未知」+ 手机端反代卡片显示）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_batch6_fixes.py

改的是三个文件：
  · backend/device_info.py —— `_ipv4_by_iface()`（两个来源合并）
                             `_iface_state()`（operstate 不可用时看 carrier）
  · frontend/index.html    —— 反代规则卡片的手机端布局 class
  · frontend/app.js        —— 首屏并行查公网 IP

判定标准只有一条：**改坏之后断言必须失败**。

⚠ 捕获口径：rc≠0 但输出里**没有 [FAIL] 行不算捕获** ——
  那说明测试自己崩了（导入失败、源码语法错误），不是「测试抓到了缺陷」。
  ⇒ 测试必须「红」而不是「死」。

⚠ 本脚本会**同时**跑后端（python）与前端（node）两份测试 ——
  任何一份崩了都算没抓住。
"""
import os
import shutil
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY_TEST = os.path.join(ROOT, 'tests', 'test_batch6_fixes.py')
JS_TEST = os.path.join(ROOT, 'tests', 'test_frontend_batch6_fixes.js')

FILES = {
    'device': os.path.join(ROOT, 'backend', 'device_info.py'),
    'index': os.path.join(ROOT, 'frontend', 'index.html'),
    'app': os.path.join(ROOT, 'frontend', 'app.js'),
}

SRC = {k: open(v, encoding='utf-8').read() for k, v in FILES.items()}


def _node():
    """找到 node —— 前端变异靠它验，跑不了就必须说清楚，不能装作验过了。"""
    p = shutil.which('node')
    if p:
        return p
    for cand in ('/home/kirito/.local/bin/node', '/usr/local/bin/node',
                 '/usr/bin/node'):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


NODE = _node()

MUTANTS = [
    # ── ① IPv4 的两个来源又变回「二选一」 ─────────────────────────────
    # 老代码：fib_trie 采到了就 return，压根不跑 getifaddrs
    # ⇒ PPPoE 这类点到点接口永远采不到地址（它在路由表里没有直连网段）。
    ('device', 'IPv4 两个来源又变回「二选一」（fib_trie 成功就不跑 getifaddrs）',
     "    if nets_by_iface:\n"
     "        for iface, addrs in _ipv4_from_fib_trie(nets_by_iface).items():\n"
     "            out.setdefault(iface, []).extend(addrs)",
     "    if nets_by_iface:\n"
     "        out = _ipv4_from_fib_trie(nets_by_iface)\n"
     "        if out:\n"
     "            return out"),

    # ── ② 合并时把同一个地址收了两遍 ───────────────────────────────
    ('device', '合并时不去重（同一地址出现两次）',
     "            if addr not in cur:\n"
     "                cur.append(addr)",
     "            cur.append(addr)"),

    # ── ③ 新接口的地址没被记下来 ───────────────────────────────────
    # out.get 拿不到就不建键 ⇒ getifaddrs 独有的接口（pppoe-wan）白采了。
    ('device', 'getifaddrs 独有的接口没被记进结果（out.get 不建键）',
     "        cur = out.setdefault(iface, [])",
     "        cur = out.get(iface, [])"),

    # ── ④ operstate 说 unknown 就直接报 unknown ────────────────────
    # PPPoE 的 operstate 恒为 unknown ⇒ 老代码永远显示「未知」。
    ('device', 'operstate 是 unknown 也直接返回（PPPoE 口永远「未知」）',
     "    if v and v.strip() not in ('', 'unknown'):\n"
     "        return v.strip()",
     "    if v:\n"
     "        return v.strip()"),

    # ── ⑤ 不看 carrier ─────────────────────────────────────────────
    ('device', 'operstate 不可用时不看 carrier（又退回「未知」）',
     "    c = _read_first_line('/sys/class/net/%s/carrier' % name)\n"
     "    if c:",
     "    c = _read_first_line('/sys/class/net/%s/carrier' % name)\n"
     "    if c and False:"),

    # ── ⑥ carrier 的 0/1 判断反了 ──────────────────────────────────
    ('device', 'carrier 的 0/1 判断反了（链路通了说断、断了说通）',
     "            return 'up' if int(c.strip()) == 1 else 'down'",
     "            return 'up' if int(c.strip()) == 0 else 'down'"),

    # ── ⑦ 卡片主行退回横排（手机上又被挤成一条） ────────────────────
    ('index', '卡片主行退回横排（手机上 URL 又被挤到几十像素宽）',
     'class="flex flex-col sm:flex-row items-stretch sm:items-start justify-between gap-3 mb-3"',
     'class="flex items-start justify-between gap-3 mb-3"'),

    # ── ⑧ 左列不撑满（items-stretch 被拿掉） ───────────────────────
    ('index', '手机上左列不撑满整行（items-stretch 被拿掉）',
     'class="flex flex-col sm:flex-row items-stretch sm:items-start justify-between gap-3 mb-3"',
     'class="flex flex-col sm:flex-row items-start justify-between gap-3 mb-3"'),

    # ── ⑨ URL 退回 break-all ───────────────────────────────────────
    ('index', '访问路径退回 break-all（一个字一个字断行）',
     'class="text-sm mt-1 nf-mono text-gray-600 break-words"',
     'class="text-sm mt-1 nf-mono text-gray-600 break-all"'),

    # ── ⑩ 域名入口退回 break-all ───────────────────────────────────
    ('index', '域名入口退回 break-all（一个字一个字断行）',
     'class="text-sm mt-1 nf-mono text-indigo-700 break-words"',
     'class="text-sm mt-1 nf-mono text-indigo-700 break-all"'),

    # ── ⑪ 目标地址退回 break-all ───────────────────────────────────
    ('index', '目标地址退回 break-all',
     'class="nf-mono text-gray-700 break-words"',
     'class="nf-mono text-gray-700 break-all"'),

    # ── ⑫ 属性表退回两列（手机上「目标地址」只剩半行宽） ────────────
    ('index', '属性表退回两列（手机上长地址被挤扁）',
     'class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 mt-3 pt-3 border-t text-sm"',
     'class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3 pt-3 border-t text-sm"'),

    # ── ⑬ 按钮组不换行 ─────────────────────────────────────────────
    ('index', '按钮组去掉 flex-wrap（极窄屏时按钮被挤出可视区）',
     'class="flex flex-wrap gap-2 shrink-0"',
     'class="flex gap-2 shrink-0"'),

    # ── ⑭ 首屏不再自动查公网 IP ────────────────────────────────────
    ('app', '首屏不再自动查公网 IP（那一栏永远「未知」）',
     "        if (!isAuto && !this.deviceInfo.publicIp) {\n"
     "          this.loadPublicIp();\n"
     "        }",
     "        // （变异：首屏不再自动查公网 IP）"),

    # ── ⑮ 自动刷新也去问外网 ───────────────────────────────────────
    ('app', '自动刷新也去问外网（每 5 秒问一次）',
     "        if (!isAuto && !this.deviceInfo.publicIp) {",
     "        if (!this.deviceInfo.publicIp) {"),

    # ── ⑯ 已经有值了还重复问 ───────────────────────────────────────
    ('app', '已经有公网 IP 了还重复问外网',
     "        if (!isAuto && !this.deviceInfo.publicIp) {",
     "        if (!isAuto) {"),
]


class _Result:
    def __init__(self, stdout, rc):
        self.stdout = stdout
        self.returncode = rc


def run_test():
    """后端 + 前端两份测试一起跑；任何一份崩了都算没过。"""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    py = subprocess.run([sys.executable, PY_TEST], capture_output=True,
                        text=True, timeout=600, env=env)
    if NODE is None:
        return _Result(py.stdout, py.returncode or 2)
    js = subprocess.run([NODE, JS_TEST], capture_output=True,
                        text=True, timeout=600, env=env)
    out = py.stdout + js.stdout
    if py.returncode or js.returncode:
        out += ('\n--- python stderr ---\n' + py.stderr[-800:] +
                '\n--- node stderr ---\n' + js.stderr[-800:])
    return _Result(out, py.returncode or js.returncode)


def report(name, r):
    # ⚠ 只数**真正的断言行** —— 汇总行「合计: [PASS] 19   [FAIL] 0」里
    # 也含 '[FAIL]'，把它当失败就等于「什么都没抓也报抓住」（run_all.sh 注释里
    # 记过同一个坑：指标自己骗自己）。
    fails = [l.strip() for l in r.stdout.splitlines()
             if '[FAIL]' in l and not l.strip().startswith('合计')]
    if fails:
        print(f'  [OK] 抓住 {name}（{len(fails)} 条断言失败）')
        print(f'        首个失败: {fails[0][:86]}')
        return True
    if r.returncode != 0:
        print(f'  [FAIL] 漏过 {name} —— 但测试是**崩了**不是红了，不算捕获')
        tail = (r.stdout.strip().splitlines() or ['(无输出)'])
        print('        ', tail[-1][:86])
    else:
        print(f'  [FAIL] 漏过 {name}')
    return False


def main():
    if NODE is None:
        print('[FAIL] 找不到 node —— 前端变异没法验，不能当作验过了')
        return 1
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print('=' * 74)
    print('变异验证：第六批修复（IPv4 未知 + 手机端反代卡片显示）')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('[FAIL] 基线没过：')
        print(base.stdout[-2500:])
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
            with open(FILES[key], 'w', encoding='utf-8') as f:
                f.write(src.replace(old, new, 1))
            caught += report(name, run_test())
            with open(FILES[key], 'w', encoding='utf-8') as f:
                f.write(src)
    finally:
        for key, path in FILES.items():
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
