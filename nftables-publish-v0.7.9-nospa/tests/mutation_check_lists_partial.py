#!/usr/bin/env python3
"""变异验证：名单面板「部分失败不能整片空白」的接线。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_lists_partial.py

改的是 frontend/app.js（loadLists 方法）。
判定标准只有一条：**旧代码必然让断言失败**。
断言如果改个变量名就绕过，等于没测。

背景
----
2026-10-19 搭 Docker 测试环境时撞见第二个能造成「预设加进去了依旧不显示」
症状的缺陷：loadLists() 里白名单/黑名单两个请求没有 .catch()，
而 Promise.all 是一错全错 —— 读不到 nft 规则集时整个 Promise.all reject，
下面四行赋值一行都不执行，ipPresets 永远停在 []。

这个脚本保证：把修复撤掉，tests/test_lists_partial_failure.js 必然变红。
不然那个测试就是"永远绿的假测试"。

**这个脚本会改写并还原源码，运行期间不能编辑源码、不能部署。**
"""
import os
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
JS = os.path.join(ROOT, 'frontend', 'app.js')
PY_TEST = os.path.join(ROOT, 'tests', 'test_lists_nft_unavailable.py')
JS_TEST = os.path.join(ROOT, 'tests', 'test_lists_partial_failure.js')

SRC = open(APP, encoding='utf-8').read()
JSRC = open(JS, encoding='utf-8').read()

# 本脚本**亲手写过**的源码内容。收尾兜底时只有"盘上内容在我这个集合里"
# 才还原 —— 否则会把别人在运行期间做的改动覆盖掉（2026-10-20 实测踩过）。
WRITTEN = set()

# ── 后端变异：NFT_UNAVAILABLE 这个 code ─────────────────────
# 后端如果把「nft 不存在」和「真故障」混在一起，前端就分不出来 ——
# 而前端那条分支（不弹红色 toast）完全依赖这个 code。
APP_MUTANTS = [
    ('去掉 FileNotFoundError 分支（环境固有又混回真故障）',
     "    except FileNotFoundError:\n"
     "        return _nft_missing('读取')",
     "    except ZeroDivisionError:\n"
     "        return _nft_missing('读取')"),

    ('漏掉 code 字段（前端就分不出环境固有）',
     '        "success": False,\n'
     '        "code": "NFT_UNAVAILABLE",\n'
     '        "message": f"当前环境没有 nft 命令，无法{action}防火墙规则集",',
     '        "success": False,\n'
     '        "message": f"当前环境没有 nft 命令，无法{action}防火墙规则集",'),

    # 写路径：没有 nft 时也必须给人能读懂的句子，而不是原始 errno
    ('写路径不再接 FileNotFoundError（用户看到原始 errno）',
     "    except FileNotFoundError:\n"
     "        return _nft_missing('修改')",
     "    except ZeroDivisionError:\n"
     "        return _nft_missing('修改')"),
]

# ── 前端变异 ───────────────────────────────────────────────
# 锚点必须**自带上下文**（AGENTS.md）：只写一句 `return fallback;` 这种
# 满地都是的短句，源码一改就漂；而且漂了也不会有人知道，只会让脚本
# 报「锚点未命中」然后被忽略。
JS_MUTANTS = [
    # ── 核心：把四个子请求的兜底拆掉 ────────────────────────
    ('白名单不兜底（退回裸 api.get，一错全错）',
     "          api.get('/api/lists/whitelist')\n"
     "            .catch(guard('whitelist', { allowed4: {}, allowed6: {} })),",
     "          api.get('/api/lists/whitelist'),"),

    ('黑名单不兜底（退回裸 api.get，一错全错）',
     "          api.get('/api/lists/blacklist')\n"
     "            .catch(guard('blacklist', { blacklist4: {}, blacklist6: {} })),",
     "          api.get('/api/lists/blacklist'),"),

    ('预设不兜底（退回裸 api.get，一错全错）',
     "          api.get('/api/lists/presets')\n"
     "            .catch(guard('presets', { presets: [] })),",
     "          api.get('/api/lists/presets'),"),

    ('历史不兜底（退回裸 api.get，一错全错）',
     "          api.get('/api/lists/history?limit=20')\n"
     "            .catch(guard('history', { history: [] })),",
     "          api.get('/api/lists/history?limit=20'),"),

    # ── 兜底本身坏掉 ────────────────────────────────────────
    ('兜底返回 undefined（后面读 .allowed4 会炸）',
     "        failed.push(name + '（' + (e.message || e) + '）');\n"
     "        return fallback;",
     "        failed.push(name + '（' + (e.message || e) + '）');\n"
     "        return undefined;"),

    # ── 「读不到」被伪装成「没有」────────────────────────────
    ('失败时不弹 toast（读不到伪装成没有）',
     "        if (failed.length) {",
     "        if (false) {"),

    # ── 环境固有被当成故障 ───────────────────────────────────
    # nft 不存在（Docker 测试环境刻意不装）是**环境固有**，不是故障 ——
    # 不该弹红色 toast，只该在卡片里显示说明。
    # 去掉 code 判断 ⇒ 环境固有也会报红，用户会以为面板坏了。
    ('环境固有（NFT_UNAVAILABLE）也弹红色 toast',
     "        if (e && e.code === 'NFT_UNAVAILABLE') {",
     "        if (false) {"),

    # 去掉 code 判断后必然连带：这条单独测「nft 不可用」的标记还在不在
    ('不标记「nft 不可用」（前端就显示不出内联说明了）',
     "          nftUnavailable = true;",
     "          nftUnavailable = false;"),

    # ── 读错一层（第十七节那类）──────────────────────────────
    ('ipPresets 少读一层（退回未拆信封）',
     "        this.ipPresets = unwrap(presets).presets || [];",
     "        this.ipPresets = presets.presets || [];"),

    ('listHistory 少读一层（退回未拆信封）',
     "        this.listHistory = unwrap(history).history || [];",
     "        this.listHistory = history.history || [];"),
]


def run_js():
    return subprocess.run(['node', JS_TEST], capture_output=True, text=True,
                          timeout=120, cwd=ROOT)


def run_py():
    return subprocess.run([sys.executable, PY_TEST], capture_output=True, text=True,
                          timeout=180, cwd=ROOT)


def report(name, r):
    fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
    if r.returncode != 0 and (fails or r.stderr.strip()):
        detail = (fails[0][:86] if fails
                  else ('测试崩溃: ' + r.stderr.strip().splitlines()[-1][:70]))
        print(f'  ✅ 抓住 {name}')
        print(f'        首个失败: {detail}')
        return 1
    print(f'  ❌ 漏过 {name}')
    return 0


def apply_and_run(path, orig_src, mutants, runner, label, guard=None):
    """对某个文件逐个应用变异、跑对应测试、还原。返回 (捕获数, 未命中列表)。

    还原时**必须核对盘上的内容**（2026-10-20 实测踩到）：
    各脚本原来都是 `finally: open(path,'w').write(orig_src)`，
    而 `orig_src` 是 **import 那一刻**读的版本。
    如果这时有人正在改源码，那份改动会被**静默覆盖** ——
    没有报错、没有告警，改动就这么没了（而且回归还报"全绿"，
    因为它测的是旧代码）。

    所以还原前分三种情况：
      · 盘上 == 变异结果 → 正常还原
      · 盘上 == 原始内容 → 已经是原样，不用写
      · 两者都不是      → **有人在我运行时改了源码** → 不覆盖！
        （保留对方的改动，并让 guard 跳过这个文件），
        并且**立刻停手**（break）—— 继续跑下去，下一处变异
        又会把对方的改动覆盖回去，白保护。
    """
    caught, noanchor, clobbered = 0, [], []
    for name, old, new in mutants:
        if old not in orig_src:
            print(f'  ⚠️  锚点未命中 [{label}]: {name}')
            noanchor.append(name)
            continue
        mutated = orig_src.replace(old, new, 1)
        if mutated == orig_src:
            print(f'  ⚠️  变异没改到内容 [{label}]: {name}')
            noanchor.append(name)
            continue
        open(path, 'w', encoding='utf-8').write(mutated)
        WRITTEN.add(mutated)
        # 闸：变异必须真的落到文件上（写完立刻回读比对）
        on_disk = open(path, encoding='utf-8').read()
        if on_disk != mutated:
            print(f'  ❌ 变异没落到文件 [{label}]: {name}')
            noanchor.append(name)
            open(path, 'w', encoding='utf-8').write(orig_src)
            continue
        try:
            r = runner()
        finally:
            now = open(path, encoding='utf-8').read()
            if now == orig_src:
                pass                       # 已经是原样
            elif now == mutated:
                open(path, 'w', encoding='utf-8').write(orig_src)
            else:
                # 运行期间被外部改过 —— 绝不能覆盖，否则吞掉别人的改动
                clobbered.append(path)
                print(f'  ❌ 运行期间 {path} 被外部改动过，放弃还原'
                      f'（保留外部改动，停止本脚本）')
                if guard is not None:
                    guard.protect(path)
                break                      # 立刻停手，别再写这个文件
        caught += report(name, r)
    return caught, noanchor, clobbered


def main():
    guard = MutationGuard(ROOT)
    guard.snapshot()
    try:
        base_js = run_js()
        base_py = run_py()
        if base_js.returncode != 0:
            print('❌ 基线就不过（前端接线测试），先修基线')
            print(base_js.stdout[-3000:])
            if base_js.stderr:
                print(base_js.stderr[-1500:])
            return 1
        if base_py.returncode != 0:
            print('❌ 基线就不过（后端 NFT_UNAVAILABLE 测试），先修基线')
            print(base_py.stdout[-3000:])
            if base_py.stderr:
                print(base_py.stderr[-1500:])
            return 1
        print(f'基线通过  前端接线断言 {base_js.stdout.count("✅")} 条  '
              f'后端断言 {base_py.stdout.count("✅")} 条\n')

        caught = 0
        noanchor = []
        clobbered = []
        try:
            c1, n1, cl1 = apply_and_run(JS, JSRC, JS_MUTANTS, run_js, '前端', guard)
            c2, n2, cl2 = apply_and_run(APP, SRC, APP_MUTANTS, run_py, '后端', guard)
            caught = c1 + c2
            noanchor = n1 + n2
            clobbered = cl1 + cl2
        finally:
            # 兜底还原：**只在我亲手写过的变异状态上还原**。
            # 盘上若是别人的改动（不在 WRITTEN 里），一律不碰。
            for path, orig in ((JS, JSRC), (APP, SRC)):
                try:
                    now = open(path, encoding='utf-8').read()
                except OSError:
                    continue
                if now in WRITTEN:
                    open(path, 'w', encoding='utf-8').write(orig)

        total = len(JS_MUTANTS) + len(APP_MUTANTS)
        print('\n' + '=' * 74)
        print(f'变异 {total} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
        if noanchor:
            for m in noanchor:
                print('  锚点未命中:', m)
            return 1
        if clobbered:
            # 运行期间源码被外部改过 ⇒ 这一轮的结果不可信，必须让人知道
            print('  运行期间源码被外部改动过，本轮变异结果不作数:')
            for p in sorted(set(clobbered)):
                print('   ', p)
            return 1
        print('全部变异均被捕获' if caught == total else '有变异漏过')
        return 0 if caught == total else 1
    finally:
        guard.restore()


if __name__ == '__main__':
    sys.exit(main())
