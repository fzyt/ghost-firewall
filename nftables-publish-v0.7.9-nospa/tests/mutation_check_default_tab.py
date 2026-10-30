"""默认页改动（2026-10-30）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_default_tab.py

测什么有效
----------
这次的需求是「进面板默认显示防火墙状态」。它是**前端默认值 + 模板门控**
两处配合的事：

    app.js      currentNav: 'firewall-status'   ← 默认打开哪一页
    app.js      firewallStatusLoaded            ← 数据到没到
    index.html  x-show="... && firewallStatusLoaded"  ← 什么时候渲染

单看任何一处都对，整体却是错的。典型的退化方式：

    · 门控被拆掉 → 数据没到就渲染 → 用户第一眼看到
      「nftables 规则：未加载」红点（真相是「还没查」）
    · 默认值退回 network → 需求没实现
    · 初值写成 true → 门控等于没有
    · finally 被删 → 页面永远空白
    · 错误被静默吞掉 → 查询失败时又退回红点
    · 加载顺序改回去 → 默认页要等四五个接口轮完才出内容

这六种退化，**功能上都不影响其它页面**，跑一遍单测很容易全绿。
只有真的拆掉，才变红。

每条变异独立重写源文件，并强制 PYTHONDONTWRITEBYTECODE=1：否则连续写入时
Python 只按 mtime+size 判过期，两条大小相近的变异会复用上一条的 .pyc，
把「漏网」伪装成「捕获」。
"""
import atexit
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, 'frontend', 'app.js')
INDEX_HTML = os.path.join(ROOT, 'frontend', 'index.html')
JS_TEST = os.path.join(ROOT, 'tests', 'test_frontend_default_tab.js')

ORIG = {
    APP_JS: open(APP_JS, encoding='utf-8').read(),
    INDEX_HTML: open(INDEX_HTML, encoding='utf-8').read(),
}

# ⚠️ 这里**故意不用** tests/_mutation_guard.py 的 MutationGuard。
#
# 原因（2026-10-30 实测踩到）：MutationGuard 还原的是**快照里的所有文件** ——
# 不只是本脚本改的那一个。并行改别的文件时，那一次清理会把**别人的改动覆盖掉**。
#
# 所以本脚本只备份/还原**自己会动的那两个文件**，一个字节都不碰别的。
# 保险丝（atexit + 信号处理）自己做。


def run_tests():
    """跑本批次的测试文件。任何一个红就算变异被抓。"""
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    r = subprocess.run(['node', JS_TEST],
                       capture_output=True, text=True, cwd=ROOT,
                       timeout=300, env=env)
    return r.returncode, r.stdout + r.stderr


def restore():
    """整体还原（保险丝用）。只碰上面那两个文件。"""
    for path, content in ORIG.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass


def restore_inplace(path, mutated_src, edits):
    """把本次变异还原，**不覆盖别人的并行改动**。

    情形 A：当前文件仍是我写的那份（逐字节相同）→ 整体写回 ORIG，最干净。
    情形 B：当前文件被别的 agent 改过了 → **只把本次变异的那几处**就地
             换回去，别人的改动一个字节都不动。
    """
    try:
        with open(path, encoding='utf-8') as f:
            cur = f.read()
    except OSError:
        return '整体还原失败（读不到文件）'

    if cur == mutated_src:
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(ORIG[path])
            return '整体还原'
        except OSError as e:
            return f'整体还原失败: {e}'

    # 情形 B：就地换回。锚点做成足够长的片段，保证 new 在文件里唯一。
    for old, new in edits:
        if not new:
            continue
        if cur.count(new) != 1:
            return f'就地还原失败：锚点出现 {cur.count(new)} 次，不是唯一'
        cur = cur.replace(new, old, 1)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(cur)
        return '就地还原（保留了并行改动）'
    except OSError as e:
        return f'就地还原失败: {e}'


# 保险丝：被取消 / 被 kill 时也把变异还原（只还原上面那两个文件）
def _install_fuse():
    def _handler(signum, frame):
        restore()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, _handler)
        except Exception:
            pass
    atexit.register(restore)


# (描述, 文件, [(旧串, 新串), ...])
# 每条的 old/new 都做成**足够长且唯一**的片段 —— 既保证锚点在源码里唯一，
# 也保证「就地还原」时能用 new 精确定位到本次变异改的那一处。
MUTATIONS = [
    ('M1  默认页退回 network（需求没实现）',
     APP_JS,
     [("    currentNav: 'firewall-status',",
       "    currentNav: 'network',")]),

    ('M2  模板门控被拆掉（数据没到就渲染 = 一上来就闪红点）',
     INDEX_HTML,
     [("""x-show="currentNav === 'firewall-status' && firewallStatusLoaded\"""",
       """x-show="currentNav === 'firewall-status'\"""")]),

    ('M3  门控初值写成 true（等于没有门控）',
     APP_JS,
     [("    firewallStatusLoaded: false,\n    // 查询失败时的原因。",
       "    firewallStatusLoaded: true,\n    // 查询失败时的原因。")]),

    ('M4  finally 被删（查询成功也永远不放开这一页 = 永久空白）',
     APP_JS,
     [("""      } finally {
        // 成功失败都要放开这一页 —— 失败时也得让用户看见「查询失败」，
        // 永远空白比报错更难查。
        this.firewallStatusLoaded = true;
      }""",
       "      }")]),

    ('M5  查询失败被静默吞掉（又退回「未加载」红点）',
     APP_JS,
     [("""        this.firewallStatusError = e.message || '查询失败';""",
       """        void e;""")]),

    ('M6  默认页的数据挪回最后取（开门先是一片空白）',
     APP_JS,
     [("""      await this.loadFirewallStatus();
      await this.loadConfig();
      await this.loadNetworkConfig();""",
       """      await this.loadConfig();
      await this.loadFirewallStatus();
      await this.loadNetworkConfig();""")]),

    ('M7  错误提示块被删（查询失败时用户什么都看不到）',
     INDEX_HTML,
     [("""        <!-- 查询失败提示：宁可明说「没查到」，也不要显示一堆红点让人以为防火墙挂了 -->
        <div x-show="firewallStatusError"
             class="rounded border border-red-300 bg-red-50 px-4 py-3 mb-4">
          <div class="text-sm text-red-800"
               x-text="'查询防火墙状态失败：' + (firewallStatusError || '未知错误')"></div>
          <div class="text-xs text-red-700 mt-1">面板与设备之间的连接可能已断开，请刷新页面重试。</div>
        </div>
""", "")]),

    ('M8  状态点的错误门控被拆（失败时红点照样画）',
     INDEX_HTML,
     [("""<div class="bg-gray-50 border rounded-lg p-5 space-y-5" x-show="!firewallStatusError">""",
       """<div class="bg-gray-50 border rounded-lg p-5 space-y-5">""")]),

    # M9 必须**同时**改两处才算真的把顺序还原了：
    #   一处是把它从第一位摘掉，一处是把它放回 firewall 后面。
    # 只改一处的话，导航里会出现**两个** firewall-status（重复项）或者一个都没有，
    # 那是另一种退化，不是「顺序没改」。
    ('M9  防火墙状态被挪回原来的第 11 位（导航第一项不再是它）',
     APP_JS,
     [("""      { id: 'firewall-status', label: '防火墙状态', icon: '🛡️' },
      { id: 'network', label: '网络接口' },""",
       """      { id: 'network', label: '网络接口' },"""),
      ("""      { id: 'firewall', label: '防火墙规则' },
      { id: 'lists', label: '名单管理', icon: '📋' },""",
       """      { id: 'firewall', label: '防火墙规则' },
      { id: 'firewall-status', label: '防火墙状态', icon: '🛡️' },
      { id: 'lists', label: '名单管理', icon: '📋' },""")]),
]


def main():
    _install_fuse()
    print('=' * 66)
    print('默认页 = 防火墙状态 变异验证')
    print('=' * 66)

    print('\n=== 基线：未变异时测试必须全绿 ===')
    rc, out = run_tests()
    if rc != 0:
        print(out)
        print('\n❌ 基线就不绿 —— 先修好再谈变异')
        return 2
    print('  ✅ 基线通过')

    caught, missed, noanchor = 0, 0, []
    for name, path, edits in MUTATIONS:
        src = ORIG[path]
        ok = True
        for old, new in edits:
            if src.count(old) != 1:
                print(f'  ⚠️  锚点未命中 [{name}]: 旧串出现 {src.count(old)} 次')
                ok = False
                break
            src = src.replace(old, new, 1)
        if not ok:
            noanchor.append(name)
            continue

        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(src)
        except OSError as e:
            print(f'  ⚠️  {name}  —— 写不进去: {e}')
            noanchor.append(name)
            continue

        rc, out = run_tests()
        if rc != 0:
            first = next((l.strip() for l in out.splitlines() if '❌' in l), '')
            print(f'  ✅ {name}  —— 被捕获')
            if first:
                print(f'      ↓ {first}')
            caught += 1
        else:
            print(f'  ❌ {name}  —— **漏网**（测试照样全绿）')
            missed += 1

        how = restore_inplace(path, src, edits)
        if how.startswith('整体还原失败') or how.startswith('就地还原失败'):
            print(f'      ⚠️ {how}')

    # 最后再整体还原一次，确保干净
    restore()

    total = len(MUTATIONS)
    print(f'\n变异 {total} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
    if noanchor:
        print('  锚点未命中:', noanchor)
    print('全部变异均被捕获' if caught == total and not noanchor else '有变异漏过')

    if missed or noanchor:
        print('❌ 有漏网或锚点未命中的变异 —— 这些缺陷从此没人守')
        return 1
    print('✅ 全部捕获')
    return 0


if __name__ == '__main__':
    sys.exit(main())
