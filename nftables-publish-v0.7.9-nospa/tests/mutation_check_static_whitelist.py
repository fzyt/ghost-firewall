"""静态资源白名单批次的变异验证（P2-21）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_static_whitelist.py

测什么有效：这类修复最危险的退化不是「写错了」，而是**改回原来的宽松行为**。
原来的静态路由只挡了 '..' 和前导 '/'，其它带点当扩展名的文件一律放行 ——
那段代码读起来完全正常、前端照样工作，单测很容易全绿。
只有真的把白名单拆掉、把一致性检查拆掉，测试才会变红。

每条变异都独立重写源文件，并强制 PYTHONDONTWRITEBYTECODE=1：否则连续写入时
Python 只按 mtime+size 判过期，两条大小相近的变异会复用上一条的 .pyc，
把「漏网」伪装成「捕获」。
"""
import atexit
import os
import shutil
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
TEST_PY = os.path.join(ROOT, 'tests', 'test_static_whitelist.py')

ORIG_APP = open(APP_PY, encoding='utf-8').read()
ORIG = {APP_PY: ORIG_APP}

# ⚠️ 这里**故意不用** tests/_mutation_guard.py 的 MutationGuard。
#
# 原因（2026-10-30 实测踩到）：MutationGuard 启动时会清理「上次被硬杀的残留快照」，
# 而它还原的是**快照里的所有文件** —— 不只是本脚本改的那一个。
# 同仓库里有别的 agent 在并行改别的文件时，那一次清理会把**别人的改动覆盖掉**
# （实测把并行 agent 正在改的 backend/auth_gateway.py 和
#   backend/nftables-web-auth.init 还原掉了）。
#
# 所以本脚本只备份/还原**自己会动的那一个文件**，一个字节都不碰别的。
# 保险丝（atexit + 信号处理）自己做，最小但够用。


def run_tests():
    """跑本批次的测试文件。任何一个红就算变异被抓。"""
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    r = subprocess.run([sys.executable, TEST_PY],
                       capture_output=True, text=True, cwd=ROOT,
                       timeout=300, env=env)
    return r.returncode, r.stdout + r.stderr


def restore():
    """整体还原（保险丝用）。只碰上面那一个文件。"""
    for path, content in ORIG.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass
    for d in (os.path.join(ROOT, 'backend', '__pycache__'),
              os.path.join(ROOT, 'tests', '__pycache__')):
        if os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)


def restore_inplace(mutated_src, edits):
    """把本次变异还原，**不覆盖别人的并行改动**。

    情形 A：当前文件仍是我写的那份（逐字节相同）→ 整体写回 ORIG，最干净。
    情形 B：当前文件被别的 agent 改过了 → **只把本次变异的那几处**就地
             换回去，别人的改动一个字节都不动。

    情形 B 是并行情形下的现实：变异窗口 ~30 秒里，别的 agent 完全可能
    在同一个文件上提交改动。无脑整体还原 = 把人家的活儿冲掉。
    """
    try:
        with open(APP_PY, encoding='utf-8') as f:
            cur = f.read()
    except OSError:
        return '整体还原失败（读不到文件）'

    if cur == mutated_src:
        try:
            with open(APP_PY, 'w', encoding='utf-8') as f:
                f.write(ORIG_APP)
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
        with open(APP_PY, 'w', encoding='utf-8') as f:
            f.write(cur)
        return '就地还原（保留了并行改动）'
    except OSError as e:
        return f'就地还原失败: {e}'


# 保险丝：被取消 / 被 kill 时也把变异还原（只还原上面那个文件）
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


# (描述, [(旧串, 新串), ...])
# 每条的 old/new 都做成**足够长且唯一**的片段 —— 既保证锚点在源码里唯一，
# 也保证「就地还原」时能用 new 精确定位到本次变异改的那一处。
MUTATIONS = [
    ('M1  白名单里加回 .bak（旧版 SPA 副本又能拿到）',
     [("_STATIC_ALLOWED_EXT = {'.' + e for e in _STATIC_EXTENSIONS} | {\n"
       "    '.html', '.txt', '.otf', '.eot', '.webp',\n}",
       "_STATIC_ALLOWED_EXT = {'.' + e for e in _STATIC_EXTENSIONS} | {\n"
       "    '.html', '.txt', '.otf', '.eot', '.webp', '.bak',\n}")]),

    ('M2  静态路径判定恒为放行（白名单形同虚设）',
     [("    ext = os.path.splitext(parts[-1])[1].lower()\n"
       "    return ext in _STATIC_ALLOWED_EXT",
       "    ext = os.path.splitext(parts[-1])[1].lower()\n"
       "    return True")]),

    ('M3  退回原来的宽松逻辑（只挡 .. 和前导 /）',
     [("    if not _static_path_allowed(filename):\n"
       "        return jsonify({\"error\": \"forbidden\"}), 403\n",
       "    pass\n")]),

    ('M4  白名单不再从 before_request 的名单派生（两处漂移）',
     [("_STATIC_ALLOWED_EXT = {'.' + e for e in _STATIC_EXTENSIONS} | {\n"
       "    '.html', '.txt', '.otf', '.eot', '.webp',\n}",
       "_STATIC_ALLOWED_EXT = {\n"
       "    '.html', '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',\n"
       "    '.ico', '.webp', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.txt',\n"
       "}")]),

    ('M5  /api/ 前缀不再走 404（未知 API 变成 403）',
     [("    if filename.startswith('api/'):\n"
       "        return jsonify({\"error\": \"not found\"}), 404\n",
       "    pass\n")]),

    ('M6  隐藏文件不再被挡（.env.js 可通过静态路由拿到）',
     [("    # 隐藏文件（.env / .gitignore）一律不放行\n"
       "    if any(p.startswith('.') for p in parts):\n"
       "        return False\n",
       "    # 隐藏文件（.env / .gitignore）一律不放行\n")]),

    # ⚠️ M7 必须**三道防线同时失效**才抓得住，原因要说清楚：
    #
    #   1. Werkzeug 在 URL 层就把 '..' 规范化掉了（'/../backend/app.py'
    #      → '/backend/app.py'），所以请求路径根本到不了路由的穿越检查；
    #   2. 就算到了，隐藏文件检查也会挡 —— 因为 '..' 本身以点开头；
    #   3. 就算都过了，扩展名白名单还会挡 —— .py 不在白名单里。
    #
    # 也就是说：单独拆掉任何一道，另外两道都还在 ⇒ 单独的那条是
    # **等价变异**（拆了也没用，说明保证已经修得更彻底了）。
    # 这条变异要守住的是「三道防线**任意两道**失效时，第三道还能挡住」，
    # 所以必须一起拆。
    ('M7  三道防线同时失效（穿越检查被删 + 隐藏文件豁免 .. + 白名单放进 .py）',
     [("    if any(p in ('..', '') for p in parts):\n"
       "        return False\n",
       ""),
      ("    if any(p.startswith('.') for p in parts):\n"
       "        return False\n",
       "    if any(p.startswith('.') and p != '..' for p in parts):\n"
       "        return False\n"),
      ("_STATIC_ALLOWED_EXT = {'.' + e for e in _STATIC_EXTENSIONS} | {\n"
       "    '.html', '.txt', '.otf', '.eot', '.webp',\n}",
       "_STATIC_ALLOWED_EXT = {'.' + e for e in _STATIC_EXTENSIONS} | {\n"
       "    '.html', '.txt', '.otf', '.eot', '.webp', '.py',\n}")]),

    ('M8  扩展名不再大小写归一（INDEX.HTML.BAK 绕过）',
     [("    ext = os.path.splitext(parts[-1])[1].lower()\n"
       "    return ext in _STATIC_ALLOWED_EXT",
       "    ext = os.path.splitext(parts[-1])[1]\n"
       "    return ext in _STATIC_ALLOWED_EXT")]),

    ('M9  白名单收得过紧（正常前端资源也拿不到 = 白屏）',
     [("_STATIC_ALLOWED_EXT = {'.' + e for e in _STATIC_EXTENSIONS} | {\n"
       "    '.html', '.txt', '.otf', '.eot', '.webp',\n}",
       "_STATIC_ALLOWED_EXT = {'.' + e for e in _STATIC_EXTENSIONS} | {\n"
       "    '.html', '.txt', '.otf', '.eot', '.webp',\n}\n"
       "_STATIC_ALLOWED_EXT = set()")]),
]


def main():
    _install_fuse()
    print('=' * 66)
    print('静态资源白名单（P2-21）变异验证')
    print('=' * 66)

    print('\n=== 基线：未变异时测试必须全绿 ===')
    rc, out = run_tests()
    if rc != 0:
        print(out)
        print('\n❌ 基线就不绿 —— 先修好再谈变异')
        return 2
    print('  ✅ 基线通过')

    caught, missed, skipped = 0, 0, 0
    for name, edits in MUTATIONS:
        src = ORIG_APP
        ok = True
        for old, new in edits:
            if src.count(old) != 1:
                print(f'  ⚠️  {name}  —— 变异锚点没匹配上（源码变了？）')
                ok = False
                break
            src = src.replace(old, new, 1)
        if not ok:
            skipped += 1
            continue

        try:
            with open(APP_PY, 'w', encoding='utf-8') as f:
                f.write(src)
        except OSError as e:
            print(f'  ⚠️  {name}  —— 写不进去: {e}')
            skipped += 1
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

        how = restore_inplace(src, edits)
        if how.startswith('整体还原失败') or how.startswith('就地还原失败'):
            print(f'      ⚠️ {how}')

    # 最后再整体还原一次，确保干净
    restore()

    print('\n' + '=' * 66)
    print(f'  变异总数 : {len(MUTATIONS)}')
    print(f'  捕获     : {caught}')
    print(f'  未捕获   : {missed}')
    print(f'  跳过     : {skipped}')
    print('=' * 66)
    if missed or skipped:
        print('❌ 有漏网或跳过的变异 —— 这些缺陷从此没人守')
        return 1
    print('✅ 全部捕获')
    return 0


if __name__ == '__main__':
    sys.exit(main())
