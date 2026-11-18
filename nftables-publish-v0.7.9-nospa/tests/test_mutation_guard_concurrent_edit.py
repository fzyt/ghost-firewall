"""变异脚本「并发编辑保护」的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_mutation_guard_concurrent_edit.py

背景
----
2026-10-20 真踩到的一次静默事故：一边跑全量回归（`tests/run_all.sh`），
一边改了 `backend/app.py`。回归跑完，**改动没了** —— 没有报错、没有告警。

根因不在业务代码，在流程：各变异脚本都在 `finally` 里
`open(path, 'w').write(orig_src)`，而 `orig_src` 是它们 **import 那一刻**
读的版本。于是"运行期间做的改动"被"启动时的快照"覆盖掉了。

更糟的是那一轮回归还报"全绿"——它测的是**旧代码**，
而新写的测试文件是在回归跑到一半时才落盘的，压根没被那一轮跑到。

修法（本测试锁住它）
--------------------
1. `tests/_mutation_guard.py`
   · `restore()` 还原前**先备份**当前内容到 `<snap>.pre-restore/` 并打告警
   · 新增 `protect(path)`：声明某文件"不要覆盖"，还原时跳过
2. `tests/mutation_check_lists_partial.py`
   · 还原前核对盘上内容，分三种情况（变异结果 / 原始内容 / 都不是）
   · 第三种 = 有人在我运行时改了源码 → **不覆盖** + 告警 + **立刻停手**
     （不停手的话，下一处变异又会把改动覆盖回去，白保护）
   · 收尾的兜底还原**只在我亲手写过的变异状态上**做

本测试用临时目录，不碰仓库里的任何文件。
"""
import contextlib
import io
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tests'))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    # detail 里如果带了 ❌，会被回归的 count_fail 数成"这个测试文件挂了"
    # （tests/run_all.sh 那次口径修正的同款坑）。这里统一消毒。
    detail = detail.replace('❌', '[x]').replace('✅', '[v]')
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


class FakeResult:
    """冒充 subprocess.CompletedProcess。"""
    returncode = 0
    stdout = '  ✅ everything fine\n'
    stderr = ''


def capture(fn, *a, **k):
    """跑一段会打印东西的代码，把它的 stdout 收进缓冲区。

    为什么必须收：变异脚本里的告警用的是 ❌ 标记，而回归的失败计数
    （tests/run_all.sh 的 count_fail）会把带 ❌ 的行算成真失败 ——
    测试自己打印的 ❌ 会被算成"这个测试文件挂了"。
    顺带还能断言「告警确实打出来了」，比只看返回值更硬。
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = fn(*a, **k)
    return r, buf.getvalue()


def main():
    from _mutation_guard import MutationGuard
    import mutation_check_lists_partial as mut

    # ── 1. 还原时不得覆盖「外部改动」 ─────────────────────────
    sec('1. 变异运行期间文件被外部改过 → 保留外部改动，不覆盖')
    tmp = tempfile.mkdtemp(prefix='mutguard-test-')
    target = os.path.join(tmp, 'src.py')
    orig = 'ORIGINAL = 1\n'
    with open(target, 'w', encoding='utf-8') as f:
        f.write(orig)

    def runner_that_edits(*a, **k):
        # 模拟"有人在变异脚本跑着的时候改了源码"
        with open(target, 'w', encoding='utf-8') as f:
            f.write('ORIGINAL = 1\n# EXTERNAL EDIT\n')
        return FakeResult()

    (caught, noanchor, clobbered), out1 = capture(
        mut.apply_and_run,
        target, orig,
        [('改个常量', 'ORIGINAL = 1', 'ORIGINAL = 2')],
        runner_that_edits, '测试', None)

    now = open(target, encoding='utf-8').read()
    check('外部改动被保留（没被 orig_src 覆盖）', '# EXTERNAL EDIT' in now, repr(now))
    check('被识别为"被外部改动过"', len(clobbered) == 1, str(clobbered))
    check('没有静默通过（该情况要报错，不算干净）', len(noanchor) == 0)
    check('**打出了告警**（不是静默吞掉）',
          '被外部改动过' in out1, out1.strip().splitlines()[0] if out1.strip() else '(无输出)')

    # ── 2. protect() 之后 guard.restore() 也不覆盖 ────────────
    sec('2. guard.protect() 声明的文件，restore() 不得覆盖')
    tmp2 = tempfile.mkdtemp(prefix='mutguard-test2-')
    os.makedirs(os.path.join(tmp2, 'backend'), exist_ok=True)
    t2 = os.path.join(tmp2, 'backend', 'app.py')
    with open(t2, 'w', encoding='utf-8') as f:
        f.write('SNAPSHOT\n')
    g = MutationGuard(tmp2)
    g.snapshot()
    with open(t2, 'w', encoding='utf-8') as f:
        f.write('EXTERNAL\n')
    g.protect(t2)
    _, out2 = capture(g.restore)
    check('protect 的文件没被还原覆盖',
          open(t2, encoding='utf-8').read() == 'EXTERNAL\n',
          repr(open(t2, encoding='utf-8').read()))
    check('**打出了告警**（保留了改动这件事要说出来）',
          '外部改动过' in out2, out2.strip().splitlines()[0] if out2.strip() else '(无输出)')

    # ── 3. 没有 protect 时：还原 + 备份当前内容 ───────────────
    sec('3. 没 protect → 从快照还原，且**还原前的内容被备份**')
    tmp3 = tempfile.mkdtemp(prefix='mutguard-test3-')
    os.makedirs(os.path.join(tmp3, 'backend'), exist_ok=True)
    t3 = os.path.join(tmp3, 'backend', 'app.py')
    with open(t3, 'w', encoding='utf-8') as f:
        f.write('SNAPSHOT\n')
    g3 = MutationGuard(tmp3)
    g3.snapshot()
    with open(t3, 'w', encoding='utf-8') as f:
        f.write('MUTATED-OR-EDITED\n')
    backup_dir = g3.backup_dir
    _, out3 = capture(g3.restore)
    check('文件已从快照还原', open(t3, encoding='utf-8').read() == 'SNAPSHOT\n',
          repr(open(t3, encoding='utf-8').read()))
    backup = os.path.join(backup_dir, 'backend', 'app.py')
    check('还原前的内容被备份（不是静默吞掉）', os.path.isfile(backup), backup)
    if os.path.isfile(backup):
        check('备份里是还原前的内容',
              open(backup, encoding='utf-8').read() == 'MUTATED-OR-EDITED\n')
    check('**打出了告警**', '还原' in out3 and 'backend/app.py' in out3,
          out3.strip().splitlines()[0] if out3.strip() else '(无输出)')

    # ── 4. 正常路径：没有外部改动 → 干净还原 ──────────────────
    sec('4. 正常路径（无外部改动）→ 文件被干净还原')
    tmp4 = tempfile.mkdtemp(prefix='mutguard-test4-')
    t4 = os.path.join(tmp4, 'src.py')
    with open(t4, 'w', encoding='utf-8') as f:
        f.write(orig)
    (caught4, noanchor4, clobbered4), _ = capture(
        mut.apply_and_run,
        t4, orig,
        [('改个常量', 'ORIGINAL = 1', 'ORIGINAL = 2')],
        lambda *a, **k: FakeResult(), '测试', None)
    check('文件已还原成原始内容',
          open(t4, encoding='utf-8').read() == orig,
          repr(open(t4, encoding='utf-8').read()))
    check('没有被误判为外部改动', len(clobbered4) == 0, str(clobbered4))
    check('锚点没报未命中', len(noanchor4) == 0, str(noanchor4))

    # ── 5. 快照范围不得包含文档目录 ──────────────────────────
    # 2026-11-18 真踩到：一边跑全量回归，一边在 `报告/` 里补文档。
    # 保险丝的快照用的是 `git ls-files`（**全部**跟踪文件，含 `报告/`）
    # ⇒ 脚本退出时 `restore()` 判定「与快照不一致」⇒ 把文档改动还原掉
    # ⇒ 内容静默丢失，不报任何错。
    # 更隐蔽的是：回归收尾的源码指纹对账只覆盖 backend/ frontend/ setup/
    # tests/ docker/ ⇒ **不含报告目录** ⇒ 连对账都发现不了。
    #
    # ⇒ 变异脚本只改源码，文档目录根本不该进快照。
    sec('5. 快照范围只含源码目录，不含文档目录')
    tmp5 = tempfile.mkdtemp(prefix='mutguard-test5-')
    os.makedirs(os.path.join(tmp5, 'backend'), exist_ok=True)
    os.makedirs(os.path.join(tmp5, '报告'), exist_ok=True)
    src5 = os.path.join(tmp5, 'backend', 'app.py')
    doc5 = os.path.join(tmp5, '报告', '说明.md')
    with open(src5, 'w', encoding='utf-8') as f:
        f.write('X = 1\n')
    with open(doc5, 'w', encoding='utf-8') as f:
        f.write('原始文档\n')

    # 造一个「有 git 跟踪文件」的环境：真 git 仓库太重，这里直接
    # 让 _tracked() 走 git 不可用的兜底分支（临时目录不是 git 仓库）
    g5 = MutationGuard(tmp5)
    tracked5 = g5._tracked()
    check('兜底分支也不含文档目录',
          not any('报告' in p for p in tracked5), str(tracked5))

    # 再验真实仓库里的过滤结果（这才是实际生效的那条路径）
    g5b = MutationGuard(ROOT)
    tracked5b = g5b._tracked()
    doc_hits = [p for p in tracked5b
                if p.split('/', 1)[0] in ('报告', 'docs', '文档')]
    check('真实仓库的快照范围不含文档目录',
          not doc_hits, str(doc_hits[:3]))
    check('真实仓库的快照范围仍含源码目录',
          any(p.startswith('backend/') for p in tracked5b),
          str(len(tracked5b)) + ' 个文件')

    # 关键行为：文档目录的文件**不在快照里** ⇒ restore() 不会碰它。
    # ⚠ 必须走**真实的 snapshot() 路径**（手工往 snap 里塞文件等于
    #   绕过了 _tracked() 过滤，测出来的是假场景 —— 2026-11-18 首版
    #   就是这么写错的，判据自己报了假失败）。
    # 办法：临时目录里建一个真 git 仓库，把文档提交进去，
    # 让 `git ls-files` 能列出它 —— 而 `_tracked()` 的 SOURCE_DIRS
    # 过滤应当把它挡在快照之外。
    import subprocess
    tmp5r = tempfile.mkdtemp(prefix='mutguard-test5-repo-')
    def _git(*args):
        return subprocess.run(['git', '-C', tmp5r] + list(args),
                              capture_output=True, text=True)
    _git('init', '-q')
    _git('config', 'user.email', 't@t')
    _git('config', 'user.name', 't')
    os.makedirs(os.path.join(tmp5r, 'backend'), exist_ok=True)
    os.makedirs(os.path.join(tmp5r, '报告'), exist_ok=True)
    with open(os.path.join(tmp5r, 'backend', 'app.py'), 'w',
              encoding='utf-8') as f:
        f.write('X = 1\n')
    with open(os.path.join(tmp5r, '报告', '说明.md'), 'w',
              encoding='utf-8') as f:
        f.write('原始文档\n')
    _git('add', '-A')
    _git('commit', '-qm', 'init')

    g5c = MutationGuard(tmp5r)
    try:
        g5c.snapshot()
        check('快照里不含文档目录',
              not os.path.isfile(os.path.join(g5c.snap, '报告', '说明.md')))
        check('快照里含源码目录',
              os.path.isfile(os.path.join(g5c.snap, 'backend', 'app.py')))
        # 模拟「有人在运行期间改了文档」
        with open(os.path.join(tmp5r, '报告', '说明.md'), 'w',
                  encoding='utf-8') as f:
            f.write('运行期间写的新内容\n')
        g5c.restore()
        after = open(os.path.join(tmp5r, '报告', '说明.md'),
                     encoding='utf-8').read()
        check('文档改动没有被保险丝还原', after == '运行期间写的新内容\n',
              repr(after))
    finally:
        try:
            g5c.restore()
        except Exception:
            pass
        if g5c.snap and os.path.isdir(g5c.snap):
            import shutil
            shutil.rmtree(g5c.snap, ignore_errors=True)
            shutil.rmtree(g5c.snap + '.pre-restore', ignore_errors=True)
        g5c.snap = None
        import shutil
        shutil.rmtree(tmp5r, ignore_errors=True)

    print('\n' + '=' * 60)
    print(f' 合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        print(' 有失败')
    else:
        print(' 全部通过')
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
