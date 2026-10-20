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
