"""变异脚本的保险丝 —— 被中断也不会把变异留在源码里。

问题（2026-10-19 真踩到）
------------------------
变异脚本靠 `try/finally` 还原源码。但**被取消 / 被 kill** 时，
`finally` 根本不执行 —— 变异就留在工作区里了。

后果比「测试没跑完」严重得多：那份「变异过的源码」看起来跟正常代码
一模一样，却带着被改坏的行为，很容易被当成真代码提交、发出去。

实测经过：取消一次全量变异运行后，`backend/auth_gateway.py` 里留下了一个
`_set_cookies(resp, "", "", clear=True)` 被包进 `if ok:` 的变异
（来自 `mutation_check_auth_session.py`）。直到
`test_auth_session_lifecycle.py` 报出一条看不懂的失败
（「失败时仍然撤掉本机 cookie」）才发现是**别人留下的变异**，
差点当成新 bug 去查。

做法
----
1. 启动时把**所有 git 跟踪的文件**快照到临时目录
2. 正常结束 / 抛异常 / **SIGTERM / SIGINT** → 全部还原
3. 启动时若发现上次的快照还在（说明上次是被硬杀的，连信号都没收到）
   → 先还原再开跑，并把还原前的内容另存一份（不丢用户的后续改动）

⚠️ 快照的是**脚本启动那一刻**的内容，不是 git HEAD ——
所以用户未提交的正常改动不会被这个保险丝动到。

**但反过来更重要**：脚本启动**之后**做的改动，会被这个保险丝
（以及各脚本自己的 `finally` 回写）**静默覆盖掉**。

2026-10-20 实测踩到：一边跑全量回归，一边改了 `backend/app.py`。
回归跑完，改动没了 —— 没有报错、没有告警，文件内容被还原成了
「脚本 import 那一刻」的版本。原因是各变异脚本都在 `finally` 里
`open(path,'w').write(orig_src)`，而 `orig_src` 是 import 那一刻读的。

所以这里的 `restore()` 做了两件事：
  1. 还原前**先备份**当前内容到 `<snap>.pre-restore/`，并打醒目告警
     （不再静默吞掉）；
  2. 提供 `protect(path)`：脚本若发现文件被**外部**改过（不是自己的变异），
     就声明「这个文件不要覆盖」，还原时跳过它。
"""
import atexit
import glob
import os
import shutil
import signal
import subprocess
import tempfile

MARKER = '.mutation-guard-snapshot'


class MutationGuard:
    """用法:
        g = MutationGuard(repo_root)
        g.snapshot()     # 启动时调用（会装信号处理器 + 注册 atexit）
        ...              # 跑变异
        g.restore()      # 正常收尾时调用（atexit 也会兜一次，幂等）
    """

    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.snap = None
        self._restored = False
        self._handlers = {}
        # 被声明「不要覆盖」的文件（绝对路径）。脚本发现文件被外部改过时调用
        # protect()，还原时就会跳过它 —— 宁可留着一个"看起来有变异"的文件，
        # 也不能把别人的改动吞掉。
        self._protected = set()
        self.backup_dir = None

    # ── 文件清单 ──────────────────────────────────────────────
    def _tracked(self):
        try:
            out = subprocess.run(
                ['git', '-C', self.root, 'ls-files', '-z'],
                capture_output=True, text=True, timeout=60)
            if out.returncode == 0:
                files = [p for p in out.stdout.split('\0') if p]
                if files:
                    return files
        except Exception:
            pass
        # 兜底：git 不可用时，至少覆盖会被改的目录
        files = []
        for sub in ('backend', 'frontend'):
            base = os.path.join(self.root, sub)
            for dp, _, fns in os.walk(base):
                for fn in fns:
                    files.append(os.path.relpath(os.path.join(dp, fn), self.root))
        return files

    # ── 快照 ──────────────────────────────────────────────────
    def snapshot(self):
        self._restore_stale()
        self.snap = tempfile.mkdtemp(prefix='mutguard-')
        self.backup_dir = self.snap + '.pre-restore'
        for rel in self._tracked():
            src = os.path.join(self.root, rel)
            if not os.path.isfile(src):
                continue
            dst = os.path.join(self.snap, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
        with open(os.path.join(self.snap, MARKER), 'w') as f:
            f.write('snapshot\n')
        self._install_handlers()
        atexit.register(self.restore)
        return self.snap

    def _install_handlers(self):
        def _handler(signum, frame):
            self.restore()
            # 交还默认行为，让进程按原信号退出
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            try:
                self._handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, _handler)
            except Exception:
                pass

    # ── 还原 ──────────────────────────────────────────────────
    def protect(self, path):
        """声明某个文件**不要在还原时覆盖**。

        脚本发现文件内容既不是「本次变异结果」也不是「原始内容」时，
        说明**有人在本脚本运行期间改了源码**。这时候：
          · 覆盖 → 把别人的改动吞掉（本轮真踩过）
          · 不覆盖 → 文件可能看着有残留，但那是别人的改动，不是变异
        所以选后者：跳过还原，并打告警。
        """
        self._protected.add(os.path.abspath(path))

    def _backup(self, dst, rel):
        """把「还原前的内容」另存一份 —— 静默吞掉是最糟的。"""
        if not self.backup_dir:
            return
        try:
            out = os.path.join(self.backup_dir, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            shutil.copy2(dst, out)
        except OSError:
            pass

    def restore(self):
        if self._restored or not self.snap:
            return
        self._restored = True
        changed, skipped = [], []
        try:
            for dp, _, fns in os.walk(self.snap):
                for fn in fns:
                    if fn == MARKER:
                        continue
                    full = os.path.join(dp, fn)
                    rel = os.path.relpath(full, self.snap)
                    dst = os.path.join(self.root, rel)
                    if not os.path.isfile(dst):
                        continue
                    try:
                        if (os.path.getsize(full) == os.path.getsize(dst)
                                and open(full, 'rb').read() == open(dst, 'rb').read()):
                            continue
                    except OSError:
                        pass
                    if os.path.abspath(dst) in self._protected:
                        # 有人在运行期间改过它 —— 保留他们的版本
                        skipped.append(rel)
                        continue
                    changed.append(rel)
                    self._backup(dst, rel)
                    shutil.copy2(full, dst)
        finally:
            shutil.rmtree(self.snap, ignore_errors=True)
            self.snap = None
        if changed:
            print(f'  ⚠️  变异还原：以下文件与快照不一致，已从快照还原'
                  f'（还原前内容另存于 {self.backup_dir}）:')
            for rel in changed:
                print(f'       {rel}')
        if skipped:
            print('  ⚠️  以下文件在变异脚本运行期间被**外部改动过**，'
                  '已跳过还原（保留改动，没有覆盖）:')
            for rel in skipped:
                print(f'       {rel}')

    # ── 上次被硬杀的残留 ──────────────────────────────────────
    def _restore_stale(self):
        """启动时发现上次的快照还在 ⇒ 上次没走到还原（被硬杀）。
        先把当前状态另存一份，再还原 —— 不丢用户后续的改动。"""
        pat = os.path.join(tempfile.gettempdir(), 'mutguard-*')
        stale = [d for d in glob.glob(pat)
                 if os.path.isfile(os.path.join(d, MARKER))]
        for d in stale:
            # 只取最新的一份（其它可能是更早的残留）
            if not os.path.isfile(os.path.join(d, MARKER)):
                continue
            backup = d + '.pre-restore'
            if not os.path.exists(backup):
                try:
                    shutil.copytree(d, backup)
                except Exception:
                    pass
            saved = self.snap
            self.snap = d
            self._restored = False
            self.restore()
            self.snap = saved
            print(f'  ⚠️  发现上次被硬杀的变异残留，已从快照还原（还原前状态另存于 {backup}）')
