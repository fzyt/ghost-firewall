#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""网关访问日志封顶的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_logtruncate.py

测什么有效
----------
这批功能只有一个脚本，但它藏在**四个不同的失败模式**里，
每个失败模式在真机上都表现为「一切正常，只是日志在偷偷涨」：

  一、**换文件而不是原地截断**
    用 mv 把副本换上去 ⇒ nginx 继续往已被 unlink 的旧 inode 写
    ⇒ 新文件永远是空的 ⇒ 访客页永远显示「没人来过」，
    而磁盘还在涨（涨的是那个没人看得见的旧 inode）。
    nginx 不报错、面板不报错 ⇒ 只有「截断前后 inode 不变」这种断言能抓住。

  二、**留错内容**
    留头部而不是尾部 ⇒ 访客页显示的是几小时前的人，看着有数据、其实全是错的。
    按字节切不丢第一行 ⇒ 日志里多一条半行残行。

  三、**阈值判错**
    没超阈值也截断 ⇒ 用户刚重启完，日志就被清空了。
    完全没有阈值判断 ⇒ 每 5 分钟清一次，访客页永远是空的。

  四、**拷贝失败却往下走**
    「先拷尾部，再截断，再追加回去」里，拷贝失败还接着走 = 把日志清空。
    比不封顶糟得多。

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。

⚠️ 语法错误的变异不是行为变异
------------------------------
改出来的代码必须**能跑**，否则测试脚本会崩，而崩溃不等于断言失败
（判定只看输出里有没有真正的断言失败行）。

保险丝：备份 / 还原本脚本会动的那几个文件。
还原后比对 sha256 —— 源码没还原干净时**必须**当成失败。
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = {
    'app': os.path.join(ROOT, 'backend', 'app.py'),
}
TESTS = [
    os.path.join(ROOT, 'tests', 'test_log_truncate.py'),
]

ORIG = {k: open(v, encoding='utf-8').read() for k, v in FILES.items()}
ORIG_SHA = {k: hashlib.sha256(s.encode('utf-8')).hexdigest()
            for k, s in ORIG.items()}

# (描述, 文件键, [(旧文本, 新文本), ...])
MUTATIONS = [
    # ── 一、换文件 vs 原地截断 ────────────────────────────────
    ('L-1 用 mv 换文件（nginx 会继续往旧 inode 写）', 'app',
     [('cat "$LOG.tmp" >> "$LOG"', 'mv "$LOG.tmp" "$LOG"')]),

    ('L-2 不截断就追加（文件越跑越大）', 'app',
     [(': > "$LOG"\ncat "$LOG.tmp" >> "$LOG"', 'cat "$LOG.tmp" >> "$LOG"')]),

    # 这条专门用来证明「截断前后 inode 不变」这条行为断言**自己**有鉴别力：
    # 脚本里没有 mv 字样、内容也完全正确，只有 inode 变了
    # ⇒ 静态断言（不许出现 mv）抓不到它，只有 inode 断言能抓。
    ('L-2b 用 rm+cp 换文件（内容对但 inode 变了，nginx 写进旧 inode）', 'app',
     [(': > "$LOG"\ncat "$LOG.tmp" >> "$LOG"',
       'rm -f "$LOG"\ncp "$LOG.tmp" "$LOG"')]),

    # ── 二、留错内容 ────────────────────────────────────────
    ('L-3 留头部而不是尾部（访客页显示的是老访客）', 'app',
     [('tail -c "$KEEP" "$LOG"', 'head -c "$KEEP" "$LOG"')]),

    ('L-4 不丢第一行（日志里混进半行残行）', 'app',
     [('| tail -n +2 2>/dev/null > "$LOG.tmp"', '> "$LOG.tmp"')]),

    ('L-5 保留量清零（日志被清成空文件）', 'app',
     [('KEEP=${{NFT_LOG_TRUNCATE_KEEP:-{LOG_TRUNCATE_KEEP_BYTES}}}',
       'KEEP=0')]),

    # ── 三、阈值判错 ────────────────────────────────────────
    ('L-6 阈值判断反了（没超阈值也截断）', 'app',
     [('[ "$size" -gt "$MAX" ] || exit 0', '[ "$size" -lt "$MAX" ] || exit 0')]),

    ('L-7 完全没有阈值判断（每 5 分钟清一次日志）', 'app',
     [('\n[ "$size" -gt "$MAX" ] || exit 0\n', '\n')]),

    ('L-8 保留量不再钳到上限一半（截断完还是超标）', 'app',
     [('[ "$KEEP" -lt "$MAX" ] || KEEP=$((MAX / 2))', ':')]),

    ('L-9 大小不是数字时不再退出（拿脏数据比大小）', 'app',
     [('  ""|*[!0-9]*) exit 0 ;;', '  "") exit 0 ;;')]),

    # ── 四、拷贝失败却往下走 ──────────────────────────────────
    ('L-10 删掉拷贝失败护栏（拷贝失败就把日志清空）', 'app',
     [('if [ ! -s "$LOG.tmp" ]; then rm -f "$LOG.tmp" 2>/dev/null; exit 0; fi\n',
       '')]),

    ('L-11 文件不存在时反而造一个出来', 'app',
     [('[ -f "$LOG" ] || exit 0', '[ -f "$LOG" ] || touch "$LOG"')]),

    ('L-12 跑完不删临时文件（tmpfs 很小，攒垃圾）', 'app',
     [('rm -f "$LOG.tmp"\nexit 0', 'exit 0')]),

    # ── 五、阈值常量与 cron 接线 ─────────────────────────────
    ('L-13 上限从 20MB 变成 50MB', 'app',
     [('LOG_TRUNCATE_MAX_BYTES = 20 * 1024 * 1024',
       'LOG_TRUNCATE_MAX_BYTES = 50 * 1024 * 1024')]),

    ('L-14 保留量从 8MB 变成 2MB', 'app',
     [('LOG_TRUNCATE_KEEP_BYTES = 8 * 1024 * 1024',
       'LOG_TRUNCATE_KEEP_BYTES = 2 * 1024 * 1024')]),

    ('L-15 cron 频率从 5 分钟变成 10 分钟', 'app',
     [("LOG_TRUNCATE_CRON_ENTRY = f'*/5 * * * * {LOG_TRUNCATE_SCRIPT_PATH}'",
       "LOG_TRUNCATE_CRON_ENTRY = f'*/10 * * * * {LOG_TRUNCATE_SCRIPT_PATH}'")]),

    ('L-16 cron 指向别的脚本（封顶脚本压根没被调度）', 'app',
     [("LOG_TRUNCATE_CRON_ENTRY = f'*/5 * * * * {LOG_TRUNCATE_SCRIPT_PATH}'",
       "LOG_TRUNCATE_CRON_ENTRY = f'*/5 * * * * /opt/nftables-web/other.sh'")]),

    ('L-17 不给脚本加执行权限（cron 跑不动）', 'app',
     [('        os.chmod(LOG_TRUNCATE_SCRIPT_PATH, 0o755)\n', '')]),

    ('L-18 不装 cron 条目（脚本写好了但没人调度）', 'app',
     [('    ok, msg = _upsert_cron_for(LOG_TRUNCATE_SCRIPT_PATH, LOG_TRUNCATE_CRON_ENTRY)',
       '    ok, msg = True, "crontab 已更新"')]),

    ('L-19 面板启动时不装封顶脚本（升级后要手动装）', 'app',
     [('    try:\n        _ensure_log_truncate_cron()\n',
       '    try:\n        pass\n')]),

    # ── 六、nginx 配置与脚本要对得上 ─────────────────────────
    ('L-20 nginx 配置写死路径（改了 env 就对不上，封了个寂寞）', 'app',
     [('    L.append(f"    access_log {GATEWAY_ACCESS_LOG} nftgw;")',
       '    L.append("    access_log /var/log/nginx/nftables-web-gateway.access.log nftgw;")')]),

    ('L-21 脚本里的上限与 Python 常量脱钩', 'app',
     [('MAX=${{NFT_LOG_TRUNCATE_MAX:-{LOG_TRUNCATE_MAX_BYTES}}}',
       'MAX=${{NFT_LOG_TRUNCATE_MAX:-{LOG_TRUNCATE_KEEP_BYTES}}}')]),
]


def _judge_capture(rc, msg):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」
      ⇒ 只有输出里真的出现**断言失败**的标记行才算捕获。
    """
    if rc == 0:
        return False
    for line in msg.splitlines():
        s = line.strip()
        if '[FAIL]' in s and '[PASS]' not in s:
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    """把源码还原成启动时的内容。幂等，可反复调用。"""
    for key, path in FILES.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(ORIG[key])
        except OSError:
            pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    for key, path in FILES.items():
        try:
            with open(path, 'rb') as f:
                got = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            got = None
        if got != ORIG_SHA[key]:
            return False, '%s 还原后 sha256 不一致（%s != %s）' % (
                os.path.basename(path), got, ORIG_SHA[key])
    return True, '源码已还原，sha256 一致'


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
    """跑本批判据，输出合并。"""
    outs = []
    rc_all = 0
    for t in TESTS:
        cmd = [sys.executable, t]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                           cwd=ROOT)
        outs.append(r.stdout + r.stderr)
        if r.returncode != 0:
            rc_all = r.returncode
    return rc_all, '\n'.join(outs)


def apply_edits(key, edits):
    """edits: [(old, new)]，每条都必须**唯一**匹配 —— 匹配不上就报错。

    为什么必须唯一：变异脚本按「第一个匹配」替换；
    old 片段不唯一 ⇒ 改到哪一处全看运气 ⇒ 「漏网」被伪装成「捕获」。
    """
    src = ORIG[key]
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点出现 %d 次，必须唯一：%r' % (n, old[:70]))
        src = src.replace(old, new, 1)
    with open(FILES[key], 'w', encoding='utf-8') as f:
        f.write(src)


def main():
    print('=== 变异验证：网关访问日志封顶 ===')
    ok, detail = restore_verified()
    if not ok:
        print('[FAIL] %s —— 变异验证无意义' % detail)
        return 1
    rc, out = run_tests()
    if rc != 0:
        print('[FAIL] 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-3000:])
        return 1
    print('  [PASS] 基线通过\n')

    caught, missed = 0, []
    for desc, key, edits in MUTATIONS:
        restore()
        try:
            apply_edits(key, edits)
        except ValueError as e:
            print('  [脚本错] %s' % desc)
            print('      ↓ %s' % e)
            missed.append('%s（变异脚本自身的错）' % desc)
            continue
        rc, out = run_tests()
        if _judge_capture(rc, out):
            caught += 1
            first = ''
            for line in out.splitlines():
                s = line.strip()
                if '[FAIL]' in s and '[PASS]' not in s:
                    first = s
                    break
            print('  [捕获] %s' % desc)
            if first:
                print('      ↓ %s' % first[:150])
        else:
            missed.append(desc)
            print('  [漏网] %s  ← 测试没变红！' % desc)

    restore()
    ok, detail = restore_verified()
    print()
    print('=' * 60)
    print('  变异 %d 条，捕获 %d 条，漏网 %d 条' %
          (len(MUTATIONS), caught, len(missed)))
    if missed:
        print('  漏网的变异：')
        for m in missed:
            print('    - ' + m)
        print('=' * 60)
        return 1
    if not ok:
        print('  [FAIL] %s' % detail)
        print('=' * 60)
        return 1
    print('  全部捕获')
    print('=' * 60)
    return 0


if __name__ == '__main__':
    sys.exit(main())
