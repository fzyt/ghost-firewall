#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""网关访问日志封顶：行为级判据（2026-11-19）

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_log_truncate.py

这批功能是什么
--------------
设备实测 /var → tmpfs（492.9M），而持久化分区 /overlay 只剩 **2.0M（97% 满）**
⇒ 访问日志**挪不走**（挪过去会把 overlay 撑爆，路由器文件系统转只读，
配置就再也写不进去了），只能**给它封顶**：
超过 20MB 就保留尾部 8MB 原地截断，cron 每 5 分钟跑一次。

本判据重点守三件事
------------------
  一、**必须是 copytruncate，不能是 mv 换文件**
     nginx 一直握着日志文件的 fd（O_APPEND）。用 mv 换文件 ⇒ nginx 继续往
     已被 unlink 的旧 inode 写 ⇒ 新文件永远是空的 ⇒ 访客页永远显示「没人来过」，
     而磁盘还在偷偷涨（涨的是那个没人看得见的旧 inode）。
     这种错在真机上**什么都不报错**（nginx 不报错、面板不报错、日志文件还在），
     只能靠「截断前后 inode 不变」这种行为断言守住。

  二、**必须保留尾部、且每行必须是完整行**
     保留头部 ⇒ 访客页显示的是「几小时前来过的人」，看着有数据、其实全是错的。
     按字节切出来的第一行一定是半行 ⇒ 日志里会多一条残行。

  三、**拷贝失败不许把日志清空**
     「先拷尾部，再截断，再追加回去」这个顺序里，拷贝失败却继续往下走，
     等于把访问日志清空 —— 那比不封顶糟得多。

沙箱
----
脚本在临时目录里跑，阈值用环境变量调小（脚本本身留了口子），
**不碰本机 /var/log、不碰真设备**；
crontab 全部打桩（替身模块），**绝不动本机 crontab**。
"""
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tokenize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def load_app(tag):
    """加载一份**独立的** app 模块实例（不同 tag ⇒ 不共享全局状态）。

    载入前先看 os.environ —— app.py 的部署参数（脚本路径、日志路径）都是
    **导入期**从环境变量读的，所以要测「改了 env 之后会怎样」，
    就得在那之前把 env 设好、然后重新载入一份。
    """
    import importlib.util as ilu
    spec = ilu.spec_from_file_location('_nftapp_' + tag,
                                       os.path.join(BACKEND, 'app.py'))
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def strip_sh_comments(script):
    """去掉 shell 脚本里的注释行（只处理整行注释）。

    「某样东西不该出现」类断言必须看**去注释版**：
    脚本里本来就有一行注释写着「不能用 mv 换文件」，
    直接搜 'mv' 会把那句注释当成真代码 ⇒ 断言永远绿。
    """
    out = []
    for line in script.splitlines():
        if line.lstrip().startswith('#'):
            continue
        out.append(line)
    return '\n'.join(out)


def strip_py_comments(src):
    """去掉 Python 注释（tokenize 版，不动字符串里的 #）。"""
    try:
        toks = [t for t in tokenize.generate_tokens(io.StringIO(src).readline)
                if t.type != tokenize.COMMENT]
        return tokenize.untokenize(toks)
    except Exception:
        return src


def func_body(src, name):
    """取出 `def name(...)` 的函数体（到下一个顶层 def/@/if __name__ 之前），已去注释。"""
    m = re.search(r'^def\s+' + re.escape(name) + r'\s*\(', src, re.M)
    if not m:
        return ''
    rest = src[m.end():]
    nxt = re.search(r'^(?:@|def\s|class\s|if\s+__name__)', rest, re.M)
    body = rest[:nxt.start()] if nxt else rest
    return strip_py_comments(body)


class FakeProc:
    """冒充 subprocess.run 的返回值。"""

    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeCrontab:
    """替身 subprocess：只认 crontab -l / crontab -，别的一律报错。

    绝不用真 crontab —— 测试不该改这台机器的调度表。
    """

    def __init__(self, store=None):
        self.store = list(store or [])

    def run(self, cmd, input=None, capture_output=False, text=False, timeout=None):
        if list(cmd[:2]) == ['crontab', '-l']:
            return FakeProc(0, '\n'.join(self.store) + ('\n' if self.store else ''), '')
        if list(cmd[:2]) == ['crontab', '-']:
            self.store = [ln for ln in (input or '').splitlines() if ln.strip()]
            return FakeProc(0, '', '')
        raise AssertionError('测试里出现了意料之外的命令: %r' % (cmd,))


def run_script(script_path, log_path, max_bytes, keep_bytes):
    """按封顶脚本的真实约定跑一次（三个参数走环境变量口子）。"""
    env = dict(os.environ)
    env['GATEWAY_ACCESS_LOG'] = log_path
    env['NFT_LOG_TRUNCATE_MAX'] = str(max_bytes)
    env['NFT_LOG_TRUNCATE_KEEP'] = str(keep_bytes)
    return subprocess.run(['sh', script_path], env=env, capture_output=True,
                          text=True, timeout=60)


def make_lines(n, tag='line'):
    """造 n 行固定宽度的日志行（每行 21 字节，含换行）。"""
    return ''.join('%s%03d-0123456789abc\n' % (tag, i) for i in range(1, n + 1))


def main():
    import app as A

    src = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
    script_src = strip_sh_comments(A.LOG_TRUNCATE_SCRIPT)

    tmpdir = tempfile.mkdtemp(prefix='logtrunc-')
    try:
        script_path = os.path.join(tmpdir, 'truncate.sh')
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(A.LOG_TRUNCATE_SCRIPT)
        os.chmod(script_path, 0o755)

        # ── 一、阈值常量 ────────────────────────────────────────
        sec('一、阈值与常量')
        check('上限是 20MB', A.LOG_TRUNCATE_MAX_BYTES == 20 * 1024 * 1024,
              str(A.LOG_TRUNCATE_MAX_BYTES))
        check('保留量是 8MB', A.LOG_TRUNCATE_KEEP_BYTES == 8 * 1024 * 1024,
              str(A.LOG_TRUNCATE_KEEP_BYTES))
        check('保留量小于上限（否则截断完还是超标）',
              A.LOG_TRUNCATE_KEEP_BYTES < A.LOG_TRUNCATE_MAX_BYTES)
        check('脚本默认装在 /opt/nftables-web/ 下',
              A.LOG_TRUNCATE_SCRIPT_PATH.startswith('/opt/nftables-web/'),
              A.LOG_TRUNCATE_SCRIPT_PATH)
        check('cron 频率是每 5 分钟',
              A.LOG_TRUNCATE_CRON_ENTRY.startswith('*/5 * * * * '),
              A.LOG_TRUNCATE_CRON_ENTRY)
        check('cron 条目指向封顶脚本',
              A.LOG_TRUNCATE_CRON_ENTRY.endswith(A.LOG_TRUNCATE_SCRIPT_PATH))
        check('默认日志路径与历史硬编码一致（老设备升级后 nginx 配置字节不变）',
              A.GATEWAY_ACCESS_LOG == '/var/log/nginx/nftables-web-gateway.access.log',
              A.GATEWAY_ACCESS_LOG)

        # ── 二、脚本内容（去注释版）─────────────────────────────
        sec('二、脚本内容（去注释后）')
        check('脚本里没有 mv（nginx 持有 fd，mv 换文件会让它写进旧 inode）',
              not re.search(r'(^|\s)mv\s', script_src))
        check('脚本里有截断动作 : > "$LOG"',
              ': > "$LOG"' in script_src)
        check('脚本里有把副本贴回去的动作 cat "$LOG.tmp" >> "$LOG"',
              'cat "$LOG.tmp" >> "$LOG"' in script_src)
        check('脚本里有取尾部的 tail -c "$KEEP"',
              'tail -c "$KEEP"' in script_src)
        check('脚本里没有 head -c（要留的是尾部，不是头部）',
              not re.search(r'head\s+-c', script_src))
        check('文件不存在时安静退出',
              '[ -f "$LOG" ] || exit 0' in script_src)
        check('用 wc -c 取文件大小',
              'wc -c < "$LOG"' in script_src)
        check('大小不是纯数字时退出（不拿脏数据比大小）',
              '*[!0-9]*)' in script_src)
        check('保留量不得小于等于上限的钳制存在',
              '[ "$KEEP" -lt "$MAX" ]' in script_src)
        check('拷贝失败不许继续（防清空日志）',
              '|| exit 0' in script_src and '[ ! -s "$LOG.tmp" ]' in script_src)
        check('日志路径可被环境变量覆盖（运维不用改面板）',
              'GATEWAY_ACCESS_LOG:-' in script_src)
        check('上限可被环境变量覆盖（测试不用造 20MB 文件）',
              'NFT_LOG_TRUNCATE_MAX:-' in script_src)
        check('保留量可被环境变量覆盖',
              'NFT_LOG_TRUNCATE_KEEP:-' in script_src)
        check('脚本里嵌的上限值与 Python 常量一致',
              str(A.LOG_TRUNCATE_MAX_BYTES) in script_src)
        check('脚本里嵌的保留量与 Python 常量一致',
              str(A.LOG_TRUNCATE_KEEP_BYTES) in script_src)
        check('脚本里嵌的日志路径与 Python 常量一致',
              A.GATEWAY_ACCESS_LOG in script_src)

        # ── 三、脚本真跑 ────────────────────────────────────────
        sec('三、脚本真跑（行为）')

        # 3.1 超过阈值 → 截断
        log1 = os.path.join(tmpdir, 'big.log')
        with open(log1, 'w', encoding='utf-8') as f:
            f.write(make_lines(100))
        before_size = os.path.getsize(log1)
        before_ino = os.stat(log1).st_ino
        r = run_script(script_path, log1, 1000, 500)
        after_size = os.path.getsize(log1)
        after_ino = os.stat(log1).st_ino
        content1 = open(log1, encoding='utf-8').read()
        check('超阈值时脚本正常退出', r.returncode == 0, r.stderr.strip()[:120])
        check('超阈值时文件被截断', after_size < before_size,
              '%d → %d' % (before_size, after_size))
        check('截断后大小不超过保留量', after_size <= 500, str(after_size))
        check('截断前后 inode 不变（nginx 握着的 fd 仍然有效）',
              before_ino == after_ino, '%s vs %s' % (before_ino, after_ino))
        check('保留的是最新的尾部（最后一行还在）',
              content1.rstrip('\n').endswith('line100-0123456789abc'))
        check('丢掉的是头部（第一行不在了）',
              'line001-0123456789abc' not in content1)
        bad = [ln for ln in content1.splitlines() if not re.fullmatch(r'line\d{3}-0123456789abc', ln)]
        check('截断后每一行都是完整行（没有半行残留）', not bad, str(bad[:2]))
        check('保留了尽可能多的尾部（行数接近理论上限）',
              len(content1.splitlines()) >= 20, str(len(content1.splitlines())))
        leftovers = [f for f in os.listdir(tmpdir) if f.endswith('.tmp')]
        check('跑完不留临时文件（tmpfs 很小，不能攒垃圾）',
              not leftovers, str(leftovers))

        # 3.2 没超阈值 → 一个字节都不许动
        log2 = os.path.join(tmpdir, 'small.log')
        with open(log2, 'w', encoding='utf-8') as f:
            f.write(make_lines(10))
        small_before = open(log2, 'rb').read()
        r = run_script(script_path, log2, 100000, 500)
        small_after = open(log2, 'rb').read()
        check('未超阈值时脚本正常退出', r.returncode == 0, r.stderr.strip()[:120])
        check('未超阈值时文件一个字节都不动', small_before == small_after,
              '%d → %d' % (len(small_before), len(small_after)))

        # 3.3 文件不存在
        missing = os.path.join(tmpdir, 'not-exist.log')
        r = run_script(script_path, missing, 1000, 500)
        check('日志文件不存在时退出码是 0（不报错、不阻断 cron）',
              r.returncode == 0, r.stderr.strip()[:120])
        check('日志文件不存在时不凭空造一个出来',
              not os.path.exists(missing))

        # 3.4 保留量 >= 上限 ⇒ 钳到上限的一半（否则每轮都白跑）
        log4 = os.path.join(tmpdir, 'clamp.log')
        with open(log4, 'w', encoding='utf-8') as f:
            f.write(make_lines(100))
        r = run_script(script_path, log4, 1000, 2000)
        clamp_size = os.path.getsize(log4)
        check('保留量不小于上限时自动钳到上限的一半',
              clamp_size <= 500, str(clamp_size))
        check('钳制场景下脚本仍正常退出', r.returncode == 0, r.stderr.strip()[:120])

        # 3.5 拷贝失败不许把日志清空
        log5 = os.path.join(tmpdir, 'guard.log')
        with open(log5, 'w', encoding='utf-8') as f:
            f.write(make_lines(100))
        guard_before = open(log5, 'rb').read()
        # 把 "$LOG.tmp" 占成一个目录 ⇒ 建不出临时文件 ⇒ 拷贝必然失败
        os.mkdir(log5 + '.tmp')
        r = run_script(script_path, log5, 1000, 500)
        guard_after = open(log5, 'rb').read()
        check('临时文件建不出来时脚本退出码是 0', r.returncode == 0,
              r.stderr.strip()[:120])
        check('拷贝失败时原日志保持原样（不许被清空）',
              guard_before == guard_after,
              '%d → %d' % (len(guard_before), len(guard_after)))
        os.rmdir(log5 + '.tmp')

        # ── 四、_ensure_log_truncate_cron ───────────────────────
        sec('四、_ensure_log_truncate_cron（装脚本 + 装 cron）')
        real_subprocess = A.subprocess
        real_path = A.LOG_TRUNCATE_SCRIPT_PATH
        try:
            inst_dir = os.path.join(tmpdir, 'opt')
            os.makedirs(inst_dir, exist_ok=True)
            inst_path = os.path.join(inst_dir, 'truncate-gateway-log.sh')

            # 用环境变量重新载入一份 app —— 这才是设备上的真实情形：
            # 脚本路径与 cron 条目都由**同一个 env** 在导入期派生，
            # 两者永远配套。只改其中一个常量的话，那是我自己造出来的假场景。
            env_keys = ('NFTABLES_WEB_LOG_TRUNCATE_SCRIPT', 'GATEWAY_ACCESS_LOG')
            env_old = {k: os.environ.get(k) for k in env_keys}
            os.environ['NFTABLES_WEB_LOG_TRUNCATE_SCRIPT'] = inst_path
            os.environ['GATEWAY_ACCESS_LOG'] = os.path.join(tmpdir, 'relocated.access.log')
            try:
                A2 = load_app('logtrunc')
            finally:
                for k, v in env_old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v

            check('重新载入后脚本路径跟着 env 走',
                  A2.LOG_TRUNCATE_SCRIPT_PATH == inst_path,
                  A2.LOG_TRUNCATE_SCRIPT_PATH)
            check('cron 条目与脚本路径配套（不会各指各的）',
                  A2.LOG_TRUNCATE_CRON_ENTRY.endswith(inst_path),
                  A2.LOG_TRUNCATE_CRON_ENTRY)
            check('脚本内容里的日志路径跟着 env 走',
                  os.path.join(tmpdir, 'relocated.access.log') in A2.LOG_TRUNCATE_SCRIPT)

            fake = FakeCrontab([
                '/etc/init.d/acme renew',
                '*/10 * * * * /opt/nftables-web/update-ipv6.sh',
                '0 3 * * * /opt/nftables-web/renew-certs.sh',
            ])
            real_subprocess2 = A2.subprocess
            A2.subprocess = fake
            ok = A2._ensure_log_truncate_cron()
            check('装完返回 True', ok is True)
            check('脚本被写到指定路径', os.path.isfile(inst_path))
            if os.path.isfile(inst_path):
                mode = stat.S_IMODE(os.stat(inst_path).st_mode)
                check('脚本权限是 0755（cron 要能执行）', mode == 0o755, oct(mode))
                body = open(inst_path, encoding='utf-8').read()
                check('脚本内容与生成的模板一致',
                      body == A2.LOG_TRUNCATE_SCRIPT)
            check('cron 条目按脚本路径去重，只有一条',
                  sum(1 for ln in fake.store if inst_path in ln) == 1,
                  str([ln for ln in fake.store if inst_path in ln]))
            check('cron 里原有的 acme 续期条目没被抹掉',
                  '/etc/init.d/acme renew' in fake.store)
            check('cron 里原有的 IPv6 更新条目没被抹掉',
                  '*/10 * * * * /opt/nftables-web/update-ipv6.sh' in fake.store)
            check('cron 里原有的证书续期条目没被抹掉',
                  '0 3 * * * /opt/nftables-web/renew-certs.sh' in fake.store)
            check('cron 条目用的是每 5 分钟的频率',
                  any(ln.startswith('*/5 * * * * ') and inst_path in ln
                      for ln in fake.store))

            # 幂等：再装一次，不许堆出第二条
            ok2 = A2._ensure_log_truncate_cron()
            check('重复安装返回 True（幂等）', ok2 is True)
            check('重复安装后 cron 条目仍然只有一条',
                  sum(1 for ln in fake.store if inst_path in ln) == 1,
                  str([ln for ln in fake.store if inst_path in ln]))

            # 脚本写不出来 ⇒ 返回 False，不抛异常（不能因此起不来）
            blocker = os.path.join(tmpdir, 'blocker')
            with open(blocker, 'w', encoding='utf-8') as f:
                f.write('x')
            real_path2 = A2.LOG_TRUNCATE_SCRIPT_PATH
            A2.LOG_TRUNCATE_SCRIPT_PATH = os.path.join(blocker, 'sub', 'x.sh')
            ok3 = A2._ensure_log_truncate_cron()
            check('脚本写不出来时返回 False 而不是抛异常', ok3 is False)

            # cron 写不进去 ⇒ 返回 False，不抛异常
            A2.LOG_TRUNCATE_SCRIPT_PATH = real_path2
            real_upsert = A2._upsert_cron_for
            A2._upsert_cron_for = lambda p, c: (False, '模拟 crontab 失败')
            try:
                ok4 = A2._ensure_log_truncate_cron()
            finally:
                A2._upsert_cron_for = real_upsert
            check('cron 写不进去时返回 False 而不是抛异常', ok4 is False)
            A2.subprocess = real_subprocess2
        finally:
            A.subprocess = real_subprocess
            A.LOG_TRUNCATE_SCRIPT_PATH = real_path

        # ── 五、接线 ────────────────────────────────────────────
        sec('五、接线（启动调用 / nginx 配置）')
        start_body = func_body(src, '_start_servers')
        check('面板启动时会调用 _ensure_log_truncate_cron',
              '_ensure_log_truncate_cron()' in start_body)

        # nginx 配置必须跟着常量走：改了 GATEWAY_ACCESS_LOG 要真的生效，
        # 否则封顶脚本盯的文件和 nginx 写的文件对不上（封了个寂寞）。
        L = []
        A._nginx_server_preamble(L, 8443, '/tmp/c.pem', '/tmp/k.pem',
                                 'TLSv1.2 TLSv1.3')
        acc = [ln for ln in L if 'access_log' in ln]
        check('nginx 配置里有一条 access_log', len(acc) == 1, str(acc))
        real_log = A.GATEWAY_ACCESS_LOG
        try:
            A.GATEWAY_ACCESS_LOG = '/tmp/zzz-access.log'
            L2 = []
            A._nginx_server_preamble(L2, 8443, '/tmp/c.pem', '/tmp/k.pem',
                                     'TLSv1.2 TLSv1.3')
            acc2 = [ln for ln in L2 if 'access_log' in ln]
            check('nginx 配置用的是 GATEWAY_ACCESS_LOG 常量（不是写死的路径）',
                  len(acc2) == 1 and '/tmp/zzz-access.log' in acc2[0],
                  str(acc2))
        finally:
            A.GATEWAY_ACCESS_LOG = real_log
        check('默认路径下生成的配置与历史一致（老设备不需要 reload nginx）',
              acc and real_log in acc[0], str(acc))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()
    print('  合计: [PASS] %d   [FAIL] %d' % (len(PASS), len(FAIL)))
    if FAIL:
        print('  失败项:')
        for name in FAIL:
            print('    - ' + name)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
