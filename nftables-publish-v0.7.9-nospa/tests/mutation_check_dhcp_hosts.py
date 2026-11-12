#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DHCP 静态绑定**写路径**（backend/dhcp_hosts.py）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_dhcp_hosts.py

测什么有效
----------
这是本项目**第一个会改系统配置**的代码路径（改设备的 /etc/config/dhcp
并重载 dnsmasq）。出错的代价是「用户的路由器 DHCP 配置被写坏」，
而这类退化在单测里最容易滑过去 —— 因为单测只看「函数返回了什么」，
看不到「磁盘上现在是什么」。

所以每条变异都往「让写操作退化」的方向改：

  **一、安全网被拆掉**
    · 写前不备份（出问题就没得恢复）
    · 写坏了不回滚（坏配置留在设备上，dnsmasq 起不来）
    · 回滚失败不上报（用户以为恢复好了，其实没恢复）
    · 写完不校验语法（坏配置直接生效）
    · 备份与回滚都不保持 0600（配置全设备可读）

  **二、校验被放宽**
    · 显示名允许控制字符（换行会破坏配置文件，.232 实测 uci 原样写入）
    · 段名用显示名（uci 拒绝非 ASCII 段名 ⇒ 中文名根本写不进去）
    · 段名格式不校验（`@host[0]` 这种能当 uci 参数使）
    · IP 校验退回 isdigit（`int('²')` 抛异常 ⇒ 接口 500）

  **三、查重与重载**
    · 同 MAC 不拦（dnsmasq 行为未定义）
    · 重载失败当写失败（文件其实是对的，用户被误导）

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。

⚠️ 语法错误的变异不是行为变异
------------------------------
改出来的代码必须**能跑**，否则测试脚本会崩，而崩溃不等于断言失败
（2026-11-11 审查 M8）。落地后先 py_compile 一次，语法不过直接算漏网。

保险丝：只备份 / 还原 backend/dhcp_hosts.py 一个文件。
还原后比对 sha256 —— 源码没还原干净时**必须**当成失败。
"""
import atexit
import hashlib
import os
import py_compile
import signal
import subprocess
import sys
import tempfile

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'backend', 'dhcp_hosts.py')
TEST = os.path.join(ROOT, 'tests', 'test_dhcp_hosts_write.py')

ORIG = open(SCRIPT, encoding='utf-8').read()
ORIG_SHA = hashlib.sha256(ORIG.encode('utf-8')).hexdigest()


def _judge_capture(rc, out):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」
      ⇒ 只有输出里真的出现**断言失败**的标记行才算捕获。
    """
    if rc == 0:
        return False
    for line in out.splitlines():
        s = line.strip()
        if ('[FAIL]' in s and '[PASS]' not in s):
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    """把源码还原成启动时的内容。幂等，可反复调用。"""
    try:
        with open(SCRIPT, 'w', encoding='utf-8') as f:
            f.write(ORIG)
    except OSError:
        pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    try:
        with open(SCRIPT, 'rb') as f:
            got = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        got = None
    if got != ORIG_SHA:
        return False, '%s 还原后 sha256 不一致（%s != %s）' % (
            os.path.basename(SCRIPT), got, ORIG_SHA)
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
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=900,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


def apply_edits(src, edits):
    """按顺序应用编辑。锚点必须在源码里**唯一**，否则报错（不静默跳过）。"""
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点出现 %d 次（要求唯一）: %r' % (n, old[:70]))
        src = src.replace(old, new)
    return src


# ─────────────────────────────────────────────────────────────
# 变异定义：(名称, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

MUTATIONS = [
    # ── 一、安全网 ────────────────────────────────────────────
    ('W1  写前不备份（出问题没得恢复）',
     [('        backup = _make_backup(\'add\')\n',
       '        backup = os.path.join(BACKUP_DIR, \'no-backup-was-made\')\n')]),

    ('W2  写坏了不回滚（坏配置留在设备上）',
     # ⚠️ 直接改 `_restore` 里「把备份拷回去」那一步。
     #   原来这条挂在 add/delete 的回滚块上 —— 两处一模一样 ⇒ 锚点不唯一。
     [('        shutil.copy2(backup, DHCP_CONFIG_PATH)\n'
       '        os.chmod(DHCP_CONFIG_PATH, 0o600)\n'
       '        return True',
       '        os.chmod(DHCP_CONFIG_PATH, 0o600)\n'
       '        return True')]),

    ('W3  回滚失败不上报（用户以为恢复了，其实没恢复）',
     [('    def __init__(self, message, rolled_back=True):\n'
       '        super().__init__(message)\n'
       '        self.rolled_back = rolled_back',
       '    def __init__(self, message, rolled_back=True):\n'
       '        super().__init__(message)\n'
       '        self.rolled_back = True')]),

    ('W4  写完不校验语法（坏配置直接生效）',
     [('    rc, out = _run_uci([\'show\', \'dhcp\'])\n'
       '    if rc != 0:\n'
       '        return False, out.strip()\n'
       '    return True, \'\'',
       '    return True, \'\'')]),

    ('W5  备份文件不收紧权限（配置全设备可读）',
     [('        shutil.copy2(DHCP_CONFIG_PATH, dst)\n'
       '        os.chmod(dst, 0o600)',
       '        shutil.copy2(DHCP_CONFIG_PATH, dst)\n'
       '        os.chmod(dst, 0o644)')]),

    ('W6  回滚后不收紧权限',
     [('        shutil.copy2(backup, DHCP_CONFIG_PATH)\n'
       '        os.chmod(DHCP_CONFIG_PATH, 0o600)',
       '        shutil.copy2(backup, DHCP_CONFIG_PATH)\n'
       '        os.chmod(DHCP_CONFIG_PATH, 0o644)')]),

    # ── 二、校验被放宽 ────────────────────────────────────────
    ('W7  显示名允许控制字符（换行会破坏配置文件）',
     [('    bad = [c for c in name if ord(c) < 0x20 or ord(c) == 0x7f]',
       '    bad = []')]),

    ('W8  段名用显示名（uci 拒绝非 ASCII 段名）',
     [('    section = _section_for_mac(mac)',
       '    section = name')]),

    ('W9  段名格式不校验（@host[0] 能当 uci 参数使）',
     [('    if not _is_ascii_ident(section):\n'
       '        raise DhcpWriteError(\'绑定标识不合法\')',
       '    if False:\n'
       '        raise DhcpWriteError(\'绑定标识不合法\')')]),

    ('W10 段名格式校验退回 isalnum（中文能过）',
     [('    return all((\'a\' <= c <= \'z\') or (\'A\' <= c <= \'Z\') or\n'
       '               (\'0\' <= c <= \'9\') or c == \'_\' for c in s)',
       '    return all(c.isalnum() or c == \'_\' for c in s)')]),

    ('W11 IP 校验退回 isdigit（int(\'²\') 抛异常 ⇒ 接口 500）',
     [('    return bool(s) and all(\'0\' <= c <= \'9\' for c in s)',
       '    return bool(s) and s.isdigit()')]),

    ('W12 显示名长度限制去掉',
     [('    if len(name) > 63:\n'
       '        return False, \'设备名太长（最多 63 个字符）\'',
       '    if False:\n'
       '        return False, \'设备名太长（最多 63 个字符）\'')]),

    ('W13 租期不校验（换行能进配置文件）',
     [('    ok, why = _validate_leasetime(leasetime)',
       '    ok, why = (True, \'\')')]),

    # ── 三、查重与重载 ────────────────────────────────────────
    ('W14 同 MAC 不拦（dnsmasq 行为未定义）',
     [('        dup = _host_with_same(\'mac\', mac)\n'
       '        if dup:\n'
       '            raise DhcpWriteError(\'MAC %s 已经绑在「%s」上了，不能绑两次\' % (mac, dup))',
       '        dup = None\n'
       '        if dup:\n'
       '            raise DhcpWriteError(\'MAC %s 已经绑在「%s」上了，不能绑两次\' % (mac, dup))')]),

    ('W15 同 IP 不拦（同一个 IP 只能绑一个 MAC）',
     [('        dup_ip = _host_with_same(\'ip\', ip)\n'
       '        if dup_ip:\n'
       '            raise DhcpWriteError(\'IP %s 已经绑在「%s」上了，不能绑两次\' % (ip, dup_ip))',
       '        dup_ip = None\n'
       '        if dup_ip:\n'
       '            raise DhcpWriteError(\'IP %s 已经绑在「%s」上了，不能绑两次\' % (ip, dup_ip))')]),

    ('W16 重载失败当写失败（文件其实是对的，用户被误导）',
     [('    if r.returncode != 0:\n'
       '        return {\'ok\': False,\n'
       '                \'message\': \'重载 dnsmasq 返回非零（绑定已写入，可能未生效）\'}',
       '    if r.returncode != 0:\n'
       '        raise DhcpWriteError(\'重载 dnsmasq 返回非零\')')]),

    ('W17 MAC 查重不区分大小写（手写配置里 MAC 可能带大写）',
     [('            if cur_val.lower() == value.lower() and cur_section != exclude_section:',
       '            if cur_val == value and cur_section != exclude_section:')]),

    ('W18 备份目录建不出来也继续写（没有备份就不许改）',
     # ⚠️ 必须**同时**放开三处（2026-11-12 实测踩过）：
     #   · 写锁的 makedirs（不放开的话，锁先抛 ⇒ 行为完全不变）
     #   · 写锁的锁文件路径（否则锁文件也建不出来，一样抛）
     #   · `_make_backup` 的建目录 与 拷贝
     #   只放开一处 ⇒ 等价变异，测不出任何东西。
     [('    lock_path = os.path.join(BACKUP_DIR, _LOCK_FILE_NAME)\n'
       '    try:\n'
       '        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)\n'
       '        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)',
       '    lock_path = \'/tmp/dhcp-mutation.lock\'\n'
       '    try:\n'
       '        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)'),
      ('    try:\n'
       '        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)\n'
       '    except OSError as e:\n'
       '        raise DhcpWriteError(\'备份目录建不出来: %s\' % e)',
       '    try:\n'
       '        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)\n'
       '    except OSError as e:\n'
       '        pass'),
      ('    try:\n'
       '        shutil.copy2(DHCP_CONFIG_PATH, dst)\n'
       '        os.chmod(dst, 0o600)\n'
       '    except OSError as e:\n'
       '        raise DhcpWriteError(\'备份失败: %s\' % e)',
       '    try:\n'
       '        shutil.copy2(DHCP_CONFIG_PATH, dst)\n'
       '        os.chmod(dst, 0o600)\n'
       '    except OSError as e:\n'
       '        pass')]),

    # ── 四、并发写保护（2026-11-12 新增）─────────────────────
    ('W19 写操作不加锁（两个写请求会丢写 / 互相覆盖备份）',
     # ⚠️ 把真正的加锁换成 LOCK_UN（对没上锁的 fd 是空操作）⇒
     #    代码照样跑，但**锁从头到尾没被持有**。
     [('                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)',
       '                fcntl.flock(lock_fd, fcntl.LOCK_UN)')]),

    ('W20 备份名不唯一（同一秒的两个写会互相覆盖备份）',
     [('        BACKUP_DIR, \'dhcp.%s.%d.%d.%s\' % (ts, os.getpid(), seq, tag))',
       '        BACKUP_DIR, \'dhcp.%s.%d.%s\' % (ts, os.getpid(), tag))')]),

    ('W21 备份在锁外做（备份的是哪一版就没保证了）',
     # ⚠️ 把 `_make_backup` 挪到 `with` 之前 —— 与 app.py 的 P1-30 同款错误。
     [('    with _write_lock():\n'
       '        if _section_exists(section):',
       '    backup = _make_backup(\'add\')\n'
       '    with _write_lock():\n'
       '        if _section_exists(section):'),
      ('        backup = _make_backup(\'add\')\n'
       '        try:\n'
       '            rc, out = _run_uci([\'set\', \'dhcp.%s=host\' % section])',
       '        try:\n'
       '            rc, out = _run_uci([\'set\', \'dhcp.%s=host\' % section])')]),

    ('W22 回滚不清 uci 的未提交变更（回滚是假的）',
     # ⚠️ .232 实测：commit 失败后 delta 还在 ⇒ 下一次 commit 会把
     #    「已回滚」的那条写回去 ⇒ 「已回滚」这句话就是假的。
     [('    rc, out = _run_uci([\'revert\', \'dhcp\'])\n'
       '    return rc == 0, out.strip()',
       '    return True, \'\'')]),

    ('W23 删除不查段类型（能删掉 LAN 的 DHCP 服务配置）',
     [('        if stype != \'host\':',
       '        if False:')]),

    ('W24 文件没被改过也要拿备份去覆盖（只读磁盘上报假警报）',
     # ⚠️ 回滚时若文件**根本没被改过**（commit 失败时就是这么），
     #   就不应该再去拿备份去覆盖 —— 只读文件系统上那次拷贝必然失败
     #   ⇒ 报「回滚失败」是假警报 ⇒ 用户照着做 = 用旧备份覆盖好配置。
     [('    try:\n'
       '        if _same_file(backup, DHCP_CONFIG_PATH):\n'
       '            return True\n'
       '        shutil.copy2(backup, DHCP_CONFIG_PATH)',
       '    try:\n'
       '        shutil.copy2(backup, DHCP_CONFIG_PATH)')]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
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

    caught = missed = 0
    for name, edits in MUTATIONS:
        src = ORIG
        bad = [old for old, _ in edits if old not in src]
        dup = [old for old, _ in edits if src.count(old) != 1]
        if bad or dup:
            why = []
            if bad:
                why.append('锚点没匹配上（源码变了？）')
            if dup:
                why.append('锚点出现 %d 次，不是唯一' % src.count(dup[0]))
            print('  [FAIL] %s  —— ' % name + '；'.join(why) + ' ⇒ 算漏网')
            missed += 1
            continue
        try:
            mutated = apply_edits(src, edits)
            with open(SCRIPT, 'w', encoding='utf-8') as f:
                f.write(mutated)
            # ⚠ 语法错误的变异不是行为变异 —— 测试会崩，而崩溃不等于断言失败。
            try:
                py_compile.compile(SCRIPT, cfile=os.path.join(
                    tempfile.gettempdir(), 'dhcp_hosts_mut_check.pyc'),
                    doraise=True)
            except py_compile.PyCompileError as e:
                print('  [FAIL] %s  —— 变异后语法错误（不是行为变异）⇒ 算漏网' % name)
                print('      ↓ %s' % str(e).splitlines()[-1][:100])
                missed += 1
                continue
            rc, out = run_tests()
            if _judge_capture(rc, out):
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l and '[PASS]' not in l), '')
                print('  [PASS] %s  —— 被捕获' % name)
                if first:
                    print('      ↓ %s' % first)
                caught += 1
            else:
                print('  [FAIL] %s  —— 漏网！测试没抓住' % name)
                missed += 1
        finally:
            ok, detail = restore_verified()
            if not ok:
                print('  [FAIL] %s  —— %s ⇒ 后续变异全部作废' % (name, detail))
                print('=' * 60)
                print('  捕获 %d / %d（本次中止：源码没还原干净）'
                      % (caught, caught + missed + 1))
                return 1

    print()
    print('=' * 60)
    print('  捕获 %d / %d' % (caught, caught + missed))
    if missed:
        print('  源码已全部还原，但有漏网项 —— 上面标 [FAIL] 的测试是假测试')
    else:
        print('  源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
