#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DHCP 静态绑定的增删（写 `/etc/config/dhcp`）。

为什么单独一个模块
------------------
`device_info.py` 是**纯只读**采集器（模块开头就写死了「不写任何东西」）。
把写操作混进去会破坏那个契约 ⇒ 单独一个模块，只做写。

这到底是什么
--------------
用户口头说的「ARP 绑定」，在 OpenWrt 上的官方等价物是
**DHCP 静态绑定**（`/etc/config/dhcp` 里的 `config host` 段）：
IP ↔ MAC ↔ 主机名 三元绑定，由 dnsmasq 负责应答主机名。

⚠️ OpenWrt **没有 arpd**（.232 实测：`which arpd` 无输出），
也没有「静态 ARP 项」这种配置。所以本模块做的是前者。

显示名 与 uci 段名 是两回事（.232 实测出来的硬约束）
--------------------------------------------------
`config host` 有两个名字：

| 名字 | 写在哪 | 允许什么 |
|---|---|---|
| **显示名** | `option name` 的值 | 任意文本（可中文、可空格） |
| **段名** | `config host 'xxx'` 的 xxx | **只允许字母数字下划线** |

⚠️ uci **拒绝非 ASCII 段名**：.232 实测
   `uci set dhcp.我的NAS=host` ⇒ `uci: Invalid argument`（rc=1）。
   ⇒ 段名**不能**用用户填的设备名 ⇒ 由 MAC 派生（见 `_section_for_mac()`），
   用户的设备名只写进 `option name`。

⚠️ 显示名里**不能有控制字符**（换行/回车/Tab）：uci 会把它们原样写进
   配置文件（.232 实测：`option name 'a<换行>option evil 1'`）⇒ 会破坏
   逐行解析，也可能被别的工具误读 ⇒ 直接拒。
   单引号不用管 —— uci 自己转义成 `'\''`（.232 实测）。

安全设计（每一条都对应一种真实会出事的情况）
--------------------------------------------
1. **写前文件级备份**。
   ⚠️ uci 的 `revert` **对已提交的内容无效**（.232 实测：
      `uci set` → `commit` → `revert`，那段配置仍在文件里）。
   ⇒ 回滚只能靠**把备份文件拷回去**。

2. **用 uci 写，不用字符串拼接**。
   uci 保留原有格式与注释；手写 `config host` 段落很容易和现有内容打架
   （缩进、段名、引号风格）。

3. **写后校验**：`uci show dhcp` 能解析 ⇒ 语法 OK。
   解析不了 ⇒ 回滚。

4. **失败自动回滚**到备份，并**如实报错**。

5. **权限保持 0600 root**（.232 实测 `/etc/config/dhcp` 就是这个权限）。
   uci commit 会自己保持；这里再核一遍。

6. **改完要重载 dnsmasq 才生效** —— 只写文件不重载，
   用户会以为没生效（或者更糟：以为生效了其实没有）。
   重载失败**不算写失败**（文件是对的），但必须**明确告诉用户**。

7. **整个写操作串行化**（flock，见 `_write_lock()`）。
   面板是多线程的 ⇒ 两个写请求可能同时进来 ⇒ 会丢写、
   备份互相覆盖、uci 的 delta 被串味。
   ⇒ 「查重 → 备份 → 写 → 校验 → 回滚 → 重载」整段在同一把锁里；
   等不到锁就**拒绝写入**（不排队无限等）。

⚠️ 本模块**只在有 uci 命令时**才允许写。
   没有 uci 就只能读 —— 宁可不能改，也不能用字符串拼接去改配置。
"""
import contextlib
import errno
import fcntl
import itertools
import os
import re
import shutil
import subprocess
import time

# ── 路径 ──────────────────────────────────────────────────────
DHCP_CONFIG_PATH = '/etc/config/dhcp'
BACKUP_DIR = '/etc/nftables/backup'
DNSMASQ_INIT = '/etc/init.d/dnsmasq'

# uci 的 set/commit 超时（秒）。uci 正常是毫秒级，
# 但设备磁盘慢或被别的操作占住时可能卡住 ⇒ 必须有界。
_UCI_TIMEOUT = 20


class DhcpWriteError(Exception):
    """写 DHCP 配置失败。

    `rolled_back` 说明**原文件是否已恢复**：
      True  —— 已恢复，设备状态与操作前一致；
      False —— 恢复也失败了（极少见，需要人工介入）。
    """

    def __init__(self, message, rolled_back=True):
        super().__init__(message)
        self.rolled_back = rolled_back


def _uci_available():
    return shutil.which('uci') is not None


def _run_uci(args, config_dir=None):
    """跑 uci，返回 (退出码, stdout+stderr)。

    ⚠️ 用 `-c <dir>` 时 uci 会把**整个目录**当成配置根，
       配置文件名必须与包名一致（`dhcp`）⇒ 调用方要保证目录里有 `dhcp` 文件。
    """
    cmd = ['uci']
    if config_dir:
        cmd += ['-c', config_dir]
    cmd += list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=_UCI_TIMEOUT)
    except subprocess.TimeoutExpired:
        return 124, 'uci 超时（%d 秒）' % _UCI_TIMEOUT
    except OSError as e:
        return 127, 'uci 执行失败: %s' % e
    return r.returncode, (r.stdout or '') + (r.stderr or '')


# 备份序号：同进程内单调递增。
# ⚠️ `next()` 在 CPython 里是原子的（GIL），而调用点又都在写锁内 ⇒ 不会重复。
_backup_seq = itertools.count()

# 写锁的等待上限（秒）与轮询间隔（秒）。
# ⚠️ 为什么是「有上限的等待」而不是无限等：
#    正常情况下第二个写请求只需要等第一个写完（含 dnsmasq 重载，约 1~3 秒）；
#    但如果前一个写操作卡死，无限等会把 HTTP 请求一起吊死。
#    ⇒ 等不到就**拒绝写入**（与 app.py 保存配置同一立场，P1-30）。
_LOCK_WAIT_TIMEOUT = 15.0
_LOCK_POLL_INTERVAL = 0.05

# 锁文件名。放在备份目录里 —— 那是部署脚本保证存在的目录。
_LOCK_FILE_NAME = 'dhcp.lock'

# leasetime（租期）的合法形态：`<数字><单位>` 的组合，或 `infinite`。
# 单位 s/m/h/d = 秒/分/时/天，可以拼多个（如 `2h30m`）。
# ⚠️ 为什么用白名单而不是「只挡控制字符」：
#    uci 会把值**原样**写进配置文件（.232 实测）⇒ 一个带换行的租期
#    就能在配置里插进一整行 option ⇒ 破坏配置、误导 dnsmasq。
#    白名单同时也挡掉了引号、逗号、空白等一切「不该出现在时长里」的字符。
_LEASETIME_RE = re.compile(r'^(infinite|(\d+[smhd])+)$')


def _now():
    """当前时间。

    ⚠️ 单独一个函数 ⇒ 判据可以把它冻结住，
       从而确定性地测「同一时刻的两次备份不会撞名」。
    """
    return time.time()


def _backup_path(tag):
    """备份文件名。

    ⚠️ 必须**唯一**（2026-11-12 补）。
       面板是 `python3 app.py` 起的 ⇒ Flask 内建服务器 **threaded=True**
       ⇒ 两个写请求可以同时进来。
       而名字原本只到**秒** ⇒ 同一秒里的两个写会算出**同一个路径**
       ⇒ 后一个备份把前一个覆盖掉 ⇒ 「写坏之前的那一版」没了。

       ⇒ 名字由三段拼出来：
         · 时间戳 —— 给人看的（哪一天哪一秒的备份）；
         · PID —— 跨进程唯一（两个面板进程不会撞）；
         · 序号 —— 同进程内唯一（**不依赖时钟精度**）。
       ⚠️ 第三段不能用「微秒」凑合：`time.time()` 的分辨率不保证，
         两个线程落在同一微秒完全可能 ⇒ 备份照样会互相覆盖。
         序号是单调计数器 ⇒ 同名**不可能**。
    """
    now = _now()
    ts = time.strftime('%Y%m%d-%H%M%S', time.localtime(now))
    seq = next(_backup_seq)
    return os.path.join(
        BACKUP_DIR, 'dhcp.%s.%d.%d.%s' % (ts, os.getpid(), seq, tag))


@contextlib.contextmanager
def _write_lock():
    """整个写操作的**互斥锁**。

    ⚠️ 为什么必须有（2026-11-12 补）：
       面板是多线程的 ⇒ 两个写请求可能同时进来。
       它们的流程都是「备份 → uci 写 → commit → 校验 → （失败）回滚」，
       交错起来会出两种事：

       1. **丢写**：A 备份（写前状态）→ A 写 → B 写 → A 失败 ⇒ A 回滚
          ⇒ **把 B 刚写进去的记录也抹掉了**；
          而 B 的接口明明回了 200「保存成功」。
       2. **备份互相覆盖**：同一秒的两个写算出同一个备份名。

    ⇒ 用 flock 把「备份 → 写 → 校验 → 回滚」整段串起来。

    ⚠️ 拿不到锁 ⇒ **拒绝写入**（与 app.py 保存配置的同一立场，P1-30）：
       在「明知道并发保护没生效」的情况下继续改共享配置，
       丢的是用户刚加的绑定，而接口都报成功。
       但不是**立即**拒绝 —— 先等一小会儿（前一个写通常几秒就完），
       等不到才拒绝。
    """
    lock_path = os.path.join(BACKUP_DIR, _LOCK_FILE_NAME)
    try:
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    except OSError as e:
        raise DhcpWriteError(
            '无法获取 DHCP 配置写锁（%s），已中止写入（未做任何修改）'
            % (type(e).__name__,))
    try:
        # ⚠️ 用 LOCK_NB 轮询而不是直接阻塞 LOCK_EX：
        #    阻塞版没有上限 ⇒ 锁被占死时 HTTP 请求会一直吊着。
        deadline = time.monotonic() + _LOCK_WAIT_TIMEOUT
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EACCES, errno.EAGAIN):
                    raise DhcpWriteError(
                        '无法获取 DHCP 配置写锁（%s），已中止写入（未做任何修改）'
                        % (type(e).__name__,))
                if time.monotonic() >= deadline:
                    raise DhcpWriteError(
                        '另一个 DHCP 配置写操作正在进行，未能在 %d 秒内获取写锁，'
                        '已中止写入（未做任何修改）' % int(_LOCK_WAIT_TIMEOUT))
                time.sleep(_LOCK_POLL_INTERVAL)
        yield
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)


def _make_backup(tag):
    """备份当前 dhcp 配置，返回备份文件路径。

    备份目录建不出来就**直接失败** —— 没有备份就不许改。
    """
    if not os.path.exists(DHCP_CONFIG_PATH):
        raise DhcpWriteError('没有 %s，无法修改' % DHCP_CONFIG_PATH)
    try:
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    except OSError as e:
        raise DhcpWriteError('备份目录建不出来: %s' % e)
    dst = _backup_path(tag)
    try:
        shutil.copy2(DHCP_CONFIG_PATH, dst)
        os.chmod(dst, 0o600)
    except OSError as e:
        raise DhcpWriteError('备份失败: %s' % e)
    return dst


def _same_file(a, b):
    """两个文件的内容是否一模一样。任一读不了就当「不一样」。

    ⚠️ 为什么要它（2026-11-12 补）：
       回滚时如果**文件根本没被改过**（`uci commit` 失败时就是这样），
       就不该再去拷备份 —— 只读文件系统 / 磁盘满时那次拷贝必然失败
       ⇒ 报「回滚失败，请手工从备份恢复」是**假警报**，
       而用户照着做 = 用一份旧备份覆盖掉本来完好的配置。
    """
    try:
        if os.path.getsize(a) != os.path.getsize(b):
            return False
        with open(a, 'rb') as fa, open(b, 'rb') as fb:
            return fa.read() == fb.read()
    except OSError:
        return False


def _restore(backup):
    """把备份拷回原位。返回是否成功。

    ⚠️ 文件**已经和备份一样**时直接算成功（见 `_same_file` 的说明）：
       那说明它压根没被改过 ⇒ 不用还原，也不用谎报「回滚失败」。
    """
    try:
        if _same_file(backup, DHCP_CONFIG_PATH):
            return True
        shutil.copy2(backup, DHCP_CONFIG_PATH)
        os.chmod(DHCP_CONFIG_PATH, 0o600)
        return True
    except OSError:
        return False


def _discard_pending():
    """丢弃 uci 里**未提交**的变更（delta）。返回 (是否成功, 详情)。

    ⚠️ 为什么必须做（.232 实测 2026-11-12）：
       uci 的 `set` 不立刻改文件，变更先存在 savedir（`/tmp/.uci/dhcp`），
       `commit` 才落盘。⇒ **commit 失败时 delta 还在**
       （.232 实测：失败后 `uci changes dhcp` 仍然列着那一段；
       同理，`uci set` 中途失败时 delta 里也留着前面几次成功的 set）。

       而「回滚」原来只把**文件**拷回去 ⇒ delta 里的变更原封不动
       ⇒ 之后任何一次 `uci commit dhcp`（**包括面板自己的下一次新增**）
       都会把「刚刚报告为已回滚」的那条再写回去
       ⇒ 回滚是假的，设备上出现了用户以为根本不存在的绑定。

    ⇒ 回滚的第一步必须是清 delta，第二步才是还原文件。

    ⚠️ `uci revert dhcp` 丢的是**整个包**的未提交变更。
       我们持着写锁 ⇒ pending 的正常情况下只有本模块自己写的那些。
    ⚠️ 对**已提交**的内容无效（.232 实测）⇒ 所以文件仍然要从备份还原，
       两步缺一不可。
    """
    rc, out = _run_uci(['revert', 'dhcp'])
    return rc == 0, out.strip()


def _check_syntax():
    """校验改完的 dhcp 配置能不能被 uci 解析。

    `uci show dhcp` 解析不了 ⇒ 配置坏了 ⇒ 必须回滚。
    """
    rc, out = _run_uci(['show', 'dhcp'])
    if rc != 0:
        return False, out.strip()
    return True, ''


def _is_ascii_ident(s):
    """uci 的段名规则：只允许 ASCII 字母、数字、下划线。

    ⚠️ **不能**用 `str.isalnum()` —— 它按 Unicode 分类，
       中文是「字母」⇒ `'中文'.isalnum()` 是 True
       ⇒ 中文段名会通过校验，而真 uci 拒绝（.232 实测：Invalid argument）。
    """
    return all(('a' <= c <= 'z') or ('A' <= c <= 'Z') or
               ('0' <= c <= '9') or c == '_' for c in s)


def _is_ascii_digits(s):
    """只认 ASCII 数字。

    ⚠️ **不能**用 `str.isdigit()` —— `'²'.isdigit()` 是 True，
       但 `int('²')` 抛 ValueError ⇒ 未捕获异常 ⇒ 接口 500。
       `'٣'.isdigit()` 也是 True（阿拉伯数字），`int('٣')` 却是 3
       ⇒ 非法的 IP 能被当成合法值写进配置。
    """
    return bool(s) and all('0' <= c <= '9' for c in s)


def _validate_host(name, mac, ip):
    """校验一条静态绑定。返回 (ok, 错误说明)。

    校验放在**写之前** —— 写坏了再回滚比根本不写危险得多。

    ⚠️ `name` 是**显示名**（写进 `option name`），不是 uci 段名：
       uci 的段名只允许 ASCII（.232 实测中文段名被拒）
       ⇒ 段名由 MAC 派生，见 `_section_for_mac()`。
       显示名允许中文、空格（.232 实测 uci 会原样保留）。
    """
    name = str(name or '').strip()
    mac = str(mac or '').strip().lower()
    ip = str(ip or '').strip()

    if not name:
        return False, '设备名不能为空'
    if len(name) > 63:
        return False, '设备名太长（最多 63 个字符）'
    # 控制字符会破坏 uci 配置文件（uci 会原样写进去，.232 实测）
    # ⇒ 换行/回车/Tab 一律拒。空格、中文、标点都允许。
    bad = [c for c in name if ord(c) < 0x20 or ord(c) == 0x7f]
    if bad:
        return False, '设备名不能包含换行、制表符等控制字符'

    if not mac:
        return False, 'MAC 地址不能为空'
    mac_parts = mac.split(':')
    if len(mac_parts) != 6 or not all(
            len(p) == 2 and all(c in '0123456789abcdef' for c in p)
            for p in mac_parts):
        return False, 'MAC 地址格式不对（应为 aa:bb:cc:dd:ee:ff）'

    if not ip:
        return False, 'IP 地址不能为空'
    parts = ip.split('.')
    if len(parts) != 4:
        return False, 'IP 地址格式不对（应为点分十进制）'
    for p in parts:
        if not _is_ascii_digits(p) or not (0 <= int(p) <= 255):
            return False, 'IP 地址格式不对（应为点分十进制）'

    return True, ''


def _validate_leasetime(leasetime):
    """校验租期（leasetime）。返回 (ok, 错误说明)。

    ⚠️ 为什么必须校验（.232 实测）：
       uci 会把值里的换行**原样**写进配置文件 ⇒ 一个带换行的租期
       就能在配置里插进一整行 option ⇒ 破坏配置、误导 dnsmasq。
       `name` 早有控制字符检查，租期之前漏了 ⇒ 一个纯攻击面。

    ⚠️ 空白（空串）是允许的 —— 那表示「不写 leasetime 选项」。

    ⚠️ **校验的就是要写进 uci 的那个值**（不 strip）：
       之前 strip 之后再校验 ⇒ 校验通过的是 '12h'，
       而写进 uci 的仍是带 \\r / \\t 的原值 ⇒ 两者不是同一个字符串
       ⇒ 控制字符照样进了配置文件（2026-11-12 实测发现）。
    """
    s = str(leasetime or '')
    if not s:
        return True, ''
    if len(s) > 32:
        return False, '租期太长（最多 32 个字符）'
    if not _LEASETIME_RE.match(s):
        return False, ('租期格式不对（应为 12h / 30m / 2h30m 这样的'
                       '数字+单位，或 infinite）')
    return True, ''


def _section_for_mac(mac):
    """由 MAC 派生 uci 段名。

    为什么不能用用户填的设备名当段名：
      uci 的段名只允许字母数字下划线，**非 ASCII 直接被拒**
      （.232 实测 `uci set dhcp.我的NAS=host` ⇒ `uci: Invalid argument`）。

    用 MAC 派生的好处：
      · 天生满足字符要求（十六进制 + 下划线）；
      · 天生唯一 —— 而同 MAC 重复绑定本来就要拦
        （见 `_host_with_same`）；
      · 段名稳定 —— 以后改显示名不会改段名，删除时不会找不到。

    返回形如 `host_aabbccddeeff`。
    """
    hexs = ''.join(c for c in str(mac).strip().lower()
                   if c in '0123456789abcdef')
    return 'host_' + hexs


def _section_type(section):
    """段类型。返回类型字符串（如 `host` / `dhcp`），段不存在返回 None。

    ⚠️ `uci get dhcp.<段>` 返回的是**段类型**，不是选项值（.232 实测：
       `uci get dhcp.lan` ⇒ `dhcp`，`uci get dhcp.odhcpd` ⇒ `odhcpd`，
       不存在的段 ⇒ rc=1 + `Entry not found`）。
    """
    rc, out = _run_uci(['get', 'dhcp.%s' % section])
    if rc != 0:
        return None
    t = out.strip()
    return t or None


def _section_exists(section):
    return _section_type(section) is not None


def _host_with_same(key, value, exclude_section=None):
    """找出已经绑了同一个 `key`（`mac` 或 `ip`）的段（排除指定段）。

    ⚠️ 同 MAC 绑到两个 IP ⇒ dnsmasq 行为未定义（通常是后者生效），
    用户会看到「绑了却没生效」⇒ 写之前就要拦。
    ⚠️ 同 IP 绑到两个 MAC ⇒ 同样只有一个能生效 ⇒ 也要拦。
    """
    rc, out = _run_uci(['show', 'dhcp'])
    if rc != 0:
        return None
    cur_section = None
    for ln in out.splitlines():
        s = ln.strip()
        if s.startswith('dhcp.') and s.endswith('=host'):
            cur_section = s.split('.', 1)[1].split('=', 1)[0]
            continue
        if cur_section is None:
            continue
        if '.%s=' % key in s:
            cur_val = s.split('=', 1)[1].strip().strip("'\"")
            # MAC 大小写不敏感 —— 手写的配置可能带大写
            if cur_val.lower() == value.lower() and cur_section != exclude_section:
                return cur_section
    return None


def add_dhcp_host(name, mac, ip, leasetime='12h'):
    """新增一条静态绑定。返回 {'section', 'name', 'mac', 'ip', 'leasetime'}。

    流程：校验 → 查重 → 备份 → uci set → commit → 校验语法 → 重载 dnsmasq。
    任何一步失败都**回滚**并抛 DhcpWriteError。

    ⚠️ `name` 是**显示名**（可中文），写进 `option name`；
       uci 段名由 MAC 派生（`_section_for_mac()`）——
       uci 不接受非 ASCII 段名（.232 实测）。
    """
    if not _uci_available():
        raise DhcpWriteError('设备上没有 uci 命令，无法修改 DHCP 配置')
    ok, why = _validate_host(name, mac, ip)
    if not ok:
        raise DhcpWriteError(why)
    ok, why = _validate_leasetime(leasetime)
    if not ok:
        raise DhcpWriteError(why)

    name = str(name).strip()
    mac = str(mac).strip().lower()
    ip = str(ip).strip()
    section = _section_for_mac(mac)

    # ⚠️ 从**查重**到**重载**，整段都在写锁内。
    #    查重也必须在锁内 —— 否则两个并发请求都查到「没绑过」，
    #    然后都去写 ⇒ 同一条绑定写两遍、后者把前者盖掉。
    with _write_lock():
        if _section_exists(section):
            raise DhcpWriteError('这个 MAC 已经绑过了（配置段 %s 已存在）' % section)

        dup = _host_with_same('mac', mac)
        if dup:
            raise DhcpWriteError('MAC %s 已经绑在「%s」上了，不能绑两次' % (mac, dup))

        # ⚠️ 同 IP 绑两个 MAC ⇒ dnsmasq 只会认其中一个
        #    ⇒ 用户看到「绑了却没生效」⇒ 同样要在写之前拦。
        dup_ip = _host_with_same('ip', ip)
        if dup_ip:
            raise DhcpWriteError('IP %s 已经绑在「%s」上了，不能绑两次' % (ip, dup_ip))

        backup = _make_backup('add')
        try:
            rc, out = _run_uci(['set', 'dhcp.%s=host' % section])
            if rc != 0:
                raise DhcpWriteError('uci set 失败: %s' % out.strip())
            for key, val in (('name', name), ('mac', mac), ('ip', ip)):
                rc, out = _run_uci(['set', 'dhcp.%s.%s=%s' % (section, key, val)])
                if rc != 0:
                    raise DhcpWriteError('uci set %s 失败: %s' % (key, out.strip()))
            if leasetime:
                rc, out = _run_uci(['set', 'dhcp.%s.leasetime=%s' % (section, leasetime)])
                if rc != 0:
                    raise DhcpWriteError('uci set leasetime 失败: %s' % out.strip())

            rc, out = _run_uci(['commit', 'dhcp'])
            if rc != 0:
                raise DhcpWriteError('uci commit 失败: %s' % out.strip())

            ok, detail = _check_syntax()
            if not ok:
                raise DhcpWriteError('改完的配置解析不了（已回滚）: %s' % detail)
        except DhcpWriteError as e:
            # ⚠️ 回滚**第一步**：清掉 uci 的未提交变更。
            #    只还原文件是不够的 —— 残留的 delta 会被下一次 commit 写回去
            #    ⇒ 那时「已回滚」就是个谎言（.232 实测，详见 _discard_pending）。
            pending_ok, pend_detail = _discard_pending()
            rolled = _restore(backup)
            if not rolled:
                raise DhcpWriteError('%s；**且回滚失败**，请手工从 %s 恢复'
                                     % (e, backup), rolled_back=False)
            if not pending_ok:
                # 文件回来了，但 uci 里可能还留着未提交变更
                # ⇒ 设备状态**不保证**与操作前一致 ⇒ 如实上报。
                raise DhcpWriteError(
                    '%s（文件已回滚，但 uci 的未提交变更未能清除：%s）'
                    % (e, pend_detail), rolled_back=False)
            raise DhcpWriteError('%s（已回滚）' % e, rolled_back=True)

        # ⚠️ 重载也放在锁内 —— 两个写请求各自 restart 一次 dnsmasq，
        #    两个 restart 撞在一起可能把 dnsmasq 停在那儿起不来。
        reload_result = reload_dnsmasq()

    return {
        'section': section,
        'name': name,
        'mac': mac,
        'ip': ip,
        'leasetime': leasetime or '',
        'reload': reload_result,
    }


def delete_dhcp_host(section):
    """删除一条静态绑定。返回 {'section', 'reload'}。"""
    if not _uci_available():
        raise DhcpWriteError('设备上没有 uci 命令，无法修改 DHCP 配置')
    section = str(section or '').strip()
    if not section:
        raise DhcpWriteError('没说要删哪一条')
    # 段名只允许字母数字下划线 —— uci 的段名规则（.232 实测非 ASCII 被拒）。
    # ⚠️ 这一条同时挡住了「删掉匿名段」和「往 uci 参数里塞别的表达式」：
    #    `dhcp.@host[0]` 这种索引写法不满足这里的规则 ⇒ 删不掉。
    if not _is_ascii_ident(section):
        raise DhcpWriteError('绑定标识不合法')

    # ⚠️ 存在性检查与删除整段都在写锁内 —— 与新增同理，
    #    否则「查得到」与「删得掉」之间可能插进另一个写请求。
    with _write_lock():
        # ⚠️ **必须确认段类型是 host** ——
        #    `_is_ascii_ident` 只挡得住段名的**形态**，挡不住段**是什么**。
        #    OpenWrt 默认的 `/etc/config/dhcp` 里就有**有名字**的段：
        #    `config dhcp 'lan'` / `config odhcpd 'odhcpd'` ——
        #    它们同样满足 ASCII 标识 ⇒ 只查形态就能把
        #    **LAN 的 DHCP 服务配置**删掉 ⇒ dnsmasq 重载后路由器不再发 IPv4。
        #    （.232 实测：`uci get dhcp.lan` ⇒ `dhcp`，`uci get dhcp.odhcpd` ⇒ `odhcpd`）
        stype = _section_type(section)
        if stype is None:
            raise DhcpWriteError('没有名为「%s」的绑定' % section)
        if stype != 'host':
            raise DhcpWriteError(
                '「%s」不是 DHCP 静态绑定（段类型是 %s），不删'
                % (section, stype))

        backup = _make_backup('del')
        try:
            rc, out = _run_uci(['delete', 'dhcp.%s' % section])
            if rc != 0:
                raise DhcpWriteError('uci delete 失败: %s' % out.strip())
            rc, out = _run_uci(['commit', 'dhcp'])
            if rc != 0:
                raise DhcpWriteError('uci commit 失败: %s' % out.strip())
            ok, detail = _check_syntax()
            if not ok:
                raise DhcpWriteError('改完的配置解析不了（已回滚）: %s' % detail)
        except DhcpWriteError as e:
            # ⚠️ 回滚**第一步**：清掉 uci 的未提交变更（理由同新增）。
            pending_ok, pend_detail = _discard_pending()
            rolled = _restore(backup)
            if not rolled:
                raise DhcpWriteError('%s；**且回滚失败**，请手工从 %s 恢复'
                                     % (e, backup), rolled_back=False)
            if not pending_ok:
                raise DhcpWriteError(
                    '%s（文件已回滚，但 uci 的未提交变更未能清除：%s）'
                    % (e, pend_detail), rolled_back=False)
            raise DhcpWriteError('%s（已回滚）' % e, rolled_back=True)

        # ⚠️ 重载也在锁内（理由同新增）。
        reload_result = reload_dnsmasq()

    return {'section': section, 'reload': reload_result}


def reload_dnsmasq():
    """重载 dnsmasq，让新的静态绑定生效。

    返回 {'ok': bool, 'message': str}。

    ⚠️ 重载失败**不算写失败** —— 配置文件是对的，只是 dnsmasq 还没换。
    ⇒ 必须**如实告诉用户**「绑定已写入，但要重载才生效」，
    而不是假装成功或假装失败。
    """
    if not os.path.exists(DNSMASQ_INIT):
        return {'ok': False, 'message': '设备上没有 dnsmasq 服务，绑定已写入但未生效'}
    try:
        r = subprocess.run([DNSMASQ_INIT, 'restart'],
                           capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'message': '重载 dnsmasq 超时，绑定已写入但可能未生效'}
    except OSError as e:
        return {'ok': False, 'message': '重载 dnsmasq 失败: %s（绑定已写入）' % e}
    if r.returncode != 0:
        return {'ok': False,
                'message': '重载 dnsmasq 返回非零（绑定已写入，可能未生效）'}
    return {'ok': True, 'message': 'dnsmasq 已重载，绑定生效'}
