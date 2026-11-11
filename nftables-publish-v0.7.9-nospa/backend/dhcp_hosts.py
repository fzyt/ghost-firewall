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

⚠️ 本模块**只在有 uci 命令时**才允许写。
   没有 uci 就只能读 —— 宁可不能改，也不能用字符串拼接去改配置。
"""
import os
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


def _backup_path(tag):
    ts = time.strftime('%Y%m%d-%H%M%S')
    return os.path.join(BACKUP_DIR, 'dhcp.%s.%s' % (ts, tag))


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


def _restore(backup):
    """把备份拷回原位。返回是否成功。"""
    try:
        shutil.copy2(backup, DHCP_CONFIG_PATH)
        os.chmod(DHCP_CONFIG_PATH, 0o600)
        return True
    except OSError:
        return False


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


def _section_for_mac(mac):
    """由 MAC 派生 uci 段名。

    为什么不能用用户填的设备名当段名：
      uci 的段名只允许字母数字下划线，**非 ASCII 直接被拒**
      （.232 实测 `uci set dhcp.我的NAS=host` ⇒ `uci: Invalid argument`）。

    用 MAC 派生的好处：
      · 天生满足字符要求（十六进制 + 下划线）；
      · 天生唯一 —— 而同 MAC 重复绑定本来就要拦
        （见 `_host_with_same_mac`）；
      · 段名稳定 —— 以后改显示名不会改段名，删除时不会找不到。

    返回形如 `host_aabbccddeeff`。
    """
    hexs = ''.join(c for c in str(mac).strip().lower()
                   if c in '0123456789abcdef')
    return 'host_' + hexs


def _section_exists(section):
    rc, out = _run_uci(['get', 'dhcp.%s' % section])
    return rc == 0 and out.strip() != ''


def _host_with_same_mac(mac, exclude_section=None):
    """找出已经绑了同一个 MAC 的段（排除指定段）。

    ⚠️ 同 MAC 绑到两个 IP ⇒ dnsmasq 行为未定义（通常是后者生效），
    用户会看到「绑了却没生效」⇒ 写之前就要拦。
    """
    rc, out = _run_uci(['show', 'dhcp'])
    if rc != 0:
        return None
    cur_section = None
    cur_mac = None
    for ln in out.splitlines():
        s = ln.strip()
        if s.startswith('dhcp.') and s.endswith('=host'):
            cur_section = s.split('.', 1)[1].split('=', 1)[0]
            cur_mac = None
            continue
        if cur_section is None:
            continue
        if '.mac=' in s:
            cur_mac = s.split('=', 1)[1].strip().strip("'\"")
            # MAC 大小写不敏感 —— 手写的配置可能带大写
            if cur_mac.lower() == mac.lower() and cur_section != exclude_section:
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

    name = str(name).strip()
    mac = str(mac).strip().lower()
    ip = str(ip).strip()
    section = _section_for_mac(mac)

    if _section_exists(section):
        raise DhcpWriteError('这个 MAC 已经绑过了（配置段 %s 已存在）' % section)

    dup = _host_with_same_mac(mac)
    if dup:
        raise DhcpWriteError('MAC %s 已经绑在「%s」上了，不能绑两次' % (mac, dup))

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
        rolled = _restore(backup)
        if not rolled:
            raise DhcpWriteError('%s；**且回滚失败**，请手工从 %s 恢复'
                                 % (e, backup), rolled_back=False)
        raise DhcpWriteError('%s（已回滚）' % e, rolled_back=True)

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

    if not _section_exists(section):
        raise DhcpWriteError('没有名为「%s」的绑定' % section)

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
        rolled = _restore(backup)
        if not rolled:
            raise DhcpWriteError('%s；**且回滚失败**，请手工从 %s 恢复'
                                 % (e, backup), rolled_back=False)
        raise DhcpWriteError('%s（已回滚）' % e, rolled_back=True)

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
