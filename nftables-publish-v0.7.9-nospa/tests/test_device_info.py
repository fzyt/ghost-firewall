#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备信息采集器（backend/device_info.py）的测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_device_info.py

测什么有效
----------
这个采集器的每一处解析都踩过坑，而且坑的共同点是：
**在开发机上看着是对的，装到设备上就静默返回空**。

所以测试不是「断言本机采集到了什么」，而是**拿构造出来的 proc 文本喂进去**，
断言解析结果 —— 这样每个坑都有对应的回归。

本轮实际踩到并修掉的五个坑
--------------------------
  1. `/proc/net/route` 的地址是**小端**字节序（`0064A8C0` = 192.168.100.0）。
     按大端解析 ⇒ 网段变成 `0.100.168.192/24` ⇒ IPv4 一个都匹配不上。
  2. 掩码解析不能把点分十进制当二进制串去 `int(..., 2)` ——
     `int('2552552550', 2)` 直接抛 ValueError。
  3. `/proc/net/fib_trie` 里地址行与 `/32 host LOCAL` 是**两行**，
     地址在上面那行。按「host LOCAL 行自己就是地址」去 split ⇒ body 是空串。
  4. `Main:` 是 `/proc/net/fib_trie` 的**第一行**，不是中间的分节。
     按「先找 Main: 再往下读」写 ⇒ 永远进不去 Main 表。
  5. `/proc/net/if_inet6` 的**第 4 列是 scope，不是 flags**（2026-11-09 真机实测）。
     把 scope 当 flags 读 ⇒ 链路本地地址（scope=0x20）被当成「临时地址」丢弃
     ⇒ 面板上 IPv6 一栏永远空。临时地址的位是 **0x01**，0x20 是「已弃用」。

沙箱：不读真设备的 proc 文件（用假的文本喂），也不碰网络。
"""
import os
import sys
import traceback
import unittest

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

import device_info  # noqa: E402


# ── 构造的 proc 文本（取自真实 Linux 的格式）──────────────────

ROUTE_TEXT = """\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
ens18\t00000000\t0164A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
ens18\t0064A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
br-lan\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
"""

FIB_TRIE_TEXT = """\
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
  +-- 127.0.0.0/8 2 0 2
     +-- 127.0.0.0/31 1 0 0
        |-- 127.0.0.0
           /8 host LOCAL
        |-- 127.0.0.1
           /32 host LOCAL
  +-- 192.168.100.0/24 2 0 2
     |-- 192.168.100.0
        /24 link UNICAST
     +-- 192.168.100.248/29 2 0 2
        |-- 192.168.100.249
           /32 host LOCAL
        |-- 192.168.100.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
"""

IF_INET6_TEXT = """\
fda768ee7b990000be2411fffef80e48 02 40 00 00    ens18
240e039048c424c0be2411fffef80e48 02 40 00 00    ens18
fe80000000000000be2411fffef80e48 02 40 20 80    ens18
00000000000000000000000000000001 01 80 10 80       lo
"""

# flags 列 = 0x01 ⇒ IFA_F_TEMPORARY（RFC 4941 隐私地址）⇒ 不展示
IF_INET6_TEXT_WITH_TEMP = IF_INET6_TEXT + \
    "240e039048c424c0be2411fffef80e49 02 40 00 01    ens18\n"

# flags 列 = 0x20 ⇒ IFA_F_DEPRECATED（已弃用）⇒ **不是**临时地址 ⇒ 要展示
IF_INET6_TEXT_WITH_DEPRECATED = IF_INET6_TEXT + \
    "240e039048c424c0be2411fffef80e4a 02 40 00 20    ens18\n"


class TestHexConversion(unittest.TestCase):
    """小端字节序 —— 坑 1。"""

    def test_route_address_is_little_endian(self):
        # /proc/net/route 里 0064A8C0 = 192.168.100.0
        self.assertEqual(device_info.socket_inet_ntoa('0064A8C0', little=True),
                         '192.168.100.0')

    def test_big_endian_is_different(self):
        # 同一个字符串按大端解析是 0.100.168.192 —— 必须不一样，
        # 否则就说明小端这个参数根本没生效
        self.assertEqual(device_info.socket_inet_ntoa('0064A8C0'),
                         '0.100.168.192')

    def test_cidr_prefix_length(self):
        # 掩码 00FFFFFF = 255.255.255.0 = /24
        self.assertEqual(device_info._hex_to_ipv4_cidr('0064A8C0', '00FFFFFF'),
                         '192.168.100.0/24')

    def test_mask_is_not_parsed_as_binary_string(self):
        # 坑 2：int('2552552550', 2) 会抛 ValueError
        net = device_info._hex_to_ipv4_cidr('0064A8C0', '00FFFFFF')
        self.assertTrue(net.endswith('/24'))

    def test_non_contiguous_mask_rejected(self):
        # 掩码必须是连续高位 1，否则前缀长度算出来是错的。
        # 00FF00FF 小端后是 255.0.255.0 —— 每一组都合法，
        # 但整体不连续 ⇒ 必须拒绝（只看「每组合不合法」会漏掉这种）。
        with self.assertRaises(ValueError):
            device_info._hex_to_ipv4_cidr('0064A8C0', '00FF00FF')


class TestIPv4ByIface(unittest.TestCase):
    """fib_trie 解析 —— 坑 3、坑 4。"""

    def _patch(self, route_text, trie_text):
        orig = device_info._read_text
        table = {
            '/proc/net/route': route_text,
            '/proc/net/fib_trie': trie_text,
        }

        def fake(path, limit=200000):
            if path in table:
                return table[path]
            return orig(path, limit)
        return fake, orig

    def test_finds_local_address_on_interface(self):
        fake, orig = self._patch(ROUTE_TEXT, FIB_TRIE_TEXT)
        device_info._read_text = fake
        try:
            out = device_info._ipv4_by_iface()
        finally:
            device_info._read_text = orig
        self.assertIn('ens18', out)
        self.assertIn('192.168.100.249', out['ens18'])
        # 127.0.0.1 属于 lo，不该被挂到 ens18 上
        self.assertNotIn('127.0.0.1', out.get('ens18', []))

    def test_main_is_first_line(self):
        """坑 4：Main: 在第一行。若实现要求先找到 Main: 就会漏掉全部。"""
        self.assertTrue(FIB_TRIE_TEXT.startswith('Main:'))
        fake, orig = self._patch(ROUTE_TEXT, FIB_TRIE_TEXT)
        device_info._read_text = fake
        try:
            out = device_info._ipv4_by_iface()
        finally:
            device_info._read_text = orig
        self.assertTrue(out, 'fib_trie 第一行就是 Main: 时也要能采到地址')

    def test_address_line_is_separate_from_host_local_line(self):
        """坑 3：地址行与 /32 host LOCAL 是两行。"""
        lines = FIB_TRIE_TEXT.splitlines()
        addr_line = [l for l in lines if '192.168.100.249' in l]
        self.assertTrue(addr_line)
        self.assertNotIn('host LOCAL', addr_line[0])

    def test_falls_back_when_fib_trie_missing(self):
        """`/proc/net/fib_trie` 依赖内核 CONFIG_FIB_TRIES，OpenWrt 上不一定开。

        缺了不能就此显示「未知」—— 必须退到 `getifaddrs`（libc 标准函数，
        musl 也有）。这个用例在**本机**跑：fib_trie 读不到时，
        仍应能从 getifaddrs 拿到本机的 IPv4。
        """
        orig = device_info._read_text
        device_info._read_text = lambda path, limit=200000: (
            None if path == '/proc/net/fib_trie' else orig(path, limit))
        try:
            out = device_info._ipv4_by_iface()
        finally:
            device_info._read_text = orig
        self.assertTrue(out, 'fib_trie 不可用时必须退到 getifaddrs')
        addrs = [a for v in out.values() for a in v]
        self.assertTrue(addrs, '兜底路径也要采到地址')
        # 采到的必须是合法 IPv4（点分十进制四段）
        for a in addrs:
            parts = a.split('.')
            self.assertEqual(len(parts), 4, '不是合法 IPv4: %r' % a)
            for p in parts:
                self.assertTrue(p.isdigit() and 0 <= int(p) <= 255,
                                '不是合法 IPv4: %r' % a)


class TestIPv6ByIface(unittest.TestCase):
    """`/proc/net/if_inet6` 解析。

    ⚠️ 2026-11-09 真机实测（.232）又抓到一个坑，列的**位置**搞错了：

    `/proc/net/if_inet6` 的六列是「地址 / ifindex / 前缀长度 / **scope** /
    **flags** / 接口名」（Linux v6.12 `net/ipv6/addrconf.c` 的 `if6_seq_show`）。
    原来把第 4 列（scope）当 flags 读 ⇒ 链路本地地址的 scope=0x20
    （RT_SCOPE_LINK）命中「临时地址」判断 ⇒ fe80:: 被整条丢弃
    ⇒ 面板上 IPv6 一栏永远空。

    临时/隐私地址的位是 **0x01**（IFA_F_TEMPORARY）；0x20 是「已弃用」。
    """

    def _collect(self, text):
        orig = device_info._read_text
        device_info._read_text = lambda path, limit=200000: (
            text if path == '/proc/net/if_inet6' else orig(path, limit))
        try:
            return device_info._ipv6_by_iface()
        finally:
            device_info._read_text = orig

    def test_parses_and_groups_by_iface(self):
        out = self._collect(IF_INET6_TEXT)
        self.assertIn('ens18', out)
        # 用 inet_ntop 的实际格式断言：单个 0 组不会被省略成 ::
        # （'fda7:68ee:7b99:0:...' 而非 'fda7:68ee:7b99::...'）
        self.assertIn('fda7:68ee:7b99:0:be24:11ff:fef8:e48', out['ens18'])
        self.assertIn('lo', out)

    def test_link_local_address_is_shown(self):
        """链路本地地址（fe80::）**必须**展示。

        它是这个接口上真实存在的地址，藏起来等于告诉用户「这机器没有 IPv6」。
        真机 .232 上 br-lan 就只有这一个 IPv6（`fe80::be24:11ff:fe48:325b`），
        藏掉它 ⇒ 面板的 IPv6 一栏永远是空的。
        """
        out = self._collect(IF_INET6_TEXT)
        self.assertIn('fe80::be24:11ff:fef8:e48', out['ens18'])

    def test_scope_column_is_not_mistaken_for_flags(self):
        """scope=0x20（链路本地）不是「临时地址」标志 ⇒ 不能因此丢地址。"""
        out = self._collect(IF_INET6_TEXT)
        # 同一行里 scope=0x20 / flags=0x80 ⇒ 地址必须在
        self.assertEqual(len(out['ens18']), 3)

    def test_temporary_address_excluded(self):
        """flags=0x01（IFA_F_TEMPORARY，隐私地址）不展示。"""
        out = self._collect(IF_INET6_TEXT_WITH_TEMP)
        for addrs in out.values():
            self.assertNotIn('240e:390:48c4:24c0:be24:11ff:fef8:e49', addrs)

    def test_deprecated_address_is_not_temporary(self):
        """flags=0x20 是 IFA_F_DEPRECATED（已弃用），**不是**临时地址 ⇒ 要展示。

        这条专门盯「临时位用错」的退化：0x20 一旦被当成临时位，
        已弃用的地址就会被丢掉；反过来真正的隐私地址（0x01）会漏出来。
        """
        out = self._collect(IF_INET6_TEXT_WITH_DEPRECATED)
        self.assertIn('240e:390:48c4:24c0:be24:11ff:fef8:e4a', out['ens18'])
        self.assertEqual(len(out['ens18']), 4)


class TestCollectAllNeverRaises(unittest.TestCase):
    """采集器不许把请求打挂。"""

    def test_missing_files_gives_none_not_exception(self):
        orig = device_info._read_text
        device_info._read_text = lambda path, limit=200000: None
        try:
            d = device_info.collect_all()
        finally:
            device_info._read_text = orig
        self.assertIsNone(d['os']['pretty_name'])
        self.assertIsNone(d['cpu']['model'])
        self.assertIsNone(d['memory']['total_kb'])
        self.assertIsNone(d['uptime_seconds'])
        self.assertEqual(d['interfaces'], [])

    def test_garbage_input_does_not_raise(self):
        """喂垃圾数据也不能抛 —— 采集器崩了页面就 500 了。"""
        orig = device_info._read_text
        device_info._read_text = lambda path, limit=200000: 'x' * 1000
        try:
            d = device_info.collect_all()
        finally:
            device_info._read_text = orig
        self.assertIsInstance(d, dict)


class TestLiveCollect(unittest.TestCase):
    """在本机实跑一次：确认真数据能采到（不是测内容，是测「不空」）。"""

    def test_collect_all_returns_structure(self):
        d = device_info.collect_all()
        for key in ('model', 'os', 'cpu', 'memory', 'storage',
                    'uptime_seconds', 'interfaces'):
            self.assertIn(key, d)
        self.assertIn('pretty_name', d['os'])
        self.assertIsInstance(d['interfaces'], list)


# ── 假的文件系统 ──────────────────────────────────────────────
#
# 这轮新增的采集（sysfs 属性、两次采样速率、设备侧服务、包清单）
# 全都依赖「读某个具体路径」—— 真机上路径和本机不一样
# （本机是 ens18，设备上是 eth0/eth1/br-lan），
# 所以必须能**把路径换成假的**，否则测试只能跑到本机的真实布局上，
# 换台机器就失效。
#
# 覆盖的入口：_read_text（文件内容）、os.readlink（符号链接）、
# os.listdir（目录内容）、os.path.isfile / islink / isdir。


class _FakeFs:
    """把采集器的文件系统访问换成一组假的；退出 with 时全部还原。"""

    def __init__(self, files=None, links=None, dirs=None,
                 isfiles=(), islinks=(), isdirs=()):
        self.files = files or {}
        self.links = links or {}
        self.dirs = dirs or {}
        self.isfiles = set(isfiles)
        self.islinks = set(islinks)
        self.isdirs = set(isdirs)
        self._orig = {}

    def __enter__(self):
        self._orig['read_text'] = device_info._read_text
        self._orig['readlink'] = os.readlink
        self._orig['listdir'] = os.listdir
        self._orig['isfile'] = os.path.isfile
        self._orig['islink'] = os.path.islink
        self._orig['isdir'] = os.path.isdir

        def fake_read_text(path, limit=200000):
            return self.files.get(path)

        def fake_readlink(path):
            if path in self.links:
                return self.links[path]
            raise OSError('no such link: %s' % path)

        def fake_listdir(path):
            if path in self.dirs:
                return list(self.dirs[path])
            raise OSError('no such dir: %s' % path)

        device_info._read_text = fake_read_text
        os.readlink = fake_readlink
        os.listdir = fake_listdir
        os.path.isfile = lambda p: p in self.isfiles
        os.path.islink = lambda p: p in self.islinks
        os.path.isdir = lambda p: p in self.isdirs
        return self

    def __exit__(self, *exc):
        device_info._read_text = self._orig['read_text']
        os.readlink = self._orig['readlink']
        os.listdir = self._orig['listdir']
        os.path.isfile = self._orig['isfile']
        os.path.islink = self._orig['islink']
        os.path.isdir = self._orig['isdir']
        return False


# ── 构造的 /proc/net/dev 文本 ─────────────────────────────────
#
# 取自真机 .232 的真实格式（2026-11-10）。
# eth0 那一行的 16 个数字**故意各不相同**（1..12），
# 这样「哪一列接到了哪个字段」错一位就立刻暴露。
NET_DEV_TEXT = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   27964     294    0    0    0     0          0         0    27964     294    0    0    0     0       0          0
  eth0: 8455698   78543    1    2    3     4          5         6  7341506   12234    7    8    9    10      11         12
  eth1:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
br-lan: 7349620   78367    0    0    0     0          0      5605  7336646   12222    0    0    0     0       0          0
"""


class TestParseNetDev(unittest.TestCase):
    """`/proc/net/dev` 的 16 列解析。

    ⚠️ 收发两段**不能按列名取**：收的第 6 列是 frame，发的第 6 列是 colls，
    而且发段还多一个 carrier ⇒ 只能按下标。
    """

    def test_every_column_maps_to_the_right_field(self):
        row = device_info._parse_net_dev(NET_DEV_TEXT)['eth0']
        self.assertEqual(row['rx_bytes'], 8455698)
        self.assertEqual(row['rx_packets'], 78543)
        self.assertEqual(row['rx_errs'], 1)
        self.assertEqual(row['rx_drop'], 2)
        self.assertEqual(row['rx_fifo'], 3)
        self.assertEqual(row['rx_frame'], 4)
        self.assertEqual(row['rx_compressed'], 5)
        self.assertEqual(row['rx_multicast'], 6)
        self.assertEqual(row['tx_bytes'], 7341506)
        self.assertEqual(row['tx_packets'], 12234)
        self.assertEqual(row['tx_errs'], 7)
        self.assertEqual(row['tx_drop'], 8)
        self.assertEqual(row['tx_fifo'], 9)
        self.assertEqual(row['tx_colls'], 10)
        self.assertEqual(row['tx_carrier'], 11)
        self.assertEqual(row['tx_compressed'], 12)

    def test_header_lines_are_not_interfaces(self):
        out = device_info._parse_net_dev(NET_DEV_TEXT)
        self.assertNotIn('face', out)
        self.assertNotIn('Inter-|', out)
        self.assertEqual(len(out), 4)

    def test_line_with_too_few_columns_is_skipped(self):
        """列数不够 16 的行是格式不对，不是数据 ⇒ 整行跳过。

        样本刻意用 **10 个**字段（不是 2 个）：只有 2 个的话，
        把下限从 16 降到 8 照样会被跳过 ⇒ 这种样本测不出下限是多少。
        """
        out = device_info._parse_net_dev(
            NET_DEV_TEXT + '  eth2: 100 200 300 400 500 600 700 800 900 1000\n')
        self.assertNotIn('eth2', out)

    def test_one_bad_column_does_not_lose_the_whole_interface(self):
        """一列不是数字，不该把整个接口丢掉 —— 那会让「有地址没流量」变成「没这个接口」。"""
        txt = NET_DEV_TEXT.replace('8455698', 'abc')
        out = device_info._parse_net_dev(txt)
        self.assertIn('eth0', out)
        self.assertIsNone(out['eth0']['rx_bytes'])
        self.assertEqual(out['eth0']['rx_packets'], 78543)

    def test_empty_text(self):
        self.assertEqual(device_info._parse_net_dev(''), {})
        self.assertEqual(device_info._parse_net_dev(None), {})


class TestIfaceSysfs(unittest.TestCase):
    """`/sys/class/net/<名字>/` 的属性采集。

    三个坑（真机 .232 实测）：
      1. `master` 是指向**目录**的符号链接 ⇒ `cat` 会报 "Is a directory"，
         必须 readlink + basename
      2. `speed = -1` 表示「这个接口没有链路速率概念」（bridge/虚拟网卡）
         ⇒ 必须归一成 None，不能显示 -1，更不能显示 0
      3. `carrier` 在链路断开时是**空文件** ⇒ 空 ≠ 0
    """

    def _fs(self, **kw):
        files = {
            '/sys/class/net/br-lan/mtu': '1500\n',
            '/sys/class/net/br-lan/address': 'bc:24:11:48:32:5b\n',
            '/sys/class/net/br-lan/type': '1\n',
            '/sys/class/net/br-lan/ifindex': '4\n',
            '/sys/class/net/br-lan/carrier': '1\n',
            '/sys/class/net/br-lan/speed': '-1\n',
            '/sys/class/net/br-lan/duplex': 'unknown\n',
            '/sys/class/net/br-lan/operstate': 'up\n',
            '/sys/class/net/eth1/mtu': '1500\n',
            '/sys/class/net/eth1/carrier': '',      # 链路断开 = 空文件
            '/sys/class/net/eth1/speed': '1000\n',
            '/sys/class/net/eth1/duplex': 'full\n',
            '/sys/class/net/eth1/operstate': 'down\n',
            '/sys/class/net/eth1/statistics/rx_dropped': '7\n',
            '/sys/class/net/eth1/statistics/rx_errors': '0\n',
            '/sys/class/net/eth1/statistics/tx_dropped': '3\n',
            '/sys/class/net/eth1/statistics/tx_errors': '0\n',
        }
        links = {
            '/sys/class/net/eth0/master': '../../../../../../../virtual/net/br-lan',
        }
        files.update(kw.pop('files', {}))
        links.update(kw.pop('links', {}))
        return _FakeFs(files=files, links=links, **kw)

    def test_master_resolved_from_directory_symlink(self):
        with self._fs():
            out = device_info._iface_sysfs('eth0')
        self.assertEqual(out['master'], 'br-lan')

    def test_no_master_means_not_a_bridge_member(self):
        with self._fs():
            out = device_info._iface_sysfs('br-lan')
        self.assertIsNone(out['master'])

    def test_speed_minus_one_becomes_none(self):
        """-1 = 没有链路速率概念 ⇒ 归一成 None。"""
        with self._fs():
            out = device_info._iface_sysfs('br-lan')
        self.assertIsNone(out['speed'])
        self.assertIsNone(out['duplex'])

    def test_real_speed_is_kept(self):
        with self._fs():
            out = device_info._iface_sysfs('eth1')
        self.assertEqual(out['speed'], 1000)
        self.assertEqual(out['duplex'], 'full')

    def test_empty_carrier_is_none_not_zero(self):
        """链路断开时 carrier 是空文件。读成 0 会被理解成「链路正常但没载波」。"""
        with self._fs():
            out = device_info._iface_sysfs('eth1')
        self.assertIsNone(out['carrier'])

    def test_linked_carrier_is_one(self):
        with self._fs():
            out = device_info._iface_sysfs('br-lan')
        self.assertEqual(out['carrier'], 1)

    def test_basic_attributes(self):
        with self._fs():
            out = device_info._iface_sysfs('br-lan')
        self.assertEqual(out['mtu'], 1500)
        self.assertEqual(out['mac'], 'bc:24:11:48:32:5b')
        self.assertEqual(out['type'], 1)
        self.assertEqual(out['ifindex'], 4)

    def test_statistics_are_collected(self):
        with self._fs():
            out = device_info._iface_statistics('eth1')
        self.assertEqual(out['rx_dropped'], 7)
        self.assertEqual(out['rx_errors'], 0)
        self.assertEqual(out['tx_dropped'], 3)
        self.assertEqual(out['tx_errors'], 0)

    def test_missing_sysfs_gives_none_not_crash(self):
        """sysfs 整个读不到（容器里常见）⇒ 全 None，不能抛。"""
        with _FakeFs():
            out = device_info._iface_sysfs('whatever')
        for k in ('mtu', 'mac', 'type', 'ifindex', 'carrier', 'master',
                  'speed', 'duplex'):
            self.assertIsNone(out[k], '%s 应为 None' % k)


class _FakeClock:
    """可控的时钟。

    只替换 `device_info.time` 这**一个名字** —— 不动全局的 time 模块
    （直接改 `time.time` 会把整个测试进程的时间都冻住，
    unittest 自己的计时、logging 都会被带偏）。
    """

    def __init__(self, ts=1000.0):
        self.ts = ts
        self._orig = None

    def __enter__(self):
        self._orig = device_info.time
        device_info.time = self
        return self

    def __exit__(self, *exc):
        device_info.time = self._orig
        return False

    def time(self):
        return self.ts

    def advance(self, dt):
        self.ts += dt


class TestRates(unittest.TestCase):
    """速率：两次采样差值。

    为什么必须有两次：累计字节 ÷ 开机时长是「开机以来的平均」，
    不是当前流量。宁可显示「采样中」，也不能给一个编出来的数。
    """

    def setUp(self):
        device_info._RATE_SNAPSHOT.clear()

    def tearDown(self):
        device_info._RATE_SNAPSHOT.clear()

    def test_first_call_has_no_rate(self):
        item = {'name': 'eth0', 'rx_bytes': 1000, 'tx_bytes': 2000}
        device_info._apply_rates([item])
        self.assertIsNone(item['rx_bps'])
        self.assertIsNone(item['tx_bps'])

    def test_second_call_computes_delta(self):
        with _FakeClock(1000.0) as clk:
            a = {'name': 'eth0', 'rx_bytes': 1000, 'tx_bytes': 2000}
            device_info._apply_rates([a])
            clk.advance(2.0)
            b = {'name': 'eth0', 'rx_bytes': 3000, 'tx_bytes': 4000}
            device_info._apply_rates([b])
        self.assertEqual(b['rx_bps'], 1000)    # 2000 字节 / 2 秒
        self.assertEqual(b['tx_bps'], 1000)

    def test_interval_too_short_gives_no_rate(self):
        """间隔太短时噪声大于信号 ⇒ 不给数。"""
        with _FakeClock(1000.0) as clk:
            a = {'name': 'eth0', 'rx_bytes': 1000, 'tx_bytes': 2000}
            device_info._apply_rates([a])
            clk.advance(0.2)
            b = {'name': 'eth0', 'rx_bytes': 3000, 'tx_bytes': 4000}
            device_info._apply_rates([b])
        self.assertIsNone(b['rx_bps'])
        self.assertIsNone(b['tx_bps'])

    def test_counter_going_backwards_gives_no_rate(self):
        """字节数变小 = 计数器回绕或接口重启 ⇒ 不能算出负速率。"""
        with _FakeClock(1000.0) as clk:
            a = {'name': 'eth0', 'rx_bytes': 5000, 'tx_bytes': 5000}
            device_info._apply_rates([a])
            clk.advance(2.0)
            b = {'name': 'eth0', 'rx_bytes': 100, 'tx_bytes': 100}
            device_info._apply_rates([b])
        self.assertIsNone(b['rx_bps'])
        self.assertIsNone(b['tx_bps'])

    def test_vanished_interface_is_forgotten(self):
        """接口在设备上被删了 ⇒ 快照不能无限膨胀。"""
        device_info._apply_rates([{'name': 'eth0', 'rx_bytes': 1, 'tx_bytes': 1}])
        self.assertIn('eth0', device_info._RATE_SNAPSHOT)
        device_info._apply_rates([{'name': 'eth1', 'rx_bytes': 1, 'tx_bytes': 1}])
        self.assertNotIn('eth0', device_info._RATE_SNAPSHOT)


class TestCollectServices(unittest.TestCase):
    """设备侧服务状态。

    ⚠️ 「enabled」（rc.d 里有 S 软链）≠「running」。
    真机 .232 上的 uhttpd 就是活例子：S50uhttpd 软链还在，
    但 uhttpd.main.enabled=0 ⇒ 开机根本不启动。
    ⇒ running 必须靠 pid 文件**且 pid 还活着**来判。
    """

    def _fs(self, extra_files=None, extra_isdirs=None):
        dirs = {
            '/etc/init.d': ['uhttpd', 'dnsmasq', 'dropbear', 'nftables-web',
                            'nftables-web.bak.1793432750'],
            '/etc/rc.d': ['S50uhttpd', 'S19dnsmasq', 'S99nftables-web',
                          'K10nftables-web', 'S00sysfixtime'],
            '/var/run': ['dropbear.main.pid', 'nftables-web.pid', 'x.txt'],
        }
        files = {
            '/var/run/dropbear.main.pid': '123\n',
            '/var/run/nftables-web.pid': '456\n',
        }
        files.update(extra_files or {})
        isfiles = {'/etc/init.d/uhttpd', '/etc/init.d/dnsmasq',
                   '/etc/init.d/dropbear', '/etc/init.d/nftables-web',
                   '/etc/init.d/nftables-web.bak.1793432750'}
        isdirs = {'/proc/123', '/proc/456'}
        isdirs.update(extra_isdirs or ())
        return _FakeFs(files=files, dirs=dirs, isfiles=isfiles, isdirs=isdirs)

    def test_installed_enabled_running_are_distinct(self):
        with self._fs():
            out = device_info.collect_services()
        by = {s['name']: s for s in out}
        self.assertTrue(by['uhttpd']['installed'])
        self.assertTrue(by['uhttpd']['enabled'])       # rc.d 里有 S50uhttpd
        self.assertFalse(by['uhttpd']['running'])     # 但没有 pid ⇒ 没在跑
        self.assertEqual(by['uhttpd']['priority'], 50)

    def test_dropbear_running_via_dotted_pid_file(self):
        """dropbear 的 pid 文件叫 dropbear.main.pid，不是 dropbear.pid。"""
        with self._fs():
            out = device_info.collect_services()
        by = {s['name']: s for s in out}
        self.assertTrue(by['dropbear']['running'])

    def test_stale_pid_file_is_not_running(self):
        """pid 文件残留（进程已死）不能报「运行中」—— 那是在骗人。"""
        with self._fs(extra_files={'/var/run/dropbear.main.pid': '999\n'},
                      extra_isdirs=set()):
            out = device_info.collect_services()
        by = {s['name']: s for s in out}
        self.assertFalse(by['dropbear']['running'])

    def test_backup_copy_is_not_a_service(self):
        """`nftables-web.bak.<时间戳>` 是备份副本，不是服务。"""
        with self._fs():
            out = device_info.collect_services()
        self.assertNotIn('nftables-web.bak.1793432750',
                         [s['name'] for s in out])

    def test_installed_but_never_enabled_is_still_listed(self):
        """装了但没设开机自启的服务也要列出来（installed 与 enabled 分开）。"""
        with self._fs():
            out = device_info.collect_services()
        by = {s['name']: s for s in out}
        self.assertIn('dropbear', by)
        self.assertTrue(by['dropbear']['installed'])
        self.assertFalse(by['dropbear']['enabled'])

    def test_running_services_come_first(self):
        with self._fs():
            out = device_info.collect_services()
        self.assertTrue(out[0]['running'])

    def test_no_files_gives_empty_list(self):
        with _FakeFs():
            out = device_info.collect_services()
        self.assertEqual(out, [])


APK_INSTALLED = """\
C:Q1r2jQD26RvvUbgA6UOeYrI3tOT/A=
P:acme-acmesh
V:3.1.3-r3
A:noarch
P:busybox
V:1.36.1-r2
P:dnsmasq
V:2.90-r1
"""

APK_WORLD = """\
acme-acmesh
busybox><Q16G4HcA94o24kSZjd7yZlEymYd4w=
base-files=1711~f5dae5ece4
dnsmasq
"""


class TestCollectPackages(unittest.TestCase):
    """包清单。"""

    def _patch(self, table):
        orig = device_info._read_text
        device_info._read_text = lambda path, limit=200000: table.get(path)
        try:
            return device_info.collect_packages()
        finally:
            device_info._read_text = orig

    def test_apk_package_count(self):
        out = self._patch({'/lib/apk/db/installed': APK_INSTALLED})
        self.assertEqual(out['total'], 3)

    def test_world_constraints_are_stripped(self):
        """`busybox><hash`、`base-files=版本` 里只有前半截是包名。"""
        out = self._patch({'/etc/apk/world': APK_WORLD})
        self.assertEqual(out['world'],
                         ['acme-acmesh', 'busybox', 'base-files', 'dnsmasq'])

    def test_opkg_fallback(self):
        """老系统用 opkg：/usr/lib/opkg/status。"""
        out = self._patch({
            '/usr/lib/opkg/status': 'Package: busybox\nVersion: 1.36\n\n'
                                    'Package: dnsmasq\nVersion: 2.90\n\n',
        })
        self.assertEqual(out['total'], 2)

    def test_nothing_available_gives_none(self):
        out = self._patch({})
        self.assertIsNone(out['total'])
        self.assertEqual(out['world'], [])


class TestCollectAllExtended(unittest.TestCase):
    """collect_all 要带上新加的两块，且任何一项缺文件都不能抛。"""

    def test_new_keys_present(self):
        d = device_info.collect_all()
        self.assertIn('services', d)
        self.assertIn('packages', d)
        self.assertIsInstance(d['services'], list)
        self.assertIn('total', d['packages'])

    def test_missing_everything_does_not_raise(self):
        orig = device_info._read_text
        device_info._read_text = lambda path, limit=200000: None
        orig_listdir = os.listdir

        def boom_listdir(path):
            raise OSError('nope')
        os.listdir = boom_listdir
        try:
            d = device_info.collect_all()
        finally:
            device_info._read_text = orig
            os.listdir = orig_listdir
        self.assertEqual(d['services'], [])
        self.assertIsNone(d['packages']['total'])


# ── 输出适配：让每个用例都打一行 [PASS]/[FAIL] ───────────────
#
# 为什么必须加这个（2026-11-08 实测踩到）：
#
# unittest 默认输出是
#   test_xxx (__main__.TestClass.test_xxx) ... ok
# **不带任何标记** ⇒ 全量回归的计数规则只认「行首是 ✅ 或 [PASS]」，
# 于是这个文件的 14 项断言**一条都进不了硬指标**，
# 回归日志里显示成「✅ test_device_info.py ✅0 ❌0」——
# 看着像"通过"，实际是 14 项被静默漏计，指标自己骗自己。
#
# 这是本项目**第二次**踩同一类坑：
# 第一次是 test_portal_frontend.py（282 项）与 test_pixelfield_trae.js（20 项），
# 当年的修法是在 run_all.sh 里加「两种标记一起数」。
# ⇒ 这次改成**在测试文件侧**输出合规标记，
#    并在 run_all.sh 里再加一道「rc=0 但断言数为 0 ⇒ 报警」的兜底，两头堵死。
#
# ⚠️ 标记必须打在**行首**（可带缩进）：回归的计数规则是行首锚定，
#    否则会被当成日志行漏掉 —— 这正是本项目之前踩过的另一个坑。
#
# ⚠️ 不用 emoji：AGENTS.md 明确要求终端输出禁用 emoji，统一用 [PASS]/[FAIL]。

def _short_id(test):
    """只取方法名：test_id 形如 module.Class.method。"""
    return test.id().rsplit('.', 1)[-1]


def _print_err(err):
    """打印失败 traceback（打 stdout，和 [FAIL] 行挨着，方便看）。"""
    exc_type, exc, tb = err
    for line in traceback.format_exception(exc_type, exc, tb):
        print('       %s' % line.rstrip())


class _MarkingResult(unittest.TestResult):
    """把每个用例的结果打成一 [PASS] / [FAIL] 行。

    为什么自己写而不用 unittest.TextTestResult：
    TextTestResult 的行尾是「ok」/「FAIL」，既不带我们的标记，
    又会被计数规则忽略（等于白写）。这里直接接管输出。
    """

    def addSuccess(self, test):
        super().addSuccess(test)
        print('  [PASS] %s' % _short_id(test))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        print('  [FAIL] %s' % _short_id(test))
        _print_err(err)

    def addError(self, test, err):
        super().addError(test, err)
        print('  [FAIL] %s' % _short_id(test))
        _print_err(err)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        # [SKIP] 不被计数规则认（既不算通过也不算失败）——
        # 与 run_all.sh 里「[跳过]不匹配 ⇒ 不计数」的既有约定一致
        print('  [SKIP] %s  — %s' % (_short_id(test), reason))

    def addSubTest(self, test, subtest, outcome):
        # 基类的 addSubTest **不会**回调 addSuccess/addFailure ⇒
        # 用了 subTest 的用例会一条标记都不打 ⇒ 必须单独处理，
        # 否则又是一次静默漏计。
        super().addSubTest(test, subtest, outcome)
        if outcome is None:
            print('  [PASS] %s' % _short_id(subtest))
        elif issubclass(outcome[0], test.skipException):
            print('  [SKIP] %s  — %s' % (_short_id(subtest), outcome[1]))
        else:
            print('  [FAIL] %s' % _short_id(subtest))
            _print_err(outcome)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = _MarkingResult()
    suite.run(result)
    failed = len(result.failures) + len(result.errors)
    print('\n' + '=' * 60)
    print('  用例 %d / 通过 %d / 失败 %d' % (result.testsRun, result.testsRun - failed, failed))
    print('=' * 60)
    sys.exit(0 if result.wasSuccessful() else 1)
