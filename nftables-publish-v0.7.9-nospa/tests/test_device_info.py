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

本轮实际踩到并修掉的四个坑
--------------------------
  1. `/proc/net/route` 的地址是**小端**字节序（`0064A8C0` = 192.168.100.0）。
     按大端解析 ⇒ 网段变成 `0.100.168.192/24` ⇒ IPv4 一个都匹配不上。
  2. 掩码解析不能把点分十进制当二进制串去 `int(..., 2)` ——
     `int('2552552550', 2)` 直接抛 ValueError。
  3. `/proc/net/fib_trie` 里地址行与 `/32 host LOCAL` 是**两行**，
     地址在上面那行。按「host LOCAL 行自己就是地址」去 split ⇒ body 是空串。
  4. `Main:` 是 `/proc/net/fib_trie` 的**第一行**，不是中间的分节。
     按「先找 Main: 再往下读」写 ⇒ 永远进不去 Main 表。

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
    """`/proc/net/if_inet6` 解析。"""

    def test_parses_and_groups_by_iface(self):
        orig = device_info._read_text
        device_info._read_text = lambda path, limit=200000: (
            IF_INET6_TEXT if path == '/proc/net/if_inet6' else orig(path, limit))
        try:
            out = device_info._ipv6_by_iface()
        finally:
            device_info._read_text = orig
        self.assertIn('ens18', out)
        # 用 inet_ntop 的实际格式断言：单个 0 组不会被省略成 ::
        # （'fda7:68ee:7b99:0:...' 而非 'fda7:68ee:7b99::...'）
        self.assertIn('fda7:68ee:7b99:0:be24:11ff:fef8:e48', out['ens18'])
        self.assertIn('lo', out)

    def test_temporary_address_excluded(self):
        """标志 0x20 = 临时地址（隐私地址），不展示。"""
        orig = device_info._read_text
        device_info._read_text = lambda path, limit=200000: (
            IF_INET6_TEXT if path == '/proc/net/if_inet6' else orig(path, limit))
        try:
            out = device_info._ipv6_by_iface()
        finally:
            device_info._read_text = orig
        for addrs in out.values():
            self.assertNotIn('fe80::be24:11ff:fef8:e48', addrs)


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
