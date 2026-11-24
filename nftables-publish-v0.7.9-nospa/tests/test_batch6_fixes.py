#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第六批修复的行为级判据（路由器状态页 IPv4 一直「未知」）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/test_batch6_fixes.py

现象（用户 2026-11-24 报）
--------------------------
「路由器状态页 ipv4 检测好像一直未知」。

实测根因（.1 上只读核实，2026-11-24）
------------------------------------
· 设备本身**能**采到公网 IP：`collect_public_ip()` = 183.141.193.10
  ⇒ 不是设备采不到，是面板没去问。
· 面板日志里只有 `GET /api/system/info`，**从未出现 `?public_ip=1`**
  ⇒ 「查询」按钮从来没被点过 ⇒ 那一栏永远是「未知」。
  （前端那一半的判据在 tests/test_frontend_batch6_fixes.js。）

· 接口表 IPv4 整列是空的：`_ipv4_by_iface()` 原来是
  「fib_trie 采到了就 return，采不到才退 getifaddrs」
  ⇒ **PPPoE 这类点到点接口永远采不到地址**：
    它在路由表里没有直连网段（只有默认路由），
    而 fib_trie 的反查是「拿接口的直连网段去匹配地址」⇒ 匹配不上。
  .1 实测：fib_trie 只给出 br-lan，getifaddrs 才给出 pppoe-wan 的公网 IPv4。

· 接口状态显示「未知」：`_iface_state()` 只认 operstate，
  而 **PPPoE 的 operstate 恒为 'unknown'**
  （.1 实测：pppoe-wan operstate=unknown、carrier=1、flags 里 IFF_UP 置位）。

判据
----
· 每条断言都写成「老代码必然失败」的形式。
· 用的都是 **.1 真机抄下来的 /proc 片段**（合成，不含任何真实凭据）。
· 只读仓库源码 + 只在内存里打桩 ⇒ 不碰 /proc、/sys、/etc 的真文件。
"""
import os
import sys
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'backend'))

import device_info  # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name
          + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


# ── .1 真机抄下来的 /proc 片段（合成，无凭据）────────────────────────
#
# /proc/net/route 的地址是**小端**字节序：
#   0064A8C0 = 192.168.100.0、00FFFFFF = 255.255.255.0
# ⚠️ pppoe-wan 只有**默认路由**（Destination/Mask 全 0）⇒ 没有直连网段
#    —— 这正是它采不到地址的原因，也是本批要修的点。
ROUTE = (
    'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\t'
    'Mask\t\tMTU\tWindow\tIRTT\n'
    'pppoe-wan\t00000000\t0AC18DB7\t0083\t0\t0\t600\t00000000\t0\t0\t0\n'
    'br-lan\t0064A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n'
)

# /proc/net/fib_trie：Local 表里**两个** host LOCAL 都在
#   192.168.100.1（br-lan 的）和 183.141.193.10（pppoe-wan 的公网地址）
#   —— 但反查要靠「接口的直连网段」⇒ pppoe-wan 那条匹配不上任何网段。
FIB_TRIE = (
    'Main:\n'
    ' +-- 0.0.0.0/0 3 0 3\n'
    '    |-- 0.0.0.0\n'
    '       0 0AC18DB7 0 0 0\n'
    '    |\n'
    ' +-- 192.168.100.0/24\n'
    '    |-- 192.168.100.1\n'
    '       0 0 0 0 0 0\n'
    '    |\n'
    'Local:\n'
    ' +-- 0.0.0.0/0 3 0 3\n'
    '    |-- 0.0.0.0\n'
    '       0 0 0 0 0 0\n'
    '    |\n'
    ' +-- 183.141.193.10/32\n'
    '    |-- 183.141.193.10\n'
    '       /32 host LOCAL\n'
    '    |\n'
    ' +-- 192.168.100.0/24\n'
    '    |-- 192.168.100.1\n'
    '       /32 host LOCAL\n'
    '    |\n'
)

# /proc/net/dev：两列都要 16 个字段，缺一个整行会被跳过
NET_DEV = (
    'Inter-|   Receive                                                |'
    '  Transmit\n'
    ' face |bytes    packets errs drop fifo frame compressed multicast|'
    'bytes    packets errs drop fifo colls carrier compressed\n'
    '    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n'
    '  br-lan: 2000 20 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n'
    'pppoe-wan: 3000 30 0 0 0 0 0 0 3000 30 0 0 0 0 0 0\n'
)

# getifaddrs() 的返回值（.1 实测抄下来的）：lo / br-lan / pppoe-wan
GETIFADDRS = {
    'lo': ['127.0.0.1'],
    'br-lan': ['192.168.100.1'],
    'pppoe-wan': ['183.141.193.10'],
}

# /sys/class/net/<名>/ 下的文件
SYSFS = {
    'pppoe-wan': {'operstate': 'unknown', 'carrier': '1'},
    'br-lan': {'operstate': 'up', 'carrier': '1'},
    'eth0': {'operstate': 'down', 'carrier': '0'},
    'eth1': {'operstate': 'unknown', 'carrier': '0'},
    'eth2': {'operstate': 'unknown'},          # carrier 读不到（空文件）
    'eth3': {},                                # operstate 与 carrier 都没有
}


def _fake_read_text(path, limit=200000):
    """顶掉真读文件：按路径返回夹具，其余一律 None（= 设备上缺文件）。"""
    if path == '/proc/net/route':
        return ROUTE
    if path == '/proc/net/fib_trie':
        return FIB_TRIE
    if path == '/proc/net/dev':
        return NET_DEV
    if path.startswith('/sys/class/net/'):
        rest = path[len('/sys/class/net/'):]
        if '/' in rest:
            name, leaf = rest.split('/', 1)
            return SYSFS.get(name, {}).get(leaf)
        return None
    return None


def _patched_getifaddrs():
    return {k: list(v) for k, v in GETIFADDRS.items()}


def _run(fn, *a, **kw):
    """在夹具环境里跑一个采集函数。"""
    with mock.patch.object(device_info, '_read_text', _fake_read_text), \
            mock.patch.object(device_info, '_ipv4_by_getifaddrs',
                              _patched_getifaddrs):
        return fn(*a, **kw)


# ══════════════════════════════════════════════════════════════════
sec('A. _ipv4_by_iface()：两个来源要合并，不能二选一')
# ══════════════════════════════════════════════════════════════════

v4 = _run(device_info._ipv4_by_iface)

check('A-1 PPPoE 口采得到公网 IPv4（老代码：fib_trie 成功就 return，压根没跑 getifaddrs）',
      v4.get('pppoe-wan') == ['183.141.193.10'],
      f"实际={v4.get('pppoe-wan')}")

check('A-2 同一个地址在两个来源里都有时只出现一次（去重）',
      v4.get('br-lan') == ['192.168.100.1'],
      f"实际={v4.get('br-lan')}")

check('A-3 getifaddrs 独有的接口不会被丢掉（老代码走不到这一支）',
      'lo' in v4,
      f"实际键={sorted(v4.keys())}")

check('A-4 采集顺序不影响结果（先 fib_trie 后 getifaddrs）',
      v4 == {'lo': ['127.0.0.1'],
             'br-lan': ['192.168.100.1'],
             'pppoe-wan': ['183.141.193.10']},
      f"实际={v4}")

# ── 边界：getifaddrs 完全不可用时，fib_trie 的结果不能被清空 ──────────
with mock.patch.object(device_info, '_read_text', _fake_read_text), \
        mock.patch.object(device_info, '_ipv4_by_getifaddrs', lambda: {}):
    v4_noget = device_info._ipv4_by_iface()
check('A-5 getifaddrs 采不到时，fib_trie 采到的仍在（不能被合并逻辑吃掉）',
      v4_noget.get('br-lan') == ['192.168.100.1'],
      f"实际={v4_noget}")

# ── 边界：fib_trie 完全不可用时，退到 getifaddrs ─────────────────────
with mock.patch.object(device_info, '_read_text',
                       lambda p, limit=200000: None), \
        mock.patch.object(device_info, '_ipv4_by_getifaddrs',
                          _patched_getifaddrs):
    v4_nofib = device_info._ipv4_by_iface()
check('A-6 fib_trie 采不到时，退到 getifaddrs（老行为不能丢）',
      v4_nofib.get('pppoe-wan') == ['183.141.193.10'],
      f"实际={v4_nofib}")

# ══════════════════════════════════════════════════════════════════
sec('B. _iface_state()：operstate 不可用时看 carrier')
# ══════════════════════════════════════════════════════════════════

st_pppoe = _run(device_info._iface_state, 'pppoe-wan')
check('B-1 PPPoE 口 operstate=unknown + carrier=1 ⇒ up（老代码：直接返回 unknown）',
      st_pppoe == 'up', f'实际={st_pppoe!r}')

st_br = _run(device_info._iface_state, 'br-lan')
check('B-2 operstate=up 时照旧返回 up',
      st_br == 'up', f'实际={st_br!r}')

st_eth0 = _run(device_info._iface_state, 'eth0')
check('B-3 operstate=down 时照旧返回 down',
      st_eth0 == 'down', f'实际={st_eth0!r}')

st_eth1 = _run(device_info._iface_state, 'eth1')
check('B-4 operstate=unknown + carrier=0 ⇒ down（链路没起来）',
      st_eth1 == 'down', f'实际={st_eth1!r}')

st_eth2 = _run(device_info._iface_state, 'eth2')
check('B-5 operstate=unknown + carrier 读不到 ⇒ 退回 flags 的 IFF_UP',
      st_eth2 is None or st_eth2 in ('up', 'down'),
      f'实际={st_eth2!r}')

# flags 兜底：用 mock_open 单独喂 flags 文件的内容
for _flags, _expect, _label in (
        ('1043', 'up', 'IFF_UP 置位 ⇒ up'),
        ('1042', 'down', 'IFF_UP 没置位 ⇒ down')):
    m = mock.mock_open(read_data=_flags)
    with mock.patch.object(device_info, '_read_text', _fake_read_text), \
            mock.patch.object(device_info, '_ipv4_by_getifaddrs',
                              _patched_getifaddrs), \
            mock.patch('builtins.open', m):
        st = device_info._iface_state('eth3')
    check(f'B-6 operstate/carrier 都没有时看 flags（{_label}）',
          st == _expect, f'实际={st!r}')

# carrier 优先于 flags：链路断了就是断了，不能被 flags 的 IFF_UP 盖住
m = mock.mock_open(read_data='1043')
with mock.patch.object(device_info, '_read_text', _fake_read_text), \
        mock.patch.object(device_info, '_ipv4_by_getifaddrs',
                          _patched_getifaddrs), \
        mock.patch('builtins.open', m):
    st = device_info._iface_state('eth1')
check('B-7 carrier=0 时不因为 flags 的 IFF_UP 置位而说成 up',
      st == 'down', f'实际={st!r}')

# ══════════════════════════════════════════════════════════════════
sec('C. 端到端：接口表里那一行（用户真正看到的那一格）')
# ══════════════════════════════════════════════════════════════════

ifaces = _run(device_info.collect_interfaces)
by_name = {i['name']: i for i in ifaces}

check('C-1 接口表里有 pppoe-wan 这一行',
      'pppoe-wan' in by_name,
      f"实际={sorted(by_name.keys())}")

check('C-2 pppoe-wan 行的 IPv4 不是空的（老代码：整格是「—」）',
      by_name.get('pppoe-wan', {}).get('ipv4') == ['183.141.193.10'],
      f"实际={by_name.get('pppoe-wan', {}).get('ipv4')}")

check('C-3 pppoe-wan 行的状态不是 unknown（老代码：显示「未知」，像坏了）',
      by_name.get('pppoe-wan', {}).get('state') == 'up',
      f"实际={by_name.get('pppoe-wan', {}).get('state')!r}")

check('C-4 br-lan 行的 IPv4 只有一个（两源合并后不能重复）',
      by_name.get('br-lan', {}).get('ipv4') == ['192.168.100.1'],
      f"实际={by_name.get('br-lan', {}).get('ipv4')}")

check('C-5 回环口不出现在对外接口列表里（老行为不变）',
      'lo' not in by_name,
      f"实际={sorted(by_name.keys())}")

# ══════════════════════════════════════════════════════════════════
print(f'\n合计: [PASS] {len(PASS)}   [FAIL] {len(FAIL)}')
if FAIL:
    for f in FAIL:
        print('  [FAIL]', f)
    sys.exit(1)
sys.exit(0)
