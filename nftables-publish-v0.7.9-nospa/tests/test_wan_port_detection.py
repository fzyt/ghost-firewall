#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAN 口自动检测的回归测试（多 eth 接入 br-lan 的前置条件）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_wan_port_detection.py

背景
----
`backend/app.py` 的 `update_uci_wan_config()` 在保存网络配置时，
要自己挑一个**没被 LAN 桥占用**的物理网卡当 WAN 口。

挑错的后果不是「配置不对」，是**整机失联**：
2026-10-06 在 x86 单网卡 OpenWrt 上实测踩中过 ——
点「PPPoE 拨号」+「保存网络配置」+「重启网络」，设备当场 ARP FAILED，
Proxmox 没开带外口，无法远程恢复。

2026-11-10 复核又挖出同一族的第二处隐患（`报告/需求评估-多eth接入br-lan-2026-11-09.md` W1）：
旧的 `list ports` 解析**只认带引号的写法**
（`line.strip().split("'")[-2] if "'" in line else ''`），
而 UCI 允许不带引号 —— `.232` 真机 2026-11-10 实测：
`uci show` 把 `list ports eth1` 正常解析成 `ports='eth0' 'eth1'`。
那种写法下 eth1 解析不到 ⇒ 被当成 WAN 候选 ⇒ **WAN 抢走 LAN 桥成员**。

测什么有效
----------
断言刻意做成**行为级**的：不看源码、不正则匹配实现，
而是拿真实的 `/etc/config/network` 文本 + 真实的假 sysfs 树喂给检测函数，
然后断言「它选出来的口是不是安全的那个」。

⚠️ 判据必须比被测对象更强
------------------------
只断言「选中了对的口」是不够的 —— 那样的判据在退化时可能照样绿。
所以每一组都额外断言**反例**：把桥成员从配置里去掉、把 sysfs 的 master
去掉，确认这时**才**会选到那个口。

也就是说：断言要能区分
    「因为 eth0 在桥上所以不选 eth0」
    「碰巧不选 eth0」
这两种情况。只有前者成立时，检测逻辑才是真的在干活。

假 sysfs 怎么造
---------------
真机上 `/sys/class/net/<if>/master` 是**指向桥目录的符号链接**
（`../../virtual/net/br-lan`）。所以假树里用 `os.symlink()` 造同样的链接即可，
`os.path.islink()` 判据就成立 —— 与真机同一条判定路径。
"""
import importlib.util as ilu
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def load_app():
    """加载面板模块（不依赖 flask 上下文，只用纯函数）。"""
    spec = ilu.spec_from_file_location('_nftapp_wanport', os.path.join(BACKEND, 'app.py'))
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mod = load_app()


# ── 假 sysfs ────────────────────────────────────────────────────
#
# 结构照抄真机（.232 实测）：
#   /sys/class/net/br-lan/          桥本身，没有 master
#   /sys/class/net/eth0/master -> ../../virtual/net/br-lan   桥成员
#   /sys/class/net/eth1/            独立口，没有 master
#
# ⚠️ 每个假 sysfs 必须住在**自己的目录**里：
# 共用一个目录的话，后建的树会叠在前一棵上（残留的 eth1/eth2、
# 已经存在的 master 符号链接），判据就会测到「上一组留下的现场」，
# 而不是被测逻辑本身 —— 那种测试是假绿。
def make_sysfs(base, name, bridged=(), standalone=(), extra=()):
    """造一棵假的 /sys/class/net。

    name      —— 本棵假树的名字（各自独立目录，避免互相污染）
    bridged   —— 在桥上的口（会造 master 符号链接）
    standalone—— 独立口（不造 master）
    extra     —— 其它名字的目录（lo / br-lan 之类）
    """
    net = os.path.join(base, name, 'net')
    os.makedirs(net, exist_ok=True)
    for n in list(extra) + list(standalone):
        os.makedirs(os.path.join(net, n), exist_ok=True)
    for n in bridged:
        os.makedirs(os.path.join(net, n), exist_ok=True)
        # 真机上 master 是指向桥目录的符号链接（不是普通文件）
        os.symlink('../../virtual/net/br-lan', os.path.join(net, n, 'master'))
    return net


# ── /etc/config/network 样本 ────────────────────────────────────
#
# 照抄 .232 真机（2026-11-10 实测的原文形态）：
#   DSA 形态下 `list ports` 在 **config device** 段里，
#   不是 config interface 'lan' 段里 —— 这一点很关键，
#   只扫 lan 段的实现会完全漏掉。
DSA_MULTI_ETH = """config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports 'eth0'
\tlist ports eth1

config interface 'lan'
\toption device 'br-lan'
\toption proto 'dhcp'

config interface 'wan'
\toption device 'eth2'
\toption proto 'dhcp'
"""

# W1 的核心样本：`list ports eth1` **不带引号**（UCI 合法，.232 实测 uci show 能解析）
DSA_UNQUOTED = """config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports 'eth0'
\tlist ports eth1

config interface 'lan'
\toption device 'br-lan'
\toption proto 'dhcp'
"""

# 双引号写法（UCI 也合法）
DSA_DOUBLE_QUOTED = """config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports "eth0"
\tlist ports "eth1"

config interface 'lan'
\toption device 'br-lan'
\toption proto 'dhcp'
"""

# swconfig 老写法：LAN 口直接列在 lan 接口的 option ifname 里，没有 config device 段
SWCONFIG_IFNAME = """config interface 'lan'
\toption ifname 'eth0 eth1'
\toption proto 'static'
\toption ipaddr '192.168.1.1'
"""

TMP = tempfile.mkdtemp(prefix='wanport-test-')
try:
    # ══════════════════════════════════════════════════════════════
    sec('1. W1：无引号 / 双引号的 list ports 都要解析出来')
    # ══════════════════════════════════════════════════════════════
    #
    # 这是本次修复的核心缺陷。旧实现只认单引号 ⇒ 无引号那行整个漏掉。

    net = make_sysfs(TMP, 'a', standalone=['eth0', 'eth1', 'eth2'])

    pick, physical, occupied = mod._detect_wan_device(DSA_UNQUOTED, net)
    check('无引号的 list ports eth1 被解析出来（eth1 不该当 WAN 口）',
          'eth1' in occupied, f'occupied={occupied}')
    check('无引号场景下选出的 WAN 口是 eth2（不是桥成员 eth1）',
          pick == 'eth2', f'实际={pick!r}')
    check('桥成员 eth0（单引号写法）也被排除',
          'eth0' in occupied, f'occupied={occupied}')

    pick, physical, occupied = mod._detect_wan_device(DSA_DOUBLE_QUOTED, net)
    check('双引号的 list ports 同样被解析出来',
          {'eth0', 'eth1'} <= set(occupied), f'occupied={occupied}')
    check('双引号场景下选出的 WAN 口是 eth2',
          pick == 'eth2', f'实际={pick!r}')

    # 反例：把 eth1 从配置里去掉 ⇒ 这时（且仅这时）才该轮到 eth1
    pick2, _, occ2 = mod._detect_wan_device(
        "config device\n\toption name 'br-lan'\n\toption type 'bridge'\n"
        "\tlist ports 'eth0'\n", net)
    check('反例：配置里只有 eth0 时才轮到 eth1（证明上面的排除是配置驱动的）',
          pick2 == 'eth1', f'实际={pick2!r}')

    # ══════════════════════════════════════════════════════════════
    sec('2. sysfs master 交叉验证（比文本解析更硬的证据）')
    # ══════════════════════════════════════════════════════════════
    #
    # 关键：文本可能漏写、写法可能怪，而「这个口挂在哪个桥上」是内核说了算。
    # 这一组里**配置里根本没提 eth0**，只有 sysfs 说它在桥上 ——
    # 只靠文本解析的实现必然选错。

    net2 = make_sysfs(TMP, 'b', bridged=['eth0'], standalone=['eth1'], extra=['br-lan', 'lo'])
    pick, physical, occupied = mod._detect_wan_device(
        "config interface 'lan'\n\toption device 'br-lan'\n", net2)
    check('配置里没提 eth0，但 sysfs 说它在桥上 ⇒ 仍然排除',
          'eth0' in occupied, f'occupied={occupied}')
    check('sysfs 证据生效时选出的是 eth1',
          pick == 'eth1', f'实际={pick!r}')

    # 反例：把 master 去掉（eth0 变成独立口）⇒ 这时才该轮到 eth0
    net3 = make_sysfs(TMP, 'c', standalone=['eth0', 'eth1'], extra=['br-lan', 'lo'])
    pick3, _, occ3 = mod._detect_wan_device(
        "config interface 'lan'\n\toption device 'br-lan'\n", net3)
    check('反例：eth0 没有 master 时它就是合法候选（证明排除确实来自 master 证据）',
          pick3 == 'eth0' and 'eth0' not in occ3,
          f'pick={pick3!r} occupied={occ3}')

    # ══════════════════════════════════════════════════════════════
    sec('3. swconfig 老写法（lan 的 option ifname）')
    # ══════════════════════════════════════════════════════════════

    net4 = make_sysfs(TMP, 'd', standalone=['eth0', 'eth1', 'eth2'])
    pick, physical, occupied = mod._detect_wan_device(SWCONFIG_IFNAME, net4)
    check('lan 的 option ifname 里的 eth0 eth1 都被排除',
          {'eth0', 'eth1'} <= set(occupied), f'occupied={occupied}')
    check('swconfig 场景选出 eth2',
          pick == 'eth2', f'实际={pick!r}')

    # ══════════════════════════════════════════════════════════════
    sec('4. VLAN 子接口不算独立物理口')
    # ══════════════════════════════════════════════════════════════
    #
    # eth0.10 是 VLAN，它 startswith('eth') 为真 ——
    # 只按前缀判会把 VLAN 当成独立 WAN 口，那等于把 LAN 的 VLAN 抢走。

    net5 = make_sysfs(TMP, 'e', standalone=['eth0', 'eth0.10', 'eth2'])
    pick, physical, occupied = mod._detect_wan_device('', net5)
    check('VLAN 子接口 eth0.10 不算物理网卡',
          'eth0.10' not in physical, f'physical={physical}')
    check('VLAN 子接口不会被选成 WAN 口',
          pick != 'eth0.10', f'实际={pick!r}')

    # ══════════════════════════════════════════════════════════════
    sec('5. 物理网卡识别（命名白名单）')
    # ══════════════════════════════════════════════════════════════

    net6 = make_sysfs(TMP, 'f', standalone=['eth0', 'ens18', 'enp3s0', 'wlan0', 'br-lan', 'lo'])
    _, physical, _ = mod._detect_wan_device('', net6)
    check('eth0 / ens18 / enp3s0 认得出来',
          {'eth0', 'ens18', 'enp3s0'} <= set(physical), f'physical={physical}')
    check('wlan0 / br-lan / lo 不是物理网卡',
          not ({'wlan0', 'br-lan', 'lo'} & set(physical)), f'physical={physical}')

    # ══════════════════════════════════════════════════════════════
    sec('6. W2：报错文案按实际口数生成')
    # ══════════════════════════════════════════════════════════════
    #
    # 旧文案写死「本机只有一张物理网卡」—— 多口机上是错的。
    # 真实原因应是「所有物理口都已划给 LAN 桥」。

    msg1 = mod._wan_device_missing_message(['eth0'], ['eth0'])
    check('单口机文案说「只有一张物理网卡」',
          '只有一张物理网卡' in msg1 and 'eth0' in msg1, msg1[:90])

    msg3 = mod._wan_device_missing_message(['eth0', 'eth1', 'eth2'],
                                           ['eth0', 'eth1', 'eth2'])
    check('三口机文案不说「只有一张物理网卡」（那是错的）',
          '只有一张物理网卡' not in msg3, msg3[:90])
    check('三口机文案说明「已全部被占用」',
          '全部' in msg3 or '已全部' in msg3, msg3[:90])
    check('三口机文案带上实际口数',
          '3' in msg3 and 'eth2' in msg3, msg3[:90])

    msg0 = mod._wan_device_missing_message([], [])
    check('没找到物理网卡时文案不谎报口数',
          '只有一张物理网卡' not in msg0 and '共' not in msg0, msg0[:90])

    # ══════════════════════════════════════════════════════════════
    sec('7. 端到端：update_uci_wan_config 必须拒绝抢桥成员')
    # ══════════════════════════════════════════════════════════════
    #
    # 前六组测的是检测函数本身；这一组走**真实调用点**：
    # 真的调 update_uci_wan_config，验证它拒绝写入，且原文件一个字节都没动。
    #
    # 样本必须落在判据真正生效的路径上 ——
    # 所以这里用的是**无引号**的 list ports（正是 W1 的场景）。

    net_path = os.path.join(TMP, 'network')
    with open(net_path, 'w') as f:
        f.write(DSA_UNQUOTED)
    os.chmod(net_path, 0o600)

    # 把 sysfs 指到「只有 eth0/eth1 且都在桥上」的假树 ⇒ 无可用 WAN 口
    net7 = make_sysfs(TMP, 'g', bridged=['eth0', 'eth1'], extra=['br-lan', 'lo'])
    orig_root = mod.SYSFS_NET_ROOT
    mod.SYSFS_NET_ROOT = net7
    before = open(net_path).read()
    raised = False
    err = ''
    try:
        mod.update_uci_wan_config(net_path, {
            'wan_pppoe': True,
            'wan_pppoe_username': 'broadband',
            'wan_pppoe_password': 'secret',
        })
    except ValueError as e:
        raised = True
        err = str(e)
    finally:
        mod.SYSFS_NET_ROOT = orig_root
    check('没有独立 WAN 口时拒绝保存（抛 ValueError）', raised, err[:90])
    check('拒绝时原文件一个字节都没动', open(net_path).read() == before)
    check('拒绝文案里带出被占用的口名',
          'eth0' in err and 'eth1' in err, err[:120])

    # 有独立口时正常写入，且写进去的是**独立口**（不是桥成员）
    #
    # ⚠️ 这里要用**只声明了 eth0** 的配置：
    # 若配置里还写着 `list ports eth1`，那 eth1 就是被声明的桥成员，
    # 判据取三路证据的并集 ⇒ 必须排除它（哪怕 sysfs 说它没有 master）。
    # 「配置声明了就排除」是刻意的保守行为，不是 bug。
    net_path2 = os.path.join(TMP, 'network2')
    with open(net_path2, 'w') as f:
        f.write("config device\n\toption name 'br-lan'\n\toption type 'bridge'\n"
                "\tlist ports 'eth0'\n\n"
                "config interface 'lan'\n\toption device 'br-lan'\n"
                "\toption proto 'dhcp'\n\n"
                "config interface 'wan'\n\toption device 'eth1'\n"
                "\toption proto 'dhcp'\n")
    os.chmod(net_path2, 0o600)

    net8 = make_sysfs(TMP, 'h', bridged=['eth0'], standalone=['eth1'], extra=['br-lan', 'lo'])
    mod.SYSFS_NET_ROOT = net8
    try:
        mod.update_uci_wan_config(net_path2, {
            'wan_pppoe': True,
            'wan_pppoe_username': 'broadband',
            'wan_pppoe_password': 'secret',
        })
    finally:
        mod.SYSFS_NET_ROOT = orig_root
    content = open(net_path2).read()
    check('有独立口时正常写入',
          "option proto 'pppoe'" in content, content[-200:])
    check('写入的 WAN 设备是独立口 eth1（不是桥成员 eth0）',
          "option device 'eth1'" in content and "option device 'eth0'" not in content,
          content[-200:])

    # 三路证据取**并集**：配置声明了 eth1，即便 sysfs 说它没有 master，
    # 也照样排除 —— 保守方向是「宁可拒绝，不可抢桥成员」。
    net9 = make_sysfs(TMP, 'i', bridged=['eth0'], standalone=['eth1', 'eth2'],
                      extra=['br-lan', 'lo'])
    pick, _, occupied = mod._detect_wan_device(DSA_UNQUOTED, net9)
    check('配置声明了 eth1 ⇒ 即使 sysfs 说它独立，也照样排除（并集语义）',
          'eth1' in occupied and pick == 'eth2',
          f'pick={pick!r} occupied={occupied}')

finally:
    shutil.rmtree(TMP, ignore_errors=True)

print('\n' + '=' * 74)
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    print('失败项:')
    for f in FAIL:
        print('  -', f)
    sys.exit(1)
print('全部通过')
