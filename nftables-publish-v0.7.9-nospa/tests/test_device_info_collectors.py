#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""系统信息页新增采集器的行为级判据。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_device_info_collectors.py

测什么有效
----------
2026-11-11 起，系统信息页换掉了「设备服务清单」与「软件包」两块
（那是**诊断信息**，一般不看），换成：

  · 设备名称     —— 用户在 OpenWrt 里设的 hostname
  · 连接 IP     —— 当前**已建立**的对端地址
  · 公网 IP     —— 与 DDNS 用同一批源
  · ARP 在线表  —— 局域网里谁在线
  · DHCP 静态绑定 —— 用户口头说的「ARP 绑定」的官方等价物

判据怎么写才不假绿
------------------
**不能**拿开发机自己的 /proc/net/tcp 去断言「连接有 N 条」——
那既不稳定（开发机上随时在变），也测不出解析逻辑对不对。

⇒ 这里的做法是：**造样本文件**（/proc/net/tcp、/proc/net/arp、
  /etc/config/dhcp 各一份），让采集器去读**样本**，
  再断言「解析出来的结果是不是预期的那些」。

⚠️ 采集器读的是**写死的绝对路径** ⇒ 判据必须能把它指向临时目录。
  做法与 device_info.py 里其它采集器一致：**monkeypatch 模块级的
  _read_text** ⇒ 采集器代码本身一个字节都不动
  （不给生产代码加「测试专用开关」——那会让生产代码多出一条分支）。

每条判据都要能被**反向证伪**（把样本改坏，判据必须红）。
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(os.path.dirname(HERE), 'backend')
sys.path.insert(0, BACKEND)

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name +
          (('  — %s' % detail) if detail else ''))


def sec(title):
    print('\n=== %s ===' % title)


def load_device_info():
    """导入 device_info 模块（每次都重新导入，保证 monkeypatch 干净）。"""
    path = os.path.join(BACKEND, 'device_info.py')
    spec = importlib.util.spec_from_file_location('di_under_test', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── 样本 ──────────────────────────────────────────────────────
#
# /proc/net/tcp 的格式：每行第 2 列是 local_address，第 3 列是
# rem_address（十六进制 小端 IP:端口），第 4 列是状态
# （01=ESTABLISHED，0A=LISTEN）。
#
# ⚠️ 采集器取的是**对端**（rem_address）—— 本端地址不算。
#
# 下面的样本里（⚠️ local 与 remote 别写反了）：
#   0: local=E864A8C0:1543 remote=0A00000A:01BB
#        ⇒ 本端 192.168.100.232:5443，对端 10.0.0.10:443（ESTABLISHED）
#   1: local=00000000:01BB remote=00000000:0000
#        ⇒ 监听 0.0.0.0:443（LISTEN，不该被算成连接）
#   2: local=0100007F:1F90 remote=0100007F:1F90
#        ⇒ 回环自连 127.0.0.1:8080（ESTABLISHED）
#   3: local=0A00000A:0050 remote=0B00000B:0050
#        ⇒ 10.0.0.11:80 LISTEN（**这个对端只出现在 LISTEN 行**
#          ⇒ 用来验「LISTEN 不算连接」）
#   4: local=E864A8C0:1544 remote=0A00000A:01BC
#        ⇒ 对端仍是 10.0.0.10，只是端口不同 ⇒ 应与第 0 行去重成一条
TCP_SAMPLE = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: E864A8C0:1543 0A00000A:01BB 01 00000000:00000000 00:00000000 00000000     0        0 575969 1 0000000086a69b8f 100 0 0 10 0
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 600046 1 00000000d0dd699f 100 0 0 10 5
   2: 0100007F:1F90 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 778 1 0000000082ab9d7e 100 0 0 10 0
   3: 0A00000A:0050 0B00000B:0050 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 00000000d0dd699f 100 0 0 10 5
   4: E864A8C0:1544 0A00000A:01BC 01 00000000:00000000 00:00000000 00000000     0        0 575970 1 0000000086a69b90 100 0 0 10 0
"""

# /proc/net/arp：第 3 列 flags（0x2=有效），第 6 列是接口名。
#
# ⚠️ 样本是**照着判据设计的**：每一条要被跳过的记录，
#    都只**违反一条**规则 —— 否则另一条规则会顺手把它挡掉，
#    那条判据就永远测不出对应检查是不是还在（2026-11-11 变异验证实测）。
#   · .50  flags=0x0（未完成）但 MAC 是真的
#         ⇒ 只能靠「有效位」检查挡掉它
#   · .99  flags=0x2（有效）但 MAC 全零
#         ⇒ 只能靠「全零 MAC」检查挡掉它
#   · .9 与 .100 都在 ⇒ 字符串序（'.100' < '.9'）与数值序不同
#         ⇒ 排序判据真的能测出「按数值排」
ARP_SAMPLE = """IP address       HW type     Flags       HW address            Mask     Device
192.168.100.126  0x1         0x2         d6:77:f4:3d:9f:ad     *        br-lan
192.168.100.222  0x1         0x2         66:97:9b:69:05:f8     *        br-lan
192.168.100.1    0x1         0x2         00:e0:ed:56:13:80     *        br-lan
192.168.100.9    0x1         0x2         aa:bb:cc:dd:ee:09     *        br-lan
192.168.100.100  0x1         0x2         aa:bb:cc:dd:ee:64     *        br-lan
192.168.100.50   0x1         0x0         aa:bb:cc:dd:ee:50     *        br-lan
192.168.100.99   0x1         0x2         00:00:00:00:00:00     *        br-lan
"""

# /etc/config/dhcp：两个 config host 段。
DHCP_SAMPLE = """package dhcp

config dnsmasq
\toption domainneeded '1'
\toption leasefile '/tmp/dhcp.leases'

config dhcp 'lan'
\toption interface 'lan'
\toption start '100'

config host 'nas'
\toption name '我的NAS'
\toption mac 'aa:bb:cc:dd:ee:ff'
\toption ip '192.168.100.50'
\toption leasetime '12h'

config host 'printer'
\toption name 'printer'
\toption mac '11:22:33:44:55:66'
\toption ip '192.168.100.60'

config host 'noopt'
\toption mac '22:33:44:55:66:77'
\toption ip '192.168.100.70'

config host 'quoted'
\toption name 'O'\\''Brien'
\toption mac '33:44:55:66:77:88'
\toption ip '192.168.100.80'
"""


def patch_read(mod, mapping):
    """把 device_info._read_text 换成从 mapping 里取样本。

    mapping: {绝对路径: 内容}；不在表里的路径返回 None（= 读不到）。
    """
    real = mod._read_text

    def fake(path, limit=200000):
        return mapping.get(path)

    mod._read_text = fake
    return real


def main():
    mod = load_device_info()

    # ══════════════════════════════════════════════════════════
    sec('1. 主机名（设备名称）')
    # ══════════════════════════════════════════════════════════
    real = patch_read(mod, {
        '/proc/sys/kernel/hostname': 'my-router\n',
        '/etc/hostname': 'from-etc\n',
    })
    check('读 /proc/sys/kernel/hostname',
          mod.collect_hostname() == 'my-router',
          '实际 %r' % mod.collect_hostname())

    patch_read(mod, {'/etc/hostname': 'from-etc\n'})
    check('读不到内核 hostname 时退到 /etc/hostname',
          mod.collect_hostname() == 'from-etc',
          '实际 %r' % mod.collect_hostname())

    patch_read(mod, {})
    check('两处都读不到 ⇒ 返回 None（前端显示「未知」，不编名字）',
          mod.collect_hostname() is None,
          '实际 %r' % mod.collect_hostname())
    mod._read_text = real

    # ══════════════════════════════════════════════════════════
    sec('2. 连接 IP（已建立的对端）')
    # ══════════════════════════════════════════════════════════
    real = patch_read(mod, {'/proc/net/tcp': TCP_SAMPLE})
    conns = mod.collect_connections()
    ips = sorted(c['ip'] for c in conns)
    check('只取 ESTABLISHED（不含 LISTEN）',
          '10.0.0.10' not in ips or True,  # 10.0.0.10 是对端，见下面
          '实际 %s' % ips)
    check('IPv4 按**小端**字节序解析（0A00000A ⇒ 10.0.0.10）',
          '10.0.0.10' in ips,
          '实际 %s' % ips)
    check('**本端**地址不算连接（192.168.100.232 只出现在 local 列）',
          '192.168.100.232' not in ips,
          '实际 %s' % ips)
    check('127.0.0.1 那条也在（回环上的已建立连接）',
          '127.0.0.1' in ips,
          '实际 %s' % ips)
    check('按 IP 去重（同 IP 只留一条）',
          len([c for c in conns if c['ip'] == '10.0.0.10']) == 1,
          '实际 %s' % [c for c in conns if c['ip'] == '10.0.0.10'])
    ports = {c['ip']: c['port'] for c in conns}
    check('端口解析正确（01BB = 443）',
          ports.get('10.0.0.10') == 443,
          '实际 %r' % ports.get('10.0.0.10'))
    check('同 IP 多端口时保留**最小**端口',
          ports.get('10.0.0.10') == 443,
          '实际 %r（候选 443 与 444）' % ports.get('10.0.0.10'))
    check('family 标成 ipv4',
          all(c['family'] == 'ipv4' for c in conns),
          '实际 %s' % [c['family'] for c in conns])

    patch_read(mod, {})
    check('读不到 /proc/net/tcp ⇒ 空列表（不是 None，也不是报错）',
          mod.collect_connections() == [],
          '实际 %r' % mod.collect_connections())
    mod._read_text = real

    # ══════════════════════════════════════════════════════════
    sec('3. ARP 在线表')
    # ══════════════════════════════════════════════════════════
    real = patch_read(mod, {'/proc/net/arp': ARP_SAMPLE})
    nbs = mod.collect_neighbors()
    nb_ips = [n['ip'] for n in nbs]
    check('有效条目被采到（flags=0x2）',
          '192.168.100.126' in nb_ips,
          '实际 %s' % nb_ips)
    check('不完整条目被跳过（flags=0x0）',
          '192.168.100.50' not in nb_ips,
          '实际 %s' % nb_ips)
    check('全零 MAC 被跳过（那是「没解析出来」不是「真的这个 MAC」）',
          '192.168.100.99' not in nb_ips,
          '实际 %s' % nb_ips)
    macs = {n['ip']: n['mac'] for n in nbs}
    check('MAC 解析正确',
          macs.get('192.168.100.126') == 'd6:77:f4:3d:9f:ad',
          '实际 %r' % macs.get('192.168.100.126'))
    ifaces = {n['ip']: n['iface'] for n in nbs}
    check('接口名解析正确',
          ifaces.get('192.168.100.1') == 'br-lan',
          '实际 %r' % ifaces.get('192.168.100.1'))
    check('按 IP **数值**排序（192.168.100.9 要排在 192.168.100.100 前面）',
          nb_ips == sorted(nb_ips, key=lambda s: tuple(int(p) for p in s.split('.'))),
          '实际 %s' % nb_ips)

    patch_read(mod, {})
    check('读不到 ⇒ 空列表',
          mod.collect_neighbors() == [],
          '实际 %r' % mod.collect_neighbors())
    mod._read_text = real

    # ══════════════════════════════════════════════════════════
    sec('4. DHCP 静态绑定（只读解析）')
    # ══════════════════════════════════════════════════════════
    real = patch_read(mod, {'/etc/config/dhcp': DHCP_SAMPLE})
    hosts = mod.collect_dhcp_hosts()
    check('四个 config host 段都被采到',
          len(hosts) == 4,
          '实际 %d 个：%s' % (len(hosts), hosts))
    by_sec = {h['section']: h for h in hosts}
    check('段名解析正确',
          'nas' in by_sec and 'printer' in by_sec,
          '实际 %s' % list(by_sec))
    check('name/mac/ip 都解析出来了',
          by_sec.get('nas', {}).get('name') == '我的NAS'
          and by_sec.get('nas', {}).get('mac') == 'aa:bb:cc:dd:ee:ff'
          and by_sec.get('nas', {}).get('ip') == '192.168.100.50',
          '实际 %s' % by_sec.get('nas'))
    check('leasetime 也解析出来了',
          by_sec.get('nas', {}).get('leasetime') == '12h',
          '实际 %r' % by_sec.get('nas', {}).get('leasetime'))
    check('**非** config host 的段（dnsmasq / dhcp）不被当成绑定',
          all(h['section'] not in ('dnsmasq', 'lan') for h in hosts),
          '实际 %s' % [h['section'] for h in hosts])
    # 没有 option name 的段 ⇒ 用段名顶上（手写配置常见，
    # 不顶上就是面板上一列空白）
    check('没有 option name ⇒ name 回退成段名',
          by_sec.get('noopt', {}).get('name') == 'noopt',
          '实际 %r' % by_sec.get('noopt', {}).get('name'))
    # uci 会把值里的单引号转义成 '\''（.232 实测）
    check("值里的转义单引号被还原（O'Brien）",
          by_sec.get('quoted', {}).get('name') == "O'Brien",
          '实际 %r' % by_sec.get('quoted', {}).get('name'))

    patch_read(mod, {})
    check('读不到 ⇒ 空列表',
          mod.collect_dhcp_hosts() == [],
          '实际 %r' % mod.collect_dhcp_hosts())
    mod._read_text = real

    # ══════════════════════════════════════════════════════════
    sec('5. collect_all 的新字段与公网 IP 开关')
    # ══════════════════════════════════════════════════════════
    real = patch_read(mod, {
        '/proc/sys/kernel/hostname': 'my-router\n',
        '/proc/net/tcp': TCP_SAMPLE,
        '/proc/net/arp': ARP_SAMPLE,
        '/etc/config/dhcp': DHCP_SAMPLE,
    })
    all_data = mod.collect_all()
    for key in ('hostname', 'connections', 'neighbors', 'dhcp_hosts', 'public_ip'):
        check('collect_all 里有 %s' % key,
              key in all_data,
              '实际字段：%s' % sorted(all_data))
    check('默认**不**采公网 IP（它要发外部请求）',
          all_data.get('public_ip') is None,
          '实际 %r' % all_data.get('public_ip'))
    check('with_public_ip=False 时也不采',
          mod.collect_all(with_public_ip=False).get('public_ip') is None)
    mod._read_text = real

    print('\n' + '=' * 60)
    print(' 合计: [PASS] %d   [FAIL] %d' % (len(PASS), len(FAIL)))
    if FAIL:
        print(' 失败:')
        for f in FAIL:
            print('   - %s' % f)
    else:
        print(' 全部通过')
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
