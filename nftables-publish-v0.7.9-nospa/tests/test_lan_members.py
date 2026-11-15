#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LAN 桥成员口（多 LAN 口）的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_lan_members.py

这块功能的失败模式不是「配置不对」，是**整机失联**：
  · 把 WAN 口划进 LAN 桥 ⇒ WAN 没口了 ⇒ 断网；
  · 把 LAN 桥的成员清空 ⇒ 桥没 IP ⇒ 管理口失联，路由器变砖。

所以判据分两层：
  1. 纯函数层：改写桥段成员口的文本处理（加口/删口/位置不能跑偏）；
  2. 端点层：真调 GET/POST，断言**危险的操作被拒绝**、
     合法的操作真的写进了文件、备份也在。

假 sysfs 树 + 临时网络配置文件 ⇒ 不碰真机任何东西。
"""
import importlib.util as ilu
import json
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
    """加载面板模块（只测纯函数与端点，不启动服务）。"""
    spec = ilu.spec_from_file_location('_nftapp_lanmembers', os.path.join(BACKEND, 'app.py'))
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mod = load_app()

# ── /etc/config/network 样本（.232 真机形态的缩影）─────────────────
SAMPLE_CONFIG = """config interface 'loopback'
\toption device 'lo'
\toption proto 'static'
\toption ipaddr '127.0.0.1'
\toption netmask '255.0.0.0'

config globals 'globals'
\toption ula_prefix 'fd00::/48'

config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports 'eth0'

config interface 'lan'
\toption device 'br-lan'
\toption proto 'static'
\toption ipaddr '192.168.100.1'
\toption netmask '255.255.255.0'
\toption ip6assign '60'

config interface 'wan'
\toption device 'eth1'
\toption proto 'dhcp'
"""


def mk_iface(sysfs, name, mac):
    d = os.path.join(sysfs, name)
    os.makedirs(d)
    with open(os.path.join(d, 'address'), 'w') as f:
        f.write(mac + '\n')
    with open(os.path.join(d, 'operstate'), 'w') as f:
        f.write('up\n')
    return d


def make_env(tmpdir):
    """造一份假的网络配置文件 + 假 sysfs 树。返回 (配置文件路径, sysfs 根)。"""
    netconf = os.path.join(tmpdir, 'network')
    with open(netconf, 'w', encoding='utf-8') as f:
        f.write(SAMPLE_CONFIG)
    sysfs = os.path.join(tmpdir, 'class', 'net')
    os.makedirs(sysfs)
    mk_iface(sysfs, 'eth0', 'aa:bb:cc:00:00:01')
    mk_iface(sysfs, 'eth1', 'aa:bb:cc:00:00:02')
    mk_iface(sysfs, 'eth2', 'aa:bb:cc:00:00:03')
    b = mk_iface(sysfs, 'br-lan', 'aa:bb:cc:00:00:01')
    # bridge 的 device 指向自己 ⇒ 判「虚拟设备」
    os.symlink(b, os.path.join(b, 'device'))
    # eth0 已是 br-lan 成员（master 是指向桥的符号链接）
    os.symlink(b, os.path.join(sysfs, 'eth0', 'master'))
    return netconf, sysfs


def run_in_env(fn):
    """在一个干净的假环境里跑 fn(netconf, sysfs, refreshed)，结束后清理。"""
    tmp = tempfile.mkdtemp(prefix='lanmembers-')
    try:
        netconf, sysfs = make_env(tmp)
        mod.NETWORK_CONF_PATH = netconf
        mod.SYSFS_NET_ROOT = sysfs
        refreshed = []
        mod._refresh_iface_pin_map = lambda: refreshed.append(1) or True
        return fn(netconf, sysfs, refreshed)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ─────────────────────────────────────────────────────────────
sec('1  纯函数：认桥、读成员口、认被占用的口')

text = SAMPLE_CONFIG
check('能从 lan 接口认出桥设备名',
      mod._lan_bridge_device(text) == 'br-lan',
      str(mod._lan_bridge_device(text)))
check('能读出桥当前声明的成员口',
      mod._lan_bridge_ports(text, 'br-lan') == ['eth0'],
      str(mod._lan_bridge_ports(text, 'br-lan')))
check('能认出 WAN 口（配置里 wan 用的设备）',
      mod._wan_config_device(text) == 'eth1',
      str(mod._wan_config_device(text)))

check('能从默认路由的输出里认出接口名（谁是 WAN 的硬证据）',
      mod._default_route_dev('default via 192.168.1.1 dev eth1 src 192.168.1.2') == 'eth1',
      str(mod._default_route_dev('default via 192.168.1.1 dev eth1 src 192.168.1.2')))
check('没有默认路由时返回空',
      mod._default_route_dev('') == '')

reserved = mod._reserved_lan_devices(text, 'br-lan')
check('WAN 口在「不可划进 LAN」名单里',
      'eth1' in reserved, str(sorted(reserved)))
check('★ 当前 LAN 成员口不在「不可划进 LAN」名单里（否则永远改不动）',
      'eth0' not in reserved, str(sorted(reserved)))
check('空闲的物理口不在名单里（否则加不进去）',
      'eth2' not in reserved, str(sorted(reserved)))

# 别的桥占着的口 ⇒ 也是reserved
text2 = text.replace("config interface 'wan'", """config device
\toption name 'br-guest'
\toption type 'bridge'
\tlist ports 'eth2'

config interface 'wan'""")
reserved2 = mod._reserved_lan_devices(text2, 'br-lan')
check('★ 别的桥段里的成员口也算被占用',
      'eth2' in reserved2, str(sorted(reserved2)))

# ─────────────────────────────────────────────────────────────
sec('2  纯函数：改写桥段成员口')

new = mod._rewrite_bridge_ports(text, 'br-lan', ['eth0', 'eth2'])
check('★ 加口后能读回两个成员口',
      mod._lan_bridge_ports(new, 'br-lan') == ['eth0', 'eth2'],
      str(mod._lan_bridge_ports(new, 'br-lan')))
check('★ 改写没有动到 lan 接口段（IP/协议还在）',
      "option ipaddr '192.168.100.1'" in new
      and "option proto 'static'" in new)
check('★ 改写没有动到 wan 接口段',
      "option device 'eth1'" in new)
check('★ 改写没有动到 globals 段',
      "option ula_prefix 'fd00::/48'" in new)
check('★ 桥段里的旧 ports 行被替换掉了（不是追加）',
      new.count("list ports 'eth0'") == 1
      and "list ports 'eth2'" in new,
      str([l for l in new.splitlines() if 'ports' in l]))
check('★ ports 行没有跑到 lan 段里（UCI 的段由下一个 config 行结束）',
      mod._uci_body_option(
          [l for st, n, b in mod._uci_sections(new)
           if st == 'interface' and n == 'lan' for l in b], 'device') == 'br-lan'
      and 'ports' not in '\n'.join(
          [l for st, n, b in mod._uci_sections(new)
           if st == 'interface' and n == 'lan' for l in b]),
      'ports 跑到别的段里 = uci 会把它当成下一段的配置')

removed = mod._rewrite_bridge_ports(text, 'br-lan', ['eth2'])
check('★ 删口后能读回剩下的成员口',
      mod._lan_bridge_ports(removed, 'br-lan') == ['eth2'],
      str(mod._lan_bridge_ports(removed, 'br-lan')))
check('★ 找不到桥段时返回 None（而不是把配置改坏）',
      mod._rewrite_bridge_ports(text, 'br-nonexistent', ['eth0']) is None)

# ─────────────────────────────────────────────────────────────
sec('3  端点：GET /api/network/lan-members')

app = mod.app
app.before_request_funcs[None] = []
app.config['TESTING'] = True


def _get():
    cli = app.test_client()
    r = cli.get('/api/network/lan-members')
    return r, (r.get_json() or {})


def _post(members):
    cli = app.test_client()
    r = cli.post('/api/network/lan-members', json={'members': members})
    return r, (r.get_json() or {})


def _do_get(netconf, sysfs, refreshed):
    cli = app.test_client()
    r = cli.get('/api/network/lan-members')
    return r, (r.get_json() or {})


r, body = run_in_env(_do_get)
check('GET 返回 200', r.status_code == 200, str(r.status_code))
check('GET 给出桥名', body.get('bridge') == 'br-lan', str(body)[:200])
check('GET 给出当前成员口', body.get('members') == ['eth0'], str(body)[:200])
roles = {c['name']: c['role'] for c in (body.get('candidates') or [])}
check('GET 认得出 eth0 已在 LAN', roles.get('eth0') == 'lan', str(roles))
check('GET 认得出 eth1 是 WAN 口', roles.get('eth1') == 'wan', str(roles))
check('GET 认得出 eth2 是空闲口', roles.get('eth2') == 'free', str(roles))
check('GET 不把桥本身列成候选口', 'br-lan' not in roles, str(roles))

# ─────────────────────────────────────────────────────────────
sec('4  端点：POST /api/network/lan-members —— 合法写入')

def _do_post_add(netconf, sysfs, refreshed):
    r, body = _post(['eth0', 'eth2'])
    with open(netconf, encoding='utf-8') as f:
        after = f.read()
    backup = os.path.exists(netconf + '.backup')
    return r, body, after, backup, len(refreshed)


r, body, after, backup, refreshed_count = run_in_env(_do_post_add)
check('POST 加口返回 200', r.status_code == 200, str(r.status_code) + ' ' + str(body)[:160])
check('POST 返回的成员口正确', body.get('members') == ['eth0', 'eth2'], str(body)[:200])
check('★ 文件里真的多了一个成员口',
      "list ports 'eth2'" in after,
      str([l for l in after.splitlines() if 'ports' in l]))
check('★ 原成员口还在', "list ports 'eth0'" in after,
      str([l for l in after.splitlines() if 'ports' in l]))
check('★ 写之前留了备份（含 PPPoE 口令 ⇒ 权限跟原文件一致）', backup)
check('★ 写完会刷新接口名钉定映射表（新口必须被钉住）', refreshed_count == 1,
      '刷新次数 %d' % refreshed_count)
check('★ 保存后的提示里说明了「要重启网络」',
      '重启网络' in (body.get('message') or ''), str(body.get('message')))

# ─────────────────────────────────────────────────────────────
sec('5  端点：POST —— 危险操作必须被拒绝（失联保护）')


def _post_expect_reject(members, label, code=None):
    def _run(netconf, sysfs, refreshed):
        with open(netconf, encoding='utf-8') as f:
            before = f.read()
        r, body = _post(members)
        with open(netconf, encoding='utf-8') as f:
            after = f.read()
        check(label + ' ⇒ 被拒绝（4xx）',
              400 <= r.status_code < 500,
              'status=%s body=%s' % (r.status_code, str(body)[:120]))
        if code:
            check(label + ' ⇒ 错误码是 ' + code,
                  body.get('code') == code,
                  str(body.get('code')))
        check(label + ' ⇒ 原配置一个字都没动',
              before == after)

    run_in_env(_run)


_post_expect_reject([], '成员口列表为空（清空 LAN 桥 = 失联）', 'INVALID_MEMBERS')
_post_expect_reject(['eth0', 'eth1'], '把 WAN 口划进 LAN 桥', 'PORT_RESERVED')
_post_expect_reject(['eth0', 'br-lan'], '把桥本身当成员口', 'INVALID_MEMBERS')
_post_expect_reject(['eth0', 'eth0.10'], '把 VLAN 子接口当成员口', 'INVALID_MEMBERS')
_post_expect_reject(['eth0', 'eth9'], '本机不存在的口', 'INVALID_MEMBERS')
_post_expect_reject(['eth0', 'lan'], '不存在的口名（不是物理网卡）', 'INVALID_MEMBERS')

# 非列表
tmp = tempfile.mkdtemp(prefix='lanmembers-')
try:
    netconf, sysfs = make_env(tmp)
    mod.NETWORK_CONF_PATH = netconf
    mod.SYSFS_NET_ROOT = sysfs
    cli = app.test_client()
    r = cli.post('/api/network/lan-members', json={'members': 'eth0'})
    check('members 不是列表 ⇒ 被拒绝', 400 <= r.status_code < 500, str(r.status_code))
    r = cli.post('/api/network/lan-members', json={})
    check('请求体没有 members ⇒ 被拒绝', 400 <= r.status_code < 500, str(r.status_code))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# ─────────────────────────────────────────────────────────────
sec('6  端点：非桥配置的机器要说清原因（不留空白）')

tmp = tempfile.mkdtemp(prefix='lanmembers-')
try:
    netconf, sysfs = make_env(tmp)
    # 老式 swconfig：LAN 口直接列在 lan 接口的 option ifname 里，没有桥段
    with open(netconf, 'w', encoding='utf-8') as f:
        f.write("""config interface 'lan'
\toption ifname 'eth0'
\toption proto 'static'
\toption ipaddr '192.168.100.1'
\toption netmask '255.255.255.0'
""")
    mod.NETWORK_CONF_PATH = netconf
    mod.SYSFS_NET_ROOT = sysfs
    cli = app.test_client()
    r = cli.get('/api/network/lan-members')
    body = r.get_json() or {}
    check('非桥配置 ⇒ GET 明确报错而不是返回空列表',
          r.status_code == 400 and body.get('code') == 'NO_LAN_BRIDGE',
          'status=%s body=%s' % (r.status_code, str(body)[:160]))
    check('★ 报错文案告诉用户去 OpenWrt 手工配置',
          'OpenWrt' in (body.get('message') or ''), str(body.get('message')))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# ─────────────────────────────────────────────────────────────
sec('7  故障注入：写进去的内容跟请求对不上 ⇒ 必须回读校验并回滚')


def _do_fault(netconf, sysfs, refreshed):
    # 假装「改写函数写错了」（比如漏写一个口、或者写串了段）——
    # 端点必须靠**回读**发现不对并回滚，而不是照样报成功。
    orig = mod._rewrite_bridge_ports
    mod._rewrite_bridge_ports = (
        lambda text, bridge, ports:
        text.replace("list ports 'eth0'", "list ports 'eth9'"))
    try:
        r, body = _post(['eth0', 'eth2'])
        with open(netconf, encoding='utf-8') as f:
            after = f.read()
        return r, body, after
    finally:
        mod._rewrite_bridge_ports = orig


r, body, after = run_in_env(_do_fault)
check('★ 写入内容与请求不一致 ⇒ 端点报失败（不是假装成功）',
      r.status_code >= 400,
      'status=%s body=%s' % (r.status_code, str(body)[:160]))
check('★ 回滚后原配置回来了',
      "list ports 'eth0'" in after and "list ports 'eth9'" not in after,
      str([l for l in after.splitlines() if 'ports' in l]))
check('★ 回滚后桥成员口仍是原来那一个',
      mod._lan_bridge_ports(after, 'br-lan') == ['eth0'],
      str(mod._lan_bridge_ports(after, 'br-lan')))


# ─────────────────────────────────────────────────────────────
sec('8  wan 段不写口名的机器：靠内核默认路由认出 WAN')


def _do_auto_wan(netconf, sysfs, refreshed):
    # 造一台「wan 段不写 option device」的机器 ——
    # 这种机器上 WAN 口是 netifd 自动挑的，配置里根本没有它的名字。
    with open(netconf, 'w', encoding='utf-8') as f:
        f.write("""config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports 'eth0'

config interface 'lan'
\toption device 'br-lan'
\toption proto 'dhcp'
""")
    # 内核视角：默认路由走 eth1 ⇒ eth1 就是 WAN
    orig = mod._default_route_dev
    mod._default_route_dev = lambda route_output=None: 'eth1'
    try:
        r, body = _post(['eth0', 'eth1'])
        with open(netconf, encoding='utf-8') as f:
            after = f.read()
        return r, body, after
    finally:
        mod._default_route_dev = orig


r, body, after = run_in_env(_do_auto_wan)
check('★ wan 段没写口名时：靠默认路由认出 WAN 并拒绝划进 LAN',
      r.status_code == 400 and body.get('code') == 'PORT_RESERVED',
      'status=%s body=%s' % (r.status_code, str(body)[:160]))
check('★ 拒绝后原配置一个字都没动',
      "list ports 'eth0'" in after and "list ports 'eth1'" not in after,
      str([l for l in after.splitlines() if 'ports' in l]))


print()
if FAIL:
    print('[FAIL] 失败 %d 项：' % len(FAIL))
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print('[PASS] 通过 %d / %d' % (len(PASS), len(PASS)))
print('全部通过')
