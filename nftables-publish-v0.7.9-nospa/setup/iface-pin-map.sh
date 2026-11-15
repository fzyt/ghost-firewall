#!/bin/sh
# 生成/刷新「MAC → 固定接口名」映射表。
#
# 用法：iface-pin-map.sh <映射文件>
#   映射表格式：JSON  {"<mac>": "<固定名>"}
#
# 为什么要有它（2026-11-15 在 .232 实测查实）：
#   Linux 给网卡编号（eth0/eth1/…）的规则是**按驱动上报设备的顺序**，
#   不是按 PCI 槽位，也不是按 MAC。
#   在 Proxmox 上加 vNIC 时，新网卡是**运行期**才被内核 enable 的
#   （实测：.232 上第三张网卡在开机 5.9 天后才 enable，拿到 eth2），
#   ⇒ 下次开机的编号顺序可能变 ⇒ /etc/config/network 里的
#   `list ports 'eth0'` 会指向另一块物理卡 ⇒ 表现为「接口对应关系变了」。
#
#   MAC 才是网卡的硬件身份 ⇒ 记住「哪块卡该叫哪个名字」，
#   开机时按 MAC 改名把它纠正回来（见 setup/iface-pin.sh）。
#
# ⚠ 刷新时机必须是「名字还正确」的时刻：
#   · 装机时
#   · /etc/config/network 变化时（init 脚本的 procd reload 触发器）
#   · 面板改 LAN 成员口时
#   在「漂移已经发生」的时刻刷新，会把错名字固化成"正确名字"，比不刷更糟。
set -u

MAP_FILE="${1:-/etc/nftables/iface-pin.json}"
# SYSFS 可被环境变量覆盖 —— 判据要用假 sysfs 树跑这个脚本
SYSFS=${SYSFS:-/sys/class/net}

python3 - "$MAP_FILE" "$SYSFS" <<'PYEOF'
import json
import os
import sys

MAP_PATH, NETDIR = sys.argv[1], sys.argv[2]

# 腾位时用的临时名后缀 —— 这种名字绝不能写进映射表
TMP_MARK = '-pin-tmp'


def load_old():
    """读旧映射表。

    旧表里的名字是「已经定下的固定名」—— MAC 是硬件身份，
    名字一旦定下就不该再变，哪怕这块卡此刻叫别的名字（漂移已发生），
    也要按旧表纠正回去。
    """
    try:
        with open(MAP_PATH, encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out = {}
    for mac, name in data.items():
        if not isinstance(name, str) or not name:
            continue
        mac = str(mac).strip().lower()
        if mac:
            out[mac] = name.strip()
    return out


def physical_ifaces():
    """只列**物理口**（device 是真实子目录，不是自指）。

    bridge / vlan / dummy 的 device 指向自己或不存在 ⇒ 必须排除。
    ⚠ 2026-11-15 .232 实测事故：对有成员口的 bridge 执行改名，
      内核既不拒绝也不返回 —— 命令挂死，把网络拖垮。
      所以「哪些是物理口」这个判断是安全底线，不是锦上添花。
    """
    out = []
    try:
        names = sorted(os.listdir(NETDIR))
    except OSError:
        return out
    for name in names:
        if name == 'lo':
            continue
        dev = os.path.join(NETDIR, name, 'device')
        if not os.path.isdir(dev):
            continue
        try:
            if os.path.realpath(dev) == os.path.realpath(os.path.join(NETDIR, name)):
                continue
        except OSError:
            continue
        try:
            with open(os.path.join(NETDIR, name, 'address')) as f:
                mac = f.read().strip().lower()
        except OSError:
            continue
        if mac:
            out.append((name, mac))
    return out


def main():
    old = load_old()
    present = physical_ifaces()
    if not present:
        print('没找到物理网卡，映射表保持原样')
        return 0

    present_macs = set(mac for _, mac in present)
    by_name = {}
    for name, mac in present:
        by_name.setdefault(name, mac)

    data = {}
    claimed = set()

    # 1) 旧表里还插着的卡 ⇒ 固定名不变
    for mac, name in old.items():
        if mac in present_macs and name not in claimed:
            data[mac] = name
            claimed.add(name)

    # 2) 旧表里没插着的卡（插槽换了卡）⇒ 名字交给现在占着它的卡
    for mac, name in old.items():
        if mac in present_macs or name in claimed:
            continue
        holder = by_name.get(name)
        if holder and holder not in data:
            data[holder] = name
            claimed.add(name)

    # 3) 新卡 ⇒ 用当前名字
    for name, mac in present:
        if mac in data:
            continue
        if TMP_MARK in name:
            # 腾位留下的临时名，不是稳定名 ⇒ 不钉
            continue
        if name in claimed:
            # 名字已被别的卡占了（换卡且旧卡还在）⇒ 先不钉，等下次刷新
            continue
        data[mac] = name
        claimed.add(name)

    d = os.path.dirname(MAP_PATH)
    if d:
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
    tmp = MAP_PATH + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write('\n')
    os.replace(tmp, MAP_PATH)
    try:
        os.chmod(MAP_PATH, 0o640)
    except OSError:
        pass

    print('映射表: %s (%d 条)' % (MAP_PATH, len(data)))
    for mac, name in sorted(data.items()):
        print('  %s -> %s' % (mac, name))
    return 0


sys.exit(main())
PYEOF
