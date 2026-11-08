#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
设备基本信息采集（路由器「系统信息」页的数据源）。

为什么单独一个模块
------------------
`app.py` 已经 13500 行，再往里塞系统信息采集会让它更难读。
这个模块只做一件事：**只读地**把设备事实采出来，采不到就如实说采不到。

采集原则（这几条是硬约束，不是风格偏好）
----------------------------------------
1. **只读**：只读 `/proc`、`/sys`、`/etc` 下的文件，不写任何东西、
   不执行任何会改状态的命令。
2. **不依赖 ubus / rpcd**：OpenWrt 的 ubus 走本地 socket，
   `POST /ubus` 会被 rpcd 的 ACL 挡（`/usr/share/rpcd/acl.d/` 里
   默认没有任何规则授权 `system.*`）。面板跑在 nginx 后面、
   权限也被降过 ⇒ 走 ubus 既不可靠也不安全。
   凡是 `/proc`、`/sys`、`/etc` 能读到的，一律直接读文件。
3. **读不到就返回 None，不猜**：宁可页面上显示「未知」，
   也不要显示一个编出来的数字。
   （这一条是本轮对账反复强调的：面板说谎比面板报错更危险。）
4. **不泄露敏感信息**：本模块采集的东西**全部**可以安全地显示在页面上。
   需要敏感值的地方（如 PPPoE 密码）根本不采集。

为什么不用 `os.uname()` 拿内核版本、而要读 `/etc/openwrt_release`
------------------------------------------------------------------------
`os.uname()` 给的是**内核**版本（Linux 5.10.x），
而用户想看的是**固件**版本（OpenWrt 25.12.5）—— 两者不是一回事，
混起来显示会误导（以为固件升了，其实只是内核不同）。
两个都采，分别标清楚。

OpenWrt 上的环境差异（真机上要重点验的）
-----------------------------------------
这个采集器是为 **OpenWrt / BusyBox** 写的，但开发机是 Debian，
两者在内核接口上有几处不一致。每一条都标了兜底：

  `/proc/net/fib_trie`   依赖内核 CONFIG_FIB_TRIES，OpenWrt 上不一定开
                        ⇒ 读不到时退到 `getifaddrs`（libc 标准函数，musl 也有）
  `/sys/class/net/*/ipv4` 较新的内核（5.15+）已经没有这个目录
                        ⇒ 不用它，IPv4 走 route+fib_trie / getifaddrs
  `/proc/net/if_inet6`  IPv6 关掉时不存在 ⇒ 采不到就是空列表，不是错
  `ubus` / `rpcd`       走本地 socket，`POST /ubus` 会被 ACL 挡
                        ⇒ **完全不用**，只用 /proc /sys /etc

所有采集路径在读不到时都返回 None / 空列表，**不会抛异常** ——
「这台设备上没这个文件」是常态，不是故障。
"""
import os
import re

# ── 单个文件读取的小工具 ────────────────────────────────────
#
# 全部吞掉异常并返回 None：设备上缺文件是常态
# （不是所有部署模式都有 /etc/openwrt_release —— linux_gateway 模式就没有），
# 缺了不该让整个页面 500。


def _read_text(path, limit=200000):
    """读文本文件，失败返回 None。"""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read(limit)
    except (OSError, IOError, UnicodeError):
        return None


def _read_first_line(path):
    txt = _read_text(path, 4096)
    if not txt:
        return None
    line = txt.splitlines()[0].strip() if txt.splitlines() else ''
    return line or None


# ── 固件 / 系统版本 ──────────────────────────────────────────


def collect_os_release():
    """系统版本。

    返回 dict：
      pretty_name  「OpenWrt 25.12.5」这种给人看的
      version      版本号本身
      distro       发行版名
      kernel       内核版本（与固件版本**不是一回事**，分开显示）
    """
    out = {'pretty_name': None, 'version': None, 'distro': None, 'kernel': None}

    # ── OpenWrt 专有：/etc/openwrt_release ──
    txt = _read_text('/etc/openwrt_release', 8192)
    if txt:
        # 格式：DISTRIB_ID='OpenWrt'
        #       DISTRIB_RELEASE='25.12.5'
        #       DISTRIB_REVISION='r1'
        #       DISTRIB_TARGET='x86/64'
        vals = {}
        for line in txt.splitlines():
            m = re.match(r"^(\w+)='(.*)'\s*$", line.strip())
            if m:
                vals[m.group(1)] = m.group(2)
        distro = vals.get('DISTRIB_ID')
        release = vals.get('DISTRIB_RELEASE')
        revision = vals.get('DISTRIB_REVISION')
        target = vals.get('DISTRIB_TARGET')
        if distro:
            out['distro'] = distro
            pretty = distro
            if release:
                out['version'] = release
                pretty += ' ' + release
            if revision:
                pretty += ' ' + revision
            if target:
                pretty += ' (' + target + ')'
            out['pretty_name'] = pretty

    # ── 通用发行版：/etc/os-release ──
    if not out['pretty_name']:
        txt = _read_text('/etc/os-release', 8192)
        if txt:
            vals = {}
            for line in txt.splitlines():
                m = re.match(r"^(\w+)=(.*)$", line.strip())
                if m:
                    v = m.group(2).strip().strip('"').strip("'")
                    vals[m.group(1)] = v
            name = vals.get('PRETTY_NAME') or vals.get('NAME')
            if name:
                out['pretty_name'] = name
                out['distro'] = vals.get('NAME')
                out['version'] = vals.get('VERSION_ID')

    # ── 内核版本 ──
    try:
        un = os.uname()
        out['kernel'] = '%s %s' % (un.release, un.machine)
    except Exception:
        pass
    return out


# ── CPU ──────────────────────────────────────────────────────


def collect_cpu():
    """CPU 信息。

    model    型号（读不到就是 None，不编）
    cores    逻辑核数
    mhz      主频 MHz（读不到就是 None）
    arch     架构
    """
    out = {'model': None, 'cores': None, 'mhz': None, 'arch': None}

    # 型号：ARM 上在 /proc/cpuinfo，x86 上要靠别的办法。
    txt = _read_text('/proc/cpuinfo', 65536)
    if txt:
        m = re.search(r"^model name\s*:\s*(.+)$", txt, re.M)
        if m:
            out['model'] = m.group(1).strip()
        else:
            m = re.search(r"^Processor\s*:\s*(.+)$", txt, re.M)
            if m:
                out['model'] = m.group(1).strip()
            else:
                # ARM 常见：Hardware : BCM2835 之类
                m = re.search(r"^Hardware\s*:\s*(.+)$", txt, re.M)
                if m:
                    out['model'] = m.group(1).strip()
        m = re.search(r"^cpu MHz\s*:\s*([\d.]+)", txt, re.M)
        if m:
            try:
                out['mhz'] = round(float(m.group(1)), 1)
            except ValueError:
                pass
        # 逻辑核数：processor / cpu 条目数
        n = len(re.findall(r"^processor\s*:", txt, re.M))
        if n:
            out['cores'] = n

    # 逻辑核数也可以从 /sys 数（更准，cpuinfo 在容器里可能不准）
    try:
        n = len([d for d in os.listdir('/sys/devices/system/cpu')
                 if re.match(r'^cpu\d+$', d)])
        if n:
            out['cores'] = n
    except OSError:
        pass

    try:
        out['arch'] = os.uname().machine
    except Exception:
        pass
    return out


# ── 内存 ─────────────────────────────────────────────────────


def collect_memory():
    """内存。

    total_kb  总量
    free_kb   可用（含 reclaimable 的粗略值）
    used_kb   已用
    """
    out = {'total_kb': None, 'free_kb': None, 'used_kb': None}
    txt = _read_text('/proc/meminfo', 65536)
    if not txt:
        return out
    vals = {}
    for line in txt.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(':'):
            try:
                vals[parts[0][:-1]] = int(parts[1])
            except ValueError:
                pass
    total = vals.get('MemTotal')
    if total is None:
        return out
    out['total_kb'] = total
    free = vals.get('MemAvailable')
    if free is None:
        free = vals.get('MemFree', 0)
        # 老内核没有 MemAvailable：把 cache/reclaimable 算成可用
        free += (vals.get('Cached', 0) + vals.get('SReclaimable', 0)
                 - vals.get('Shmem', 0))
        free = max(free, 0)
    out['free_kb'] = free
    out['used_kb'] = max(total - free, 0)
    return out


# ── 存储 ─────────────────────────────────────────────────────


def collect_storage():
    """根分区与挂载点占用。

    只报**真实占用**（按 statvfs 算），不读 df 的输出 ——
    BusyBox 的 df 输出格式各版本不一致，解析它反而脆。
    """
    out = {'total_kb': None, 'used_kb': None, 'free_kb': None, 'path': '/'}
    try:
        st = os.statvfs('/')
        # f_blocks 是块数，f_frsize 是每块字节数
        block = st.f_frsize if st.f_frsize else st.f_bsize
        out['total_kb'] = st.f_blocks * block // 1024
        out['free_kb'] = st.f_bavail * block // 1024
        used = (st.f_blocks - st.f_bfree) * block // 1024
        out['used_kb'] = max(used, 0)
    except (OSError, AttributeError, ValueError):
        pass
    return out


# ── 运行时间 ─────────────────────────────────────────────────


def collect_uptime():
    """开机时长。

    返回秒数；读不到就是 None。
    """
    txt = _read_first_line('/proc/uptime')
    if not txt:
        return None
    try:
        return int(float(txt.split()[0]))
    except (ValueError, IndexError):
        return None


# ── 网络接口 ─────────────────────────────────────────────────


def collect_interfaces():
    """网络接口清单。

    刻意**只读 /proc**：不调 `ip`、不跑 `ifconfig`、不用 netlink ——
    `ip`/`ifconfig` 在 BusyBox 上输出格式各异且要 fork 子进程；
    netlink 的 `recv` 在某些环境下会阻塞（实测本机就卡住），
    一个「显示系统信息」的页面不该有把面板请求挂住的风险。

    地址来源：
      · IPv6 → `/proc/net/if_inet6`（直接带接口名，最干净）
      · IPv4 → `/proc/net/route` 的网段 + `/proc/net/fib_trie` 的本地地址
    """
    # 先建「接口名 → 统计量」
    stats = {}
    txt = _read_text('/proc/net/dev', 65536)
    if txt:
        for line in txt.splitlines()[2:]:
            if ':' not in line:
                continue
            name, rest = line.split(':', 1)
            name = name.strip()
            if not name:
                continue
            fields = rest.split()
            if len(fields) < 16:
                continue
            try:
                stats[name] = {'rx_bytes': int(fields[0]), 'tx_bytes': int(fields[8])}
            except (ValueError, IndexError):
                continue

    if not stats:
        return []

    v4 = _ipv4_by_iface()
    v6 = _ipv6_by_iface()

    out = []
    for name in sorted(stats):
        if name == 'lo':
            # 回环对用户没有信息量，跳过（不是「假装它不存在」——
            # 页面展示的是「对外的接口」）。
            continue
        out.append({
            'name': name,
            'rx_bytes': stats[name]['rx_bytes'],
            'tx_bytes': stats[name]['tx_bytes'],
            'state': _iface_state(name),
            'ipv4': v4.get(name),
            'ipv6': v6.get(name),
        })
    return out


def _ipv6_by_iface():
    """`/proc/net/if_inet6` → {接口名: [地址, ...]}。

    格式：地址(32位十六进制) 作用域 前缀长度 标志 接口名
    标志第 2 位为 0x20 的是临时地址（不显示，那是隐私地址）。
    """
    out = {}
    txt = _read_text('/proc/net/if_inet6', 65536)
    if not txt:
        return out
    for line in txt.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        hex_addr, _scope, _prefix, flags, iface = parts[0], parts[1], parts[2], parts[3], parts[5]
        # 0x20 = temporary（RFC 4941 隐私地址），不展示
        try:
            if int(flags, 16) & 0x20:
                continue
        except ValueError:
            pass
        try:
            addr = socket_inet_ntop6(hex_addr)
        except Exception:
            continue
        out.setdefault(iface, []).append(addr)
    return out


def _ipv4_by_iface():
    """`/proc/net/route` + `/proc/net/fib_trie` → {接口名: [地址, ...]}。

    做法：
      1. `/proc/net/route` 给出「接口 → 该接口直连的网段」
      2. `/proc/net/fib_trie` 的 Main 表里，`host LOCAL` 的地址
         属于某个网段
      3. 两者按网段匹配 ⇒ 得到「这个地址配在哪个接口上」

    比 netlink 稳（纯文件），比解析 `ip addr` 稳（不 fork）。

    ⚠️ **`/proc/net/fib_trie` 依赖内核的 CONFIG_FIB_TRIES**，
    OpenWrt 上不一定开 ⇒ 采不到时必须退到 `getifaddrs`（libc 标准函数，
    musl 也有），不能就此显示「未知」。
    """
    nets_by_iface = _direct_nets_by_iface()
    if nets_by_iface:
        out = _ipv4_from_fib_trie(nets_by_iface)
        if out:
            return out
    # fib_trie 不可用（或采不到）⇒ 退到 getifaddrs
    return _ipv4_by_getifaddrs()


def _direct_nets_by_iface():
    """`/proc/net/route` → {接口名: ['网段', ...]}（只取直连网段）。"""
    nets_by_iface = {}
    txt = _read_text('/proc/net/route', 65536)
    if not txt:
        return nets_by_iface
    for line in txt.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        iface = parts[0]
        dest = parts[1]
        mask = parts[7]
        if dest == '00000000' or mask == '00000000':
            # 默认路由或掩码为 0 ⇒ 不是直连网段
            continue
        try:
            net = _hex_to_ipv4_cidr(dest, mask)
        except Exception:
            continue
        nets_by_iface.setdefault(iface, []).append(net)
    return nets_by_iface


def _ipv4_from_fib_trie(nets_by_iface):
    """在给定的「接口 → 网段」映射下，从 fib_trie 里找出本地地址。

    ⚠️ 两个踩过的坑，都记在这里免得再犯：
    #
    # 1. `Main:` 是**文件的第一行**（不是某个中间的分节）——
    #    第一次实现时按「先找 Main: 再往下读」写，结果 in_main 永远是 False。
    #    教训：别假设分节标记在文件中间。
    #
    # 2. 地址行与 `/32 host LOCAL` 是**两行**，地址在上面那行：
    #        |-- 192.168.100.249
    #           /32 host LOCAL
    #    第一次实现时把「以 /32 host LOCAL 结尾的行」当地址行去 split('/')，
    #    结果 split 出的是 ['/32 host LOCAL'] ⇒ body 是空串 ⇒ 一个都匹配不上。
    #    ⇒ 正确做法：记住**上一行**的地址，等看到 host LOCAL 时用它。
    #
    # 也不需要区分 Main: / Local: 两张表 —— 两张表里都有
    # `host LOCAL` 的地址，重复采到同一个地址去重即可。
    """
    out = {}
    txt = _read_text('/proc/net/fib_trie', 262144)
    if not txt:
        return out
    prev_addr = None
    for line in txt.splitlines():
        stripped = line.strip()
        if stripped.endswith('/32 host LOCAL'):
            body = prev_addr
            prev_addr = None
            if not body:
                continue
            for iface, nets in nets_by_iface.items():
                for net in nets:
                    try:
                        if _ipv4_in_cidr(body, net):
                            if body not in out.setdefault(iface, []):
                                out[iface].append(body)
                            break
                    except Exception:
                        continue
            continue
        # 记住「可能是一个地址」的行：`|-- 192.168.100.249`
        # （`+-- 192.168.100.0/24` 是网段，不是地址，带 / 的一律排除）
        m = re.match(r'^[\s|+\-]*([\d.]+)\s*$', stripped)
        if m:
            prev_addr = m.group(1)
        else:
            prev_addr = None
    return out


def _ipv4_by_getifaddrs():
    """`getifaddrs()` → {接口名: [IPv4, ...]}。

    这是 fib_trie 不可用时的兜底（内核没开 CONFIG_FIB_TRIES 时）。

    为什么用 ctypes 而不是 `ip addr`：
      · `ip` 在 BusyBox 上的输出格式各版本不一致，解析它脆
      · `ip` 要 fork 子进程，而这是个**展示型**接口，不值得

    为什么不用 netlink：
      实测本机 netlink 的 `recv` 会**阻塞**（收不到响应）——
      一个「显示系统信息」的页面不该有把面板请求挂住的风险。
    """
    try:
        import ctypes
        import ctypes.util
        import socket as _socket
        import struct as _struct

        libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6',
                            use_errno=True)

        class _SockAddr(ctypes.Structure):
            _fields_ = [('sa_family', ctypes.c_uint16),
                        ('sa_data', ctypes.c_byte * 14)]

        class _IfAddrs(ctypes.Structure):
            pass
        _IfAddrs._fields_ = [
            ('ifa_next', ctypes.POINTER(_IfAddrs)),
            ('ifa_name', ctypes.c_char_p),
            ('ifa_flags', ctypes.c_uint),
            ('ifa_addr', ctypes.POINTER(_SockAddr)),
            ('ifa_netmask', ctypes.POINTER(_SockAddr)),
            ('ifa_ifu', ctypes.POINTER(_SockAddr)),
            ('ifa_data', ctypes.c_void_p),
        ]

        head = ctypes.POINTER(_IfAddrs)()
        if libc.getifaddrs(ctypes.byref(head)) != 0:
            return {}
        out = {}
        cur = head
        AF_INET = 2
        while cur:
            item = cur.contents
            if item.ifa_addr:
                sa = item.ifa_addr.contents
                if sa.sa_family == AF_INET:
                    raw = ctypes.string_at(
                        ctypes.addressof(sa.sa_data) + 2, 4)
                    # sockaddr_in: sa_family(2) + sin_port(2) + sin_addr(4)
                    addr = _socket.inet_ntop(_socket.AF_INET, raw)
                    name = item.ifa_name.decode('utf-8', 'replace')
                    out.setdefault(name, []).append(addr)
            cur = item.ifa_next
        try:
            libc.freeifaddrs(head)
        except Exception:
            pass
        return out
    except Exception:
        return {}


def _hex_to_ipv4_cidr(hex_dest, hex_mask):
    """`/proc/net/route` 里的十六进制 → 'a.b.c.d/len'。

    ⚠️ `/proc/net/route` 的地址是**小端**字节序（`0064A8C0` = 192.168.100.0），
    而 `/proc/net/fib_trie` 里的是点分十进制。两者不能共用同一个转换函数 ——
    第一次实现时按大端解析，得到的网段是 `0.100.168.192/24`，
    于是每个地址都匹配不上，IPv4 一个都取不到。
    """
    dest = socket_inet_ntoa(hex_dest, little=True)
    mask = socket_inet_ntoa(hex_mask, little=True)
    # 前缀长度 = 掩码里连续的 1 的个数。
    # 掩码已经是点分十进制（255.255.255.0），要按 8 位一组数，
    # 不能把它当二进制串去 int(..., 2) —— 那会拿到 '2552552550' 报错。
    #
    # 连续性检查：**整体**必须是「高位若干个 1 + 低位若干个 0」。
    # 逐组检查八位组本身合不合法是不够的 ——
    # 255.0.255.0 的每一组都合法，但整体不连续（前缀长度算出来是 16，
    # 而这个掩码根本不是任何合法前缀）。
    bits = 0
    for octet in mask.split('.'):
        b = int(octet)
        if b not in (0, 128, 192, 224, 240, 248, 252, 254, 255):
            raise ValueError('mask not contiguous: %r' % mask)
        n = 0
        while n < 8 and (b & (0x80 >> n)):
            n += 1
        bits += n
    # 掩码的二进制必须是 111...1100...0 这样的连续形态：
    # 把点分十进制还原成 32 位整数，检查「取反后 +1 是 2 的幂」这个经典判据。
    m = 0
    for octet in mask.split('.'):
        m = (m << 8) | int(octet)
    if m == 0:
        return '%s/0' % dest
    inv = (~m) & 0xFFFFFFFF
    if (inv & (inv + 1)) != 0:
        raise ValueError('mask not contiguous: %r' % mask)
    return '%s/%d' % (dest, bits)


def _ipv4_in_cidr(addr, cidr):
    """判断 addr 是否落在 cidr 内（纯字符串算，避免依赖 ipaddress）。"""
    import ipaddress
    return ipaddress.ip_address(addr) in ipaddress.ip_network(cidr, strict=False)


def _iface_state(name):
    """接口状态：up / down / unknown。"""
    # /sys/class/net/<name>/operstate：up / down / unknown / dormant
    v = _read_first_line('/sys/class/net/%s/operstate' % name)
    if v:
        return v.strip()
    # 有些系统（容器里）没有 operstate，退回 flags
    try:
        with open('/sys/class/net/%s/flags' % name) as f:
            flags = int(f.read().strip(), 16)
        return 'up' if flags & 0x1 else 'down'
    except (OSError, IOError, ValueError):
        return None


def socket_inet_ntoa(hex_addr, little=False):
    """十六进制 IPv4 → 点分十进制。

    little=True 时按**小端**字节序解释（`/proc/net/route` 用这个）。
    """
    if len(hex_addr) != 8:
        raise ValueError('bad hex addr')
    b = bytes.fromhex(hex_addr)
    if little:
        b = b[::-1]
    return '%d.%d.%d.%d' % (b[0], b[1], b[2], b[3])


def socket_inet_ntop6(hex_addr):
    """把 /sys 里的十六进制 IPv6 转成压缩写法。"""
    if len(hex_addr) != 32:
        raise ValueError('bad hex addr')
    b = bytes.fromhex(hex_addr)
    import socket
    return socket.inet_ntop(socket.AF_INET6, b)


# ── 设备型号 ─────────────────────────────────────────────────


def collect_device_model():
    """设备型号。

    OpenWrt 上有两条路：
      · /etc/openwrt_release 的 DISTRIB_TARGET（编译目标，如 x86/64）
      · /tmp/sysinfo/model（真实硬件型号，如 GL-MT6000）
    优先要真实型号。
    """
    model = _read_first_line('/tmp/sysinfo/model')
    if model:
        return model.strip()
    # 有些设备是 board_name
    bn = _read_first_line('/tmp/sysinfo/board_name')
    if bn:
        return bn.strip()
    return None


# ── 汇总 ─────────────────────────────────────────────────────


def collect_all():
    """采全部信息，返回一个 dict。

    **任何一项采不到都不会抛异常** —— 缺项就是 None，
    由前端显示「未知」。这比让整个接口 500 要好得多：
    用户要看到的是「这台设备长什么样」，不是「采集器崩了」。
    """
    try:
        os_info = collect_os_release()
    except Exception:
        os_info = {'pretty_name': None, 'version': None, 'distro': None, 'kernel': None}
    try:
        cpu = collect_cpu()
    except Exception:
        cpu = {'model': None, 'cores': None, 'mhz': None, 'arch': None}
    try:
        mem = collect_memory()
    except Exception:
        mem = {'total_kb': None, 'free_kb': None, 'used_kb': None}
    try:
        storage = collect_storage()
    except Exception:
        storage = {'total_kb': None, 'used_kb': None, 'free_kb': None, 'path': '/'}
    try:
        interfaces = collect_interfaces()
    except Exception:
        interfaces = []
    try:
        uptime = collect_uptime()
    except Exception:
        uptime = None
    try:
        model = collect_device_model()
    except Exception:
        model = None

    return {
        'model': model,
        'os': os_info,
        'cpu': cpu,
        'memory': mem,
        'storage': storage,
        'uptime_seconds': uptime,
        'interfaces': interfaces,
    }
