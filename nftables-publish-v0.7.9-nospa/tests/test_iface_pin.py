#!/usr/bin/env python3
"""接口名钉定（iface-pin）的行为级判据。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_iface_pin.py

为什么要有这个
--------------
`setup/iface-pin.sh` 干的事是「按 MAC 把网卡改名成固定名字」，
目的是解决「重启后 eth0/eth1/eth2 对应的物理口会漂」。

这个脚本的风险极高：改错一个接口名 = 路由器失联。
2026-11-15 在 .232 上就因为**没排除 bridge**（对 br-lan 执行改名）
把网络拖垮了 —— 内核对有成员口的 bridge 改名既不拒绝也不返回，命令挂死。

⇒ 判据必须覆盖：
  1. **虚拟设备（bridge/vlan/dummy）绝不被改名** —— 挂死会让路由器失联
  2. **只在开机时改名**（系统里已有桥就整体跳过）—— 运行期改名会拆桥
  3. **改名失败不中断整体** —— 一个口失败不能把后面的口全跳过
  4. **按 MAC 找口** —— 名字是随机的，MAC 才是身份
  5. **目标名被占用时先腾位** —— 互占时两个都跳过 = 永远纠正不回来

怎么测
------
真机上没法随便制造多网卡，也没法随便制造 bridge 改名挂死。
所以判据用**假 sysfs 树**：
  - 造一棵 /sys/class/net 的替身，里面有真接口目录、bridge、vlan
  - 把脚本里的 SYSFS 换成这棵树（脚本支持环境变量覆盖）
  - 用假的 `ip` 命令桩住内核调用，**并且真的把假 sysfs 里的目录改名**
    ⇒ 判据断言的是**最终状态**（谁叫什么名字），不是调用序列

沙箱运行：只抽函数、桩掉外部命令，不碰真实路径、不碰真实网卡。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'setup', 'iface-pin.sh')
MAPGEN = os.path.join(ROOT, 'setup', 'iface-pin-map.sh')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('[PASS] ' if ok else '[FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


SCRIPT_SRC = open(SCRIPT, encoding='utf-8').read()
MAPGEN_SRC = open(MAPGEN, encoding='utf-8').read()


def strip_sh_comments(src):
    """剥掉 shell 注释，保留引号内的 # 。

    为什么需要：setup.sh 的教训 —— 注释里写着关键信息时，
    「代码里有没有 XXX」的静态断言会被注释顶住。
    """
    out = []
    for line in src.splitlines():
        st = line.lstrip()
        if st.startswith('#'):
            continue
        in_s = in_d = False
        cut = None
        for idx, ch in enumerate(line):
            if ch == "'" and not in_d:
                in_s = not in_s
            elif ch == '"' and not in_s:
                in_d = not in_d
            elif ch == '#' and not in_s and not in_d:
                if idx == 0 or line[idx - 1] in ' \t':
                    cut = idx
                    break
        out.append(line if cut is None else line[:cut])
    return '\n'.join(out)


# ─────────────────────────────────────────────────────────────
sec('1  两个脚本都在，且基本结构正确')

check('setup/iface-pin.sh 存在', os.path.exists(SCRIPT))
check('setup/iface-pin-map.sh 存在', os.path.exists(MAPGEN))
check('脚本有可执行位或至少是可读文本',
      os.path.exists(SCRIPT) and os.path.getsize(SCRIPT) > 0,
      f'{os.path.getsize(SCRIPT) if os.path.exists(SCRIPT) else 0} 字节')

# ── 执行位：这是 2026-11-15 真机踩到的坑 ──
# 部署用 `tar -x` 传输，**保留文件权限** ⇒ git 索引里的 mode 直接决定设备上的 mode。
# 源文件是 100644 时，设备上就是 -rw-rw-r-- ⇒ S15 钩子开机时 Permission denied (rc=126)
# ⇒ 钉名保护静默失效（只有手动跑过 setup.sh 才会被 chmod 755 救回来）。
# 所以这里同时卡两道：磁盘可执行位 + git 索引 100755。
for _p, _label in ((SCRIPT, 'setup/iface-pin.sh'),
                   (MAPGEN, 'setup/iface-pin-map.sh')):
    check(f'{_label} 在磁盘上可执行（os.access X_OK）',
          os.path.exists(_p) and os.access(_p, os.X_OK),
          oct(os.stat(_p).st_mode & 0o777) if os.path.exists(_p) else '文件不存在')

# git 索引 mode 检查：git 不可用 / 不在仓库内时跳过，不让判据因环境而红
def _git_index_mode(path):
    """返回 git 索引里的 mode（如 '100755'）；查不到返回 None。"""
    try:
        top = subprocess.run(['git', '-C', ROOT, 'rev-parse', '--show-toplevel'],
                             capture_output=True, text=True, timeout=15)
        if top.returncode != 0:
            return None
        rel = os.path.relpath(path, top.stdout.strip())
        out = subprocess.run(['git', '-C', top.stdout.strip(), 'ls-files', '-s', '--', rel],
                             capture_output=True, text=True, timeout=15)
        if out.returncode != 0 or not out.stdout.strip():
            return None
        return out.stdout.split()[0]
    except (OSError, subprocess.SubprocessError):
        return None


for _p, _label in ((SCRIPT, 'setup/iface-pin.sh'),
                   (MAPGEN, 'setup/iface-pin-map.sh')):
    _mode = _git_index_mode(_p)
    check(f'{_label} 在 git 索引里是 100755（部署保留权限 ⇒ 设备上才可执行）',
          _mode is None or _mode == '100755',
          f'索引 mode={_mode}' if _mode else '不在 git 索引里（未 git add），跳过索引检查')

_code = strip_sh_comments(SCRIPT_SRC)
_mapcode = strip_sh_comments(MAPGEN_SRC)

# SYSFS 必须能被覆盖 —— 否则判据没法用假 sysfs 树跑
check('SYSFS 路径可被环境变量覆盖（判据要用假 sysfs 树跑）',
      re.search(r'SYSFS=\$\{SYSFS:-/sys/class/net\}', SCRIPT_SRC) is not None,
      '没法覆盖就没法在开发机上测这个脚本')
check('映射表生成器也能覆盖 SYSFS',
      re.search(r'SYSFS=\$\{SYSFS:-/sys/class/net\}', MAPGEN_SRC) is not None)

# ─────────────────────────────────────────────────────────────
sec('2  静态结构：钉名脚本的三条硬约束都在代码里（不是只在注释里）')

check('有「判断是不是物理设备」的函数',
      re.search(r'is_physical\s*\(\)\s*\{', _code) is not None)
check('is_physical 判据是「device 是真实子目录」而不是靠名字猜',
      re.search(r'\[.*-d.*\$SYSFS/\$_n/device.*\]', _code) is not None
      and re.search(r'readlink -f.*device.*readlink -f.*\$_n', _code, re.S) is not None,
      '靠名字猜会漏掉 bridge/vlan/dummy')
check('有「按 MAC 找接口」的函数',
      re.search(r'iface_by_mac\s*\(\)\s*\{', _code) is not None)
check('按 MAC 找口时是读 /sys/class/net/*/address',
      re.search(r'iface_by_mac[\s\S]*?address', _code) is not None)

# ⚠️ 这三条是最关键的：缺一条就是 .232 失联那种事故
check('★ 虚拟设备（bridge/vlan/dummy）绝不被改名',
      re.search(r'if ! is_physical "\$cur"; then[\s\S]{0,200}?continue', _code) is not None,
      '漏了这条 = .232 失联那种事故：bridge 改名会挂死')
check('★ 改名失败只跳过当前这个，不中断整体',
      re.search(r'if rename_iface[^\n]*; then[\s\S]{0,300}?else[\s\S]{0,200}?'
                r'log .*失败', _code) is not None,
      '漏了这条 = 一个口失败就全卡住')
check('★ 目标名被别的接口占用时：先腾位再改名，不是直接跳过',
      re.search(r'pin-tmp', _code) is not None,
      '直接跳过 ⇒ 互占时两个口都纠正不回来（.232 实测：桥成员变成了 WAN 那块卡）')

# ★ 安全窗口：系统里有桥就整体跳过
check('★ 有「系统里有没有桥」的判断',
      re.search(r'has_bridge\s*\(\)\s*\{', _code) is not None)
check('★ 有桥时整体跳过、一个名字都不改',
      re.search(r'if has_bridge; then[\s\S]{0,300}?exit 0', _code) is not None,
      '漏了这条 = 运行期改名会拆桥 ⇒ 桥变空桥 ⇒ 桥上 IP 掉 ⇒ 整机断网')
check('★ 跳过时会说明「下次重启才生效」（不是静默退出）',
      re.search(r'下次重启', _code) is not None)

# ★ 「改名后放回桥」那套逻辑必须**不存在**
# 2026-11-15 实测：对有成员口的 bridge/成员口做这套操作救不回来
# （桥的 MAC 继承自成员口 ⇒ 成员口改名后桥本身在内核里也消失了）。
# 留着它 = 运行期误用时会把网络拖垮。
check('★ 不存在「改名后放回原桥」的逻辑（ip link set ... master）',
      re.search(r'ip link set .* master ', _code) is None,
      '这套逻辑实测救不回来，只会制造第二次事故')
check('★ 不存在「在桥里就跳过改名」的旧规则（会让漂移永远纠正不回来）',
      re.search(r'已在桥里.*跳过改名', _code) is None)

# ─────────────────────────────────────────────────────────────
sec('3  静态结构：映射表生成器')

check('映射表生成器只列物理口（device 是真实子目录）',
      re.search(r'os\.path\.isdir\(dev\)', _mapcode) is not None
      and re.search(r'os\.path\.realpath\(dev\).*os\.path\.realpath', _mapcode, re.S) is not None,
      '把 bridge 收进映射表 = 给 bridge 钉名 = .232 失联那种事故')
check('映射表生成器不把 bridge/vlan 写进映射表',
      re.search(r'TMP_MARK', _mapcode) is not None,
      '临时名（腾位留下的）绝不能被钉成"固定名"')
check('映射表生成器是原子写入（先写 .tmp 再 replace）',
      re.search(r'os\.replace\(tmp, MAP_PATH\)', _mapcode) is not None)
check('映射表生成器读旧表并保留旧名（MAC 是硬件身份，名字不该再变）',
      re.search(r'load_old', _mapcode) is not None)


# ─────────────────────────────────────────────────────────────
sec('4  行为级：假 sysfs 树上真跑钉名脚本')

# 假 sysfs 树的构造
#
# 结构：
#   <root>/class/net/
#       eth0/address            真接口
#       eth0/device/            真子目录（物理口）
#       br-lan/address          bridge
#       br-lan/device -> br-lan 自指 ⇒ 虚拟设备
#       br-lan/bridge/          ⇒ 表明「系统里有桥」
#       eth0.10/address         vlan（无 device 目录）
#
# `ip` 是桩：记录调用，**并且真的把假 sysfs 里的目录改名** ——
# 这样判据能断言最终状态（谁叫什么），而不只是调用序列。

IP_STUB = r'''#!/bin/sh
# ip 命令桩：记录调用，并真的把假 sysfs 里的目录改名。
# 参数位置（ip link set <if> ...）：
#   $1=link $2=set $3=<if> $4=down|up|name $5=<新名>
echo "$*" >> "$IP_LOG"
case "$1" in
    link)
        case "$2" in
            set)
                if [ "$4" = "name" ]; then
                    if [ -n "${IP_FAIL_RENAME:-}" ] && [ "$3" = "${IP_FAIL_RENAME}" ]; then
                        echo "RENAMEFAIL $3 -> $5" >> "$IP_LOG"
                        exit 1
                    fi
                    if [ -n "${IP_FAKE_SYSFS:-}" ] && [ -e "$IP_FAKE_SYSFS/$5" ]; then
                        # 内核行为：目标名已存在 ⇒ EEXIST，改名失败
                        echo "RENAMEEXISTS $3 -> $5" >> "$IP_LOG"
                        exit 1
                    fi
                    if [ -n "${IP_FAKE_SYSFS:-}" ]; then
                        mv "$IP_FAKE_SYSFS/$3" "$IP_FAKE_SYSFS/$5" 2>/dev/null || true
                    fi
                    echo "RENAME $3 -> $5" >> "$IP_LOG"
                    exit 0
                fi
                ;;
        esac
        ;;
esac
exit 0
'''


def mk_iface(net, name, mac, has_device=True, self_ref=False, is_bridge=False):
    d = os.path.join(net, name)
    os.makedirs(d)
    with open(os.path.join(d, 'address'), 'w') as f:
        f.write(mac + '\n')
    if has_device:
        dev = os.path.join(d, 'device')
        if self_ref:
            os.symlink(d, dev)
        else:
            os.makedirs(dev)
    if is_bridge:
        os.makedirs(os.path.join(d, 'bridge'))
    return d


def build_fakesys(root, ifaces, bridges=(), vlans=()):
    """造假 sysfs 树。

    ifaces  : [(名字, MAC)] —— 都是物理口
    bridges : [(名字, MAC)] —— 桥（device 自指 + 有 bridge/ 子目录）
    vlans   : [(名字, MAC)] —— vlan（没有 device 目录）
    """
    net = os.path.join(root, 'class', 'net')
    os.makedirs(net)
    for name, mac in ifaces:
        mk_iface(net, name, mac)
    for name, mac in bridges:
        mk_iface(net, name, mac, self_ref=True, is_bridge=True)
    for name, mac in vlans:
        mk_iface(net, name, mac, has_device=False)
    return net


def net_state(net):
    """读出假 sysfs 当前的「名字 → MAC」状态。"""
    out = {}
    try:
        names = sorted(os.listdir(net))
    except OSError:
        return out
    for name in names:
        try:
            with open(os.path.join(net, name, 'address')) as f:
                out[name] = f.read().strip()
        except OSError:
            continue
    return out


def run_script(mapfile, builder=None, fail_rename=None):
    """在假 sysfs 上真跑 iface-pin.sh。

    返回 (假sysfs当前状态, ip调用日志, stdout+stderr)。
    builder 缺省 = 两个物理口、**没有桥**（= 开机时的状态，唯一允许改名的场景）。
    """
    d = tempfile.mkdtemp(prefix='ifacepin-')
    try:
        if builder is None:
            builder = lambda root: build_fakesys(root, [
                ('eth0', 'aa:bb:cc:00:00:01'),
                ('eth1', 'aa:bb:cc:00:00:02'),
            ])
        net = builder(d)
        ipbin = os.path.join(d, 'ip')
        with open(ipbin, 'w') as f:
            f.write(IP_STUB)
        os.chmod(ipbin, 0o755)
        iplog = os.path.join(d, 'ip.log')
        open(iplog, 'w').close()

        env = dict(os.environ)
        env['SYSFS'] = net
        env['IP_LOG'] = iplog
        env['IP_FAKE_SYSFS'] = net
        env['PATH'] = d + ':' + env.get('PATH', '')
        if fail_rename:
            env['IP_FAIL_RENAME'] = fail_rename

        r = subprocess.run(['sh', SCRIPT, mapfile], capture_output=True, text=True,
                           env=env, timeout=30)
        with open(iplog) as f:
            log = f.read()
        return net_state(net), log, r.stdout + r.stderr
    finally:
        shutil.rmtree(d, ignore_errors=True)


def write_map(content, suffix='.list'):
    fd, path = tempfile.mkstemp(prefix='ifacemap-', suffix=suffix)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(content)
    return path


# --- 4.1 物理口按 MAC 被改成固定名 ---
map1 = write_map("""# MAC            固定名
aa:bb:cc:00:00:01  lan0
aa:bb:cc:00:00:02  wan0
""")
state, iplog, out = run_script(map1)
check('物理口按 MAC 被改名成映射表里的名字',
      state.get('lan0') == 'aa:bb:cc:00:00:01' and state.get('wan0') == 'aa:bb:cc:00:00:02',
      '最终状态: %s' % state)
check('改完名后旧名字不再存在',
      'eth0' not in state and 'eth1' not in state,
      '最终状态: %s' % state)

# --- 4.2 ★ 有桥时整体跳过：一个名字都不改 ---
#
# 这是 .232 失联那次的形态（运行期有桥）。安全窗口必须挡住。


def builder_with_bridge(root):
    return build_fakesys(
        root,
        [('eth0', 'aa:bb:cc:00:00:01'), ('eth1', 'aa:bb:cc:00:00:02')],
        bridges=[('br-lan', 'aa:bb:cc:00:00:01')])


state_b, iplog_b, out_b = run_script(map1, builder_with_bridge)
check('★ 系统里已有桥时：一个接口都不改名',
      state_b.get('eth0') == 'aa:bb:cc:00:00:01' and state_b.get('eth1') == 'aa:bb:cc:00:00:02'
      and 'lan0' not in state_b and 'wan0' not in state_b,
      '最终状态: %s' % state_b)
check('★ 有桥时 ip 一次都没被调用（连 down 都不该有）',
      'ip link set' not in iplog_b,
      'ip 调用: %s' % iplog_b.replace('\n', ' | ').strip()[:200])
check('★ 有桥时会提示「下次重启才生效」',
      '下次重启' in out_b,
      '输出: %s' % out_b.strip()[:200])

# --- 4.3 ★ bridge / vlan 绝不出现在改名序列里 ---


def builder_with_vlan(root):
    return build_fakesys(
        root,
        [('eth0', 'aa:bb:cc:00:00:01'), ('eth1', 'aa:bb:cc:00:00:02')],
        vlans=[('eth0.10', 'aa:bb:cc:00:00:03')])


map_vlan = write_map("""aa:bb:cc:00:00:03  lan9
""")
state_v, iplog_v, out_v = run_script(map_vlan, builder_with_vlan)
check('★ vlan（eth0.10）没有被改名',
      state_v.get('eth0.10') == 'aa:bb:cc:00:00:03' and 'lan9' not in state_v,
      '最终状态: %s' % state_v)

# --- 4.4 ★ 虚拟设备是唯一匹配该 MAC 时必须拒绝改名 ---
#
# 为什么用 vlan 而不是 bridge 来触发这条：
#   bridge 一旦存在，脚本就在最外层被「安全窗口」拦下（见 4.2），
#   根本走不到 per-card 的虚拟设备判断 ⇒ 拿 bridge 测这条永远测不到
#   is_physical 本身。vlan 没有 bridge/ 子目录 ⇒ 安全窗口放行，
#   正好走到 is_physical ⇒ 这才是 is_physical 真正负责的那类设备。
#
#   bridge 那一侧由 4.2 的安全窗口负责（系统里有桥就一个名字都不改）。
#
# 这正是 .232 失联那次的形态：映射指向了一个虚拟设备。


def builder_vlan_only(root):
    return build_fakesys(
        root,
        [('eth0', 'aa:bb:cc:00:00:01')],
        vlans=[('eth0.10', 'aa:bb:cc:00:00:03')])


map_vlan_only = write_map("""aa:bb:cc:00:00:03  lan0
""")
state_vo, iplog_vo, out_vo = run_script(map_vlan_only, builder_vlan_only)
check('★ 唯一匹配的是虚拟设备（vlan）⇒ 拒绝改名',
      state_vo.get('eth0.10') == 'aa:bb:cc:00:00:03' and 'lan0' not in state_vo,
      '最终状态: %s' % state_vo)
check('★ 拒绝改虚拟设备时会说明原因（不是静默跳过）',
      '虚拟设备' in out_vo,
      '输出: %s' % out_vo.strip()[:200])

# --- 4.5 ★ 改名失败不中断整体 ---
map2 = write_map("""aa:bb:cc:00:00:01  lan0
aa:bb:cc:00:00:02  wan0
""")
state_f, iplog_f, out_f = run_script(map2, fail_rename='eth0')
check('★ 第一个口改名失败时，后面的口照样被改名',
      state_f.get('wan0') == 'aa:bb:cc:00:00:02',
      '最终状态: %s' % state_f)
check('★ 改名失败时会留下可查的日志',
      '失败' in out_f or 'fail' in out_f.lower(),
      '输出: %s' % out_f.strip()[:200])

# --- 4.6 映射里的 MAC 不在时不报错 ---
map3 = write_map("""aa:bb:cc:00:00:ff  nothere
""")
state_n, iplog_n, out_n = run_script(map3)
check('映射里的 MAC 当前不存在 ⇒ 跳过而不是报错退出',
      'RENAME' not in iplog_n and state_n.get('eth0') == 'aa:bb:cc:00:00:01',
      '最终状态: %s' % state_n)

# --- 4.7 已经是目标名就跳过 ---
map4 = write_map("""aa:bb:cc:00:00:01  eth0
""")
state_s, iplog_s, out_s = run_script(map4)
check('当前名已经等于目标名 ⇒ 不做多余改名',
      'RENAME' not in iplog_s and state_s.get('eth0') == 'aa:bb:cc:00:00:01',
      'ip 调用: %s' % iplog_s.replace('\n', ' | ').strip()[:200])

# --- 4.8 JSON 格式的映射表也要认 ---
map5 = write_map(json.dumps({
    'aa:bb:cc:00:00:02': 'wan0',
}), suffix='.json')
state_j, iplog_j, out_j = run_script(map5)
check('JSON 格式的映射表也能用',
      state_j.get('wan0') == 'aa:bb:cc:00:00:02',
      '最终状态: %s' % state_j)

# --- 4.9 目标名被占用时：先腾位再改名（不是跳过）---
#
# ⚠️ 2026-11-15 .232 实测踩到：原来的实现是「目标名被占用 ⇒ 跳过」。
#   但接口名漂移时经常是**互占**（eth0 和 eth1 互相对调），
#   两个都「被对方占用」⇒ 两个都跳过 ⇒ 谁也纠正不回来，
#   而 /etc/config/network 里的 list ports 'eth0' 就绑到了错误的物理卡。
#   实测那次 br-lan 的成员直接变成了 WAN 那块卡。
map6 = write_map("""aa:bb:cc:00:00:02  eth0
""")
state_t, iplog_t, out_t = run_script(map6)
check('目标名被占用时先腾位（占位的口挪到临时名），不是直接跳过',
      'RENAME eth0 -> eth0-pin-tmp' in iplog_t,
      'ip 调用: %s' % iplog_t.replace('\n', ' | ').strip()[:200])
check('腾位之后真正的口能拿到目标名',
      state_t.get('eth0') == 'aa:bb:cc:00:00:02',
      '最终状态: %s' % state_t)

# --- 4.10 ★ 互占（eth0 ↔ eth1 对调）能被纠正回来 ---
#
# 这是真机上的真实失败形态：.232 实测漂移后脚本没能纠正，
# 桥成员变成了错误的物理卡。判据必须覆盖这个场景。


def builder_swapped(root):
    # 名字和 MAC 故意错开：叫 eth0 的那块卡其实是 eth1 该管的
    return build_fakesys(root, [
        ('eth0', 'aa:bb:cc:00:00:02'),
        ('eth1', 'aa:bb:cc:00:00:01'),
    ])


map_swap = write_map("""aa:bb:cc:00:00:01  eth0
aa:bb:cc:00:00:02  eth1
""")
state_w, iplog_w, out_w = run_script(map_swap, builder_swapped)
check('★ 接口名互占时，两块卡都能归位（不互卡死）',
      state_w.get('eth0') == 'aa:bb:cc:00:00:01' and state_w.get('eth1') == 'aa:bb:cc:00:00:02',
      '最终状态: %s' % state_w)
check('★ 互占场景不会死循环（每块卡腾位+改名各一轮，没有第三轮腾位）',
      len([l for l in iplog_w.splitlines()
           if l.startswith('RENAME ') and 'pin-tmp' in l]) <= 2,
      '临时名改名次数: %d（实测正常值 2：两块卡各腾位一次）'
      % len([l for l in iplog_w.splitlines()
             if l.startswith('RENAME ') and 'pin-tmp' in l]))


# --- 4.11 ★ 按 MAC 找口时必须物理口优先 ---
#
# .232 实测踩到的坑：bridge 的 MAC 是**继承自成员口**的 ——
# br-lan 和 eth0 的 MAC 完全一样（bc:24:11:48:32:5b）。
# 如果按目录顺序找，撞上的可能是虚拟设备 ⇒ 物理口永远匹配不到
# ⇒ 固定名落在虚拟设备上（而 bridge 改名会挂死）。
#
# 这里用 bond0 复刻这个形态（bond 的 MAC 同样继承自成员口，
# 且目录名排在物理口前面 ⇒ 「去掉物理口优先」这个变异一定会暴露）。
def builder_same_mac(root):
    return build_fakesys(
        root,
        [('eth0', 'aa:bb:cc:00:00:01')],
        vlans=[('bond0', 'aa:bb:cc:00:00:01')])


map_same_mac = write_map("""aa:bb:cc:00:00:01  lan0
""")
state_sm, iplog_sm, out_sm = run_script(map_same_mac, builder_same_mac)
check('★ 与虚拟设备同 MAC 时，固定名落在**物理口**上',
      state_sm.get('lan0') == 'aa:bb:cc:00:00:01' and 'bond0' in state_sm,
      '最终状态: %s' % state_sm)


# ── 4.x 执行痕迹：每次执行都必须留下「我跑过了」的正面证据 ──
#
# 为什么这是硬要求（2026-11-15 真机踩到的坑）：
#   脚本「所有口名字都已经对得上、一个都不用改」时是**零日志**的 ——
#   而「脚本压根没跑起来」也是零日志。两种情况在 logread 里长得一模一样，
#   于是没人知道钉名保护已经失效。
#   实测就栽在这：源文件是 100644 ⇒ 设备上不可执行 ⇒ S15 钩子
#   Permission denied (rc=126) ⇒ 保护静默失效，日志里一个字都没有。
#   ⇒ 必须有「开始」和「执行完毕」两句，且**无事可做时也要有**。
def builder_already_ok(root):
    # 口的名字已经就是映射表里的固定名 ⇒ 不需要改名
    return build_fakesys(root, [
        ('eth0', 'aa:bb:cc:00:00:01'),
    ])


map_ok = write_map("""aa:bb:cc:00:00:01  eth0
""")
state_ok, iplog_ok, out_ok = run_script(map_ok, builder_already_ok)
check('★ 名字已经全对（无事可做）时，仍然有「开始」日志',
      '接口名钉定开始' in out_ok,
      '输出: %s' % out_ok.strip())
check('★ 名字已经全对（无事可做）时，仍然有「执行完毕」日志',
      '接口名钉定执行完毕' in out_ok,
      '输出: %s' % out_ok.strip())
check('★ 「执行完毕」日志带映射条数（能看出这次处理了几条）',
      re.search(r'执行完毕.*映射\s*\d+\s*条', out_ok) is not None,
      '输出: %s' % out_ok.strip())
check('★ 名字已经全对时，确实一个口都没改名',
      'RENAME' not in iplog_ok,
      'ip 调用: %s' % iplog_ok.strip())

# 安全窗口（有桥）分支也必须留痕迹：那句「下次重启生效」是给用户的提示
def builder_with_bridge(root):
    return build_fakesys(root, [('eth0', 'aa:bb:cc:00:00:01')],
                         bridges=[('br-lan', 'aa:bb:cc:00:00:01')])


state_wb, iplog_wb, out_wb = run_script(map_ok, builder_with_bridge)
check('★ 安全窗口分支也有日志（不是静默退出）',
      '检测到系统里已有桥' in out_wb and '下次重启生效' in out_wb,
      '输出: %s' % out_wb.strip())


# ─────────────────────────────────────────────────────────────
sec('5  行为级：映射表生成器')


def run_mapgen(builder, old_map=None):
    """在假 sysfs 上真跑 iface-pin-map.sh，返回 (映射表 dict, stdout)。"""
    d = tempfile.mkdtemp(prefix='ifacemapgen-')
    try:
        net = builder(d)
        mappath = os.path.join(d, 'iface-pin.json')
        if old_map is not None:
            with open(mappath, 'w', encoding='utf-8') as f:
                json.dump(old_map, f)
        env = dict(os.environ)
        env['SYSFS'] = net
        r = subprocess.run(['sh', MAPGEN, mappath], capture_output=True, text=True,
                           env=env, timeout=30)
        data = {}
        if os.path.exists(mappath):
            with open(mappath, encoding='utf-8') as f:
                data = json.load(f)
        return data, r.stdout + r.stderr
    finally:
        shutil.rmtree(d, ignore_errors=True)


def builder_three(root):
    return build_fakesys(root, [
        ('eth0', 'aa:bb:cc:00:00:01'),
        ('eth1', 'aa:bb:cc:00:00:02'),
        ('eth2', 'aa:bb:cc:00:00:03'),
    ], bridges=[('br-lan', 'aa:bb:cc:00:00:01')])


data1, out_m1 = run_mapgen(builder_three)
check('映射表：每块物理口都记下「MAC → 当前名」',
      data1.get('aa:bb:cc:00:00:01') == 'eth0'
      and data1.get('aa:bb:cc:00:00:02') == 'eth1'
      and data1.get('aa:bb:cc:00:00:03') == 'eth2',
      '映射表: %s' % data1)
check('映射表：bridge 不会被收进去（否则等于给 bridge 钉名）',
      'br-lan' not in data1.values(),
      '映射表: %s' % data1)

# --- 5.2 旧表里的名字不被改（哪怕卡现在叫别的名字 = 漂移已发生）---
data2, out_m2 = run_mapgen(builder_three, old_map={
    'aa:bb:cc:00:00:01': 'lan0',
    'aa:bb:cc:00:00:02': 'wan0',
})
check('映射表：旧表里的固定名保留（MAC 是硬件身份，名字不该再变）',
      data2.get('aa:bb:cc:00:00:01') == 'lan0'
      and data2.get('aa:bb:cc:00:00:02') == 'wan0',
      '映射表: %s' % data2)

# --- 5.3 新卡用当前名字（用户后来加进 LAN 的口）---
data3, out_m3 = run_mapgen(builder_three, old_map={
    'aa:bb:cc:00:00:01': 'eth0',
    'aa:bb:cc:00:00:02': 'eth1',
})
check('映射表：后加的卡用当前名字补进表里',
      data3.get('aa:bb:cc:00:00:03') == 'eth2',
      '映射表: %s' % data3)

# --- 5.4 临时名不被钉成固定名 ---
def builder_tmp(root):
    return build_fakesys(root, [
        ('eth0', 'aa:bb:cc:00:00:01'),
        ('eth0-pin-tmp', 'aa:bb:cc:00:00:09'),
    ])


data4, out_m4 = run_mapgen(builder_tmp)
check('映射表：腾位留下的临时名不会被钉成固定名',
      'aa:bb:cc:00:00:09' not in data4,
      '映射表: %s' % data4)

# --- 5.5 插槽换了卡：旧卡不在 ⇒ 名字交给现在占着它的卡 ---
def builder_replaced(root):
    return build_fakesys(root, [
        ('eth0', 'aa:bb:cc:00:00:09'),
    ])


data5, out_m5 = run_mapgen(builder_replaced, old_map={
    'aa:bb:cc:00:00:01': 'eth0',
})
check('映射表：旧卡不在了（插槽换卡）⇒ 名字交给现在占着它的卡',
      data5.get('aa:bb:cc:00:00:09') == 'eth0',
      '映射表: %s' % data5)

print()
if FAIL:
    print(f'[FAIL] 失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'[PASS] 通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
