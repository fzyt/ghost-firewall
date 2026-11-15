#!/bin/sh
# 按 MAC 把网卡钉成固定名字。
#
# 为什么需要（2026-11-15 在 .232 实测）：
#   Linux 给网卡编号（eth0/eth1/...）的规则是**按驱动上报设备的顺序**，
#   不是按 PCI 槽位，也不是按 MAC。
#   在 Proxmox 上加 vNIC 时，新网卡是**运行期**才被内核 enable 的
#   （实测：.232 上第三张网卡在开机 5.9 天后才 enable，拿到 eth2），
#   ⇒ 下次开机的编号顺序可能变 ⇒ `/etc/config/network` 里的
#   `list ports 'eth0'` 会指向另一块物理卡 ⇒ 表现为「接口对应关系变了」。
#
#   MAC 是网卡的硬件身份，不会变 ⇒ 按 MAC 找回接口并改名，
#   就能让配置里的名字永远对应同一块卡。
#
# 用法：
#   iface-pin.sh <映射文件>
#   映射文件每行一条：<mac> <固定名>，# 开头是注释
#
# ⚠️ 三条硬约束（都是踩过的坑）：
#   1. **只在开机时改名**（系统里还没有任何桥时）。
#      运行期改名会拆桥 ⇒ 桥变空桥 ⇒ 桥上的 IP 掉 ⇒ 整机断网（.232 实测）。
#      漂移是开机时发生的，修复也必须在开机时做
#      （init 脚本 START=15，卡在 boot S10 与 network S20 之间）。
#   2. **绝不能给 bridge 改名**。有成员口的 bridge（br-lan）改名时内核不
#      拒绝也不返回 —— 命令**挂死**，把网络拖垮（.232 就是这么失联的）。
#      判据：只看 `/sys/class/net/<name>/device` 是不是**真实子目录** ——
#      bridge / vlan / dummy 这类虚拟设备指向自己或不存在。
#   3. **改名失败不能中断整体**。一个口失败就跳到下一个，
#      不能因为它把后面的口全跳过了。

set -u

MAP_FILE="${1:-/etc/nftables/iface-pin.json}"
# SYSFS 可被环境变量覆盖 —— 判据要用假 sysfs 树跑这个脚本
# （真机上没法随便造多网卡，也没法造 bridge 改名挂死）。
SYSFS=${SYSFS:-/sys/class/net}

log() { logger -t iface-pin "$*" 2>/dev/null; echo "$*"; }

# 读映射表：输出 "<mac> <name>" 每行一条。
# 兼容两种格式：
#   纯文本：<mac> <name>
#   JSON ：{"<mac>": "<name>"}
read_map() {
    [ -f "$MAP_FILE" ] || return 0
    case "$(head -c 1 "$MAP_FILE" 2>/dev/null)" in
        '{')
            # JSON：借 python3 解析（OpenWrt 上一定有）
            python3 - "$MAP_FILE" 2>/dev/null <<'PYEOF' || true
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as f:
        data = json.load(f)
except Exception:
    sys.exit(0)
if isinstance(data, dict):
    for mac, name in data.items():
        if isinstance(name, str) and mac and name:
            print(mac.strip().lower(), name.strip())
PYEOF
            ;;
        *)
            grep -v '^[[:space:]]*#' "$MAP_FILE" 2>/dev/null | grep -v '^[[:space:]]*$'
            ;;
    esac
}

# 这个接口是不是「真实物理设备」。
# 判据：/sys/class/net/<name>/device 是真实子目录（不是指向自己）。
# bridge 的 device 指向自身 ⇒ 排除；vlan/dummy 没有 device 目录 ⇒ 排除。
is_physical() {
    _n="$1"
    [ -d "$SYSFS/$_n/device" ] || return 1
    # device 指向自己 ⇒ 虚拟设备
    [ "$(readlink -f "$SYSFS/$_n/device" 2>/dev/null)" = "$(readlink -f "$SYSFS/$_n" 2>/dev/null)" ] && return 1
    return 0
}

# 按 MAC 找当前接口名（找不到返回空）
#
# ⚠️ 必须**优先返回物理口**（2026-11-15 .232 实测踩到）：
#   bridge 的 MAC 是**继承自成员口**的 —— .232 上 br-lan 和 eth0
#   的 MAC 完全一样（bc:24:11:48:32:5b）。
#   如果按目录顺序找，撞上的是 br-lan ⇒ 物理口 eth0 永远匹配不到
#   ⇒ 改名目标永远落在 bridge 上（而 bridge 改名会挂死）。
iface_by_mac() {
    _mac="$1"
    _fallback=""
    for _d in "$SYSFS"/*; do
        [ -d "$_d" ] || continue
        _n=$(basename "$_d")
        [ "$(cat "$_d/address" 2>/dev/null)" = "$_mac" ] || continue
        # 物理口优先
        if is_physical "$_n"; then
            echo "$_n"
            return 0
        fi
        # 虚拟设备先记着当兜底（真找不到物理口时用）
        [ -z "$_fallback" ] && _fallback="$_n"
    done
    [ -n "$_fallback" ] && { echo "$_fallback"; return 0; }
    return 1
}

# 改名：只改名字，不碰接口状态
#
# ⚠️ 改名会**拆桥**（2026-11-15 .232 实测，两次）：
#   ① 桥成员口改名时，内核把成员关系丢了 ⇒ 桥变空桥
#      ⇒ 桥上的 IP 跟着掉 ⇒ 整机断网（实测面板 000）。
#   ② 桥的 MAC 是**继承自成员口**的 ⇒ 成员口改名后，
#      桥本身在内核里也变得不存在了（连 `ip link set` 加回去都失败）。
#      实测那次改名完 br-lan 直接从 /sys/class/net 里消失。
#
#   ⇒ 结论：**运行期不能改名**。
#     漂移是开机时发生的（内核重新编号），修复也必须在开机时做 ——
#     那时 netifd 还没起、桥还不存在，改名绝对安全。
#     下面 rename_iface 只在「系统里没有任何桥」时才允许改名；
#     有桥（说明 netifd 已经在跑）就整体跳过，等下次开机。
rename_iface() {
    _cur="$1"; _want="$2"
    # ⚠ **只改名，不碰 up/down 状态**。
    #   实测（2026-11-15 在 .232 真机验过，两条都成立）：
    #     · UP 的口直接改名是**干净**的 —— 改名不打断数据通路
    #       （内核里还是同一个 netdev，只是名字变了），
    #       状态与 carrier 原样保留，MAC 也跟着走：
    #           ip link set eth2 up
    #           ip link set eth2 name eth2-pin-test    # rc=0，仍是 UP
    #           cat /sys/class/net/eth2-pin-test/address # bc:24:11:54:ee:82
    #     · DOWN 的口直接改名同样干净。
    #
    #   ⇒ 不需要「先 down、改完再 up」那套动作。
    #     顺带把口拉起来反而是**多余的风险**：开机时（S15）这些口本来是 down，
    #     那是 netifd 接管前的正常状态。抢先拉起来等于把一个
    #     「已经被别人拉起」的口交给 netifd，而我们没验证过 netifd
    #     接管这种口时的行为。保持原样 ⇒ netifd 拿到的仍是它预期的状态。
    ip link set "$_cur" name "$_want" 2>/dev/null
}

# 系统里有没有桥（bridge 型网络设备）。
#
# 判据：`/sys/class/net/<name>/bridge` 目录存在 ⇒ 这个设备是桥。
# 比看 type 更直接 —— 不依赖 uevent 里的 type 字段格式。
has_bridge() {
    for _d in "$SYSFS"/*; do
        [ -d "$_d/bridge" ] && return 0
    done
    return 1
}

rc=0

# ── 安全窗口检查：系统里有桥 ⇒ 不改名 ──
#
# 原因见 rename_iface 的注释：运行期改名会拆桥、桥本身都会消失。
# 漂移是开机时发生的，所以修复也放在开机时做
# （init 脚本 START=15，卡在 boot S10 与 network S20 之间，
#   那时 netifd 还没起，桥还不存在 ⇒ 改名绝对安全）。
#
# 手动在运行期跑这个脚本（比如热插拔钩子）时，
# 这里会挡住危险操作，只留一句「下次开机会生效」。
if has_bridge; then
    log "检测到系统里已有桥（netifd 已在运行）—— 此时改名会拆桥，跳过。"
    log "接口名钉定只在开机时执行（init 脚本 START=15），下次重启生效。"
    exit 0
fi

# 映射表先读进变量，后面要数条数 —— 计数必须发生在**管道外面**的父 shell 里
# （`read_map | while ...` 的循环体在子 shell 里，子 shell 的计数出不来）。
#
# ⚠️ 用变量 + printf 喂给 while，**不要用 heredoc**：
#   heredoc 里的内容会做变量展开，映射表里万一有 `$` 就会变成命令执行（注入）。
#   printf '%s\n' "$map_data" 只是把数据当数据输出，`read` 拿到的是原文。
map_data=$(read_map)
map_count=$(printf '%s\n' "$map_data" | grep -c . 2>/dev/null)
[ -n "$map_count" ] || map_count=0

# ⚠️ 为什么要专门打这两句日志（2026-11-15 真机踩到的坑）：
#   脚本「全部口名字都对、什么都不用改」时是**零日志**的 ——
#   而「脚本压根没跑」也是零日志。两种情况在 logread 里长得一模一样。
#   实测就栽在这：源文件是 100644 ⇒ 设备上不可执行 ⇒ S15 钩子
#   Permission denied (rc=126) ⇒ 钉名保护**静默失效**，没有任何日志提示。
#   ⇒ 每次执行都必须留下「我跑过了、跑的时候是什么状态」的正面证据。
log "接口名钉定开始：映射表 $MAP_FILE，共 $map_count 条"

printf '%s\n' "$map_data" | while read -r mac want; do
    [ -z "$mac" ] && continue
    [ -z "$want" ] && continue

    cur=$(iface_by_mac "$mac")
    if [ -z "$cur" ]; then
        log "映射里的 $mac 当前不在（那块卡没插或没被驱动认领），跳过"
        continue
    fi

    if [ "$cur" = "$want" ]; then
        continue
    fi

    # ⚠️ 硬约束 2：bridge / 虚拟设备一律不碰
    if ! is_physical "$cur"; then
        log "$mac 当前叫 $cur，是虚拟设备（bridge/vlan/dummy），不改名"
        continue
    fi

    # 关于「口在桥里」：安全窗口检查（has_bridge）已经在最外层拦住了
    # ——系统里有任何桥就整体跳过 ⇒ 走到这里的口**一定不在桥里**
    # （桥由 netifd 在 S20 才建，S15 时还不存在）。
    # 所以不需要、也**不能**在这里做「改名后放回桥」那套逻辑：
    # 实测那套逻辑救不回来（桥的 MAC 继承自成员口，
    # 成员口改名后桥本身在内核里也消失了，ip link set 加不回去）。

    # 目标名已被别的接口占用。
    #
    # ⚠️ 不能直接跳过（2026-11-15 .232 实测踩到）：
    #   接口名漂移时经常是**互占** —— eth0 和 eth1 互相对调，
    #   两个都「被对方占用」⇒ 两个都跳过 ⇒ 谁也纠正不回来，
    #   而且 /etc/config/network 里的 list ports 'eth0' 会绑到错误的物理卡
    #   （实测那次 br-lan 的成员就变成了 WAN 那块卡）。
    #
    #   正确做法：**先腾位再改名** ——
    #   把占着目标名的那个口挪到临时名，腾出目标名给真正该用它的口。
    #   那个被挪走的口自己也会在后面的循环里被纠正回它该有的名字。
    if [ -e "$SYSFS/$want" ]; then
        other_mac=$(cat "$SYSFS/$want/address" 2>/dev/null)
        if [ "$other_mac" != "$mac" ]; then
            # 占位的那个口也得是物理口才能挪（虚拟设备挪了会出事）
            if ! is_physical "$want"; then
                log "$mac 想改成 $want，但 $want 是虚拟设备（$other_mac），跳过"
                continue
            fi
            # 腾位：占位的口挪到临时名
            tmp_name="${want}-pin-tmp"
            # 临时名也已被占用 ⇒ 换后缀
            n=0
            while [ -e "$SYSFS/$tmp_name" ]; do
                n=$((n + 1))
                tmp_name="${want}-pin-tmp-${n}"
                [ "$n" -gt 16 ] && break
            done
            if rename_iface "$want" "$tmp_name"; then
                log "腾位: $want（$other_mac）→ $tmp_name"
                # ⚠️ 被挪走的口**不用**单独归位 —— 它自己也在映射表里，
                #   循环走到它时会按它的固定名改回去。
                #   （2026-11-15 实测：加「第二轮归位」反而产生误导性日志，
                #    因为第一轮已经把两块卡都归位了。）
            else
                log "$mac 想改成 $want，但 $want（$other_mac）腾位失败，跳过"
                continue
            fi
        fi
    fi

    if rename_iface "$cur" "$want"; then
        log "$mac: $cur -> $want 改名成功"
    else
        # ⚠️ 硬约束 3：失败只跳过这一个，不能中断整体
        log "$mac: $cur -> $want 改名失败，继续处理下一个"
    fi
done

# 收尾日志：证明「跑完了」，且给出这次处理了多少条映射。
# 上面每一条改名/跳过/失败都有各自单独的日志，这句是整体收口。
log "接口名钉定执行完毕：映射 $map_count 条"
exit $rc
