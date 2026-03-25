# Version: 0.7.7
from flask import Flask, jsonify, request, send_from_directory
import os, subprocess, shutil, json, time, re, hmac, hashlib, base64, datetime, uuid
from template_engine import load_template, generate_rules

app = Flask(__name__)
CONFIG_PATH = '/etc/nftables/nftables-web-config.json'
RULES_PATH = '/etc/nftables.d/99-custom-rules.nft'

# 默认配置
DEFAULT_CONFIG = {
    # 网络接口
    "wan_if": "pppoe-wan",
    "lan_if": "br-lan",
    "router_ip4": "192.168.100.1",
    "router_ip6": "",
    # 敲门端口
    "knock1_port": 1,
    "knock2_port": 2,
    "knock3_port": 3,
    "knock4_port": 4,
    # 白名单超时时间（秒），默认 5 小时
    "whitelist_timeout": 18000,
    # 端口转发（多条规则）
    "forward_rules": [
        {
            "tcp_ports": "41820, 41825",
            "udp_ports": "21116",
            "target_ip": "192.168.4.226"
        }
    ],
    # 信任IP
    "trusted_ip4": "192.168.100.2",
    "trusted_ip6": "fd93:86bb:a142:0:e9d:92ff:fe87:fd28",
    # 日志开关
    "foreign_scan_log": False,
    "ipv6_wan_lan_log": False,
    "wan_drop_log": False,
    "lan_drop_log": False,
    "forward_log": False,
    "whitelist_access_log": True,
    # 网络段配置
    "lan_subnet4": "192.168.4.0/24",
    "lan_broadcast4": "192.168.4.255",
    "ula_prefix6": "fd93:86bb:a142::/60",
    "wan_prefix6": "240e:390:4944:b191::/64",
    # 访问模式
    "access_mode": "lan",
    # LAN 自定义放行端口（信任模式下生效，逗号分隔端口号）
    "lan_allowed_ports": "",
    # 国外IP拦截
    "china_ip_block": False,
}


def load_config():
    """加载配置，如果不存在则返回默认值"""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        # 合并默认值（防止新增字段丢失）
        result = dict(DEFAULT_CONFIG)
        result.update(config)
        result = _migrate_forward_rules(result)
        return result
    return dict(DEFAULT_CONFIG)


def save_config(config):
    """保存配置到 JSON 文件"""
    # 自动备份当前配置
    if os.path.exists(CONFIG_PATH):
        shutil.copy(CONFIG_PATH, CONFIG_PATH + '.backup')
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def _migrate_forward_rules(config):
    """向后兼容：旧格式 tcp_services/udp_services/dsm_ip4 自动迁移为 forward_rules"""
    if "forward_rules" not in config and ("tcp_services" in config or "dsm_ip4" in config):
        config["forward_rules"] = [{
            "tcp_ports": config.get("tcp_services", ""),
            "udp_ports": config.get("udp_services", ""),
            "target_ip": config.get("dsm_ip4", ""),
            "target_ipv6": "",
        }]
        # 迁移后清理旧字段
        for old_key in ("tcp_services", "udp_services", "dsm_ip4"):
            config.pop(old_key, None)
    # 确保 forward_rules 存在且每个规则有 target_ipv6 字段
    if "forward_rules" not in config:
        config["forward_rules"] = []
    for rule in config["forward_rules"]:
        rule.setdefault("target_ipv6", "")
    return config


def _auto_detect_network():
    """自动检测网络段配置"""
    result = {}
    try:
        uci = parse_uci_config('/etc/config/network')
        ipaddr = uci.get('lan_ipaddr', '')
        netmask = uci.get('lan_netmask', '')
        if ipaddr and netmask:
            import ipaddress
            net = ipaddress.ip_network(f"{ipaddr}/{netmask}", strict=False)
            result['LAN_SUBNET4'] = str(net)
            result['LAN_BROADCAST4'] = str(net.broadcast_address)
        res = subprocess.run(['ip', '-6', 'addr', 'show', 'dev', 'br-lan'], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            if 'inet6' in line and 'fd' in line:
                addr = line.strip().split()[1]
                ip, plen = addr.split('/')
                parts = [p for p in ip.split(':') if p]  # 过滤空段
                if len(parts) >= 4:
                    result['ULA_PREFIX6'] = ':'.join(parts[:4]) + '::/' + plen
                    break
        res = subprocess.run(['ip', '-6', 'addr', 'show', 'dev', 'pppoe-wan', 'scope', 'global'], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            if 'inet6' in line:
                addr = line.strip().split()[1]
                ip, plen = addr.split('/')
                parts = [p for p in ip.split(':') if p]  # 过滤空段
                if len(parts) >= 4:
                    result['WAN_PREFIX6'] = ':'.join(parts[:4]) + '::/' + plen
                    break
    except:
        pass
    return result

def config_to_variables(config):
    """将 web 配置转换为模板变量"""
    config = _migrate_forward_rules(config)
    forward_rules = config.get("forward_rules", [])

    # 合并所有规则的端口（用于 WAN 链白名单放行）
    all_tcp = set()
    all_udp = set()
    for rule in forward_rules:
        for p in rule.get("tcp_ports", "").split(","):
            p = p.strip()
            if p:
                all_tcp.add(p)
        for p in rule.get("udp_ports", "").split(","):
            p = p.strip()
            if p:
                all_udp.add(p)

    # 反代公网端口
    for rule in config.get("reverse_proxy", {}).get("rules", []):
        if rule.get("enabled") and rule.get("public_access"):
            port = str(rule.get("listen_port", ""))
            if port:
                all_tcp.add(port)

    # 生成端口集合定义（直接带 elements）
    tcp_elems = ", ".join(sorted(all_tcp)) if all_tcp else ""
    udp_elems = ", ".join(sorted(all_udp)) if all_udp else ""
    port_sets_block = "    set tcp_services {\n        type inet_service;\n        flags interval;\n"
    if tcp_elems:
        port_sets_block += f"        elements = {{ {tcp_elems} }}\n"
    port_sets_block += "    }\n    set udp_services {\n        type inet_service;\n        flags interval;\n"
    if udp_elems:
        port_sets_block += f"        elements = {{ {udp_elems} }}\n"
    port_sets_block += "    }"

    # 自动检测网络段
    detected = _auto_detect_network()

    variables = {
        "WAN_IF": f'"{config.get("wan_if", "pppoe-wan")}"',
        "LAN_IF": f'"{config.get("lan_if", "br-lan")}"',
        "ROUTER_IP4": config.get("router_ip4", "192.168.4.1"),
        "ROUTER_IP6": config.get("router_ip6", ""),
        "LAN_SUBNET4": detected.get("LAN_SUBNET4", "192.168.4.0/24"),
        "LAN_BROADCAST4": detected.get("LAN_BROADCAST4", "192.168.4.255"),
        "ULA_PREFIX6": detected.get("ULA_PREFIX6", "fd93:86bb:a142::/60"),
        "WAN_PREFIX6": detected.get("WAN_PREFIX6", "240e:390:4944:b191::/64"),
        "KNOCK1_PORT": str(config.get("knock1_port", 1)),
        "KNOCK2_PORT": str(config.get("knock2_port", 2)),
        "KNOCK3_PORT": str(config.get("knock3_port", 3)),
        "KNOCK4_PORT": str(config.get("knock4_port", 4)),
        "PORT_SETS_BLOCK": port_sets_block,
        "TRUSTED_IP4": config.get("trusted_ip4", "192.168.4.229"),
        "TRUSTED_IP6": config.get("trusted_ip6", "fd93:86bb:a142:0:e9d:92ff:fe87:fd28"),
        "ACCESS_MODE": config.get("access_mode", "trusted"),
        "CHINA_IP_BLOCK": "true" if config.get("china_ip_block", True) else "false",
    }

    # LAN 自定义放行端口规则
    lan_ports = [p.strip() for p in config.get("lan_allowed_ports", "").replace("，", ",").split(",") if p.strip()]
    if lan_ports:
        variables["LAN_ALLOWED_RULES"] = "        iifname $LAN_IF tcp dport { " + ", ".join(lan_ports) + " } accept"
    else:
        variables["LAN_ALLOWED_RULES"] = ""

    # 为每条规则生成转发块
    forward_block = []
    nat_block = []
    forward_log = config.get("forward_log", False)
    for i, rule in enumerate(forward_rules, 1):
        target_ip = rule.get("target_ip", "")
        tcp_ports = [p.strip() for p in rule.get("tcp_ports", "").split(",") if p.strip()]
        udp_ports = [p.strip() for p in rule.get("udp_ports", "").split(",") if p.strip()]

        tcp_set_str = "{ " + ", ".join(tcp_ports) + " }" if tcp_ports else ""
        udp_set_str = "{ " + ", ".join(udp_ports) + " }" if udp_ports else ""

        # 转发链规则
        fwd_lines = [f"# 端口转发规则 {i}: -> {target_ip}"]
        if tcp_ports:
            tcp_log_part = f'log prefix "[I4-ALVN-T-{i}] " ' if forward_log else ''
            fwd_lines.append(
                f"        iifname $WAN_IF meta nfproto ipv4 oifname $LAN_IF \\\n"
                f"            ip saddr @allowed4 ip daddr {target_ip} tcp dport {{ {', '.join(tcp_ports)} }} \\\n"
                f"            {tcp_log_part}accept"
            )
        if udp_ports:
            udp_log_part = f'log prefix "[I4-ALVN-U-{i}] " ' if forward_log else ''
            fwd_lines.append(
                f"        iifname $WAN_IF meta nfproto ipv4 oifname $LAN_IF \\\n"
                f"            ip saddr @allowed4 ip daddr {target_ip} udp dport {{ {', '.join(udp_ports)} }} \\\n"
                f"            {udp_log_part}accept"
            )
        forward_block.append("\n".join(fwd_lines))

        # NAT 规则
        nat_lines = [f"# NAT 规则 {i}: -> {target_ip}"]
        if tcp_ports:
            nat_lines.append(f"        iifname $WAN_IF tcp dport {tcp_set_str} dnat to {target_ip}")
        if udp_ports:
            nat_lines.append(f"        iifname $WAN_IF udp dport {udp_set_str} dnat to {target_ip}")
        nat_block.append("\n".join(nat_lines))

    variables["FORWARD_RULES_BLOCK"] = "\n\n".join(forward_block)
    variables["NAT_RULES_BLOCK"] = "\n\n".join(nat_block)

    # IPv6 集合定义（每个规则一个独立集合）
    ipv6_sets = []
    for i, rule in enumerate(forward_rules, 1):
        ipv6_sets.append(f"    set nas_ip6_{i} {{\n        type ipv6_addr;\n        flags dynamic;\n    }}")
    variables["IPV6_SETS_BLOCK"] = "\n".join(ipv6_sets)

    # IPv6 转发规则（每个规则独立，指向对应的 @nas_ip6_{i}）
    ipv6_fwd_block = []
    for i, rule in enumerate(forward_rules, 1):
        tcp_ports = [p.strip() for p in rule.get("tcp_ports", "").split(",") if p.strip()]
        udp_ports = [p.strip() for p in rule.get("udp_ports", "").split(",") if p.strip()]
        tcp_set_str = "{ " + ", ".join(tcp_ports) + " }" if tcp_ports else ""
        udp_set_str = "{ " + ", ".join(udp_ports) + " }" if udp_ports else ""
        log_part = 'log prefix "[I6-ALVN-T-' + str(i) + '] " ' if forward_log else ''

        lines = [f"# IPv6 转发规则 {i}"]
        if tcp_ports:
            lines.append(
                f"        iifname $WAN_IF meta nfproto ipv6 oifname $LAN_IF \\\n"
                f"            ip6 saddr @allowed6 ip6 daddr @nas_ip6_{i} \\\n"
                f"            tcp dport {tcp_set_str} \\\n"
                f"            {log_part}accept"
            )
        if udp_ports:
            log_part_udp = 'log prefix "[I6-ALVN-U-' + str(i) + '] " ' if forward_log else ''
            lines.append(
                f"        iifname $WAN_IF meta nfproto ipv6 oifname $LAN_IF \\\n"
                f"            ip6 saddr @allowed6 ip6 daddr @nas_ip6_{i} \\\n"
                f"            udp dport {udp_set_str} \\\n"
                f"            {log_part_udp}accept"
            )
        ipv6_fwd_block.append("\n".join(lines))
    variables["IPV6_FWD_RULES_BLOCK"] = "\n\n".join(ipv6_fwd_block)

    # IPv6 拒绝规则（每个规则独立）
    ipv6_den_block = []
    for i, rule in enumerate(forward_rules, 1):
        tcp_ports = [p.strip() for p in rule.get("tcp_ports", "").split(",") if p.strip()]
        udp_ports = [p.strip() for p in rule.get("udp_ports", "").split(",") if p.strip()]
        tcp_set_str = "{ " + ", ".join(tcp_ports) + " }" if tcp_ports else ""
        udp_set_str = "{ " + ", ".join(udp_ports) + " }" if udp_ports else ""
        log_part = 'log prefix "[I6-DEN-T-' + str(i) + '] " ' if forward_log else ''

        lines = []
        if tcp_ports:
            lines.append(f"        iifname $WAN_IF meta nfproto ipv6 oifname $LAN_IF \\\n            ip6 daddr @nas_ip6_{i} tcp dport {tcp_set_str} \\\n            {log_part}drop")
        if udp_ports:
            log_part_udp = 'log prefix "[I6-DEN-U-' + str(i) + '] " ' if forward_log else ''
            lines.append(f"        iifname $WAN_IF meta nfproto ipv6 oifname $LAN_IF \\\n            ip6 daddr @nas_ip6_{i} udp dport {udp_set_str} \\\n            {log_part_udp}drop")
        if lines:
            lines.insert(0, f"# IPv6 拒绝规则 {i}")
            ipv6_den_block.append("\n".join(lines))
    variables["IPV6_DEN_RULES_BLOCK"] = "\n\n".join(ipv6_den_block)

    return variables


def config_to_log_switches(config):
    """从配置中提取日志开关"""
    return {
        "foreign_scan_log": config.get("foreign_scan_log", False),
        "ipv6_wan_lan_log": config.get("ipv6_wan_lan_log", False),
        "wan_drop_log": config.get("wan_drop_log", False),
        "lan_drop_log": config.get("lan_drop_log", False),
        "forward_log": config.get("forward_log", False),
        "whitelist_access_log": config.get("whitelist_access_log", True),
    }


# === API 端点 ===

@app.route('/')
def serve_index():
    return send_from_directory('../frontend', 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    if '..' in filename or filename.startswith('/'):
        return jsonify({"error": "forbidden"}), 403
    return send_from_directory('../frontend', filename)


@app.route('/api/config', methods=['GET'])
def get_config():
    """获取当前配置"""
    config = load_config()
    config["success"] = True
    return jsonify(config)


@app.route('/api/config', methods=['POST'])
def post_config():
    """保存配置（不应用）"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    save_config(data)
    return jsonify({"success": True, "message": "配置已保存"})


@app.route('/api/config/restore', methods=['POST'])
def restore_config():
    """恢复上次备份的防火墙配置"""
    backup_path = CONFIG_PATH + '.backup'
    if not os.path.exists(backup_path):
        return jsonify({"success": False, "message": "没有可恢复的备份文件"}), 400
    try:
        shutil.copy(backup_path, CONFIG_PATH)
        return jsonify({"success": True, "message": "配置已恢复，请刷新页面"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


def build_rules(config):
    """生成规则，替换白名单超时时间"""
    variables = config_to_variables(config)
    log_switches = config_to_log_switches(config)
    rules = generate_rules(variables, log_switches)
    whitelist_timeout = config.get("whitelist_timeout", 18000)
    timeout_str = f"timeout {whitelist_timeout}s"
    rules = rules.replace("timeout 5h", timeout_str)
    return rules


@app.route('/api/rules/preview', methods=['GET'])
def preview_rules():
    """预览当前配置生成的规则（不写入文件）"""
    config = load_config()
    rules = build_rules(config)
    return jsonify({"success": True, "rules": rules})


@app.route('/api/rules/save', methods=['POST'])
def save_rules():
    """生成规则并写入文件"""
    config = load_config()
    rules = build_rules(config)

    os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)

    # 备份
    if os.path.exists(RULES_PATH):
        shutil.copy(RULES_PATH, RULES_PATH + '.backup')

    with open(RULES_PATH, 'w') as f:
        f.write(rules)

    return jsonify({"success": True, "message": "规则已保存", "path": RULES_PATH})


# === 网络配置辅助函数 ===

def sanitize_uci_value(value):
    """过滤 UCI 值中的危险字符，防止注入恶意配置行"""
    if not value:
        return ''
    return value.replace('\n', '').replace('\r', '').replace("'", '').replace('`', '')


def extract_uci_value(line):
    """从 UCI option 行提取值，如 "option device 'br-lan'" -> "br-lan" """
    parts = line.split(None, 2)
    if len(parts) >= 3:
        return parts[2].strip().strip("'\"")
    return ''


def get_lan_ipv6():
    """获取 br-lan 接口的第一个 IPv6 地址"""
    try:
        result = subprocess.run(['ip', '-6', 'addr', 'show', 'dev', 'br-lan'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('inet6') and 'fe80' not in line and 'scope global' in line:
                addr = line.split()[1].split('/')[0]
                return addr
        # 如果没有 global 地址，取 link-local
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('inet6') and 'fe80' in line:
                addr = line.split()[1].split('/')[0]
                return addr
    except:
        pass
    return ''


def parse_uci_config(path):
    """简单的 UCI 配置解析器"""
    result = {
        'lan_device': '', 'lan_proto': '', 'lan_ipaddr': '', 'lan_netmask': '',
        'wan_device': '', 'wan_proto': '',
        'wan_pppoe_username': '', 'wan_pppoe_password': '',
        'wan_pppoe': False,
        'lan_ip6': '',
    }
    current_section = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if re.match(r"config interface 'lan'$", line):
                current_section = 'lan'
            elif re.match(r"config interface 'wan'$", line):
                current_section = 'wan'
            elif line.startswith("config interface 'wan6'"):
                current_section = 'wan6'
            elif line.startswith("config "):
                current_section = None
            elif current_section == 'lan':
                if 'option device' in line or 'option ifname' in line:
                    result['lan_device'] = extract_uci_value(line)
                elif 'option proto' in line:
                    result['lan_proto'] = extract_uci_value(line)
                elif 'option ipaddr' in line:
                    result['lan_ipaddr'] = extract_uci_value(line)
                elif 'option netmask' in line:
                    result['lan_netmask'] = extract_uci_value(line)
            elif current_section == 'wan':
                if 'option ifname' in line or 'option device' in line:
                    result['wan_device'] = extract_uci_value(line)
                elif 'option proto' in line:
                    proto = extract_uci_value(line)
                    result['wan_proto'] = proto
                    if proto == 'pppoe':
                        result['wan_pppoe'] = True
                elif 'option username' in line:
                    result['wan_pppoe_username'] = extract_uci_value(line)
                elif 'option password' in line:
                    result['wan_pppoe_password'] = extract_uci_value(line)
            elif current_section == 'wan6':
                if 'option ifname' in line or 'option device' in line:
                    result['wan6_device'] = extract_uci_value(line)
                elif 'option proto' in line:
                    result['wan6_proto'] = extract_uci_value(line)
                elif 'option ip6addr' in line:
                    result['wan6_ip6addr'] = extract_uci_value(line)
    return result


def update_uci_wan_config(path, data):
    """更新 /etc/config/network 中的 wan 接口配置"""
    with open(path, 'r') as f:
        lines = f.readlines()

    new_lines = []
    has_pppoe = data.get('wan_pppoe', False)
    wan_device = sanitize_uci_value(data.get('wan_device', ''))
    # 始终自动检测 WAN 设备（比前端传值更可靠）
    try:
        import subprocess as _sp
        lan_ports = set()
        with open(path, 'r') as f:
            for line in f:
                if 'list ports' in line:
                    p = line.strip().split("'")[-2] if "'" in line else ''
                    if p:
                        lan_ports.add(p)
        # 用 ls /sys/class/net/ 检测接口（兼容 BusyBox）
        r = _sp.run(['ls', '/sys/class/net/'], capture_output=True, text=True, timeout=5)
        for name in r.stdout.strip().split():
            if (name.startswith('eth') or name.startswith('ens') or name.startswith('enp')) and name not in lan_ports:
                wan_device = name
                break
    except Exception:
        pass
    if not wan_device:
        wan_device = 'eth0'
    pppoe_username = sanitize_uci_value(data.get('wan_pppoe_username', ''))
    pppoe_password = sanitize_uci_value(data.get('wan_pppoe_password', ''))
    shutil.copy(path, path + '.backup')

    # 保存 wan6 块内容，以便切换回非 PPPoE 时恢复
    saved_wan6_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if re.match(r"config interface 'wan'$", stripped):
            new_lines.append(line)
            if has_pppoe:
                new_lines.append(f"\toption device '{wan_device}'\n")
                new_lines.append(f"\toption proto 'pppoe'\n")
                new_lines.append(f"\toption username '{pppoe_username}'\n")
                new_lines.append(f"\toption password '{pppoe_password}'\n")
                new_lines.append(f"\toption ipv6 'auto'\n")
                new_lines.append(f"\toption mtu '1492'\n")
            else:
                new_lines.append(f"\toption device '{wan_device}'\n")
                new_lines.append(f"\toption proto 'dhcp'\n")
            # 跳过 wan 块内的旧 option 行，但保留注释行
            i += 1
            while i < len(lines):
                next_stripped = lines[i].strip()
                if next_stripped.startswith('config '):
                    break
                if next_stripped == '':
                    if i + 1 < len(lines) and not lines[i+1].strip().startswith('config '):
                        new_lines.append(lines[i])
                        i += 1
                        continue
                    break
                # 保留注释行
                if next_stripped.startswith('#'):
                    new_lines.append(lines[i])
                i += 1
            continue

        if stripped.startswith("config interface 'wan6'"):
            # 收集 wan6 块所有行
            wan6_block = [line]
            i += 1
            while i < len(lines):
                if lines[i].strip().startswith('config '):
                    break
                wan6_block.append(lines[i])
                i += 1
            if has_pppoe:
                # PPPoE 模式：删除 wan6，但保存内容以便恢复
                saved_wan6_lines = wan6_block
                continue
            else:
                new_lines.extend(wan6_block)
                continue

        new_lines.append(line)
        i += 1

    # 切换回非 PPPoE 时，如果 wan6 被删除过且原文件中不再存在，则恢复
    if not has_pppoe and saved_wan6_lines:
        has_wan6 = any(re.match(r"config interface 'wan6'", l.strip()) for l in new_lines)
        if not has_wan6:
            new_lines.append('\n')
            new_lines.extend(saved_wan6_lines)

    # 如果文件中没有 wan 块，在末尾追加
    has_wan_block = any(re.match(r"config interface 'wan'$", l.strip()) for l in new_lines)
    if not has_wan_block:
        new_lines.append('\n')
        if has_pppoe:
            new_lines.append("config interface 'wan'\n")
            new_lines.append(f"\toption device '{wan_device}'\n")
            new_lines.append(f"\toption proto 'pppoe'\n")
            new_lines.append(f"\toption username '{pppoe_username}'\n")
            new_lines.append(f"\toption password '{pppoe_password}'\n")
            new_lines.append(f"\toption ipv6 'auto'\n")
            new_lines.append(f"\toption mtu '1492'\n")
        else:
            new_lines.append("config interface 'wan'\n")
            new_lines.append(f"\toption device '{wan_device}'\n")
            new_lines.append(f"\toption proto 'dhcp'\n")

    # 如果没有 wan6 块，在末尾追加
    has_wan6_block = any(re.match(r"config interface 'wan6'", l.strip()) for l in new_lines)
    if not has_wan6_block:
        new_lines.append('\n')
        new_lines.append("config interface 'wan6'\n")
        new_lines.append(f"\toption device '{wan_device}'\n")
        new_lines.append("\toption proto 'dhcpv6'\n")

    with open(path, 'w') as f:
        f.writelines(new_lines)


# === 网络配置 API ===

@app.route('/api/network/interfaces', methods=['GET'])
def get_interfaces():
    """获取可用网络接口列表"""
    interfaces = []
    net_path = '/sys/class/net'
    for name in os.listdir(net_path):
        if name == 'lo':
            continue
        state_path = os.path.join(net_path, name, 'operstate')
        state = 'unknown'
        if os.path.exists(state_path):
            with open(state_path) as f:
                state = f.read().strip()
        interfaces.append({'name': name, 'state': state})
    interfaces.sort(key=lambda x: x['name'])
    return jsonify({"success": True, "interfaces": interfaces})


@app.route('/api/network/config', methods=['GET'])
def get_network_config():
    """读取 OpenWrt 网络配置"""
    try:
        config = parse_uci_config('/etc/config/network')
        config['lan_ip6'] = get_lan_ipv6()
    except FileNotFoundError:
        return jsonify({"success": True, "message": "网络配置文件不存在，显示默认值", **dict(
            lan_device='', lan_proto='', lan_ipaddr='', lan_netmask='',
            wan_device='', wan_proto='', wan_pppoe_username='', wan_pppoe_password='',
            wan_pppoe=False, lan_ip6='',
        )})
    except Exception as e:
        return jsonify({"success": False, "message": f"读取网络配置失败: {str(e)}"}), 500
    return jsonify({"success": True, **config})


def _ensure_lan_essentials(path, has_pppoe=False):
    """确保 LAN 接口关键字段存在，防止配置丢失导致路由器失联"""
    with open(path, 'r') as f:
        content = f.read()
    lan_match = re.search(r"config interface 'lan'\n((?:[ \t][^\n]*\n)*?)(?=\nconfig |\n*\Z)", content)
    if not lan_match:
        return
    lan_block = lan_match.group(1)
    defaults = {
        'ipaddr': '192.168.100.1',
        'netmask': '255.255.255.0',
        'proto': 'static',
        'device': 'br-lan',
        'ip6assign': '60',
    }
    needs_update = False
    for key, default in defaults.items():
        if f'option {key}' not in lan_block:
            needs_update = True
            break
    # PPPoE 模式下强制 LAN proto 为 static
    if has_pppoe and re.search(r"option\s+proto\s+'dhcp'", lan_block):
        lan_block = re.sub(r"option\s+proto\s+'dhcp'", "option proto 'static'", lan_block)
        needs_update = True
    if needs_update:
        for key, default in defaults.items():
            if f'option {key}' not in lan_block:
                lan_block = lan_block.rstrip('\n') + f"\n\toption {key} '{default}'\n"
        content = content.replace(lan_match.group(1), lan_block)
        with open(path, 'w') as f:
            f.write(content)


@app.route('/api/network/config', methods=['POST'])
def save_network_config():
    """保存 OpenWrt 网络配置"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    try:
        update_uci_wan_config('/etc/config/network', data)
        if data.get('wan_pppoe', False):
            _ensure_lan_essentials('/etc/config/network', has_pppoe=True)
        # 同步 LAN IP 到 Web 配置
        with open('/etc/config/network', 'r') as f:
            content = f.read()
        lan_match = re.search(r"config interface 'lan'\n((?:[ \t][^\n]*\n)*?)(?=\nconfig |\n*\Z)", content)
        if lan_match:
            ip_match = re.search(r"option\s+ipaddr\s+'([^']+)'", lan_match.group(1))
            if ip_match:
                new_ip = ip_match.group(1)
                web_config = load_config()
                if web_config.get('router_ip4') != new_ip:
                    web_config['router_ip4'] = new_ip
                    save_config(web_config)
        return jsonify({"success": True, "message": "网络配置已保存（需重启网络生效）"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/network/restart', methods=['POST'])
def restart_network():
    """重启网络服务"""
    try:
        config = load_config()
        rules = build_rules(config)
        os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)
        with open(RULES_PATH, 'w') as f:
            f.write(rules)
        subprocess.run(['/etc/init.d/network', 'restart'], capture_output=True, text=True, timeout=30)
        # 等待网络接口恢复（阻塞 5s 是可接受的，因为后续需要加载 nft 规则）
        time.sleep(5)
        subprocess.run(['nft', '-f', RULES_PATH], capture_output=True, text=True, timeout=30)
        return jsonify({"success": True, "message": "网络已重启，防火墙规则已重新应用"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/firewall/status', methods=['GET'])
def get_firewall_status():
    """检测 fw4 和 nftables 运行状态"""
    try:
        # 检测 fw4 状态
        result = subprocess.run(['/etc/init.d/firewall', 'status'],
                                capture_output=True, text=True, timeout=5)
        fw4_active = 'inactive' not in result.stdout

        # 检测 nftables 是否已配置（检查 allowed4 set 是否存在）
        result2 = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'allowed4'],
                                 capture_output=True, text=True, timeout=5)
        nftables_loaded = result2.returncode == 0

        # init 脚本检测
        init_exists = os.path.exists('/etc/init.d/nftables-web')

        init_enabled = False
        if init_exists:
            r = subprocess.run(['/etc/init.d/nftables-web', 'enabled'],
                               capture_output=True, text=True, timeout=5)
            init_enabled = r.returncode == 0

        # 检查 init 脚本是否包含 fw4 stop（最新版本）
        init_has_fw4_stop = False
        if init_exists:
            with open('/etc/init.d/nftables-web', 'r') as f:
                init_content = f.read()
            init_has_fw4_stop = 'firewall stop' in init_content and 'firewall disable' in init_content

        return jsonify({
            "success": True,
            "fw4_active": fw4_active,       # true=fw4在运行(红点), false=已停止(绿点)
            "nftables_loaded": nftables_loaded,  # true=已配置(绿点), false=未配置(红点)
            "init_exists": init_exists,
            "init_enabled": init_enabled,
            "init_has_fw4_stop": init_has_fw4_stop,
            "init_up_to_date": init_exists and init_enabled and init_has_fw4_stop
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/firewall/repair-init', methods=['POST'])
def repair_init_script():
    """重新安装 init 脚本"""
    try:
        import shutil
        src = '/opt/nftables-web-v2/backend/nftables-web.init'
        dst = '/etc/init.d/nftables-web'
        if not os.path.exists(src):
            return jsonify({"success": False, "message": "源脚本不存在"}), 400
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)
        subprocess.run(['/etc/init.d/nftables-web', 'enable'],
                       capture_output=True, text=True, timeout=5)
        return jsonify({"success": True, "message": "init 脚本已修复并启用开机自启"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/rules/apply', methods=['POST'])
def apply_rules():
    """保存规则并执行 nft -f"""
    config = load_config()
    rules = build_rules(config)

    # 写入文件
    os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)
    with open(RULES_PATH, 'w') as f:
        f.write(rules)

    # 先校验规则语法（nft -c 只检查不执行）
    # 确保 include 所需的文件存在（避免因文件缺失导致校验失败）
    if config.get("china_ip_block", False):
        os.makedirs('/etc/nftables', exist_ok=True)
        if not os.path.exists('/etc/nftables/china-ips.nft'):
            open('/etc/nftables/china-ips.nft', 'w').close()
    check = subprocess.run(['nft', '-c', '-f', RULES_PATH],
                           capture_output=True, text=True, timeout=10)
    if check.returncode != 0:
        return jsonify({"success": False, "message": f"规则语法错误，未应用: {check.stderr or check.stdout}"}), 400

    # 校验通过，先备份旧规则文件
    if os.path.exists(RULES_PATH + '.backup'):
        pass  # 已有备份，不覆盖
    elif os.path.exists('/etc/nftables.d/99-custom-rules.nft.backup'):
        pass
    else:
        # 首次应用前备份当前 nftables 规则集
        try:
            subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, timeout=5,
                           stdout=open('/etc/nftables.d/99-custom-rules.nft.backup', 'w'))
        except Exception:
            pass

    # 确保 fw4 已停止
    subprocess.run(['/etc/init.d/firewall', 'stop'],
                   capture_output=True, text=True, timeout=5)

    # 执行 nft -f
    result = subprocess.run(
        ['nft', '-f', RULES_PATH],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        return jsonify({"success": False, "message": f"nft -f 失败: {result.stderr or result.stdout}"}), 500

    # 应用成功后，静默确保 IPv6 自动更新 cron 已安装
    try:
        _ensure_ipv6_cron()
    except Exception:
        pass

    return jsonify({"success": True, "message": "规则已应用"})


def _ensure_ipv6_cron():
    """静默确保 IPv6 自动更新脚本和 crontab 已就绪（幂等）"""
    script_path = '/opt/nftables-web/update-ipv6.sh'
    os.makedirs(os.path.dirname(script_path), exist_ok=True)
    with open(script_path, 'w') as f:
        f.write(IPV6_CRON_SCRIPT)
    os.chmod(script_path, 0o755)

    cron_entry = '*/10 * * * * /opt/nftables-web/update-ipv6.sh'
    result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
    existing = result.stdout.splitlines()
    if cron_entry not in existing:
        existing.append(cron_entry)
        subprocess.run(['crontab', '-'], input='\n'.join(existing) + '\n',
                       capture_output=True, text=True, timeout=10)


# === IPv6 辅助函数和 API ===

def _get_wan_ipv6_prefix():
    """获取公网 IPv6 前缀（前4段）和完整地址，优先从 WAN 接口获取，回退到 LAN 接口"""
    config = load_config()
    wan_if = config.get("wan_if", "pppoe-wan")
    lan_if = config.get("lan_if", "br-lan")

    def _extract_from_interface(ifname):
        """从指定接口提取 scope global 的 IPv6 地址和前缀"""
        result = subprocess.run(
            ['ip', '-6', 'addr', 'show', ifname],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if 'scope global' in line:
                parts = line.split()
                if 'inet6' in parts:
                    idx = parts.index('inet6')
                    addr_full = parts[idx + 1].split('/')[0]
                    if addr_full and addr_full != '::':
                        segments = addr_full.split(':')
                        prefix = ':'.join(segments[:4])
                        return addr_full, prefix
        return "", ""

    full_addr, prefix = _extract_from_interface(wan_if)
    source = "wan"
    if not full_addr:
        full_addr, prefix = _extract_from_interface(lan_if)
        source = "lan" if full_addr else "none"
    return {"full_addr": full_addr, "prefix": prefix, "source": source}


def _extract_ipv6_suffix(addr):
    """提取 IPv6 地址的最后4段作为后缀"""
    segments = addr.split(':')
    if len(segments) < 4:
        return ""
    return ':'.join(segments[-4:])


@app.route('/api/network/wan-ipv6', methods=['GET'])
def get_wan_ipv6():
    """获取 WAN 接口的公网 IPv6 信息"""
    try:
        info = _get_wan_ipv6_prefix()
        if not info["full_addr"]:
            return jsonify({"success": False, "message": "WAN 接口无公网 IPv6 地址"}), 404
        return jsonify({"success": True, **info})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/network/update-ipv6', methods=['POST'])
def update_ipv6():
    """更新 nas_ip6 合集：拼接 WAN 前缀 + 各规则 IPv6 后缀"""
    try:
        config = load_config()
        wan_info = _get_wan_ipv6_prefix()
        if not wan_info["prefix"]:
            return jsonify({"success": False, "message": "WAN 接口无公网 IPv6 前缀，无法更新"}), 400

        prefix = wan_info["prefix"]
        forward_rules = config.get("forward_rules", [])
        updated = []

        for idx, rule in enumerate(forward_rules, 1):
            set_name = f"nas_ip6_{idx}"
            # 清空该规则的集合
            subprocess.run(['nft', 'flush', 'set', 'inet', 'fw4', set_name],
                           capture_output=True, text=True, timeout=10)

            target_ipv6 = rule.get("target_ipv6", "").strip()
            if not target_ipv6:
                continue
            suffix = _extract_ipv6_suffix(target_ipv6)
            if not suffix:
                continue
            full_ipv6 = f"{prefix}:{suffix}"
            result = subprocess.run(
                ['nft', 'add', 'element', 'inet', 'fw4', set_name, '{', full_ipv6, '}'],
                capture_output=True, text=True, timeout=10
            )
            updated.append({
                "set_name": set_name,
                "target_ipv6": target_ipv6,
                "suffix": suffix,
                "full_ipv6": full_ipv6,
                "success": result.returncode == 0,
                "error": result.stderr.strip() if result.returncode != 0 else None,
            })

        return jsonify({
            "success": True,
            "prefix": prefix,
            "updated": updated,
            "message": f"已更新 {len(updated)} 条 IPv6 地址",
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


IPV6_CRON_SCRIPT = '''#!/bin/sh
# IPv6 合集自动更新脚本 - 由 nftables-web 生成
# 从 nftables-web 配置读取 IPv6 后缀，拼接 WAN 前缀后更新各规则对应的 nas_ip6_{i} 合集
CONFIG="/etc/nftables/nftables-web-config.json"
WAN_IF=$(jsonfilter -e '$.wan_if' $CONFIG 2>/dev/null || echo "pppoe-wan")
LAN_IF=$(jsonfilter -e '$.lan_if' $CONFIG 2>/dev/null || echo "br-lan")
PREFIX=$(ip -6 addr show dev "$WAN_IF" scope global 2>/dev/null | grep 'inet6' | head -1 | awk '{print $2}' | cut -d: -f1-4)
if [ -z "$PREFIX" ]; then
    PREFIX=$(ip -6 addr show dev "$LAN_IF" scope global 2>/dev/null | grep 'inet6' | head -1 | awk '{print $2}' | cut -d: -f1-4)
fi

if [ -z "$PREFIX" ]; then exit 0; fi

# 写入路由器本机 IPv6（DDNS 用）
echo -n "$PREFIX::1" > /tmp/ddns-ipv6-0

# 从配置读取每条规则的 target_ipv6 后缀，拼接并添加到对应的 nas_ip6_{i} 合集
# 使用 python3 解析 JSON（OpenWrt jsonfilter 不支持 [*] 通配符）
python3 - "$CONFIG" "$PREFIX" << 'PYEOF'
import json, subprocess, sys
config_path, prefix = sys.argv[1], sys.argv[2]
with open(config_path) as f:
    config = json.load(f)
for i, rule in enumerate(config.get("forward_rules", []), 1):
    set_name = f"nas_ip6_{i}"
    subprocess.run(["nft", "flush", "set", "inet", "fw4", set_name],
                   capture_output=True, timeout=10)
    suffix = rule.get("target_ipv6", "").strip()
    if not suffix:
        continue
    parts = suffix.split(":")
    suffix_4 = ":".join(parts[-4:]) if len(parts) >= 4 else ""
    if not suffix_4:
        continue
    full = f"{prefix}:{suffix_4}"
    subprocess.run(["nft", "add", "element", "inet", "fw4", set_name, "{", full, "}"],
                   capture_output=True, timeout=10)
    with open(f"/tmp/ddns-ipv6-{i}", "w") as f:
        f.write(full)
PYEOF
'''


@app.route('/api/scripts/update-ipv6.sh', methods=['GET'])
def get_ipv6_script():
    """返回 IPv6 自动更新脚本内容"""
    return IPV6_CRON_SCRIPT, 200, {'Content-Type': 'text/x-shellscript'}


@app.route('/api/network/install-ipv6-cron', methods=['POST'])
def install_ipv6_cron():
    """安装 IPv6 自动更新脚本到 crontab"""
    try:
        script_path = '/opt/nftables-web/update-ipv6.sh'
        os.makedirs(os.path.dirname(script_path), exist_ok=True)

        with open(script_path, 'w') as f:
            f.write(IPV6_CRON_SCRIPT)
        os.chmod(script_path, 0o755)

        # 检查 crontab 中是否已有该条目
        cron_entry = '0 * * * * /opt/nftables-web/update-ipv6.sh'
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
        existing = result.stdout.splitlines()
        if cron_entry not in existing:
            existing.append(cron_entry)
            proc = subprocess.run(['crontab', '-'], input='\n'.join(existing) + '\n',
                                  capture_output=True, text=True, timeout=10)
            if proc.returncode != 0:
                return jsonify({"success": False, "message": f"crontab 更新失败: {proc.stderr}"}), 500

        return jsonify({
            "success": True,
            "message": f"脚本已安装到 {script_path}，crontab 已配置每小时执行",
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


CHINA_IPS_SCRIPT = '''#!/bin/sh
# 中国IP集合自动更新脚本
# 从 GitHub 下载中国IP列表，转换为 nftables 集合格式
NFT_FILE="/etc/nftables/china-ips.nft"
URL="https://cdn.jsdelivr.net/gh/17mon/china_ip_list@master/china_ip_list.txt"

TMP=$(mktemp)
wget -qO "$TMP" "$URL" 2>/dev/null
if [ ! -s "$TMP" ]; then
    echo "下载失败"
    rm -f "$TMP"
    exit 1
fi

mkdir -p /etc/nftables

# 生成 nftables 文件：先清空合集，再逐条添加
echo "# 中国IP集合 - 自动生成 $(date)" > "$NFT_FILE"
echo "flush set inet fw4 china_ipv4" >> "$NFT_FILE"

COUNT=0
ELEMENTS=""
while IFS= read -r line; do
    line=$(echo "$line" | tr -d '\\r' | grep -oE '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+(/[0-9]+)?')
    if [ -n "$line" ]; then
        if [ -n "$ELEMENTS" ]; then
            ELEMENTS="${ELEMENTS}, "
        fi
        ELEMENTS="${ELEMENTS}${line}"
        COUNT=$((COUNT+1))
        # 每500条flush一次避免单行过长
        if [ $((COUNT % 500)) -eq 0 ]; then
            echo "add element inet fw4 china_ipv4 { ${ELEMENTS} }" >> "$NFT_FILE"
            ELEMENTS=""
        fi
    fi
done < "$TMP"

# 写入剩余的
if [ -n "$ELEMENTS" ]; then
    echo "add element inet fw4 china_ipv4 { ${ELEMENTS} }" >> "$NFT_FILE"
fi

rm -f "$TMP"
echo "完成，共 $COUNT 条中国IP，已写入 $NFT_FILE"
echo "请执行: nft -f /etc/nftables/china-ips.nft"
'''


@app.route('/api/firewall/china-ips-script', methods=['GET'])
def get_china_ips_script():
    """返回中国IP自动更新脚本内容"""
    return CHINA_IPS_SCRIPT, 200, {'Content-Type': 'text/x-shellscript'}


@app.route('/api/firewall/update-china-ips', methods=['POST'])
def update_china_ips():
    """手动触发执行中国IP更新脚本"""
    script_path = '/opt/nftables-web-v2/update-china-ips.sh'
    if not os.path.exists(script_path):
        return jsonify({"success": False, "message": "脚本未安装，请先执行安装"}), 400
    try:
        result = subprocess.run(
            ['sh', script_path],
            capture_output=True, text=True, timeout=120
        )
        return jsonify({
            "success": result.returncode == 0,
            "message": result.stdout.strip(),
            "error": result.stderr.strip() if result.returncode != 0 else None,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "脚本执行超时（120秒）"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/firewall/install-china-ips', methods=['POST'])
def install_china_ips():
    """安装中国IP自动更新脚本到 crontab 并立即执行一次"""
    try:
        # 检查国外IP拦截是否启用
        config = load_config()
        if not config.get("china_ip_block", True):
            return jsonify({"success": False, "message": "国外IP拦截未启用，无需安装"}), 400

        script_path = '/opt/nftables-web-v2/update-china-ips.sh'
        os.makedirs(os.path.dirname(script_path), exist_ok=True)

        with open(script_path, 'w') as f:
            f.write(CHINA_IPS_SCRIPT)
        os.chmod(script_path, 0o755)

        # 添加 crontab：每周一凌晨3点执行
        cron_entry = '0 3 * * 1 /opt/nftables-web-v2/update-china-ips.sh'
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
        existing = result.stdout.splitlines()
        if cron_entry not in existing:
            existing.append(cron_entry)
            proc = subprocess.run(['crontab', '-'], input='\n'.join(existing) + '\n',
                                  capture_output=True, text=True, timeout=10)
            if proc.returncode != 0:
                return jsonify({"success": False, "message": f"crontab 更新失败: {proc.stderr}"}), 500

        # 自动执行一次
        run_result = subprocess.run(
            ['sh', script_path],
            capture_output=True, text=True, timeout=120
        )

        return jsonify({
            "success": True,
            "script_path": script_path,
            "cron": cron_entry,
            "run_output": run_result.stdout.strip(),
            "run_error": run_result.stderr.strip() if run_result.returncode != 0 else None,
            "run_success": run_result.returncode == 0,
            "message": "脚本已安装，crontab 已配置每周一凌晨3点执行" + ("，首次执行成功" if run_result.returncode == 0 else "，首次执行失败"),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "脚本执行超时（120秒）"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# === DDNS 配置 ===

DDNS_PROVIDER_NAMES = {
    "cloudflare.com-v4": "Cloudflare",
    "dnspod.cn": "DNSPod 腾讯云（2.0旧版）",
    "dnspod.cn-v3": "DNSPod 腾讯云 3.0",
    "dnspod-v3.tencentcloudapi.com": "DNSPod 腾讯云 3.0",
    "huaweicloud.com": "华为云",
    "cloud.google.com-v1": "Google Cloud DNS",
    "google.com": "Google Domains",
    "godaddy.com-v1": "GoDaddy",
    "no-ip.com": "No-IP",
    "gandi.net": "Gandi",
    "freedns.42.pl": "FreeDNS",
    "porkbun.com": "Porkbun",
    "digitalocean.com": "DigitalOcean",
}

DDNS_PROVIDER_DIR = '/usr/share/ddns/default'
DDNS_CONFIG_PATH = '/etc/config/ddns'
DDNS_INIT_SCRIPT = '/etc/init.d/ddns'


def _mask_password(pwd):
    """密码掩码：长度>4 显示前2后2，否则显示****"""
    if not pwd:
        return ''
    if len(pwd) > 4:
        return pwd[:2] + '****' + pwd[-2:]
    return '****'


def _parse_ddns_config():
    """解析 uci show ddns 输出，返回 service 列表"""
    try:
        result = subprocess.run(['uci', 'show', 'ddns'], capture_output=True, text=True, timeout=10)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    services = {}
    for line in result.stdout.strip().splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        value = value.strip("'\"")
        parts = key.split('.', 2)
        if len(parts) < 2 or parts[0] != 'ddns':
            continue
        name = parts[1]
        if len(parts) == 2 and value == 'service':
            services[name] = {
                'name': name, 'enabled': False, 'use_ipv6': False,
                'service_name': '', 'lookup_host': '', 'domain': '',
                'username': '', 'password': '', 'interface': '',
                'ip_source': '', 'ip_network': '', 'param_enc': '', 'param_opt': '',
                'ipv6_source': '', 'ip_script': '',
                'sub_domain': '', 'main_domain': '',
            }
        elif len(parts) == 3 and name in services:
            field = parts[2]
            if field in ('enabled', 'use_ipv6'):
                services[name][field] = value == '1'
            elif field in services[name]:
                services[name][field] = value

    svc_list = list(services.values())
    for svc in svc_list:
        svc['password'] = _mask_password(svc['password'])
        # 从 ip_script 反推 ipv6_source
        ip_script = svc.get('ip_script', '')
        if svc.get('ip_source') == 'script' and '/tmp/ddns-ipv6-' in ip_script:
            idx = ip_script.split('/tmp/ddns-ipv6-')[-1]
            svc['ipv6_source'] = 'router' if idx == '0' else f'rule_{idx}'
        # 从 UCI domain 值反向拆分为 sub_domain 和 main_domain
        domain_val = svc.get('domain', '')
        sub_domain = ''
        main_domain = ''
        service_name = svc.get('service_name', '')
        if service_name == 'google.com':
            # FQDN 格式: host.example.com
            parts = domain_val.rsplit('.', 1)
            if len(parts) == 2:
                sub_domain = parts[0]
                main_domain = parts[1]
            else:
                main_domain = domain_val
        else:
            # @ 分隔格式: host@maindomain 或 @maindomain（主域名本身）
            if domain_val.startswith('@'):
                sub_domain = '@'
                main_domain = domain_val[1:].lstrip('.')
            elif '@' in domain_val:
                sub_domain, main_domain = domain_val.split('@', 1)
            else:
                # 无 @ 说明只有主域名或旧格式
                parts = domain_val.rsplit('.', 1)
                if len(parts) == 2:
                    sub_domain = parts[0]
                    main_domain = parts[1]
                else:
                    main_domain = domain_val
        svc['sub_domain'] = sub_domain
        svc['main_domain'] = main_domain
    return svc_list


def _uci_set(key, value):
    """执行 uci set，值用双引号包裹，特殊字符已转义"""
    safe_val = value.replace('\\', '\\\\').replace('"', '\\"') if value else ''
    return subprocess.run(['uci', '-q', 'set', f'{key}={safe_val}'],
                          capture_output=True, text=True, timeout=10)


# === DDNS API ===

@app.route('/api/ddns/ipv6-sources', methods=['GET'])
def get_ddns_ipv6_sources():
    """返回可用的 IPv6 来源列表（根据 forward_rules 动态生成）"""
    sources = [{"id": "router", "name": "路由器本机 IPv6"}]
    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        rules = config.get('forward_rules', [])
        for i, rule in enumerate(rules):
            target = rule.get('target_ip', f'规则{i+1}')
            sources.append({"id": f"rule_{i+1}", "name": f"转发规则 {i+1}"})
    except Exception:
        pass
    return jsonify({"success": True, "sources": sources})


@app.route('/api/ddns/providers', methods=['GET'])
def get_ddns_providers():
    """获取已安装的 DDNS 服务商列表"""
    providers = []
    if os.path.isdir(DDNS_PROVIDER_DIR):
        for fname in os.listdir(DDNS_PROVIDER_DIR):
            if not fname.endswith('.json'):
                continue
            provider_id = fname[:-5]  # 去掉 .json
            display_name = DDNS_PROVIDER_NAMES.get(provider_id, provider_id)
            providers.append({'id': provider_id, 'name': display_name})
    providers.sort(key=lambda x: x['name'])
    return jsonify({"success": True, "providers": providers})


@app.route('/api/ddns/config', methods=['GET'])
def get_ddns_config():
    """获取 DDNS 配置列表"""
    try:
        services = _parse_ddns_config()
        # 读取当前 IPv6 地址文件
        ipv6_addresses = {}
        for i in range(10):
            key = 'router' if i == 0 else f'rule_{i}'
            try:
                with open(f'/tmp/ddns-ipv6-{i}') as f:
                    ipv6_addresses[key] = f.read().strip()
            except Exception:
                pass
        return jsonify({"success": True, "services": services, "ipv6_addresses": ipv6_addresses})
    except Exception as e:
        return jsonify({"success": False, "message": f"读取 DDNS 配置失败: {str(e)}"}), 500


@app.route('/api/ddns/save', methods=['POST'])
def save_ddns_config():
    """保存 DDNS 配置（先清除所有 service，再重建）"""
    data = request.get_json(silent=True)
    if not data or 'services' not in data:
        return jsonify({"success": False, "message": "请求体缺少 services 字段"}), 400

    services = data['services']
    try:
        # 1. 先获取现有的 service 名称和密码缓存
        existing = _parse_ddns_config()
        # 缓存原始密码（掩码值跳过写入时使用）
        import re as _re
        password_cache = {}
        for svc in existing:
            svc_name = svc.get('name', '')
            uci_name = _re.sub(r'[^a-zA-Z0-9_]', '_', svc_name) or svc_name
            # 从 UCI 读取原始未掩码密码
            result = subprocess.run(
                ['uci', '-q', 'get', f'ddns.{uci_name}.password'],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                password_cache[uci_name] = result.stdout.strip()

        # 2. 删除所有现有 service 块
        for svc in existing:
            subprocess.run(['uci', '-q', 'delete', f'ddns.{svc["name"]}'],
                           capture_output=True, text=True, timeout=10)

        # 3. 重建 global 块
        subprocess.run(['uci', 'set', 'ddns.global=ddns'],
                       capture_output=True, text=True, timeout=10)
        _uci_set('ddns.global.ddns_dateformat', '%F %R')
        _uci_set('ddns.global.ddns_loglines', '250')
        _uci_set('ddns.global.upd_privateip', '0')

        # 4. 添加每个 service
        for i, svc in enumerate(services):
            svc_name = svc.get('name', f'ddns_{i + 1}')
            # UCI section 名称只允许字母、数字、下划线，中文等无效
            uci_name = re.sub(r'[^a-zA-Z0-9_]', '_', svc_name) or f'ddns_{i + 1}'
            subprocess.run(['uci', 'set', f'ddns.{uci_name}=service'],
                           capture_output=True, text=True, timeout=10)
            _uci_set(f'ddns.{uci_name}.enabled', '1' if svc.get('enabled') else '0')
            _uci_set(f'ddns.{uci_name}.service_name', svc.get('service_name', ''))
            # 拼接域名
            sub = svc.get('sub_domain', '').strip()
            main = svc.get('main_domain', '').strip()
            service_name = svc.get('service_name', '')
            if service_name == 'google.com':
                domain_val = f"{sub}.{main}" if sub else main
                lookup_host = domain_val
            else:
                if sub == '@':
                    domain_val = f"@{main}"
                elif sub:
                    domain_val = f"{sub}@{main}"
                else:
                    domain_val = main
                lookup_host = f"{sub}.{main}" if sub and sub != '@' else main
            _uci_set(f'ddns.{uci_name}.domain', domain_val)
            _uci_set(f'ddns.{uci_name}.lookup_host', lookup_host)
            # Cloudflare API Token: username 自动设为 Bearer
            svc_username = svc.get('username', '')
            if 'cloudflare' in svc.get('service_name', ''):
                svc_username = 'Bearer'
            _uci_set(f'ddns.{uci_name}.username', svc_username)
            # 密码：如果包含掩码标记则从缓存还原原始密码
            pwd = svc.get('password', '')
            if '****' in str(pwd):
                cached_pwd = password_cache.get(uci_name, '')
                if cached_pwd:
                    pwd = cached_pwd
                else:
                    continue  # 缓存也没有，跳过不写入
            _uci_set(f'ddns.{uci_name}.password', pwd)
            _uci_set(f'ddns.{uci_name}.interface', svc.get('interface', 'wan'))
            ipv6_source = svc.get('ipv6_source', '')
            if svc.get('use_ipv6') and ipv6_source:
                # 映射 ipv6_source 到 ip_script
                _uci_set(f'ddns.{uci_name}.ip_source', 'script')
                idx = '0' if ipv6_source == 'router' else ipv6_source.replace('rule_', '')
                _uci_set(f'ddns.{uci_name}.ip_script', f'/bin/cat /tmp/ddns-ipv6-{idx}')
                _uci_set(f'ddns.{uci_name}.ipv6_source', ipv6_source)
            else:
                _uci_set(f'ddns.{uci_name}.ip_source', svc.get('ip_source', 'network'))
                _uci_set(f'ddns.{uci_name}.ipv6_source', '')
            _uci_set(f'ddns.{uci_name}.ip_network', svc.get('ip_network', 'wan'))
            _uci_set(f'ddns.{uci_name}.use_ipv6', '1' if svc.get('use_ipv6') else '0')
            _uci_set(f'ddns.{uci_name}.param_enc', svc.get('param_enc', ''))
            _uci_set(f'ddns.{uci_name}.param_opt', svc.get('param_opt', ''))
            # ddns-scripts 必需的运行参数
            check_interval = svc.get('check_interval', 10)
            _uci_set(f'ddns.{uci_name}.check_interval', str(check_interval))
            _uci_set(f'ddns.{uci_name}.check_unit', 'minutes')
            _uci_set(f'ddns.{uci_name}.force_interval', '72')
            _uci_set(f'ddns.{uci_name}.force_unit', 'hours')
            _uci_set(f'ddns.{uci_name}.retry_interval', '60')
            _uci_set(f'ddns.{uci_name}.retry_interval_unit', 'seconds')
            _uci_set(f'ddns.{uci_name}.retry_max_count', '0')
            # 使用外部 DNS 查询注册 IP，避免本地 DNS 缓存导致检测不到变化
            _uci_set(f'ddns.{uci_name}.dns_server', '1.1.1.1')

        # 5. commit
        result = subprocess.run(['uci', 'commit', 'ddns'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return jsonify({"success": False, "message": f"uci commit 失败: {result.stderr}"}), 500

        # 6. 确保 DDNS 服务已启用并重启（后台重启，避免阻塞）
        subprocess.run([DDNS_INIT_SCRIPT, 'enable'], capture_output=True, text=True, timeout=10)
        subprocess.Popen([DDNS_INIT_SCRIPT, 'restart'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return jsonify({"success": True, "message": f"已保存 {len(services)} 条 DDNS 记录"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "UCI 命令执行超时"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/ddns/restart', methods=['POST'])
def restart_ddns():
    """重启 DDNS 服务"""
    try:
        result = subprocess.run([DDNS_INIT_SCRIPT, 'restart'],
                                capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return jsonify({"success": False, "message": f"重启失败: {result.stderr or result.stdout}"}), 500
        return jsonify({"success": True, "message": "DDNS 服务已重启"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "DDNS 重启超时（15秒）"}), 500
    except FileNotFoundError:
        return jsonify({"success": False, "message": "DDNS 服务未安装"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/ddns/status', methods=['POST'])
def ddns_status():
    """获取 DDNS 服务状态和日志"""
    try:
        # 服务状态
        status_result = subprocess.run([DDNS_INIT_SCRIPT, 'status'],
                                       capture_output=True, text=True, timeout=10)
        running = status_result.returncode == 0

        # 日志
        log_result = subprocess.run(['logread', '-e', 'ddns'],
                                    capture_output=True, text=True, timeout=10)
        log_lines = log_result.stdout.strip().splitlines()[-50:] if log_result.stdout.strip() else []

        return jsonify({
            "success": True,
            "running": running,
            "status_output": status_result.stdout.strip(),
            "logs": log_lines,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "查询超时"}), 500
    except FileNotFoundError:
        return jsonify({"success": False, "message": "DDNS 服务未安装"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# === 阿里云 DDNS ===

ALIYUN_DDNS_CONFIG_PATH = '/etc/nftables/aliyun-ddns-config.json'


def _aliyun_mask_secret(secret):
    """AccessKey Secret 掩码"""
    if not secret:
        return ''
    if len(secret) > 6:
        return secret[:2] + '****' + secret[-2:]
    return '****'


def _load_aliyun_ddns_config():
    """加载阿里云 DDNS 配置"""
    if os.path.exists(ALIYUN_DDNS_CONFIG_PATH):
        with open(ALIYUN_DDNS_CONFIG_PATH, 'r') as f:
            return json.load(f)
    return None


def _save_aliyun_ddns_config(config):
    """保存阿里云 DDNS 配置"""
    os.makedirs(os.path.dirname(ALIYUN_DDNS_CONFIG_PATH), exist_ok=True)
    with open(ALIYUN_DDNS_CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    os.chmod(ALIYUN_DDNS_CONFIG_PATH, 0o600)


def _generate_ddns_update_script():
    """生成阿里云 DDNS 自动更新脚本"""
    script_path = "/opt/nftables-web-v2/aliyun-ddns-update.py"
    script_content = '''#!/usr/bin/env python3
"""阿里云 DDNS 自动更新脚本（由 nftables-web 生成）"""
import json, sys, os, urllib.request, urllib.parse, hmac, hashlib, base64, datetime, uuid

CONFIG_PATH = "/etc/nftables/aliyun-ddns-config.json"

def _sign(params, secret):
    qs = "&".join(f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe='')}" for k, v in sorted(params.items()))
    sts = "GET&" + urllib.parse.quote("/", safe='') + "&" + urllib.parse.quote(qs, safe='')
    return base64.b64encode(hmac.new((secret + "&").encode(), sts.encode(), hashlib.sha1).digest()).decode()

def _api(action, ak_id, ak_secret, region, extra={}):
    params = {"Action": action, "Format": "json", "Version": "2015-01-09", "AccessKeyId": ak_id,
              "SignatureMethod": "HMAC-SHA1", "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
              "SignatureVersion": "1.0", "SignatureNonce": str(uuid.uuid4()), "RegionId": region}
    params.update(extra)
    params["Signature"] = _sign(params, ak_secret)
    url = "https://alidns.aliyuncs.com/?" + "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params.items())
    with urllib.request.urlopen(urllib.request.Request(url), timeout=15) as resp:
        return json.loads(resp.read())

try:
    with open(CONFIG_PATH) as f:
        config = json.load(f)
    records = config.get("records", [])
    ak_id = config.get("access_key_id", "")
    ak_secret = config.get("access_key_secret", "")
    region = config.get("region_id", "cn-hangzhou")
    domain = config.get("domain", "")
    if not ak_id or not ak_secret or not domain:
        sys.exit(0)
    
    source_map = {"router": "0"}
    for i in range(1, 10):
        source_map[f"rule_{i}"] = str(i)
    
    for rec in records:
        if not rec.get("enabled"):
            continue
        rr = rec.get("rr", "")
        rtype = rec.get("type", "")
        ipv6_source = rec.get("ipv6_source", "")
        value = rec.get("value", "").strip()
        
        if ipv6_source:
            idx = source_map.get(ipv6_source)
            if idx is not None:
                try:
                    with open(f"/tmp/ddns-ipv6-{idx}") as f:
                        value = f.read().strip()
                except:
                    pass
            if not value:
                continue
        # A 记录自动获取路由器公网 IPv4
        if rtype == "A":
            try:
                import urllib.request as _ur
                _req = _ur.Request("https://ipv4.icanhazip.com")
                with _ur.urlopen(_req, timeout=5) as _r:
                    value = _r.read().decode().strip()
            except:
                pass
        if not value:
            continue
        
        # 查询现有记录，值相同则跳过
        result = _api("DescribeDomainRecords", ak_id, ak_secret, region, {"DomainName": domain, "RRKeyWord": rr, "Type": rtype})
        found_same = False
        for r in result.get("DomainRecords", {}).get("Record", []):
            if r.get("RR") == rr and r.get("Type") == rtype:
                if r.get("Value") == value:
                    found_same = True
                else:
                    _api("DeleteDomainRecord", ak_id, ak_secret, region, {"RecordId": str(r["RecordId"])})
                break
        if not found_same:
            _api("AddDomainRecord", ak_id, ak_secret, region, {"DomainName": domain, "RR": rr, "Type": rtype, "Value": value})
except Exception as e:
    with open("/tmp/aliyun-ddns-error.log", "a") as f:
        f.write(f"{datetime.datetime.now().isoformat()}: {e}\\n")
    sys.exit(1)
'''
    os.makedirs(os.path.dirname(script_path), exist_ok=True)
    with open(script_path, 'w') as f:
        f.write(script_content)
    os.chmod(script_path, 0o755)


def _manage_ddns_cron(config):
    """管理 DDNS 自动更新的 cron 条目"""
    cron_entry = "*/10 * * * * /opt/nftables-web-v2/aliyun-ddns-update.py"
    has_enabled = any(rec.get("enabled") for rec in config.get("records", []))
    
    # 读取当前 crontab
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
        current_crontab = result.stdout
    except Exception:
        current_crontab = ""
    
    # 删除旧的 DDNS cron 条目
    lines = [line for line in current_crontab.splitlines()
             if "aliyun-ddns-update.py" not in line]
    
    # 如果有启用的记录，追加新条目
    if has_enabled:
        lines.append(cron_entry)
    
    # 写回 crontab
    new_crontab = "\n".join(lines) + ("\n" if lines else "")
    proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True, timeout=10)


def _aliyun_sign(params, access_key_secret, method="GET"):
    """阿里云 API 签名"""
    import urllib.parse
    qs = "&".join(f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(v), safe='')}" for k, v in sorted(params.items()))
    string_to_sign = method + "&" + urllib.parse.quote("/", safe='') + "&" + urllib.parse.quote(qs, safe='')
    h = hmac.new((access_key_secret + "&").encode(), string_to_sign.encode(), hashlib.sha1)
    return base64.b64encode(h.digest()).decode()


def _aliyun_api(action, access_key_id, access_key_secret, region_id, extra_params={}):
    """调用阿里云 DNS API"""
    import urllib.request, urllib.parse
    params = {
        "Action": action,
        "Format": "json",
        "Version": "2015-01-09",
        "AccessKeyId": access_key_id,
        "SignatureMethod": "HMAC-SHA1",
        "Timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SignatureVersion": "1.0",
        "SignatureNonce": str(uuid.uuid4()),
        "RegionId": region_id,
    }
    params.update(extra_params)
    params["Signature"] = _aliyun_sign(params, access_key_secret)
    url = "https://alidns.aliyuncs.com/?" + "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in params.items())
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _aliyun_ddns_update(config, rr, rtype, value):
    """通过阿里云 API 更新单条 DNS 记录（删除+添加，避免 RecordId 精度问题）"""
    domain = config['domain']
    ak_id = config['access_key_id']
    ak_secret = config['access_key_secret']
    region = config.get('region_id', 'cn-hangzhou')

    # 查询现有记录
    result = _aliyun_api("DescribeDomainRecords", ak_id, ak_secret, region, {
        "DomainName": domain,
        "RRKeyWord": rr,
        "Type": rtype,
    })
    records = result.get('DomainRecords', {}).get('Record', [])

    for r in records:
        if r.get('RR') == rr and r.get('Type') == rtype:
            if r.get('Value') == value:
                return {"success": True, "message": "IP 未变化，无需更新"}
            # 删除旧记录
            _aliyun_api("DeleteDomainRecord", ak_id, ak_secret, region, {
                "RecordId": r['RecordId'],
            })
            break

    # 添加新记录
    _aliyun_api("AddDomainRecord", ak_id, ak_secret, region, {
        "DomainName": domain,
        "RR": rr,
        "Type": rtype,
        "Value": value,
    })
    return {"success": True, "message": f"记录 {rr}.{rtype} 已更新为 {value}"}


@app.route('/api/aliyun-ddns/status', methods=['GET'])
def aliyun_ddns_status():
    """检查阿里云 DDNS 配置状态"""
    config = _load_aliyun_ddns_config()
    response = {
        "success": True,
        "cli_installed": True,  # 不再依赖 aliyun-cli
        "cli_configured": config is not None and bool(config.get('access_key_id')),
        "config_exists": config is not None,
    }

    if config:
        safe = dict(config)
        safe['access_key_secret'] = _aliyun_mask_secret(safe.get('access_key_secret', ''))
        response['config'] = safe
        response["records"] = config.get("records", [])

    return jsonify(response)


@app.route('/api/aliyun-ddns/setup', methods=['POST'])
def aliyun_ddns_setup():
    """配置阿里云 AccessKey"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400

    access_key_id = data.get('access_key_id', '').strip()
    access_key_secret = data.get('access_key_secret', '').strip()
    region_id = data.get('region_id', 'cn-hangzhou').strip()
    domain = data.get('domain', '').strip()

    if not access_key_id or not access_key_secret:
        return jsonify({"success": False, "message": "access_key_id 和 access_key_secret 不能为空"}), 400

    # 验证 AK 是否有效（尝试查询域名列表）
    try:
        _aliyun_api("DescribeDomains", access_key_id, access_key_secret, region_id)
    except Exception as e:
        return jsonify({"success": False, "message": f"AccessKey 验证失败: {str(e)}"}), 400

    # 保存到配置文件（合并已有配置）
    existing = _load_aliyun_ddns_config() or {}
    existing['access_key_id'] = access_key_id
    existing['access_key_secret'] = access_key_secret
    existing['region_id'] = region_id
    if domain:
        existing['domain'] = domain
    _save_aliyun_ddns_config(existing)

    return jsonify({"success": True, "message": "AccessKey 配置完成"})


@app.route('/api/aliyun-ddns/records', methods=['GET'])
def aliyun_ddns_records():
    """获取阿里云 DNS 记录列表"""
    config = _load_aliyun_ddns_config()
    if not config or not config.get('domain'):
        return jsonify({"success": False, "message": "请先配置域名（保存配置时设置 domain 字段）"}), 400

    domain = config['domain']

    try:
        output = _aliyun_api("DescribeDomainRecords",
                             config['access_key_id'], config['access_key_secret'],
                             config.get('region_id', 'cn-hangzhou'),
                             {"DomainName": domain})

        records = []
        for r in output.get('DomainRecords', {}).get('Record', []):
            records.append({
                'record_id': r.get('RecordId', ''),
                'rr': r.get('RR', ''),
                'type': r.get('Type', ''),
                'value': r.get('Value', ''),
            })

        # 合并本地配置（启用状态、IPv6 来源等）
        # 同时支持 record_id 和 rr+type 两种匹配方式
        local_records_map = {}
        for lr in config.get('records', []):
            key = lr.get('record_id', '') or f"{lr.get('rr','')}:{lr.get('type','')}"
            local_records_map[key] = lr

        for r in records:
            key1 = r.get('record_id', '')
            key2 = f"{r.get('rr','')}:{r.get('type','')}"
            local = local_records_map.get(key1) or local_records_map.get(key2) or {}
            r['enabled'] = local.get('enabled', False)
            r['ipv6_source'] = local.get('ipv6_source', '')

        # 返回配置（掩码）
        safe_config = dict(config)
        safe_config['access_key_secret'] = _aliyun_mask_secret(safe_config.get('access_key_secret', ''))

        return jsonify({
            "success": True,
            "records": records,
            "config": safe_config,
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/aliyun-ddns/save', methods=['POST'])
def aliyun_ddns_save():
    """保存阿里云 DDNS 配置"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400

    # 合并已有配置，避免前端只发 records 时覆盖凭证
    existing = _load_aliyun_ddns_config() or {}
    existing.update(data)
    # AAAA 记录 ipv6_source 为空时默认设为 router（路由器本机 IPv6）
    # 因为前端下拉默认选中第一项但实际值为空，@change 不会触发
    for rec in existing.get('records', []):
        if (rec.get('type') or rec.get('Type', '')) == 'AAAA' and not rec.get('ipv6_source'):
            rec['ipv6_source'] = 'router'
    # 统一大小写键，阿里云 API 返回 Type/RR/Value/RecordId，生成脚本使用小写
    for rec in existing.get('records', []):
        for big, small in [('Type','type'), ('RR','rr'), ('Value','value'), ('RecordId','record_id')]:
            if rec.get(big) and not rec.get(small):
                rec[small] = rec[big]
    # 如果 access_key_secret 是掩码值则保留原值
    if '****' in str(existing.get('access_key_secret', '')):
        old = _load_aliyun_ddns_config()
        if old:
            existing['access_key_secret'] = old.get('access_key_secret', '')

    _save_aliyun_ddns_config(existing)

    # 生成自动更新脚本
    _generate_ddns_update_script()

    # 管理 cron 条目
    _manage_ddns_cron(data)

    return jsonify({"success": True, "message": "配置已保存"})


@app.route('/api/aliyun-ddns/test', methods=['POST'])
def aliyun_ddns_test():
    """测试单条 DNS 记录更新"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400

    rr = data.get('rr', '')
    rtype = data.get('type', '')
    ipv6_source = data.get('ipv6_source', '')
    value = data.get('value', '').strip()

    # 如果选择了 IPv6 来源且未手动输入值，从文件读取实际 IP
    if ipv6_source and not value:
        source_map = {"router": "0"}
        for i in range(1, 10):
            source_map[f"rule_{i}"] = str(i)
        idx = source_map.get(ipv6_source)
        if idx is not None:
            try:
                with open(f'/tmp/ddns-ipv6-{idx}') as f:
                    value = f.read().strip()
            except (IOError, OSError):
                pass

    if not all([rr, rtype, value]):
        return jsonify({"success": False, "message": "rr, type, value 都不能为空" + ("（IPv6 来源文件不存在或为空）" if ipv6_source and not value else "")}), 400

    config = _load_aliyun_ddns_config()
    if not config or not config.get('domain'):
        return jsonify({"success": False, "message": "请先配置域名"}), 400

    try:
        result = _aliyun_ddns_update(config, rr, rtype, value)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/system/logs", methods=["GET"])
def get_system_logs():
    """获取系统日志（通过 logread）"""
    try:
        lines = request.args.get("lines", 5000, type=int)
        lines = min(max(lines, 1), 5000)

        result = subprocess.run(
            ["logread", "-l", str(lines)],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            return jsonify({
                "success": False,
                "message": result.stderr.strip() or "logread 执行失败"
            }), 500

        log_pattern = re.compile(
            r"^(\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+"
            r"(\w+)\.(\w+)\s+"
            r"([^\[:]+)"
            r"(?:\[(\d+)\])?:\s+"
            r"(.*)$"
        )

        logs = []
        sources = {}
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            m = log_pattern.match(line)
            if m:
                entry = {
                    "timestamp": m.group(1),
                    "facility": m.group(2),
                    "level": m.group(3),
                    "program": m.group(4).strip(),
                    "pid": m.group(5),
                    "message": m.group(6),
                }
                logs.append(entry)
                program = entry["program"]
                sources[program] = sources.get(program, 0) + 1

        sources = dict(sorted(sources.items(), key=lambda x: x[1], reverse=True))

        return jsonify({
            "success": True,
            "total": len(logs),
            "logs": logs,
            "sources": sources,
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500



# ── logd 远程日志转发配置 ──────────────────────────────────────────────
import re

@app.route("/api/logd/config", methods=["GET"])
def get_logd_config():
    """读取当前 logd 远程日志转发配置"""
    try:
        result = subprocess.run(
            ["uci", "show", "system"], capture_output=True, text=True, timeout=10
        )
        output = result.stdout
        config = {"success": True, "log_ip": "", "log_port": "", "log_proto": ""}
        for key, field in [
            ("system.@system[0].log_ip", "log_ip"),
            ("system.@system[0].log_port", "log_port"),
            ("system.@system[0].log_proto", "log_proto"),
        ]:
            m = re.search(rf"^{re.escape(key)}='(.*)'", output, re.MULTILINE)
            if m:
                config[field] = m.group(1)
        return jsonify(config)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/logd/config", methods=["POST"])
def set_logd_config():
    """保存并应用 logd 远程日志转发配置"""
    try:
        data = request.get_json(force=True)
        log_ip = data.get("log_ip", "").strip()
        log_port = data.get("log_port", "").strip()
        log_proto = data.get("log_proto", "").strip()

        # 如果 log_ip 为空，则删除转发配置
        if not log_ip:
            for key in [
                "system.@system[0].log_ip",
                "system.@system[0].log_port",
                "system.@system[0].log_proto",
            ]:
                subprocess.run(
                    ["uci", "delete", key], capture_output=True, text=True, timeout=10
                )
            subprocess.run(["uci", "commit", "system"], timeout=10)
            subprocess.run(["/etc/init.d/log", "restart"], timeout=10)
            return jsonify({"success": True, "message": "日志转发配置已清除"})

        # 验证 log_ip：简单 IP 格式
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(ip_pattern, log_ip):
            return jsonify({"success": False, "message": "log_ip 格式无效"}), 400
        parts = log_ip.split(".")
        if any(not (0 <= int(p) <= 255) for p in parts):
            return jsonify({"success": False, "message": "log_ip 格式无效"}), 400

        # 验证 log_port：1-65535
        if log_port:
            if not log_port.isdigit() or not (1 <= int(log_port) <= 65535):
                return jsonify({"success": False, "message": "log_port 必须是 1-65535 的数字"}), 400

        # 验证 log_proto
        if log_proto and log_proto not in ("tcp", "udp"):
            return jsonify({"success": False, "message": "log_proto 只允许 tcp 或 udp"}), 400

        # uci set
        subprocess.run(
            ["uci", "set", f"system.@system[0].log_ip={log_ip}"],
            capture_output=True, text=True, timeout=10,
        )
        if log_port:
            subprocess.run(
                ["uci", "set", f"system.@system[0].log_port={log_port}"],
                capture_output=True, text=True, timeout=10,
            )
        if log_proto:
            subprocess.run(
                ["uci", "set", f"system.@system[0].log_proto={log_proto}"],
                capture_output=True, text=True, timeout=10,
            )
        subprocess.run(["uci", "commit", "system"], timeout=10)
        subprocess.run(["/etc/init.d/log", "restart"], timeout=10)
        return jsonify({"success": True, "message": "日志转发配置已保存"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# === 黑白名单管理 API ===

VALID_SET_NAMES = {"allowed4", "allowed6", "blacklist4", "blacklist6"}


def _parse_nft_set_output(output):
    """从 nft list set 输出中提取 IP 地址及过期时间，返回 {ip: expires_str|None}"""
    result = {}
    for m in re.finditer(r'elements = \{([^}]+)\}', output):
        block = m.group(1)
        for entry in block.split(','):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split()
            ip = parts[0]
            if not ip:
                continue
            # 查找 "expires <value>"
            expires = None
            for i, p in enumerate(parts):
                if p == "expires" and i + 1 < len(parts):
                    expires = parts[i + 1]
                    break
            result[ip] = expires
    return result


@app.route('/api/lists/whitelist', methods=['GET'])
def get_whitelist():
    """读取白名单 (allowed4 + allowed6)"""
    try:
        result4 = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'allowed4'],
                                 capture_output=True, text=True, timeout=10)
        result6 = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'allowed6'],
                                 capture_output=True, text=True, timeout=10)
        return jsonify({
            "success": True,
            "allowed4": _parse_nft_set_output(result4.stdout) if result4.returncode == 0 else {},
            "allowed6": _parse_nft_set_output(result6.stdout) if result6.returncode == 0 else {},
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/lists/blacklist', methods=['GET'])
def get_blacklist():
    """读取黑名单 (blacklist4 + blacklist6)"""
    try:
        result4 = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'blacklist4'],
                                 capture_output=True, text=True, timeout=10)
        result6 = subprocess.run(['nft', 'list', 'set', 'inet', 'fw4', 'blacklist6'],
                                 capture_output=True, text=True, timeout=10)
        return jsonify({
            "success": True,
            "blacklist4": _parse_nft_set_output(result4.stdout) if result4.returncode == 0 else {},
            "blacklist6": _parse_nft_set_output(result6.stdout) if result6.returncode == 0 else {},
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/lists/add', methods=['POST'])
def list_add():
    """添加 IP 到指定名单"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    set_name = data.get('set_name', '').strip()
    ip = data.get('ip', '').strip()
    if not set_name or not ip:
        return jsonify({"success": False, "message": "set_name 和 ip 不能为空"}), 400
    if set_name not in VALID_SET_NAMES:
        return jsonify({"success": False, "message": f"无效的 set_name，允许值: {', '.join(sorted(VALID_SET_NAMES))}"}), 400
    try:
        result = subprocess.run(
            ['nft', 'add', 'element', 'inet', 'fw4', set_name, '{', ip, '}'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return jsonify({"success": False, "message": f"添加失败: {result.stderr.strip() or result.stdout.strip()}"}), 400
        return jsonify({"success": True, "message": f"已添加 {ip} 到 {set_name}"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "nft 命令执行超时"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400


@app.route('/api/lists/delete', methods=['POST'])
def list_delete():
    """从指定名单删除 IP"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    set_name = data.get('set_name', '').strip()
    ip = data.get('ip', '').strip()
    if not set_name or not ip:
        return jsonify({"success": False, "message": "set_name 和 ip 不能为空"}), 400
    if set_name not in VALID_SET_NAMES:
        return jsonify({"success": False, "message": f"无效的 set_name，允许值: {', '.join(sorted(VALID_SET_NAMES))}"}), 400
    try:
        result = subprocess.run(
            ['nft', 'delete', 'element', 'inet', 'fw4', set_name, '{', ip, '}'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return jsonify({"success": False, "message": f"删除失败: {result.stderr.strip() or result.stdout.strip()}"}), 400
        return jsonify({"success": True, "message": f"已从 {set_name} 删除 {ip}"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "nft 命令执行超时"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400


@app.route('/api/lists/flush', methods=['POST'])
def list_flush():
    """清空指定名单"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    set_name = data.get('set_name', '').strip()
    if not set_name:
        return jsonify({"success": False, "message": "set_name 不能为空"}), 400
    if set_name not in VALID_SET_NAMES:
        return jsonify({"success": False, "message": f"无效的 set_name，允许值: {', '.join(sorted(VALID_SET_NAMES))}"}), 400
    try:
        result = subprocess.run(
            ['nft', 'flush', 'set', 'inet', 'fw4', set_name],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return jsonify({"success": False, "message": f"清空失败: {result.stderr.strip() or result.stdout.strip()}"}), 400
        return jsonify({"success": True, "message": f"已清空 {set_name}"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "message": "nft 命令执行超时"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400


# ======================= 反向代理模块 =======================
# nftables-web v0.7.6 — HTTPS 反向代理管理

ACME_SH_PATH = os.path.expanduser("~/.acme.sh/acme.sh")
NGINX_SSL_DIR = "/etc/nginx/ssl"
NGINX_CONF_DIR = "/etc/nginx/conf.d"

# TLS 版本映射
TLS_VERSION_MAP = {
    "TLSv1.0": "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
    "TLSv1.1": "TLSv1.1 TLSv1.2 TLSv1.3",
    "TLSv1.2": "TLSv1.2 TLSv1.3",
    "TLSv1.3": "TLSv1.3",
}

def _is_port_in_use(port):
    """检测端口是否被占用"""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def _sanitize_domain(domain):
    """净化域名，防止路径遍历和注入"""
    domain = domain.strip().lower()
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$', domain):
        raise ValueError(f"无效域名格式: {domain}")
    return domain


def _sanitize_target_address(addr):
    """校验目标地址格式（IP:port 或 domain:port）"""
    if not re.match(r'^[a-zA-Z0-9.\-:]+:[0-9]+$', addr):
        raise ValueError(f"无效目标地址: {addr}")
    return addr


# 反代默认设置
RP_DEFAULT_SETTINGS = {
    "http_redirect_enabled": True,
    "hsts_enabled": True,
    "tls_min_version": "TLSv1.2",
    "auto_reload_nginx": True,
}


DNS_PROVIDERS = {
    "ali": {
        "name": "阿里云 DNS",
        "acme_param": "dns_ali",
        "fields": [
            {"key": "Ali_Key", "label": "AccessKey ID", "type": "text"},
            {"key": "Ali_Secret", "label": "AccessKey Secret", "type": "password"}
        ],
        "auto_fill": "aliyun"
    },
    "tencent": {
        "name": "腾讯云 DNSPod",
        "acme_param": "dns_tencent",
        "fields": [
            {"key": "Tencent_SecretId", "label": "SecretId", "type": "text"},
            {"key": "Tencent_SecretKey", "label": "SecretKey", "type": "password"}
        ]
    },
    "cf": {
        "name": "Cloudflare",
        "acme_param": "dns_cf",
        "fields": [
            {"key": "CF_Token", "label": "API Token", "type": "text"}
        ]
    },
    "huaweicloud": {
        "name": "华为云 DNS",
        "acme_param": "dns_huaweicloud",
        "fields": [
            {"key": "HUAWEICLOUD_Username", "label": "Username", "type": "text"},
            {"key": "HUAWEICLOUD_Password", "label": "Password", "type": "password"}
        ]
    },
    "porkbun": {
        "name": "Porkbun",
        "acme_param": "dns_porkbun",
        "fields": [
            {"key": "PORKBUN_API_KEY", "label": "API Key", "type": "text"},
            {"key": "PORKBUN_SECRET_API_KEY", "label": "Secret API Key", "type": "password"}
        ]
    },
    "godaddy": {
        "name": "GoDaddy",
        "acme_param": "dns_gd",
        "fields": [
            {"key": "GD_Key", "label": "API Key", "type": "text"},
            {"key": "GD_Secret", "label": "API Secret", "type": "password"}
        ]
    },
    "namesilo": {
        "name": "NameSilo",
        "acme_param": "dns_namesilo",
        "fields": [
            {"key": "Namesilo_Key", "label": "API Key", "type": "text"}
        ]
    },
    "google": {
        "name": "Google Domains",
        "acme_param": "dns_google",
        "fields": [
            {"key": "GOOGLE_ACCESS_TOKEN", "label": "Access Token", "type": "text"}
        ]
    },
    "duckdns": {
        "name": "DuckDNS",
        "acme_param": "dns_duckdns",
        "fields": [
            {"key": "DUCKDNS_TOKEN", "label": "Token", "type": "text"}
        ]
    },
    "linode": {
        "name": "Linode",
        "acme_param": "dns_linode",
        "fields": [
            {"key": "LINODE_API_KEY", "label": "API Token", "type": "text"}
        ]
    }
}


def _get_dns_credentials(rp, provider_id):
    """获取某 DNS 提供商的凭证，阿里云自动从 DDNS 配置读取"""
    if provider_id == "ali":
        ak_id, ak_secret = _acme_load_aliyun_credentials()
        if ak_id and ak_secret:
            return {"Ali_Key": ak_id, "Ali_Secret": ak_secret}
        return None
    stored = rp.get("dns_credentials", {}).get(provider_id, {})
    return stored if stored else None


def _get_rp_config():
    """获取 reverse_proxy 配置段，确保结构完整"""
    config = load_config()
    rp = config.setdefault("reverse_proxy", {})
    rp.setdefault("rules", [])
    rp.setdefault("certificates", [])
    rp.setdefault("settings", dict(RP_DEFAULT_SETTINGS))
    return config, rp


def _save_rp_config(config):
    """保存包含 reverse_proxy 的完整配置"""
    save_config(config)


def _find_rp_rule(rp, rule_id):
    """按 id 查找反代规则"""
    for r in rp.get("rules", []):
        if r["id"] == rule_id:
            return r
    return None


def _find_rp_cert(rp, cert_id):
    """按 id 查找证书"""
    for c in rp.get("certificates", []):
        if c["id"] == cert_id:
            return c
    return None


def _next_id(prefix, existing_ids):
    """生成下一个可用 ID，格式 prefix_001"""
    nums = []
    for rid in existing_ids:
        m = re.search(r'(\d+)$', rid)
        if m:
            nums.append(int(m.group(1)))
    n = max(nums) + 1 if nums else 1
    return f"{prefix}_{n:03d}"


def _get_cert_expiry(cert_path):
    """用 openssl 读取证书过期时间，返回 (expires_at_str, days_remaining)"""
    if not cert_path or not os.path.exists(cert_path):
        return None, -1
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-enddate", "-issuer", "-subject"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None, -1
        output = result.stdout
        m = re.search(r"notAfter=(.+)", output)
        if not m:
            return None, -1
        raw = m.group(1).strip()
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                dt = datetime.datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        else:
            return None, -1
        expires_at = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        now = datetime.datetime.utcnow()
        days_remaining = (dt - now).days
        return expires_at, days_remaining
    except Exception:
        return None, -1


def _generate_nginx_conf(rule, cert, settings):
    """为一条反代规则生成 nginx 配置（Python 字符串拼接）"""
    domain = _sanitize_domain(rule["domain"])
    listen_port = rule.get("listen_port", 443)
    target = _sanitize_target_address(rule.get("target_address", ""))
    protocol = rule.get("target_protocol", "http")
    websocket = rule.get("websocket_enabled", True)
    cert_path = cert.get("cert_path", "") if cert else ""
    key_path = cert.get("key_path", "") if cert else ""
    http_redirect = settings.get("http_redirect_enabled", True)
    hsts = settings.get("hsts_enabled", True)
    tls_min = settings.get("tls_min_version", "TLSv1.2")
    tls_protos = TLS_VERSION_MAP.get(tls_min, "TLSv1.2 TLSv1.3")
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append(f"# ============================================================")
    lines.append(f"# 反向代理配置: {domain}")
    lines.append(f"# 生成时间: {now_str}")
    lines.append(f"# nftables-web-v2 自动生成，请勿手动修改")
    lines.append(f"# ============================================================")
    lines.append("")

    # HTTP → HTTPS 重定向（检测 80 端口是否可用）
    if http_redirect and not _is_port_in_use(80):
        lines.append("server {")
        lines.append("    listen 80;")
        lines.append("    listen [::]:80;")
        lines.append(f"    server_name {domain};")
        lines.append("")
        lines.append("    return 301 https://$server_name$request_uri;")
        lines.append("}")
        lines.append("")

    # HTTPS server block
    lines.append("server {")
    lines.append(f"    listen {listen_port} ssl;")
    lines.append(f"    listen [::]:{listen_port} ssl;")
    lines.append("    http2 on;")
    lines.append(f"    server_name {domain};")
    lines.append("")
    lines.append("    # SSL")
    lines.append(f"    ssl_certificate {cert_path};")
    lines.append(f"    ssl_certificate_key {key_path};")
    lines.append(f"    ssl_protocols {tls_protos};")
    lines.append("    ssl_prefer_server_ciphers on;")
    lines.append("    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384;")
    lines.append("    ssl_session_timeout 1d;")
    lines.append("    ssl_session_cache shared:SSL:50m;")
    lines.append("    ssl_session_tickets off;")
    lines.append("")
    if hsts:
        lines.append('    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;')
        lines.append("")
    lines.append("    server_tokens off;")
    lines.append("")
    lines.append("    location / {")
    lines.append(f"        proxy_pass {protocol}://{target};")
    lines.append("")
    lines.append("        proxy_set_header Host $http_host;")
    lines.append("        proxy_set_header X-Real-IP $remote_addr;")
    lines.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
    lines.append("        proxy_set_header X-Forwarded-Proto $scheme;")
    lines.append("        proxy_set_header X-Forwarded-Host $host;")
    lines.append("        proxy_set_header X-Forwarded-Port $server_port;")
    lines.append("")
    lines.append("        # DSM/Synology cookie 域重写（解决反代登录态丢失）")
    lines.append("        proxy_cookie_domain ~^(\\d+\\.\\d+\\.\\d+\\.\\d+) $host;")
    lines.append("")
    lines.append("        proxy_buffering off;")
    lines.append("        proxy_request_buffering off;")
    if websocket:
        lines.append("")
        lines.append("        # WebSocket")
        lines.append("        proxy_http_version 1.1;")
        lines.append("        proxy_set_header Upgrade $http_upgrade;")
        lines.append('        proxy_set_header Connection "upgrade";')
    lines.append("")
    lines.append("        proxy_connect_timeout 60s;")
    lines.append("        proxy_send_timeout 300s;")
    lines.append("        proxy_read_timeout 300s;")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _write_nginx_conf_file(rule, cert, settings):
    """生成并写入 nginx 配置文件，返回配置文件路径"""
    domain = _sanitize_domain(rule["domain"])
    listen_port = rule.get("listen_port", 443)
    conf_content = _generate_nginx_conf(rule, cert, settings)
    conf_path = os.path.join(NGINX_CONF_DIR, f"{domain}-{listen_port}.conf")
    os.makedirs(NGINX_CONF_DIR, exist_ok=True)
    with open(conf_path, "w") as f:
        f.write(conf_content)
    return conf_path


def _remove_nginx_conf_file(rule):
    """删除反代规则的 nginx 配置文件"""
    domain = _sanitize_domain(rule.get("domain", ""))
    listen_port = rule.get("listen_port", 443)
    conf_path = os.path.join(NGINX_CONF_DIR, f"{domain}-{listen_port}.conf")
    if os.path.exists(conf_path):
        os.remove(conf_path)
        return True
    return False


def _nginx_test():
    """测试 nginx 配置，忽略 warn 只检查 error"""
    try:
        result = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=10)
        output = result.stderr or result.stdout or ""
        if result.returncode != 0:
            return False, output.strip()
        # 只关心 error 行，warn 可忽略
        for line in output.splitlines():
            if "error" in line.lower():
                return False, line.strip()
        return True, "nginx 配置语法正确"
    except FileNotFoundError:
        return False, "nginx 未安装"
    except subprocess.TimeoutExpired:
        return False, "nginx -t 命令超时"
    except Exception as e:
        return False, str(e)


def _nginx_reload():
    """重载 nginx，如果没运行则启动"""
    try:
        result = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, "nginx 已重载"
    except Exception:
        pass
    # reload 失败，尝试直接启动
    try:
        result = subprocess.run(["nginx"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, "nginx 已启动"
        else:
            return False, f"nginx 启动失败: {result.stderr}"
    except Exception as e:
        return False, f"nginx 启动失败: {str(e)}"


def _acme_load_aliyun_credentials():
    """从阿里云 DDNS 配置中读取 AK/SK，返回 (ak_id, ak_secret)"""
    cfg = _load_aliyun_ddns_config()
    if not cfg:
        return None, None
    return cfg.get("access_key_id", ""), cfg.get("access_key_secret", "")


def _acme_issue(domain, dns_provider="ali", dns_credentials=None):
    """使用 acme.sh + 指定 DNS 提供商申请证书，返回 (ok, result_dict)"""
    domain = _sanitize_domain(domain)
    provider = DNS_PROVIDERS.get(dns_provider)
    if not provider:
        return False, {"error": f"不支持的 DNS 提供商: {dns_provider}"}

    # 收集凭证
    if dns_credentials:
        creds = dns_credentials
    else:
        return False, {"error": f"未提供 {provider['name']} 的 DNS 凭证"}

    # 检查必填字段
    for field in provider["fields"]:
        if not creds.get(field["key"]):
            return False, {"error": f"缺少字段: {field['label']}"}

    if not os.path.exists(ACME_SH_PATH):
        return False, {"error": f"acme.sh 未安装: {ACME_SH_PATH}"}

    cert_dir = os.path.join(NGINX_SSL_DIR, domain)
    os.makedirs(cert_dir, exist_ok=True)

    env = os.environ.copy()
    for field in provider["fields"]:
        env[field["key"]] = creds[field["key"]]

    # 申请证书
    try:
        result = subprocess.run(
            [ACME_SH_PATH, "--issue", "--dns", provider["acme_param"], "-d", domain, "--force"],
            capture_output=True, text=True, env=env, timeout=300
        )
        if result.returncode != 0:
            return False, {"error": "证书申请失败", "log": (result.stderr + result.stdout)[-2000:]}
    except subprocess.TimeoutExpired:
        return False, {"error": "证书申请超时（5分钟）"}
    except Exception as e:
        return False, {"error": str(e)}

    # 安装证书
    fullchain = os.path.join(cert_dir, "fullchain.pem")
    keyfile = os.path.join(cert_dir, "privkey.pem")
    certfile = os.path.join(cert_dir, "cert.pem")
    try:
        result = subprocess.run(
            [ACME_SH_PATH, "--install-cert", "-d", domain,
             "--fullchain-file", fullchain,
             "--key-file", keyfile,
             "--cert-file", certfile,
             "--reloadcmd", "nginx -s reload"],
            capture_output=True, text=True, env=env, timeout=60
        )
        if result.returncode != 0:
            return False, {"error": "证书安装失败", "log": (result.stderr + result.stdout)[-2000:]}
    except Exception as e:
        return False, {"error": str(e)}

    expires_at, days = _get_cert_expiry(fullchain)
    return True, {
        "cert_path": fullchain,
        "key_path": keyfile,
        "expires_at": expires_at,
        "days_remaining": days,
    }


def _acme_renew(domain, dns_provider="ali", dns_credentials=None):
    """使用 acme.sh 续期证书"""
    domain = _sanitize_domain(domain)
    provider = DNS_PROVIDERS.get(dns_provider)
    if not provider:
        return False, {"error": f"不支持的 DNS 提供商: {dns_provider}"}

    creds = dns_credentials or {}
    if not os.path.exists(ACME_SH_PATH):
        return False, {"error": "acme.sh 未安装"}

    env = os.environ.copy()
    for field in provider["fields"]:
        if creds.get(field["key"]):
            env[field["key"]] = creds[field["key"]]

    try:
        result = subprocess.run(
            [ACME_SH_PATH, "--renew", "-d", domain, "--force"],
            capture_output=True, text=True, env=env, timeout=120
        )
        if result.returncode != 0:
            return False, {"error": "证书续期失败", "log": (result.stderr + result.stdout)[-2000:]}
    except Exception as e:
        return False, {"error": str(e)}

    cert_dir = os.path.join(NGINX_SSL_DIR, domain)
    fullchain = os.path.join(cert_dir, "fullchain.pem")
    expires_at, days = _get_cert_expiry(fullchain)
    return True, {"new_expires_at": expires_at, "days_remaining": days}


def _deploy_all_rules(config=None):
    """重新生成所有已启用规则的 nginx 配置并重载 nginx"""
    if config is None:
        config = load_config()
    rp = config.get("reverse_proxy", {})
    rules = rp.get("rules", [])
    certs = {c["id"]: c for c in rp.get("certificates", [])}
    settings = rp.get("settings", RP_DEFAULT_SETTINGS)

    # 先清理不再存在的域名的配置文件
    # 构建当前所有启用规则的文件名集合
    active_conf_files = set()
    for rule in rules:
        if rule.get("enabled"):
            d = _sanitize_domain(rule["domain"])
            p = rule.get("listen_port", 443)
            active_conf_files.add(f"{d}-{p}.conf")

    if os.path.isdir(NGINX_CONF_DIR):
        for fname in os.listdir(NGINX_CONF_DIR):
            if fname.endswith(".conf"):
                if fname not in active_conf_files:
                    os.remove(os.path.join(NGINX_CONF_DIR, fname))

    # 生成所有启用规则的配置
    for rule in rules:
        if not rule.get("enabled"):
            _remove_nginx_conf_file(rule)
            continue
        cert = certs.get(rule.get("ssl_cert_id", ""))
        _write_nginx_conf_file(rule, cert, settings)

    # 测试并重载
    ok, msg = _nginx_test()
    if not ok:
        return False, msg
    ok, msg = _nginx_reload()
    return ok, msg


# ======================= 反代规则 API =======================

@app.route('/api/reverse-proxy/rules', methods=['GET'])
def rp_get_rules():
    config, rp = _get_rp_config()
    certs = {c["id"]: c for c in rp.get("certificates", [])}
    rules_out = []
    for r in rp["rules"]:
        cert = certs.get(r.get("ssl_cert_id", ""))
        cert_path = cert.get("cert_path", "") if cert else ""
        expires_at, days = _get_cert_expiry(cert_path)
        rules_out.append({
            **r,
            "ssl_cert_domain": cert.get("domain", "") if cert else "",
            "ssl_expires_at": expires_at,
            "ssl_days_remaining": days,
            "nginx_config_path": os.path.join(NGINX_CONF_DIR, f"{r['domain']}.conf"),
        })
    return jsonify({"success": True, "data": {"rules": rules_out, "total": len(rules_out)}})


@app.route('/api/reverse-proxy/rules', methods=['POST'])
def rp_create_rule():
    config, rp = _get_rp_config()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    domain = data.get("domain", "").strip()
    try:
        domain = _sanitize_domain(domain)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    target = data.get("target_address", "").strip()
    try:
        target = _sanitize_target_address(target)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    # listen_port 校验
    listen_port = data.get("listen_port", 443)
    if not isinstance(listen_port, int) or not (1 <= listen_port <= 65535):
        return jsonify({"success": False, "message": "listen_port 必须是 1-65535 的整数"}), 400
    # target_protocol 校验
    target_protocol = data.get("target_protocol", "http")
    if target_protocol not in ("http", "https"):
        return jsonify({"success": False, "message": "target_protocol 只允许 http 或 https"}), 400
    cert_id = data.get("ssl_cert_id", "").strip()
    if not domain or not target or not cert_id:
        return jsonify({"success": False, "message": "domain, target_address, ssl_cert_id 不能为空"}), 400
    # 检查证书存在
    cert = _find_rp_cert(rp, cert_id)
    if not cert:
        return jsonify({"success": False, "message": "指定的证书不存在"}), 400
    now_iso = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
    new_id = _next_id("rp", [r["id"] for r in rp["rules"]])
    rule = {
        "id": new_id,
        "enabled": data.get("enabled", True),
        "domain": domain,
        "listen_port": data.get("listen_port", 443),
        "target_address": target,
        "target_protocol": data.get("target_protocol", "http"),
        "websocket_enabled": data.get("websocket_enabled", True),
        "public_access": data.get("public_access", False),
        "ssl_cert_id": cert_id,
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    rp["rules"].append(rule)
    _save_rp_config(config)

    # 生成 nginx 配置并重载
    deploy_ok, deploy_msg = _deploy_all_rules(config)
    if not deploy_ok:
        return jsonify({"success": False, "message": f"规则已保存但 nginx 重载失败: {deploy_msg}"}), 500

    # 更新防火墙
    try:
        variables = config_to_variables(config)
        template = load_template(variables)
        rules_content = generate_rules(template)
        with open(RULES_PATH, 'w') as f:
            f.write(rules_content)
        subprocess.run(["nft", "-f", RULES_PATH], capture_output=True, text=True, timeout=10)
    except Exception:
        pass

    return jsonify({"success": True, "data": {"rule_id": new_id, "message": "反代规则创建成功", "nginx_reloaded": True}})


@app.route('/api/reverse-proxy/rules/<rule_id>', methods=['PUT'])
def rp_update_rule(rule_id):
    config, rp = _get_rp_config()
    rule = _find_rp_rule(rp, rule_id)
    if not rule:
        return jsonify({"success": False, "message": "规则不存在"}), 404
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400

    updatable = ["enabled", "domain", "listen_port", "target_address", "target_protocol",
                 "websocket_enabled", "public_access", "ssl_cert_id"]
    for key in updatable:
        if key in data:
            rule[key] = data[key]

    # 净化域名和目标地址
    try:
        rule["domain"] = _sanitize_domain(rule["domain"])
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    try:
        rule["target_address"] = _sanitize_target_address(rule["target_address"])
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400

    rule["updated_at"] = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
    _save_rp_config(config)

    deploy_ok, deploy_msg = _deploy_all_rules(config)
    if not deploy_ok:
        return jsonify({"success": False, "message": f"规则已更新但 nginx 重载失败: {deploy_msg}"}), 500

    # 更新防火墙
    try:
        variables = config_to_variables(config)
        template = load_template(variables)
        rules_content = generate_rules(template)
        with open(RULES_PATH, 'w') as f:
            f.write(rules_content)
        subprocess.run(["nft", "-f", RULES_PATH], capture_output=True, text=True, timeout=10)
    except Exception:
        pass

    return jsonify({"success": True, "data": {"message": "反代规则已更新", "nginx_reloaded": True}})


@app.route('/api/reverse-proxy/rules/<rule_id>', methods=['DELETE'])
def rp_delete_rule(rule_id):
    config, rp = _get_rp_config()
    rule = _find_rp_rule(rp, rule_id)
    if not rule:
        return jsonify({"success": False, "message": "规则不存在"}), 404
    rp["rules"] = [r for r in rp["rules"] if r["id"] != rule_id]
    _save_rp_config(config)
    _remove_nginx_conf_file(rule)
    deploy_ok, deploy_msg = _deploy_all_rules(config)

    # 更新防火墙
    try:
        variables = config_to_variables(config)
        template = load_template(variables)
        rules_content = generate_rules(template)
        with open(RULES_PATH, 'w') as f:
            f.write(rules_content)
        subprocess.run(["nft", "-f", RULES_PATH], capture_output=True, text=True, timeout=10)
    except Exception:
        pass

    return jsonify({"success": True, "data": {"message": "反代规则已删除", "nginx_reloaded": deploy_ok}})


@app.route('/api/reverse-proxy/rules/<rule_id>/test', methods=['POST'])
def rp_test_rule(rule_id):
    config, rp = _get_rp_config()
    rule = _find_rp_rule(rp, rule_id)
    if not rule:
        return jsonify({"success": False, "message": "规则不存在"}), 404
    target = rule.get("target_address", "")
    if not target:
        return jsonify({"success": False, "message": "目标地址为空"}), 400

    # 解析 host:port
    host = target
    port = 80
    if ":" in target:
        parts = target.rsplit(":", 1)
        host, port = parts[0], int(parts[1])
    if rule.get("target_protocol") == "https":
        port = port or 443

    # TCP 连通性测试
    import socket
    reachable = False
    response_ms = -1
    try:
        t0 = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        response_ms = int((time.time() - t0) * 1000)
        sock.close()
        reachable = True
    except Exception as e:
        return jsonify({"success": True, "data": {"target_reachable": False, "response_time_ms": -1, "ssl_valid": False, "message": f"连接失败: {str(e)}"}})

    return jsonify({"success": True, "data": {
        "target_reachable": True,
        "response_time_ms": response_ms,
        "ssl_valid": True,
        "message": f"目标服务可达 ({response_ms}ms)"
    }})


# ======================= DNS 提供商 API =======================

@app.route('/api/reverse-proxy/dns-providers', methods=['GET'])
def rp_get_dns_providers():
    """获取所有支持的 DNS 提供商列表"""
    config, rp = _get_rp_config()
    stored_creds = rp.get("dns_credentials", {})
    providers_out = []
    for pid, pinfo in DNS_PROVIDERS.items():
        # 检查是否已配置
        creds = _get_dns_credentials(rp, pid)
        configured = bool(creds)
        # 构造 fields（脱敏）
        fields_out = []
        for field in pinfo["fields"]:
            f = {"key": field["key"], "label": field["label"], "type": field["type"]}
            if creds and creds.get(field["key"]):
                if field["type"] == "password":
                    f["value"] = _mask_password(creds[field["key"]])
                else:
                    f["value"] = creds[field["key"]][:4] + "****" if len(creds[field["key"]]) > 4 else "****"
            fields_out.append(f)
        providers_out.append({
            "id": pid,
            "name": pinfo["name"],
            "acme_param": pinfo["acme_param"],
            "fields": fields_out,
            "configured": configured,
        })
    return jsonify({"success": True, "data": {"providers": providers_out}})


# ======================= SSL 证书 API =======================

@app.route('/api/reverse-proxy/certificates', methods=['GET'])
def rp_get_certs():
    config, rp = _get_rp_config()
    certs_out = []
    for c in rp.get("certificates", []):
        expires_at, days = _get_cert_expiry(c.get("cert_path", ""))
        # 读取 issuer
        issuer = ""
        cp = c.get("cert_path", "")
        if cp and os.path.exists(cp):
            try:
                r = subprocess.run(["openssl", "x509", "-in", cp, "-noout", "-issuer"],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0:
                    issuer = r.stdout.strip().replace("issuer=", "")
            except Exception:
                pass
        certs_out.append({
            **c,
            "expires_at": expires_at,
            "days_remaining": days,
            "issuer": issuer,
        })
    return jsonify({"success": True, "data": {"certificates": certs_out, "total": len(certs_out)}})


@app.route('/api/reverse-proxy/certificates/upload', methods=['POST'])
def rp_upload_cert():
    config, rp = _get_rp_config()
    domain = request.form.get("domain", "").strip()
    try:
        domain = _sanitize_domain(domain)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    cert_file = request.files.get("cert_file")
    key_file = request.files.get("key_file")
    if not domain or not cert_file or not key_file:
        return jsonify({"success": False, "message": "domain, cert_file, key_file 不能为空"}), 400

    cert_dir = os.path.join(NGINX_SSL_DIR, domain)
    os.makedirs(cert_dir, exist_ok=True)
    fullchain_path = os.path.join(cert_dir, "fullchain.pem")
    key_path = os.path.join(cert_dir, "privkey.pem")
    cert_file.save(fullchain_path)
    key_file.save(key_path)
    os.chmod(key_path, 0o600)

    expires_at, days = _get_cert_expiry(fullchain_path)
    now_iso = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
    new_id = _next_id("cert", [c["id"] for c in rp.get("certificates", [])])
    cert_entry = {
        "id": new_id,
        "domain": domain,
        "source": "manual",
        "cert_path": fullchain_path,
        "key_path": key_path,
        "expires_at": expires_at,
        "days_remaining": days,
        "auto_renew": False,
        "dns_provider": "",
        "created_at": now_iso,
    }
    rp["certificates"].append(cert_entry)
    _save_rp_config(config)
    return jsonify({"success": True, "data": {"cert_id": new_id, "domain": domain, "cert_path": fullchain_path, "key_path": key_path, "expires_at": expires_at, "message": "证书上传成功"}})


@app.route('/api/reverse-proxy/certificates/request', methods=['POST'])
def rp_request_cert():
    config, rp = _get_rp_config()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"success": False, "message": "domain 不能为空"}), 400
    try:
        domain = _sanitize_domain(domain)
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    # 检查域名唯一
    for c in rp.get("certificates", []):
        if c["domain"] == domain:
            return jsonify({"success": False, "message": f"域名 {domain} 已有证书"}), 400

    dns_provider = data.get("dns_provider", "ali").strip()
    if dns_provider not in DNS_PROVIDERS:
        return jsonify({"success": False, "message": f"不支持的 DNS 提供商: {dns_provider}"}), 400

    # 收集凭证：优先用请求中的，阿里云可以自动读取
    dns_credentials = data.get("dns_credentials")
    if not dns_credentials:
        dns_credentials = _get_dns_credentials(rp, dns_provider)
    if not dns_credentials:
        provider_name = DNS_PROVIDERS[dns_provider]["name"]
        if dns_provider == "ali":
            return jsonify({"success": False, "message": f"未提供 {provider_name} 凭证，且 DDNS 配置中未找到阿里云 AccessKey"}), 400
        return jsonify({"success": False, "message": f"请提供 {provider_name} 的 DNS 凭证"}), 400

    # 非阿里云：保存凭证到配置
    if dns_provider != "ali" and data.get("dns_credentials"):
        if "dns_credentials" not in rp:
            rp["dns_credentials"] = {}
        rp["dns_credentials"][dns_provider] = data["dns_credentials"]

    ok, result = _acme_issue(domain, dns_provider, dns_credentials)
    if not ok:
        return jsonify({"success": False, "message": result.get("error", "证书申请失败"), "log": result.get("log", "")}), 400

    now_iso = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
    new_id = _next_id("cert", [c["id"] for c in rp.get("certificates", [])])
    cert_entry = {
        "id": new_id,
        "domain": domain,
        "source": "auto",
        "dns_provider": dns_provider,
        "cert_path": result["cert_path"],
        "key_path": result["key_path"],
        "expires_at": result["expires_at"],
        "auto_renew": data.get("auto_renew", True),
        "renew_days": data.get("renew_days", 60),
        "created_at": now_iso,
    }
    rp["certificates"].append(cert_entry)
    _save_rp_config(config)
    return jsonify({"success": True, "data": {"cert_id": new_id, "domain": domain, **result, "message": "证书申请成功"}})


@app.route('/api/reverse-proxy/certificates/<cert_id>/renew', methods=['POST'])
def rp_renew_cert(cert_id):
    config, rp = _get_rp_config()
    cert = _find_rp_cert(rp, cert_id)
    if not cert:
        return jsonify({"success": False, "message": "证书不存在"}), 404
    if cert.get("source") != "auto":
        return jsonify({"success": False, "message": "手动上传的证书不支持在线续期"}), 400

    cert_provider = cert.get("dns_provider", "ali")
    dns_credentials = _get_dns_credentials(rp, cert_provider)
    if not dns_credentials:
        return jsonify({"success": False, "message": "未找到 DNS 凭证，无法续期"}), 400

    ok, result = _acme_renew(cert["domain"], cert_provider, dns_credentials)
    if not ok:
        return jsonify({"success": False, "message": result.get("error", "续期失败")}), 400

    cert["expires_at"] = result.get("new_expires_at", "")
    _save_rp_config(config)
    return jsonify({"success": True, "data": {"cert_id": cert_id, "domain": cert["domain"], **result, "message": "证书续期成功"}})


@app.route('/api/reverse-proxy/certificates/<cert_id>', methods=['DELETE'])
def rp_delete_cert(cert_id):
    config, rp = _get_rp_config()
    cert = _find_rp_cert(rp, cert_id)
    if not cert:
        return jsonify({"success": False, "message": "证书不存在"}), 404
    # 检查是否被规则引用
    for r in rp.get("rules", []):
        if r.get("ssl_cert_id") == cert_id:
            return jsonify({"success": False, "message": f"证书被规则 {r['id']} ({r['domain']}) 引用，请先删除关联规则"}), 400

    # 删除证书文件
    domain = _sanitize_domain(cert.get("domain", ""))
    cert_dir = os.path.join(NGINX_SSL_DIR, domain)
    if os.path.isdir(cert_dir):
        shutil.rmtree(cert_dir)

    rp["certificates"] = [c for c in rp["certificates"] if c["id"] != cert_id]
    _save_rp_config(config)
    return jsonify({"success": True, "data": {"message": "证书已删除"}})


# ======================= nginx 管理 API =======================

@app.route('/api/reverse-proxy/nginx/test', methods=['POST'])
def rp_nginx_test():
    ok, msg = _nginx_test()
    return jsonify({"success": True, "data": {"valid": ok, "message": msg}})


@app.route('/api/reverse-proxy/nginx/reload', methods=['POST'])
def rp_nginx_reload():
    ok, msg = _nginx_reload()
    return jsonify({"success": True, "data": {"message": msg}})


@app.route('/api/reverse-proxy/nginx/preview/<rule_id>', methods=['GET'])
def rp_nginx_preview(rule_id):
    config, rp = _get_rp_config()
    rule = _find_rp_rule(rp, rule_id)
    if not rule:
        return jsonify({"success": False, "message": "规则不存在"}), 404
    cert = _find_rp_cert(rp, rule.get("ssl_cert_id", ""))
    settings = rp.get("settings", RP_DEFAULT_SETTINGS)
    conf_content = _generate_nginx_conf(rule, cert, settings)
    conf_path = os.path.join(NGINX_CONF_DIR, f"{rule['domain']}.conf")
    return jsonify({"success": True, "data": {"config_content": conf_content, "config_path": conf_path}})


# ======================= 全局设置 API =======================

@app.route('/api/reverse-proxy/settings', methods=['GET'])
def rp_get_settings():
    config, rp = _get_rp_config()
    settings = dict(rp.get("settings", RP_DEFAULT_SETTINGS))
    settings["default_cert_id"] = rp.get("settings", {}).get("default_cert_id")
    return jsonify({"success": True, "data": settings})


@app.route('/api/reverse-proxy/settings', methods=['POST'])
def rp_save_settings():
    config, rp = _get_rp_config()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体不能为空"}), 400
    settings = rp.setdefault("settings", dict(RP_DEFAULT_SETTINGS))
    for key in ["http_redirect_enabled", "hsts_enabled", "tls_min_version", "auto_reload_nginx"]:
        if key in data:
            settings[key] = data[key]
    _save_rp_config(config)

    # 重新生成所有规则配置
    if settings.get("auto_reload_nginx", True):
        _deploy_all_rules(config)

    return jsonify({"success": True, "data": {"message": "设置已保存"}})



@app.route('/api/reverse-proxy/certificates/<cert_id>/set-default', methods=['POST'])
def rp_set_default_cert(cert_id):
    config, rp = _get_rp_config()
    certs = {c["id"] for c in rp.get("certificates", [])}
    if cert_id not in certs:
        return jsonify({"success": False, "message": f"证书 {cert_id} 不存在"}), 404
    settings = rp.setdefault("settings", dict(RP_DEFAULT_SETTINGS))
    settings["default_cert_id"] = cert_id
    _save_rp_config(config)
    return jsonify({"success": True, "data": {"message": "默认证书已设置", "default_cert_id": cert_id}})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True, debug=os.environ.get('FLASK_DEBUG', '0') == '1')
