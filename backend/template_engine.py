"""
模板引擎：读取 nftables.conf 模板，替换变量和日志开关，生成最终规则。
"""
import re
import os

TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates', 'nftables.conf')


def load_template():
    """读取原始模板"""
    with open(TEMPLATE_PATH, 'r') as f:
        return f.read()


def generate_rules(variables, log_switches):
    """
    根据变量和日志开关生成最终规则。

    variables: dict - 变量名到值的映射
    log_switches: dict - 日志开关名到布尔值的映射

    返回: str - 生成的 nftables 规则文本
    """
    template = load_template()

    # 0. 处理中国IP拦截开关（在日志开关之前，因为日志开关依赖这些行）
    if variables.get("CHINA_IP_BLOCK") == "true":
        template = template.replace("# CHINA_IP_SET_BLOCK",
            "    # 中国IP集合，根据集合文件自动更新\n    set china_ipv4 {\n        type ipv4_addr;\n        flags interval;\n    }")
        template = template.replace("# CHINA_IP_FILTER_BLOCK",
            "        #iifname $WAN_IF ip saddr != @china_ipv4 log prefix \"[FOREIGN-SCAN] \" drop\n"
            "        iifname $WAN_IF ip saddr != @china_ipv4 drop")
        template = template.replace("# CHINA_IP_INCLUDE_BLOCK",
            '# 包含中国IP列表\ninclude "/etc/nftables/china-ips.nft"')
    else:
        template = template.replace("# CHINA_IP_SET_BLOCK", "")
        template = template.replace("# CHINA_IP_FILTER_BLOCK", "")
        template = template.replace("# CHINA_IP_INCLUDE_BLOCK", "")

    # 1. 处理日志开关
    # 逻辑：模板中注释行（带日志版）在前，启用行（无日志版）在后
    # 开关打开时：取消注释带日志行，注释掉无日志行

    # 境外IP拦截日志
    if log_switches.get("foreign_scan_log"):
        template = template.replace(
            "        #iifname $WAN_IF ip saddr != @china_ipv4 log prefix \"[FOREIGN-SCAN] \" drop\n        iifname $WAN_IF ip saddr != @china_ipv4 drop",
            "        iifname $WAN_IF ip saddr != @china_ipv4 log prefix \"[FOREIGN-SCAN] \" drop\n        #iifname $WAN_IF ip saddr != @china_ipv4 drop"
        )

    # WAN拒绝流量日志
    if log_switches.get("wan_drop_log"):
        template = template.replace(
            "        #meta nfproto ipv6 log prefix \"[IPv6-WAN-DROP] \" drop\n        #meta nfproto ipv4 log prefix \"[IPv4-WAN-DROP] \" drop\n        #以上是下面带日志的平替，需要查看拦截调试的时候解除注释\n        meta nfproto ipv6 drop\n        meta nfproto ipv4 drop",
            "        meta nfproto ipv6 log prefix \"[IPv6-WAN-DROP] \" drop\n        meta nfproto ipv4 log prefix \"[IPv4-WAN-DROP] \" drop\n        #以上是下面带日志的平替，需要查看拦截调试的时候解除注释\n        #meta nfproto ipv6 drop\n        #meta nfproto ipv4 drop"
        )

    # LAN拒绝流量日志：由 LAN_MODE_BLOCK 统一处理（在下方）

    # IPv6 WAN→LAN 访问日志
    if log_switches.get("ipv6_wan_lan_log"):
        template = template.replace(
            "#iifname $WAN_IF oifname $LAN_IF meta nfproto ipv6 \\\n        #    log prefix \"[IPv6-WAN-to-LAN-ATTEMPT] \"",
            "iifname $WAN_IF oifname $LAN_IF meta nfproto ipv6 \\\n            log prefix \"[IPv6-WAN-to-LAN-ATTEMPT] \""
        )

    # 2. 替换动态规则块（IPv6 集合、转发、拒绝规则，需在 FORWARD/NAT 之前）
    template = template.replace("# PORT_SETS_BLOCK", variables.get("PORT_SETS_BLOCK", ""))
    template = template.replace("# IPV6_SETS_BLOCK", variables.get("IPV6_SETS_BLOCK", ""))
    template = template.replace("# IPV6_FWD_RULES_BLOCK", variables.get("IPV6_FWD_RULES_BLOCK", ""))
    template = template.replace("# IPV6_DEN_RULES_BLOCK", variables.get("IPV6_DEN_RULES_BLOCK", ""))

    # LAN 模式切换 + LAN 自定义放行端口
    access_mode = variables.get("ACCESS_MODE", "trusted")
    lan_allowed_rules = variables.get("LAN_ALLOWED_RULES", "")
    if access_mode == "lan":
        lan_block = "        # LAN 模式：内网默认放行\n        meta nfproto ipv6 accept\n        meta nfproto ipv4 accept"
    elif log_switches.get("lan_drop_log"):
        # 信任模式 + 开启LAN丢弃日志
        lan_block = (f"{lan_allowed_rules}\n"
            "        # 信任模式：内网默认丢弃（带日志），仅放行基础协议 + 自定义端口 + 敲门/信任IP\n"
            "        meta nfproto ipv6 log prefix \"[IPv6-LAN-DROP] \" drop\n"
            "        meta nfproto ipv4 log prefix \"[IPv4-LAN-DROP] \" drop")
    else:
        # 信任模式：默认丢弃
        lan_block = (f"{lan_allowed_rules}\n"
            "        # 信任模式：内网默认丢弃，仅放行基础协议 + 自定义端口 + 敲门/信任IP\n"
            "        meta nfproto ipv6 drop\n"
            "        meta nfproto ipv4 drop")
    template = template.replace("# LAN_MODE_BLOCK", lan_block)

    # 3. 替换动态转发规则块
    template = template.replace("# FORWARD_RULES_BLOCK", variables.get("FORWARD_RULES_BLOCK", ""))
    template = template.replace("# NAT_RULES_BLOCK", variables.get("NAT_RULES_BLOCK", ""))

    # 3. 替换变量（define KEY = value 格式）
    for key, value in variables.items():
        # 单行匹配
        pattern = rf'define {key}\s*=\s*.+'
        replacement = f'define {key} = {value}'
        template = re.sub(pattern, replacement, template)

    return template
