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


def generate_rules(variables, log_switches, list_elements=None):
    """
    根据变量和日志开关生成最终规则。

    variables: dict - 变量名到值的映射
    log_switches: dict - 日志开关名到布尔值的映射
    list_elements: dict - 名单成员 {allowed4:[...], blacklist4:[...], ...}，
                    用于在规则重建后把黑/白名单回填回 set（见 _inject_list_elements）

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
    # RULESET_PREAMBLE 决定「清空到什么程度」，由 deploy_mode 决定：
    #   openwrt       → flush ruleset：接管整机规则集（项目核心设计，见审查记录 N-1）
    #   linux_gateway → flush table inet fw4：只重建本项目自己的表，
    #                   绝不碰宿主机上 Docker / 管理员自建的其他规则
    # 默认走 openwrt 分支：即使变量缺失也不会退化成「不清理」导致重复应用失败。
    deploy_mode = variables.get("DEPLOY_MODE", "openwrt")
    if deploy_mode == "linux_gateway":
        preamble = (
            "# deploy_mode=linux_gateway: 仅重建本项目自己的表，\n"
            "# 不清空宿主机全局 ruleset（否则会连带清掉 Docker 等其他规则）\n"
            "flush table inet fw4"
        )
    else:
        preamble = (
            "# deploy_mode=openwrt: 接管整机规则集，fw4 已被本项目停用\n"
            "flush ruleset"
        )
    template = template.replace("# RULESET_PREAMBLE", preamble)

    template = template.replace("# PORT_SETS_BLOCK", variables.get("PORT_SETS_BLOCK", ""))
    template = template.replace("# IPV6_SETS_BLOCK", variables.get("IPV6_SETS_BLOCK", ""))
    template = template.replace("# IPV6_FWD_RULES_BLOCK", variables.get("IPV6_FWD_RULES_BLOCK", ""))
    template = template.replace("# IPV6_DEN_RULES_BLOCK", variables.get("IPV6_DEN_RULES_BLOCK", ""))
    template = template.replace("# IPV6_LAN_WAN_DNS_BLOCK", variables.get("IPV6_LAN_WAN_DNS_BLOCK", ""))
    template = template.replace("# DNS_LAN_BLOCK", variables.get("DNS_LAN_BLOCK", ""))

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

    # 白名单访问端口日志
    if log_switches.get("whitelist_access_log"):
        template = template.replace(
            "        # IPv4授权访问\n"
            "        #ip saddr @allowed4 tcp dport @tcp_services log prefix \"[I4-ALV-T] \" accept\n"
            "        #ip saddr @allowed4 udp dport @udp_services log prefix \"[I4-ALV-UDP] \" accept\n"
            "        ip saddr @allowed4 tcp dport @tcp_services accept\n"
            "        ip saddr @allowed4 udp dport @udp_services accept\n"
            "\n"
            "        # IPv6授权访问\n"
            "        #ip6 saddr @allowed6 tcp dport @tcp_services log prefix \"[I6-ALV-T] \" accept\n"
            "        #ip6 saddr @allowed6 udp dport @udp_services log prefix \"[I6-ALV-UDP] \" accept\n"
            "        ip6 saddr @allowed6 tcp dport @tcp_services accept\n"
            "        ip6 saddr @allowed6 udp dport @udp_services accept",
            "        # IPv4授权访问\n"
            "        ip saddr @allowed4 tcp dport @tcp_services log prefix \"[I4-ALV-T] \" accept\n"
            "        ip saddr @allowed4 udp dport @udp_services log prefix \"[I4-ALV-UDP] \" accept\n"
            "        #ip saddr @allowed4 tcp dport @tcp_services accept\n"
            "        #ip saddr @allowed4 udp dport @udp_services accept\n"
            "\n"
            "        # IPv6授权访问\n"
            "        ip6 saddr @allowed6 tcp dport @tcp_services log prefix \"[I6-ALV-T] \" accept\n"
            "        ip6 saddr @allowed6 udp dport @udp_services log prefix \"[I6-ALV-UDP] \" accept\n"
            "        #ip6 saddr @allowed6 tcp dport @tcp_services accept\n"
            "        #ip6 saddr @allowed6 udp dport @udp_services accept"
        )

    # 3. 替换动态转发规则块
    template = template.replace("# FORWARD_RULES_BLOCK", variables.get("FORWARD_RULES_BLOCK", ""))
    template = template.replace("# NAT_RULES_BLOCK", variables.get("NAT_RULES_BLOCK", ""))

    # 3. 替换变量（define KEY = value 格式）
    for key, value in variables.items():
        # 列表类型：转 nftables 集合语法 { elem1, elem2, ... }
        # 例: ["192.168.1.1", "192.168.1.2"] → { 192.168.1.1, 192.168.1.2 }
        if isinstance(value, list):
            # 空列表 / 全是空字符串：跳过替换，保留模板的原始占位符
            non_empty = [e for e in value if str(e).strip()]
            if not non_empty:
                continue
            elements = []
            for elem in non_empty:
                if isinstance(elem, str):
                    # 数字字符串保持原样，否则加引号
                    if elem.isdigit():
                        elements.append(elem)
                    else:
                        elements.append(f'"{elem}"')
                else:
                    elements.append(str(elem))
            value = '{ ' + ', '.join(elements) + ' }'
        # 空值保护：保留引号避免 nftables 解析错误（空值也必须是 ""）
        elif value == "":
            value = '""'
        # 单行匹配
        # 用 lambda 传 replacement：re.sub 会把 replacement 里的 \1 \g<name> \ 当作
        # 替换指令解析，变量值里只要有一个反斜杠就会抛 re.error 让整个规则生成失败。
        pattern = rf'define {key}\s*=\s*.+'
        new_line = f'define {key} = {value}'
        template = re.sub(pattern, lambda _m, _n=new_line: _n, template)

    # 4. 信任 IP 相关规则：条件生成
    #
    # TRUSTED_IP4/6 现在是 fail-closed 的（_safe_ip(..., strict=True)）：
    # 用户填错或清空时返回空串。模板里若还硬写 `ip saddr $TRUSTED_IP4 accept`，
    # 空串会展开成 `ip saddr "" accept` —— nft 语法错误，整套规则加载失败。
    # 所以这两处必须按「有没有配」来生成。
    trusted4 = str(variables.get('TRUSTED_IP4', '') or '').strip()
    trusted6 = str(variables.get('TRUSTED_IP6', '') or '').strip()

    accept_lines = ['        # 未配置信任IP：不生成该放行规则（fail-closed）']
    if trusted4:
        accept_lines.append(f'        ip saddr {trusted4} accept')
    if trusted6:
        accept_lines.append(f'        ip6 saddr {trusted6} accept')
    template = template.replace('__TRUSTED_ACCEPT_BLOCK__', '\n'.join(accept_lines))

    # 敲门链：没有信任 IP 时去掉 `ip saddr != $TRUSTED_IP4` 条件，
    # 让所有来源都走正常敲门流程（而不是留下一条恒真的判断）。
    guard = f'ip saddr != {trusted4}' if trusted4 else ''
    template = template.replace('__TRUSTED_GUARD__', guard)

    # 4.5 LAN→WAN 普通流量放行：条件生成
    #
    # 原来是模板里一条无条件 `iifname $LAN_IF oifname $WAN_IF accept`，
    # 紧跟在两条 DNS 定向放行之后 —— 它无条件为真，把上面「内网只能访问
    # 指定 DNS」的收紧整个吃掉，内网可以随便指向任意 DNS。
    # 现在：dns_lan_resolver_enabled 打开时，本机做 DNS 递归解析，
    # 只放行「指向路由器自己」的 DNS，不放行直连公网 DNS；
    # 关闭时才放行普通 LAN→WAN（保持原有默认行为，不擅自改变用户意图）。
    if variables.get('DNS_LAN_RESOLVER_ENABLED') == 'true':
        # 递归解析时内网应当只跟路由器说话，指向外部 DNS 的请求一律不放行
        general = '        # DNS 递归解析已启用：LAN→WAN 只允许访问路由器自身 DNS\n' \
                  '        # （公网 DNS 直连被拒，防止绕过本机解析与日志）\n' \
                  '        iifname $LAN_IF oifname $WAN_IF meta nfproto ipv4 udp dport 53 \\\n' \
                  '            ip daddr != $ROUTER_IP4 drop'
    else:
        general = '        # 允许其他所有LAN→WAN\n        iifname $LAN_IF oifname $WAN_IF accept'
    template = template.replace('# LAN_WAN_GENERAL_BLOCK\n', '')
    template = template.replace('# LAN_WAN_GENERAL_BLOCK', '')
    template = template.replace('__LAN_WAN_GENERAL__', general)

    # 5. 名单元素回填
    #
    # 为什么需要：模板以 `flush ruleset` 开头，完全重建 table inet fw4。
    # 黑/白名单的成员此前只存在于内核 set 里，用户点「应用规则」或重启
    # 触发重建时，整个 set 变回空声明 —— 名单静默清空，用户毫无感知。
    # 所以成员必须落盘，在每次生成规则时回填进 set 声明体内。
    template = _inject_list_elements(template, list_elements or {})

    return template


def _format_set_elements(elements):
    """把一批 IP 渲染成 nft set 的 elements 声明。

    注意必须带 `elements =` 关键字：nft 的声明式写法是
        set s { type ipv4_addr; elements = { 1.2.3.4, 5.6.7.8 } }
    直接把裸 IP 一行一个塞进 set 体里是语法错误（真机 nft -c 实测报
    "syntax error, unexpected string"），单测只查字符串存在性抓不到。
    """
    seen, out = set(), []
    for raw in elements or []:
        s = str(raw).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _inject_list_elements(template, elements):
    """把名单元素填进模板里对应的占位符。

    元素在写入前必须逐个过一遍 IP 校验 —— 这个文件来自落盘数据，
    一旦被手工改坏（写进 `delete table` 之类），会随规则集一起 nft -f 下去。
    校验失败就丢弃该元素并继续，绝不把可疑内容拼进规则。
    """
    import ipaddress
    for placeholder, key in (
        ('# ALLOWED4_ELEMENTS', 'allowed4'),
        ('# ALLOWED6_ELEMENTS', 'allowed6'),
        ('# BLACKLIST4_ELEMENTS', 'blacklist4'),
        ('# BLACKLIST6_ELEMENTS', 'blacklist6'),
    ):
        want6 = key.endswith('6')
        lines, dropped = [], 0
        for elem in _format_set_elements(elements.get(key)):
            try:
                addr = ipaddress.ip_address(elem.strip())
            except ValueError:
                dropped += 1
                continue
            if (addr.version == 6) != want6:
                dropped += 1
                continue
            lines.append(elem)
        if dropped:
            print(f'[WARN] 名单 {key} 有 {dropped} 个非法元素被丢弃，不写入规则', flush=True)
        if lines:
            # 一行写完，元素多时 nft 会自动折行；折行样式由 nft 自己负责
            block = '        elements = { ' + ', '.join(lines) + ' }'
            template = template.replace(placeholder + '\n', block + '\n')
        else:
            # 没有元素就把占位符整行删掉，不能让注释残留在最终规则集里
            template = template.replace(placeholder + '\n', '')
            template = template.replace(placeholder, '')
    return template
