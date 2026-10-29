"""linux_gateway 模式的 ruleset 前导块（preamble）回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_linux_gateway_preamble.py

背景（Shannon 渗透测试 P0-8，2026-10-29 在 .233 的隔离 netns 里实测）
------------------------------------------------------------------
`deploy_mode=linux_gateway` 的前导块原来只有一句 `flush table inet fw4`，
实测出三个问题：

  ① **首次部署整个规则集加载失败**
     `flush table inet fw4` 在表不存在时报错：
       Error: No such file or directory; did you mean table 'fw4' in family inet?
     ⇒ 修法：先 `table inet fw4 { }` 建空表，再 flush。

  ② **`table ip nat` 里的端口转发规则永久残留**
     nft 的 ruleset 文件里写 `table ip nat { chain prerouting { ... } }` 是
     **往已有表里合并**，不是替换 —— 只有显式 flush / delete 才清空。
     用户在面板上删掉端口转发、面板也显示已移除，内核里的
       iifname $WAN_IF tcp dport { 41820 } dnat to 192.168.100.10
     仍然在跑 ⇒ 外网照样能连进内网。
     同理 postrouting 链里的 masquerade / MSS 钳制每 apply 叠加一份。
     ⇒ 修法：把本项目自己那两条链 delete 掉，由模板正文重新定义。

  ③ **不能用 `flush table ip nat`**
     `table ip nat` 是宿主机上的标准 NAT 表，Docker / iptables-nft 的规则
     都在里面。实测 flush 整张表会把 Docker 的 dnat / masquerade 一起清掉
     —— 与 linux_gateway「只重建本项目自己的东西」的设计原则直接冲突。
     ⇒ 修法：只 delete 本项目自己那两条小写链（Docker 用大写链名）。

本文件盯住这些修法不被改坏，特别是**前导块与模板模板不许不同步**。
"""
import os
import re
import sys

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

import template_engine  # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(t):
    print(f'\n=== {t} ===')


def gen(deploy_mode):
    """用模板引擎生成一份规则（只关心前导块与 nat 表）。"""
    variables = {
        "DEPLOY_MODE": deploy_mode,
        "WAN_IF": '"pppoe-wan"', "LAN_IF": '"br-lan"',
        "ROUTER_IP4": "192.168.1.1", "ROUTER_IP6": "fd00::1",
        "LAN_SUBNET4": "192.168.1.0/24", "LAN_BROADCAST4": "192.168.1.255",
        "ULA_PREFIX6": "fd00::/60", "WAN_PREFIX6": "240e::/64",
        "TRUSTED_IP4": "192.168.1.100", "TRUSTED_IP6": "fd00::100",
        "SMTP_PORT": "25", "DNS_PORT": "53", "NTP_PORT": "123",
    }
    log_switches = {}
    return template_engine.generate_rules(variables, log_switches)


TEMPLATE = template_engine.load_template()
LG = gen("linux_gateway")
OW = gen("openwrt")


def preamble_of(rules):
    """取前导块：生成结果开头到模板正文第一条 `define ` 之前。

    不能按「第一个 `table `」切 —— 前导块自己就含 `table inet fw4 { }`，
    那样切出来的不是前导块。模板正文的第一条 `define` 是稳定的分界。
    """
    i = rules.find("\ndefine ")
    return rules[:i] if i > 0 else rules


def nat_block_of(rules, preamble_len):
    """取**模板正文里**那个 table ip nat 块（跳过前导块里的同名块）。

    linux_gateway 的前导块里也有一份 `table ip nat { ... }`（先建出来
    才能 delete），所以不能直接 re.search 第一个 —— 必须从前导块之后找。
    """
    i = rules.find("table ip nat {", preamble_len)
    if i < 0:
        return ""
    m = re.compile(r'table ip nat\s*\{(.*?)\n\}', re.S).search(rules, i)
    return m.group(1) if m else ""


def table_body(src, header):
    """按**大括号配对**取一个块的内容。

    为什么不用正则 `table X \\{(.*?)\\n\\}`：那个写法依赖「内层闭合大括号
    必须缩进、表闭合大括号必须顶格」这个排版约定。模板一旦被重排版，
    解析会悄悄截断 —— 后面的「每条链都必须被 preamble delete」防护就
    **静默失效**（DeepSeek 独立审查指出的问题）。按大括号深度走则与
    排版无关。
    """
    i = src.find(header)
    if i < 0:
        return ""
    j = src.find("{", i)
    if j < 0:
        return ""
    depth = 0
    for k in range(j, len(src)):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                return src[j + 1:k]
    return ""


LG_PREAMBLE = preamble_of(LG)
OW_PREAMBLE = preamble_of(OW)


# ═════════════════════════════════════════════════════════════════════
sec('① 首次部署：fw4 表不存在时不能报错')

check('linux_gateway 前导块先建空表再 flush',
      'table inet fw4 { }' in LG_PREAMBLE
      and LG_PREAMBLE.find('table inet fw4 { }') < LG_PREAMBLE.find('flush table inet fw4'),
      'flush table X 在表不存在时报错 → 首次部署整个规则集加载失败')
check('openwrt 分支不受影响（仍是 flush ruleset）',
      'flush ruleset' in OW_PREAMBLE and 'flush table inet fw4' not in OW_PREAMBLE)
check('openwrt 分支没有引入 delete/flush chain ip nat',
      'ip nat' not in OW_PREAMBLE,
      'openwrt 走 flush ruleset，整表都清了，不需要额外动作')


# ═════════════════════════════════════════════════════════════════════
sec('② table ip nat 必须被重建（陈旧转发规则不能残留）')

check('前导块里 delete 了 prerouting 链',
      'delete chain ip nat prerouting' in LG_PREAMBLE)
check('前导块里 delete 了 postrouting 链',
      'delete chain ip nat postrouting' in LG_PREAMBLE,
      'postrouting 链里的 masquerade / MSS 钳制每 apply 也会叠加一份')

check('**没有**用 flush table ip nat（会清掉宿主机 Docker 的规则）',
      'flush table ip nat' not in LG_PREAMBLE,
      'table ip nat 是宿主机标准 NAT 表，Docker 的 dnat/masquerade 都在里面')
check('**没有**用 flush ruleset（会清掉宿主机全部规则）',
      'flush ruleset' not in LG_PREAMBLE)

# delete 要求链先存在 → 前导块必须先把两条链建出来
_lg_nat_body = table_body(LG_PREAMBLE, "table ip nat {")
check('前导块先把两条链建出来（delete 要求链存在）',
      'chain prerouting' in _lg_nat_body and 'chain postrouting' in _lg_nat_body,
      f'链不存在时 delete chain 会报错 → 整个规则集 apply 失败；'
      f'解析到的 nat 块={_lg_nat_body.strip()!r}')

# ⚠️ 顺序必须对：脚手架（建链）在前，delete 在后。
# DeepSeek 独立审查提出：现在只断言了 fw4 的「先建表后 flush」顺序，
# 没断言 delete 必须在脚手架块**之后** —— 将来有人把 delete 挪到块前面，
# 上面那些断言照样全绿，但 nft 运行时会报 "No such file or directory"。
_i_scaffold = LG_PREAMBLE.find("table ip nat {")
_i_delete = LG_PREAMBLE.find("delete chain ip nat prerouting")
check('delete 必须在「建链脚手架」之后（nft 按文件顺序求值）',
      _i_scaffold >= 0 and _i_delete >= 0 and _i_scaffold < _i_delete,
      f'脚手架位置={_i_scaffold}，delete 位置={_i_delete}')
check('两条 delete 都在脚手架之后',
      LG_PREAMBLE.find("delete chain ip nat postrouting") > _i_scaffold,
      f'postrouting delete 位置={LG_PREAMBLE.find("delete chain ip nat postrouting")}')


# ═════════════════════════════════════════════════════════════════════
sec('③ 前导块与模板不许不同步（防将来改模板时漏改）')

# 从模板里取出 table ip nat 里的链名 + hook 声明
_nat_body = table_body(TEMPLATE, "table ip nat {")
_tpl_chains = re.findall(r'chain\s+(\w+)\s*\{', _nat_body)
# 链名 → "type nat hook <hook> priority <prio>"（模板里的原文）
_tpl_hooks = {}
for _c, _h, _p in re.findall(
        r'chain\s+(\w+)\s*\{[^}]*?type\s+nat\s+hook\s+(\w+)\s+priority\s+(\w+)',
        _nat_body):
    _tpl_hooks[_c] = f"type nat hook {_h} priority {_p}"
check('从模板里解析出了 table ip nat 的链', bool(_tpl_chains),
      f'解析结果={_tpl_chains}')
check('从模板里解析出了 table ip nat 的 hook 声明', bool(_tpl_hooks),
      f'解析结果={_tpl_hooks}')
# ⚠️ 防解析截断（DeepSeek 独立审查提出）：
# 原来用 `re.search(r'table ip nat\s*\{(.*?)\n\}')` 依赖「链闭合大括号缩进
# 4 空格、表闭合大括号顶格」这个格式约定。模板一旦被重排版，解析可能只
# 取到 prerouting，后面「每条链都必须被 delete」的防护就**静默失效**。
# 现在改成按大括号配对取块（table_body，与缩进无关），并加一条
# 「解析到的链数必须 ≥ 2」的断言：截断了就直接红，不会悄悄放过。
check('table ip nat 的链解析没有被截断（至少解析出 2 条）',
      len(_tpl_chains) >= 2,
      f'解析结果={_tpl_chains} —— 若模板被重排版导致截断，这条会红')

for _c in _tpl_chains:
    check(f'模板里的链 {_c} 被前导块 delete 了',
          f'delete chain ip nat {_c}' in LG_PREAMBLE,
          '模板给 table ip nat 加了新链却忘了 delete → 陈旧规则又会累积')
    # 前导块里为这条链声明的 hook 必须和模板一致
    _seg = re.search(r'chain\s+' + re.escape(_c) + r'\s*\{([^}]*)\}', LG_PREAMBLE)
    _seg_body = _seg.group(1) if _seg else ""
    _tpl_hook = _tpl_hooks.get(_c)
    if _tpl_hook:
        check(f'前导块里 {_c} 的 hook 声明与模板一致',
              _tpl_hook in _seg_body,
              f'模板={_tpl_hook!r}，前导块={_seg_body.strip()!r}；'
              f'不一致时 delete 方案仍以模板为准（无副作用），'
              f'但 flush chain 方案会直接 apply 失败')


# ═════════════════════════════════════════════════════════════════════
sec('④ 生成的完整规则里，nat 表结构没被改坏')

check('生成的规则里 table ip nat 存在', 'table ip nat {' in LG)
check('生成的规则里 prerouting 链存在', 'chain prerouting {' in LG)
check('生成的规则里 postrouting 链存在', 'chain postrouting {' in LG)
check('NAT_RULES_BLOCK 占位符已被替换',
      '# NAT_RULES_BLOCK' not in LG)
# 两个分支只有前导块不同，模板正文（nat 表）必须完全一致
_lg_nat_gen = nat_block_of(LG, len(LG_PREAMBLE))
_ow_nat_gen = nat_block_of(OW, len(OW_PREAMBLE))
check('linux_gateway 与 openwrt 生成的 nat 表内容一致',
      bool(_lg_nat_gen) and _lg_nat_gen == _ow_nat_gen,
      '两个分支的模板正文相同，只有前导块不同')
check('模板正文的 nat 表里 masquerade 仍在（没被前导块逻辑误删）',
      'masquerade' in _lg_nat_gen,
      'linux_gateway 的 nat 表也要有 masquerade，否则出网 NAT 没了')

# ═════════════════════════════════════════════════════════════════════
sec('⑤ 模板的顶层表集合（DeepSeek 独立审查提出）')

# 模板若将来新增第三张顶层表，那张表同样不会被 flush —— P0-8 这一整类
# bug 会换个表名复活。所以这里把「顶层表集合」钉死：加表必须同时想清楚
# 「这张表谁来清」，否则测试直接红。
_tpl_tables = re.findall(r'^table\s+(\S+)\s+(\S+)\s*\{', TEMPLATE, re.M)
_tpl_table_set = {f"{_f} {_n}" for _f, _n in _tpl_tables}
check('模板的顶层表集合就是 fw4 + nat 两张',
      _tpl_table_set == {"inet fw4", "ip nat"},
      f'实际={sorted(_tpl_table_set)} —— 新增顶层表必须同时想清楚谁来清它，'
      f'否则同样的「陈旧规则残留」bug 会换个表名复活')
check('两张顶层表都被 linux_gateway 的前导块覆盖',
      'flush table inet fw4' in LG_PREAMBLE
      and 'table ip nat' in LG_PREAMBLE,
      'fw4 由 flush table 清；nat 由 delete 本项目自己的两条链清')

print()
print(f'  合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
if FAIL:
    for name in FAIL:
        print(f'  ❌ {name}')
    sys.exit(1)
print('  全部通过')
