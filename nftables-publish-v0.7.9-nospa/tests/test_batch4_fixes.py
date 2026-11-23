#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第四批修复的行为级判据（LAN→WAN 的强制 DNS：去掉写死的公共 DNS）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/test_batch4_fixes.py

测什么
------
面板上有个「DNS 局域网解析」开关（dns_lan_resolver_enabled）。开着时，
模板生成的收紧规则是：

    iifname $LAN_IF oifname $WAN_IF meta nfproto ipv4 udp dport 53 \
        ip daddr != $ROUTER_IP4 drop

意图很清楚：**LAN 只能走路由器自己的 DNS**，防止绕过本机解析与日志
（模板注释原话：「公网 DNS 直连被拒，防止绕过本机解析与日志」）。

但在这条 drop **前面**还有两条 accept，它们的 daddr 集合里写着
114.114.114.114 和 223.5.5.5（IPv6 那边是 2400:3200::1 与
2400:3200:baba::1）—— 公共 DNS 被单独放行 ⇒ 开关形同虚设，
「强制 DNS 到本机」根本没成立。

2026-11-23 改：两对写死的公共 DNS 全部删掉，只留路由器自己。

判据要领
--------
- 必须**剥掉注释**再查「不该出现的地址」：模板的说明性注释里本来就
  写着那些地址的历史，不剥掉就是在查注释而不是查规则。
- 必须真的生成两遍规则（开关开 / 关）：关的时候那条无条件 accept 会把
  一切放行 ⇒ 改动的效果只在「开」的时候才看得见。
- 只查「有没有那条 drop」是不够的（那正是上一轮漏网的根因）：
  必须查**排在它前面的 accept 有没有把公共 DNS 又放回来**。
- 必须钉住**方向**：内网解析走 LAN→LAN（dns_lan_servers），
  与 LAN→WAN 的强制 DNS 是两批互不相干的规则 ⇒ 改后者不能碰前者。

本文件只读仓库里的源码、只在临时目录里写东西：
不碰 /etc/nftables、/var/log、/opt/nftables-web-v2。
"""
import importlib.util as ilu
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(HERE, '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name
          + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def strip_comments(text):
    """去掉 # 注释行 —— 「东西不该出现」类断言必须用去注释版。

    不剥会踩同一个坑踩第二次：模板的说明性注释里本来就写着
    114.114.114.114 这些地址的历史，直接 grep 整份规则文本永远命中。
    """
    return '\n'.join(l for l in text.splitlines()
                     if not l.lstrip().startswith('#'))


# ── 沙箱：环境变量必须在 import app 之前设好 ───────────────────────
TD = tempfile.mkdtemp(prefix='batch4-')
CFG = os.path.join(TD, 'config.json')
PWD = os.path.join(TD, 'password')
SECRET = os.path.join(TD, 'secret')
for _p in (PWD, SECRET):
    with open(_p, 'w', encoding='utf-8') as _f:
        _f.write('x')
with open(CFG, 'w', encoding='utf-8') as _f:
    _f.write('{}')

os.environ.update({
    "AUTH_CONFIG_PATH": CFG,
    "AUTH_PASSWORD_FILE": PWD,
    "AUTH_SECRET_FILE": SECRET,
    "AUTH_RATELIMIT_FILE": os.path.join(TD, 'ratelimit.json'),
    "AUTH_AUDIT_LOG": os.path.join(TD, 'audit.log'),
    "AUTH_API_PORT": "18445",
})

_spec = ilu.spec_from_file_location('_nftapp_batch4', os.path.join(BACKEND, 'app.py'))
panel = ilu.module_from_spec(_spec)
_spec.loader.exec_module(panel)


# ── 生成规则的小工具 ────────────────────────────────────────────────
ROUTER_IP4 = '192.168.100.193'
ROUTER_IP6 = 'fe80::be24:11ff:fe48:325b'

# 写死的四个公共 DNS（IPv4 两个 + IPv6 两个）—— 改完都不该再出现
PUBLIC_DNS = ('114.114.114.114', '223.5.5.5',
               '2400:3200::1', '2400:3200:baba::1')


def build(resolver_enabled, router_ip6=ROUTER_IP6):
    """按配置生成一份规则，返回**去注释后**的有效规则文本。"""
    cfg = dict(panel.DEFAULT_CONFIG)
    cfg.update({
        'lan_subnet4': '192.168.100.0/24',
        'router_ip4': ROUTER_IP4,
        'router_ip6': router_ip6,
        'dns_lan_resolver_enabled': resolver_enabled,
        'dns_lan_servers': ['192.168.100.218'],
        'reverse_proxy': {'rules': []},
    })
    return strip_comments(panel.build_rules(cfg))


def define_value(text, name):
    """取生成文本里 `define <name> = <value>` 的值。

    为什么需要它：规则里写的是 nft 变量 `$ROUTER_IP4`，真正生效的地址
    在顶部的 define 里，由 nft 加载时解析 ⇒ 只看规则行看不到真实地址，
    只看 define 又看不到规则用了哪些地址，两边都得查。
    """
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith(f'define {name} ='):
            return s.split('=', 1)[1].strip().strip('"')
    return None


def daddr_sets(text, v6=False):
    """取出所有「dport 53 ... daddr { ... }」规则里的 daddr 集合。"""
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if 'dport 53' not in s or 'daddr {' not in s:
            continue
        if v6 and 'ip6 daddr' not in s:
            continue
        if not v6 and 'ip6 daddr' in s:
            continue
        if 'oifname $WAN_IF' not in s:
            continue
        seg = s.split('daddr {', 1)[1].split('}', 1)[0]
        out.append((s, [x.strip() for x in seg.split(',')]))
    return out


# ============================================================
sec('第四批：LAN→WAN 的强制 DNS 不再放行写死的公共 DNS')
# ============================================================

r_on = build(True)
r_off = build(False)

# ── ① 开关打开时，IPv4 的 DNS 放行只列路由器自己 ────────────────────
check('define ROUTER_IP4 解析成配置的路由器地址',
      define_value(r_on, 'ROUTER_IP4') == ROUTER_IP4,
      str(define_value(r_on, 'ROUTER_IP4')))
v4_on = daddr_sets(r_on, v6=False)
check('开关打开时，LAN→WAN 仍有 IPv4 的 DNS 放行规则', len(v4_on) >= 2,
      f'找到 {len(v4_on)} 条')
v4_sets = [s for _ln, s in v4_on]
check('IPv4 的 DNS 放行 daddr 集合里只有路由器自己',
      all(s == ['$ROUTER_IP4'] for s in v4_sets),
      str(v4_sets[:3]))

# ── ② 开关打开时，IPv6 的 DNS 放行只列路由器自己 ────────────────────
v6_on = daddr_sets(r_on, v6=True)
check('开关打开时，LAN→WAN 仍有 IPv6 的 DNS 放行规则', len(v6_on) >= 2,
      f'找到 {len(v6_on)} 条')
v6_sets = [s for _ln, s in v6_on]
check('IPv6 的 DNS 放行 daddr 集合里只有路由器自己',
      all(s == [ROUTER_IP6] for s in v6_sets),
      str(v6_sets[:3]))

# ── ③ 四个公共 DNS 一个都不该再出现（去注释版）─────────────────────
for dns in PUBLIC_DNS:
    check(f'规则里不再出现公共 DNS {dns}', dns not in r_on,
          '仍在规则中出现' if dns in r_on else '')

# ── ④ 收紧本身没被顺手删掉 ────────────────────────────────────────
# 规则里写的是 nft 变量 $ROUTER_IP4（真值由上面的 define 解析），
# 所以这里断言的也是变量形式。
check('开关打开时仍在拒绝「指向非路由器 DNS」',
      'ip daddr != $ROUTER_IP4 drop' in r_on)
check('开关打开时不再有无条件的 LAN→WAN 放行',
      'iifname $LAN_IF oifname $WAN_IF accept' not in r_on)

# ── ⑤ 开关关闭时行为不变（不擅自改变用户意图）──────────────────────
check('开关关闭时保持原有的无条件 LAN→WAN 放行',
      'iifname $LAN_IF oifname $WAN_IF accept' in r_off)
for dns in PUBLIC_DNS:
    check(f'开关关闭时规则里也不出现公共 DNS {dns}', dns not in r_off)

# ── ⑥ router_ip6 为空时不生成 IPv6 DNS 块 ─────────────────────────
r_nov6 = build(True, router_ip6='')
check('router_ip6 为空时不生成 IPv6 的 DNS 放行（避免空集合语法错）',
      not daddr_sets(r_nov6, v6=True))

# ── ⑦ 内网解析（LAN→LAN）不受这次改动影响 ──────────────────────────
# 用户关心的点：这次改的是 LAN→WAN（出网方向）的强制 DNS，
# 而内网解析走的是 LAN→LAN 的另一批规则（dns_lan_servers），两者互不相干。
# 这里把「方向」钉死 —— 免得以后有人把内网解析的规则改成出网方向。
lan_lan = [s.strip() for s in r_on.splitlines()
           if 'dport 53' in s and 'iifname $LAN_IF oifname $LAN_IF' in s]
check('内网解析（LAN→LAN）的 DNS 规则仍在，且指向 dns_lan_servers',
      len(lan_lan) >= 2 and all('192.168.100.218' in s for s in lan_lan),
      f'找到 {len(lan_lan)} 条')
check('内网 DNS 服务器没有被放进 LAN→WAN 的放行列表',
      not any('dport 53' in s and 'oifname $WAN_IF' in s
              and '192.168.100.218' in s for s in r_on.splitlines()))

# ── ⑧ 占位符无残留 ────────────────────────────────────────────────
check('模板占位符无残留', '__LAN_WAN_GENERAL__' not in r_on
      and '__IPV6_LAN_WAN_DNS_BLOCK__' not in r_on)


# ============================================================
print('\n' + '=' * 60)
print(f'通过 {len(PASS)} 条，失败 {len(FAIL)} 条')
if FAIL:
    for _f in FAIL:
        print('  [FAIL] ' + _f)
    sys.exit(1)
print('[OK] 全部通过')
sys.exit(0)
