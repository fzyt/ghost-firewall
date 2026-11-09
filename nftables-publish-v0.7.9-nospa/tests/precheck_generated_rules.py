#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
破坏性操作前的安全闸：生成的规则集会不会把管理通道一起关掉。

用途
----
「应用防火墙规则」（applyRules）会以 `flush ruleset` 开头**完全接管**规则表。
在**没有带外通道**的机器上（无 WAN 网卡、无串口/IPMI，只有 LAN 一根网线连着），
这意味着：如果生成的规则没有放行 LAN 侧的 SSH 22 和面板 5443，
flush 之后我们就再也连不上这台设备 —— 不是「测试失败」，是**设备失联、无法收场**。

所以破坏性档（e2e 的 `click --destructive`）在跑之前必须先回答这个问题。
这个脚本**纯本地**：不碰任何设备，只用项目源码生成规则集，然后检查管理通道。

检查四件事（缺一不可）
----------------------
1. ``input`` 链里有没有跳到 LAN 链的语句（``iifname $LAN_IF jump input_lan``）
   —— 放行规则写在 input_lan 里，input 链不跳过去，规则再不对也不生效。
2. LAN 链里有没有放行管理通道的规则（见下面「两种形态」）。
3. 放行规则是不是排在丢弃规则（``... drop``）**之前**
   —— 顺序反了等于没放行。
4. ``define LAN_IF`` 的值和目标设备实际网卡名是否一致
   —— 网卡名对不上，``iifname`` 永远不匹配，等于没放行。

管理通道的两种放行形态
----------------------
**形态 A：显式放行管理端口** —— 信任模式 ``access_mode=trusted`` 生成的就是它：

    iifname $LAN_IF tcp dport { 22, 5443 } accept

**形态 B：LAN 侧整片放行** —— LAN 模式 ``access_mode=lan`` 生成的就是它：

    meta nfproto ipv4 accept

形态 B 里 22 / 5443 自然都被放行，压根不需要逐个端口去 grep。

⚠️ 2026-11-09 真机实测踩到的坑：安全闸最初**只认形态 A**，而 .232 真机跑的
是 LAN 模式（形态 B）⇒ 闸门对**默认配置**的机器永远判「没保障」⇒ 破坏性档永远
跑不了、闸门形同虚设。根因在 ``app.py`` 的 ``DEFAULT_CONFIG["access_mode"]``
默认值就是 ``"lan"``，而样本配置里缺这个键 ⇒ 模板走的是另一条分支。
判据必须同时认这两种形态。

⚠️ 下面这些形态**不算**「放行管理通道」：

  · ``meta nfproto ipv6 accept`` —— 只放行 IPv6；SSH / 面板走 IPv4，照样断
  · ``ip saddr <某个IP> accept`` —— 只放行一个源地址，换台机器就断
  · ``udp dport 53 accept`` 之类 —— 只放行某个服务

只查「规则文本里出现了 22/5443」是不够的 —— 上面四件事任何一条不成立，
放行都是假的。这正是本脚本存在的原因。

运行
----
    PYTHONDONTWRITEBYTECODE=1 python3 tests/precheck_generated_rules.py
    PYTHONDONTWRITEBYTECODE=1 python3 tests/precheck_generated_rules.py --config <配置.json>
    PYTHONDONTWRITEBYTECODE=1 python3 tests/precheck_generated_rules.py --lan-if eth0
    PYTHONDONTWRITEBYTECODE=1 python3 tests/precheck_generated_rules.py --rules-file <现成规则.nft>

``--rules-file`` 直接检查一份现成的规则文本，跳过「按配置生成」这一步。
用途有两个：一是检查设备上**当前生效**的规则文件；二是让测试能喂进
「故意改坏的规则」来验证本脚本会不会误判 PASS（只查文本里有没有 22/5443
是不够的，放行规则写错位置照样会失联）。

退出码
------
    0  管理通道有保障（可以跑破坏性档）
    1  管理通道没有保障（**不要**跑破坏性档）
    2  其它错误（配置读不到、规则生成失败等）
"""
import argparse
import importlib.util
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BACKEND = os.path.join(ROOT, 'backend')
DEFAULT_CONFIG = os.path.join(HERE, 'fixtures', 'lan232-config.json')

# 管理通道必须活着的端口：SSH + 面板
MGMT_PORTS = (22, 5443)

# ── 形态 B：LAN 侧「整片放行」的几种写法 ─────────────────────────
# 不限端口、不限源地址、且覆盖 IPv4 ⇒ 22 / 5443 都在里面。
#
# 这几条正则都是**整行精确匹配**（锚 ^ $），所以
#   ip saddr 192.168.100.232 accept
# 这种源地址受限的放行**不会**被误判成整片放行 —— 它左边有前缀，匹配不上。
BLANKET_ACCEPTS = (
    re.compile(r'^meta\s+nfproto\s+ipv4\s+accept$'),   # LAN 模式生成的就是这条
    re.compile(r'^accept$'),                          # 最宽的写法
    re.compile(r'^iifname\s+\$LAN_IF\s+accept$'),      # 放行全部 LAN 流量
)

# 任何以 drop 结尾的规则都是「丢弃」——不限具体写法
# （meta nfproto ipv4 drop / meta nfproto ipv4 log prefix "..." drop / counter drop）
DROP_RE = re.compile(r'\bdrop\s*$')


def load_app(tmpdir):
    """加载 app.py，把所有落盘路径指到临时目录 —— 不碰真实文件。"""
    env = {
        'AUTH_CONFIG_PATH': os.path.join(tmpdir, 'config.json'),
        'AUTH_PASSWORD_FILE': os.path.join(tmpdir, 'password.json'),
        'AUTH_SECRET_FILE': os.path.join(tmpdir, 'secret'),
        'AUTH_SESSION_SECRET_FILE': os.path.join(tmpdir, 'session-secret'),
        'AUTH_PANEL_RATELIMIT_FILE': os.path.join(tmpdir, 'ratelimit.json'),
        'AUTH_AUDIT_LOG': os.path.join(tmpdir, 'audit.log'),
        'NFTABLES_WEB_LISTS_PATH': os.path.join(tmpdir, 'lists.json'),
        'NFTABLES_WEB_ALIYUN_CONFIG': os.path.join(tmpdir, 'aliyun.json'),
        'NFTABLES_WEB_RULES_PATH': os.path.join(tmpdir, 'rules.nft'),
        'NFTABLES_WEB_SSL_DIR': os.path.join(tmpdir, 'ssl'),
        'NFTABLES_WEB_NGINX_CONF_DIR': os.path.join(tmpdir, 'nginx-conf'),
    }
    os.environ.update(env)
    sys.path.insert(0, BACKEND)        # app.py 里是裸 import template_engine
    spec = importlib.util.spec_from_file_location(
        'app_precheck', os.path.join(BACKEND, 'app.py'))
    mod = importlib.util.module_from_spec(spec)
    sys.modules['app_precheck'] = mod
    spec.loader.exec_module(mod)
    return mod


def strip_comment(line):
    """去掉行尾注释 —— nft 的注释到行尾为止。"""
    return line.split('#', 1)[0].strip()


def split_chain(lines, name):
    """取出 ``chain <name> { ... }`` 的行（按大括号配平，注释里的花括号忽略）。"""
    start = None
    for i, l in enumerate(lines):
        s = l.strip()
        if s.startswith('chain %s {' % name):
            start = i
            break
    if start is None:
        return []
    depth = 0
    out = []
    for l in lines[start:]:
        code = l.split('#', 1)[0]
        depth += code.count('{') - code.count('}')
        out.append(l)
        if depth == 0 and len(out) > 1:
            break
    return out


def main():
    ap = argparse.ArgumentParser(
        description='检查生成的规则集是否放行管理通道（SSH 22 / 面板 5443）')
    ap.add_argument('--config', default=DEFAULT_CONFIG,
                    help='配置 JSON 路径（默认：%s）' % DEFAULT_CONFIG)
    ap.add_argument('--lan-if', default=None,
                    help='目标设备实际 LAN 网卡名；给了就核对 define LAN_IF 是否一致')
    ap.add_argument('--rules-file', default=None,
                    help='直接检查这份规则文本（跳过按配置生成）')
    args = ap.parse_args()

    if args.rules_file:
        try:
            with open(args.rules_file, encoding='utf-8') as f:
                rules = f.read()
        except Exception as e:
            print('读规则文件失败: %s' % e)
            return 2
    else:
        try:
            with open(args.config, encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception as e:
            print('读配置失败: %s' % e)
            return 2
        cfg.pop('_comment', None)

        tmpdir = tempfile.mkdtemp(prefix='nft-precheck-')
        try:
            app = load_app(tmpdir)
            rules = app.build_rules(cfg)
        except Exception as e:
            print('生成规则失败: %s' % e)
            return 2

    lines = rules.splitlines()
    print('生成规则行数: %d' % len(lines))

    # ---- 1. define LAN_IF 的值 ----
    lan_define = None
    for l in lines:
        s = l.strip()
        if s.startswith('define LAN_IF'):
            lan_define = s.split('=', 1)[1].strip().strip('"')
            break
    print('define LAN_IF = %s' % lan_define)

    # ---- 2. input 链有没有跳到 LAN 链 ----
    input_chain = split_chain(lines, 'input')
    jumps = [l.strip() for l in input_chain if 'jump' in l and 'LAN_IF' in l]
    jump_ok = bool(jumps)

    # ---- 3. LAN 链里的管理通道放行 ----
    lan_chain = split_chain(lines, 'input_lan')
    # 链内代码行：去注释、去空行；保留原行号用于排序检查
    lan_code = []
    for i, l in enumerate(lan_chain):
        code = strip_comment(l)
        if code:
            lan_code.append((i, code))

    # 链内第一个「丢弃」规则的位置（没有则 None）
    drop_at = None
    for i, c in lan_code:
        if DROP_RE.search(c):
            drop_at = i
            break

    # 形态 A：显式放行管理端口
    mgmt_allow = []
    covered = set()
    for i, c in lan_code:
        if 'dport' not in c or 'accept' not in c:
            continue
        ports = {p for p in MGMT_PORTS if re_search_port(c, p)}
        if ports:
            mgmt_allow.append((i, c, sorted(ports)))
            covered |= ports

    # 形态 B：LAN 侧整片放行（不限端口、不限源地址、覆盖 IPv4）
    blanket = [(i, c) for i, c in lan_code
               if any(rx.match(c) for rx in BLANKET_ACCEPTS)]

    # 两种形态任一成立 ⇒ 管理端口被放行
    #
    # 形态 A 下必须是**全部**管理端口都被放行才算有保障：22 通了但 5443 没通，
    # 面板进不去 ⇒ 破坏性档跑不了、也没法用面板恢复，一样是收不了场。
    allow_ok = bool(blanket) or (covered == set(MGMT_PORTS))
    if blanket:
        allow_form = '形态B：LAN 侧整片放行'
    elif covered == set(MGMT_PORTS):
        allow_form = '形态A：显式放行管理端口'
    else:
        allow_form = '无'

    # 放行必须排在丢弃规则之前 —— 顺序反了等于没放行
    if drop_at is None:
        order_ok = True
        order_note = 'LAN 链里没有丢弃规则（无需排序检查）'
    elif blanket:
        order_ok = min(i for i, _ in blanket) < drop_at
        order_note = '整片放行排在丢弃规则之前'
    elif mgmt_allow:
        order_ok = max(i for i, _, _ in mgmt_allow) < drop_at
        order_note = '端口放行排在丢弃规则之前'
    else:
        order_ok = False
        order_note = '链里没有放行规则'

    # ---- 4. 网卡名一致性 ----
    lanif_ok = True
    if args.lan_if:
        lanif_ok = (lan_define == args.lan_if)

    print('\n检查结果:')
    print('  [PASS] input 链跳到 LAN 链' if jump_ok else '  [FAIL] input 链没有跳到 LAN 链')
    for l in jumps:
        print('         %s' % l)
    if allow_ok:
        print('  [PASS] LAN 链放行管理端口 %s（%s）' % (list(MGMT_PORTS), allow_form))
    else:
        print('  [FAIL] LAN 链没有放行全部管理端口 %s（已覆盖 %s，缺 %s）'
              % (list(MGMT_PORTS), sorted(covered),
                 sorted(set(MGMT_PORTS) - covered)))
    for _, s, ports in mgmt_allow:
        print('         %s   <- %s' % (s, ports))
    for _, s in blanket:
        print('         %s   <- 整片放行（覆盖全部管理端口）' % s)
    print('  [PASS] 放行排在丢弃规则之前（%s）' % order_note if order_ok
          else '  [FAIL] 放行排在丢弃规则之后（等于没放行）')
    if args.lan_if:
        print('  [PASS] define LAN_IF 与目标网卡名一致（%s）' % args.lan_if if lanif_ok
              else '  [FAIL] define LAN_IF=%s 与目标网卡名 %s 不一致' % (lan_define, args.lan_if))

    ok = jump_ok and allow_ok and order_ok and lanif_ok
    print('\n结论:')
    if ok:
        print('  管理通道有保障 —— 破坏性档可以跑。')
        return 0
    print('  管理通道**没有**保障 —— 没有带外通道的机器上不要跑破坏性档。')
    return 1


def re_search_port(line, port):
    """这条放行规则里是否含指定端口（按完整数字边界匹配，避免 220 命中 22）。"""
    return re.search(r'\b%d\b' % port, line) is not None


if __name__ == '__main__':
    sys.exit(main())
