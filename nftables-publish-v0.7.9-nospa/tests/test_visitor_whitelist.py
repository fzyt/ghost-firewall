#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""网关访客页 + 白名单时效分离：行为级判据（2026-11-18）

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_visitor_whitelist.py

这批功能是什么
--------------
用户要两样东西：

  1. 访客页 —— 最近一段时间访问过网关端口的 IP 列表，右边一键加白名单。
  2. 加白名单的时效**与端口敲门的时效分开**，可自定义，默认 10 分钟。

第 2 条挖出一个真实的坑（这是本判据重点守的东西）
--------------------------------------------------
「敲门成功后该 IP 免敲门多久」走的是 nft set 的**默认** timeout
（`whitelist_timeout`，默认 5 小时）；「手动加的白名单」走的是**元素级**
timeout（`nft add element ... { ip timeout 600s }`）。

但手动加的那个元素级 timeout **只存在内核里**：名单文件（lists.json）
落盘的是**裸 IP** ⇒ 一旦点「应用规则」重建 set，回填的是裸 IP ⇒
元素级 timeout 丢失 ⇒ 用户手动加的「10 分钟」悄悄变回 **5 小时**。

⇒ 所以「时效分离」必须做到**落盘也带得上**，否则只是看着分离。
本判据第 2 组守的就是这条：重建规则后时效仍然是 10 分钟。

沙箱
----
全部在临时目录里跑：CONFIG_PATH / LISTS_PATH / RULES_PATH 都指到 tmpdir，
subprocess.run 一律打桩 ⇒ **绝不碰本机 /etc、绝不碰真设备**。
"""
import importlib.util as ilu
import json
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def load_app(tag):
    """加载一份**独立的** app 模块实例（不同 tag ⇒ 不共享全局状态）。"""
    spec = ilu.spec_from_file_location('_nftapp_' + tag, os.path.join(BACKEND, 'app.py'))
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_te(tag):
    """加载一份**独立的** template_engine 模块实例。"""
    spec = ilu.spec_from_file_location('_nftte_' + tag,
                                       os.path.join(BACKEND, 'template_engine.py'))
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeProc:
    """冒充 subprocess.run 的返回值。"""

    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def make_client(app):
    """起一个已登录的 test client（绕开密码文件/限流那堆无关依赖）。"""
    client = app.app.test_client()
    cfg = {'panel_allowed_nets': '127.0.0.1/32',
           'lan_subnet4': '127.0.0.1/32',
           'trusted_ip4': '192.168.100.50',
           'router_ip4': '192.168.100.1',
           'auth_token_epoch': 1}
    with open(app.CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f)
    app._NETS_CACHE.update(mtime=None, nets=None)
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['auth_epoch'] = app._current_token_epoch()
        sess['last_active'] = time.time()
    return client


def session_alive(client):
    """探针：会话现在还有效吗（排除「401 冒充测试结果」）。"""
    try:
        return client.get('/api/config').status_code == 200
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════
# 一、名单元素的中间形态解析（单元级）
# ══════════════════════════════════════════════════════════════════════

def group1_split_elem():
    sec('1 单元级：split_list_elem —— 名单元素的 timeout 子句解析')
    te = load_te('vis1')

    check('纯 IP ⇒ (ip, 空子句)',
          te.split_list_elem('1.2.3.4') == ('1.2.3.4', ''))
    check("带 timeout 600s ⇒ (ip, ' timeout 600s')",
          te.split_list_elem('1.2.3.4 timeout 600s') == ('1.2.3.4', ' timeout 600s'))
    check('裸数字形式也收（600 ⇒ 600s）',
          te.split_list_elem('1.2.3.4 timeout 600') == ('1.2.3.4', ' timeout 600s'))
    check('IPv6 也能拆（地址里的冒号不是分隔符）',
          te.split_list_elem('2001:db8::1 timeout 60s') == ('2001:db8::1', ' timeout 60s'))

    # 非法形态必须**整个丢弃** —— timeout 子句会被原样拼进 nft 规则文本，
    # 而规则集文件是 `nft -f` 执行的 ⇒ 放行一个脏形态等于往防火墙里塞指令。
    bad_cases = [
        ('1.2.3.4 timeout 0s', '0 秒'),
        ('1.2.3.4 timeout 999999999s', '超出上限'),
        ('1.2.3.4 timeout 60m', '分钟单位（元素级只认秒）'),
        ('1.2.3.4 timeout 600s drop', '多出一截'),
        ('1.2.3.4 timeout １s', '全角数字'),
        ('1.2.3.4 timeout abc', '非数字'),
        ('1.2.3.4; delete table inet fw4', '注入'),
        ('1.2.3.4 timeout 600s; delete table inet fw4', '注入（带 timeout）'),
        ('', '空串'),
    ]
    for raw, why in bad_cases:
        check(f'非法形态被丢弃（{why}）',
              te.split_list_elem(raw) == (None, ''), repr(raw)[:60])

    check('上限常量是正整数（7 天）',
          isinstance(te.LIST_ELEM_MAX_TIMEOUT, int) and te.LIST_ELEM_MAX_TIMEOUT == 604800,
          str(getattr(te, 'LIST_ELEM_MAX_TIMEOUT', None)))


# ══════════════════════════════════════════════════════════════════════
# 二、时效分离（行为级）
# ══════════════════════════════════════════════════════════════════════

def group2_whitelist_ttl():
    sec('2 行为级：list_add 的元素级 timeout + 与敲门时效分离')
    app = load_app('vis2')
    d = tempfile.mkdtemp(prefix='nftvis-')
    app.CONFIG_PATH = os.path.join(d, 'config.json')
    app.LISTS_PATH = os.path.join(d, 'lists.json')
    app.RULES_PATH = os.path.join(d, 'rules.conf')
    client = make_client(app)

    nft_calls = []

    def fake_run(cmd, *a, **k):
        nft_calls.append(cmd)
        return FakeProc(returncode=0, stdout='')

    real_run = app.subprocess.run
    app.subprocess.run = fake_run
    try:
        check('会话有效（排除 401 冒充结果）', session_alive(client))

        # ── (a) 白名单 + timeout ⇒ 内核命令必须带元素级 timeout ──
        nft_calls.clear()
        r = client.post('/api/lists/add',
                        json={'set_name': 'allowed4', 'ip': '203.0.113.5', 'timeout': 600})
        check('白名单带 timeout ⇒ 200', r.status_code == 200, f'实际 {r.status_code}')
        check('内核命令里带了元素级 timeout 600s',
              any('timeout' in c and '600s' in c for c in nft_calls),
              str(nft_calls)[:200])
        check('内核命令里的 IP 正确',
              any('203.0.113.5' in c for c in nft_calls), str(nft_calls)[:200])

        # 时效必须**落进 config**（名单文件里只存裸 IP，格式不变）
        cfg = json.load(open(app.CONFIG_PATH, encoding='utf-8'))
        check('config 的 whitelist_ttls 记下了 203.0.113.5 → 600',
              cfg.get('whitelist_ttls', {}).get('203.0.113.5') == 600,
              str(cfg.get('whitelist_ttls'))[:120])
        lists_raw = (open(app.LISTS_PATH, encoding='utf-8').read()
                     if os.path.exists(app.LISTS_PATH) else '')
        check('名单文件里仍是**裸 IP**（格式不变，老设备升级零风险）',
              '203.0.113.5' in lists_raw and 'timeout' not in lists_raw,
              lists_raw[:120])

        # ── (b) 不带 timeout ⇒ 保持原行为（不带元素级 timeout）──
        nft_calls.clear()
        r = client.post('/api/lists/add',
                        json={'set_name': 'allowed4', 'ip': '203.0.113.9'})
        check('不带 timeout ⇒ 200（不破坏既有调用方）',
              r.status_code == 200, f'实际 {r.status_code}')
        check('不带 timeout ⇒ 内核命令不带 timeout 子句（沿用 set 默认 = 敲门那套）',
              any('203.0.113.9' in c and 'timeout' not in c for c in nft_calls),
              str(nft_calls)[:200])
        cfg = json.load(open(app.CONFIG_PATH, encoding='utf-8'))
        check('不带 timeout ⇒ 不写 whitelist_ttls（没有时效就是没有）',
              '203.0.113.9' not in cfg.get('whitelist_ttls', {}),
              str(cfg.get('whitelist_ttls'))[:120])

        # ── (c) 黑名单带 timeout ⇒ 必须被拒（黑名单 set 没有 timeout 标志）──
        nft_calls.clear()
        r = client.post('/api/lists/add',
                        json={'set_name': 'blacklist4', 'ip': '203.0.113.7', 'timeout': 600})
        check('黑名单带 timeout ⇒ 400', r.status_code == 400, f'实际 {r.status_code}')
        check('黑名单带 timeout ⇒ 没有调 nft（校验在 nft 之前）',
              len(nft_calls) == 0, f'调用了 {len(nft_calls)} 次')

        # ── (d) 非法 timeout 一律 400，且不碰 nft ──
        for bad in (-1, 'abc', 999999999, '60m'):
            nft_calls.clear()
            r = client.post('/api/lists/add',
                            json={'set_name': 'allowed4', 'ip': '203.0.113.8',
                                  'timeout': bad})
            check(f'非法 timeout {bad!r} ⇒ 400',
                  r.status_code == 400, f'实际 {r.status_code}')
            check(f'非法 timeout {bad!r} ⇒ 没调 nft',
                  len(nft_calls) == 0, f'调用了 {len(nft_calls)} 次')

        # ── (e) 删除 IP ⇒ 时效记录一起清掉 ──
        r = client.post('/api/lists/delete',
                        json={'set_name': 'allowed4', 'ip': '203.0.113.5'})
        check('删除名单成员 ⇒ 200', r.status_code == 200, f'实际 {r.status_code}')
        cfg = json.load(open(app.CONFIG_PATH, encoding='utf-8'))
        check('删除后 whitelist_ttls 里那条也清了',
              '203.0.113.5' not in cfg.get('whitelist_ttls', {}),
              str(cfg.get('whitelist_ttls'))[:120])

        # ── (f) 清空名单 ⇒ 该名单所有 IP 的时效一起清掉 ──
        nft_calls.clear()
        r = client.post('/api/lists/add',
                        json={'set_name': 'allowed4', 'ip': '203.0.113.11', 'timeout': 120})
        check('再加一条带时效的 ⇒ 200', r.status_code == 200, f'实际 {r.status_code}')
        r = client.post('/api/lists/flush', json={'set_name': 'allowed4'})
        check('清空名单 ⇒ 200', r.status_code == 200, f'实际 {r.status_code}')
        cfg = json.load(open(app.CONFIG_PATH, encoding='utf-8'))
        check('清空后 whitelist_ttls 里没有残留',
              '203.0.113.11' not in cfg.get('whitelist_ttls', {}),
              str(cfg.get('whitelist_ttls'))[:120])
    finally:
        app.subprocess.run = real_run
        shutil.rmtree(d, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════
# 三、规则回填：重建 set 之后时效仍然在（这一组是本批的核心）
# ══════════════════════════════════════════════════════════════════════

def group3_ruleset_refill():
    sec('3 行为级：「应用规则」重建 set 之后，10 分钟仍然是 10 分钟')
    app = load_app('vis3')
    d = tempfile.mkdtemp(prefix='nftvis-')
    app.CONFIG_PATH = os.path.join(d, 'config.json')
    app.LISTS_PATH = os.path.join(d, 'lists.json')
    app.RULES_PATH = os.path.join(d, 'rules.conf')
    os.makedirs(d, exist_ok=True)

    # 名单文件里是裸 IP（真实形态），时效在 config 里（真实形态）
    with open(app.LISTS_PATH, 'w', encoding='utf-8') as f:
        json.dump({'allowed4': ['203.0.113.5'], 'allowed6': [],
                   'blacklist4': ['203.0.113.66'], 'blacklist6': []}, f)
    cfg = {'panel_allowed_nets': '127.0.0.1/32',
           'lan_subnet4': '127.0.0.1/32',
           'trusted_ip4': '192.168.100.50',
           'router_ip4': '192.168.100.1',
           'auth_token_epoch': 1,
           'whitelist_ttls': {'203.0.113.5': 600,
                              '203.0.113.66': 600}}
    with open(app.CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f)

    real_run = app.subprocess.run
    app.subprocess.run = lambda *a, **k: FakeProc(returncode=0, stdout='')
    try:
        rules = app.build_rules(cfg)
        check('生成的规则里白名单元素带上了 timeout 600s',
              '203.0.113.5 timeout 600s' in rules,
              [ln.strip() for ln in rules.splitlines() if '203.0.113.5' in ln][:3])
        check('黑名单元素**不带** timeout（黑名单 set 没有 timeout 标志）',
              '203.0.113.66 timeout' not in rules,
              [ln.strip() for ln in rules.splitlines() if '203.0.113.66' in ln][:3])

        # 时效字典里的 IP 不在名单里 ⇒ 不得凭空出现在规则里
        cfg2 = dict(cfg)
        cfg2['whitelist_ttls'] = {'198.51.100.9': 600}
        rules2 = app.build_rules(cfg2)
        check('时效字典里有、名单里没有的 IP 不会凭空进规则',
              '198.51.100.9' not in rules2)

        # 单元级：_apply_list_timeouts 的边界
        els = {'allowed4': ['1.2.3.4'], 'allowed6': ['2001:db8::1'],
               'blacklist4': ['5.6.7.8'], 'blacklist6': []}
        out = app._apply_list_timeouts(els, {'1.2.3.4': 60, '5.6.7.8': 60})
        check('_apply_list_timeouts 只对白名单生效（黑名单仍是无 timeout 的裸 IP）',
              out['blacklist4'] == ['5.6.7.8'], str(out.get('blacklist4')))
        check('_apply_list_timeouts 给白名单元素加上 timeout 子句',
              out['allowed4'] == ['1.2.3.4 timeout 60s'], str(out.get('allowed4')))
        check('_apply_list_timeouts 不改传入的原对象（别处还要拿它统计条数）',
              els['allowed4'] == ['1.2.3.4'], str(els['allowed4']))
        check('_apply_list_timeouts 在没有时效字典时原样返回',
              app._apply_list_timeouts(els, {}) is els or
              app._apply_list_timeouts(els, {}) == els)
        check('_apply_list_timeouts 忽略非法时效值（布尔不算数字）',
              app._apply_list_timeouts({'allowed4': ['1.2.3.4']},
                                       {'1.2.3.4': True})['allowed4'] == ['1.2.3.4'])

        # ── 规则集**文件**那条路（设备重启加载的是它，不是内核内存）──
        # 为什么必须单独测：build_rules 与 _persist_list_elements_to_ruleset
        # 是两条独立的路，只测前者的话，后者在重建时丢掉时效没人发现。
        base = app.build_rules(dict(cfg, whitelist_ttls={}))
        check('对照组：没有时效字典时规则里是裸 IP',
              '203.0.113.5' in base and '203.0.113.5 timeout' not in base)
        with open(app.RULES_PATH, 'w', encoding='utf-8') as f:
            f.write(base)
        app._persist_list_elements_to_ruleset(
            {'allowed4': ['203.0.113.5'], 'allowed6': [],
             'blacklist4': ['203.0.113.66'], 'blacklist6': []})
        after = open(app.RULES_PATH, encoding='utf-8').read()
        check('同步进规则集文件后，白名单元素带上了 timeout 600s（重启后仍有效）',
              '203.0.113.5 timeout 600s' in after,
              [ln.strip() for ln in after.splitlines() if '203.0.113.5' in ln][:3])
    finally:
        app.subprocess.run = real_run
        shutil.rmtree(d, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════
# 四、访客列表（行为级）
# ══════════════════════════════════════════════════════════════════════

GW_LOG_SAMPLE = (
    '2026-11-17T23:51:24+08:00 192.168.100.249 GET 200 2764 rt=0.002 '
    'host="192.168.100.193" uri="/siy/" ua="Mozilla/5.0" ref="-" '
    'auth_user="" auth_dev="dev-abc"\n'
    '2026-11-17T23:52:21+08:00 192.168.100.249 GET 302 0 rt=0.001 '
    'host="192.168.100.193" uri="/siy/login" ua="Mozilla/5.0" ref="-" '
    'auth_user="" auth_dev="dev-abc"\n'
    '2026-11-17T23:53:00+08:00 10.0.0.9 GET 200 100 rt=0.010 '
    'host="siyuan.fzyto.top" uri="/" ua="curl/8.23.0" ref="-" '
    'auth_user="" auth_dev=""\n'
    '2026-11-17T23:54:00+08:00 10.0.0.9 POST 401 12 rt=0.003 '
    'host="siyuan.fzyto.top" uri="/auth/login" ua="curl/8.23.0" ref="-" '
    'auth_user="" auth_dev=""\n'
)


def group4_visitors():
    sec('4 行为级：/api/gateway/visitors —— 解析 nginx 访问日志并按 IP 聚合')
    app = load_app('vis4')
    d = tempfile.mkdtemp(prefix='nftvis-')
    app.CONFIG_PATH = os.path.join(d, 'config.json')
    app.LISTS_PATH = os.path.join(d, 'lists.json')
    log_path = os.path.join(d, 'gateway.access.log')
    app.GATEWAY_ACCESS_LOG = log_path
    client = make_client(app)

    real_run = app.subprocess.run
    app.subprocess.run = lambda *a, **k: FakeProc(returncode=0, stdout='')
    try:
        check('会话有效（排除 401 冒充结果）', session_alive(client))

        # ── (a) 日志文件不存在 ⇒ 空列表，不是错误 ──
        r = client.get('/api/gateway/visitors?window=60')
        body = r.get_json(silent=True) or {}
        check('日志文件不存在 ⇒ 200（网关没开过是正常情况）',
              r.status_code == 200, f'实际 {r.status_code}')
        check('日志文件不存在 ⇒ 空列表',
              (body.get('data') or {}).get('visitors') == [],
              str(body.get('data'))[:160])

        # ── (b) 有日志 ⇒ 按 IP 聚合 ──
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(GW_LOG_SAMPLE)
        # 日志里的时间是 2026-11-17，现在更晚 ⇒ 默认 60 分钟窗口内全是过期的。
        # 为了测到东西，先看「窗口放到最大」能不能捞回来。
        r = client.get('/api/gateway/visitors?window=10080')
        body = (r.get_json(silent=True) or {}).get('data') or {}
        visitors = body.get('visitors') or []
        check('大窗口下能读到访客', len(visitors) == 2, f'实际 {len(visitors)} 个')
        by_ip = {v['ip']: v for v in visitors}
        check('192.168.100.249 被聚合成一条（2 次请求）',
              by_ip.get('192.168.100.249', {}).get('count') == 2,
              str(by_ip.get('192.168.100.249'))[:160])
        check('聚合项带上了访问过的服务域名',
              '192.168.100.193' in by_ip.get('192.168.100.249', {}).get('hosts', []),
              str(by_ip.get('192.168.100.249', {}).get('hosts'))[:120])
        check('聚合项带上了访问过的路径',
              '/siy/' in by_ip.get('192.168.100.249', {}).get('uris', []),
              str(by_ip.get('192.168.100.249', {}).get('uris'))[:120])
        check('聚合项带上了最近访问时间',
              bool(by_ip.get('192.168.100.249', {}).get('last_seen')),
              str(by_ip.get('192.168.100.249', {}).get('last_seen'))[:60])
        check('聚合项带上了 UA',
              'Mozilla/5.0' in by_ip.get('192.168.100.249', {}).get('ua', ''),
              str(by_ip.get('192.168.100.249', {}).get('ua'))[:80])
        check('聚合项带上了设备 ID（auth_dev）',
              by_ip.get('192.168.100.249', {}).get('auth_dev') == 'dev-abc',
              str(by_ip.get('192.168.100.249', {}).get('auth_dev'))[:60])
        check('10.0.0.9 也在（不同 IP 各一条）',
              by_ip.get('10.0.0.9', {}).get('count') == 2,
              str(by_ip.get('10.0.0.9'))[:160])

        # ── (c) 时间窗过滤：窗口很小 ⇒ 全部过期 ⇒ 空 ──
        r = client.get('/api/gateway/visitors?window=1')
        body = (r.get_json(silent=True) or {}).get('data') or {}
        check('窗口太小 ⇒ 过滤掉过期记录（空列表）',
              (body.get('visitors') or []) == [], str(body.get('visitors'))[:160])

        # ── (d) 坏行跳过，不让整个接口崩 ──
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write('这不是一行合法的访问日志\n')
            f.write('2026-11-17T23:55:00+08:00 缺字段\n')
            f.write('\n')
            # nginx 的 access_log 是**多个 worker 追加写**的，偶发会写出
            # 字符交织的半截行（真机实测过 "192.168.100.gzl"）。
            # 正则照样能把它当 IP 收下 ⇒ 访客列表里会出现一条不存在的访客。
            f.write('2026-11-17T23:56:00+08:00 192.168.100.gzl GET 200 1 rt=0.001 '
                    'host="x" uri="/" ua="curl" ref="-" auth_user="" auth_dev=""\n')
        r = client.get('/api/gateway/visitors?window=10080')
        check('日志里有坏行 ⇒ 仍然 200（跳过坏行，不整体失败）',
              r.status_code == 200, f'实际 {r.status_code}')
        body = (r.get_json(silent=True) or {}).get('data') or {}
        ips = [v['ip'] for v in (body.get('visitors') or [])]
        check('字符交织的坏行不会变成一条假访客（IP 必须是真 IP）',
              '192.168.100.gzl' not in ips, str(ips)[:160])
        check('坏行跳过不影响正常访客',
              '192.168.100.249' in ips, str(ips)[:160])

        # ── (e) 窗口参数非法 ⇒ 回落默认值，不 500 ──
        r = client.get('/api/gateway/visitors?window=abc')
        check('window 非法 ⇒ 仍然 200（回落默认值）',
              r.status_code == 200, f'实际 {r.status_code}')

        # ── (f) 手动加白名单的默认时效随接口一起给出 ──
        r = client.get('/api/gateway/visitors?window=60')
        body = (r.get_json(silent=True) or {}).get('data') or {}
        check('接口带回「手动加白名单的默认时效」（秒）',
              body.get('manual_whitelist_timeout') == 600,
              str(body.get('manual_whitelist_timeout')))

        # ── (g) 永久白名单（nft 里没 timeout 的元素）也算「已在白名单」──
        # ⚠ 不能拿「有没有剩余时效」判存在：_nft_read_set 对永久元素返回
        # None ⇒ 用 `.get(...) is not None` 判会把永久白名单误报成「没加」。
        real_read = app._nft_read_set
        app._nft_read_set = lambda name, timeout=10: (
            {'192.168.100.249': None} if name == 'allowed4' else {})
        try:
            r = client.get('/api/gateway/visitors?window=10080')
            body = (r.get_json(silent=True) or {}).get('data') or {}
            by_ip = {v['ip']: v for v in (body.get('visitors') or [])}
            check('永久白名单的访客也算「已在白名单」',
                  by_ip.get('192.168.100.249', {}).get('whitelisted') is True,
                  str(by_ip.get('192.168.100.249'))[:160])
            check('不在名单的访客仍然算「没加」',
                  by_ip.get('10.0.0.9', {}).get('whitelisted') is False,
                  str(by_ip.get('10.0.0.9'))[:160])
        finally:
            app._nft_read_set = real_read

        # ── (h) 日志很大时只读尾部（access_log 只增不减，内存必须有界）──
        # 设备实测：网关的 access_log 落在 tmpfs 上，而 OpenWrt 没有
        # logrotate ⇒ 这份日志只增不减。整个读进来早晚是内存问题。
        old_tail = app.GATEWAY_LOG_TAIL_BYTES
        app.GATEWAY_LOG_TAIL_BYTES = 200
        try:
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write('2026-11-17T23:51:24+08:00 10.0.0.1 GET 200 1 rt=0.001 '
                        'host="old" uri="/old" ua="curl" ref="-" '
                        'auth_user="" auth_dev=""\n')
                f.write('# ' + 'x' * 400 + '\n')     # 填充，把老记录顶出尾部
                f.write('2026-11-17T23:59:00+08:00 10.0.0.2 GET 200 1 rt=0.001 '
                        'host="new" uri="/new" ua="curl" ref="-" '
                        'auth_user="" auth_dev=""\n')
            vis2 = app._read_gateway_visitors(7 * 24 * 3600)
            ips2 = [v['ip'] for v in vis2]
            check('日志很大时只读尾部（老记录不参与，内存有界）',
                  '10.0.0.2' in ips2 and '10.0.0.1' not in ips2, str(ips2))
        finally:
            app.GATEWAY_LOG_TAIL_BYTES = old_tail
    finally:
        app.subprocess.run = real_run
        shutil.rmtree(d, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════
# 五、配置项与前端接线（静态 + 单元级）
# ══════════════════════════════════════════════════════════════════════

def group5_config_and_frontend():
    sec('5 配置项与前端接线')
    app = load_app('vis5')

    check('DEFAULT_CONFIG 里有 manual_whitelist_timeout（默认 600 秒 = 10 分钟）',
          app.DEFAULT_CONFIG.get('manual_whitelist_timeout') == 600,
          str(app.DEFAULT_CONFIG.get('manual_whitelist_timeout')))

    errs = app.validate_config({'manual_whitelist_timeout': 'abc'})
    check('validate_config 拒绝非整数的 manual_whitelist_timeout',
          any('manual_whitelist_timeout' in e for e in errs), str(errs)[:160])
    errs = app.validate_config({'manual_whitelist_timeout': 600})
    check('validate_config 接受合法的 manual_whitelist_timeout',
          not any('manual_whitelist_timeout' in e for e in errs), str(errs)[:160])

    # 前端：静态接线
    app_js = open(os.path.join(ROOT, 'frontend', 'app.js'), encoding='utf-8').read()
    index_html = open(os.path.join(ROOT, 'frontend', 'index.html'), encoding='utf-8').read()

    check('前端导航里有「访客」这一项',
          "{ id: 'visitors', label: '访客' }" in app_js)
    check('导航点击会加载访客数据',
          "item.id === 'visitors') loadVisitors()" in index_html)
    check('前端有 loadVisitors 方法', 'async loadVisitors()' in app_js)
    check('前端有「一键加白名单」方法', 'async addVisitorToWhitelist(ip)' in app_js)
    check('加白名单时把时效（秒）传给了后端',
          'timeout: seconds' in app_js)
    check('页面填的是分钟 ⇒ 换算成秒（× 60）才发给后端',
          'this.visitors.ttlMinutes * 60' in app_js)
    check('加白名单按 IP 版本选 set（IPv4→allowed4，IPv6→allowed6）',
          "ip.indexOf(':') >= 0 ? 'allowed6' : 'allowed4'" in app_js)
    check('页面有「访客」这一页的容器',
          "currentNav === 'visitors'" in index_html)
    check('观察窗口的 option 用**静态 value**（Alpine 的 x-model 才能匹配上默认值）',
          '<option value="60">最近 1 小时</option>' in index_html
          and ':value="60"' not in index_html)
    check('页面表格有「加白名单」按钮',
          'addVisitorToWhitelist(v.ip)' in index_html)
    check('页面上写明了时效与敲门是两套（用户不能被误导）',
          '与端口敲门的时效' in index_html)


def main():
    print('=== 网关访客页 + 白名单时效分离：行为级判据 ===')
    group1_split_elem()
    group2_whitelist_ttl()
    group3_ruleset_refill()
    group4_visitors()
    group5_config_and_frontend()

    print()
    print(f'  断言合计：{len(PASS) + len(FAIL)}　通过 {len(PASS)}　失败 {len(FAIL)}')
    if FAIL:
        print('\n[FAIL] 失败明细：')
        for f in FAIL:
            print('   - ' + f)
        sys.exit(1)
    print('[PASS] 全部通过')
    return 0


if __name__ == '__main__':
    sys.exit(main())
