#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批 C（面板可用性）的行为级测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_panel_usability_batch_c.py

测四条
------
M5  CNAME / TXT 的「测试」按钮**恒 400** —— 本轮自己引入的回归
L8  `/api/aliyun-ddns/records` 不传 PageSize（只回 20 条），
    且点「获取记录」会把本地配置**清空**（随后的保存把 enabled 全丢掉）
L12 TXT 外层引号 / CNAME 尾点没归一化 ⇒ 同一个值被判成「值变了」
L13 面板侧取公网 IPv4 的源写死，与 cron 侧不一致（运维改了源两边不一样）
L9  面板侧 `_fetch_public_ipv4` 的**真实实现从未被测到**（测试全打桩）

为什么都要行为级判据
--------------------
M5：「前端不传 value」这种断言在「前端改成传了别的值」时**照样通过** ——
    判据必须落在**接口真的返回什么**上。
L8：断言「源码里有 PageSize」抓不住「PageSize 传错了字段名」。
L12：面板侧和 cron 侧**必须归一化成同一个结果** —— 两侧规则不一样 ⇒
    面板判「没变」而 cron 判「变了」（或反过来）⇒ 自动更新要么不触发、
    要么每轮都触发。所以判据是**两侧跑同一批输入、结果必须相同**。
L13/L9：源可注入之后，**真的**起一个本地假源、让真实实现去取 ——
    而不是把函数换成 lambda（那正是 L9 说的「真实实现从未被测到」）。

⚠ 本文件只读仓库里的源码、只在临时目录与本地回环端口上写东西：
  不碰 `/opt/nftables-web-v2`，不碰 `/etc/nftables`，不动 crontab。
"""
import ast
import importlib
import ipaddress
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
APP_PY = os.path.join(BACKEND, 'app.py')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name
          + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


# ============================================================
# 工具
# ============================================================

def extract_cron_script():
    """用 AST 取出生成物模板的原文（与 tests/test_aliyun_ddns_update.py 同法）。

    不用正则切：模板里满是引号、缩进、三引号，正则切出来的边界经常差一个
    字符，而且**切错时不会报错**，只是内容变了。
    """
    tree = ast.parse(open(APP_PY, encoding='utf-8').read())
    for node in tree.body:
        if (isinstance(node, ast.FunctionDef)
                and node.name == '_generate_ddns_update_script'):
            for stmt in node.body:
                if (isinstance(stmt, ast.Assign)
                        and getattr(stmt.targets[0], "id", "") == "script_content"):
                    return ast.literal_eval(stmt.value)
    return None


def extract_cron_func(name, extra_ns=None):
    """从 cron 模板里取出某个函数的源码，**单独**编译执行。

    ⚠ 不能直接 exec 整个模板 —— 它会读配置、装 cron、退出。
    ⇒ 只取那一个函数定义。
    """
    src = extract_cron_script()
    if not src:
        return None
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            mod = ast.Module(body=[node], type_ignores=[])
            ns = dict(extra_ns or {})
            exec(compile(ast.unparse(mod), '<cron-%s>' % name, 'exec'), ns)
            return ns[name]
    return None


def load_app(env=None):
    """加载面板模块：所有会落盘的路径都指向临时目录。

    env: 额外设置的环境变量（必须在 import **之前**设好 ——
          模块级的 IPV4_SOURCES 是 import 时读的）。
    """
    old = {}
    for k, v in (env or {}).items():
        old[k] = os.environ.get(k)
        os.environ[k] = v
    try:
        sys.path.insert(0, os.path.abspath(BACKEND))
        sys.modules.pop('app', None)
        mod = importlib.import_module('app')
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    d = tempfile.mkdtemp(prefix='batchc-panel-')
    cfg = os.path.join(d, 'cfg.json')
    with open(cfg, 'w', encoding='utf-8') as f:
        json.dump({
            'lan_subnet4': '127.0.0.0/8',
            'panel_allowed_nets': ['127.0.0.0/8'],
            'auth_session_timeout': 1800,
            'auth_token_epoch': 1,
        }, f)
    mod.CONFIG_PATH = cfg
    mod.LISTS_PATH = os.path.join(d, 'lists.json')
    mod.RULES_PATH = os.path.join(d, 'rules.nft')
    mod.ALIYUN_DDNS_CONFIG_PATH = os.path.join(d, 'aliyun-ddns-config.json')
    return mod


def login(client, appmod):
    """预设一个已登录且世代号匹配的会话（面板接口要登录态）"""
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['username'] = 'admin'
        sess['auth_epoch'] = appmod._current_token_epoch()
        sess['last_active'] = time.time()


def write_ddns_config(appmod, config):
    with open(appmod.ALIYUN_DDNS_CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False)


# ============================================================
# 本地假 IP 源（L9/L13）
# ============================================================

class _IpHandler(BaseHTTPRequestHandler):
    """按路径返回不同内容：/fail 500、/v6 返回 IPv6、/ok 返回 IPv4。"""

    def do_GET(self):
        if self.path.startswith('/fail'):
            self.send_response(500)
            self.end_headers()
            return
        if self.path.startswith('/v6'):
            body = b'2001:db8::1\n'
        else:
            body = b'203.0.113.7\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_ip_server():
    srv = ThreadingHTTPServer(('127.0.0.1', 0), _IpHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, 'http://127.0.0.1:%d' % srv.server_address[1]


# ============================================================
# M5：CNAME / TXT 的测试按钮恒 400
# ============================================================

sec('M5：CNAME / TXT 的「测试」不再恒 400')

app = load_app()
CFG = {
    'access_key_id': 'AK-batchc',
    'access_key_secret': 'SK-batchc-secret',
    'region_id': 'cn-hangzhou',
    'domain': 'example.com',
    'records': [
        {'rr': 'www', 'type': 'CNAME', 'value': 'target.example.com',
         'record_id': '1001', 'enabled': True, 'ipv6_source': ''},
    ],
}
write_ddns_config(app, CFG)

calls = []
# ⚠ 第一条是**干扰记录**：同类型、不同 RR。
#   兜底查询必须按 RR/Type 精确匹配，否则会取到它 ⇒ 值取错 ⇒ 白写一次。
FAKE_RECORDS = [{
    'RecordId': '9999', 'RR': 'other', 'Type': 'CNAME',
    'Value': 'wrong.example.com', 'Line': 'default', 'TTL': 600,
}, {
    'RecordId': '1001', 'RR': 'www', 'Type': 'CNAME',
    'Value': 'target.example.com', 'Line': 'default', 'TTL': 600,
}]


def fake_api(action, ak, secret, region, extra=None):
    calls.append((action, extra or {}))
    if action == 'DescribeDomainRecords':
        return {'TotalCount': len(FAKE_RECORDS),
                'DomainRecords': {'Record': list(FAKE_RECORDS)}}
    return {'RecordId': '1001'}


saved_api = app._aliyun_api
saved_cron = app._manage_ddns_cron
try:
    app._aliyun_api = fake_api
    app._manage_ddns_cron = lambda cfg: (True, 'ok')
    client = app.app.test_client()
    login(client, app)

    # 前端传空 value（旧前端/缓存住的旧 app.js 就是这样）
    resp = client.post('/api/aliyun-ddns/test',
                       json={'rr': 'www', 'type': 'CNAME', 'value': '',
                             'record_id': '1001'})
    body = resp.get_json(silent=True) or {}
    check('CNAME 传空 value 时不再 400', resp.status_code != 400,
          '实际 %d / %s' % (resp.status_code, body))
    check('CNAME 传空 value 时能走到阿里云查询',
          any(a == 'DescribeDomainRecords' for a, _ in calls),
          str([a for a, _ in calls]))
    check('CNAME 传空 value 时回 success=true',
          body.get('success') is True, str(body))
    check('CNAME 值没变 ⇒ 不发写接口',
          not any(a in ('AddDomainRecord', 'UpdateDomainRecord',
                        'DeleteDomainRecord') for a, _ in calls),
          str([a for a, _ in calls]))

    # 不给 record_id 时，兜底查询必须自己按 RR/Type 精确匹配 ——
    # 上面 FAKE_RECORDS 里第一条是**干扰记录**（同类型、不同 RR）。
    # 匹配不准就会取到它的值 ⇒ 值与阿里云上的不一样 ⇒ 白写一次。
    calls.clear()
    resp_noid = client.post('/api/aliyun-ddns/test',
                             json={'rr': 'www', 'type': 'CNAME', 'value': ''})
    body_noid = resp_noid.get_json(silent=True) or {}
    check('不给 record_id 时也能定位到**正确**的那条记录（没取到干扰记录）',
          resp_noid.status_code != 400
          and not any(a in ('AddDomainRecord', 'UpdateDomainRecord',
                            'DeleteDomainRecord') for a, _ in calls),
          '实际 %d / %s / %s' % (resp_noid.status_code, body_noid,
                                [a for a, _ in calls]))

    # TXT 同理
    calls.clear()
    FAKE_RECORDS[:] = [{
        'RecordId': '1002', 'RR': 'txt', 'Type': 'TXT',
        'Value': '"v=spf1 include:_spf.example.com ~all"',
        'Line': 'default', 'TTL': 600,
    }]
    resp_t = client.post('/api/aliyun-ddns/test',
                          json={'rr': 'txt', 'type': 'TXT', 'value': '',
                                'record_id': '1002'})
    body_t = resp_t.get_json(silent=True) or {}
    check('TXT 传空 value 时不再 400', resp_t.status_code != 400,
          '实际 %d / %s' % (resp_t.status_code, body_t))
    check('TXT 值没变 ⇒ 不发写接口',
          not any(a in ('AddDomainRecord', 'UpdateDomainRecord',
                        'DeleteDomainRecord') for a, _ in calls),
          str([a for a, _ in calls]))
finally:
    app._aliyun_api = saved_api
    app._manage_ddns_cron = saved_cron


# ============================================================
# L8：/records 的 PageSize 与 localRecords
# ============================================================

sec('L8：/records 带 PageSize，且把本地配置原样带回去')

app2 = load_app()
CFG2 = {
    'access_key_id': 'AK-batchc',
    'access_key_secret': 'SK-batchc-secret',
    'region_id': 'cn-hangzhou',
    'domain': 'example.com',
    'records': [
        {'rr': 'www', 'type': 'A', 'value': '1.1.1.1',
         'record_id': '2001', 'enabled': True, 'ipv6_source': ''},
        {'rr': 'www6', 'type': 'AAAA', 'value': '::1',
         'record_id': '2002', 'enabled': False, 'ipv6_source': 'router'},
        # 阿里云上已经没有的那条（本地还留着）
        {'rr': 'old', 'type': 'A', 'value': '9.9.9.9',
         'record_id': '2003', 'enabled': True, 'ipv6_source': ''},
    ],
}
write_ddns_config(app2, CFG2)

rec_calls = []


def fake_api2(action, ak, secret, region, extra=None):
    rec_calls.append((action, extra or {}))
    if action == 'DescribeDomainRecords':
        return {'TotalCount': 1,
                'DomainRecords': {'Record': [{
                    'RecordId': '2001', 'RR': 'www', 'Type': 'A',
                    'Value': '1.1.1.1', 'Line': 'default', 'TTL': 600,
                }]}}
    return {}


saved_api2 = app2._aliyun_api
try:
    app2._aliyun_api = fake_api2
    client2 = app2.app.test_client()
    login(client2, app2)
    resp2 = client2.get('/api/aliyun-ddns/records')
    body2 = resp2.get_json(silent=True) or {}
    check('/records 接口返回 200', resp2.status_code == 200, str(resp2.status_code))
    check('查询记录时带了 PageSize（否则阿里云只回前 20 条）',
          rec_calls and rec_calls[0][1].get('PageSize'),
          str(rec_calls[:1]))
    check('PageSize 是 500',
          rec_calls and rec_calls[0][1].get('PageSize') == 500,
          str(rec_calls[:1]))
    check('响应里带回了 localRecords',
          isinstance(body2.get('localRecords'), list), str(body2)[:200])
    local2 = body2.get('localRecords') or []
    check('localRecords 包含**阿里云上已经没有**的那条本地记录',
          any(l.get('rr') == 'old' for l in local2), str(local2))
    check('localRecords 保留了 enabled',
          [l.get('enabled') for l in local2 if l.get('rr') == 'www'] == [True],
          str(local2))
    check('localRecords 保留了 ipv6_source',
          [l.get('ipv6_source') for l in local2 if l.get('rr') == 'www6'] == ['router'],
          str(local2))
    check('localRecords 的 rr/type/value 都是小写键（前端按小写匹配）',
          all(('rr' in l and 'type' in l and 'value' in l) for l in local2),
          str(local2))
finally:
    app2._aliyun_api = saved_api2


# ============================================================
# L12：TXT / CNAME 归一化（面板侧与 cron 侧必须一致）
# ============================================================

sec('L12：TXT 外层引号 / CNAME 尾点被归一化，且两侧结果一致')

app3 = load_app()
cron_norm = extract_cron_func('_norm_value', {'ipaddress': ipaddress})
check('能从 cron 模板里取出 _norm_value', cron_norm is not None)

CASES = [
    (' 1.2.3.4 ', '1.2.3.4'),
    ('2001:DB8::1', '2001:db8::1'),
    ('"v=spf1 include:_spf.example.com ~all"', 'v=spf1 include:_spf.example.com ~all'),
    ('target.example.com.', 'target.example.com'),
    ('""', ''),
    ('"', '"'),
    ('', ''),
    ('plain', 'plain'),
]
for raw, want in CASES:
    got = app3._ddns_norm_value(raw)
    check('面板侧归一化 %r → %r' % (raw, want), got == want, '实际 %r' % got)

if cron_norm:
    mismatch = [(raw, app3._ddns_norm_value(raw), cron_norm(raw))
                for raw, _ in CASES
                if app3._ddns_norm_value(raw) != cron_norm(raw)]
    check('面板侧与 cron 侧对同一批输入结果**完全一致**',
          not mismatch, str(mismatch))


# ============================================================
# L13 / L9：面板侧取公网 IPv4 的源可注入，真实实现能被测到
# ============================================================

sec('L13 / L9：探测源可注入，真实实现真的去取')

srv, base = start_ip_server()
try:
    sources = '%s/fail,%s/v6,%s/ok' % (base, base, base)
    app4 = load_app({'NFTW_IPV4_SOURCES': sources})
    check('面板侧的探测源来自 NFTW_IPV4_SOURCES 环境变量',
          app4.IPV4_SOURCES == ['%s/fail' % base, '%s/v6' % base, '%s/ok' % base],
          str(app4.IPV4_SOURCES))

    # ⭐ 真实实现（不是 lambda 打桩）真的去取
    val = app4._fetch_public_ipv4()
    check('真实实现能取到公网 IPv4（第一个源失败、第二个返回 IPv6、第三个可用）',
          val == '203.0.113.7', '实际 %r' % val)

    # 默认源（不注入）时，面板侧与 cron 侧必须一致
    app5 = load_app()
    cron_sources = None
    src = extract_cron_script()
    if src:
        tree = ast.parse(src)
        for node in tree.body:
            if (isinstance(node, ast.Assign)
                    and getattr(node.targets[0], 'id', '') == 'IPV4_SOURCES'):
                mod = ast.Module(body=[node], type_ignores=[])
                ns = {'os': os}
                exec(compile(ast.unparse(mod), '<src>', 'exec'), ns)
                cron_sources = ns['IPV4_SOURCES']
    check('cron 模板里的 IPV4_SOURCES 能取出来', cron_sources is not None)
    check('面板侧与 cron 侧的**默认**探测源一致（运维改一边另一边不改就分叉了）',
          app5.IPV4_SOURCES == cron_sources,
          '面板=%s cron=%s' % (app5.IPV4_SOURCES, cron_sources))
finally:
    srv.shutdown()


print('\n' + '=' * 60)
print('  通过 %d / 失败 %d' % (len(PASS), len(FAIL)))
if FAIL:
    print('  失败项: %s' % FAIL)
print('=' * 60)
sys.exit(1 if FAIL else 0)
