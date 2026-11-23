#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第五批修复的行为级判据（证书死锁 + network 解析容错）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/test_batch5_fixes.py

两条独立的线，都是用户实机报的现象：

A. 证书：上传的删不掉、泛域名申请不下来（互相死锁）
   ────────────────────────────────────────────────────
   · 申请端点按 **base_domain** 判重（`c["domain"] == domain`），
     而泛域名证书的 base_domain 跟普通证书一样 ⇒
     手动上传过 fzyto.top 之后，*.fzyto.top 永远申请不下来；
   · 默认证书又不许删 ⇒ 用户只有一张证书时「先切换再删」做不到
     ⇒ 两边都卡住；
   · 普通证书和泛域名证书还共用同一个存放目录
     ⇒ 装一张就把另一张的 fullchain/privkey 冲掉。

B. /etc/config/network：加个空格就读不出来
   ────────────────────────────────────────────────────
   同一个文件以前有 4 套各写各的解析，容错程度还不一样：
     段名/关键字之间多个空格、双引号、不带引号、段内行顶格、CRLF……
   任意一种都能让「LAN 段读不出来」，
   而读不出来的代价是**整机失联**（LAN 没设备 ⇒ 管理口没了）。

判据要领
--------
- 每条断言都写成「老代码必然失败」的形式。
- 网络侧用**合成**配置（不含任何真实凭据），覆盖各种写法变体。
- 证书侧走**真实端点**（Flask test client），不是只测纯函数 ——
  死锁发生在端点里（判重 + 删除保护），只测 helper 测不到。

本文件只读仓库里的源码、只在临时目录里写东西：
不碰 /etc/nftables、/var/log、/opt/nftables-web-v2。
"""
import importlib
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name
          + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


# ── 沙箱：环境变量必须在 import app 之前设好 ─────────────────────────
TD = tempfile.mkdtemp(prefix='batch5-')
for _n in ('password', 'secret'):
    with open(os.path.join(TD, _n), 'w', encoding='utf-8') as _f:
        _f.write('x')
with open(os.path.join(TD, 'config.json'), 'w', encoding='utf-8') as _f:
    _f.write('{}')
os.environ.update({
    "AUTH_CONFIG_PATH": os.path.join(TD, 'config.json'),
    "AUTH_PASSWORD_FILE": os.path.join(TD, 'password'),
    "AUTH_SECRET_FILE": os.path.join(TD, 'secret'),
    "AUTH_RATELIMIT_FILE": os.path.join(TD, 'ratelimit.json'),
    "AUTH_AUDIT_LOG": os.path.join(TD, 'audit.log'),
    "AUTH_API_PORT": "18445",
})

sys.modules.pop('app', None)
import app as panel  # noqa: E402

panel.CONFIG_PATH = os.path.join(TD, 'panel-config.json')
panel.LISTS_PATH = os.path.join(TD, 'lists.json')
panel.RULES_PATH = os.path.join(TD, 'rules.nft')
panel.NGINX_SSL_DIR = os.path.join(TD, 'ssl')
os.makedirs(panel.NGINX_SSL_DIR, exist_ok=True)


# ══════════════════════════════════════════════════════════════════
sec('B. /etc/config/network 的解析容错')
# ══════════════════════════════════════════════════════════════════

# 合成配置（结构照抄 OpenWrt 的 /etc/config/network，不含任何真实凭据）
BASE_NET = """config interface 'loopback'
\toption device 'lo'
\toption proto 'static'
\tlist ipaddr '127.0.0.1/8'

config globals 'globals'
\toption ula_prefix 'fd7e:3e9:7996::/48'

config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports 'eth0'
\tlist ports 'eth2'

config interface 'lan'
\toption device 'br-lan'
\toption proto 'static'
\toption ipaddr '192.168.100.1'
\toption netmask '255.255.255.0'

config interface 'wan'
\toption device 'eth1'
\toption proto 'dhcp'
"""


def write_net(text, name='network'):
    p = os.path.join(TD, name)
    with open(p, 'w', encoding='utf-8') as f:
        f.write(text)
    return p


def parsed(text):
    return panel.parse_uci_config(write_net(text, 'network-' + str(abs(hash(text)) % 9999)))


# ── B-1 段头写法变体都要能读出 LAN 设备 ─────────────────────────────
VARIANTS = [
    ("单引号（原样）", BASE_NET),
    ("config 与 interface 之间两个空格", BASE_NET.replace("config interface 'lan'",
                                                  "config  interface 'lan'")),
    ("段名双引号", BASE_NET.replace("config interface 'lan'", 'config interface "lan"')),
    ("段名不带引号", BASE_NET.replace("config interface 'lan'", 'config interface lan')),
    ("段头末尾多个空格", BASE_NET.replace("config interface 'lan'\n",
                                    "config interface 'lan'   \n")),
]
for tag, text in VARIANTS:
    r = parsed(text)
    check(f'B-1 段头写法「{tag}」仍能读出 LAN 设备',
          r.get('lan_device') == 'br-lan', f"读到 {r.get('lan_device')!r}")

# ── B-2 WAN 段同样容错 ──────────────────────────────────────────────
for tag, text in VARIANTS:
    r = parsed(text)
    check(f'B-2 段头写法「{tag}」仍能读出 WAN 设备',
          r.get('wan_device') == 'eth1', f"读到 {r.get('wan_device')!r}")

# ── B-3 option 的键与值之间多个空格 ─────────────────────────────────
r = parsed(BASE_NET.replace("\toption device 'br-lan'", "\toption  device 'br-lan'"))
check('B-3 option 与键之间两个空格仍能读出 LAN 设备',
      r.get('lan_device') == 'br-lan', f"读到 {r.get('lan_device')!r}")

# ── B-4 值里带尾随空格不能带出来 ───────────────────────────────────
check("B-4 剥引号后再去空白（值里的空格不外泄）",
      panel.extract_uci_value("option device 'br-lan '") == 'br-lan',
      repr(panel.extract_uci_value("option device 'br-lan '")))
check("B-4 常规写法仍正确",
      panel.extract_uci_value("option device 'br-lan'") == 'br-lan')

# ── B-5 段内行顶格时，段体不能被截断 ───────────────────────────────
TOP = BASE_NET.replace("\toption netmask '255.255.255.0'",
                        "option netmask '255.255.255.0'")
_find = getattr(panel, '_uci_find_section', None)
if _find is None:
    check('B-5 段内有一行顶格时，LAN 段体不被截断', False, '缺 _uci_find_section')
else:
    body, _s, _e = _find(TOP, 'interface', 'lan')
    check('B-5 段内有一行顶格时，LAN 段体不被截断',
          body is not None and 'netmask' in body and '192.168.100.1' in body,
          repr(body)[:120] if body else 'None')

# ── B-6 段内 option 检测容错 ───────────────────────────────────────
_has = getattr(panel, '_uci_has_option', None)
if _find is None or _has is None:
    check('B-6 段内 option 与键之间两个空格也算「有这个字段」', False, '缺新解析 helper')
else:
    body2, _s2, _e2 = _find(
        BASE_NET.replace("\toption ipaddr", "\toption  ipaddr"), 'interface', 'lan')
    check('B-6 段内 option 与键之间两个空格也算「有这个字段」',
          _has(body2, 'ipaddr'))

# ── B-7 写前校验：段头变体不该误拒 ─────────────────────────────────
for tag, text in VARIANTS:
    ok, err = panel._validate_network_config_content(text, text)
    check(f'B-7 写前校验对段头写法「{tag}」不误拒', ok, err)

# ── B-8 但真丢了 LAN 段仍然要拒（保护没被削弱）─────────────────────
NO_LAN = BASE_NET.replace("config interface 'lan'\n"
                           "\toption device 'br-lan'\n"
                           "\toption proto 'static'\n"
                           "\toption ipaddr '192.168.100.1'\n"
                           "\toption netmask '255.255.255.0'\n", '')
ok, err = panel._validate_network_config_content(BASE_NET, NO_LAN)
check('B-8 新配置真丢了 LAN 段仍然拒绝写入', not ok and 'LAN' in err, err[:80])

# ── B-9 丢了 LAN 的 ipaddr 仍然要拒 ────────────────────────────────
NO_IP = BASE_NET.replace("\toption ipaddr '192.168.100.1'\n", '')
ok, err = panel._validate_network_config_content(BASE_NET, NO_IP)
check('B-9 丢了 LAN 的 ipaddr 仍然拒绝写入', not ok and 'ipaddr' in err, err[:80])

# ── B-10 _ensure_lan_essentials 不得追加重复 option ────────────────
# 段内 option 写成多空格 ⇒ 老代码判定「字段不存在」⇒ 追加一份默认值
# （用户的真实 ipaddr 被默认值覆盖 ⇒ 失联）
netp = write_net(BASE_NET.replace("\toption ipaddr '192.168.100.1'",
                                   "\toption  ipaddr '192.168.100.1'"), 'ess')
panel._ensure_lan_essentials(netp)
after = open(netp, encoding='utf-8').read()
n_ipaddr = after.count('option ipaddr') + after.count('option  ipaddr')
check('B-10 option 多空格时不会被追加重复的 ipaddr', n_ipaddr == 1,
      f'文件里有 {n_ipaddr} 条 ipaddr')
check('B-10 用户的真实 ipaddr 没被默认值覆盖',
      "192.168.100.1" in after and "option ipaddr '192.168.100.1'" in after.replace(
          'option  ipaddr', 'option ipaddr'))

# ── B-11 缺字段时该补还得补（功能没被改坏）────────────────────────
netp2 = write_net(BASE_NET.replace("\toption netmask '255.255.255.0'\n", ''), 'ess2')
panel._ensure_lan_essentials(netp2)
after2 = open(netp2, encoding='utf-8').read()
check('B-11 缺 netmask 时仍然会被补上', "option netmask '255.255.255.0'" in after2)

# ── B-12 顶格写的行也不会被当成「字段缺失」────────────────────────
netp3 = write_net(BASE_NET.replace("\toption netmask '255.255.255.0'",
                                   "option netmask '255.255.255.0'"), 'ess3')
panel._ensure_lan_essentials(netp3)
after3 = open(netp3, encoding='utf-8').read()
check('B-12 顶格写的行不被当成缺失字段（不追加重复 netmask）',
      after3.count('netmask') == 1, f'文件里有 {after3.count("netmask")} 处 netmask')


# ══════════════════════════════════════════════════════════════════
sec('A. 证书申请 / 删除的死锁')
# ══════════════════════════════════════════════════════════════════

# ── A-1 泛域名证书与普通证书必须分目录 ─────────────────────────────
_dirname = getattr(panel, '_cert_dir_name', None)
if _dirname is None:
    check('A-1 泛域名证书与普通证书目录不同', False, '缺 _cert_dir_name')
    check('A-1 目录名不含 *（shell 通配/运维的坑）', False, '缺 _cert_dir_name')
    check('A-1 普通证书目录名不变（存量兼容）', False, '缺 _cert_dir_name')
    d_plain = d_wild = 'fzyto.top'
else:
    d_plain = _dirname('fzyto.top', False)
    d_wild = _dirname('fzyto.top', True)
check('A-1 泛域名证书与普通证书目录不同', d_plain != d_wild, f'{d_plain} vs {d_wild}')
check('A-1 目录名不含 *（shell 通配/运维的坑）', '*' not in d_wild, d_wild)
check('A-1 普通证书目录名不变（存量兼容）', d_plain == 'fzyto.top', d_plain)


# ── 端点级测试 ──────────────────────────────────────────────────────
def write_panel_config(certs, default_cert_id=''):
    cfg = {
        'lan_subnet4': '127.0.0.0/8',
        'panel_allowed_nets': ['127.0.0.0/8'],
        'auth_session_timeout': 1800,
        'auth_token_epoch': 1,
        'reverse_proxy': {
            'rules': [],
            'certificates': certs,
            'settings': {'default_cert_id': default_cert_id},
        },
    }
    with open(panel.CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False)
    return cfg


def login(client):
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['username'] = 'admin'
        sess['auth_epoch'] = panel._current_token_epoch()
        sess['last_active'] = time.time()


# 打桩：不真跑 acme.sh、不真跑 nginx
# 真实现先存一份 —— A-7 要验「签发时把证书装到哪个目录」，
# 桩函数是绕开这段逻辑的，直接调桩等于什么都没验。
_real_acme_issue = panel._acme_issue
_stub_acme_issue = lambda domain, provider='ali', creds=None, wildcard=False: (
    True, {
        'cert_path': os.path.join(panel.NGINX_SSL_DIR, _dirname(domain, wildcard),
                                  'fullchain.pem'),
        'key_path': os.path.join(panel.NGINX_SSL_DIR, _dirname(domain, wildcard),
                                 'privkey.pem'),
        'expires_at': '2027-02-21T15:30:20Z',
        'days_remaining': 90,
    })
panel._acme_issue = _stub_acme_issue
panel._deploy_all_rules = lambda config=None: (True, '')
panel._sync_local_domain_resolution = lambda config, lan_ip=None: {'ok': True}

REQ = {
    'domain': 'fzyto.top',
    'wildcard': True,
    'dns_provider': 'ali',
    'dns_credentials': {'Ali_Key': 'AK', 'Ali_Secret': 'SK'},
}


def request_cert(client, body=None):
    return client.post('/api/reverse-proxy/certificates/request',
                       json=body if body is not None else REQ)


# ── A-2 没有任何证书时能申请 ────────────────────────────────────────
write_panel_config([], '')
client = panel.app.test_client()
login(client)
resp = request_cert(client)
data = resp.get_json() or {}
check('A-2 没有证书时申请成功', resp.status_code == 200,
      f'状态 {resp.status_code} {str(data)[:120]}')
cfg = json.load(open(panel.CONFIG_PATH, encoding='utf-8'))
certs = cfg.get('reverse_proxy', {}).get('certificates', [])
check('A-2 证书列表里有 1 条', len(certs) == 1, str(len(certs)))
check('A-2 新证书标记为泛域名', certs and certs[0].get('wildcard') is True)

# ── A-3 已有同 domain 的**普通**证书时，泛域名申请不再被挡 ──────────
write_panel_config([{
    'id': 'cert_001', 'domain': 'fzyto.top', 'wildcard': False, 'source': 'manual',
    'cert_path': os.path.join(panel.NGINX_SSL_DIR, 'fzyto.top', 'fullchain.pem'),
    'key_path': os.path.join(panel.NGINX_SSL_DIR, 'fzyto.top', 'privkey.pem'),
    'expires_at': '2027-01-16T23:59:59Z',
}], 'cert_001')
client = panel.app.test_client()
login(client)
resp = request_cert(client)
data = resp.get_json() or {}
check('A-3 已有同名普通证书时，泛域名申请不再 400', resp.status_code == 200,
      f'状态 {resp.status_code} {str(data)[:160]}')
cfg = json.load(open(panel.CONFIG_PATH, encoding='utf-8'))
certs = cfg.get('reverse_proxy', {}).get('certificates', [])
check('A-3 证书列表变成 2 条（两张都留着）', len(certs) == 2, str(len(certs)))
check('A-3 原来的手动证书还在（没被偷偷删掉）',
      any(c.get('id') == 'cert_001' and c.get('source') == 'manual' for c in certs))
new = [c for c in certs if c.get('wildcard') is True]
check('A-3 新增的是泛域名证书', len(new) == 1)
check('A-3 两张证书的存放目录不同（不会互相覆盖文件）',
      new and new[0].get('cert_path') != certs[0].get('cert_path'),
      f"{certs[0].get('cert_path')} vs {new[0].get('cert_path') if new else ''}")

# ── A-4 已有同 domain 同 wildcard 时：原地替换（覆盖默认）──────────
write_panel_config([{
    'id': 'cert_001', 'domain': 'fzyto.top', 'wildcard': True, 'source': 'auto',
    'cert_path': '/旧路径/fullchain.pem',
    'key_path': '/旧路径/privkey.pem',
    'expires_at': '2026-12-01T00:00:00Z',
}], 'cert_001')
client = panel.app.test_client()
login(client)
resp = request_cert(client)
data = resp.get_json() or {}
check('A-4 已有同名同类型证书时申请不再 400', resp.status_code == 200,
      f'状态 {resp.status_code} {str(data)[:160]}')
cfg = json.load(open(panel.CONFIG_PATH, encoding='utf-8'))
certs = cfg.get('reverse_proxy', {}).get('certificates', [])
check('A-4 是原地替换（列表还是 1 条）', len(certs) == 1, str(len(certs)))
check('A-4 id 没变（默认证书指向的 id 仍然有效）',
      certs and certs[0].get('id') == 'cert_001')
check('A-4 证书路径换成了新签发的那张',
      certs and certs[0].get('cert_path') != '/旧路径/fullchain.pem')
check('A-4 返回体标明是覆盖',
      (data.get('data') or {}).get('replaced') is True, str(data.get('data'))[:120])

# ── A-5 删除默认证书不再死锁 ────────────────────────────────────────
write_panel_config([{
    'id': 'cert_001', 'domain': 'fzyto.top', 'wildcard': False, 'source': 'manual',
    'cert_path': os.path.join(panel.NGINX_SSL_DIR, 'fzyto.top', 'fullchain.pem'),
    'key_path': os.path.join(panel.NGINX_SSL_DIR, 'fzyto.top', 'privkey.pem'),
    'expires_at': '2027-01-16T23:59:59Z',
}], 'cert_001')
client = panel.app.test_client()
login(client)
resp = client.delete('/api/reverse-proxy/certificates/cert_001')
data = resp.get_json() or {}
check('A-5 删除默认证书不再 400', resp.status_code == 200,
      f'状态 {resp.status_code} {str(data)[:160]}')
cfg = json.load(open(panel.CONFIG_PATH, encoding='utf-8'))
certs = cfg.get('reverse_proxy', {}).get('certificates', [])
check('A-5 证书真的删掉了', len(certs) == 0, str(len(certs)))
check('A-5 默认证书被取消（不留指向已删证书的 id）',
      cfg.get('reverse_proxy', {}).get('settings', {}).get('default_cert_id') == '',
      str(cfg.get('reverse_proxy', {}).get('settings', {}).get('default_cert_id')))
check('A-5 消息里说清了后果（网关回退自签）',
      '默认证书' in str((data.get('data') or {}).get('message', '')),
      str((data.get('data') or {}).get('message', ''))[:120])

# ── A-6 删除非默认证书仍然正常 ──────────────────────────────────────
write_panel_config([
    {'id': 'cert_001', 'domain': 'fzyto.top', 'wildcard': False, 'source': 'manual',
     'cert_path': '/a/fullchain.pem', 'key_path': '/a/privkey.pem',
     'expires_at': '2027-01-16T23:59:59Z'},
    {'id': 'cert_002', 'domain': 'other.top', 'wildcard': True, 'source': 'auto',
     'cert_path': '/b/fullchain.pem', 'key_path': '/b/privkey.pem',
     'expires_at': '2027-02-21T15:30:20Z'},
], 'cert_001')
client = panel.app.test_client()
login(client)
resp = client.delete('/api/reverse-proxy/certificates/cert_002')
check('A-6 删除非默认证书正常', resp.status_code == 200,
      f'状态 {resp.status_code} {str(resp.get_json())[:120]}')
cfg = json.load(open(panel.CONFIG_PATH, encoding='utf-8'))
certs = cfg.get('reverse_proxy', {}).get('certificates', [])
check('A-6 只剩 1 条', len(certs) == 1, str(len(certs)))
check('A-6 默认证书没被误动',
      cfg.get('reverse_proxy', {}).get('settings', {}).get('default_cert_id') == 'cert_001')


# ── A-7 签发 / 续期装证书的目录必须跟证书类型一致 ──────────────────
# 泛域名若装进普通证书的目录，就会把普通证书的 fullchain/privkey 冲掉 ——
# 面板上两张证书都「有效」，浏览器拿到的却是另一张。
import unittest.mock as _mock

_acme_cmds = []


def _fake_run(cmd, **kw):
    _acme_cmds.append(list(cmd))

    class _R:
        returncode = 0
        stdout = ''
        stderr = ''
    return _R()


def acme_install_dir(which, wildcard):
    """跑一次 _acme_issue / _acme_renew，返回 --install-cert 装到哪个目录。"""
    _acme_cmds.clear()
    old_path = panel._acme_sh_path
    old_plugins = panel._acme_plugin_paths
    old_issue = panel._acme_issue
    panel._acme_sh_path = lambda: '/usr/bin/true'
    # 插件检查只认「路径存在」，指到本文件即可过（不真去装 acme.sh）
    panel._acme_plugin_paths = lambda name: [__file__]
    # 签发路径必须走真实现（桩函数绕开了装证书那段逻辑）
    panel._acme_issue = _real_acme_issue
    try:
        with _mock.patch.object(panel.subprocess, 'run', side_effect=_fake_run):
            if which == 'issue':
                panel._acme_issue('fzyto.top', 'ali',
                                  {'Ali_Key': 'A', 'Ali_Secret': 'B'},
                                  wildcard=wildcard)
            else:
                panel._acme_renew('fzyto.top', 'ali',
                                  {'Ali_Key': 'A', 'Ali_Secret': 'B'},
                                  wildcard=wildcard)
    finally:
        panel._acme_sh_path = old_path
        panel._acme_plugin_paths = old_plugins
        panel._acme_issue = old_issue
    for c in _acme_cmds:
        if '--install-cert' in c and '--fullchain-file' in c:
            return os.path.basename(os.path.dirname(c[c.index('--fullchain-file') + 1]))
    return ''


if not hasattr(panel, '_acme_issue') or not hasattr(panel, '_acme_renew'):
    check('A-7 泛域名签发装进 .wildcard 目录', False, '缺 _acme_issue/_acme_renew')
    check('A-7 泛域名续期装进 .wildcard 目录', False, '缺 _acme_issue/_acme_renew')
    check('A-7 普通证书签发仍装进原目录（存量兼容）', False, '缺 _acme_issue')
else:
    d_issue_wild = acme_install_dir('issue', True)
    d_renew_wild = acme_install_dir('renew', True)
    d_issue_plain = acme_install_dir('issue', False)
    check('A-7 泛域名签发装进 .wildcard 目录（不冲掉普通证书）',
          d_issue_wild == 'fzyto.top.wildcard', repr(d_issue_wild))
    check('A-7 泛域名续期装进 .wildcard 目录（不冲掉普通证书）',
          d_renew_wild == 'fzyto.top.wildcard', repr(d_renew_wild))
    check('A-7 普通证书签发仍装进原目录（存量兼容）',
          d_issue_plain == 'fzyto.top', repr(d_issue_plain))
    check('A-7 泛域名证书目录与面板记录一致',
          d_issue_wild == _dirname('fzyto.top', True),
          f'{d_issue_wild} vs {_dirname("fzyto.top", True)}')


# ── A-8 上传端点：泛域名与普通证书分目录、互不挤掉 ──────────────────
import subprocess as _sp

_up_crt = os.path.join(TD, 'up-cert.pem')
_up_key = os.path.join(TD, 'up-key.pem')
_gen = _sp.run([
    'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', _up_key, '-out', _up_crt, '-days', '1',
    '-subj', '/CN=fzyto.top',
    '-addext', 'subjectAltName=DNS:*.fzyto.top,DNS:fzyto.top',
], capture_output=True, text=True)
if _gen.returncode != 0:
    check('A-8 上传泛域名证书成功', False, f'openssl 生成失败: {_gen.stderr[:120]}')
    check('A-8 泛域名证书落在 .wildcard 目录', False, '跳过')
    check('A-8 上传泛域名证书不挤掉普通证书', False, '跳过')
else:
    write_panel_config([{
        'id': 'cert_001', 'domain': 'fzyto.top', 'wildcard': False, 'source': 'manual',
        'cert_path': os.path.join(panel.NGINX_SSL_DIR, 'fzyto.top', 'fullchain.pem'),
        'key_path': os.path.join(panel.NGINX_SSL_DIR, 'fzyto.top', 'privkey.pem'),
        'expires_at': '2027-01-16T23:59:59Z',
    }], 'cert_001')
    client = panel.app.test_client()
    login(client)
    with open(_up_crt, 'rb') as _fc, open(_up_key, 'rb') as _fk:
        resp = client.post('/api/reverse-proxy/certificates/upload',
                           data={'domain': '*.fzyto.top',
                                 'cert_file': (_fc, 'cert.pem'),
                                 'key_file': (_fk, 'key.pem')},
                           content_type='multipart/form-data')
    data = resp.get_json() or {}
    check('A-8 上传泛域名证书成功', resp.status_code == 200,
          f'状态 {resp.status_code} {str(data)[:160]}')
    cfg = json.load(open(panel.CONFIG_PATH, encoding='utf-8'))
    certs = cfg.get('reverse_proxy', {}).get('certificates', [])
    wild = [c for c in certs if c.get('wildcard') is True]
    check('A-8 泛域名证书落在 .wildcard 目录',
          wild and os.path.basename(os.path.dirname(wild[0].get('cert_path', '')))
          == 'fzyto.top.wildcard',
          wild[0].get('cert_path') if wild else str(len(certs)))
    check('A-8 泛域名证书文件真的落在那个目录里',
          os.path.exists(os.path.join(panel.NGINX_SSL_DIR, 'fzyto.top.wildcard',
                                      'fullchain.pem')))
    check('A-8 上传泛域名证书不挤掉普通证书（两张都在）', len(certs) == 2,
          f'列表里有 {len(certs)} 条')
    check('A-8 原来的普通证书条目还在',
          any(c.get('id') == 'cert_001' and c.get('wildcard') is False
              for c in certs))


# ── B-13 写 wan 段时不能把后面的段头吞掉 ───────────────────────────
# 老代码用 startswith('config ') 判「下一行是不是新段头」，而
# `config<TAB>interface 'lan'` 是 UCI 合法写法 ⇒ 认不出来 ⇒ 那行被当成
# 普通行吞掉 ⇒ 写出的文件里 LAN 段整段消失 ⇒ 整机失联。
_det = getattr(panel, '_detect_wan_device', None)
if _det is None:
    check('B-13 tab 分隔的段头不会被写 wan 段时吞掉', False, '缺 _detect_wan_device')
    check('B-13 tab 分隔的段头不会被写 wan6 段时吞掉', False, '缺 _detect_wan_device')
else:
    _old_det = panel._detect_wan_device
    # 本机只有一张物理网卡，测不出「独立 WAN 口」；打桩给一个（不碰真判定）
    panel._detect_wan_device = (
        lambda text, sysfs_root=None: ('eth1', ['eth0', 'eth1'], ['eth0']))
    # wan / wan6 段后面都跟一个用 TAB 分隔段头的 LAN 段
    NET_TAB = (
        "config interface 'wan'\n"
        "\toption device 'eth1'\n"
        "\toption proto 'dhcp'\n"
        "\n"
        "config interface 'wan6'\n"
        "\toption device 'eth1'\n"
        "\toption proto 'dhcp'\n"
        "\n"
        "config\tinterface 'lan'\n"
        "\toption device 'br-lan'\n"
        "\toption proto 'static'\n"
        "\toption ipaddr '192.168.100.1'\n"
        "\toption netmask '255.255.255.0'\n"
    )
    try:
        # 场景一：切 PPPoE（wan6 被删，wan 段重写）
        netp4 = write_net(NET_TAB, 'wanwrite-pppoe')
        try:
            panel.update_uci_wan_config(netp4, {
                'wan_pppoe': True, 'wan_pppoe_username': 'u',
                'wan_pppoe_password': 'p',
            })
        except ValueError as e:
            # 老代码把后面的段头吞掉 ⇒ 拼出的内容丢了 LAN 段 ⇒ 落盘前
            # 被校验拦下。文件没被写坏（原子写保护住了），但用户**保存
            # 不进去** —— 真机日志里那条「已拒绝写入」就是这么来的。
            after4 = ''
            check('B-13 tab 分隔的段头不会被写 wan 段时吞掉', False,
                  '保存被校验拦下（拼出的内容丢了 LAN 段）：%s' % str(e)[:120])
        else:
            after4 = open(netp4, encoding='utf-8').read()
            check('B-13 tab 分隔的段头不会被写 wan 段时吞掉',
                  'br-lan' in after4 and 'lan' in after4,
                  after4.replace('\n', ' | ')[:180])
        check('B-13 写完 wan 段后 LAN 段字段完整',
              '192.168.100.1' in after4 and 'netmask' in after4,
              after4.replace('\n', ' | ')[:180])

        # 场景二：不切 PPPoE（wan6 保留）
        netp5 = write_net(NET_TAB, 'wanwrite-dhcp')
        try:
            panel.update_uci_wan_config(netp5, {
                'wan_pppoe': False, 'wan_pppoe_username': 'u',
                'wan_pppoe_password': 'p',
            })
        except ValueError as e:
            after5 = ''
            check('B-13 tab 分隔的段头不会被写 wan6 段时吞掉', False,
                  '保存被校验拦下（拼出的内容丢了 LAN 段）：%s' % str(e)[:120])
        else:
            after5 = open(netp5, encoding='utf-8').read()
            check('B-13 tab 分隔的段头不会被写 wan6 段时吞掉',
                  'br-lan' in after5 and 'lan' in after5,
                  after5.replace('\n', ' | ')[:180])
        check('B-13 写完 wan6 段后 LAN 段字段完整',
              '192.168.100.1' in after5 and 'netmask' in after5,
              after5.replace('\n', ' | ')[:180])
    finally:
        panel._detect_wan_device = _old_det


# ══════════════════════════════════════════════════════════════════
print('\n' + '=' * 60)
print(f'通过 {len(PASS)} 条，失败 {len(FAIL)} 条')
if FAIL:
    for _f in FAIL:
        print('  [FAIL] ' + _f)
    sys.exit(1)
print('[OK] 全部通过')
sys.exit(0)
