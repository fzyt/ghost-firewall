#!/usr/bin/env python3
"""第七批：反代「路径改写」改为保存时自动探测 —— 行为级测试。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/test_batch7_autodetect.py

背景（2026-11-24，用户拍板）：
  「上游 API 路径前缀」输入框与「根绝对路径改写」勾选框两个框撤掉，
  改成**新建规则时由后端自动探测上游后决定**。

为什么值得单独测（而不是只改界面）：
  这两个字段填错的后果是「页面能开、数据接口全 404」——
  症状极具迷惑性，用户会以为是自己部署坏了。
  自动化以后，判定口径就成了产品的一部分：
    · 多个 API 前缀候选时选哪个（按命中条数，不是按名字）；
    · 什么情况下才开根绝对路径改写（有根绝对路径、且没有协议相对 URL）；
    · 探测失败时**不动**已有值（失败 ≠ 结论是「不需要」）；
    · 只在**新建**时装配（编辑不覆盖 —— 内置 /fw 规则的硬编码值会被改坏）；
    · 只对 LAN 网段内的目标探测（P2-9 的同一条 SSRF 边界）。

沙箱：所有落盘路径指到临时目录；部署与规则下发全部打桩，绝不碰设备。
"""
import importlib.util as ilu
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

# ⚠️ 沙箱必须在 **import 之前**设好：app.py 的路径常量是在 import 时
# 从环境变量读出来的（项目里所有测试都这么干），事后改 module 属性
# 只能盖住一部分 —— 比如 _write_password_hash 用的 AUTH_PASSWORD_FILE
# 在写盘前就会先去建 /etc/nftables 目录（非 root 直接 PermissionError）。
SBX = tempfile.mkdtemp(prefix='nftv2_batch7_')
os.environ.update({
    'AUTH_CONFIG_PATH': os.path.join(SBX, 'config.json'),
    'AUTH_PASSWORD_FILE': os.path.join(SBX, 'password.json'),
    'AUTH_SECRET_FILE': os.path.join(SBX, 'secret'),
    'AUTH_SESSION_SECRET_FILE': os.path.join(SBX, 'session-secret'),
    'AUTH_PANEL_RATELIMIT_FILE': os.path.join(SBX, 'ratelimit.json'),
    'AUTH_RATELIMIT_FILE': os.path.join(SBX, 'gw-ratelimit.json'),
    'AUTH_AUDIT_LOG': os.path.join(SBX, 'audit.log'),
    'NFTABLES_WEB_LISTS_PATH': os.path.join(SBX, 'lists.json'),
    'NFTABLES_WEB_RULES_PATH': os.path.join(SBX, 'rules.nft'),
    'NFTABLES_WEB_SSL_DIR': os.path.join(SBX, 'ssl'),
    'NFTABLES_WEB_NGINX_CONF_DIR': os.path.join(SBX, 'nginx-conf'),
    'NFTABLES_WEB_ALIYUN_CONFIG': os.path.join(SBX, 'aliyun.json'),
    'NFTABLES_WEB_DDNS_SCRIPT': os.path.join(SBX, 'ddns.sh'),
})

spec = ilu.spec_from_file_location('nftapp', os.path.join(BACKEND, 'app.py'))
app = ilu.module_from_spec(spec)
sys.modules['nftapp'] = app
spec.loader.exec_module(app)

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(t):
    print(f'\n=== {t} ===')


# ── 本地假上游 ────────────────────────────────────────────────────────
# 一个 HTTP server 同时提供：
#   /openapi.json  —— 声明的路由表（/api/ 多、/admin/ 少）
#   /              —— 首页 HTML（按用例切形态）
OPENAPI = {
    'paths': {
        '/api/notes': {},
        '/api/notes/{id}': {},
        '/api/tree': {},
        '/admin/panel': {},          # 只有一条 ⇒ 按名字排会排到 /api/ 前面
    }
}
HOME_MODE = {'mode': 'root'}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/openapi.json'):
            body = json.dumps(OPENAPI).encode()
            ctype = 'application/json'
        elif self.path == '/':
            if HOME_MODE['mode'] == 'root':
                body = (b'<link href="/static/app.css">\n'
                        b'<script src="/static/app.js"></script>\n')
            elif HOME_MODE['mode'] == 'proto':
                body = (b'<link href="/static/app.css">\n'
                        b'<link href="//cdn.example.com/x.css">\n')
            else:                                    # 'none'
                body = b'<link href="relative/app.css">\n'
            ctype = 'text/html'
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


SRV = HTTPServer(('127.0.0.1', 0), Handler)
PORT = SRV.server_address[1]
TH = threading.Thread(target=SRV.serve_forever, daemon=True)
TH.start()


def _allow_lan(_host):
    """放行 LAN 判定 —— 这一条单独测（见第 4 组），这里只测判定之后的逻辑。"""
    return True


def main():
    # ── 0. 前置：自动装配的入口必须存在 ──────────────────────────────
    # 老代码（HEAD）没有这个函数。装一个「什么都不做」的替身，
    # 让下面的断言**正常判红**，而不是 AttributeError 把整个脚本掀翻 ——
    # 掀翻 ⇒ 一条失败行都没有 ⇒ 老代码对照拿不到红/绿计数。
    sec('0. 自动装配入口存在')
    if callable(getattr(app, '_rp_autofill_path_rewrite', None)):
        check('_rp_autofill_path_rewrite 存在', True)
    else:
        check('_rp_autofill_path_rewrite 存在', False, '老代码没有这个函数')
        app._rp_autofill_path_rewrite = lambda clean: ''

    # ── 1. API 前缀候选的排序 ────────────────────────────────────────
    sec('1. API 前缀候选按命中条数排序（不是按名字）')

    prefixes, err = app._detect_upstream_api_prefixes('127.0.0.1', PORT, 'http')
    check('探测到候选前缀', err is None and len(prefixes) == 2,
          f'prefixes={prefixes} err={err}')
    check('命中条数多的排前面（/api/ 三条 > /admin/ 一条）',
          prefixes and prefixes[0] == '/api/', str(prefixes))
    check('按名字排会选错 —— 字母序里 /admin/ 在 /api/ 前面',
          prefixes and prefixes[1] == '/admin/', str(prefixes))

    # ── 2. 自动装配的各分支 ──────────────────────────────────────────
    sec('2. _rp_autofill_path_rewrite 的判定')

    orig_allowed = app._detect_target_allowed
    app._detect_target_allowed = _allow_lan
    try:
        # 2.1 有根绝对路径、无协议相对 ⇒ 开启改写 + 填上 API 前缀
        HOME_MODE['mode'] = 'root'
        clean = {'target_address': f'127.0.0.1:{PORT}', 'target_protocol': 'http',
                 'api_path_prefix': '', 'rewrite_root_paths': False}
        note = app._rp_autofill_path_rewrite(clean)
        check('自动填上 API 路径前缀', clean['api_path_prefix'] == '/api/',
              str(clean['api_path_prefix']))
        check('有根绝对路径 ⇒ 开启根绝对路径改写',
              clean['rewrite_root_paths'] is True, str(clean['rewrite_root_paths']))
        check('返回一句给用户看的说明', isinstance(note, str) and note != '', note)

        # 2.2 有协议相对 URL ⇒ 不开（宽模式必然把它们一起改坏）
        HOME_MODE['mode'] = 'proto'
        clean = {'target_address': f'127.0.0.1:{PORT}', 'target_protocol': 'http',
                 'api_path_prefix': '', 'rewrite_root_paths': False}
        app._rp_autofill_path_rewrite(clean)
        check('有协议相对 URL ⇒ 不开根绝对路径改写',
              clean['rewrite_root_paths'] is False, str(clean['rewrite_root_paths']))
        check('API 前缀照旧填上（协议相对只影响宽模式）',
              clean['api_path_prefix'] == '/api/', str(clean['api_path_prefix']))

        # 2.3 没有根绝对路径 ⇒ 不开
        HOME_MODE['mode'] = 'none'
        clean = {'target_address': f'127.0.0.1:{PORT}', 'target_protocol': 'http',
                 'api_path_prefix': '', 'rewrite_root_paths': False}
        app._rp_autofill_path_rewrite(clean)
        check('没有根绝对路径 ⇒ 不开根绝对路径改写',
              clean['rewrite_root_paths'] is False, str(clean['rewrite_root_paths']))

        # 2.4 探测失败 ⇒ **不动**已有值（失败 ≠ 结论是「不需要」）
        clean = {'target_address': '127.0.0.1:1', 'target_protocol': 'http',
                 'api_path_prefix': '/api/', 'rewrite_root_paths': True}
        note = app._rp_autofill_path_rewrite(clean)
        check('探测失败时不动已有的 API 前缀',
              clean['api_path_prefix'] == '/api/', str(clean['api_path_prefix']))
        check('探测失败时不动已有的改写开关',
              clean['rewrite_root_paths'] is True, str(clean['rewrite_root_paths']))
        check('探测失败要说清楚为什么没改', isinstance(note, str) and note != '', note)

        # 2.5 目标不在 LAN 网段 ⇒ 完全不探测
        app._detect_target_allowed = lambda _h: False
        clean = {'target_address': f'127.0.0.1:{PORT}', 'target_protocol': 'http',
                 'api_path_prefix': '', 'rewrite_root_paths': False}
        note = app._rp_autofill_path_rewrite(clean)
        check('LAN 网段外的目标不探测',
              clean['api_path_prefix'] == '' and clean['rewrite_root_paths'] is False,
              f'prefix={clean["api_path_prefix"]!r} rrp={clean["rewrite_root_paths"]}')
        check('跳过时要说明原因', '局域网' in (note or ''), note)
        app._detect_target_allowed = _allow_lan
    finally:
        app._detect_target_allowed = orig_allowed

    # ── 3. 端到端：POST 自动装配、PUT 不装配 ─────────────────────────
    sec('3. 端到端：新建时装配、编辑时不覆盖')

    rp = {'rules': []}
    cfg = {'reverse_proxy': rp, 'settings': {}}
    saved = {}

    def fake_get_rp_config():
        return cfg, rp

    def fake_save_rp_config(c):
        saved['cfg'] = json.loads(json.dumps(c))

    def fake_deploy_all_rules(_c):
        return True, 'ok'

    def fake_apply_ruleset(_c):
        return True, 'ok'

    orig = (app._get_rp_config, app._save_rp_config,
            app._deploy_all_rules, app._apply_ruleset)
    app._get_rp_config = fake_get_rp_config
    app._save_rp_config = fake_save_rp_config
    app._deploy_all_rules = fake_deploy_all_rules
    app._apply_ruleset = fake_apply_ruleset
    try:
        HOME_MODE['mode'] = 'root'
        # 面板的访问边界是 **fail-closed** 的：配置文件不存在 ⇒ 拒绝一切来源。
        # 所以必须先把配置建出来并放行本测试用的来源网段。
        cfg0 = app.load_config()
        cfg0['lan_subnet4'] = '192.168.100.0/24'
        app.save_config(cfg0)
        client = app.app.test_client()
        client.environ_base['REMOTE_ADDR'] = '192.168.100.50'
        app._write_password_hash(app._hash_password('batch7-pw'))
        client.post('/api/auth/login', json={'password': 'batch7-pw'})

        # 目标要落在 LAN 网段里 ⇒ 这里把判定放开
        app._detect_target_allowed = _allow_lan
        r = client.post('/api/reverse-proxy/rules', json={
            'name': 'nas', 'path_prefix': '/nas', 'enabled': True,
            'target_address': f'127.0.0.1:{PORT}', 'target_protocol': 'http',
            'public_access': False,
        })
        body = r.get_json() or {}
        data = body.get('data') or {}
        check('POST 新建成功', r.status_code == 200 and body.get('success'),
              f'HTTP {r.status_code} {body.get("message")}')
        check('落盘的规则已带上自动探测的 API 前缀',
              (saved.get('cfg') or {}).get('reverse_proxy', {}).get('rules', [{}])[0]
              .get('api_path_prefix') == '/api/',
              json.dumps(saved.get('cfg', {}), ensure_ascii=False)[:200])
        check('落盘的规则已带上自动开启的根绝对路径改写',
              (saved.get('cfg') or {}).get('reverse_proxy', {}).get('rules', [{}])[0]
              .get('rewrite_root_paths') is True)
        check('响应里回传了探测结论（前端要靠它回显）',
              isinstance(data.get('autofill_note'), str) and data.get('autofill_note'),
              str(data.get('autofill_note')))
        check('响应里回传了实际生效的两个字段',
              data.get('api_path_prefix') == '/api/'
              and data.get('rewrite_root_paths') is True,
              f'prefix={data.get("api_path_prefix")!r} rrp={data.get("rewrite_root_paths")!r}')

        # 编辑：改成「不该改写」的组合，PUT 不该覆盖已有值
        rule_id = (saved.get('cfg') or {}).get('reverse_proxy', {}).get('rules', [{}])[0].get('id')
        rp['rules'] = (saved.get('cfg') or {}).get('reverse_proxy', {}).get('rules', [])
        if rp['rules']:
            rp['rules'][0]['api_path_prefix'] = '/api/'
            rp['rules'][0]['rewrite_root_paths'] = True
        HOME_MODE['mode'] = 'none'          # 首页没有根绝对路径 ⇒ 若被覆盖会被关掉
        r = client.put(f'/api/reverse-proxy/rules/{rule_id}', json={
            'name': 'nas2', 'path_prefix': '/nas', 'enabled': True,
            'target_address': f'127.0.0.1:{PORT}', 'target_protocol': 'http',
            'public_access': False,
        })
        body = r.get_json() or {}
        check('PUT 更新成功', r.status_code == 200 and body.get('success'),
              f'HTTP {r.status_code} {body.get("message")}')
        saved_rule = (saved.get('cfg') or {}).get('reverse_proxy', {}).get('rules', [{}])[0]
        check('PUT **不**覆盖已生效的 API 前缀',
              saved_rule.get('api_path_prefix') == '/api/', str(saved_rule.get('api_path_prefix')))
        check('PUT **不**覆盖已生效的根绝对路径改写',
              saved_rule.get('rewrite_root_paths') is True,
              str(saved_rule.get('rewrite_root_paths')))
    finally:
        (app._get_rp_config, app._save_rp_config,
         app._deploy_all_rules, app._apply_ruleset) = orig
        app._detect_target_allowed = orig_allowed

    # ── 4. LAN 边界（P2-9 的同一条） ────────────────────────────────
    sec('4. 探测的 LAN 边界')

    check('LAN 网段内的目标被允许',
          app._detect_target_allowed('192.168.100.50') is True)
    check('公网地址被拒绝',
          app._detect_target_allowed('8.8.8.8') is False)
    check('回环地址被拒绝',
          app._detect_target_allowed('127.0.0.1') is False)
    check('主机名被拒绝（防 DNS rebinding）',
          app._detect_target_allowed('evil.example.com') is False)

    src = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
    if 'def _rp_autofill_path_rewrite' in src:
        body = src[src.index('def _rp_autofill_path_rewrite'):]
        body = body[:body.index('\ndef ')]
        check('自动装配内部确实查了 LAN 边界',
              '_detect_target_allowed' in body)
    else:
        check('自动装配内部确实查了 LAN 边界', False,
              '老代码没有 _rp_autofill_path_rewrite')

    SRV.shutdown()
    print()
    print('=' * 60)
    print(f'  通过 {len(PASS)} / 失败 {len(FAIL)}')
    if FAIL:
        for f in FAIL:
            print(f'  [FAIL] {f}')
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
