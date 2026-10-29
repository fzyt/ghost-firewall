"""泛域名证书能力的回归测试。

运行:  python3 tests/test_wildcard_cert.py

覆盖 2026-10-28 补齐的四件事，每条都写成「老代码必然失败」的形式：

  WC-1  证书域名解析器支持 *. 前缀（_sanitize_cert_domain）
  WC-2  反代目标主机校验器**没有**被顺手放宽（_sanitize_domain 仍拒 *）
  WC-3  证书 SAN 解析（表头是 "Subject Alternative Name"，不是 "subjectAltName"）
  WC-4  acme.sh 路径多候选探测（OpenWrt 的 opkg 版在 /usr/lib/acme/client/）
  WC-5  泛域名签发命令要带两个 -d（裸域 + 通配）
  WC-6  缺 DNS 插件时给出人话报错（OpenWrt 裁剪版 acme.sh 不带插件）
  WC-7  定时自动续期的筛选与执行
  WC-8  --renew-certs CLI 入口 + crontab 写入
  WC-9  setup.sh 会补装 acme.sh 的 DNS 插件
  WC-10 前端把泛域名开关与自动续期参数传给后端

沙箱运行：不碰真实路径、不执行 openssl/nft/nginx（需要外部命令的分支打桩）。
"""
import importlib
import json
import os
import re
import subprocess as _sp
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def fresh():
    """独立加载一份 app 模块，避免模块级状态互相污染"""
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    app.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'cfg.json')
    app.LISTS_PATH = os.path.join(tempfile.mkdtemp(), 'lists.json')
    app.RULES_PATH = os.path.join(tempfile.mkdtemp(), 'rules.nft')
    return app


APP_SRC = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
SETUP_SRC = open(os.path.join(ROOT, 'setup', 'setup.sh'), encoding='utf-8').read()
APPJS_SRC = open(os.path.join(ROOT, 'frontend', 'app.js'), encoding='utf-8').read()
INDEX_SRC = open(os.path.join(ROOT, 'frontend', 'index.html'), encoding='utf-8').read()

# ─────────────────────────────────────────────────────────────
sec('WC-1  证书域名解析器支持 *. 前缀')

app = fresh()
scd = app._sanitize_cert_domain
check('普通域名 → (base, False)', scd('fzyto.top') == ('fzyto.top', False))
check('通配域名 → (base, True)', scd('*.fzyto.top') == ('fzyto.top', True))
check('通配 + 大写 → 归一化小写',
      scd('*.FZYTO.TOP') == ('fzyto.top', True))
check('前后空格被裁掉', scd('  fzyto.top  ') == ('fzyto.top', False))
for bad in ('', '   ', '*.', '*.fzyto.top.', 'fzyto', 'a..b', '*.a b', 'fzyto.top/../x'):
    try:
        scd(bad)
        check(f'非法输入 {bad!r} 被拒', False, '竟然通过了')
    except ValueError:
        check(f'非法输入 {bad!r} 被拒', True)

# ─────────────────────────────────────────────────────────────
sec('WC-2  反代目标主机校验器没有被放宽')

# _sanitize_domain 是 _sanitize_target_address 用的（反代 proxy_pass 的
# 目标主机）。放行 * 等于允许把 *.evil.com 写进 proxy_pass —— nginx
# 解析时是当字面主机名的，这是放开一个注入面。
for bad in ('*.fzyto.top', '*', 'a*b.com'):
    try:
        app._sanitize_domain(bad)
        check(f'_sanitize_domain 仍拒 {bad!r}', False, '被放行了 —— 注入面开了')
    except ValueError:
        check(f'_sanitize_domain 仍拒 {bad!r}', True)
check('_sanitize_domain 仍接受正常域名',
      app._sanitize_domain('example.com') == 'example.com')

src_sanitize = re.search(r"def _sanitize_domain\(.*?\n(?=\ndef |\n# )", APP_SRC, re.S)
check('_sanitize_domain 的正则里不含裸 *',
      bool(src_sanitize) and r'\*' not in src_sanitize.group(0).split('re.match')[1][:200]
      if src_sanitize else False)

# ─────────────────────────────────────────────────────────────
sec('WC-3  证书 SAN 解析')

tmp = tempfile.mkdtemp()
crt = os.path.join(tmp, 'c.pem')
key = os.path.join(tmp, 'k.pem')
gen = _sp.run([
    'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', key, '-out', crt, '-days', '1',
    '-subj', '/CN=fzyto.top',
    '-addext', 'subjectAltName=DNS:*.fzyto.top,DNS:fzyto.top',
], capture_output=True, text=True)
if gen.returncode != 0:
    check('能生成测试用自签证书', False, gen.stderr[:120])
else:
    check('能生成测试用自签证书', True)
    sans = app._get_cert_san(crt)
    check('SAN 解析出两个域名',
          sans == ['*.fzyto.top', 'fzyto.top'], f'实际 {sans}')
    check('泛域名项带 * 前缀', any(s.startswith('*.') for s in sans))

    # 老代码的坑：表头是 "Subject Alternative Name"，
    # 按命令行参数里的 "subjectAltName" 去匹配永远匹配不到。
    out = _sp.run(['openssl', 'x509', '-in', crt, '-noout', '-ext', 'subjectAltName'],
                  capture_output=True, text=True).stdout
    check('openssl 表头是 Subject Alternative Name（含空格）',
          'Subject Alternative Name' in out and 'subjectAltName:' not in out)
    check('正则不是按 subjectAltName: 匹配的',
          not re.search(r'search\(r?["\']subjectAltName:', APP_SRC))

check('文件不存在时返回空列表而不是抛异常',
      app._get_cert_san('/nonexistent/xx.pem') == [])

# ─────────────────────────────────────────────────────────────
sec('WC-4  acme.sh 路径多候选探测')

check('候选里含 OpenWrt opkg 版路径',
      '/usr/lib/acme/client/acme.sh' in app.ACME_SH_CANDIDATES)
check('候选里含 curl 官方安装路径',
      '~/.acme.sh/acme.sh' in app.ACME_SH_CANDIDATES)
check('不再是写死的单路径常量',
      'ACME_SH_PATH = os.path.expanduser' not in APP_SRC)
check('有 _acme_sh_path() 函数', hasattr(app, '_acme_sh_path'))

# 打桩 os.path.isfile / access，验证候选顺序
_real_isfile, _real_access = app.os.path.isfile, app.os.access
try:
    app.os.path.isfile = lambda p: p in (
        os.path.expanduser('~/.acme.sh/acme.sh'),
        '/usr/lib/acme/client/acme.sh')
    app.os.access = lambda p, mode: True
    got = app._acme_sh_path()
    check('优先命中 ~/.acme.sh/acme.sh',
          got == os.path.expanduser('~/.acme.sh/acme.sh'), f'实际 {got}')
    app.os.path.isfile = lambda p: p == '/usr/lib/acme/client/acme.sh'
    got = app._acme_sh_path()
    check('没有 ~/.acme.sh 时回落到 OpenWrt opkg 路径',
          got == '/usr/lib/acme/client/acme.sh', f'实际 {got}')
finally:
    app.os.path.isfile, app.os.access = _real_isfile, _real_access

# ─────────────────────────────────────────────────────────────
sec('WC-5  泛域名签发命令要带两个 -d')


def _capture_issue(wildcard):
    """打桩 subprocess.run，捕获 _acme_issue 发给 acme.sh 的参数。

    沙箱要点：不碰 /etc/nginx，也不改全局 os 模块 —— 用临时目录当
    证书根目录，插件文件真建一个出来，让插件检查自然通过。
    """
    a = fresh()
    calls = []

    class R:
        returncode = 0
        stdout = ''
        stderr = ''

    def fake_run(args, **kw):
        calls.append(list(args))
        return R()

    sandbox = tempfile.mkdtemp()
    fake_acme = os.path.join(sandbox, 'acme.sh')
    open(fake_acme, 'w').write('#!/bin/sh\n')
    os.chmod(fake_acme, 0o755)
    os.makedirs(os.path.join(sandbox, 'dnsapi'), exist_ok=True)
    open(os.path.join(sandbox, 'dnsapi', 'dns_ali.sh'), 'w').write('#!/bin/sh\n')

    a.subprocess.run = fake_run
    a._acme_sh_path = lambda: fake_acme
    a.NGINX_SSL_DIR = os.path.join(sandbox, 'ssl')
    a._get_cert_expiry = lambda p: ('2027-01-01T00:00:00Z', 90)
    a._harden_key_for_nginx_worker = lambda p: None
    creds = {'Ali_Key': 'k', 'Ali_Secret': 's'}
    ok, res = a._acme_issue('fzyto.top', 'ali', creds, wildcard=wildcard)
    return ok, calls, res


ok, calls, res = _capture_issue(True)
check('泛域名签发成功', ok, str(res)[:120])
issue_args = calls[0] if calls else []
check('命令里有裸域 -d fzyto.top',
      '-d' in issue_args and 'fzyto.top' in issue_args, str(issue_args))
check('命令里有第二个 -d *.fzyto.top',
      issue_args.count('-d') == 2 and '*.fzyto.top' in issue_args,
      str(issue_args))
check('两个 -d 相邻（先裸域后通配）',
      issue_args[issue_args.index('-d') + 1] == 'fzyto.top'
      and issue_args[issue_args.index('-d') + 3] == '*.fzyto.top',
      str(issue_args))
check('仍走 --dns dns_ali', 'dns_ali' in issue_args, str(issue_args))

ok, calls, res = _capture_issue(False)
issue_args = calls[0] if calls else []
check('非泛域名只有一个 -d', issue_args.count('-d') == 1, str(issue_args))
check('非泛域名不含 * 域名', not any('*' in x for x in issue_args), str(issue_args))

# ─────────────────────────────────────────────────────────────
sec('WC-6  缺 DNS 插件时给出人话报错')

a = fresh()
# 沙箱里放一个 acme.sh，但**不放** dnsapi/ 目录 → 插件检查必须拦下来
sandbox = tempfile.mkdtemp()
fake_acme = os.path.join(sandbox, 'acme.sh')
open(fake_acme, 'w').write('#!/bin/sh\n')
os.chmod(fake_acme, 0o755)
a._acme_sh_path = lambda: fake_acme
a.NGINX_SSL_DIR = os.path.join(sandbox, 'ssl')
ok, res = a._acme_issue('fzyto.top', 'ali', {'Ali_Key': 'k', 'Ali_Secret': 's'})
check('缺插件时签发失败', not ok)
check('报错提到「插件」', '插件' in res.get('error', ''), res.get('error', '')[:120])
check('报错提到裁剪版 acme.sh', 'acme-acmesh' in res.get('error', ''),
      res.get('error', '')[:160])

# ─────────────────────────────────────────────────────────────
sec('WC-7  定时自动续期的筛选与执行')

a = fresh()
saved = {'n': 0}


def _mk_certs():
    return [
        # 手动上传 → 不该被自动续期
        {'id': 'cert_m', 'domain': 'manual.com', 'source': 'manual',
         'auto_renew': True, 'renew_days': 60,
         'cert_path': '/x/manual.pem'},
        # 自动但关掉了自动续期 → 不该续
        {'id': 'cert_off', 'domain': 'off.com', 'source': 'auto',
         'auto_renew': False, 'renew_days': 60,
         'cert_path': '/x/off.pem'},
        # 还有 90 天才到期 → 不该续
        {'id': 'cert_far', 'domain': 'far.com', 'source': 'auto',
         'auto_renew': True, 'renew_days': 60,
         'cert_path': '/x/far.pem'},
        # 只剩 10 天 → 该续
        {'id': 'cert_due', 'domain': 'due.com', 'source': 'auto',
         'auto_renew': True, 'renew_days': 60,
         'cert_path': '/x/due.pem'},
        # 该续但缺凭证 → 记 error（用没有凭证的 provider 表达）
        {'id': 'cert_nocred', 'domain': 'nocred.com', 'source': 'auto',
         'auto_renew': True, 'renew_days': 60, 'dns_provider': 'nopass',
         'cert_path': '/x/nocred.pem'},
    ]


DAYS = {'/x/manual.pem': 90, '/x/off.pem': 90, '/x/far.pem': 90,
        '/x/due.pem': 10, '/x/nocred.pem': 10}
renewed_calls = []


def fake_exp(path):
    return ('2027-01-01T00:00:00Z', DAYS.get(path, -1))


def fake_renew(domain, provider='ali', creds=None):
    renewed_calls.append(domain)
    return True, {'new_expires_at': '2027-04-01T00:00:00Z', 'days_remaining': 90}


def fake_creds(rp, provider):
    if provider == 'nopass':
        return None
    return {'Ali_Key': 'k', 'Ali_Secret': 's'}


a._get_rp_config = lambda: ({}, {'certificates': _mk_certs()})
a._get_cert_expiry = fake_exp
a._acme_renew = fake_renew
a._get_dns_credentials = fake_creds
a._save_rp_config = lambda cfg: saved.__setitem__('n', saved['n'] + 1)

renewed, errors = a._renew_due_certs()
check('只续了真正该续的那张', renewed == ['due.com'], f'实际 {renewed}')
check('手动上传的没被续', 'manual.com' not in renewed)
check('关掉自动续期的没被续', 'off.com' not in renewed)
check('没到期的没被续', 'far.com' not in renewed)
check('缺凭证的记进 errors', any('nocred' in e for e in errors), str(errors))
check('缺凭证的没被当成续成功', 'nocred.com' not in renewed)
check('续期后落了盘', saved['n'] == 1, f'保存次数 {saved["n"]}')

# 边界：剩余天数 == renew_days 时应该续
a2 = fresh()
saved2 = {'n': 0}
c2 = [{'id': 'c', 'domain': 'edge.com', 'source': 'auto', 'auto_renew': True,
       'renew_days': 30, 'cert_path': '/x/edge.pem'}]
a2._get_rp_config = lambda: ({}, {'certificates': c2})
a2._get_cert_expiry = lambda p: ('2027-01-01T00:00:00Z', 30)
calls2 = []
a2._acme_renew = lambda d, p='ali', c=None: (
    calls2.append(d), (True, {'new_expires_at': 'x', 'days_remaining': 90}))[1]
a2._get_dns_credentials = lambda rp, p: {'Ali_Key': 'k', 'Ali_Secret': 's'}
a2._save_rp_config = lambda cfg: saved2.__setitem__('n', saved2['n'] + 1)
r2, e2 = a2._renew_due_certs()
check('剩余天数 == renew_days 时触发续期', r2 == ['edge.com'], f'实际 {r2}')

# renew_days 缺失/非法时回落到 60
a3 = fresh()
c3 = [{'id': 'c', 'domain': 'nodef.com', 'source': 'auto', 'auto_renew': True,
       'cert_path': '/x/nodef.pem'}]
a3._get_rp_config = lambda: ({}, {'certificates': c3})
a3._get_cert_expiry = lambda p: ('2027-01-01T00:00:00Z', 61)
calls3 = []
a3._acme_renew = lambda d, p='ali', c=None: (
    calls3.append(d), (True, {'new_expires_at': 'x', 'days_remaining': 90}))[1]
a3._get_dns_credentials = lambda rp, p: {'Ali_Key': 'k', 'Ali_Secret': 's'}
a3._save_rp_config = lambda cfg: None
r3, _ = a3._renew_due_certs()
check('renew_days 缺失时回落到 60 天（61 天不续）', r3 == [], f'实际 {r3}')

# ─────────────────────────────────────────────────────────────
sec('WC-8  --renew-certs CLI 入口 + crontab')

check('有 --renew-certs CLI 分支', '"--renew-certs" in sys.argv' in APP_SRC)
check('有 _renew_certs_cli 函数', hasattr(app, '_renew_certs_cli'))
check('有 _ensure_cert_renew_cron 函数', hasattr(app, '_ensure_cert_renew_cron'))
check('crontab 条目每 30 分钟一次',
      app.CERT_RENEW_CRON_ENTRY.startswith('*/30 * * * * '),
      app.CERT_RENEW_CRON_ENTRY)
check('crontab 指向续期脚本',
      app.CERT_RENEW_SCRIPT_PATH in app.CERT_RENEW_CRON_ENTRY)
check('续期脚本调用 app.py --renew-certs',
      '--renew-certs' in app.CERT_RENEW_SCRIPT)
check('启动时会装 crontab', '_ensure_cert_renew_cron()' in APP_SRC)

# ─────────────────────────────────────────────────────────────
sec('WC-9  setup.sh 补装 acme.sh 的 DNS 插件')

check('定义了插件清单变量', 'ACME_DNSAPI_PLUGINS=' in SETUP_SRC)
check('插件清单含阿里云', 'dns_ali' in
      re.search(r'ACME_DNSAPI_PLUGINS="([^"]*)"', SETUP_SRC).group(1))
check('清单覆盖面板支持的全部提供商',
      all(p in re.search(r'ACME_DNSAPI_PLUGINS="([^"]*)"', SETUP_SRC).group(1)
          for p in ('dns_ali', 'dns_tencent', 'dns_cf')))
check('install_acme 会复制 opkg 版主脚本',
      '/usr/lib/acme/client/acme.sh' in SETUP_SRC)
check('install_acme 从 raw.githubusercontent 拉插件',
      'raw.githubusercontent.com/acmesh-official/acme.sh' in SETUP_SRC)
check('插件下载失败有告警', '插件 ${p}.sh 下载失败' in SETUP_SRC)

# ─────────────────────────────────────────────────────────────
sec('WC-10 前端把泛域名开关与自动续期参数传给后端')

req_body = re.search(r'async requestRpCert\(\).*?\n    \},', APPJS_SRC, re.S)
check('requestRpCert 把 wildcard 传给后端',
      bool(req_body) and 'wildcard: this.rpRequestWildcard' in req_body.group(0))
check('requestRpCert 把 auto_renew 传给后端',
      bool(req_body) and 'auto_renew: this.rpRequestAutoRenew' in req_body.group(0))
check('requestRpCert 把 renew_days 传给后端',
      bool(req_body) and 'renew_days:' in req_body.group(0))
check('前端有泛域名复选框', 'x-model="rpRequestWildcard"' in INDEX_SRC)
check('证书列表展示 SAN 覆盖范围', 'cert.sans.join' in INDEX_SRC)
check('证书列表展示自动续期状态', 'cert.auto_renew' in INDEX_SRC)

# ─────────────────────────────────────────────────────────────
sec('WC-11 前端 getRpCertDaysClass 不再缺失')

# index.html 引用了 getRpCertDaysClass，但 app.js 里从来没实现过它 ——
# Alpine 求值时抛 "getRpCertDaysClass is not defined"，证书卡片的
# 「剩余天数」和「状态」两行颜色一直绑不上（跟历史上那个
# cancelRpEdit 是同一类问题：HTML 引用了，JS 里没实现）。
check('app.js 里实现了 getRpCertDaysClass',
      'getRpCertDaysClass(' in APPJS_SRC)
check('index.html 确实在用它',
      'getRpCertDaysClass(cert.days_remaining)' in INDEX_SRC)
check('实现了不是只声明',
      re.search(r'getRpCertDaysClass\(days\)\s*\{', APPJS_SRC) is not None)
check('过期/临期/正常三档颜色都区分了',
      all(c in APPJS_SRC for c in ('text-red-600', 'text-yellow-600', 'text-green-600')))
check('getRpCertStatusText 也不再只有「有效/已过期」两档',
      '即将过期' in APPJS_SRC and '需尽快续期' in APPJS_SRC)

# ─────────────────────────────────────────────────────────────
sec('WC-12 打开反代页不再误触发 nginx 重生成')

# loadReverseProxy 里「只有一个证书就自动设默认」的判断，**必须**在
# settings 赋值之后。放前面的话读到的是初始值（default_cert_id 为空串），
# 于是每次新开面板进反代页都会误判「没设默认证书」→ 自动调 set-default
# → 后端 _deploy_all_rules 重生成整份 nginx 配置 → 冲掉手工补丁。
# 2026-10-28 在 .233 实测：一次「打开面板截图」就把 33 条 sub_filter
# 补丁冲成了 7 条。
m = re.search(r'async loadReverseProxy\(\).*?\n    \},', APPJS_SRC, re.S)
body = m.group(0) if m else ''
i_auto = body.find('certificates.length === 1')
i_settings = body.find('default_cert_id: s.default_cert_id')
check('找到 loadReverseProxy', bool(body))
check('找到自动设默认的判断', i_auto >= 0)
check('找到 settings 的赋值', i_settings >= 0)
check('自动设默认的判断在 settings 赋值**之后**',
      i_auto > i_settings >= 0,
      f'auto@{i_auto} settings@{i_settings}')
check('这段逻辑还带着解释为什么会冲掉手工配置',
      'sub_filter' in body or '手工' in body)

print()
if FAIL:
    print(f'❌ 失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
