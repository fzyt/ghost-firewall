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
# init 脚本（治本的一层：显式 export HOME=/root）
INIT_SRC = open(os.path.join(BACKEND, 'nftables-web.init'), encoding='utf-8').read()
# vendor 说明（随包分发的内容要交代来源和许可）
VENDOR_README = open(os.path.join(ROOT, 'setup', 'vendor', 'README.md'),
                      encoding='utf-8').read()
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
#
# ⚠️ 2026-10-31 起 "/root/.acme.sh/acme.sh" **排在 "~" 前面** ——
# 面板由 procd 启动时 HOME=/ （不是 /root），expanduser("~") 展开成 "/"，
# 若 "~" 先命中就会拿到裁剪版的 /usr/lib/acme/client/acme.sh，
# 它的同级 dnsapi/ 是空的 ⇒ 插件检查全盘落空（.230 实测）。
_real_isfile, _real_access = app.os.path.isfile, app.os.access
try:
    app.os.path.isfile = lambda p: p in (
        '/root/.acme.sh/acme.sh',
        os.path.expanduser('~/.acme.sh/acme.sh'),
        '/usr/lib/acme/client/acme.sh')
    app.os.access = lambda p, mode: True
    got = app._acme_sh_path()
    check('优先命中 /root/.acme.sh/acme.sh（写死路径，不依赖 HOME）',
          got == '/root/.acme.sh/acme.sh', f'实际 {got}')
    app.os.path.isfile = lambda p: p == os.path.expanduser('~/.acme.sh/acme.sh')
    got = app._acme_sh_path()
    check('/root 不存在时回落到 ~ 路径',
          got == os.path.expanduser('~/.acme.sh/acme.sh'), f'实际 {got}')
    app.os.path.isfile = lambda p: p == '/usr/lib/acme/client/acme.sh'
    got = app._acme_sh_path()
    check('前两个都没有时回落到 OpenWrt opkg 路径',
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
# ⚠️ 2026-10-31 起：插件**优先从随包目录**拷，网络下载降级为兜底。
# （原先只有网络下载，raw.githubusercontent 国内间歇性可达，
#   失败时最坏烧 6 分钟，且只验「非空」会把 200 错误页当插件存下。）
check('install_acme 优先用随包携带的插件',
      'vendor/acme-dnsapi' in SETUP_SRC and '随包分发' in SETUP_SRC)
check('网络下载仍保留为兜底',
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

# ─────────────────────────────────────────────────────────────
sec('WC-13 acme.sh 路径探测不依赖 HOME 环境变量（2026-10-31 .230 实测）')

# 现场：procd 启动的面板进程 HOME=/ （不是 /root），
# 于是 os.path.expanduser("~") 展开成 "/"，
# "~/.acme.sh/dnsapi/dns_ali.sh" → "/.acme.sh/dnsapi/dns_ali.sh" → 不存在。
# 而插件**明明在** /root/.acme.sh/dnsapi/ 下 —— 面板却报「缺少插件」。
#
# 迷惑性在于：部署完当场能用（setup.sh 从 shell 起，HOME=/root），
# 一重启就坏（procd 起，HOME=/）。.232 就是"还没重启所以侥幸能用"。
#
# 修法：候选里把 /root 写死并**排在 "~" 前面** ——
# 面板永远以 root 运行，root 的家目录就是 /root，不该依赖环境变量。

check('候选里有写死的 /root 路径',
      '/root/.acme.sh/acme.sh' in app.ACME_SH_CANDIDATES)
check('/root 候选排在 "~" 候选前面',
      app.ACME_SH_CANDIDATES.index('/root/.acme.sh/acme.sh')
      < app.ACME_SH_CANDIDATES.index('~/.acme.sh/acme.sh'),
      str(app.ACME_SH_CANDIDATES))
check('插件目录候选也含 /root',
      '/root/.acme.sh/dnsapi' in app.ACME_DNSAPI_DIRS)
check('插件目录候选里 /root 排在 "~" 前面',
      app.ACME_DNSAPI_DIRS.index('/root/.acme.sh/dnsapi')
      < app.ACME_DNSAPI_DIRS.index('~/.acme.sh/dnsapi'),
      str(app.ACME_DNSAPI_DIRS))

# 打桩：模拟 HOME=/ 的运行环境，验证仍能命中 /root 下的 acme.sh
_real_expanduser = app.os.path.expanduser
try:
    def _expanduser_stub(path):
        # 模拟 HOME=/：expanduser("~x") → "/x"
        if path.startswith('~'):
            return '/' + path[1:].lstrip('/')
        return path
    app.os.path.expanduser = _expanduser_stub
    app.os.path.isfile = lambda p: p == '/root/.acme.sh/acme.sh'
    app.os.access = lambda p, mode: True
    got = app._acme_sh_path()
    check('HOME=/ 时仍能命中 /root/.acme.sh/acme.sh',
          got == '/root/.acme.sh/acme.sh', f'实际 {got}')
finally:
    app.os.path.expanduser = _real_expanduser
    app.os.path.isfile, app.os.access = _real_isfile, _real_access

# 插件路径列表：HOME=/ 时也必须含 /root 那条
_real_expanduser = app.os.path.expanduser
try:
    app.os.path.expanduser = lambda path: (
        '/' + path[1:].lstrip('/') if path.startswith('~') else path)
    paths = app._acme_plugin_paths('dns_ali.sh')
    check('插件路径列表含 /root/.acme.sh/dnsapi/dns_ali.sh',
          '/root/.acme.sh/dnsapi/dns_ali.sh' in paths, str(paths))
finally:
    app.os.path.expanduser = _real_expanduser

check('有 _acme_plugin_paths() 函数', hasattr(app, '_acme_plugin_paths'))
check('缺插件时的报错带上「已查找的路径」（便于下次直接定位）',
      '已查找的路径' in APP_SRC)

# init 脚本必须显式 export HOME=/root —— 这是治本的一层
check('init 脚本显式 export HOME=/root',
      'export HOME=/root' in INIT_SRC,
      '面板由 procd 启动时默认 HOME=/')
check('init 脚本里 export HOME 在 python3 app.py 之前',
      INIT_SRC.find('export HOME=/root') < INIT_SRC.find('python3 app.py')
      if 'export HOME=/root' in INIT_SRC else False)

# ─────────────────────────────────────────────────────────────
sec('WC-14 setup.sh 固定 ACME CA，避开 ZeroSSL 的邮箱强制（2026-10-31 实测）')

# acme.sh v3.1.3 源码第 37 行 `DEFAULT_CA=$CA_ZEROSSL` —— 默认 CA 硬编码。
# ZeroSSL 强制要邮箱，没邮箱就抛 "Please update your account with an email
# address first." 然后退出。后端调的是 `acme.sh --issue`（不带 --server），
# ⇒ 面板点「申请证书」必然失败，跟插件、跟阿里云凭据都无关。
# .232 和 .230 都实测复现过，报错一字不差。
#
# acme.sh 官方支持的持久化方式是 account.conf 的 DEFAULT_ACME_SERVER 键
# （源码第 2919 行 _readaccountconf 读它）。
# ⚠️ 没有 ca.conf 机制 —— 往 ca.conf 写 CA_SERVER 是**无效**的（踩过的弯路）。

check('定义了 ACME_CA_URL 常量', 'ACME_CA_URL=' in SETUP_SRC)
ca_url = re.search(r'ACME_CA_URL="([^"]+)"', SETUP_SRC)
check('ACME_CA_URL 指向 letsencrypt',
      ca_url and 'letsencrypt' in ca_url.group(1),
      ca_url.group(1) if ca_url else '(未找到)')
check('install_acme 会写 account.conf',
      'account.conf' in SETUP_SRC)
check('写的是 DEFAULT_ACME_SERVER 键（acme.sh 唯一支持的机制）',
      'DEFAULT_ACME_SERVER' in SETUP_SRC)
check('没往 ca.conf 里写 CA_SERVER（那是无效的）',
      'CA_SERVER=' not in SETUP_SRC)

# ─────────────────────────────────────────────────────────────
sec('WC-15 acme.sh DNS 插件随包分发，不再依赖运行时下载')

# 2026-10-31 在 .142 / .156 / .230 三台设备上连续踩到：
#   · raw.githubusercontent.com 国内间歇性可达，失败时最坏烧 6 分钟
#   · 老 setup.sh 只验「文件非空」不验内容，200 错误页被当成插件存下
# 现在改成随包携带（跟 vendor/blinker 同一套路），网络下载降级为兜底。

VENDOR_DIR = os.path.join(ROOT, 'setup', 'vendor', 'acme-dnsapi')
check('vendor 目录存在', os.path.isdir(VENDOR_DIR))

plugins = re.search(r'ACME_DNSAPI_PLUGINS="([^"]*)"', SETUP_SRC).group(1).split()
check('插件清单非空', len(plugins) >= 6, str(plugins))
missing = [p for p in plugins
           if not os.path.isfile(os.path.join(VENDOR_DIR, p + '.sh'))]
check('vendor 里每个插件都有对应文件', not missing, f'缺 {missing}')

bad = []
for p in plugins:
    fp = os.path.join(VENDOR_DIR, p + '.sh')
    if not os.path.isfile(fp):
        continue
    with open(fp, 'rb') as f:
        head = f.readline()
    size = os.path.getsize(fp)
    if not head.startswith(b'#!') or size < 1000:
        bad.append(f'{p}({size}B,{head[:20]!r})')
check('vendor 插件首行是 shebang 且体积正常（非错误页）',
      not bad, str(bad))

check('setup.sh 会找 vendor/acme-dnsapi 目录',
      'vendor/acme-dnsapi' in SETUP_SRC)
check('setup.sh 有「随包分发」路径', '随包分发' in SETUP_SRC)
check('安装时验首行（防错误页冒充插件）',
      "grep -q '^#!'" in SETUP_SRC)
check('网络下载仍保留为兜底（老用法不能坏）',
      'raw.githubusercontent.com' in SETUP_SRC)
check('vendor README 说明了 acme-dnsapi',
      'acme-dnsapi' in VENDOR_README)
check('vendor README 说明了许可（acme.sh 是 GPL-3.0）',
      'GPL' in VENDOR_README)

print()
if FAIL:
    print(f'❌ 失败 {len(FAIL)} 项：')
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print(f'通过 {len(PASS)} / {len(PASS)}')
print('全部通过')
