"""面板侧认证/会话/访问边界批次的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_panel_auth_fixes.py

覆盖（2026-10-30 批次 A）：
  P1-21 证书私钥下载端点无二次认证
  P1-22 面板会话无绝对生命周期
  P1-25 /api/knock-info 的 LAN 判断接受过宽网段
  P1-46 auth_api_port 不与面板 HTTPS 端口交叉校验
  P2-17 面板与网关的 cookie domain 推导逻辑不一致
  P2-18 Cookie Domain 取自未校验的证书 SAN
  P2-22 认证数据响应不带 Cache-Control
  P2-24 预置名单无上限 + 每条 spawn 一个 nft 子进程

沙箱：所有落盘路径指到临时目录，不碰真实系统文件。
"""
import importlib.util as ilu
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    detail = detail.replace('❌', '[x]').replace('✅', '[v]')
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


TEST_PASSWORD = 'panel-auth-test-pw'


def load_modules(paths):
    """加载 app.py 与 auth_gateway.py，路径全部指到临时目录。

    两个模块都必须在环境变量设好**之后**导入：它们在模块级就读配置路径。
    """
    os.environ.update(paths)
    for name in ('app', 'auth_gateway'):
        sys.modules.pop(name, None)

    spec = ilu.spec_from_file_location('app', os.path.join(BACKEND, 'app.py'))
    app = ilu.module_from_spec(spec)
    sys.modules['app'] = app
    spec.loader.exec_module(app)

    spec2 = ilu.spec_from_file_location('auth_gateway',
                                         os.path.join(BACKEND, 'auth_gateway.py'))
    ag = ilu.module_from_spec(spec2)
    sys.modules['auth_gateway'] = ag
    spec2.loader.exec_module(ag)
    return app, ag


def make_selfsigned(dirpath, cn='perm-test.example.com', san=None):
    """生成一对自签证书/私钥。san 可指定 SAN（不加则用 CN）。"""
    key = os.path.join(dirpath, 'k.pem')
    crt = os.path.join(dirpath, 'c.pem')
    cmd = ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
           '-keyout', key, '-out', crt, '-days', '1', '-subj', f'/CN={cn}']
    if san:
        cmd += ['-addext', f'subjectAltName={san}']
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f'openssl 生成自签证书失败: {r.stderr}')
    return crt, key


def write_config(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False)


def main():
    tmpdir = tempfile.mkdtemp(prefix='panel-auth-')
    paths = {
        'AUTH_CONFIG_PATH': os.path.join(tmpdir, 'config.json'),
        'AUTH_PASSWORD_FILE': os.path.join(tmpdir, 'password.json'),
        'AUTH_SECRET_FILE': os.path.join(tmpdir, 'secret'),
        'AUTH_SESSION_SECRET_FILE': os.path.join(tmpdir, 'session-secret'),
        'AUTH_PANEL_RATELIMIT_FILE': os.path.join(tmpdir, 'ratelimit.json'),
        'AUTH_RATELIMIT_FILE': os.path.join(tmpdir, 'gw-ratelimit.json'),
        'AUTH_AUDIT_LOG': os.path.join(tmpdir, 'audit.log'),
        'NFTABLES_WEB_LISTS_PATH': os.path.join(tmpdir, 'lists.json'),
        'NFTABLES_WEB_ALIYUN_CONFIG': os.path.join(tmpdir, 'aliyun.json'),
        'NFTABLES_WEB_RULES_PATH': os.path.join(tmpdir, 'rules.nft'),
        'NFTABLES_WEB_SSL_DIR': os.path.join(tmpdir, 'ssl'),
        'NFTABLES_WEB_NGINX_CONF_DIR': os.path.join(tmpdir, 'nginx-conf'),
        'NFTABLES_WEB_RECOVERY_STATUS': os.path.join(tmpdir, 'recovery.status'),
        'AUTH_API_PORT': '18444',
    }
    os.makedirs(paths['NFTABLES_WEB_SSL_DIR'], exist_ok=True)

    print('=' * 66)
    print('面板侧认证/会话/访问边界批次')
    print('=' * 66)

    app, ag = load_modules(paths)

    # ── 基础：写一份能登录的配置 ────────────────────────────────────
    app._write_password_hash(app._hash_password(TEST_PASSWORD))
    write_config(paths['AUTH_CONFIG_PATH'], {
        'lan_subnet4': '192.168.100.0/24',
        'wan_if': 'eth0',
        'lan_if': 'br-lan',
        'router_ip4': '192.168.100.1',
        'auth_absolute_timeout': 43200,
        'reverse_proxy': {'rules': [], 'certificates': [], 'settings': {}},
    })

    client = app.app.test_client()
    client.environ_base['REMOTE_ADDR'] = '192.168.100.50'
    r = client.post('/api/auth/login', json={'password': TEST_PASSWORD})
    check('登录成功（后续用例的前提）',
          r.status_code == 200 and (r.get_json() or {}).get('success'),
          f'HTTP {r.status_code}')

    # ── P1-21 私钥下载二次认证 ───────────────────────────────────────
    sec('P1-21 证书私钥下载端点需要二次认证')

    crt, key = make_selfsigned(tmpdir)
    cert_dir = os.path.join(paths['NFTABLES_WEB_SSL_DIR'], 'perm-test.example.com')
    os.makedirs(cert_dir, exist_ok=True)
    with open(crt, 'rb') as f:
        open(os.path.join(cert_dir, 'fullchain.pem'), 'wb').write(f.read())
    with open(key, 'rb') as f:
        open(os.path.join(cert_dir, 'privkey.pem'), 'wb').write(f.read())

    cfg = app.load_config()
    cfg.setdefault('reverse_proxy', {}).setdefault('certificates', []).append({
        'id': 'cert_test_001',
        'domain': 'perm-test.example.com',
        'source': 'manual',
        'cert_path': os.path.join(cert_dir, 'fullchain.pem'),
        'key_path': os.path.join(cert_dir, 'privkey.pem'),
    })
    app.save_config(cfg)

    url = '/api/reverse-proxy/certificates/cert_test_001/download'
    r = client.get(url)
    body = r.get_json() or {}
    check('不带确认口令 → 拒绝（403 CONFIRM_REQUIRED）',
          r.status_code == 403 and body.get('code') == 'CONFIRM_REQUIRED',
          f'HTTP {r.status_code} code={body.get("code")}')

    r = client.get(url, headers={'X-Confirm-Password': 'wrong-password'})
    body = r.get_json() or {}
    check('口令错误 → 拒绝（403 CONFIRM_FAILED）',
          r.status_code == 403 and body.get('code') == 'CONFIRM_FAILED',
          f'HTTP {r.status_code} code={body.get("code")}')

    # 不确认就探测不存在的证书：必须和「证书不存在」返回**同一个**结果，
    # 否则未确认的调用者能靠状态码差别把证书列表探出来
    r_unknown = client.get('/api/reverse-proxy/certificates/cert_nope/download')
    body_unknown = r_unknown.get_json() or {}
    check('未确认时探测不存在的证书 → 与存在的证书同样被 CONFIRM_REQUIRED 挡下',
          r_unknown.status_code == 403
          and body_unknown.get('code') == 'CONFIRM_REQUIRED',
          f'HTTP {r_unknown.status_code} code={body_unknown.get("code")}')
    check('未确认时探测不存在的证书 ≠ 404（否则能靠状态码枚举证书 id）',
          r_unknown.status_code != 404, f'HTTP {r_unknown.status_code}')

    r = client.get(url, headers={'X-Confirm-Password': TEST_PASSWORD})
    ok = r.status_code == 200
    names = []
    if ok:
        try:
            with zipfile.ZipFile(io.BytesIO(r.data)) as z:
                names = z.namelist()
        except Exception:
            ok = False
    check('口令正确 → 正常下载 zip（含私钥）',
          ok and any('privkey' in n for n in names),
          f'HTTP {r.status_code} 内容={names}')

    # 一张带通配 SAN 的「默认证书」—— P2-17 / P2-18 都要用：
    # 面板**自己**从证书 SAN 推导时，只有真的有这张证书才推得出值。
    good_crt, good_key = make_selfsigned(tmpdir, cn='y', san='DNS:*.good.example.com')
    good_dir = os.path.join(paths['NFTABLES_WEB_SSL_DIR'], 'good.example.com')
    os.makedirs(good_dir, exist_ok=True)
    with open(good_crt, 'rb') as f:
        open(os.path.join(good_dir, 'fullchain.pem'), 'wb').write(f.read())
    with open(good_key, 'rb') as f:
        open(os.path.join(good_dir, 'privkey.pem'), 'wb').write(f.read())

    # ── P1-22 面板会话绝对生命周期 ───────────────────────────────────
    sec('P1-22 面板会话有绝对生命周期上限')

    # ⚠️ 必须用**受鉴权管辖**的端点来测：`/api/auth/status` 在
    # before_request 的豁免名单里（`path.startswith('/api/auth/')`），
    # 它压根不走会话检查 —— 拿它测会话过期是**测不到东西的**。
    probe = '/api/config'

    # 起点戳必须在登录时打上 —— 否则「绝对上限」永远无从计算
    # （这一条单独断言：少了它，下面的过期用例可以靠手工塞戳来凑绿）
    client.post('/api/auth/login', json={'password': TEST_PASSWORD})
    with client.session_transaction() as sess:
        check('登录后会话里有 auth_started_at 起点戳',
              float(sess.get('auth_started_at', 0) or 0) > 0,
              repr(sess.get('auth_started_at')))

    r = client.get(probe)
    check('会话仍然有效（基线）', r.status_code == 200, f'HTTP {r.status_code}')

    with client.session_transaction() as sess:
        sess['auth_started_at'] = 1.0        # 1970 年 ⇒ 一定超期
    r = client.get(probe)
    body = r.get_json() or {}
    check('超过绝对上限 → 会话失效（401 AUTH_EXPIRED）',
          r.status_code == 401 and body.get('code') == 'AUTH_EXPIRED',
          f'HTTP {r.status_code} code={body.get("code")}')

    # 重新登录
    client.post('/api/auth/login', json={'password': TEST_PASSWORD})
    with client.session_transaction() as sess:
        sess.pop('auth_started_at', None)   # 老会话（升级前建立的）
    r = client.get(probe)
    check('老会话（没有起点戳）→ 不判过期（升级不该把人全踢下线）',
          r.status_code == 200, f'HTTP {r.status_code}')

    # 绝对上限取自配置：60 秒。起点 120 秒前 → 过期；起点 10 秒前 → 还在。
    #
    # ⚠️ 不用 0 来测「不启用」：load_config() 里的 _migrate_auth_absolute_timeout
    # 会把 0 提升成 43200（旧的「不启用」默认值已被判定为危险），
    # 所以 0 这个状态**根本存不住**，拿它测等于测一个到不了的状态。
    cfg = app.load_config()
    cfg['auth_absolute_timeout'] = 60
    app.save_config(cfg)

    client.post('/api/auth/login', json={'password': TEST_PASSWORD})
    with client.session_transaction() as sess:
        sess['auth_started_at'] = time.time() - 120
    r = client.get(probe)
    body = r.get_json() or {}
    check('起点早于上限 → 会话失效',
          r.status_code == 401 and body.get('code') == 'AUTH_EXPIRED',
          f'HTTP {r.status_code} code={body.get("code")}')

    client.post('/api/auth/login', json={'password': TEST_PASSWORD})
    with client.session_transaction() as sess:
        sess['auth_started_at'] = time.time() - 10
    r = client.get(probe)
    check('起点还在上限内 → 会话有效（滑动不影响绝对上限）',
          r.status_code == 200, f'HTTP {r.status_code}')

    # 恢复默认
    cfg = app.load_config()
    cfg['auth_absolute_timeout'] = 43200
    app.save_config(cfg)
    client.post('/api/auth/login', json={'password': TEST_PASSWORD})
    r = client.get(probe)
    check('刚登录的会话不受绝对上限影响',
          r.status_code == 200, f'HTTP {r.status_code}')

    # ── P1-25 knock-info 的 LAN 判断 ────────────────────────────────
    sec('P1-25 /api/knock-info 的 LAN 判断不接受过宽网段')

    # 绕过配置校验直接写配置（模拟手工改坏 / 自动检测出来的宽网段）
    cfg = app.load_config()
    cfg['lan_subnet4'] = '0.0.0.0/1'
    app.save_config(cfg)
    check('lan_subnet4 = 0.0.0.0/1 → 1.2.3.4 不算 LAN',
          app._client_is_lan('1.2.3.4') is False,
          f'_client_is_lan → {app._client_is_lan("1.2.3.4")}')

    cfg['lan_subnet4'] = '192.168.100.0/24'
    app.save_config(cfg)
    check('lan_subnet4 = 192.168.100.0/24 → 段内地址算 LAN',
          app._client_is_lan('192.168.100.50') is True)
    check('lan_subnet4 = 192.168.100.0/24 → 段外地址不算 LAN',
          app._client_is_lan('10.0.0.1') is False)

    # ── P1-46 auth_api_port 与面板端口交叉校验 ───────────────────────
    sec('P1-46 auth_api_port 与面板 HTTPS 端口交叉校验')

    base_cfg = {
        'lan_subnet4': '192.168.100.0/24', 'wan_if': 'eth0', 'lan_if': 'br-lan',
        'router_ip4': '192.168.100.1', 'gateway_enabled': True,
        'gateway_port': 8443, 'auth_api_port': 8444,
    }
    errs = app.validate_config(dict(base_cfg))
    check('正常端口组合不报错',
          not any('auth_api_port' in e for e in errs), str(errs))

    bad = dict(base_cfg)
    bad['auth_api_port'] = app.HTTPS_PORT
    errs = app.validate_config(bad)
    check('auth_api_port 撞面板 HTTPS 端口 → 报错',
          any('auth_api_port' in e for e in errs), str(errs))

    # ── P2-17 面板与网关的 cookie domain 推导一致 ───────────────────
    sec('P2-17 面板与网关的 cookie domain 推导逻辑一致')

    # 场景一：settings 里有 base_domain，没有 cookie_domain
    cfg = app.load_config()
    cfg['reverse_proxy'] = {'rules': [], 'certificates': [],
                            'settings': {'base_domain': 'fzyto.top'}}
    app.save_config(cfg)
    panel_cd = app._rp_cookie_domain(app.load_config())
    gw_cd = ag._cookie_domain(app.load_config())
    check('两边对「只有 base_domain」的推导结果一致',
          panel_cd == gw_cd, f'面板={panel_cd!r} 网关={gw_cd!r}')
    check('推导结果确实是共享域', panel_cd == '.fzyto.top', repr(panel_cd))

    # 场景二：settings 里什么都没有，但**默认证书的 SAN 能推出 base_domain**
    # ⇒ 面板如果自己推导就会返回 '.good.example.com'，而网关只读落盘值 ⇒ ''。
    # 这正是 P2-17 的那个不一致。
    cfg = app.load_config()
    cfg['reverse_proxy'] = {
        'rules': [], 'settings': {'default_cert_id': 'cert_good_001'},
        'certificates': [{
            'id': 'cert_good_001', 'domain': 'good.example.com', 'source': 'manual',
            'cert_path': os.path.join(good_dir, 'fullchain.pem'),
            'key_path': os.path.join(good_dir, 'privkey.pem'),
        }],
    }
    app.save_config(cfg)
    panel_cd = app._rp_cookie_domain(app.load_config())
    gw_cd = ag._cookie_domain(app.load_config())
    check('两边对「只有默认证书」的推导结果一致',
          panel_cd == gw_cd, f'面板={panel_cd!r} 网关={gw_cd!r}')
    check('面板不再自己从证书 SAN 推导 cookie 域（否则与网关不一致）',
          panel_cd == '', repr(panel_cd))
    check('网关确实推导不出来（这个场景才有区分度）',
          gw_cd == '', repr(gw_cd))

    # ── P2-18 Cookie Domain 取自未校验的证书 SAN ────────────────────
    sec('P2-18 从证书 SAN 推出的域名落盘前必须净化')

    # SAN 里必须**带点**（推导逻辑挑的是「含点的普通 SAN」），但要含一个
    # 非法字符（下划线）⇒ _sanitize_rp_host 会拒绝它。
    bad_crt, bad_key = make_selfsigned(tmpdir, cn='x',
                                       san='DNS:bad_domain.example.com')
    bad_dir = os.path.join(paths['NFTABLES_WEB_SSL_DIR'], 'bad.example.com')
    os.makedirs(bad_dir, exist_ok=True)
    with open(bad_crt, 'rb') as f:
        open(os.path.join(bad_dir, 'fullchain.pem'), 'wb').write(f.read())
    with open(bad_key, 'rb') as f:
        open(os.path.join(bad_dir, 'privkey.pem'), 'wb').write(f.read())

    cfg = app.load_config()
    cfg['reverse_proxy'] = {
        'rules': [],
        # ⚠️ 必须设 default_cert_id —— 没有它，_rp_default_cert_entry 返回 None，
        # 推导那段根本不进 ⇒ 断言恒真，净化这条等于没测。
        'settings': {'default_cert_id': 'cert_bad_001'},
        'certificates': [{
            'id': 'cert_bad_001', 'domain': 'bad.example.com', 'source': 'manual',
            'cert_path': os.path.join(bad_dir, 'fullchain.pem'),
            'key_path': os.path.join(bad_dir, 'privkey.pem'),
        }],
    }
    app.save_config(cfg)
    # _rp_sync_base_domain 只改内存里的 config，落盘由调用方负责
    # （真实的调用点是 rp_upload_cert → _rp_sync_base_domain → _save_rp_config）。
    # ⚠️ 必须**落盘之后**再查磁盘 —— 否则无论净化与否，磁盘上都是空的，
    # 断言恒真，净化这条就等于没测。
    work = app.load_config()
    app._rp_sync_base_domain(work)
    app.save_config(work)
    after = app.load_config().get('reverse_proxy', {}).get('settings', {})
    check('SAN 推出的非法域名（下划线）没有落盘',
          'base_domain' not in after and 'cookie_domain' not in after,
          f'settings={after}')

    # 合法 SAN 仍然要能自动推导（别把功能改没了）
    cfg = app.load_config()
    cfg['reverse_proxy'] = {
        'rules': [],
        'settings': {'default_cert_id': 'cert_good_001'},
        'certificates': [{
            'id': 'cert_good_001', 'domain': 'good.example.com', 'source': 'manual',
            'cert_path': os.path.join(good_dir, 'fullchain.pem'),
            'key_path': os.path.join(good_dir, 'privkey.pem'),
        }],
    }
    app.save_config(cfg)
    # _rp_sync_base_domain 只改内存里的 config，落盘由调用方负责
    # （真实的调用点是 rp_upload_cert → _rp_sync_base_domain → _save_rp_config）
    work = app.load_config()
    derived = app._rp_sync_base_domain(work)
    app.save_config(work)
    after = app.load_config().get('reverse_proxy', {}).get('settings', {})
    check('合法通配 SAN 仍能自动推出 base_domain',
          derived == 'good.example.com' and after.get('base_domain') == 'good.example.com',
          f'derived={derived!r} settings={after}')
    check('合法 SAN 时 cookie 共享域也跟着落盘',
          after.get('cookie_domain') == '.good.example.com',
          f'settings={after}')

    # ── P2-22 认证数据响应带 Cache-Control ──────────────────────────
    sec('P2-22 认证数据响应带 Cache-Control: no-store')

    r = client.get('/api/config')
    check('/api/config 的响应带 no-store',
          'no-store' in (r.headers.get('Cache-Control') or ''),
          repr(r.headers.get('Cache-Control')))
    r = client.get('/api/lists/presets')
    check('/api/lists/presets 的响应带 no-store',
          'no-store' in (r.headers.get('Cache-Control') or ''),
          repr(r.headers.get('Cache-Control')))

    # ── P2-24 预置名单：查询次数与条数无关 + 有上限 ──────────────────
    sec('P2-24 预置名单的 nft 查询次数与条数无关，且有上限')

    n = 60
    cfg = app.load_config()
    cfg['ip_presets'] = [
        {'id': f'p_{i:04d}', 'label': f'p{i}', 'ip': f'192.168.1.{i % 250 + 1}',
         'type': 'whitelist' if i % 2 == 0 else 'blacklist', 'auto_expire': True}
        for i in range(n)
    ]
    app.save_config(cfg)

    calls = []
    real_run = subprocess.run

    def counting_run(cmd, *a, **kw):
        if isinstance(cmd, (list, tuple)) and cmd[:2] == ['nft', 'list']:
            calls.append(cmd)
        return real_run(cmd, *a, **kw)

    app.subprocess.run = counting_run
    try:
        r = client.get('/api/lists/presets')
    finally:
        app.subprocess.run = real_run
    body = r.get_json() or {}
    check(f'{n} 条预设全部返回', len((body.get('data') or {}).get('presets') or []) == n,
          f'返回 {len((body.get("data") or {}).get("presets") or [])} 条')
    check(f'{n} 条预设的 nft 查询次数 ≤ 4（与条数无关）',
          len(calls) <= 4, f'实际 {len(calls)} 次')

    cfg = app.load_config()
    cfg['ip_presets'] = [
        {'id': f'p_{i:06d}', 'label': f'p{i}', 'ip': f'10.0.{i // 250}.{i % 250 + 1}',
         'type': 'whitelist', 'auto_expire': True}
        for i in range(app.PRESET_MAX + 5)
    ]
    app.save_config(cfg)
    r = client.post('/api/lists/presets', json={
        'label': 'over', 'ip': '203.0.113.9', 'type': 'whitelist'})
    body = r.get_json() or {}
    check('超过预设条数上限 → 拒绝新增（400）',
          r.status_code == 400 and '上限' in str(body.get('message', '')),
          f'HTTP {r.status_code} {body.get("message")}')

    # ── P1-34 开机恢复状态：面板要能看见「现在跑的是不是过期策略」────
    sec('P1-34 面板能读到 init 写的开机恢复状态')

    status_file = paths['NFTABLES_WEB_RECOVERY_STATUS']

    check('状态文件不存在 → recovery 为 None（未知，不是「正常」）',
          app._read_recovery_status() is None,
          repr(app._read_recovery_status()))

    with open(status_file, 'w', encoding='utf-8') as f:
        f.write('state=degraded\nreason=规则集语法错误，已回退到 .lastgood\n'
                'ts=2026-10-30 18:00:00\nsource=init\n')
    st = app._read_recovery_status()
    check('degraded 状态被解析出来',
          st is not None and st.get('state') == 'degraded', repr(st))
    check('reason / ts 一并读出',
          st and 'lastgood' in st.get('reason', '') and st.get('ts'),
          repr(st))

    with open(status_file, 'w', encoding='utf-8') as f:
        f.write('state=whatever\n')
    check('不认识的状态值 → 当作未知（不谎报）',
          app._read_recovery_status() is None,
          repr(app._read_recovery_status()))

    # 端点层面：degraded 必须让面板知道（而不是照报「规则已加载」）
    with open(status_file, 'w', encoding='utf-8') as f:
        f.write('state=degraded\nreason=回退到旧策略\nts=2026-10-30 18:00:00\n')

    real_run2 = app.subprocess.run

    def stub_run(cmd, *a, **kw):
        class R:
            returncode = 1
            stdout = 'inactive'
            stderr = ''
        return R()

    app.subprocess.run = stub_run
    try:
        r = client.get('/api/firewall/status')
    finally:
        app.subprocess.run = real_run2
    body = r.get_json() or {}
    check('/api/firewall/status 返回 recovery 状态',
          (body.get('recovery') or {}).get('state') == 'degraded',
          f'HTTP {r.status_code} recovery={body.get("recovery")}')
    check('degraded 时 recovery_degraded=True（面板不能说「正常」）',
          body.get('recovery_degraded') is True, repr(body.get('recovery_degraded')))

    with open(status_file, 'w', encoding='utf-8') as f:
        f.write('state=ok\nreason=自定义规则已加载\nts=2026-10-30 18:00:00\n')
    app.subprocess.run = stub_run
    try:
        r = client.get('/api/firewall/status')
    finally:
        app.subprocess.run = real_run2
    body = r.get_json() or {}
    check('ok 时 recovery_degraded=False',
          body.get('recovery_degraded') is False, repr(body.get('recovery_degraded')))

    print('\n' + '=' * 66)
    print(f' 合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        print(' 有失败:')
        for f in FAIL:
            print('   - ' + f)
    else:
        print(' 全部通过')
    print('=' * 66)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
