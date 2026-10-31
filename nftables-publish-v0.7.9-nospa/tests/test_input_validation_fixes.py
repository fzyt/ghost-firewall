"""输入校验与注入批次的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_input_validation_fixes.py

覆盖（2026-10-30 批次 B）：
  P1-38 knock-lan.sh 把 host 插进 `bash -c` 的命令串 → 命令注入
  P1-39 knock-lan.sh 用 `eval` 解析配置 → 配置里的值被当代码执行
  P2-6  router_ip6 原样插进 nftables 规则 → 规则注入
  P2-7  证书路径原样进 nginx 的 ssl_certificate → nginx 配置注入
  P2-8  端口转发/反代冲突检测用裸字符串比较 → 漏报冲突（免登录公网入口）
  P2-9  detect-* 端点抓取任意 host:port 且回显可区分的错误 → SSRF oracle
  P2-11 lan_if 原样插进兜底 nftables 规则 → 规则注入
  P2-15 名单元素二次注入（读出来再落地时没再校验）→ nftables set 注入
  P2-16 规则校验放行、nginx 生成器却静默丢弃 → API 报成功但规则没生效
  P2-19 客户端可控的 Host 头被转发给上游 → Host Header Injection

沙箱：所有落盘路径指到临时目录；knock-lan.sh 复制到临时目录后改掉它写死的
配置文件路径再跑（**不碰** /etc/nftables）。
"""
import importlib.util as ilu
import json
import os
import re
import subprocess
import sys
import tempfile

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


def load_app(paths):
    os.environ.update(paths)
    sys.modules.pop('app', None)
    spec = ilu.spec_from_file_location('app', os.path.join(BACKEND, 'app.py'))
    app = ilu.module_from_spec(spec)
    sys.modules['app'] = app
    spec.loader.exec_module(app)
    return app


def write_json(path, data):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False)


def run_knock(tmpdir, config=None, argv=None, tag='t'):
    """把 knock-lan.sh 复制到临时目录、改掉它写死的配置路径，再跑。

    为什么不能直接跑原脚本：它的 CONFIG 写死 /etc/nftables/nftables-web-config.json
    —— 测试机不该往那儿写东西，而且那要求 root。
    """
    src = os.path.join(ROOT, 'setup', 'knock-lan.sh')
    cfg_path = os.path.join(tmpdir, f'knock-config-{tag}.json')
    if config is not None:
        write_json(cfg_path, config)
    else:
        cfg_path = ''
    dst = os.path.join(tmpdir, f'knock-lan-{tag}.sh')
    with open(src, encoding='utf-8') as f:
        body = f.read()
    body = body.replace('CONFIG="/etc/nftables/nftables-web-config.json"',
                        f'CONFIG="{cfg_path}"')
    with open(dst, 'w', encoding='utf-8') as f:
        f.write(body)
    os.chmod(dst, 0o755)
    cmd = ['bash', dst] + (argv or [])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return r, dst, cfg_path


def main():
    tmpdir = tempfile.mkdtemp(prefix='input-val-')
    paths = {
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
    os.makedirs(paths['NFTABLES_WEB_SSL_DIR'], exist_ok=True)

    print('=' * 66)
    print('输入校验与注入批次')
    print('=' * 66)

    app = load_app(paths)

    # ── P1-38 / P1-39 knock-lan.sh ──────────────────────────────────
    sec('P1-38 / P1-39 knock-lan.sh 不再执行配置里的内容')

    canary = os.path.join(tmpdir, 'pwned')
    evil_cfg = {
        'router_ip4': f'x"; touch {canary}; echo "',
        'knock1_port': 1, 'knock2_port': 2, 'knock3_port': 3, 'knock4_port': 4,
    }
    r, _, _ = run_knock(tmpdir, config=evil_cfg, tag='evil')
    check('恶意 router_ip4 不会执行任何命令',
          not os.path.exists(canary),
          f'脚本退出码 {r.returncode}，输出 {r.stdout[:120]!r}')
    check('恶意 router_ip4 不会原样出现在目标地址里',
          not any(c in r.stdout for c in (';', '"', '`', '$(')),
          f'stdout={r.stdout[:200]!r}')

    # 命令串注入：host 里带 `;` 必须被白名单挡住
    canary2 = os.path.join(tmpdir, 'pwned2')
    r, _, _ = run_knock(tmpdir, argv=['-h', f'x; touch {canary2}; echo y',
                                      '-p', '1,2,3,4'], tag='inj')
    check('-h 里的注入串被白名单拒绝',
          not os.path.exists(canary2) and r.returncode != 0,
          f'退出码 {r.returncode}，stderr={r.stderr[:160]!r}')

    with open(os.path.join(ROOT, 'setup', 'knock-lan.sh'), encoding='utf-8') as f:
        knock_src = f.read()
    code = '\n'.join(l for l in knock_src.split('\n')
                     if not l.strip().startswith('#'))
    check('脚本里不再有 eval（配置值不会被当代码解析）',
          not re.search(r'(?<![\w-])eval(?=[\s(])', code),
          'eval 仍存在')
    check('bash -c 的命令串里不再插值 host/port',
          'bash -c "exec 3<>/dev/udp/${host}/${port}' not in code
          and '/dev/udp/"$1"/"$2"' in code,
          '命令串仍是插值形式')

    # ── P2-6 router_ip6 注入 ───────────────────────────────────────
    sec('P2-6 router_ip6 不再原样进 nftables 规则')

    cfg = app.load_config() if os.path.exists(paths['AUTH_CONFIG_PATH']) else {}
    cfg.setdefault('reverse_proxy', {'rules': [], 'certificates': [], 'settings': {}})
    cfg['router_ip6'] = '::1, }; delete table inet fw4; #'
    app.save_config(cfg)
    rules = app.build_rules(app.load_config())
    check('注入串没有进规则集',
          'delete table inet fw4' not in rules,
          '注入串出现在规则里')
    check('非法 router_ip6 被整个丢掉（DNS 转发块不生成）',
          'ip6 daddr {' not in rules.split('IPV6_LAN_WAN_DNS_BLOCK')[-1][:400]
          if 'IPV6_LAN_WAN_DNS_BLOCK' in rules else True,
          'DNS 转发块还在')

    # ── P2-7 nginx 证书路径注入 ────────────────────────────────────
    sec('P2-7 证书路径必须落在 SSL 目录内')

    ssl_dir = paths['NFTABLES_WEB_SSL_DIR']
    good = os.path.join(ssl_dir, 'ok.pem')
    with open(good, 'w') as f:
        f.write('x')
    check('SSL 目录内的路径被接受',
          app._safe_ssl_path(good) == os.path.realpath(good),
          repr(app._safe_ssl_path(good)))
    check('带 nginx 语句分隔符的路径被拒绝',
          app._safe_ssl_path('/etc/nftables/x.pem; include /etc/nginx/evil.conf;') == '',
          repr(app._safe_ssl_path('/etc/nftables/x.pem; include /etc/nginx/evil.conf;')))
    check('SSL 目录之外的路径被拒绝',
          app._safe_ssl_path('/etc/passwd') == '',
          repr(app._safe_ssl_path('/etc/passwd')))
    check('带 .. 的路径被拒绝（realpath 之后不在 SSL 目录内）',
          app._safe_ssl_path(os.path.join(ssl_dir, '..', '..', 'etc', 'passwd')) == '',
          repr(app._safe_ssl_path(os.path.join(ssl_dir, '..', '..', 'etc', 'passwd'))))

    # ── P2-8 冲突检测不能漏报 ──────────────────────────────────────
    sec('P2-8 端口转发/反代冲突检测不漏报等价写法')

    base = {
        'reverse_proxy': {'rules': [{
            'enabled': True, 'name': 'nas',
            'target_address': '192.168.1.10:8080',
            'path_prefix': '/nas',
        }]},
        'forward_rules': [{
            'target_ip': '192.168.001.010', 'tcp_ports': '8080',
        }],
    }
    errs = app._rp_forward_conflicts(base)
    check('等价写法的目标 IP 也能认出冲突',
          len(errs) == 1 and '绕过认证' in errs[0], str(errs))

    base2 = json.loads(json.dumps(base))
    base2['forward_rules'][0]['target_ip'] = '192.168.1.11'
    errs2 = app._rp_forward_conflicts(base2)
    check('确实不同的目标 IP 不误报',
          len(errs2) == 0, str(errs2))

    # ⚠️ 上面那条用例把「等价写法」放在**转发侧**。但变异脚本 M6 改的是
    # **反代侧**的归一化（rp_targets 那一半）。如果等价写法只在转发侧，
    # 变异后反代侧存的是原样字符串、转发侧仍归一化 —— 两边照样对得上，
    # 冲突仍被报出 ⇒ **测试抓不住这条变异**。
    #
    # 所以这里把等价写法放到**反代侧**，让两个方向各覆盖一次。
    base3 = {
        'reverse_proxy': {'rules': [{
            'enabled': True, 'name': 'nas',
            'target_address': '192.168.001.010:8080',   # 前导零
            'path_prefix': '/nas',
        }]},
        'forward_rules': [{
            'target_ip': '192.168.1.10', 'tcp_ports': '8080',
        }],
    }
    errs3 = app._rp_forward_conflicts(base3)
    check('等价写法在反代侧也能认出冲突',
          len(errs3) == 1 and '绕过认证' in errs3[0], str(errs3))

    # IPv6：反代侧带 URL 方括号、转发侧不带 —— 归一化后应视为同一个
    base4 = {
        'reverse_proxy': {'rules': [{
            'enabled': True, 'name': 'nas',
            'target_address': '[fd00::1]:8080',
            'path_prefix': '/nas',
        }]},
        'forward_rules': [{
            'target_ip': 'fd00::1', 'tcp_ports': '8080',
        }],
    }
    errs4 = app._rp_forward_conflicts(base4)
    check('IPv6 等价写法（方括号）也能认出冲突',
          len(errs4) == 1 and '绕过认证' in errs4[0], str(errs4))

    # ── P2-9 detect-* SSRF oracle ──────────────────────────────────
    sec('P2-9 detect-* 端点不再是对任意 host:port 的抓取器')

    cfg = app.load_config()
    cfg['lan_subnet4'] = '192.168.100.0/24'
    app.save_config(cfg)
    check('LAN 网段内的目标被允许',
          app._detect_target_allowed('192.168.100.50') is True)
    check('LAN 网段外的目标被拒绝',
          app._detect_target_allowed('10.0.0.1') is False)
    check('公网地址被拒绝',
          app._detect_target_allowed('8.8.8.8') is False)
    check('回环地址被拒绝',
          app._detect_target_allowed('127.0.0.1') is False)
    check('主机名被拒绝（防 DNS rebinding）',
          app._detect_target_allowed('evil.example.com') is False)
    check('IPv6 字面量被拒绝',
          app._detect_target_allowed('::1') is False)

    client = app.app.test_client()
    client.environ_base['REMOTE_ADDR'] = '192.168.100.50'
    # detect-* 是面板接口，要先登录
    app._write_password_hash(app._hash_password('input-val-pw'))
    client.post('/api/auth/login', json={'password': 'input-val-pw'})
    r = client.post('/api/reverse-proxy/detect-api-prefix',
                    json={'target_address': '10.0.0.1:80'})
    body = r.get_json() or {}
    check('detect-api-prefix 拒绝 LAN 网段外的目标',
          r.status_code == 400, f'HTTP {r.status_code} {body.get("message")}')
    r = client.post('/api/reverse-proxy/detect-protocol-relative',
                    json={'target_address': '8.8.8.8:80'})
    body = r.get_json() or {}
    check('detect-protocol-relative 拒绝公网目标',
          r.status_code == 400, f'HTTP {r.status_code} {body.get("message")}')
    r = client.post('/api/reverse-proxy/detect-api-prefix',
                    json={'target_address': 'evil.example.com:80'})
    body = r.get_json() or {}
    check('detect-api-prefix 拒绝主机名（防 DNS rebinding）',
          r.status_code == 400, f'HTTP {r.status_code} {body.get("message")}')

    # 错误信息里不能回显 URL（否则就成了能区分「超时/拒绝/404」的 oracle）
    _, err = app._detect_upstream_api_prefixes('192.168.100.50', '1', 'http', 0.1)
    check('探测失败时错误信息里没有 URL',
          'http://' not in (err or ''), repr(err))
    check('探测失败时错误信息里没有异常原文',
          'Error' not in (err or '') and 'refused' not in (err or ''), repr(err))

    # ── P2-11 lan_if 注入 ─────────────────────────────────────────
    sec('P2-11 兜底防火墙的 lan_if 经过白名单')

    check('_safe_iface 拒绝含引号/分号的接口名',
          app._safe_iface('lo" ; delete table inet fw4; #', 'br-lan') == 'br-lan',
          repr(app._safe_iface('lo" ; delete table inet fw4; #', 'br-lan')))
    check('_safe_iface 接受正常接口名',
          app._safe_iface('br-lan', 'br-lan') == 'br-lan')

    # ⚠️ 上面只测了 _safe_iface 这个**函数**。但变异脚本 M9 改的是
    # _apply_basic_lockdown 里的**调用点** —— 函数本身还在，只是调用点
    # 被改回「原样插值」。光测函数永远抓不住这种变异。
    #
    # 必须真的调一次兜底防火墙，看它**交给 nft 的那份规则文本**里
    # 有没有注入串。
    captured = {}

    class _FakeRes:
        returncode = 0
        stdout = ''
        stderr = ''

    def _fake_run(cmd, *a, **kw):
        if isinstance(cmd, (list, tuple)) and '-f' in cmd and cmd[-1] == '-':
            captured['rules'] = kw.get('input') or ''
        return _FakeRes()

    orig_run = app.subprocess.run
    orig_exists = app._interface_exists
    app.subprocess.run = _fake_run
    app._interface_exists = lambda name: True     # 让它别在存在性检查处早退
    try:
        app._apply_basic_lockdown({
            'lan_if': 'lo" ; delete table inet fw4; #',
            'lan_allowed_ports': '22',
        })
    finally:
        app.subprocess.run = orig_run
        app._interface_exists = orig_exists

    rules = captured.get('rules', '')
    check('兜底防火墙交给 nft 的规则被捕获到了（用例前提）',
          rules != '', repr(rules[:80]))
    check('注入串没有进兜底规则',
          'delete table inet fw4' not in rules, repr(rules[:200]))
    check('注入串的引号没有进兜底规则',
          'lo" ;' not in rules, repr(rules[:200]))
    check('非法 lan_if 回落成默认接口名',
          'br-lan' in rules, repr(rules[:200]))

    # ── P2-15 / P2-29 名单元素二次注入 ─────────────────────────────
    sec('P2-15 / P2-29 名单元素读出来时再校验一次')

    lists_path = paths['NFTABLES_WEB_LISTS_PATH']
    write_json(lists_path, {
        'allowed4': ['192.168.1.10', '1.2.3.4, }; delete table inet fw4; #'],
        'allowed6': ['fd00::1', 'fd00::2'],
        'blacklist4': [],
        'blacklist6': [],
    })
    out = app.load_lists()
    check('注入串被丢弃',
          all('delete table' not in x for x in out['allowed4']),
          str(out['allowed4']))
    check('合法元素保留',
          '192.168.1.10' in out['allowed4'], str(out['allowed4']))
    check('IPv6 名单保留合法元素',
          out['allowed6'] == ['fd00::1', 'fd00::2'], str(out['allowed6']))
    check('版本放错的元素被丢弃（v4 的 set 不收 v6）',
          'fd00::1' not in out['allowed4'], str(out['allowed4']))

    # ── P2-16 校验与生成器判定一致 ────────────────────────────────
    sec('P2-16 规则校验与 nginx 生成器用同一份目标主机判定')

    check('_valid_upstream_host 接受 IPv4',
          app._valid_upstream_host('192.168.1.10') is True)
    check('_valid_upstream_host 接受 IPv6',
          app._valid_upstream_host('fd00::1') is True)
    check('_valid_upstream_host 接受接口名',
          app._valid_upstream_host('br-lan') is True)
    check('_valid_upstream_host 拒绝带空格的怪串',
          app._valid_upstream_host('evil host') is False)

    # 生成器对不合法的目标主机不再静默丢弃
    src = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
    gs = src[src.index('def _gateway_services'):]
    gs = gs[:gs.index('\ndef ')]
    check('生成器与校验用的是同一个判定函数',
          '_valid_upstream_host(host)' in gs and '_valid_upstream_host(' in src,
          '两边判定不一致')
    check('生成器丢弃规则时会留日志',
          '[WARN]' in gs and '已从网关配置中剔除' in gs,
          '静默丢弃没有日志')

    # ⚠️ 上面两条是**读源码**做的一致性检查，能守住「两边用同一个函数」，
    # 但守不住「校验侧**根本不调用**那个函数」。
    # 变异脚本 M12 改的正是后者 —— 把 _validate_rp_service 里的
    # _valid_upstream_host 检查整段删掉。
    # 所以这里必须**真的调一次校验**，看它到底拒不拒绝非法目标主机。
    #
    # 更关键的一条：**校验侧放行的目标，生成器必须也保留**。
    # P2-16 的原话是「规则校验接受生成器会静默丢弃的目标主机 →
    # API 报告成功但规则没生效」。这条性质不能靠读源码保证，
    # 只能靠**同一个目标，两边各跑一遍，比结果**。
    #
    # ⚠️ 注意方向是**单向蕴含**，不是双向相等：
    #   校验放行 + 生成器丢弃 = 有害（API 报成功，规则没生效）
    #   校验拒绝 + 生成器保留 = 无害（配置根本存不进去，生成器看不到）
    # 断言成双向相等会把「校验更严」这种**安全方向**的差异也判成失败。
    def _accepted_and_generated(target_address, name='probe'):
        rule = {'enabled': True, 'name': name,
                'target_address': target_address,
                'path_prefix': '/' + name}
        _c, e = app._validate_rp_service(rule)
        accepted = (e is None)
        svc = app._gateway_services({'reverse_proxy': {'rules': [rule]}})
        generated = len(svc) == 1
        return accepted, generated, e

    for tgt in ('192.168.1.10:8080',     # IPv4
                'nas.example.com:8080'):  # 域名
        acc, gen, e = _accepted_and_generated(tgt)
        check(f'校验放行 ⇒ 生成器也保留（{tgt}）',
              (not acc) or gen,
              f'校验放行={acc} 生成器保留={gen} err={e!r}')

    # 校验侧必须真的调用**同一个**判定函数（不调用 = 两边迟早分叉）
    spy_calls = []
    _orig_vuh = app._valid_upstream_host

    def _spy(host):
        spy_calls.append(host)
        return _orig_vuh(host)

    app._valid_upstream_host = _spy
    try:
        app._validate_rp_service({
            'name': 'spy-target',
            'target_address': '192.168.1.10:8080',
            'path_prefix': '/spy',
        })
    finally:
        app._valid_upstream_host = _orig_vuh
    check('规则校验调用的是与生成器同一份目标主机判定',
          spy_calls == ['192.168.1.10'], str(spy_calls))

    # 这道检查必须**排在 _sanitize_target_address 前面**，否则它是一段
    # 永远轮不到的死代码：那时含空格的怪目标会先被「无效域名格式」拦下，
    # 用户看到的文案既不准（「192.168.1.10:99999」也说成域名格式不对），
    # 也证明这道检查白写了。
    _c2, e2 = app._validate_rp_service({
        'name': 'weird-target',
        'target_address': 'evil host:80',
        'path_prefix': '/weird',
    })
    check('含空格的目标被「不是有效的内网 IP 或接口名」拦下（证明检查在跑）',
          e2 is not None and '不是有效的内网 IP' in str(e2),
          f'err={e2!r}')

    clean2, err2 = app._validate_rp_service({
        'name': 'ok-target',
        'target_address': '192.168.1.10:8080',
        'path_prefix': '/ok',
    })
    check('合法目标主机通过校验（这条不能被误伤）',
          err2 is None and clean2 is not None, f'err={err2!r}')

    # ── P2-19 Host 头 ─────────────────────────────────────────────
    sec('P2-19 上游收到的 Host 头不是客户端可控的原始值')

    check('_valid_upstream_host 之外的判定不影响本条；查生成器',
          True)
    # ⚠️ 作用域必须是 **_nginx_service_location** —— 那里才是「反代上游」
    # 真正收到的 Host 头。
    #
    # 之前盯的是 _generate_gateway_nginx_conf，但它里面只剩「门户页」那一行
    # Host 转发（面板自己的服务），反代上游那行在另一个函数里 ——
    # 盯着不相干的地方，等于真出问题时测试照样全绿。
    svc = src[src.index('def _nginx_service_location'):]
    svc = svc[:svc.index('\ndef ')]
    check('反代上游的 Host 头不是客户端可控的原始值',
          'proxy_set_header Host $http_host;' not in svc,
          '仍在转发客户端可控的 Host 头')
    check('反代上游的 Host 头带服务端端口（思源 origin 校验要求）',
          'proxy_set_header Host $host:$server_port;' in svc,
          '没有改用 $host:$server_port')
    check('X-Forwarded-Host 同样带端口（上游拼绝对 URL 时才指得对）',
          'proxy_set_header X-Forwarded-Host $host:$server_port;' in svc,
          'X-Forwarded-Host 丢了端口')
    # 门户页 / 认证端点转发的是面板自己的服务，不是对外站点，
    # 继续用不带端口的 $host —— 这条也要守住，别让人顺手改成 $http_host。
    gs2 = src[src.index('def _generate_gateway_nginx_conf'):]
    gs2 = gs2[:gs2.index('\ndef ')]
    check('门户页转发同样不用 $http_host',
          'proxy_set_header Host $http_host;' not in gs2,
          '仍在转发客户端可控的 Host 头')

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
