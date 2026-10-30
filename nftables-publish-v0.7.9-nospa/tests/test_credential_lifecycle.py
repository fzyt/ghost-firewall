"""凭据的存放与生命周期 —— P1-20 / P1-23 / P1-29 / P1-40 / P1-41 / P2-13 / P2-14

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_credential_lifecycle.py

背景（2026-10-29 Shannon 问题清单里这一批的共同点）
--------------------------------------------------
这七条缺陷的根子是同一类：**凭据和配置的落盘方式不对，或者失败被静默吞掉**。

    P1-20  第三方 DNS 凭据明文躺在 640 root:nftweb 的共享配置里
           ⇒ 降权后的网关进程读得到服务商的 API token
    P1-23  出厂配置带一条示例 DNAT 规则 ⇒ 新装即生效（指向陌生网段）
    P1-29  /etc/config/network 原地 truncate 重写 ⇒ 写一半断电 = 路由器变砖
    P1-40  一张证书续期抛异常 ⇒ 剩下所有证书一起停止续期
    P1-41  DDNS 口令掩码还原不出来 ⇒ 口令被静默清空，接口还报「已保存」
    P2-13  过期 DDNS 中转文件永不失效 ⇒ 继续发布已删除的地址
    P2-14  中转文件在共享 /tmp 里、名字可预测、不防软链 ⇒ root 任意文件写

这个测试怎么验
--------------
**全部是行为级断言**：真的调函数、真的看真实文件、真的看真实权限。
没有一条是「源码里应该出现某段文字」这种文本匹配 ——
文本匹配抓不住「写完了再 chmod」和「先写后校验」这类退化。

沙箱
----
所有落盘路径都指到 tempfile.mkdtemp() 建出来的临时目录：
共享配置、凭据文件、规则集、证书、DDNS 中转文件、阿里云配置…
外部命令（uci / nft / ip / openssl / nginx）全部打桩：
  · uci 用一个**内存状态机**实现（show / get / set / delete / commit），
    这样「口令有没有被清空」「有没有执行 delete」都能直接断言；
  · nft 恒返回成功，并记录调用参数；
  · 其余命令返回空输出。

写权限的两个机关
----------------
1. **umask 设成 0**：任何「靠 umask 蒙对权限」的写法在这里会直接建出
   0666，一眼红。默认 umask 022 的话 0644 / 0600 的差别容易看漏。
2. **写探针**：包一层 builtins.open，记录「目标路径被以写模式直接打开过
   几次」。原地 truncate 重写必然命中（1 次），tmp + os.replace 必然是 0 次。
"""
import builtins
import contextlib
import importlib.util as ilu
import json
import os
import re
import subprocess
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')

# app.py 顶层 `from template_engine import ...` —— backend 必须在 sys.path 上
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    detail = str(detail).replace('❌', '[x]').replace('✅', '[v]')
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


# ── 外部命令打桩 ──────────────────────────────────────────────────────

class _Completed:
    """subprocess.CompletedProcess 的最小替身。"""

    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeUci:
    """内存里的 uci 状态机。

    state = {'ddns': {'<section>': {'__type__': 'service',
                                   '<option>': '<value>'}}}

    fail_get 里的 section，`uci get` 一律返回非零 —— 用来模拟
    「uci 查询本身失败」（锁/超时/环境异常），也就是 P1-41 里
    「取不到原值」的那种情形。
    """

    def __init__(self):
        self.state = {}
        self.calls = []
        self.fail_get = set()

    def show(self, pkg):
        out = []
        for sec_name in sorted(self.state.get(pkg, {})):
            opts = self.state[pkg][sec_name]
            out.append(f"{pkg}.{sec_name}={opts.get('__type__', '')}")
            for k in sorted(opts):
                if k == '__type__':
                    continue
                out.append(f"{pkg}.{sec_name}.{k}='{opts[k]}'")
        return '\n'.join(out)

    def run(self, argv):
        argv = list(argv)
        self.calls.append(list(argv))
        args = [a for a in argv[1:] if a != '-q']
        if not args:
            return _Completed(1, '', 'uci: no command')
        cmd = args[0]
        if cmd == 'show':
            return _Completed(0, self.show(args[1]), '')
        if cmd == 'get':
            parts = args[1].split('.')
            if len(parts) < 3:
                return _Completed(1, '', 'uci: Entry not found')
            pkg, sec_name = parts[0], parts[1]
            opt = '.'.join(parts[2:])
            if sec_name in self.fail_get:
                return _Completed(1, '', 'uci: Entry not found')
            opts = self.state.get(pkg, {}).get(sec_name)
            if opts is None or opt not in opts:
                return _Completed(1, '', 'uci: Entry not found')
            return _Completed(0, opts[opt] + '\n', '')
        if cmd == 'delete':
            pkg, sec_name = args[1].split('.', 1)
            self.state.get(pkg, {}).pop(sec_name, None)
            return _Completed(0, '', '')
        if cmd == 'set':
            arg = args[1]
            key, val = arg.split('=', 1)
            if key.count('.') == 1:
                pkg, sec_name = key.split('.', 1)
                self.state.setdefault(pkg, {})[sec_name] = {'__type__': val}
            else:
                parts = key.split('.')
                pkg, sec_name = parts[0], parts[1]
                opt = '.'.join(parts[2:])
                slot = self.state.setdefault(pkg, {}).setdefault(
                    sec_name, {'__type__': 'service'})
                slot[opt] = val
            return _Completed(0, '', '')
        if cmd == 'commit':
            return _Completed(0, '', '')
        return _Completed(0, '', '')

    def ops(self, kind):
        """返回执行过的某一类 uci 操作（'delete' / 'set' / 'get' / 'commit'）。"""
        out = []
        for call in self.calls:
            args = [a for a in call[1:] if a != '-q']
            if args and args[0] == kind:
                out.append(args[1] if len(args) > 1 else '')
        return out


def make_runner(uci=None, nft_ok=True, nft_calls=None):
    """构造假的 subprocess.run。"""
    def runner(argv, **kwargs):
        argv = list(argv)
        prog = argv[0] if argv else ''
        if prog == 'uci' and uci is not None:
            return uci.run(argv)
        if prog == 'nft':
            if nft_calls is not None:
                nft_calls.append(argv)
            return _Completed(0 if nft_ok else 1, '', '' if nft_ok else 'nft failed')
        if prog == 'ip':
            return _Completed(0, '', '')
        if prog == 'openssl':
            return _Completed(1, '', 'stub openssl')
        if prog == 'nginx':
            return _Completed(0, '', '')
        if prog == 'ls':
            return _Completed(0, 'eth0 eth1\n', '')
        return _Completed(0, '', '')
    return runner


@contextlib.contextmanager
def patched_subprocess(runner):
    """把 subprocess.run / Popen 换成假的（退出时还原）。"""
    real_run = subprocess.run
    real_popen = subprocess.Popen
    subprocess.run = runner
    subprocess.Popen = lambda *a, **kw: _Completed(0, '', '')
    try:
        yield
    finally:
        subprocess.run = real_run
        subprocess.Popen = real_popen


@contextlib.contextmanager
def write_probe(target):
    """记录「目标路径被以写模式直接打开」过几次。

    原地 truncate 重写必然命中；tmp + os.replace 必然是 0 次。
    """
    hits = []
    real_open = builtins.open

    def spy(file, mode='r', *a, **kw):
        try:
            same = isinstance(file, (str, bytes, os.PathLike)) and str(file) == target
        except Exception:
            same = False
        if same and any(c in mode for c in 'wxa+'):
            hits.append(mode)
        return real_open(file, mode, *a, **kw)

    builtins.open = spy
    try:
        yield hits
    finally:
        builtins.open = real_open


def load_app(paths):
    """加载 app 模块，所有落盘路径都指到临时目录。"""
    for k, v in paths.items():
        os.environ[k] = v
    spec = ilu.spec_from_file_location('app_credential_lifecycle',
                                       os.path.join(BACKEND, 'app.py'))
    mod = ilu.module_from_spec(spec)
    sys.modules['app_credential_lifecycle'] = mod
    spec.loader.exec_module(mod)
    # 认证在本测试里不是重点 —— 关掉全局拦截器，直接打业务接口。
    mod.app.before_request_funcs[None] = []
    return mod


def write_json(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.chmod(path, mode)
    return path


def read_json(path):
    with open(path) as f:
        return json.load(f)


def mode_of(path):
    return os.stat(path).st_mode & 0o777


# ══════════════════════════════════════════════════════════════════════
# 1. P1-20 第三方 DNS 凭据：独立 0600 文件 + 向后兼容迁移
# ══════════════════════════════════════════════════════════════════════

def test_p1_20(app, paths, tmp):
    sec('1. P1-20 第三方 DNS 凭据：拆到独立 0600 文件（向后兼容迁移）')

    cfg_path = os.path.join(tmp, 'p120-config.json')
    cred_path = os.path.join(tmp, 'p120-credentials.json')
    app.CONFIG_PATH = cfg_path
    app.DNS_CREDENTIALS_PATH = cred_path

    legacy = {
        'forward_rules': [],
        'reverse_proxy': {
            'rules': [], 'certificates': [],
            'dns_credentials': {'cf': {'CF_Token': 'cf-legacy-token'}},
        },
    }
    write_json(cfg_path, legacy)
    # 存量机器上 .backup 是共享配置的同权限副本，里面也有明文
    write_json(cfg_path + '.backup', legacy, mode=0o640)

    ok = app._migrate_dns_credentials_on_startup()
    check('启动迁移把存量凭据搬进了独立文件', ok is True, str(ok))
    check('独立凭据文件已创建', os.path.exists(cred_path))
    if os.path.exists(cred_path):
        data = read_json(cred_path)
        check('独立文件里确实是原来的凭据',
              data.get('cf', {}).get('CF_Token') == 'cf-legacy-token',
              json.dumps(data))
        check('独立凭据文件权限是 0600（共享配置是 0640，凭据必须更严）',
              mode_of(cred_path) == 0o600, oct(mode_of(cred_path)))

    shared = read_json(cfg_path)
    check('共享配置里的明文凭据已被抹掉',
          'dns_credentials' not in shared.get('reverse_proxy', {}),
          json.dumps(shared.get('reverse_proxy', {})))
    backup = read_json(cfg_path + '.backup')
    check('.backup（同权限副本）里的明文也被抹掉',
          'dns_credentials' not in backup.get('reverse_proxy', {}),
          json.dumps(backup.get('reverse_proxy', {})))

    # ── 迁移之后：凭据**只在**独立文件里，共享配置里没有 ──────────────
    # 这是迁移后的常态，必须还能读出来（否则证书续期直接失能）。
    _cfg, rp = app._get_rp_config()
    check('迁移之后凭据只在独立文件里，读取路径仍然拿得到',
          rp.get('dns_credentials', {}).get('cf', {}).get('CF_Token')
          == 'cf-legacy-token',
          json.dumps(rp.get('dns_credentials', {})))

    # ── 向后兼容：只有共享配置里有凭据时也必须读得出来 ──────────────
    os.unlink(cred_path)
    write_json(cfg_path, legacy)
    _cfg, rp = app._get_rp_config()
    check('独立文件不存在时，仍能从存量共享配置里读到凭据',
          rp.get('dns_credentials', {}).get('cf', {}).get('CF_Token')
          == 'cf-legacy-token',
          json.dumps(rp.get('dns_credentials', {})))

    # ── 保存路径：凭据进独立文件，共享配置里不出现 ──────────────────
    _cfg, rp = app._get_rp_config()
    rp.setdefault('dns_credentials', {})['cf'] = {'CF_Token': 'cf-new-token'}
    app._save_rp_config(_cfg)
    shared = read_json(cfg_path)
    check('保存后共享配置里仍然没有凭据',
          'dns_credentials' not in shared.get('reverse_proxy', {}))
    check('保存后独立文件里是新凭据',
          read_json(cred_path).get('cf', {}).get('CF_Token') == 'cf-new-token',
          json.dumps(read_json(cred_path)))

    # ── 写不进独立文件 ⇒ 必须报错，不能装作保存成功 ──────────────────
    blocked = os.path.join(tmp, 'blocked')
    with open(blocked, 'w') as f:
        f.write('not a directory')
    app.DNS_CREDENTIALS_PATH = os.path.join(blocked, 'creds.json')
    cfg2 = os.path.join(tmp, 'p120-config2.json')
    app.CONFIG_PATH = cfg2
    write_json(cfg2, legacy)
    _cfg2, rp2 = app._get_rp_config()
    rp2.setdefault('dns_credentials', {})['cf'] = {'CF_Token': 'cf-x'}
    raised = False
    try:
        app._save_rp_config(_cfg2)
    except app.DnsCredentialsStoreError:
        raised = True
    except Exception as e:  # 别的异常也算「没被当成成功」，但要说明
        raised = True
        print(f'      （抛出的是 {type(e).__name__} 而不是 DnsCredentialsStoreError）')
    check('凭据文件写不进去时会报错（而不是静默退回共享配置）', raised)
    shared2 = read_json(cfg2)
    check('写不进去时共享配置**没有被改动**（原配置保住了）',
          shared2.get('reverse_proxy', {}).get('dns_credentials', {})
          .get('cf', {}).get('CF_Token') == 'cf-legacy-token',
          json.dumps(shared2.get('reverse_proxy', {})))

    app.DNS_CREDENTIALS_PATH = cred_path


# ══════════════════════════════════════════════════════════════════════
# 2. P1-23 新装不再落盘示例 DNAT 规则
# ══════════════════════════════════════════════════════════════════════

def test_p1_23(app, paths, tmp):
    sec('2. P1-23 出厂配置里不再有示例 DNAT 规则')

    check('DEFAULT_CONFIG 的 forward_rules 是空列表',
          app.DEFAULT_CONFIG.get('forward_rules') == [],
          repr(app.DEFAULT_CONFIG.get('forward_rules')))

    # 配置文件不存在时 load_config 返回的就是 DEFAULT_CONFIG ——
    # 那正是「示例规则被落盘」的入口。
    cfg_path = os.path.join(tmp, 'p123-config.json')
    app.CONFIG_PATH = cfg_path
    for leftover in (cfg_path, cfg_path + '.backup'):
        if os.path.exists(leftover):
            os.unlink(leftover)
    cfg = app.load_config()
    check('配置文件缺失时 load_config 不会带出示例转发规则',
          cfg.get('forward_rules') == [], repr(cfg.get('forward_rules')))
    check('出厂配置里没有任何指向陌生网段的转发目标',
          '192.168.4.226' not in json.dumps(app.DEFAULT_CONFIG),
          '192.168.4.226 仍在出厂配置里')

    # 存量配置里用户自己的规则必须原样保留
    write_json(cfg_path, {'forward_rules': [
        {'tcp_ports': '8080', 'udp_ports': '', 'target_ip': '192.168.100.50'},
    ]})
    cfg = app.load_config()
    rules = cfg.get('forward_rules')
    check('存量配置里的转发规则不受影响（不会被清空）',
          isinstance(rules, list) and len(rules) == 1
          and rules[0].get('target_ip') == '192.168.100.50',
          repr(rules))


# ══════════════════════════════════════════════════════════════════════
# 3. P1-29 /etc/config/network 原子替换
# ══════════════════════════════════════════════════════════════════════

NETWORK_ORIGINAL = """config interface 'lan'
\toption device 'br-lan'
\toption proto 'static'
\toption ipaddr '192.168.100.1'
\toption netmask '255.255.255.0'

config interface 'wan'
\toption device 'eth1'
\toption proto 'dhcp'

config interface 'wan6'
\toption device 'eth1'
\toption proto 'dhcpv6'
"""


def test_p1_29(app, paths, tmp):
    sec('3. P1-29 /etc/config/network：tmp + 校验 + os.replace 原子替换')

    net_path = os.path.join(tmp, 'etc-config-network')
    with open(net_path, 'w') as f:
        f.write(NETWORK_ORIGINAL)
    os.chmod(net_path, 0o600)

    # ── 正常写入 ────────────────────────────────────────────────────
    with write_probe(net_path) as hits:
        app.update_uci_wan_config(net_path, {
            'wan_pppoe': True,
            'wan_pppoe_username': 'broadband',
            'wan_pppoe_password': 'secret-pw',
        })
    check('目标文件从未被以写模式直接打开（没有原地 truncate）',
          len(hits) == 0, f'直接写 {len(hits)} 次')
    content = open(net_path).read()
    check('写完之后内容完整（LAN 段还在）',
          "config interface 'lan'" in content and "option ipaddr '192.168.100.1'" in content)
    check('写完之后内容完整（新的 PPPoE wan 段在）',
          "option proto 'pppoe'" in content and "option username 'broadband'" in content)
    check('备份文件已生成（可回滚）', os.path.exists(net_path + '.backup'))
    if os.path.exists(net_path + '.backup'):
        check('备份文件权限与原文件一致（里面有 PPPoE 口令）',
              mode_of(net_path + '.backup') == 0o600,
              oct(mode_of(net_path + '.backup')))
        check('备份里是**旧内容**（不是新内容）',
              "option proto 'dhcp'" in open(net_path + '.backup').read())

    # ── 校验：会伤到 LAN 的内容必须被拒绝 ──────────────────────────
    ok, err = app._validate_network_config_content(
        NETWORK_ORIGINAL, "config interface 'wan'\n\toption device 'eth1'\n")
    check('丢掉 LAN 段的新内容会被拒绝', ok is False and 'LAN' in err, err)

    ok, err = app._validate_network_config_content(
        NETWORK_ORIGINAL,
        NETWORK_ORIGINAL.replace("\toption ipaddr '192.168.100.1'\n", ''))
    check('丢掉 LAN ipaddr 的新内容会被拒绝', ok is False and 'ipaddr' in err, err)

    ok, err = app._validate_network_config_content(NETWORK_ORIGINAL, '')
    check('空内容会被拒绝', ok is False, err)

    # 只少一个 wan6 段是合法的（切 PPPoE 时本来就要删它）
    without_wan6 = NETWORK_ORIGINAL.split("config interface 'wan6'")[0]
    ok, err = app._validate_network_config_content(NETWORK_ORIGINAL, without_wan6)
    check('只少一个 wan6 段是允许的', ok is True, err)

    # ── 调用点真的用了校验吗？───────────────────────────────────────
    # 把校验器换成「永远拒绝」，保存网络配置就必须**拒绝写入**、
    # 并且原文件一个字节都不动。这验的是调用点，不是校验器本身。
    real_validator = app._validate_network_config_content
    app._validate_network_config_content = lambda old, new: (False, '注入的拒绝理由')
    before = open(net_path).read()
    raised = False
    try:
        app.update_uci_wan_config(net_path, {
            'wan_pppoe': True, 'wan_pppoe_username': 'u', 'wan_pppoe_password': 'p'})
    except ValueError as e:
        raised = True
    finally:
        app._validate_network_config_content = real_validator
    check('校验不通过时拒绝写入（抛 ValueError）', raised)
    check('校验不通过时原文件一个字节都没动', open(net_path).read() == before)

    # ── 写失败时原文件必须原封不动 ──────────────────────────────────
    before = open(net_path).read()
    os.makedirs(net_path + '.tmp')          # 让 tmp 变成目录 ⇒ 写入必然失败
    raised = False
    try:
        app._atomic_write_network_config(net_path, 'GARBAGE')
    except OSError:
        raised = True
    check('写失败会抛异常（不装作成功）', raised)
    check('写失败后原文件原封不动', open(net_path).read() == before)
    os.rmdir(net_path + '.tmp')

    # ── _ensure_lan_essentials 走的是同一条原子路径 ─────────────────
    lan_path = os.path.join(tmp, 'etc-config-network-lan')
    with open(lan_path, 'w') as f:
        f.write("config interface 'lan'\n\toption device 'br-lan'\n")
    os.chmod(lan_path, 0o600)
    with write_probe(lan_path) as hits:
        app._ensure_lan_essentials(lan_path, has_pppoe=True)
    check('_ensure_lan_essentials 也没有原地 truncate 目标文件',
          len(hits) == 0, f'直接写 {len(hits)} 次')
    lan_content = open(lan_path).read()
    check('_ensure_lan_essentials 补齐了 LAN 关键字段',
          "option ipaddr '192.168.100.1'" in lan_content
          and "option proto 'static'" in lan_content, lan_content)


# ══════════════════════════════════════════════════════════════════════
# 4. P1-40 一张坏证书不能连累剩下的证书
# ══════════════════════════════════════════════════════════════════════

def test_p1_40(app, paths, tmp):
    sec('4. P1-40 证书续期：每张证书单独 try/except')

    cfg_path = os.path.join(tmp, 'p140-config.json')
    app.CONFIG_PATH = cfg_path
    certs = [
        {'id': 'cert_001', 'domain': 'bad.example.com', 'source': 'auto',
         'auto_renew': True, 'cert_path': '/nonexistent/bad.pem',
         'key_path': '/nonexistent/bad.key', 'dns_provider': 'cf',
         'renew_days': 60},
        {'id': 'cert_002', 'domain': 'ok1.example.com', 'source': 'auto',
         'auto_renew': True, 'cert_path': '/nonexistent/ok1.pem',
         'key_path': '/nonexistent/ok1.key', 'dns_provider': 'cf',
         'renew_days': 60},
        {'id': 'cert_003', 'domain': 'ok2.example.com', 'source': 'auto',
         'auto_renew': True, 'cert_path': '/nonexistent/ok2.pem',
         'key_path': '/nonexistent/ok2.key', 'dns_provider': 'cf',
         'renew_days': 60},
    ]
    write_json(cfg_path, {
        'forward_rules': [],
        'reverse_proxy': {
            'rules': [], 'certificates': certs,
            'dns_credentials': {'cf': {'CF_Token': 'cf-token'}},
        },
    })

    real_expiry = app._get_cert_expiry
    real_renew = app._acme_renew

    def fake_expiry(cert_path):
        return ('2026-12-31T00:00:00Z', 10)      # 只剩 10 天 ⇒ 需要续

    def fake_renew(domain, provider, creds, *a, **kw):
        if domain == 'bad.example.com':
            raise RuntimeError('模拟 acme.sh 崩了')
        return True, {'new_expires_at': '2027-06-01T00:00:00Z',
                      'days_remaining': 365}

    app._get_cert_expiry = fake_expiry
    app._acme_renew = fake_renew
    try:
        renewed, errors = app._renew_due_certs()
    except Exception as e:
        # 续期循环**自己**抛出来了 ⇒ 一张坏证书把整个循环带崩了。
        # 记成失败项（而不是让测试脚本崩掉），这样「变红」看得清楚。
        renewed, errors = [], [f'调用本身抛异常（{type(e).__name__}: {e}）']
    finally:
        app._get_cert_expiry = real_expiry
        app._acme_renew = real_renew

    check('一张证书抛异常不会中止其余证书的续期',
          set(renewed) == {'ok1.example.com', 'ok2.example.com'}, str(renewed))
    check('出问题的证书被记进 errors（不是静默吞掉）',
          any('bad.example.com' in e for e in errors), str(errors))
    check('errors 里说明了「其余证书继续续期」',
          any('继续续期' in e for e in errors), str(errors))


# ══════════════════════════════════════════════════════════════════════
# 5. P1-41 DDNS 口令不能被静默清空
# ══════════════════════════════════════════════════════════════════════

def _ddns_service_payload(password, name='1'):
    return {
        'name': name,
        'enabled': True,
        'service_name': 'cloudflare.com-v4',
        'sub_domain': '@',
        'main_domain': 'example.com',
        'username': 'Bearer',
        'password': password,
        'interface': 'wan',
        'use_ipv6': False,
        'ip_source': 'network',
        'ip_network': 'wan',
        'param_enc': '',
        'param_opt': '',
        'ipv6_source': '',
        'check_interval': 10,
    }


def test_p1_41(app, paths, tmp):
    sec('5. P1-41 DDNS 口令：掩码必须还原成原值，取不到就报错')

    uci = FakeUci()
    uci.state['ddns'] = {
        'global': {'__type__': 'ddns'},
        '1': {'__type__': 'service', 'service_name': 'cloudflare.com-v4',
              'domain': '@example.com', 'username': 'Bearer',
              'password': 's3cret-token'},
    }
    client = app.app.test_client()

    # ── 正常路径：掩码还原成原值 ────────────────────────────────────
    with patched_subprocess(make_runner(uci=uci)):
        r = client.post('/api/ddns/save',
                         json={'services': [_ddns_service_payload('s3****et')]})
    body = r.get_json() or {}
    check('带掩码保存返回成功', r.status_code == 200 and body.get('success'),
          f'HTTP {r.status_code} {body.get("message", "")}')
    pwd = uci.state.get('ddns', {}).get('1', {}).get('password')
    check('口令没有被清空（仍是原值）', pwd == 's3cret-token', repr(pwd))
    check('口令也没有被存成掩码', pwd and '****' not in pwd, repr(pwd))

    # ── 取不到原值 ⇒ 必须报错，且 UCI 不能被动过 ────────────────────
    uci.fail_get = {'1'}
    uci.calls = []
    with patched_subprocess(make_runner(uci=uci)):
        r = client.post('/api/ddns/save',
                         json={'services': [_ddns_service_payload('s3****et')]})
    body = r.get_json() or {}
    check('还原不出来时接口返回 400（不是「保存成功」）',
          r.status_code == 400, f'HTTP {r.status_code}')
    check('返回体里有明确的 code',
          body.get('code') == 'DDNS_PASSWORD_UNRESOLVED', json.dumps(body))
    check('UCI 里的口令没有被清空',
          uci.state.get('ddns', {}).get('1', {}).get('password') == 's3cret-token',
          repr(uci.state.get('ddns', {}).get('1', {}).get('password')))
    check('没有执行任何 delete（旧的 service 块没被拆掉）',
          not uci.ops('delete'), str(uci.ops('delete')))
    uci.fail_get = set()

    # ── 阿里云：掩码不能被当成口令存进去 ────────────────────────────
    aliyun_path = os.path.join(tmp, 'aliyun-p141.json')
    app.ALIYUN_DDNS_CONFIG_PATH = aliyun_path
    real_gen = app._generate_ddns_update_script
    real_cron = app._manage_ddns_cron
    app._generate_ddns_update_script = lambda: True
    app._manage_ddns_cron = lambda cfg: (True, '')
    try:
        write_json(aliyun_path, {'access_key_id': 'AK',
                                  'access_key_secret': 'real-secret',
                                  'domain': 'example.com'})
        with patched_subprocess(make_runner()):
            r = client.post('/api/aliyun-ddns/save',
                             json={'access_key_id': 'AK',
                                   'access_key_secret': 're****et'})
        body = r.get_json() or {}
        check('阿里云：掩码被还原成原 secret',
              read_json(aliyun_path).get('access_key_secret') == 'real-secret',
              json.dumps(read_json(aliyun_path)))
        check('阿里云：保存返回成功', r.status_code == 200 and body.get('success'),
              f'HTTP {r.status_code}')

        # 原值读不到 ⇒ 拒绝保存，不能把掩码存进去
        os.unlink(aliyun_path)
        with patched_subprocess(make_runner()):
            r = client.post('/api/aliyun-ddns/save',
                             json={'access_key_id': 'AK',
                                   'access_key_secret': 're****et'})
        body = r.get_json() or {}
        check('阿里云：读不到原值时拒绝保存（不落盘）',
              r.status_code == 400 and body.get('code') == 'ALIYUN_SECRET_UNRESOLVED',
              f'HTTP {r.status_code} {body.get("code")}')
        check('阿里云：掩码没有被写进配置文件',
              not os.path.exists(aliyun_path)
              or 're****et' not in open(aliyun_path).read())
    finally:
        app._generate_ddns_update_script = real_gen
        app._manage_ddns_cron = real_cron


# ══════════════════════════════════════════════════════════════════════
# 6/7. P2-13 / P2-14 DDNS 中转文件：失效 + 防软链
# ══════════════════════════════════════════════════════════════════════

def test_p2_13_14(app, paths, tmp):
    sec('6/7. P2-13 / P2-14 DDNS 中转文件：过期即失效 + 不跟随软链')

    relay_dir = paths['NFTABLES_WEB_DDNS_RELAY_DIR']
    app.DDNS_RELAY_DIR = relay_dir
    cfg_path = os.path.join(tmp, 'p2-config.json')
    app.CONFIG_PATH = cfg_path
    client = app.app.test_client()

    real_prefix = app._get_wan_ipv6_prefix
    real_nft_write = app._nft_set_write
    app._get_wan_ipv6_prefix = lambda: {
        'full_addr': '240e:1:2:3::1', 'prefix': '240e:1:2:3', 'source': 'wan'}
    app._nft_set_write = lambda args, timeout=10: True

    try:
        # ── P2-13：规则变少 ⇒ 残留的中转文件必须删掉 ────────────────
        write_json(cfg_path, {'forward_rules': [
            {'tcp_ports': '8080', 'udp_ports': '',
             'target_ip': '192.168.100.50', 'target_ipv6': '240e:1:2:3::1234'},
        ]})
        for idx in (0, 1, 2, 3):
            with open(os.path.join(relay_dir, f'ddns-ipv6-{idx}'), 'w') as f:
                f.write('240e:1:2:3::9999')
        with patched_subprocess(make_runner()):
            r = client.post('/api/network/update-ipv6', json={})
        body = r.get_json() or {}
        check('更新 IPv6 接口返回成功', r.status_code == 200 and body.get('success'),
              f'HTTP {r.status_code} {body.get("message", "")}')
        check('P2-13 规则变少后残留的中转文件被删掉了',
              not os.path.exists(os.path.join(relay_dir, 'ddns-ipv6-2'))
              and not os.path.exists(os.path.join(relay_dir, 'ddns-ipv6-3')),
              str(sorted(os.listdir(relay_dir))))
        check('P2-13 还在用的中转文件保留下来了',
              os.path.exists(os.path.join(relay_dir, 'ddns-ipv6-1')))
        if os.path.exists(os.path.join(relay_dir, 'ddns-ipv6-1')):
            # '240e:1:2:3::1234' 展开后是 240e:1:2:3:0:0:0:1234，
            # 后 4 组 = 0:0:0:1234，拼上前缀 = 240e:1:2:3:0:0:0:1234
            check('中转文件里是拼好的完整地址',
                  open(os.path.join(relay_dir, 'ddns-ipv6-1')).read()
                  == '240e:1:2:3:0:0:0:1234',
                  open(os.path.join(relay_dir, 'ddns-ipv6-1')).read())

        # ── P2-13：规则没有 IPv6 目标 ⇒ 它的中转文件也要删 ──────────
        write_json(cfg_path, {'forward_rules': [
            {'tcp_ports': '8080', 'udp_ports': '',
             'target_ip': '192.168.100.50', 'target_ipv6': ''},
        ]})
        with open(os.path.join(relay_dir, 'ddns-ipv6-1'), 'w') as f:
            f.write('240e:1:2:3::1234')
        with patched_subprocess(make_runner()):
            r = client.post('/api/network/update-ipv6', json={})
        check('P2-13 目标被清空后，对应的中转文件被删掉了',
              not os.path.exists(os.path.join(relay_dir, 'ddns-ipv6-1')),
              str(sorted(os.listdir(relay_dir))))

        # ── P2-14：软链攻击 ────────────────────────────────────────
        victim = os.path.join(tmp, 'victim-file')
        with open(victim, 'w') as f:
            f.write('DO-NOT-TOUCH')
        link = os.path.join(relay_dir, 'ddns-ipv6-0')
        if os.path.exists(link) or os.path.islink(link):
            os.unlink(link)
        os.symlink(victim, link)
        ok, err = app._write_ddns_relay(0, '240e:1:2:3::1')
        check('P2-14 写中转文件成功', ok is True, err)
        check('P2-14 受害文件没有被改写（软链没被跟随）',
              open(victim).read() == 'DO-NOT-TOUCH', open(victim).read())
        check('P2-14 中转文件现在是普通文件（不是软链）',
              os.path.isfile(link) and not os.path.islink(link))
        check('P2-14 中转文件内容正确',
              open(link).read() == '240e:1:2:3::1', open(link).read())
        check('P2-14 中转文件权限是 0600', mode_of(link) == 0o600,
              oct(mode_of(link)))

        # ── cron 脚本里那段 python 也必须安全 ───────────────────────
        _test_cron_script(app, tmp, relay_dir)
    finally:
        app._get_wan_ipv6_prefix = real_prefix
        app._nft_set_write = real_nft_write


def _test_cron_script(app, tmp, relay_dir):
    """把 cron 脚本里的 python 段抠出来**真的跑一遍**。

    这是 P2-13 / P2-14 在 cron 路径上的行为级验证：
    脚本是 root 跑的，它才是中转文件的主要写入方。
    """
    m = re.search(r"<< 'PYEOF'\n(.*?)\nPYEOF\n", app.IPV6_CRON_SCRIPT, re.S)
    if not m:
        check('cron 脚本里能抠出 python 段', False, '没找到 PYEOF 段')
        return
    src = m.group(1)

    cfg_path = os.path.join(tmp, 'p2-cron-config.json')
    write_json(cfg_path, {'forward_rules': [
        {'target_ipv6': '240e:1:2:3::1234'},
        {'target_ipv6': ''},          # 这条没有目标 ⇒ 它的中转文件要删
    ]})
    cron_relay = os.path.join(tmp, 'cron-relay')
    os.makedirs(cron_relay, exist_ok=True)
    # 预置：0 号、1 号（在用）、2 号（规则没有目标）、3 号（规则已经没了）
    for idx in (0, 1, 2, 3):
        with open(os.path.join(cron_relay, f'ddns-ipv6-{idx}'), 'w') as f:
            f.write('240e:1:2:3::dead')

    # 软链攻击：0 号预先做成指向受害文件的软链
    victim = os.path.join(tmp, 'cron-victim')
    with open(victim, 'w') as f:
        f.write('CRON-DO-NOT-TOUCH')
    link = os.path.join(cron_relay, 'ddns-ipv6-0')
    if os.path.exists(link) or os.path.islink(link):
        os.unlink(link)
    os.symlink(victim, link)

    fake_sub = types.ModuleType('subprocess')
    fake_sub.run = lambda *a, **kw: _Completed(0, '', '')
    fake_sub.TimeoutExpired = subprocess.TimeoutExpired
    real_sub = sys.modules.get('subprocess')
    real_argv = sys.argv
    sys.modules['subprocess'] = fake_sub
    sys.argv = ['cron', cfg_path, '240e:1:2:3::1/64', cron_relay]
    rc = None
    try:
        exec(compile(src, 'ipv6-cron', 'exec'), {'__name__': '__main__'})
    except SystemExit as e:
        rc = e.code
    except Exception as e:
        print(f'      （cron python 段抛异常: {type(e).__name__}: {e}）')
    finally:
        sys.argv = real_argv
        if real_sub is not None:
            sys.modules['subprocess'] = real_sub

    check('cron 的 python 段跑完了（没有异常退出）', rc is not None, f'rc={rc}')
    check('cron 段：受害文件没有被改写（软链没被跟随）',
          open(victim).read() == 'CRON-DO-NOT-TOUCH', open(victim).read())
    check('cron 段：0 号中转文件是普通文件',
          os.path.isfile(link) and not os.path.islink(link))
    check('cron 段：0 号中转文件内容正确',
          os.path.exists(link) and open(link).read() == '240e:1:2:3::1',
          open(link).read() if os.path.exists(link) else '没写出来')
    check('cron 段：1 号中转文件写好了',
          os.path.exists(os.path.join(cron_relay, 'ddns-ipv6-1'))
          and open(os.path.join(cron_relay, 'ddns-ipv6-1')).read()
          == '240e:1:2:3:0:0:0:1234',
          open(os.path.join(cron_relay, 'ddns-ipv6-1')).read()
          if os.path.exists(os.path.join(cron_relay, 'ddns-ipv6-1')) else '没写出来')
    check('cron 段：没有目标的规则，其中转文件被删掉了',
          not os.path.exists(os.path.join(cron_relay, 'ddns-ipv6-2')))
    check('cron 段：规则删除后残留的 3 号中转文件被清理了',
          not os.path.exists(os.path.join(cron_relay, 'ddns-ipv6-3')))


def main():
    tmp = tempfile.mkdtemp(prefix='nft-credlife-')
    paths = {
        'AUTH_CONFIG_PATH': os.path.join(tmp, 'config.json'),
        'AUTH_PASSWORD_FILE': os.path.join(tmp, 'password.json'),
        'AUTH_SECRET_FILE': os.path.join(tmp, 'secret'),
        'AUTH_SESSION_SECRET_FILE': os.path.join(tmp, 'session-secret'),
        'AUTH_PANEL_RATELIMIT_FILE': os.path.join(tmp, 'ratelimit.json'),
        'AUTH_AUDIT_LOG': os.path.join(tmp, 'audit.log'),
        'NFTABLES_WEB_LISTS_PATH': os.path.join(tmp, 'lists.json'),
        'NFTABLES_WEB_ALIYUN_CONFIG': os.path.join(tmp, 'aliyun.json'),
        'NFTABLES_WEB_RULES_PATH': os.path.join(tmp, 'rules.nft'),
        'NFTABLES_WEB_SSL_DIR': os.path.join(tmp, 'ssl'),
        'NFTABLES_WEB_NGINX_CONF_DIR': os.path.join(tmp, 'nginx-conf'),
        'NFTABLES_WEB_DNS_CREDENTIALS_FILE': os.path.join(tmp, 'credentials.json'),
        'NFTABLES_WEB_DDNS_RELAY_DIR': os.path.join(tmp, 'relay'),
    }
    os.makedirs(paths['NFTABLES_WEB_SSL_DIR'], exist_ok=True)
    os.makedirs(paths['NFTABLES_WEB_DDNS_RELAY_DIR'], exist_ok=True)

    print('=' * 66)
    print('凭据的存放与生命周期：P1-20 / P1-23 / P1-29 / P1-40 / P1-41 / P2-13 / P2-14')
    print('=' * 66)

    # umask 设成 0：任何「靠 umask 蒙对权限」的写法会直接建出 0666，一眼红。
    old_umask = os.umask(0o000)
    try:
        app = load_app(paths)
        test_p1_20(app, paths, tmp)
        test_p1_23(app, paths, tmp)
        test_p1_29(app, paths, tmp)
        test_p1_40(app, paths, tmp)
        test_p1_41(app, paths, tmp)
        test_p2_13_14(app, paths, tmp)
    finally:
        os.umask(old_umask)

    print()
    print(f'  合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        for name in FAIL:
            print(f'    ❌ {name}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
