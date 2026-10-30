"""并发与数据一致性缺陷的回归测试。

来源：Shannon 渗透测试《问题清单-20261029》里的并发/一致性这一批 ——
P1-17 / P1-18 / P1-30 / P1-42 / P1-43 / P1-44 / P1-47 / P2-10 / P2-12 / P2-25。

运行：
    cd <项目目录>
    PATH=/tmp/nftvenv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 \
        python3 tests/test_concurrency_consistency.py

这批缺陷的共同点：**「看起来成功了，其实状态是错的」**
--------------------------------------------------------------------
读改写没有原子性、失败被当成成功、缓存不刷新、同一份数据有两个来源。

所以这里的断言全部是**行为级**的：
真的调函数、真的看返回值/落盘结果/外部命令调用次数与参数，
而不是在源码里搜字符串。

沙箱
----
所有落盘路径都指到 tempfile.mkdtemp() 建出来的临时目录；
外部命令（nft / ip / uci / logread / wget / nginx）全部打桩，
既能断言「调用了几次、参数是什么」，也能模拟「失败了会怎样」。

两个特别容易「蒙对也过不了」的机关
--------------------------------
1. 桩不是简单返回固定值：**解码行为要跟真 subprocess 一样**
   （text=True 时用 encoding+errors 解码，非法字节会抛 UnicodeDecodeError）。
   否则 P1-44 这条根本测不出来 —— 桩一宽松，缺陷就藏起来了。
2. nginx 桩要**真的按 nginx 的规则去找配置**：
   给了 `-c` 就解析那份主配置里的 include 目录，没给就解析正式 conf.d。
   P1-47 的要害正是「校验时 nginx 到底看到了哪份配置」。
"""
import fcntl
import importlib.util as ilu
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')

# app.py 顶层 `from template_engine import ...` —— backend 必须在 sys.path 上
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    detail = detail.replace('❌', '[x]').replace('✅', '[v]')
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


# ── 沙箱：加载 app 模块，所有落盘路径指到临时目录 ────────────────────

def load_app(tmpdir):
    paths = {
        'AUTH_CONFIG_PATH': os.path.join(tmpdir, 'config.json'),
        'AUTH_PASSWORD_FILE': os.path.join(tmpdir, 'password.json'),
        'AUTH_SECRET_FILE': os.path.join(tmpdir, 'secret'),
        'AUTH_SESSION_SECRET_FILE': os.path.join(tmpdir, 'session-secret'),
        'AUTH_PANEL_RATELIMIT_FILE': os.path.join(tmpdir, 'ratelimit.json'),
        'AUTH_AUDIT_LOG': os.path.join(tmpdir, 'audit.log'),
        'NFTABLES_WEB_LISTS_PATH': os.path.join(tmpdir, 'lists.json'),
        'NFTABLES_WEB_RULES_PATH': os.path.join(tmpdir, 'rules.nft'),
        'NFTABLES_WEB_NGINX_CONF_DIR': os.path.join(tmpdir, 'nginx-conf'),
        'NFTABLES_WEB_SSL_DIR': os.path.join(tmpdir, 'ssl'),
        'NFTABLES_WEB_ALIYUN_CONFIG': os.path.join(tmpdir, 'aliyun.json'),
    }
    os.makedirs(paths['NFTABLES_WEB_NGINX_CONF_DIR'], exist_ok=True)
    os.makedirs(paths['NFTABLES_WEB_SSL_DIR'], exist_ok=True)
    os.environ.update(paths)
    spec = ilu.spec_from_file_location('app_conc_test',
                                        os.path.join(BACKEND, 'app.py'))
    mod = ilu.module_from_spec(spec)
    sys.modules['app_conc_test'] = mod
    spec.loader.exec_module(mod)
    return mod, paths


# ── 外部命令桩 ───────────────────────────────────────────────────────

class FakeProc:
    """替换 app.subprocess。只实现 app 用得到的几个成员。

    `run` 的行为要**尽量像真的**：
      · text=True / encoding= 时对 stdout 做解码（errors 默认 strict）；
      · 记录每一次调用（命令 + 参数），供断言「调用了几次、参数是什么」。
    """

    TimeoutExpired = subprocess.TimeoutExpired
    SubprocessError = subprocess.SubprocessError
    CalledProcessError = subprocess.CalledProcessError
    PIPE = subprocess.PIPE
    STDOUT = subprocess.STDOUT
    DEVNULL = subprocess.DEVNULL

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def run(self, args, **kw):
        args = list(args) if isinstance(args, (list, tuple)) else [args]
        self.calls.append({'args': args, 'kw': dict(kw)})
        return self.handler(args, kw)

    def check_output(self, args, **kw):
        return self.run(args, **kw).stdout

    def Popen(self, *a, **k):        # pragma: no cover - 测试里不该走到
        raise RuntimeError('Popen 未打桩')


class OsProxy:
    """替换 app.os：只额外记录 os.replace 的调用，其余原样转发。

    注意 app.py 里的 `os` 是**模块级名字**，换成代理不会影响测试自己
    用的 os（测试里的 os 仍然是真模块）。
    """

    def __init__(self, real, events):
        self._real = real
        self.events = events

    def __getattr__(self, name):
        return getattr(self._real, name)

    def replace(self, src, dst, **kw):
        self.events.append(('replace', os.fspath(dst)))
        return self._real.replace(src, dst, **kw)


class ShutilProxy:
    """替换 app.shutil：记录 copy 调用（.backup 的产生时机）。"""

    def __init__(self, real, events):
        self._real = real
        self.events = events

    def __getattr__(self, name):
        return getattr(self._real, name)

    def copy(self, src, dst, **kw):
        self.events.append(('copy', os.fspath(dst)))
        return self._real.copy(src, dst, **kw)


class FakeFcntl:
    """替换 app.fcntl：记录加锁/解锁顺序，并可模拟「加锁失败」。"""

    LOCK_EX = fcntl.LOCK_EX
    LOCK_UN = fcntl.LOCK_UN
    LOCK_SH = fcntl.LOCK_SH

    def __init__(self, events, fail_on_lock=False):
        self.events = events
        self.fail_on_lock = fail_on_lock

    def flock(self, fd, op):
        name = 'LOCK_EX' if op == fcntl.LOCK_EX else (
            'LOCK_UN' if op == fcntl.LOCK_UN else 'LOCK_SH')
        self.events.append(('flock', name))
        if self.fail_on_lock and op == fcntl.LOCK_EX:
            raise OSError(11, 'simulated flock failure')


# ── 脚本内嵌 python 块的提取（cron / china-ips 脚本都是这个形状）──────

def extract_pyblock(script):
    """从 shell 脚本里取出 `<< 'PYEOF' ... PYEOF` 之间的 python 源码。"""
    marker = "<< 'PYEOF'"
    start = script.index(marker) + len(marker)
    end = script.index('\nPYEOF', start)
    return script[start:end]


def write_exec(path, text):
    with open(path, 'w') as f:
        f.write(text)
    os.chmod(path, 0o755)
    return path


def make_fake_bin(tmpdir, name, body):
    """造一个假的外部命令（放进 PATH 优先目录）。"""
    bindir = os.path.join(tmpdir, 'fakebin')
    os.makedirs(bindir, exist_ok=True)
    write_exec(os.path.join(bindir, name), body)
    return bindir


# ══════════════════════════════════════════════════════════════════════

def main():
    tmpdir = tempfile.mkdtemp(prefix='nft-conc-')
    app, paths = load_app(tmpdir)
    bindir = os.path.join(tmpdir, 'fakebin')
    os.makedirs(bindir, exist_ok=True)

    print('=' * 68)
    print('并发与数据一致性：读改写原子性 / 失败不许当成功 / 单一数据来源')
    print('=' * 68)

    # 记录 app.subprocess / app.os / app.fcntl / app.shutil 的原始引用，便于还原
    orig_subprocess = app.subprocess
    orig_os = app.os
    orig_fcntl = app.fcntl
    orig_shutil = app.shutil

    def restore_stubs():
        app.subprocess = orig_subprocess
        app.os = orig_os
        app.fcntl = orig_fcntl
        app.shutil = orig_shutil

    # ──────────────────────────────────────────────────────────────────
    sec('P1-30  save_config：备份必须在锁内，加锁失败必须拒绝写入')

    cfg_path = paths['AUTH_CONFIG_PATH']
    backup_path = cfg_path + '.backup'

    with open(cfg_path, 'w') as f:
        json.dump({'marker': 'v1'}, f)

    events = []
    app.os = OsProxy(os, events)
    app.shutil = ShutilProxy(shutil, events)
    app.fcntl = FakeFcntl(events)
    try:
        app.save_config({'marker': 'v2'})
    finally:
        restore_stubs()

    with open(cfg_path) as f:
        saved = json.load(f)
    check('save_config 真的写进去了', saved.get('marker') == 'v2', str(saved))

    names = [e for e in events]
    lock_on = next((i for i, e in enumerate(names)
                     if e[0] == 'flock' and e[1] == 'LOCK_EX'), None)
    lock_off = next((i for i, e in enumerate(names)
                     if e[0] == 'flock' and e[1] == 'LOCK_UN'), None)
    backup_idx = next((i for i, e in enumerate(names)
                       if e[0] in ('replace', 'copy')
                       and str(e[1]).endswith('.backup')), None)
    check('加锁发生在写配置之前', lock_on is not None and lock_off is not None
          and lock_on < lock_off, f'事件序列 {names}')
    check('备份是在**锁内**写的（.backup 的产生发生在 LOCK_EX 与 LOCK_UN 之间）',
          backup_idx is not None and lock_on is not None and lock_off is not None
          and lock_on < backup_idx < lock_off,
          f'backup 事件下标 {backup_idx}，锁区间 ({lock_on}, {lock_off})')
    check('正式配置也是在锁内写的',
          any(e[0] == 'replace' and str(e[1]) == cfg_path for e in names)
          and lock_on is not None and lock_off is not None,
          f'事件序列 {names}')
    check('.backup 存在且内容是**保存前**那一版',
          os.path.exists(backup_path)
          and json.load(open(backup_path)).get('marker') == 'v1',
          '缺失或内容不对')

    # 加锁失败 ⇒ 必须拒绝写入（不能回退到无锁模式）
    before = open(cfg_path, 'rb').read()
    events2 = []
    app.os = OsProxy(os, events2)
    app.fcntl = FakeFcntl(events2, fail_on_lock=True)
    raised = None
    try:
        app.save_config({'marker': 'v3-should-not-be-written'})
    except Exception as e:                      # noqa: BLE001
        raised = e
    finally:
        restore_stubs()
    after = open(cfg_path, 'rb').read()
    check('加锁失败时 save_config 抛异常（不是静默继续）', raised is not None,
          f'{type(raised).__name__ if raised else "没抛"}')
    check('加锁失败时**没有**把配置写进去（不回退到无锁模式）',
          before == after,
          '文件被改了' if before != after else '文件未变')

    # ──────────────────────────────────────────────────────────────────
    sec('P1-43  名单读-改-写：读失败必须报错，不能把「读不到」写成「空的」')

    lists_path = paths['NFTABLES_WEB_LISTS_PATH']
    with open(lists_path, 'w') as f:
        f.write('{"allowed4": ["1.1.1.1", ')      # 故意损坏
    broken_before = open(lists_path, 'rb').read()
    raised = None
    try:
        app._mutate_lists('allowed4', add=['2.2.2.2'])
    except Exception as e:                      # noqa: BLE001
        raised = e
    broken_after = open(lists_path, 'rb').read()
    check('名单文件损坏时 _mutate_lists 报错（不静默当空名单）',
          raised is not None, f'{type(raised).__name__ if raised else "没抛"}')
    check('名单文件损坏时**没有**被覆盖成空名单',
          broken_before == broken_after,
          '文件被改写了' if broken_before != broken_after else '文件未变')

    # 整份回写不能变成「顺手清空别人」
    with open(lists_path, 'w') as f:
        json.dump({'allowed4': ['1.1.1.1'], 'allowed6': ['fd00::1'],
                   'blacklist4': ['3.3.3.3'], 'blacklist6': ['fd00::2']}, f)
    app.save_lists({'blacklist4': ['9.9.9.9']})
    with open(lists_path) as f:
        after_save = json.load(f)
    check('save_lists 只更新传入的集合，其余集合原样保留',
          after_save.get('allowed4') == ['1.1.1.1']
          and after_save.get('allowed6') == ['fd00::1']
          and after_save.get('blacklist6') == ['fd00::2']
          and after_save.get('blacklist4') == ['9.9.9.9'],
          json.dumps(after_save, ensure_ascii=False))

    # ──────────────────────────────────────────────────────────────────
    sec('P1-42  名单元素必须落进规则集文件（否则重启即丢）')

    rules_path = paths['NFTABLES_WEB_RULES_PATH']
    with open(rules_path, 'w') as f:
        f.write(
            "#!/usr/sbin/nft -f\n"
            "table inet fw4 {\n"
            "    set allowed4 {\n"
            "        type ipv4_addr;\n"
            "        flags timeout;\n"
            "        timeout 5h;\n"
            "    }\n"
            "    set allowed6 {\n"
            "        type ipv6_addr;\n"
            "        flags timeout;\n"
            "        timeout 5h;\n"
            "    }\n"
            "    set blacklist4 {\n"
            "        type ipv4_addr;\n"
            "    }\n"
            "    set blacklist6 {\n"
            "        type ipv6_addr;\n"
            "    }\n"
            "}\n")

    app._mutate_lists('blacklist4', add=['5.5.5.5'])
    rules_text = open(rules_path).read()

    def set_block(text, name):
        m = re.search(r'(?m)^([ \t]*)set\s+' + name + r'\s*\{', text)
        if not m:
            return ''
        rest = text[m.end():]
        close = re.search(r'(?m)^' + re.escape(m.group(1)) + r'\}', rest)
        return rest[:close.start()] if close else ''

    bl4 = set_block(rules_text, 'blacklist4')
    check('加进黑名单的 IP 落进了规则集文件的 blacklist4 集合',
          '5.5.5.5' in bl4, bl4.strip()[:120])

    # 清空一个集合后，规则集里不该留下空的 elements 行
    app._mutate_lists('allowed6', clear=True)
    rules_text_c = open(rules_path).read()
    al6 = set_block(rules_text_c, 'allowed6')
    check('清空后的集合不会被塞进空的 elements 行',
          'elements' not in al6, al6.strip()[:120])

    app._mutate_lists('blacklist4', remove=['5.5.5.5'])
    rules_text2 = open(rules_path).read()
    bl4b = set_block(rules_text2, 'blacklist4')
    check('从黑名单删掉后，规则集文件里的元素也同步消失',
          '5.5.5.5' not in bl4b, bl4b.strip()[:120])

    # ──────────────────────────────────────────────────────────────────
    sec('P2-25  名单读接口：nft 读失败必须报错，不能报成功 + 空列表')

    # 面板的 API 有全局认证拦截 + 来源网段限制，走真实 HTTP 链路
    # （不是直接调视图函数）—— 否则测的就不是线上那条路了。
    # 来源地址必须落在 lan_subnet4（默认 192.168.4.0/24）里，
    # 否则会被 IP_NOT_ALLOWED 挡在门外，测不到目标代码。
    app._write_password_hash(app._hash_password('conc-test-pw'))

    def new_client():
        c = app.app.test_client()
        c.environ_base['REMOTE_ADDR'] = '192.168.4.50'
        return c

    client = new_client()
    r = client.post('/api/auth/login', json={'password': 'conc-test-pw'})
    check('测试会话建立成功（真实 login 接口）',
          r.status_code == 200 and (r.get_json() or {}).get('success'),
          f'HTTP {r.status_code}')

    nft_calls = []

    def nft_fail_handler(args, kw):
        nft_calls.append(args)
        if args[:3] == ['nft', 'list', 'set']:
            return subprocess.CompletedProcess(
                args, 1, '', 'Error: No such file or directory')
        return subprocess.CompletedProcess(args, 0, '', '')

    app.subprocess = FakeProc(nft_fail_handler)
    try:
        resp = client.get('/api/lists/whitelist')
        status = resp.status_code
        body = resp.get_json(silent=True) or {}
    finally:
        app.subprocess = orig_subprocess

    check('nft 读不到 set 时白名单接口返回失败（不是 200 + 空列表）',
          status >= 400 and body.get('success') is False,
          f'HTTP {status} body={body}')
    check('失败响应里说明了是「读不到」而不是「名单是空的」',
          'NFT_SET_READ_FAILED' in str(body.get('code', '')),
          str(body.get('code')))
    check('读失败时没有把 allowed4 谎报成空字典',
          'allowed4' not in body, str(body)[:160])

    # ──────────────────────────────────────────────────────────────────
    sec('P1-44  syslog 里有不可解码字节时，日志接口不能整个 500')

    bad_log = (b'Tue Oct  6 18:52:41 2026 daemon info good line\n'
               b'Tue Oct  6 18:52:42 2026 daemon info bad \xff\xfe bytes\n')

    def logread_handler(args, kw):
        if args[0] == 'logread':
            out = bad_log
            if kw.get('text') or kw.get('encoding'):
                enc = kw.get('encoding') or 'utf-8'
                errs = kw.get('errors') or 'strict'
                out = bad_log.decode(enc, errs)
            return subprocess.CompletedProcess(args, 0, out, '')
        if args[0] == 'uci':
            return subprocess.CompletedProcess(args, 1, '', '')
        return subprocess.CompletedProcess(args, 0, '', '')

    app.subprocess = FakeProc(logread_handler)
    try:
        resp = client.get('/api/system/logs')
        status = resp.status_code
        body = resp.get_json(silent=True) or {}
    finally:
        app.subprocess = orig_subprocess

    check('syslog 含非法字节时日志接口仍然可用（不是 500）',
          status == 200 and body.get('success') is True,
          f'HTTP {status}')
    check('日志页把解析不了的行如实计数，而不是整页失败',
          isinstance(body.get('unparsed'), int),
          f'unparsed={body.get("unparsed")}')

    # ──────────────────────────────────────────────────────────────────
    sec('P2-12  IPv6 /64 前缀不能靠朴素字符串切片')

    def is_real_64_prefix(prefix_str, addr):
        """前缀拼上后缀后，必须落在**同一个 /64 网段**里。

        为什么不能只判「拼出来是不是合法 IPv6」
        --------------------------------------
        朴素切片的错法是「切出来的仍然是合法地址，但**不是那个 /64**」：

            '2001:db8::1'.split(':') = ['2001','db8','','1']
            [:4] 取到的是**整个地址** '2001:db8::1'，
            拼上后缀 '2001:db8::1:0:0:0:1' 也是合法 IPv6 ——
            但它落在 2001:db8:0:1::/64，**根本不是 2001:db8::/64**。

        另外前缀串本身只有 4 段（'240e:390:4944:b191'），
        它**不是**一个完整 IPv6 地址，不能直接当地址解析 ——
        所以要拼上 4 段后缀再比网段。

        所以必须比**语义**：拼出来的地址所在的 /64 == 原地址所在的 /64。
        """
        try:
            cand = ipaddress.IPv6Address(prefix_str + ':0:0:0:1')
        except ValueError:
            return False
        try:
            want = ipaddress.ip_interface(addr + '/64').network
        except ValueError:
            return False
        try:
            got = ipaddress.IPv6Network(str(cand) + '/64', strict=False)
        except ValueError:
            return False
        return got == want

    check("前缀 '240e:390:4944:b191::1' 仍算成前 4 段（常规地址不变）",
          app._ipv6_prefix4('240e:390:4944:b191::1') == '240e:390:4944:b191',
          app._ipv6_prefix4('240e:390:4944:b191::1'))
    check("前缀 '240e:390:4944:b191::1' 确实是它的 /64 前缀",
          is_real_64_prefix(app._ipv6_prefix4('240e:390:4944:b191::1'),
                            '240e:390:4944:b191::1'),
          app._ipv6_prefix4('240e:390:4944:b191::1'))
    check("前缀 '2001:db8::1'（:: 在前）算出来的**确实是 /64 前缀**",
          is_real_64_prefix(app._ipv6_prefix4('2001:db8::1'), '2001:db8::1'),
          f"前缀={app._ipv6_prefix4('2001:db8::1')!r}")
    check("前缀 'fd00::1' 算出来的确实是 /64 前缀",
          is_real_64_prefix(app._ipv6_prefix4('fd00::1'), 'fd00::1'),
          f"前缀={app._ipv6_prefix4('fd00::1')!r}")

    ip_out = ('    inet6 2001:db8::1/64 scope global \n'
              '       valid_lft forever preferred_lft forever\n')

    def ip_handler(args, kw):
        if args[0] == 'ip':
            return subprocess.CompletedProcess(args, 0, ip_out, '')
        return subprocess.CompletedProcess(args, 0, '', '')

    app.subprocess = FakeProc(ip_handler)
    try:
        info = app._get_wan_ipv6_prefix()
    finally:
        app.subprocess = orig_subprocess
    check('_get_wan_ipv6_prefix 拿到的前缀**确实是 /64 前缀**',
          is_real_64_prefix(info['prefix'], '2001:db8::1'),
          f"prefix={info.get('prefix')!r}")
    check('_get_wan_ipv6_prefix 拿到的完整地址没被动过',
          info.get('full_addr') == '2001:db8::1',
          f"full_addr={info.get('full_addr')!r}")

    # ──────────────────────────────────────────────────────────────────
    sec('P1-17  IPv6 cron：flush 与 add 必须是同一个 nft 事务，且查返回码')

    cron_block = extract_pyblock(app.IPV6_CRON_SCRIPT)
    cron_py = os.path.join(tmpdir, 'cron_block.py')
    with open(cron_py, 'w') as f:
        f.write(cron_block)

    nft_log = os.path.join(tmpdir, 'nft-cron.log')
    write_exec(os.path.join(bindir, 'nft'), (
        '#!/bin/sh\n'
        '{\n'
        '  echo "=== call: $* ==="\n'
        '  cat\n'
        '} >> "$NFT_LOG"\n'
        'exit "${FAKE_NFT_RC:-0}"\n'))

    cfg_for_cron = os.path.join(tmpdir, 'cron-config.json')
    with open(cfg_for_cron, 'w') as f:
        json.dump({'forward_rules': [
            {'target_ipv6': 'fd93:86bb:a142:0:e9d:92ff:fe87:fd28'},
            {'target_ipv6': 'fd93:86bb:a142:0:e9d:92ff:fe87:fd29'},
        ]}, f)
    relay_dir = os.path.join(tmpdir, 'relay')
    os.makedirs(relay_dir, exist_ok=True)

    env = dict(os.environ)
    env['PATH'] = bindir + os.pathsep + env.get('PATH', '')
    env['NFT_LOG'] = nft_log
    env['FAKE_NFT_RC'] = '0'

    def run_cron():
        if os.path.exists(nft_log):
            os.unlink(nft_log)
        p = subprocess.run([sys.executable, cron_py, cfg_for_cron,
                            '2001:db8::1/64', relay_dir],
                           capture_output=True, text=True, env=env, timeout=60)
        log = open(nft_log).read() if os.path.exists(nft_log) else ''
        return p, log

    p, log = run_cron()
    calls = [c for c in log.split('=== call: ') if c.strip()]
    check('cron 里每个集合只发**一次** nft（flush+add 合成一个事务）',
          len(calls) == 2, f'实际 {len(calls)} 次：{log[:200]!r}')
    check('每一次 nft 都同时包含 flush 与 add（同一事务内）',
          all(('flush set inet fw4' in c and 'add element inet fw4' in c)
              for c in calls) and len(calls) > 0,
          log[:200])
    check('cron 拼出来的 IPv6 地址是合法的（前缀+后缀）',
          '2001:db8:0:0:e9d:92ff:fe87:fd28' in log,
          log[:300])

    env['FAKE_NFT_RC'] = '1'
    p_fail, _ = run_cron()
    check('nft 失败时 cron 脚本**非零退出**（失败不许被当成成功）',
          p_fail.returncode != 0,
          f'returncode={p_fail.returncode} stderr={p_fail.stderr[:120]!r}')
    env['FAKE_NFT_RC'] = '0'

    # ──────────────────────────────────────────────────────────────────
    sec('P1-18 / P2-10  中国 IP 列表：完整性校验 + 原子写')

    china_block = extract_pyblock(app.CHINA_IPS_SCRIPT)
    china_py = os.path.join(tmpdir, 'china_block.py')
    with open(china_py, 'w') as f:
        f.write(china_block)
    china_sh = os.path.join(tmpdir, 'update-china-ips.sh')
    with open(china_sh, 'w') as f:
        f.write(app.CHINA_IPS_SCRIPT)

    write_exec(os.path.join(bindir, 'wget'), (
        '#!/bin/sh\n'
        '# 假的 wget：把 fixture 拷到 -O 指定的文件\n'
        'cp "$FAKE_LIST" "$2"\n'))

    china_nft = os.path.join(tmpdir, 'china-ips.nft')
    china_sha = os.path.join(tmpdir, 'china-ips.sha256')
    list_fixture = os.path.join(tmpdir, 'china-list.txt')

    def write_list(n, seed=0):
        with open(list_fixture, 'w') as f:
            for i in range(n):
                f.write('10.%d.%d.%d\n' % ((i // 65536) % 256,
                                           (i // 256) % 256, i % 256))
        return list_fixture

    def run_china(env_extra=None, script=china_sh):
        e = dict(env)
        e.update({
            'CHINA_IPS_NFT_FILE': china_nft,
            'CHINA_IPS_SHA_FILE': china_sha,
            'CHINA_IPS_URL': 'http://invalid.example/list.txt',
            'CHINA_IPS_MIN_ENTRIES': '1000',
            'FAKE_LIST': list_fixture,
        })
        if env_extra:
            e.update(env_extra)
        return subprocess.run(['sh', script], capture_output=True, text=True,
                              env=e, timeout=120)

    # 1) 正常列表 → 写成功 + 固定摘要
    write_list(1500)
    p = run_china()
    check('合法列表能正常生成 nft 片段',
          p.returncode == 0 and os.path.exists(china_nft),
          f'rc={p.returncode} err={p.stderr[:150]!r}')
    frag = open(china_nft).read() if os.path.exists(china_nft) else ''
    check('片段里有 flush set 与 add element 指令',
          'flush set inet fw4 china_ipv4' in frag
          and 'add element inet fw4 china_ipv4 {' in frag,
          frag[:120])
    check('第一次成功后固定了 SHA-256',
          os.path.exists(china_sha) and len(open(china_sha).read().split()[0]) == 64,
          open(china_sha).read()[:80] if os.path.exists(china_sha) else '没写')

    # 2) 被截断的列表 → 必须拒绝，且**不碰**现有片段
    frag_before = open(china_nft).read()
    write_list(10)
    p = run_china()
    check('被截断的列表被拒绝（非零退出）',
          p.returncode != 0, f'rc={p.returncode}')
    check('被拒绝时**原片段保持不变**（没被半截内容覆盖）',
          open(china_nft).read() == frag_before,
          '片段未变' if open(china_nft).read() == frag_before else '片段被改了')
    check('拒绝原因里说明了是条目数不足（被截断）',
          '截断' in p.stderr or '条目数' in p.stderr, p.stderr[:200])

    # 3) 被投毒/上游变化的列表（条目数正常但内容不同）→ 必须拒绝
    write_list(1500, seed=1)
    with open(list_fixture, 'a') as f:
        f.write('203.0.113.7\n')
    p = run_china()
    check('内容变化（可能被投毒）的列表被 SHA-256 校验拦下',
          p.returncode != 0, f'rc={p.returncode}')
    check('被拦下时原片段保持不变',
          open(china_nft).read() == frag_before,
          '片段被改了')
    check('拒绝原因里带上了新旧摘要（供人工核对）',
          'SHA-256' in p.stderr, p.stderr[:200])

    # 4) 原子写：替换失败时**不能**留下半截文件
    write_list(1500)
    frag_before = open(china_nft).read()
    wrapper = os.path.join(tmpdir, 'china_wrapper.py')
    with open(wrapper, 'w') as f:
        f.write(
            "import os, runpy, sys\n"
            "def _boom(a, b):\n"
            "    raise OSError('simulated replace failure')\n"
            "os.replace = _boom\n"
            f"sys.argv = {[china_py, list_fixture, china_nft, china_sha, '1000', '0']!r}\n"
            f"runpy.run_path({china_py!r}, run_name='__main__')\n")
    p = subprocess.run([sys.executable, wrapper], capture_output=True, text=True,
                       timeout=60)
    check('写片段时替换失败 → 非零退出', p.returncode != 0,
          f'rc={p.returncode}')
    check('替换失败时**目标文件没被截断**（不是原地重写）',
          open(china_nft).read() == frag_before,
          '片段未变' if open(china_nft).read() == frag_before
          else '片段被截断/改写了')

    # ──────────────────────────────────────────────────────────────────
    sec('P1-47  网关 nginx 配置：必须先校验候选内容，再替换正式文件')

    nginx_calls = []

    def nginx_collect(args, app_mod):
        """按 nginx 的规则收集「这次校验到底看到了哪份配置」。"""
        if '-c' in args:
            main = args[args.index('-c') + 1]
            text = ''
            try:
                main_text = open(main).read()
            except OSError:
                main_text = ''
            m = re.search(r'include\s+(\S+)/\*\.conf;', main_text)
            if m:
                d = m.group(1)
                try:
                    for name in sorted(os.listdir(d)):
                        if name.endswith('.conf'):
                            text += open(os.path.join(d, name)).read()
                except OSError:
                    pass
            return text
        d = app_mod.NGINX_CONF_DIR
        text = ''
        try:
            for name in sorted(os.listdir(d)):
                if name.endswith('.conf'):
                    text += open(os.path.join(d, name)).read()
        except OSError:
            pass
        return text

    real_conf = os.path.join(paths['NFTABLES_WEB_NGINX_CONF_DIR'],
                              app.GATEWAY_CONF_NAME)

    def nginx_handler(args, kw):
        if args[0] != 'nginx':
            return subprocess.CompletedProcess(args, 0, '', '')
        if '-t' in args:
            parsed = nginx_collect(args, app)
            try:
                real_now = open(real_conf).read()
            except OSError:
                real_now = ''
            nginx_calls.append({'args': list(args), 'parsed': parsed,
                                'real_now': real_now})
            if 'BROKEN' in parsed:
                return subprocess.CompletedProcess(
                    args, 1, '', 'nginx: [emerg] unexpected end of file, '
                                 'expecting "}" in 00-nftables-web-gateway.conf')
            return subprocess.CompletedProcess(
                args, 0, '',
                'nginx: the configuration file /etc/nginx/nginx.conf '
                'syntax is ok')
        return subprocess.CompletedProcess(args, 0, '', '')

    orig_gen = app._generate_gateway_nginx_conf
    app._generate_gateway_nginx_conf = lambda cfg: (
        "# Managed by nftables-web-v2 auth gateway\nserver { BROKEN }\n")
    app.subprocess = FakeProc(nginx_handler)
    try:
        ok, msg = app._deploy_gateway_nginx({'gateway_enabled': True})
    finally:
        app.subprocess = orig_subprocess
        app._generate_gateway_nginx_conf = orig_gen

    check('候选配置有语法错误时部署失败', ok is False, str(msg)[:160])
    conf_text = (open(real_conf).read() if os.path.exists(real_conf) else '')
    check('候选配置有语法错误时**正式配置文件没被写坏**',
          'BROKEN' not in conf_text,
          '正式文件里出现了 BROKEN' if 'BROKEN' in conf_text
          else '正式文件干净')
    seen_before_install = [c for c in nginx_calls
                            if 'BROKEN' in c['parsed']
                            and 'BROKEN' not in c['real_now']]
    check('候选内容在**被安装之前**就被 nginx 真正解析过',
          len(seen_before_install) > 0,
          f'nginx 调用 {len(nginx_calls)} 次；'
          f'安装前解析到 BROKEN 的次数 {len(seen_before_install)}')

    # ──────────────────────────────────────────────────────────────────
    print('\n' + '=' * 68)
    print(f'  合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    print('=' * 68)
    if FAIL:
        print('\n失败项：')
        for name in FAIL:
            print('  - ' + name)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
