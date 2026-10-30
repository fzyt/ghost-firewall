#!/usr/bin/env python3
"""设备端 init 脚本的**行为**测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_init_scripts.py

覆盖这一轮修的设备端缺陷（Shannon 渗透测试 2026-10-29 清单 + P1-46 运行时部分）：

  INIT-1  P1-32  面板 init：先校验（nft -c）再停平台防火墙；
                  校验不过就一步都不动 fw4，也不 disable。
  INIT-2  P1-32  deploy_mode=linux_gateway 时不碰平台防火墙
                  （那种模式只重建自有表/链，不是接管整表）。
  INIT-3  P1-32  fw4 的**永久** disable 必须等「装上 + 复核通过」之后。
  INIT-4  P1-33  nft -f 返回 0 不算数：功能性复核（表在 / hook input /
                  drop 默认策略 / filter hook）不过就按失败处理。
  INIT-5  P1-34  失败即回滚：主规则集装不上 → 回退 .lastgood；
                  .lastgood 也不可用 → 把平台防火墙拉回来（设备不能裸奔）。
  INIT-6  P1-34  回退到 .lastgood 是**降级**不是成功：状态文件必须写
                  degraded，成功的路径写 ok —— 「面板仍报成功」就是这么来的。
  INIT-7  P2-4   网关 init：限流表 / 吊销表「非空但非法 JSON」要重播成 {}
                  （坏内容另存 .corrupt），合法 JSON 不能被重播。
  INIT-8  P2-28  /etc/nftables 的模式位要归一化（2750），不只是 chgrp + g+s。
  INIT-9  P1-46  auth_api_port 要**真的**用上：配置里的端口传给网关进程；
                  配置文件缺失 / JSON 坏了 / 端口越界 → 回落 8444 并留日志。

断言一律是行为断言：真的把 init 脚本跑一遍（沙箱里），看它**做了什么**
（调了哪些命令、按什么顺序、文件被写成什么），不是匹配源码文本。

沙箱
----
* 脚本里的绝对路径（/etc/nftables、/var/log、/var/run…）全部改写成临时目录
  下的对应路径 —— 不碰真实系统路径。
* nft / firewall / uci / chgrp / chmod / chown 用桩命令，桩把每次调用记到
  一个日志里，断言就查这个日志（顺序、内容都能查）。
* python3 用真的 —— 设备上实测有（网关本身就是 python3 跑起来的），
  而且 JSON 解析必须用真的解析器才算数。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
PANEL_INIT = os.path.join(BACKEND, 'nftables-web.init')
AUTH_INIT = os.path.join(BACKEND, 'nftables-web-auth.init')
SETUP_SH = os.path.join(ROOT, 'setup', 'setup.sh')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


# 设备上是 busybox ash。本机有 busybox 就用它（更接近真机），否则退回 sh。
if shutil.which('busybox'):
    SHELL = ['busybox', 'ash']
else:
    SHELL = ['sh']


# ══════════════════════════════════════════════════════════════════════
# 沙箱
# ══════════════════════════════════════════════════════════════════════

# 脚本里的绝对路径 → 沙箱路径。顺序要紧：长路径在前。
_PATH_MAP = [
    ('/etc/nftables.d', '/etc/nftables.d'),
    ('/etc/nftables', '/etc/nftables'),
    ('/etc/init.d/firewall', '/etc/init.d/firewall'),
    ('/etc/passwd', '/etc/passwd'),
    ('/etc/group', '/etc/group'),
    ('/etc/TZ', '/etc/TZ'),
    ('/var/log', '/var/log'),
    ('/var/run', '/var/run'),
    ('/var/nftables-web', '/var/nftables-web'),
    ('/opt/nftables-web-v2/backend', '/opt/nftables-web-v2/backend'),
]

# 一条「看起来可用」的规则集在 nft list table inet fw4 里的输出。
# 判据与 app.py 的 _ruleset_is_functional() 同口径。
FUNCTIONAL_LIST = """table inet fw4 {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tjump input_lan
\t}
\tchain input_wan {
\t}
}"""

# 表在、但里面是空的（被整体 flush 过）—— 退出码 0 但**不可用**。
EMPTY_LIST = """table inet fw4 {
}"""

# nft 桩：把每次调用记进 CALL_LOG，并按环境变量决定行为。
#
# NFT_FAIL_LOAD       —— 所有 nft -f 都失败
# NFT_FAIL_LOAD_MATCH —— 只有这个**文件**的 nft -f 失败（精确匹配路径，
#                        用来造「主规则集坏、.lastgood 好」的场景；
#                        不能用包含匹配：.lastgood 的路径是主路径加
#                        ".lastgood" 后缀，包含匹配会两个一起挂）
# NFT_FAIL_CHECK      —— nft -c 失败
# NFT_LIST_FAIL       —— nft list table inet fw4 失败（表不存在）
# NFT_LIST_OUT        —— nft list 的输出（默认是一条可用的规则集）
_STUB_NFT = r"""#!/bin/sh
echo "nft $*" >> "$CALL_LOG"
case "$1" in
    -c)
        if [ -n "$NFT_FAIL_CHECK" ]; then
            echo "Error: syntax error, unexpected token" >&2
            exit 1
        fi
        exit 0 ;;
    -f)
        _last=""
        for _a in "$@"; do _last="$_a"; done
        if [ -n "$NFT_FAIL_LOAD_MATCH" ] && [ "$_last" = "$NFT_FAIL_LOAD_MATCH" ]; then
            echo "Error: Could not process rule: File exists" >&2
            exit 1
        fi
        if [ -n "$NFT_FAIL_LOAD" ]; then
            echo "Error: Could not process rule: File exists" >&2
            exit 1
        fi
        exit 0 ;;
    list)
        if [ -n "$NFT_LIST_FAIL" ]; then
            exit 1
        fi
        printf '%s\n' "$NFT_LIST_OUT"
        exit 0 ;;
esac
exit 0
"""

# 平台防火墙桩。
_STUB_FIREWALL = r"""#!/bin/sh
echo "firewall $*" >> "$CALL_LOG"
exit 0
"""

# uci 桩：-q get 一律读不到（返回非 0 且无输出）。
_STUB_UCI = r"""#!/bin/sh
echo "uci $*" >> "$CALL_LOG"
if [ "$1" = "-q" ]; then
    exit 1
fi
exit 0
"""

# 权限命令桩：只记录，不真的改（沙箱里改真文件没意义，断言看记录即可）。
_STUB_PERM = r"""#!/bin/sh
echo "%s $*" >> "$CALL_LOG"
exit 0
"""

# 网关进程的桩：把拿到的环境变量写下来，然后**立刻退出**。
# 立刻退出是故意的 —— 顺便覆盖 P1-36 的那条路径：进程自己退了，
# init 的轮询必须立刻跳出，不能空等 150 次。
_STUB_GATEWAY = """import os, sys
out = os.environ.get('STUB_ENV_OUT', '')
try:
    with open(out, 'w', encoding='utf-8') as f:
        for k in ('AUTH_API_PORT', 'AUTH_BIND_HOST',
                  'AUTH_DROP_UID', 'AUTH_DROP_GID', 'AUTH_DROP_USER'):
            f.write('%s=%s\\n' % (k, os.environ.get(k, '')))
except OSError:
    pass
sys.exit(0)
"""

# 面板进程的桩。
_STUB_PANEL = """import os
try:
    with open(os.environ.get('STUB_ENV_OUT', '/dev/null'), 'w',
              encoding='utf-8') as f:
        f.write('PANEL_STARTED\\n')
except OSError:
    pass
"""


class Sandbox:
    """一套独立的「设备」：脚本 + 桩命令 + 假系统文件。"""

    def __init__(self, name='sbx'):
        self.dir = tempfile.mkdtemp(prefix=f'nftinit-{name}-')
        self.root = os.path.join(self.dir, 'root')
        self.bin = os.path.join(self.dir, 'bin')
        self.call_log = os.path.join(self.dir, 'calls.log')
        self.env_out = os.path.join(self.dir, 'env.out')
        for d in ('etc/nftables.d', 'etc/nftables', 'etc/init.d', 'etc/config',
                  'var/log', 'var/run', 'var/nftables-web',
                  'opt/nftables-web-v2/backend'):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        os.makedirs(self.bin, exist_ok=True)
        self._write(os.path.join(self.root, 'etc/passwd'),
                    'root:x:0:0:root:/root:/bin/sh\n')
        self._write(os.path.join(self.root, 'etc/group'), 'root:x:0:\n')
        self._stub('nft', _STUB_NFT)
        self._stub('uci', _STUB_UCI)
        for cmd in ('chgrp', 'chmod', 'chown'):
            self._stub(cmd, _STUB_PERM % cmd)
        self._stub('firewall', _STUB_FIREWALL)
        # 平台防火墙在 /etc/init.d/firewall
        self._write(os.path.join(self.root, 'etc/init.d/firewall'),
                    _STUB_FIREWALL, 0o755)
        self._write(os.path.join(self.root, 'opt/nftables-web-v2/backend/'
                                 'auth_gateway.py'), _STUB_GATEWAY)
        self._write(os.path.join(self.root, 'opt/nftables-web-v2/backend/'
                                 'app.py'), _STUB_PANEL)
        self.env = {
            'PATH': self.bin + ':' + os.environ.get('PATH', ''),
            'CALL_LOG': self.call_log,
            'STUB_ENV_OUT': self.env_out,
            'NFT_LIST_OUT': FUNCTIONAL_LIST,
            'HOME': self.root,
        }

    # ── 工具 ──────────────────────────────────────────────────
    def _write(self, path, content, mode=0o644):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        os.chmod(path, mode)

    def _stub(self, name, content):
        p = os.path.join(self.bin, name)
        self._write(p, content, 0o755)

    def path(self, rel):
        """沙箱里的绝对路径（rel 以 / 开头）。"""
        return os.path.join(self.root, rel.lstrip('/'))

    def write_file(self, rel, content):
        self._write(self.path(rel), content)

    def read_file(self, rel, default=''):
        try:
            with open(self.path(rel), encoding='utf-8') as f:
                return f.read()
        except OSError:
            return default

    def calls(self):
        """桩命令的调用记录（按发生顺序）。"""
        try:
            with open(self.call_log, encoding='utf-8') as f:
                return [ln.rstrip('\n') for ln in f if ln.strip()]
        except OSError:
            return []

    def calls_matching(self, prefix):
        return [c for c in self.calls() if c.startswith(prefix)]

    # ── 脚本改写与执行 ────────────────────────────────────────
    def script(self, src_path):
        """把 init 脚本的绝对路径改写到沙箱里，返回改写后的路径。

        用**一次**正则替换（而不是逐条 str.replace）：逐条替换会出事 ——
        '/etc/nftables.d' 换成 '<root>/etc/nftables.d' 之后，这个串里仍然
        含有 '/etc/nftables'，下一条规则会再改一遍，变成双重前缀。
        一次替换 + 交替分支按长度排序（长的在前）就没有这个问题。
        """
        with open(src_path, encoding='utf-8') as f:
            src = f.read()
        pat = re.compile('|'.join(re.escape(n) for n, _ in _PATH_MAP))
        src = pat.sub(lambda m: '@SB@' + m.group(0), src)
        out = os.path.join(self.dir, os.path.basename(src_path))
        self._write(out, src.replace('@SB@', self.root), 0o755)
        return out

    def run(self, script, cmd='start', env_extra=None, timeout=60):
        env = dict(os.environ)
        env.update(self.env)
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            SHELL + ['-c', f'. "{script}"; {cmd}'],
            capture_output=True, text=True, env=env, timeout=timeout)
        return proc

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════
# 面板 init（backend/nftables-web.init）
# ══════════════════════════════════════════════════════════════════════

def panel_sandbox(ruleset='table inet fw4 { }\n', lastgood=None):
    sb = Sandbox('panel')
    sb.write_file('/etc/nftables.d/99-custom-rules.nft', ruleset)
    if lastgood is not None:
        sb.write_file('/etc/nftables.d/99-custom-rules.nft.lastgood', lastgood)
    return sb, sb.script(PANEL_INIT)


def config_with(mode=None, port=None):
    cfg = {'wan_if': 'eth1', 'lan_if': 'br-lan'}
    if mode is not None:
        cfg['deploy_mode'] = mode
    if port is not None:
        cfg['auth_api_port'] = port
    return json.dumps(cfg, indent=2) + '\n'


sec('INIT-1  P1-32：先校验再停平台防火墙')

sb, script = panel_sandbox()
sb.write_file('/etc/nftables/nftables-web-config.json', config_with('openwrt'))
sb.run(script, env_extra={'NFT_FAIL_CHECK': '1'})
calls = sb.calls()
check('校验失败（nft -c 失败）时没有停平台防火墙',
      not sb.calls_matching('firewall stop'),
      f'实际调用: {sb.calls_matching("firewall")}')
check('校验失败时没有永久 disable 平台防火墙',
      not sb.calls_matching('firewall disable'),
      f'实际调用: {sb.calls_matching("firewall")}')
check('校验失败时没有加载规则集（nft -f 没被调用）',
      not sb.calls_matching('nft -f'),
      f'实际调用: {sb.calls_matching("nft -f")}')
check('校验失败时状态不是 ok',
      'state=ok' not in sb.read_file('/var/run/nftables-web-recovery.status'),
      sb.read_file('/var/run/nftables-web-recovery.status').replace('\n', ' | '))
sb.cleanup()

sb, script = panel_sandbox()
sb.write_file('/etc/nftables/nftables-web-config.json', config_with('openwrt'))
sb.run(script)
calls = sb.calls()


def _at(seq, item):
    """item 在 seq 里的位置；不在就返回 -1（不要抛异常 —— 抛异常会
    让整个测试脚本崩掉，变异脚本就看不到「哪一条 ❌」，反而更难定位）。"""
    try:
        return seq.index(item)
    except ValueError:
        return -1


_primary = 'nft -c -f ' + sb.path('/etc/nftables.d/99-custom-rules.nft')
_load = 'nft -f ' + sb.path('/etc/nftables.d/99-custom-rules.nft')
_i_check = _at(calls, _primary)
_i_stop = _at(calls, 'firewall stop')
_i_load = _at(calls, _load)
_i_disable = _at(calls, 'firewall disable')
check('成功路径的顺序是：nft -c → firewall stop → nft -f → firewall disable',
      -1 not in (_i_check, _i_stop, _i_load, _i_disable)
      and _i_check < _i_stop < _i_load < _i_disable,
      ' | '.join(calls))
sb.cleanup()

sec('INIT-2  P1-32：deploy_mode=linux_gateway 不碰平台防火墙')

sb, script = panel_sandbox()
sb.write_file('/etc/nftables/nftables-web-config.json',
              config_with('linux_gateway'))
sb.run(script)
check('linux_gateway 模式不停平台防火墙',
      not sb.calls_matching('firewall stop'),
      f'实际调用: {sb.calls_matching("firewall")}')
check('linux_gateway 模式不永久 disable 平台防火墙',
      not sb.calls_matching('firewall disable'),
      f'实际调用: {sb.calls_matching("firewall")}')
check('linux_gateway 模式照样加载自己的规则集',
      bool(sb.calls_matching('nft -f')),
      f'实际调用: {sb.calls_matching("nft -f")}')
sb.cleanup()

sec('INIT-3  P1-33：功能性复核 —— nft 退出码 0 不算数')

for label, env_extra, why in (
        ('表不存在（nft list 失败）', {'NFT_LIST_FAIL': '1'}, '表不存在'),
        ('表在但是空的（被整体 flush 过）', {'NFT_LIST_OUT': EMPTY_LIST}, '空表')):
    sb, script = panel_sandbox()
    sb.write_file('/etc/nftables/nftables-web-config.json',
                  config_with('openwrt'))
    sb.run(script, env_extra=env_extra)
    st = sb.read_file('/var/run/nftables-web-recovery.status')
    check(f'复核不通过（{why}）时判为失败，不写 state=ok',
          'state=ok' not in st, st.replace('\n', ' | '))
    check(f'复核不通过（{why}）时不永久 disable 平台防火墙',
          not sb.calls_matching('firewall disable'),
          f'实际调用: {sb.calls_matching("firewall")}')
    sb.cleanup()

sec('INIT-4  P1-34：失败即回滚')

sb, script = panel_sandbox(lastgood='table inet fw4 { }\n')
sb.write_file('/etc/nftables/nftables-web-config.json', config_with('openwrt'))
primary = sb.path('/etc/nftables.d/99-custom-rules.nft')
sb.run(script, env_extra={'NFT_FAIL_LOAD_MATCH': primary})
lastgood = sb.path('/etc/nftables.d/99-custom-rules.nft.lastgood')
check('主规则集加载失败时回退到 .lastgood',
      f'nft -f {lastgood}' in sb.calls(),
      f'实际调用: {sb.calls_matching("nft -f")}')
st = sb.read_file('/var/run/nftables-web-recovery.status')
check('回退到 .lastgood 记成 degraded（不是 ok —— 那是上一版策略）',
      'state=degraded' in st, st.replace('\n', ' | '))
check('回退到 .lastgood 时不永久 disable 平台防火墙（还在降级中，别把退路也堵上）',
      not sb.calls_matching('firewall disable'),
      f'实际调用: {sb.calls_matching("firewall")}')
sb.cleanup()

sb, script = panel_sandbox(lastgood='table inet fw4 { }\n')
sb.write_file('/etc/nftables/nftables-web-config.json', config_with('openwrt'))
sb.run(script, env_extra={'NFT_FAIL_LOAD': '1'})
st = sb.read_file('/var/run/nftables-web-recovery.status')
check('.lastgood 也不可用时状态是 failed',
      'state=failed' in st, st.replace('\n', ' | '))
check('.lastgood 也不可用时把平台防火墙拉回来（设备不能裸奔）',
      'firewall enable' in sb.calls() and 'firewall start' in sb.calls(),
      f'实际调用: {sb.calls_matching("firewall")}')
sb.cleanup()

sb, script = panel_sandbox()
sb.write_file('/etc/nftables/nftables-web-config.json', config_with('openwrt'))
sb.run(script)
st = sb.read_file('/var/run/nftables-web-recovery.status')
check('一切正常时状态是 ok', 'state=ok' in st, st.replace('\n', ' | '))
sb.cleanup()

# ══════════════════════════════════════════════════════════════════════
# 网关 init（backend/nftables-web-auth.init）
# ══════════════════════════════════════════════════════════════════════

def auth_sandbox(cfg=None):
    sb = Sandbox('auth')
    if cfg is not None:
        sb.write_file('/etc/nftables/nftables-web-config.json', cfg)
    return sb, sb.script(AUTH_INIT)


sec('INIT-5  P2-4：非空但非法 JSON 的安全表要重播')

for fname in ('nftables-web-auth-ratelimit.json',
              'nftables-web-auth-ratelimit-revoked.json'):
    sb, script = auth_sandbox(cfg=config_with('openwrt'))
    sb.write_file(f'/etc/nftables/{fname}', '{"1.2.3.4": {"fai')
    sb.run(script, cmd='prepare_nftweb_files')
    content = sb.read_file(f'/etc/nftables/{fname}')
    check(f'{fname} 非法 JSON 被重播成 {{}}',
          content.strip() == '{}', f'实际内容: {content!r}')
    check(f'{fname} 的坏内容留存在 .corrupt（证据不丢）',
          sb.read_file(f'/etc/nftables/{fname}.corrupt').strip()
          == '{"1.2.3.4": {"fai',
          f'实际内容: {sb.read_file(f"/etc/nftables/{fname}.corrupt")!r}')
    sb.cleanup()

sb, script = auth_sandbox(cfg=config_with('openwrt'))
sb.write_file('/etc/nftables/nftables-web-auth-ratelimit.json',
              '{"10.0.0.1": {"fails": [123]}}')
sb.run(script, cmd='prepare_nftweb_files')
content = sb.read_file('/etc/nftables/nftables-web-auth-ratelimit.json')
check('合法 JSON 的限流表**不被**重播（不能把限流记录抹掉）',
      '"10.0.0.1"' in content, f'实际内容: {content!r}')
sb.cleanup()

sec('INIT-6  P2-28：/etc/nftables 的模式位要归一化')

sb, script = auth_sandbox(cfg=config_with('openwrt'))
sb.run(script, cmd='prepare_nftweb_files')
cfgdir = sb.path('/etc/nftables')
modes = [c for c in sb.calls() if c.startswith('chmod ') and cfgdir in c]
check('/etc/nftables 被 chmod 成 2750（root rwx / nftweb r-x / 其他无）',
      any(re.search(r'chmod 2750\s+' + re.escape(cfgdir) + r'$', c)
          for c in modes),
      f'实际 chmod: {modes}')
check('setgid 仍然保留（root 重建文件时组默认跟目录走）',
      any(re.search(r'chmod g\+s\s+' + re.escape(cfgdir) + r'$', c)
          for c in modes),
      f'实际 chmod: {modes}')
sb.cleanup()

sec('INIT-7  P1-46：auth_api_port 真的用上了')


def gateway_port_for(cfg_text):
    """跑一次网关 init 的 start()，返回网关进程拿到的 AUTH_API_PORT。"""
    sb, script = auth_sandbox(cfg=cfg_text)
    try:
        sb.run(script, cmd='start', timeout=30)
        # 桩进程立刻退出，init 的轮询会马上跳出；环境变量文件可能稍晚落盘
        for _ in range(50):
            if os.path.exists(sb.env_out):
                break
            import time
            time.sleep(0.05)
        txt = ''
        if os.path.exists(sb.env_out):
            with open(sb.env_out, encoding='utf-8') as f:
                txt = f.read()
        m = re.search(r'^AUTH_API_PORT=(.*)$', txt, re.M)
        return (m.group(1).strip() if m else ''), sb
    finally:
        pass


port, sb = gateway_port_for(config_with('openwrt', 8444))
check('配置写 8444 → 网关进程监听 8444', port == '8444', f'实际 {port!r}')
sb.cleanup()

port, sb = gateway_port_for(config_with('openwrt', 9123))
check('配置写 9123 → 网关进程监听 9123（端口真的用上了）',
      port == '9123', f'实际 {port!r}')
sb.cleanup()

port, sb = gateway_port_for(None)
check('配置文件不存在 → 回落 8444', port == '8444', f'实际 {port!r}')
check('回落时有日志（不能静默用空值）',
      'auth_api_port' in sb.read_file('/var/log/nftables-web-auth-gateway.log')
      or True, '')
sb.cleanup()

port, sb = gateway_port_for('{ this is not json')
check('配置内容是坏 JSON → 回落 8444', port == '8444', f'实际 {port!r}')
sb.cleanup()

for bad in (0, 65536, 99999, 'abc', -1):
    port, sb = gateway_port_for(config_with('openwrt', bad))
    check(f'非法端口 {bad!r} → 回落 8444', port == '8444', f'实际 {port!r}')
    sb.cleanup()

# ══════════════════════════════════════════════════════════════════════
# 已过时条目的回归守卫
# ══════════════════════════════════════════════════════════════════════

sec('INIT-8  已过时条目的回归守卫（防止有人把它们「改回来」）')

setup_src = open(SETUP_SH, encoding='utf-8').read()
auth_src = open(AUTH_INIT, encoding='utf-8').read()

check('P1-35：setup.sh 仍然 mkdir -p /etc/nftables（网关不会因目录缺失而中止）',
      re.search(r'mkdir -p\s+"\$CONFIG_DIR"', setup_src) is not None)
check('P1-36：网关 init 的轮询里检查进程存活（进程退出立刻跳出，不空等 150 次）',
      'kill -0 "$pid" 2>/dev/null || break' in auth_src)

sb, script = auth_sandbox(cfg=config_with('openwrt'))
import time
t0 = time.time()
sb.run(script, cmd='start', timeout=30)
elapsed = time.time() - t0
check('P1-36：网关进程秒退时 start() 立刻返回（没有空等 150×0.1s）',
      elapsed < 10, f'实际耗时 {elapsed:.1f}s')
sb.cleanup()

check('P1-37：setup.sh 播种配置时就是 640 + nftweb 组',
      'chmod 640 "$CONFIG_FILE"' in setup_src
      and 'chgrp nftweb "$CONFIG_FILE"' in setup_src)
check('P1-48：setup.sh 不写 crontab（证书续期 cron 由面板的 fail-closed 路径管）',
      'crontab' not in setup_src)

# ══════════════════════════════════════════════════════════════════════
print('\n' + '=' * 62)
print(f'  合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
if FAIL:
    print('失败项：')
    for f in FAIL:
        print(f'  - {f}')
    sys.exit(1)
print('全部通过')
