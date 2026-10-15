"""lan_subnet4 掩码丢失 —— 回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_lan_mask_loss.py

背景（.224 真机实测，2026-10-15）：

setup.sh 算 LAN 网段的老管道是

    ip -4 addr show "$LAN_IFACE" | grep inet | awk '{print $2}' \
        | cut -d/ -f1 | sed 's/\\.[0-9]*$/.0/'

在 .224 上原样跑，输出是 `192.168.100.0` —— **掩码没了**。这个值写进
config.json 之后：

  * `_safe_cidr('192.168.100.0')` → `192.168.100.0/32`
  * `_generate_gateway_nginx_conf` 于是写 `allow 192.168.100.0/32;`
  * 真实 LAN 是 192.168.100.0/24（256 个地址）
  * → 所有 public=false 的反代对整个内网**完全不可用**

而且安装、部署、保存全程零报错。这是典型的「静默失效」：功能看上去
装好了，只有真的从另一台机器访问内网服务时才发现。

同一个管道还有第二个更严重的缺陷：没有 head -1。LAN 接口挂第二个 IPv4
（VLAN / 多网段，OpenWrt 上很常见）时输出是两行，直接嵌进 JSON 就变成

    "lan_subnet4": "192.168.100.0
    10.8.0.0"

→ **整个 config.json 非法** → 启动时 load_config 判损坏、静默回退
DEFAULT_CONFIG → trusted_ip4 变成 192.168.100.2、转发规则指向
192.168.4.226，而接口照样返回 success。

第三个：broadcast4 靠 "${lan_subnet4%.*}.255" 拼，只对 /24 成立；
掩码补回来之后它还会拼成 "192.168.100.0/24.255"。

断言方式：setup.sh 那侧**不写源码正则**，而是把它的探测函数原样抽出来
用真实 `ip -4 addr show` 的输出喂进去，看它到底算出什么 —— 正则断言改个
变量名就绕过去了，喂真实输出绕不过去。
"""
import importlib.util as ilu
import ipaddress
import json as _json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
SETUP_SH = os.path.join(ROOT, 'setup', 'setup.sh')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


spec = ilu.spec_from_file_location('_nftapp_mask', os.path.join(BACKEND, 'app.py'))
app = ilu.module_from_spec(spec)
spec.loader.exec_module(app)

# .224 的真实 `ip -4 addr show br-lan` 输出（实测抓的）
REAL_IP_OUT = (
    '3: br-lan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue '
    'state UP qlen 1000\n'
    '    inet 192.168.100.224/24 brd 192.168.100.255 scope global br-lan\n'
    '       valid_lft forever preferred_lft forever\n'
)
# 多地址 LAN：第二个地址会让老管道输出两行
MULTI_IP_OUT = REAL_IP_OUT.replace(
    '       valid_lft forever preferred_lft forever\n',
    '    inet 10.8.0.1/24 brd 10.8.0.255 scope global br-lan\n'
    '       valid_lft forever preferred_lft forever\n')

# ── 老管道（原样复制，用于证明"旧代码必然失败"） ──────────────────────
def legacy_pipeline(ip_out):
    """setup.sh 修复前的那条管道。测试里保留一份，用来演示旧行为。

    原管道（逐字）：
        grep inet | awk '{print $2}' | cut -d/ -f1 | sed 's/\\.[0-9]*$/.0/'
    注意它**没有 head -1**：多个 IPv4 时输出多行，直接嵌 JSON 就非法。
    """
    lines = [l for l in ip_out.splitlines() if ' inet ' in l]
    out = []
    for l in lines:
        tok = l.split()[1]                      # awk '{print $2}'
        out.append(tok.split('/')[0].rsplit('.', 1)[0] + '.0')   # cut + sed
    return '\n'.join(out)


def legacy_broadcast(lan_subnet4_no_mask):
    return f'{lan_subnet4_no_mask.rsplit(".", 1)[0]}.255'


# ── 新的探测函数：从 setup.sh 源码里抽出来实跑 ────────────────────────
setup_src = open(SETUP_SH, encoding='utf-8').read()
m = re.search(r'^detect_lan_ipv4\(\) \{\n(.*?)^\}', setup_src, re.S | re.M)
if not m:
    print('  ❌ setup.sh 里找不到 detect_lan_ipv4 —— 探测函数被改名或删掉了')
    sys.exit(1)

PY_BODY = re.search(r"<<'PYEOF'\n(.*?)\nPYEOF", m.group(1), re.S).group(1)
# 把 shell 函数体转成可执行的 python：去掉 python3 调用壳
PY_SRC = PY_BODY.replace("python3 - \"$1\" <<'PYEOF'", '')
PY_SRC = PY_SRC.replace('PYEOF', '')
# 不要在这里 exec：探测函数体以 sys.exit(0) 正常退出，模块级跑一遍会让
# 整个测试脚本「静默成功」退出（rc=0、零输出）。真正的执行在 run_detect()
# 的子进程里。
assert 'PYEOF' not in PY_SRC and '<<' not in PY_SRC, '提取 python 体失败'
compile(PY_SRC, '<detect_lan_ipv4>', 'exec')      # 只验语法


class _FakeProc:
    def __init__(self, stdout=''):
        self.stdout = stdout
        self.stderr = ''
        self.returncode = 0


# 探测函数体在**真 python3 子进程**里跑：先打桩 subprocess.run，再喂假输出。
# 必须在子进程里做 —— 在本进程里替换 sys.stdout / sys.modules 会污染整个
# 测试进程，导致缓冲的输出全部丢失。
_RUNNER = r'''
import subprocess as _sp
import sys

_OUT_ADDR = sys.argv[2]
_OUT_ROUTE = sys.argv[3]

class _P:
    def __init__(self, stdout=''):
        self.stdout = stdout
        self.stderr = ''
        self.returncode = 0


def _fake_run(cmd, *a, **kw):
    if isinstance(cmd, (list, tuple)):
        if '-4' in cmd and 'route' in cmd:
            return _P(_OUT_ROUTE)
        if '-4' in cmd and 'addr' in cmd:
            return _P(_OUT_ADDR)
    return _P('')

_sp.run = _fake_run
'''

_runner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '_tmp_lan_detect_runner.py')


def run_detect(ip_out, iface='br-lan', route_out=''):
    """用假 subprocess 跑真探测逻辑，返回它 print 出来的 shell 赋值。"""
    src = _RUNNER + PY_SRC
    tmp = _runner_path
    try:
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write(src)
        os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
        r = subprocess.run([sys.executable, tmp, iface, ip_out, route_out],
                           capture_output=True, text=True, timeout=20)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    if r.returncode != 0:
        raise RuntimeError(f'探测函数执行失败: {r.stderr.strip()[:300]}')
    out = {}
    for line in r.stdout.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            out[k] = v
    return out


print('=' * 74)
print('lan_subnet4 掩码丢失回归测试')
print('=' * 74)

# ── 1. 先证明老管道确实是坏的 ──────────────────────────────────────────
sec('1. 旧管道复现（这份测试存在的理由）')
legacy_val = legacy_pipeline(REAL_IP_OUT)
check('旧管道确实丢掩码（拿到裸网段）',
      legacy_val == '192.168.100.0', f'实际={legacy_val!r}')
check('旧值被 _safe_cidr 归一化成 /32（256 个地址缩成 1 个）',
      app._safe_cidr(legacy_val, '192.168.0.0/16') == '192.168.100.0/32',
      f"实际={app._safe_cidr(legacy_val, '192.168.0.0/16')}")
check('旧值让网关只放行 1 个地址，真实 LAN 是 256 个',
      ipaddress.ip_network('192.168.100.0/24').num_addresses == 256)
# ── 2. 新的 setup.sh 探测必须保留掩码 ────────────────────────────────
sec('2. setup.sh 探测保留掩码')
d = run_detect(REAL_IP_OUT)
check('lan_subnet4 带掩码',
      d.get('lan_subnet4') == '192.168.100.0/24', f"实际={d.get('lan_subnet4')!r}")
check('broadcast 按掩码算，不是拼出来的',
      d.get('lan_broadcast4') == '192.168.100.255',
      f"实际={d.get('lan_broadcast4')!r}")
check('主机地址也拿到了（router_ip4/trusted_ip4 依赖它）',
      d.get('lan_host4') == '192.168.100.224', f"实际={d.get('lan_host4')!r}")

# ── 3. 多地址 LAN：必须收敛成单值，否则整个 JSON 非法 ──────────────────
sec('3. 多地址 LAN 收敛成单值（旧代码在这里写出非法 JSON）')
legacy_multi = legacy_pipeline(MULTI_IP_OUT)
check('旧管道在多地址时产出多行（这就是 JSON 损坏的根因）',
      len(legacy_multi.splitlines()) == 2,
      f'实际={legacy_multi!r}')
try:
    _json.loads('{"lan_subnet4": "%s"}' % legacy_multi)
    old_ok = True
except ValueError:
    old_ok = False
check('旧值拼进 JSON 直接非法（→ 静默回退 DEFAULT_CONFIG）', not old_ok)
d = run_detect(MULTI_IP_OUT)
val = d.get('lan_subnet4', '')
check('新探测只取第一个地址',
      val == '192.168.100.0/24' and '\n' not in val, f'实际={val!r}')
try:
    _json.loads('{"lan_subnet4": "%s", "lan_broadcast4": "%s"}'
                % (d.get('lan_subnet4', ''), d.get('lan_broadcast4', '')))
    ok = True
except ValueError:
    ok = False
check('拼出来的 JSON 片段合法', ok)

# ── 4. 非 /24 掩码：broadcast 不能靠 "${x%.*}.255" ────────────────────
sec('4. 非 /24 掩码的 broadcast')
for cidr, want_net, want_bcast in [
    ('192.168.100.224/23', '192.168.100.0/23', '192.168.101.255'),
    ('192.168.100.224/25', '192.168.100.128/25', '192.168.100.255'),
    ('10.5.7.9/8', '10.0.0.0/8', '10.255.255.255'),
    ('172.16.9.3/12', '172.16.0.0/12', '172.31.255.255'),
]:
    out = ('    inet %s brd 0.0.0.0 scope global br-lan\n' % cidr)
    d = run_detect(out)
    check(f'{cidr} → {want_net}',
          d.get('lan_subnet4') == want_net, f"实际={d.get('lan_subnet4')!r}")
    check(f'{cidr} 广播={want_bcast}',
          d.get('lan_broadcast4') == want_bcast,
          f"实际={d.get('lan_broadcast4')!r}")
check('老拼法在 /23 上是错的（%.*.255 只对 /24 成立）',
      legacy_broadcast('192.168.100.0') != '192.168.101.255',
      f"旧拼法={legacy_broadcast('192.168.100.0')!r}")

# ── 5. 探测不到时必须安静失败，不能吐半截值 ────────────────────────────
sec('5. 探测失败路径')
d = run_detect('')
check('无地址时不输出 lan_subnet4（交给调用方兜底）',
      'lan_subnet4' not in d, f'实际={d}')
d = run_detect('    inet not-an-address/24 scope global br-lan\n')
check('非法地址时不输出（不产出半截垃圾）', 'lan_subnet4' not in d, f'实际={d}')

# ── 6. validate_config 必须挡住无掩码输入 ──────────────────────────────
sec('6. validate_config 拒绝无掩码输入')
for key, bad in [('lan_subnet4', '192.168.100.0'), ('lan_subnet6', 'fd00::1')]:
    cfg = dict(app.DEFAULT_CONFIG)
    cfg[key] = bad
    errs = [e for e in app.validate_config(cfg) if key in e]
    check(f'{key}={bad!r} 被拒绝', bool(errs), f'实际={errs}')
    if errs:
        check(f'{key} 的报错点名了「掩码」', '掩码' in errs[0], errs[0][:60])
for key, good in [('lan_subnet4', '192.168.100.0/24'), ('lan_subnet4', '192.168.100.0/28'),
                  ('lan_subnet6', 'fd00::/64')]:
    cfg = dict(app.DEFAULT_CONFIG)
    cfg[key] = good
    errs = [e for e in app.validate_config(cfg) if key in e]
    check(f'{key}={good!r} 合法值放行（含用户有意的小掩码）', not errs, f'实际={errs}')
cfg = dict(app.DEFAULT_CONFIG)
cfg['lan_subnet4'] = 'garbage'
errs = [e for e in app.validate_config(cfg) if 'lan_subnet4' in e]
check("非 IP 输入报「网段非法」而不是「缺少掩码」",
      bool(errs) and '非法' in errs[0], f'实际={errs}')

# ── 7. load_config 迁移：已部署的机器要能自愈 ──────────────────────────
sec('7. _migrate_lan_subnet 自愈已部署机器')
check('无掩码 → 补 /24',
      app._migrate_lan_subnet({'lan_subnet4': '192.168.100.0'})['lan_subnet4']
      == '192.168.100.0/24')
check('IPv6 无掩码 → 补 /64（不是 /24）',
      app._migrate_lan_subnet({'lan_subnet6': 'fd00::1'})['lan_subnet6']
      == 'fd00::1/64')
for keep in ['192.168.100.0/24', '192.168.100.0/28', '10.0.0.0/8',
             '172.16.0.0/12', '192.168.0.0/16']:
    got = app._migrate_lan_subnet({'lan_subnet4': keep})['lan_subnet4']
    check(f'已带掩码的 {keep} 原样不动（不能覆盖用户意图）',
          got == keep, f'实际={got}')
# 掩码不能被「规整」掉：/28 必须还是 /28（16 个地址），不能变成 /24（256 个）
_got28 = app._safe_cidr(
    app._migrate_lan_subnet({'lan_subnet4': '192.168.100.0/28'})['lan_subnet4'],
    '192.168.0.0/16')
check('/28 自愈后放行范围仍是 16 个地址（没被放大成 /24）',
      ipaddress.ip_network(_got28).num_addresses == 16,
      f'实际={_got28} = {ipaddress.ip_network(_got28).num_addresses} 个地址')
check('空值不动', app._migrate_lan_subnet({'lan_subnet4': ''})['lan_subnet4'] == '')
check('非 IP 不动', app._migrate_lan_subnet({'lan_subnet4': 'x'})['lan_subnet4'] == 'x')
check('缺字段不动', 'lan_subnet4' not in app._migrate_lan_subnet({}))

# ── 8. 自愈后的放行范围必须是真实 LAN ────────────────────────────────
sec('8. 自愈后的实际放行范围')
fixed = app._migrate_lan_subnet({'lan_subnet4': '192.168.100.0'})
cidr = app._safe_cidr(fixed['lan_subnet4'], '192.168.0.0/16')
net = ipaddress.ip_network(cidr)
check('放行范围 = 256 个地址（与真实 LAN 一致）',
      net.num_addresses == 256, f'实际={net.num_addresses}')
check('.55 判为内网（修复前是 False）',
      ipaddress.ip_address('192.168.100.55') in net)
check('.224 判为内网', ipaddress.ip_address('192.168.100.224') in net)
check('网段外仍然不是内网',
      ipaddress.ip_address('192.168.101.5') not in net)

# ── 9. 端到端：网关 nginx 放行指令 ──────────────────────────────────
sec('9. 端到端：网关 nginx 放行指令')


def _gw_conf(lan_subnet4):
    """跑真的 _generate_gateway_nginx_conf，返回配置文件文本。"""
    cfg = _json.loads(_json.dumps(app.DEFAULT_CONFIG))
    cfg['gateway_enabled'] = True
    cfg['lan_subnet4'] = lan_subnet4
    cfg['reverse_proxy'] = {
        'rules': [{
            'name': '内网测试', 'enabled': True, 'path_prefix': '/dsm',
            'target_address': 'http://192.168.100.9:5000',
            'public_access': False,
        }],
        'certificates': [], 'settings': {},
    }
    return app._generate_gateway_nginx_conf(cfg) or ''


try:
    broken = _gw_conf('192.168.100.0')
    check('旧配置下内网服务写的是 /32',
          'allow 192.168.100.0/32;' in broken,
          '期望看到 allow 192.168.100.0/32;')
    good = _gw_conf('192.168.100.0/24')
    check('修复后内网服务写的是 /24',
          'allow 192.168.100.0/24;' in good,
          f"实际={[l.strip() for l in good.splitlines() if 'allow ' in l][:4]}")
    check('修复后配置里不再出现 /32 放行',
          '192.168.100.0/32' not in good)
    healed = app._migrate_lan_subnet({'lan_subnet4': '192.168.100.0'})
    check('走迁移自愈后再生成，也是 /24',
          'allow 192.168.100.0/24;' in _gw_conf(healed['lan_subnet4']))
except Exception as e:                                   # noqa: BLE001
    check('生成网关配置不抛异常', False, f'{type(e).__name__}: {e}')

# ── 10. 调用点真的用了新探测（防止"函数改了但没接上"） ────────────────
# 前九节都是直接调用 detect_lan_ipv4()。但如果有人把 init_config 里的调用
# 换回老管道、函数本身却留着，第 2~5 节照样全绿 —— 必须真的把 init_config
# 里那几行抽出来跑一遍。
sec('10. init_config 的真实提取逻辑（改回老管道这里必须失败）')


def run_init_block(ip_out):
    """把 setup.sh 里 init_config 计算网段的那段真代码抽出来执行。

    只抽「探测 + 兜底」这一段，不跑整个 init_config（它会写配置文件、
    装依赖）。抽出来的代码原样执行，用假 ip 命令喂数据。
    """
    block = re.search(
        r'( *)local lan_subnet4 broadcast4 router_ip4.*?'
        r'\[ -z "\$router_ip4" \] && router_ip4="192\.168\.1\.1"',
        setup_src, re.S)
    if not block:
        raise RuntimeError('init_config 里找不到网段提取段')
    fns = []
    for name in ('detect_lan_ipv4', 'detect_lan_broadcast4', 'detect_lan_ipv4_gateway'):
        mm = re.search(rf'^{name}\(\) \{{\n(.*?)^\}}', setup_src, re.S | re.M)
        fns.append(mm.group(0))
    script = '\n'.join(fns) + '\n' + (
        # LAN_IFACE 由 init_config 在这段之前设置，抽出来时要自己给。
        'LAN_IFACE=br-lan\n'
        # 段里有 `local`（在函数内才合法），eval 出来的变量也只在函数作用域里，
        # 所以由函数自己 printf 出来，外面再用分隔符切回三元组。
        '_probe_block() {\n' + block.group(0) + '\n'
        'printf \'%s|%s|%s\' "$lan_subnet4" "$broadcast4" "$router_ip4"\n'
        '}\n_probe_block')
    # 假 ip：PATH 里必须正好叫 `ip`（shell 按命令名查找）。
    # 放独立临时目录，避免和真 ip / 仓库里的文件撞名。
    import tempfile
    bindir = tempfile.mkdtemp(prefix='nftv2_fakeip_')
    ip_stub = os.path.join(bindir, 'ip')
    with open(ip_stub, 'w', encoding='utf-8') as fh:
        fh.write('#!/bin/sh\ncat <<\'IPEOF\'\n' + ip_out + 'IPEOF\n')
    os.chmod(ip_stub, 0o755)
    tmp_sh = os.path.join(bindir, 'probe.sh')
    try:
        with open(tmp_sh, 'w', encoding='utf-8') as fh:
            fh.write(script)
        env = dict(os.environ)
        env['PATH'] = bindir + os.pathsep + env.get('PATH', '')
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        r = subprocess.run(['sh', tmp_sh], capture_output=True, text=True,
                           timeout=25, env=env)
    finally:
        import shutil
        shutil.rmtree(bindir, ignore_errors=True)
    if r.returncode != 0:
        raise RuntimeError(f'init_config 提取段执行失败: {r.stderr.strip()[:300]}')
    parts = r.stdout.strip().split('|')
    while len(parts) < 3:
        parts.append('')
    return tuple(parts)


try:
    subnet, bcast, gw = run_init_block(REAL_IP_OUT)
    check('init_config 真的算出带掩码的网段',
          subnet == '192.168.100.0/24', f'实际={subnet!r}')
    check('init_config 的 broadcast 正确',
          bcast == '192.168.100.255', f'实际={bcast!r}')
    check('init_config 的 router_ip4 / trusted_ip4 取到主机地址',
          gw == '192.168.100.224', f'实际={gw!r}')
    subnet_m, bcast_m, gw_m = run_init_block(MULTI_IP_OUT)
    check('多地址时 init_config 不产出多行（JSON 不再损坏）',
          '\n' not in subnet_m and subnet_m == '192.168.100.0/24',
          f'实际={subnet_m!r}')
    check('多地址时 broadcast 也不含换行', '\n' not in bcast_m, f'实际={bcast_m!r}')
    subnet_e, bcast_e, _ = run_init_block('')
    check('探测不到时兜底值也带掩码（不能是裸网段）',
          '/' in subnet_e, f'实际={subnet_e!r}')
except Exception as e:                                   # noqa: BLE001
    check('init_config 网段提取段可执行', False, f'{type(e).__name__}: {e}')

# ── 11. load_config 真的接上了迁移（防止"函数在但没调用"） ───────────
# 第 7 节直接调 _migrate_lan_subnet()，但如果有人把 load_config 里那行
# 删掉，第 7 节照样全绿 —— 已部署的机器就永远自愈不了。
# 这里必须真的走 load_config（临时改 CONFIG_PATH 指到 tmp 文件）。
sec('11. load_config 端到端自愈（删掉迁移调用这里必须失败）')
import tempfile as _tf

with _tf.TemporaryDirectory(prefix='nftv2_mask_') as _td:
    _cfg_path = os.path.join(_td, 'config.json')
    with open(_cfg_path, 'w', encoding='utf-8') as _fh:
        _json.dump({'lan_subnet4': '192.168.100.0', 'lan_if': 'br-lan'}, _fh)
    _orig_path = app.CONFIG_PATH
    _orig_rules = app.RULES_PATH
    app.CONFIG_PATH = _cfg_path
    # 规则文件「不存在」→ 不触发 _config_lost_after_setup 的丢失守卫
    app.RULES_PATH = os.path.join(_td, 'no-such-rules.nft')
    try:
        _loaded = app.load_config()
    finally:
        app.CONFIG_PATH = _orig_path
        app.RULES_PATH = _orig_rules

    check('load_config 读出的 lan_subnet4 已带掩码',
          _loaded.get('lan_subnet4') == '192.168.100.0/24',
          f"实际={_loaded.get('lan_subnet4')!r}（旧代码这里是 '192.168.100.0'，"
          f"随后被 _safe_cidr 归一成 /32）")
    check('自愈后网关放行范围是 256 个地址',
          ipaddress.ip_network(
              app._safe_cidr(_loaded['lan_subnet4'], '192.168.0.0/16')
          ).num_addresses == 256)
    check('用户其他字段没被迁移动过',
          _loaded.get('lan_if') == 'br-lan', f"实际={_loaded.get('lan_if')!r}")

# 带掩码的配置必须原样透传（迁移不能改写合法值）
with _tf.TemporaryDirectory(prefix='nftv2_mask2_') as _td:
    _cfg_path = os.path.join(_td, 'config.json')
    with open(_cfg_path, 'w', encoding='utf-8') as _fh:
        _json.dump({'lan_subnet4': '192.168.100.0/28'}, _fh)
    _orig_path, _orig_rules = app.CONFIG_PATH, app.RULES_PATH
    app.CONFIG_PATH = _cfg_path
    app.RULES_PATH = os.path.join(_td, 'no-such-rules.nft')
    try:
        _loaded2 = app.load_config()
    finally:
        app.CONFIG_PATH, app.RULES_PATH = _orig_path, _orig_rules
    check('合法 /28 配置透传不被改写',
          _loaded2.get('lan_subnet4') == '192.168.100.0/28',
          f"实际={_loaded2.get('lan_subnet4')!r}")

print('\n' + '=' * 74)
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    print('失败项:')
    for f in FAIL:
        print('  - ' + f)
    sys.exit(1)
print('全部通过')
