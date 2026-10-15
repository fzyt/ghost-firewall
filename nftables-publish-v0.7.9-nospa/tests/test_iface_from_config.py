"""接口名必须来自配置，不能写死 —— 回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_iface_from_config.py

背景（.224 真机实测，2026-10-15）：
  .224 的配置里 wan_if='pppoe-wan'，但这台机器上根本没有这个接口 ——
  uci show network 只有 loopback 和 lan，实际网卡是 lo/eth0/br-lan/eth1。
  连带两个后果：

  1. 规则模板里 26 处 `iifname $WAN_IF` 全部匹配不到任何包，整条 input_wan
     chain 一次都没执行过。之前所有「防火墙在位 = 端口全超时」的测绘结论，
     实际测到的只是 policy drop，精细规则从未跑过。

  2. `_auto_detect_network()` 里 IPv6 前缀探测写死了
     `ip -6 addr show dev pppoe-wan scope global`，同样恒空 → WAN_PREFIX6
     静默回落到 DEFAULT_CONFIG 的 240e:390:4944:b191::/64（别人家宽带的前缀），
     IPv6 地址段生成规则全错，一路无报错。

断言方式刻意用**行为断言**而不是源码正则：真的调用 _auto_detect_network()，
把它实际 exec 出去的 argv 抓下来看。正则断言改个变量名就绕过去了，
抓 argv 绕不过去 —— 本 bug 的本质就是「传下去的参数不对」。
"""
import importlib.util as ilu
import os
import subprocess
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def load_app():
    spec = ilu.spec_from_file_location('_nftapp_iface', os.path.join(BACKEND, 'app.py'))
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mod = load_app()


class _FakeProc:
    """假的 subprocess 结果"""
    def __init__(self, stdout=''):
        self.stdout = stdout
        self.stderr = ''
        self.returncode = 0


def capture_argv(mod_obj, config, answers=None):
    """真跑 _auto_detect_network(config)，抓它实际执行的所有 argv。

    answers: {接口名: ip -6 addr 的 stdout}，用来喂假地址。
    返回 (argv 列表, detected dict)。
    """
    argv_log = []
    answers = answers or {}

    def fake_run(cmd, *a, **kw):
        argv_log.append(list(cmd))
        if isinstance(cmd, (list, tuple)) and 'addr' in cmd:
            dev = cmd[cmd.index('dev') + 1] if 'dev' in cmd else ''
            return _FakeProc(answers.get(dev, ''))
        return _FakeProc('')

    orig_run = mod_obj.subprocess.run
    orig_parse = mod_obj.parse_uci_config
    mod_obj.subprocess.run = fake_run
    mod_obj.parse_uci_config = lambda *a, **kw: {}
    try:
        detected = mod_obj._auto_detect_network(config)
    finally:
        mod_obj.subprocess.run = orig_run
        mod_obj.parse_uci_config = orig_parse
    return argv_log, detected


def dev_names(argv_log):
    out = []
    for cmd in argv_log:
        if 'dev' in cmd:
            out.append(cmd[cmd.index('dev') + 1])
    return out


ULA = ('    inet6 fd12:3456:789a::1/64 scope global\n')
WANV6 = ('    inet6 240e:abcd:ef01:2345::1/64 scope global\n')


print('=' * 74)
print('接口名配置化回归测试')
print('=' * 74)

# ── 1. wan_if 生效 ────────────────────────────────────────────────────
sec('1. IPv6 WAN 前缀探测用配置里的 wan_if')
argv, det = capture_argv(
    mod, {'wan_if': 'eth1', 'lan_if': 'br-lan'},
    answers={'eth1': WANV6})
check('argv 里出现 dev eth1',
      'eth1' in dev_names(argv), f'dev 实参={dev_names(argv)}')
check('argv 里不出现 dev pppoe-wan',
      'pppoe-wan' not in dev_names(argv),
      '写死 pppoe-wan 的旧代码会在这里失败')
check('WAN_PREFIX6 拿到真实探测值',
      det.get('WAN_PREFIX6') == '240e:abcd:ef01:2345::/64',
      f"实际={det.get('WAN_PREFIX6')!r}（旧代码恒为 None，然后回落成 "
      f"DEFAULT_CONFIG 的 240e:390:4944:b191::/64）")

# ── 2. lan_if 生效 ────────────────────────────────────────────────────
sec('2. IPv6 ULA 前缀探测用配置里的 lan_if')
argv, det = capture_argv(
    mod, {'wan_if': 'pppoe-wan', 'lan_if': 'br-test0'},
    answers={'br-test0': ULA})
check('argv 里出现 dev br-test0',
      'br-test0' in dev_names(argv), f'dev 实参={dev_names(argv)}')
check('ULA_PREFIX6 拿到真实探测值',
      det.get('ULA_PREFIX6') == 'fd12:3456:789a::/64',
      f"实际={det.get('ULA_PREFIX6')!r}")

# ── 3. linux_gateway 模式：两个接口都不是 br-lan / pppoe-wan ───────────
sec('3. linux_gateway 部署模式（eth0/wan0，两个都不是默认值）')
argv, det = capture_argv(
    mod, {'wan_if': 'wan0', 'lan_if': 'eth0'},
    answers={'wan0': WANV6, 'eth0': ULA})
check('argv 里 dev 实参恰好是 [eth0, wan0]',
      dev_names(argv) == ['eth0', 'wan0'], f'实参={dev_names(argv)}')
check('WAN_PREFIX6 正确',
      det.get('WAN_PREFIX6') == '240e:abcd:ef01:2345::/64')
check('ULA_PREFIX6 正确',
      det.get('ULA_PREFIX6') == 'fd12:3456:789a::/64')

# ── 4. 配置缺失 / 非法时的回落 ─────────────────────────────────────────
sec('4. 配置缺失或非法时回落默认值（不能抛异常）')
argv, det = capture_argv(mod, None)
check('config=None 不抛异常，返回 dict', isinstance(det, dict), f'返回={type(det).__name__}')
check('config=None 回落到 br-lan / pppoe-wan',
      set(dev_names(argv)) == {'br-lan', 'pppoe-wan'}, f'实参={dev_names(argv)}')

argv, det = capture_argv(mod, {'wan_if': 'eth1; rm -rf /', 'lan_if': 'br-lan'})
check('注入型接口名被白名单挡下（不原样传给 ip）',
      'eth1; rm -rf /' not in dev_names(argv) and 'pppoe-wan' in dev_names(argv),
      f'实参={dev_names(argv)}')

argv, det = capture_argv(mod, {'wan_if': '', 'lan_if': None})
check('空值 / None 回落到默认值不炸',
      set(dev_names(argv)) == {'br-lan', 'pppoe-wan'}, f'实参={dev_names(argv)}')

argv, det = capture_argv(mod, 'not-a-dict')
check('config 传非 dict 也不炸', isinstance(det, dict), f'返回={type(det).__name__}')

# ── 5. 探测不到时不产生半吊子结果 ──────────────────────────────────────
sec('5. 接口不存在时静默不产生活跃键（让下游走 DEFAULT 而不是拿到垃圾）')
argv, det = capture_argv(mod, {'wan_if': 'eth9', 'lan_if': 'br-none'}, answers={})
check('探测不到时不返回 WAN_PREFIX6', 'WAN_PREFIX6' not in det, f'返回={det}')
check('探测不到时不返回 ULA_PREFIX6', 'ULA_PREFIX6' not in det, f'返回={det}')

# ── 6. 调用点必须把 config 传下去 ──────────────────────────────────────
# 上面五节都是直接调 _auto_detect_network(config)。如果有人把两个调用点的
# config 去掉（传成 _auto_detect_network()），前五节照样全绿 —— 必须真的走
# config_to_variables / _is_lan_client 这两条链路才抓得住。


def stub(mod_obj, answers):
    """接管 subprocess.run 与 parse_uci_config，按接口名喂 IPv6 地址。"""
    def fake_run(cmd, *a, **kw):
        if isinstance(cmd, (list, tuple)) and 'dev' in cmd:
            dev = cmd[cmd.index('dev') + 1]
            return _FakeProc(answers.get(dev, ''))
        return _FakeProc('')
    orig = (mod_obj.subprocess.run, mod_obj.parse_uci_config)
    mod_obj.subprocess.run = fake_run
    mod_obj.parse_uci_config = lambda *a, **kw: {}
    return orig


def unstub(mod_obj, orig):
    mod_obj.subprocess.run, mod_obj.parse_uci_config = orig


sec('6. config_to_variables 调用点把 config 传下去了')
cfg6 = dict(mod.DEFAULT_CONFIG)
cfg6['lan_if'] = 'br-probe0'
cfg6['wan_if'] = 'wan-probe9'
orig = stub(mod, {'br-probe0': ULA, 'wan-probe9': WANV6})
try:
    v = mod.config_to_variables(cfg6)
finally:
    unstub(mod, orig)
check('WAN_PREFIX6 用的是探测值',
      v.get('WAN_PREFIX6') == '240e:abcd:ef01:2345::/64',
      f"实际={v.get('WAN_PREFIX6')!r}；调用点不传 config 时会是 DEFAULT 的 "
      f"240e:390:4944:b191::/64")
check('ULA_PREFIX6 用的是探测值',
      v.get('ULA_PREFIX6') == 'fd12:3456:789a::/64',
      f"实际={v.get('ULA_PREFIX6')!r}；不传 config 时会是 DEFAULT 的 "
      f"fd93:86bb:a142::/60")
check('WAN_IF 变量取自配置', v.get('WAN_IF') == '"wan-probe9"',
      f"实际={v.get('WAN_IF')!r}")

sec('7. _client_is_lan 的 lan_subnet4 兜底路径')
# 注意：这一节测不到「调用点传没传 cfg」——_client_is_lan 只处理 IPv4
# （首行 ':' in client_ip 直接 False），而它唯一消费的 LAN_SUBNET4 来自
# parse_uci_config('/etc/config/network')，与 lan_if/wan_if 无关。
# 所以传不传 cfg 在这里行为完全一致，不构成可测的变异。
cfg7 = dict(mod.DEFAULT_CONFIG)
cfg7['lan_subnet4'] = ''          # 清空，逼它必须靠自动检测
orig = (mod.load_config, mod.parse_uci_config)
mod.load_config = lambda *a, **kw: cfg7
mod.parse_uci_config = lambda *a, **kw: {
    'lan_ipaddr': '192.168.100.224', 'lan_netmask': '255.255.255.0'}
try:
    in_lan = mod._client_is_lan('192.168.100.66')
    not_in = mod._client_is_lan('8.8.8.8')
    v6 = mod._client_is_lan('fd12:3456:789a::5')
finally:
    (mod.load_config, mod.parse_uci_config) = orig
check('配置里 lan_subnet4 为空时，自动检测的网段仍生效', in_lan is True)
check('网段外的 IPv4 不算内网', not_in is False)
check('IPv6 一律判非内网（首行即拒，与本主题无关但记录现状）', v6 is False)

print('\n' + '=' * 74)
print(f'通过 {len(PASS)} / 失败 {len(FAIL)}')
if FAIL:
    print('失败项:')
    for f in FAIL:
        print('  -', f)
    sys.exit(1)
print('全部通过')
