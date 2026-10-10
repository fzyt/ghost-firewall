"""代码审核缺陷修复的回归测试。

运行:  python3 tests/test_review_fixes.py

覆盖 2026-10-10 全量审核发现的 14 条缺陷 + 2 条确认项，每条都断言「修复后的
正确行为」。沙箱运行：只 import app 并打补丁，不碰真实路径、不执行 nft/nginx。
"""
import importlib
import json
import subprocess as _sp
import os
import re
import sys
import tempfile

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def fresh(cfg=True):
    """独立加载一份 app 模块，避免模块级状态互相污染"""
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    if cfg:
        app.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'cfg.json')
        app.LISTS_PATH = os.path.join(tempfile.mkdtemp(), 'lists.json')
        app.RULES_PATH = os.path.join(tempfile.mkdtemp(), 'rules.nft')
    return app


def base_cfg():
    return json.loads(json.dumps(importlib.import_module('app').DEFAULT_CONFIG))


def sec(title):
    print(f'\n=== {title} ===')


# ─────────────────────────────────────────────────────────────
sec('P0-1  反代部署：序号变量 + 异常回滚')
app = fresh()
d = tempfile.mkdtemp()
app.NGINX_CONF_DIR = d
seen = []
app._nginx_test = lambda: (True, 'ok')
app._nginx_reload = lambda: (True, 'reloaded')
app._deploy_gateway_nginx = lambda c: (True, '')
app._is_managed_conf = lambda p: True
app._write_nginx_conf_file = lambda rule, cert, settings, idx=0: (
    seen.append((rule['domain'], idx)),
    open(os.path.join(d, f"{rule['domain']}-{rule.get('listen_port',443)}.conf"), 'w').write('# m\n'))
stale = os.path.join(d, 'stale.example.com-443.conf')
open(stale, 'w').write('# managed by nftables-web-v2\n')
cfg = {'reverse_proxy': {'rules': [
    {'domain': f's{i}.example.com', 'listen_port': 443, 'enabled': True,
     'target_ip': '192.168.100.50', 'path': '/', 'ssl_cert_id': ''} for i in range(4)],
    'certificates': [], 'settings': {'access_mode': 'lan'}}}
ok, msg = app._deploy_all_rules(cfg)
check('启用规则不再触发 NameError', ok is True, f'返回 {ok}: {msg[:60]}')
check('每条规则拿到唯一递增序号', [i for _, i in seen] == [1, 2, 3, 4], str([i for _, i in seen]))
check('不再启用的 conf 被清理', not os.path.exists(stale))
check('全部启用规则都生成了 conf', len(seen) == 4)

# 异常路径必须回滚，不能把 conf.d 停在半更新
app2 = fresh()
d2 = tempfile.mkdtemp()
app2.NGINX_CONF_DIR = d2
app2._nginx_test = lambda: (True, 'ok')
app2._nginx_reload = lambda: (True, 'reloaded')
app2._deploy_gateway_nginx = lambda c: (True, '')
app2._is_managed_conf = lambda p: True


def boom(rule, cert, settings, idx=0):
    raise ValueError('模拟生成失败')


app2._write_nginx_conf_file = boom
keep = os.path.join(d2, 'keep.example.com-443.conf')
open(keep, 'w').write('# managed by nftables-web-v2\n')
cfg2 = {'reverse_proxy': {'rules': [
    {'domain': 'gone.example.com', 'listen_port': 443, 'enabled': True,
     'target_ip': '192.168.100.50', 'path': '/', 'ssl_cert_id': ''}],
    'certificates': [], 'settings': {'access_mode': 'lan'}}}
ok2, msg2 = app2._deploy_all_rules(cfg2)
check('生成异常时不抛裸 500，而是走回滚', ok2 is False and '异常' in msg2, msg2[:70])
check('回滚恢复了部署前的 conf 目录', os.path.exists(keep), f'keep 存在={os.path.exists(keep)}')

# ─────────────────────────────────────────────────────────────
sec('P0-2  旧格式 forward_rules 迁移不再是死代码')


def migrate(inp):
    a = fresh()
    with open(a.CONFIG_PATH, 'w') as f:
        json.dump(inp, f)
    return a.load_config()['forward_rules']


got = migrate({'tcp_services': '8080,9090', 'dsm_ip4': '192.168.100.50'})
check('旧配置迁移出自己的端口而不是 DEFAULT 示例',
      got == [{'tcp_ports': '8080,9090', 'udp_ports': '', 'target_ip': '192.168.100.50',
               'target_ipv6': ''}], str(got))
check('迁移结果不含 DEFAULT 的示例目标 192.168.4.226',
      all(r.get('target_ip') != '192.168.4.226' for r in got))
check('新格式 forward_rules 原样保留',
      migrate({'forward_rules': [{'tcp_ports': '8443', 'target_ip': '192.168.100.60'}]})[0]['tcp_ports'] == '8443')
check('显式空列表保持为空', migrate({'forward_rules': []}) == [])
check('两者都没有时不再凭空出现示例转发', migrate({'lan_subnet4': '10.0.0.0/24'}) == [])

# ─────────────────────────────────────────────────────────────
sec('P1-3  黑/白名单落盘并在规则重建后回填')
app = fresh()
app._mutate_lists('blacklist4', add=['203.0.113.5', '198.51.100.9'])
app._mutate_lists('allowed4', add=['192.168.100.50'])
app._mutate_lists('blacklist6', add=['2001:db8::1'])
app._mutate_lists('blacklist4', remove=['203.0.113.5'])
on_disk = json.load(open(app.LISTS_PATH))
check('增删都写进落盘文件',
      sorted(on_disk['blacklist4']) == ['198.51.100.9'] and on_disk['allowed4'] == ['192.168.100.50'],
      str(on_disk))
rules = app.build_rules(app.load_config())
check('规则重建后黑名单成员仍在',
      all(ip in rules for ip in ('198.51.100.9', '192.168.100.50', '2001:db8::1')))
seg = rules.split('set blacklist4 {')[1].split('}')[0]
check('成员写在 set 声明体内', '198.51.100.9' in seg)
# 形状必须是 `elements = { ... }`：裸 IP 一行一个塞进 set 体是 nft 语法错误。
# 这条 2026-10-10 在真机 nft -c 上实测炸过一次，单测只查字符串存在性抓不到。
check('set 成员用 elements = 声明（否则 nft 语法错误）',
      re.search(r'elements\s*=\s*\{[^}]*198\.51\.100\.9', seg) is not None, seg.strip()[:90])
for nm in ('allowed4', 'allowed6', 'blacklist4', 'blacklist6'):
    b = rules.split(f'set {nm} {{')[1].split('}')[0]
    bare = [l.strip() for l in b.split('\n')
            if l.strip() and not l.strip().startswith(('type ', 'flags', 'timeout', '}', 'elements'))
            and not l.strip().startswith('#')]
    check(f'{nm} set 体里没有裸元素行', bare == [], str(bare)[:80])

# 注入防护
data = json.load(open(app.LISTS_PATH))
data['blacklist4'] += ['delete table inet fw4; #', 'not-an-ip', '2.2.2.2']
json.dump(data, open(app.LISTS_PATH, 'w'))
rules2 = app.build_rules(app.load_config())
check('名单里的 nft 注入内容被丢弃', 'delete table' not in rules2)
check('丢弃非法元素不影响合法元素', '2.2.2.2' in rules2 and '198.51.100.9' in rules2)
data = json.load(open(app.LISTS_PATH))
data['blacklist6'] = ['10.0.0.1']
json.dump(data, open(app.LISTS_PATH, 'w'))
r3 = app.build_rules(app.load_config())
check('版本错配（IPv4 进 blacklist6）被丢弃',
      '10.0.0.1' not in r3.split('set blacklist6 {')[1].split('}')[0])
check('模板占位符全部被替换', '_ELEMENTS' not in r3)

# 损坏的名单文件不能带崩名单读取
open(app.LISTS_PATH, 'w').write('{ broken')
check('名单文件损坏时按空名单处理而不抛异常', app.load_lists()['blacklist4'] == [])

# ─────────────────────────────────────────────────────────────
sec('P1-4  配置损坏时拒绝下发规则')
app = fresh()
with open(app.CONFIG_PATH, 'w') as f:
    f.write('{ not json ')
cfg = app.load_config()
bad, err = app._config_corrupted()
check('load_config 记录了损坏状态', bad is True and bool(err), f'{bad} {err!r}')
check('损坏时不抛异常（Web UI 仍可用）', isinstance(cfg, dict))
with app.app.app_context():          # jsonify 需要 Flask 应用上下文
    resp = app._config_corrupted_response()
check('下发入口能拿到拒绝应答', resp is not None)
body = resp[0].get_json()
check('拒绝应答带明确 code 与原因',
      body.get('code') == 'CONFIG_CORRUPTED' and '已拒绝下发规则' in body.get('message', ''),
      json.dumps(body, ensure_ascii=False)[:110])
check('应答里点明了损坏副本位置', '.corrupted.' in body.get('message', ''))
app2 = fresh()
with app2.app.app_context():
    check('健康配置时不拦截', app2._config_corrupted_response() is None)

# 行为层：apply_rules 本身必须拒绝下发，不能只测辅助函数
app3 = fresh()
with open(app3.CONFIG_PATH, 'w') as f:
    f.write('{ not json ')
called = []
app3._apply_ruleset = lambda c: called.append(c) or (True, '不应走到这里')
with app3.app.test_request_context('/api/rules/apply', method='POST'):
    app3._is_authenticated = lambda: True
    resp = app3.apply_rules()
    body, status = (resp if isinstance(resp, tuple) else (resp, 200))
    body = body.get_json()
check('apply_rules 在配置损坏时不下发规则', called == [], f'_apply_ruleset 调用 {len(called)} 次')
check('apply_rules 返回失败而不是 success',
      body.get('success') is False and body.get('code') == 'CONFIG_CORRUPTED')
check('apply_rules 返回 5xx', status == 500, str(status))
app4 = fresh()
with open(app4.CONFIG_PATH, 'w') as f:
    json.dump({**base_cfg()}, f)
ok_called = []
app4._apply_ruleset = lambda c: ok_called.append(c) or (True, '已应用')
with app4.app.test_request_context('/api/rules/apply', method='POST'):
    app4._is_authenticated = lambda: True
    r4 = app4.apply_rules()
check('配置正常时 apply_rules 照常下发', len(ok_called) == 1 and r4.get_json()['success'] is True)

# ─────────────────────────────────────────────────────────────
sec('P1-5  备份失败不得删掉现有规则')
app = fresh()
open(app.RULES_PATH, 'w').write('# 旧规则\ntable inet fw4 { chain input { } }\n')


def fake_run(cmd, **kw):
    import subprocess as sp
    if cmd[:2] == ['nft', '-c']:
        return sp.CompletedProcess(cmd, 0, '', '')
    return sp.CompletedProcess(cmd, 0, '', '')


app.subprocess_run_hook = None
orig_run = app.subprocess.run
app.subprocess.run = fake_run
real_copy = app.shutil.copy


def boom_copy(src, dst, *a, **k):
    if str(dst).endswith('.lastgood'):
        raise OSError('模拟磁盘满')
    return real_copy(src, dst, *a, **k)


app.shutil.copy = boom_copy
ok, msg = app._apply_ruleset(base_cfg())
app.shutil.copy = real_copy
app.subprocess.run = orig_run
check('备份失败时中止应用而不是继续', ok is False and '备份' in msg, msg[:70])
check('中止时现有规则文件原封不动',
      open(app.RULES_PATH).read().startswith('# 旧规则'))
check('中止时不会产生半成品 lastgood', not os.path.exists(app.RULES_PATH + '.lastgood'))

# 真正的危险组合：备份失败（无回滚材料）+ nft -f 再失败。
# 旧代码会把 had_old 置 False，于是失败分支去删刚写好的 RULES_PATH，
# 而 .lastgood 从没创建过 —— 磁盘上旧规则、新规则都没有。
app_b = fresh()
old_rules = '# 旧规则\ntable inet fw4 { chain input { policy drop; } }\n'
open(app_b.RULES_PATH, 'w').write(old_rules)
app_b.subprocess.run = lambda cmd, **kw: _sp.CompletedProcess(
    cmd, 1 if cmd[:2] == ['nft', '-f'] else 0, '', '模拟 nft -f 失败')
app_b._ruleset_is_empty = lambda: True
app_b._apply_basic_lockdown = lambda *a, **k: False
app_b._ensure_ipv6_cron = lambda: None
# 不打桩 _unlink_quiet：旧代码正是在这里把刚写好的规则文件删掉，
# 打桩等于把要检测的行为屏蔽掉。
unlinked = []
app_b._unlink_quiet = lambda p: (unlinked.append(p),
                                 os.remove(p) if os.path.exists(p) else None)
real_copy_b = app_b.shutil.copy
app_b.shutil.copy = lambda src, dst, *a, **k: (
    (_ for _ in ()).throw(OSError('模拟备份失败'))
    if str(dst).endswith('.lastgood') else real_copy_b(src, dst, *a, **k))
ok_b, msg_b = app_b._apply_ruleset(base_cfg())
app_b.shutil.copy = real_copy_b
check('备份失败 + nft 失败时不会删掉规则文件',
      os.path.exists(app_b.RULES_PATH), 'RULES_PATH 已被删除')
check('备份失败 + nft 失败时没有尝试删规则文件',
      app_b.RULES_PATH not in unlinked, f'unlink 记录={unlinked}')
check('备份失败 + nft 失败时仍保留原规则内容',
      open(app_b.RULES_PATH).read() == old_rules)

# 备份成功 + nft -f 失败 → lastgood 必须还在（P2-9）
app = fresh()
open(app.RULES_PATH, 'w').write('# 旧规则\ntable inet fw4 { chain input { policy drop; } }\n')
def failing_run(cmd, **kw):
    import subprocess as sp
    if cmd[:2] == ['nft', '-f']:
        return sp.CompletedProcess(cmd, 1, '', '模拟 nft -f 失败')
    return sp.CompletedProcess(cmd, 0, '', '')


app.subprocess.run = failing_run
app._ruleset_is_empty = lambda: True
app._apply_basic_lockdown = lambda *a, **k: False
app._ensure_ipv6_cron = lambda: None
app._unlink_quiet = lambda p: None
ok, msg = app._apply_ruleset(base_cfg())
check('nft -f 失败时返回失败', ok is False, msg[:60])
check('回滚后 .lastgood 仍在（二次故障还有材料）',
      os.path.exists(app.RULES_PATH + '.lastgood'),
      f'lastgood 存在={os.path.exists(app.RULES_PATH + ".lastgood")}')

# ─────────────────────────────────────────────────────────────
sec('P1-7  信任 IP fail-closed，不再回落到硬编码网段')
app = fresh()
for name, val in [('空值', ''), ('垃圾值', 'not-an-ip'), ('数组全非法', ['', 'abc'])]:
    v = app._safe_ip(val, 4, '192.168.4.229', strict=True)
    check(f'{name} 的 trusted_ip4 不回落默认', v == '', f'得到 {v!r}')
v4 = app.config_to_variables({**base_cfg(), 'trusted_ip4': '192.168.100.2',
                              'trusted_ip6': ''})['TRUSTED_IP4']
check('合法信任 IP 正常透传', v4 == '192.168.100.2', v4)
v6 = app.config_to_variables({**base_cfg(), 'trusted_ip4': '',
                              'trusted_ip6': 'fd93::1'})['TRUSTED_IP6']
check('合法信任 IPv6 正常透传', v6 == 'fd93::1', v6)
check('路由类字段仍保留默认值（不误伤首装）',
      app.config_to_variables({**base_cfg(), 'router_ip4': ''})['ROUTER_IP4'] == '192.168.4.1')
r = app.build_rules({**base_cfg(), 'trusted_ip4': '', 'trusted_ip6': ''})
# 只看有效规则行：模板里那条注释本身就写着 `ip saddr "" accept` 的反例说明
code_lines = [l.strip() for l in r.split('\n')
              if l.strip() and not l.strip().startswith('#')]
check('未配信任 IP 时不生成空地址 accept（否则 nft 语法错误）',
      not any('saddr ""' in l or re.search(r'ip6? saddr\s+accept', l) for l in code_lines),
      str([l for l in code_lines if re.search(r'ip6? saddr\s+accept', l)]))
check('未配信任 IP 时放行段整体消失（只剩 @allowed 白名单规则）',
      not any(l.startswith('ip saddr') and 'accept' in l and '@allowed' not in l
              and 'fe80' not in l and 'ULA' not in l for l in code_lines))
check('未配信任 IP 时硬编码默认 IP 不出现在规则里',
      '192.168.4.229' not in r and 'fd93:86bb:a142:0:e9d:92ff:fe87:fd28' not in r)
check('模板占位符无残留', '__TRUSTED' not in r)

# ─────────────────────────────────────────────────────────────
sec('P1-8  端口转发目标的语义校验')
app = fresh()
ctx = {'router_ip4': '192.168.100.1', 'router_ip6': '', 'lan_subnet4': '192.168.100.0/24',
       'lan_broadcast4': '192.168.100.255'}
for ip, why in [('127.0.0.1', '回环'), ('169.254.169.254', '云元数据'),
                ('0.0.0.0', '未指定'), ('255.255.255.255', '全局广播'),
                ('192.168.100.255', '网段广播'), ('192.168.100.1', '路由器自身'),
                ('::1', 'v6回环'), ('::ffff:127.0.0.1', 'v4映射回环')]:
    check(f'拒绝 {why}（{ip}）', bool(app._bad_forward_target(ip, '', ctx)),
          app._bad_forward_target(ip, '', ctx)[:40])
check('放行正常内网地址', app._bad_forward_target('192.168.100.50', '', ctx) == '')
check('放行同网段不同主机', app._bad_forward_target('192.168.100.99', '', ctx) == '')

# 行为层：validate_config 必须真的把语义问题报出来
for bad_ip in ('127.0.0.1', '169.254.169.254', '192.168.100.1'):
    errs = app.validate_config({**ctx, 'trusted_ip4': '192.168.100.2',
                                'lan_allowed_ports': '22', 'forward_rules': [
        {'tcp_ports': '8080', 'udp_ports': '', 'target_ip': bad_ip}]})
    check(f'validate_config 拒绝 {bad_ip}',
          any('target_ip' in e for e in errs), str(errs)[:90])
ok_ctx = {**ctx, 'trusted_ip4': '192.168.100.2', 'lan_allowed_ports': '22'}
errs_ok = app.validate_config({**ok_ctx, 'forward_rules': [
    {'tcp_ports': '8080', 'udp_ports': '', 'target_ip': '192.168.100.50'}]})
check('validate_config 放行正常转发目标', errs_ok == [], str(errs_ok)[:90])
errs_v6 = app.validate_config({**ok_ctx, 'forward_rules': [
    {'tcp_ports': '8080', 'udp_ports': '', 'target_ip': '192.168.100.50',
     'target_ipv6': '::1'}]})
check('validate_config 也校验 target_ipv6',
      any('target_ipv6' in e for e in errs_v6), str(errs_v6)[:90])

# ─────────────────────────────────────────────────────────────
sec('P1-6  敲门限流按源分桶')
app = fresh()
r = app.build_rules(app.load_config())
check('不再存在规则级 limit rate 1/minute（全局桶）',
      len(re.findall(r'^\s+limit rate 1/minute', r, re.M)) == 0)
check('声明了 knock_rate4 集合', 'set knock_rate4' in r and 'set knock_rate6' in r)
check('knock_rate4 集合是 dynamic+timeout（桶能回收）',
      re.search(r'set knock_rate4 \{[^}]*flags dynamic,timeout', r) is not None)
check('v4 敲门按源分桶', r.count('@knock_rate4 { ip saddr limit rate 1/minute') == 4,
      str(r.count('@knock_rate4 { ip saddr limit rate 1/minute')))
check('v6 敲门按源分桶', r.count('@knock_rate6 { ip6 saddr limit rate 1/minute') == 4,
      str(r.count('@knock_rate6 { ip6 saddr limit rate 1/minute')))
check('v6 链没有误用 v4 集合',
      'knock_wan_v6' in r and r.split('chain knock_wan_v6')[1].split('chain knock_lan')[0].count('@knock_rate4') == 0)

# ─────────────────────────────────────────────────────────────
sec('P2-10  兜底防火墙读配置，不写死 br-lan')
app = fresh()
src = open(os.path.join(BACKEND, 'app.py')).read()
fn = src[src.index('def _apply_basic_lockdown'):]
fn = fn[:fn.index('\ndef ') if '\ndef ' in fn else len(fn)]
body = fn.split("rules = f'''", 1)[1] if "rules = f'''" in fn else ''
check('兜底规则模板里不再硬编码 "br-lan"', '"br-lan"' not in body)
check('兜底规则模板用的是配置里的 lan_if', '{lan_if}' in body)
check('接口不存在时拒绝执行（避免 policy drop 自锁）', 'return False' in fn)
app._interface_exists = lambda n: n in ('eth0', 'br-lan')
app._detect_default_route_if = lambda: 'eth0'
import subprocess as _sp
captured = {}


def cap(cmd, **kw):
    captured['rules'] = kw.get('input', '')
    return _sp.CompletedProcess(cmd, 0, '', '')


app.subprocess.run = cap
app._ruleset_is_empty = lambda: False
app._apply_basic_lockdown({**base_cfg(), 'lan_if': 'eth0', 'lan_allowed_ports': '22, 8080'})
check('linux_gateway 模式用 eth0 而不是 br-lan',
      'iifname "eth0"' in captured['rules'] and 'br-lan' not in captured['rules'])
check('放行端口来自配置 + SSH + 面板',
      all(f'dport {{ {p} ' not in captured['rules'] for p in ())
      and '5443' in captured['rules'] and '8080' in captured['rules'])
app._interface_exists = lambda n: False
app._detect_default_route_if = lambda: None
check('lan_if 不存在且无法自动识别时拒绝执行',
      app._apply_basic_lockdown({**base_cfg(), 'lan_if': 'eth9'}) is False)

# ─────────────────────────────────────────────────────────────
sec('P2-11  forward 链不再用无条件 accept 吃掉 DNS 收紧')
app = fresh()
r_on = app.build_rules({**base_cfg(), 'dns_lan_resolver_enabled': True})
r_off = app.build_rules({**base_cfg(), 'dns_lan_resolver_enabled': False})
def fwd_block(r):
    i = r.index('# 3. 内网→外网')
    j = r.index('meta nfproto ipv4 drop', i)     # 必须从 i 开始找，
    return r[i:j]                                 # 否则会命中 input 链里的同名行


blk_on = fwd_block(r_on)
blk_off = fwd_block(r_off)
# 只看有效规则行：模板里那段说明性注释本身就引用了这条规则
blk_on_code = [l.strip() for l in blk_on.split('\n') if l.strip() and not l.strip().startswith('#')]
blk_off_code = [l.strip() for l in blk_off.split('\n') if l.strip() and not l.strip().startswith('#')]
UNCOND = 'iifname $LAN_IF oifname $WAN_IF accept'
check('开启 DNS 递归时不再放行无条件 LAN→WAN',
      not any(l == UNCOND for l in blk_on_code),
      str([l[:70] for l in blk_on_code if 'WAN_IF' in l]))
check('开启时改为拒绝指向非路由器 DNS',
      'daddr != $ROUTER_IP4 drop' in blk_on)
check('关闭时保持原有放行行为（不擅自改变用户意图）',
      UNCOND in blk_off_code)
check('LAN_WAN_GENERAL 占位符无残留', '__LAN_WAN_GENERAL__' not in r_on)

# ─────────────────────────────────────────────────────────────
sec('P2-13  健康检查能识别「表在但链是空的」')
app = fresh()


def fake_list(out, rc=0):
    return _sp.CompletedProcess(['nft'], rc, out, '')


app.subprocess.run = lambda cmd, **kw: fake_list('')
ok, why = app._ruleset_is_functional()
check('表存在但无 hook 时判定为不可用', ok is False, why)
app.subprocess.run = lambda cmd, **kw: fake_list(
    'table inet fw4 {\n chain input {\n  type filter hook input priority filter; policy accept;\n }\n}')
ok, why = app._ruleset_is_functional()
check('没有 drop/reject 策略时判定为不可用（防火墙没生效）', ok is False, why)
app.subprocess.run = lambda cmd, **kw: fake_list(
    'table inet fw4 {\n chain input {\n  type filter hook input priority filter; policy drop;\n'
    '  iifname "lo" accept\n }\n}')
ok, why = app._ruleset_is_functional()
check('完整规则集判定为正常', ok is True, why)

# ─────────────────────────────────────────────────────────────
sec('P2-14  反代部署失败不能报 success')
src = open(os.path.join(BACKEND, 'app.py')).read()
del_fn = None
for name in ('def rp_delete_rule', 'def reverse_proxy_rule_delete',
             'def delete_proxy_rule', 'def proxy_delete'):
    if name in src:
        del_fn = src[src.index(name):]
        del_fn = del_fn[:del_fn.index('\n@app.route')] if '\n@app.route' in del_fn else del_fn
        break
check('能找到反代删除处理函数', del_fn is not None)
if del_fn:
    # 检查点在 _apply_ruleset **之后**（防火墙先更新，再判 nginx 结果），
    # 所以不能只截到 _apply_ruleset 为止
    check('返回 success 前检查 deploy_ok', 'if not deploy_ok:' in del_fn)
    check('deploy_ok 检查位于 success 返回之前',
          del_fn.index('if not deploy_ok:') < del_fn.index('"success": True'))
    check('部署失败时报 NGINX_DEPLOY_FAILED',
          'NGINX_DEPLOY_FAILED' in del_fn)
    check('部署失败时 HTTP 状态码是 5xx 不是 200', '}), 500' in del_fn)

# ─────────────────────────────────────────────────────────────
sec('额外确认项  黑名单必须早于 established 与 LAN IPv6 放行')
app = fresh()
r = app.build_rules(app.load_config())
lines = r.split('\n')
bl = [i for i, l in enumerate(lines) if '@blacklist4 log' in l][0]
est = [i for i, l in enumerate(lines) if 'ct state { established, related } accept;' in l][0]
ula = [i for i, l in enumerate(lines) if 'ULA_PREFIX6 accept' in l][0]
fe80 = [i for i, l in enumerate(lines) if 'fe80::/10 accept' in l][0]
check('黑名单早于 established accept（对已建立连接生效）', bl < est, f'黑名单 {bl+1} / established {est+1}')
check('黑名单早于 LAN ULA 放行', bl < ula)
check('黑名单早于 LAN fe80 放行', bl < fe80)

# ─────────────────────────────────────────────────────────────
print('\n' + '=' * 60)
print(f'通过 {len(PASS)} / {len(PASS) + len(FAIL)}' + (f'，失败 {len(FAIL)}' if FAIL else ''))
if FAIL:
    for f in FAIL:
        print('  ❌ ' + f)
sys.exit(1 if FAIL else 0)