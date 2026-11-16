#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""「证书域名 → 本机 IP」本地解析的行为级判据（沙箱内跑，绝不碰真机）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_local_domain_resolution.py

这功能解决什么
--------------
host 分发入口挂的是**域名**（如 siyuan.fzyto.top）。内网客户端用域名访问时，
公网 DNS 把它指到公网 IP（或别的机器）⇒ 要么绕不出去（NAT 回环不通），
要么落到不对的机器上。
⇒ 让本机 dnsmasq 把这个域名（及其所有子域）直接答成本机 LAN IP。

判据为什么必须在沙箱里
----------------------
`backend/dhcp_hosts.py` 会**改系统配置**（`/etc/config/dhcp`）。
这里要验的恰恰是「备份 → 写 → 校验 → 回滚」这条**会动文件**的链，
所以它**绝不能**在开发机或真机对着真配置跑。

⇒ 做法（沿用 tests/test_dhcp_hosts_write.py 的骨架）：
  · 配置目录 = 临时目录；`uci` = `tests/fixtures/fake_uci.py`（无 FAKE_UCI_DIR
    就拒绝运行 ⇒ 不可能碰到真实 /etc/config）；
  · 模块里的路径常量全部指向沙箱；
  · `app.py` 加载前先把沙箱版 `dhcp_hosts` 塞进 `sys.modules`
    ⇒ app.py 的 `import dhcp_hosts` 拿到的就是沙箱版。

判据要能被反向证伪
------------------
每条断言都对着一个**具体的失败模式**：
  · 写错格式（少斜杠）⇒ 解析不到那条记录；
  · 误删用户自己的 address ⇒ 用户手写的解析条目不见了；
  · 不幂等 ⇒ 每存一次配置就多一条记录；
  · 域名变了不清理 ⇒ 旧域名还指向本机；
  · 校验没做 ⇒ 非法域名/IP 也被写进去；
  · 回滚没做 ⇒ 写坏配置留在设备上；
  · 钩子抛异常 ⇒ 保存配置的整个流程被拖垮。
"""
import importlib.util as ilu
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BACKEND = os.path.join(ROOT, 'backend')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name +
          (('  — %s' % detail) if detail else ''))


def sec(title):
    print('\n=== %s ===' % title)


# ── 沙箱 ──────────────────────────────────────────────────────

SANDBOX = tempfile.mkdtemp(prefix='local-domain-test-')
CFG_DIR = os.path.join(SANDBOX, 'etc', 'config')
CFG = os.path.join(CFG_DIR, 'dhcp')
BACKUP_DIR = os.path.join(SANDBOX, 'backup')
BIN_DIR = os.path.join(SANDBOX, 'bin')
EMPTY_BIN_DIR = os.path.join(SANDBOX, 'emptybin')
INITD = os.path.join(SANDBOX, 'init.d')
DNSMASQ_INIT = os.path.join(INITD, 'dnsmasq')

for _d in (CFG_DIR, BACKUP_DIR, BIN_DIR, EMPTY_BIN_DIR, INITD):
    os.makedirs(_d, mode=0o700)

shutil.copy2(os.path.join(HERE, 'fixtures', 'fake_uci.py'),
             os.path.join(BIN_DIR, 'uci'))
os.chmod(os.path.join(BIN_DIR, 'uci'), 0o755)

# 假 dnsmasq init：退出码由 FAKE_DNSMASQ_RC 决定
with open(DNSMASQ_INIT, 'w', encoding='utf-8') as f:
    f.write('#!/bin/sh\nexit ${FAKE_DNSMASQ_RC:-0}\n')
os.chmod(DNSMASQ_INIT, 0o755)

os.environ['FAKE_UCI_DIR'] = CFG_DIR
os.environ['FAKE_UCI_DELTA'] = os.path.join(SANDBOX, 'uci_delta.json')
os.environ['PATH'] = BIN_DIR + os.pathsep + os.environ.get('PATH', '')
os.environ.pop('FAKE_UCI_FAIL_COMMIT', None)
os.environ.pop('FAKE_DNSMASQ_RC', None)

sys.path.insert(0, BACKEND)


def load_dhcp_hosts():
    spec = ilu.spec_from_file_location('dhcp_hosts_sandbox',
                                       os.path.join(BACKEND, 'dhcp_hosts.py'))
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dhcp_hosts = load_dhcp_hosts()
dhcp_hosts.DHCP_CONFIG_PATH = CFG
dhcp_hosts.BACKUP_DIR = BACKUP_DIR
dhcp_hosts.DNSMASQ_INIT = DNSMASQ_INIT

# ⚠️ 安全闸：路径必须全在沙箱里，否则**拒绝跑**（防手滑改到真机）
for _p in (dhcp_hosts.DHCP_CONFIG_PATH, dhcp_hosts.BACKUP_DIR,
           dhcp_hosts.DNSMASQ_INIT):
    if not os.path.abspath(_p).startswith(os.path.abspath(SANDBOX) + os.sep):
        print('[FAIL] 沙箱路径越界，拒绝运行: %s' % _p)
        sys.exit(2)

# app.py 的 `import dhcp_hosts` 必须拿到沙箱版
sys.modules['dhcp_hosts'] = dhcp_hosts

# ── 基线配置 ─────────────────────────────────────────────────
#
# 照 .193 真机形态写（2026-11-17 实测）：
#   · 默认 dnsmasq 实例是**匿名段**（uci show 显示成 @dnsmasq[0]）；
#   · 用户自己可能写过 list address（LuCI 之外的玩法）⇒ **不许被删**。
BASE = """config dnsmasq
\toption domain 'lan'
\toption local '/lan/'
\tlist address '/user.example.com/10.0.0.1'

config dhcp 'lan'
\toption interface 'lan'
\toption start '100'
\toption limit '150'
\toption leasetime '12h'

config host 'existing'
\toption name '旧设备'
\toption mac 'aa:bb:cc:dd:ee:00'
\toption ip '192.168.100.99'
"""


def reset_cfg(text=BASE):
    """把配置恢复成基线（权限 0600），并清掉备份目录与 delta。"""
    with open(CFG, 'w', encoding='utf-8') as f:
        f.write(text)
    os.chmod(CFG, 0o600)
    if os.path.isdir(BACKUP_DIR):
        shutil.rmtree(BACKUP_DIR)
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    delta = os.environ['FAKE_UCI_DELTA']
    if os.path.exists(delta):
        os.remove(delta)


def cfg_text():
    with open(CFG, encoding='utf-8') as f:
        return f.read()


def cfg_bytes():
    with open(CFG, 'rb') as f:
        return f.read()


# ─────────────────────────────────────────────────────────────
sec('1  写入：域名 → 本机 IP')

reset_cfg()
before = cfg_bytes()
res = dhcp_hosts.set_local_domain_resolution('example.com', '192.168.100.193')
txt = cfg_text()

check('写完有 list address 条目（格式 /域名/IP）',
      "list address '/example.com/192.168.100.193'" in txt,
      txt)
check('写完有标记 option（认得出哪条是本面板写的）',
      "option nftweb_local_domain 'example.com'" in txt,
      txt)
check('返回 changed=True', res.get('changed') is True, repr(res))
check('返回里带重载结果', 'reload' in res, repr(res))
check('★ 用户自己写的 address 条目**没被动**',
      "list address '/user.example.com/10.0.0.1'" in txt,
      txt)
check('★ 配置确实被改了', cfg_bytes() != before)


# ─────────────────────────────────────────────────────────────
sec('2  幂等：同样的输入再写一次，什么都不该变')

reset_cfg()
dhcp_hosts.set_local_domain_resolution('example.com', '192.168.100.193')
snap1 = cfg_bytes()
res2 = dhcp_hosts.set_local_domain_resolution('example.com', '192.168.100.193')
check('第二次写 changed=False', res2.get('changed') is False, repr(res2))
check('★ 第二次写文件一个字节都没变', cfg_bytes() == snap1)
check('★ 没有写出重复条目',
      cfg_text().count("'/example.com/192.168.100.193'") == 1,
      cfg_text())


# ─────────────────────────────────────────────────────────────
sec('3  域名变了：旧的清掉，新的加上')

reset_cfg()
dhcp_hosts.set_local_domain_resolution('old.example.com', '192.168.100.193')
dhcp_hosts.set_local_domain_resolution('new.example.com', '192.168.100.193')
txt = cfg_text()
check('★ 旧域名的条目被删了',
      '/old.example.com/' not in txt, txt)
check('新域名的条目写上了',
      "list address '/new.example.com/192.168.100.193'" in txt, txt)
check('标记跟着更新成新域名',
      "option nftweb_local_domain 'new.example.com'" in txt, txt)
check('★ 用户自己的条目仍然在',
      "list address '/user.example.com/10.0.0.1'" in txt, txt)


# ─────────────────────────────────────────────────────────────
sec('4  同域名、IP 变了（机器换 IP）：条目要跟着更新')

reset_cfg()
dhcp_hosts.set_local_domain_resolution('example.com', '192.168.100.146')
dhcp_hosts.set_local_domain_resolution('example.com', '192.168.100.193')
txt = cfg_text()
check('★ 旧 IP 的条目没了', '192.168.100.146' not in txt, txt)
check('新 IP 的条目在',
      "list address '/example.com/192.168.100.193'" in txt, txt)


# ─────────────────────────────────────────────────────────────
sec('5  域名清空（证书换掉了/不用了）：条目要删掉')

reset_cfg()
dhcp_hosts.set_local_domain_resolution('example.com', '192.168.100.193')
res5 = dhcp_hosts.set_local_domain_resolution('', '')
txt = cfg_text()
check('★ 本面板写的条目被删了', '/example.com/' not in txt, txt)
check('★ 用户自己的条目没被误删',
      "list address '/user.example.com/10.0.0.1'" in txt, txt)
check('标记被保留（下次域名变回来还认得出）',
      "option nftweb_local_domain 'example.com'" in txt, txt)
check('清空也算一次改动', res5.get('changed') is True, repr(res5))


# ─────────────────────────────────────────────────────────────
sec('6  校验：非法域名/IP 一律不写，且文件一个字节都不动')

for bad_domain in ('example.com/../x', 'a b.com', '*', 'a..b',
                   'example.com;evil', 'example.com/1.2.3.4'):
    reset_cfg()
    before = cfg_bytes()
    try:
        dhcp_hosts.set_local_domain_resolution(bad_domain, '192.168.100.193')
        ok = False
        why = '没有报错'
    except dhcp_hosts.DhcpWriteError as e:
        ok = True
        why = str(e)
    check('非法域名被拒: %r' % bad_domain, ok, why)
    check('★ 非法域名没写进文件: %r' % bad_domain, cfg_bytes() == before)

# 大写 + 结尾的点 = FQDN 写法 ⇒ **规范化**（不是拒绝）。
# 拒绝会让 "EXAMPLE.COM." 和 "example.com" 变成两条不同的解析记录。
reset_cfg()
dhcp_hosts.set_local_domain_resolution('EXAMPLE.COM.', '192.168.100.193')
check('★ 大写/结尾点被规范化成小写无尾点',
      "list address '/example.com/192.168.100.193'" in cfg_text(),
      cfg_text())

for bad_ip in ('192.168.100', '999.1.1.1', '192.168.100.193.5', 'abc', ''):
    reset_cfg()
    before = cfg_bytes()
    try:
        dhcp_hosts.set_local_domain_resolution('example.com', bad_ip)
        ok = False
        why = '没有报错'
    except dhcp_hosts.DhcpWriteError as e:
        ok = True
        why = str(e)
    check('非法 IP 被拒: %r' % bad_ip, ok, why)
    check('★ 非法 IP 没写进文件: %r' % bad_ip, cfg_bytes() == before)


# ─────────────────────────────────────────────────────────────
sec('7  故障注入：写坏了必须回滚')

reset_cfg()
before = cfg_bytes()
os.environ['FAKE_UCI_FAIL_COMMIT'] = '1'
try:
    dhcp_hosts.set_local_domain_resolution('example.com', '192.168.100.193')
    ok = False
    why = '没有报错'
except dhcp_hosts.DhcpWriteError as e:
    ok = True
    why = str(e)
finally:
    os.environ.pop('FAKE_UCI_FAIL_COMMIT', None)
check('commit 失败时报错', ok, why)
check('★ commit 失败后文件恢复成写前内容', cfg_bytes() == before)

# 写前必须**留下备份文件** —— 出事要靠它恢复，光「能恢复」不够，
# 备份本身也得真的落盘了（.232 那次教训：回滚脚本指向一份不存在的备份）。
# ⚠️ 备份文件名是 dhcp.<时间戳>.<pid>.<序号>.<tag>（**没有扩展名**），
#    同一个目录里还有写锁文件 dhcp.lock ⇒ 两个都要排除掉。
_backups = [f for f in os.listdir(BACKUP_DIR)
            if f.startswith('dhcp.') and f != 'dhcp.lock']
check('★ 写前留下了备份文件', len(_backups) > 0, str(os.listdir(BACKUP_DIR)))
if _backups:
    with open(os.path.join(BACKUP_DIR, sorted(_backups)[-1]), 'rb') as f:
        check('★ 备份内容等于写前内容', f.read() == before)

reset_cfg()
before = cfg_bytes()
os.environ['FAKE_UCI_CORRUPT_COMMIT'] = '1'
try:
    # 桩会把**整个文件**写成坏的 ⇒ 语法校验失败 ⇒ 必须回滚
    dhcp_hosts.set_local_domain_resolution('example.com', '192.168.100.193')
    ok = False
    why = '没有报错'
except dhcp_hosts.DhcpWriteError as e:
    ok = True
    why = str(e)
finally:
    os.environ.pop('FAKE_UCI_CORRUPT_COMMIT', None)
check('写坏配置时报错', ok, why)
check('★ 写坏配置后文件恢复成写前内容', cfg_bytes() == before)


# ─────────────────────────────────────────────────────────────
sec('8  dnsmasq 重载失败：写成功，但必须如实报告「没生效」')

reset_cfg()
os.environ['FAKE_DNSMASQ_RC'] = '3'
try:
    res8 = dhcp_hosts.set_local_domain_resolution('example.com',
                                                   '192.168.100.193')
    raised = None
except Exception as e:          # noqa: BLE001
    res8, raised = {}, e
finally:
    os.environ.pop('FAKE_DNSMASQ_RC', None)
check('★ 重载失败**不能**当成写失败抛异常（文件是对的）', raised is None,
      repr(raised))
check('重载失败时 reload.ok=False',
      (res8.get('reload') or {}).get('ok') is False, repr(res8.get('reload')))
check('重载失败也要说明「已写入但未生效」',
      '未生效' in (res8.get('reload') or {}).get('message', ''),
      (res8.get('reload') or {}).get('message', ''))
check('★ 配置确实写进去了（没因为重载失败就回滚）',
      "list address '/example.com/192.168.100.193'" in cfg_text())


# ─────────────────────────────────────────────────────────────
sec('9  没有 uci 命令：明确拒绝，不改任何东西')

reset_cfg()
before = cfg_bytes()
old_path = os.environ['PATH']
os.environ['PATH'] = EMPTY_BIN_DIR
try:
    dhcp_hosts.set_local_domain_resolution('example.com', '192.168.100.193')
    ok = False
    why = '没有报错'
except dhcp_hosts.DhcpWriteError as e:
    ok = True
    why = str(e)
finally:
    os.environ['PATH'] = old_path
check('没有 uci 时报错', ok, why)
check('★ 没有 uci 时文件没动', cfg_bytes() == before)


# ─────────────────────────────────────────────────────────────
sec('10  面板侧的钩子 _sync_local_domain_resolution')

spec = ilu.spec_from_file_location('_nftapp_localdomain',
                                   os.path.join(BACKEND, 'app.py'))
app = ilu.module_from_spec(spec)
spec.loader.exec_module(app)


def rp_config(base_domain=None, lan_if='br-lan'):
    """造一份最小 reverse_proxy 配置。"""
    settings = {}
    if base_domain is not None:
        settings['base_domain'] = base_domain
    return {'lan_if': lan_if,
            'reverse_proxy': {'settings': settings, 'rules': [],
                              'certificates': []}}


reset_cfg()
r1 = app._sync_local_domain_resolution(rp_config('example.com'),
                                       lan_ip='192.168.100.193')
check('★ 钩子返回 ok=True', r1.get('ok') is True, repr(r1))
check('★ 钩子写进了正确的条目',
      "list address '/example.com/192.168.100.193'" in cfg_text(),
      cfg_text())

reset_cfg()
r2 = app._sync_local_domain_resolution(rp_config(''),
                                       lan_ip='192.168.100.193')
check('基础域名为空 ⇒ 不留下任何本面板的条目',
      '/example.com/' not in cfg_text() and 'nftweb_local_domain' not in cfg_text(),
      cfg_text())
check('基础域名为空时仍返回 ok（不是失败）', r2.get('ok') is True, repr(r2))

reset_cfg()
r3 = app._sync_local_domain_resolution(rp_config('example.com',
                                                  lan_if='nonexistent-if0'))
check('★ 探测不到 LAN 地址 ⇒ 不写解析', '/example.com/' not in cfg_text(),
      cfg_text())
check('探测不到 LAN 地址时如实报失败', r3.get('ok') is False, repr(r3))

reset_cfg()
os.environ['FAKE_UCI_FAIL_COMMIT'] = '1'
try:
    r4 = app._sync_local_domain_resolution(rp_config('example.com'),
                                           lan_ip='192.168.100.193')
    raised4 = None
except Exception as e:          # noqa: BLE001
    r4, raised4 = {}, e
finally:
    os.environ.pop('FAKE_UCI_FAIL_COMMIT', None)
check('★ 写失败时钩子**不抛异常**（保存流程不能被拖垮）',
      raised4 is None and isinstance(r4, dict) and r4.get('ok') is False,
      repr(raised4) if raised4 else repr(r4))

reset_cfg()
r5 = app._sync_local_domain_resolution(rp_config('example.com'),
                                       lan_ip='192.168.100.193')
check('★ 域名取的是 base_domain，不是随便什么域名',
      "list address '/example.com/192.168.100.193'" in cfg_text(),
      cfg_text())


# ─────────────────────────────────────────────────────────────
shutil.rmtree(SANDBOX, ignore_errors=True)

print()
if FAIL:
    print('[FAIL] 失败 %d 项：' % len(FAIL))
    for f in FAIL:
        print('   - ' + f)
    sys.exit(1)
print('[PASS] 通过 %d / %d' % (len(PASS), len(PASS)))
print('全部通过')
