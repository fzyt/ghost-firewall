#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DHCP 静态绑定**写操作**的行为级判据（沙箱内跑，绝不碰真机）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_dhcp_hosts_write.py

为什么必须在沙箱里
------------------
`backend/dhcp_hosts.py` 会**改系统配置**（`/etc/config/dhcp`）。
判据要验的恰恰是「备份 → 写 → 校验 → 回滚」这条**会动文件**的链，
所以它**绝不能**在开发机或真机对着真配置跑。

⇒ 做法：
  · 配置目录 = 临时目录（`tempfile.mkdtemp`）；
  · `uci` = `tests/fixtures/fake_uci.py`（子集实现，行为按 .232 实测对齐）；
    它**没有 `FAKE_UCI_DIR` 就拒绝运行** ⇒ 不可能碰到真实 `/etc/config`；
  · 模块里的三个路径常量（配置/备份/init 脚本）全部指向沙箱。

判据要能被反向证伪
------------------
每条断言都对着一个**具体的失败模式**：
  · 校验漏了 ⇒ 「文件一个字节都没动」这条会红；
  · 备份没做 ⇒ 「备份文件存在且内容等于写前」会红；
  · 回滚没做 ⇒ 「文件恢复成写前内容」会红；
  · 回滚失败没上报 ⇒ `rolled_back` 标志会红；
  · 重载失败被当成写失败 ⇒ 「绑定已写入 + 不抛异常」会红。

⚠️ 这份判据与 .232 实测绑死的三条硬件事实（改了实现就得同步改判据）：
  1. uci **拒绝非 ASCII 段名**（`uci set dhcp.我的NAS=host` ⇒ Invalid argument）
     ⇒ 段名必须由 MAC 派生（ASCII），显示名走 `option name`；
  2. uci **允许**值里有空格/等号/中文/单引号（自己转义成 `'\''`）；
  3. uci **会把值里的换行原样写进文件** ⇒ 显示名必须拒绝控制字符。
"""
import importlib.util
import os
import shutil
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(os.path.dirname(HERE), 'backend')
sys.path.insert(0, BACKEND)

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name +
          (('  — %s' % detail) if detail else ''))


def sec(title):
    print('\n=== %s ===' % title)


def load_dhcp_hosts():
    path = os.path.join(BACKEND, 'dhcp_hosts.py')
    spec = importlib.util.spec_from_file_location('dhcp_under_test', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── 沙箱 ──────────────────────────────────────────────────────

SANDBOX = tempfile.mkdtemp(prefix='dhcp-write-test-')
CFG_DIR = os.path.join(SANDBOX, 'etc', 'config')
CFG = os.path.join(CFG_DIR, 'dhcp')
BACKUP_DIR = os.path.join(SANDBOX, 'backup')
BIN_DIR = os.path.join(SANDBOX, 'bin')
EMPTY_BIN_DIR = os.path.join(SANDBOX, 'emptybin')
INITD = os.path.join(SANDBOX, 'init.d')
DNSMASQ_INIT = os.path.join(INITD, 'dnsmasq')

os.makedirs(CFG_DIR, mode=0o700)
os.makedirs(BIN_DIR, mode=0o700)
os.makedirs(EMPTY_BIN_DIR, mode=0o700)
os.makedirs(INITD, mode=0o700)

# 假 uci：拷贝成可执行文件放进沙箱 PATH
shutil.copy2(os.path.join(HERE, 'fixtures', 'fake_uci.py'),
             os.path.join(BIN_DIR, 'uci'))
os.chmod(os.path.join(BIN_DIR, 'uci'), 0o755)

# 假 dnsmasq init：退出码由 FAKE_DNSMASQ_RC 决定
with open(DNSMASQ_INIT, 'w', encoding='utf-8') as f:
    f.write('#!/bin/sh\nexit ${FAKE_DNSMASQ_RC:-0}\n')
os.chmod(DNSMASQ_INIT, 0o755)

# 环境：假 uci 只认沙箱目录
os.environ['FAKE_UCI_DIR'] = CFG_DIR
os.environ['FAKE_UCI_DELTA'] = os.path.join(SANDBOX, 'uci_delta.json')
os.environ['PATH'] = BIN_DIR + os.pathsep + os.environ.get('PATH', '')
os.environ.pop('FAKE_UCI_FAIL_COMMIT', None)
os.environ.pop('FAKE_DNSMASQ_RC', None)

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

# ── 基线配置 ─────────────────────────────────────────────────
#
# 照 .232 的真实格式写：段之间空行、option 用 tab 缩进、单引号包值。
BASE = """config dnsmasq
\toption domain 'lan'
\toption local '/lan/'

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
    """把配置恢复成基线（权限 0600，与 .232 一致），并清空备份目录与 delta。"""
    with open(CFG, 'w', encoding='utf-8') as f:
        f.write(text)
    os.chmod(CFG, 0o600)
    if os.path.isdir(BACKUP_DIR):
        shutil.rmtree(BACKUP_DIR)
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    # delta 是「未提交的变更」⇒ 重置时必须一起清掉，
    # 否则上一条用例留下的半截变更会渗进下一条（判据就不干净了）。
    delta = os.environ['FAKE_UCI_DELTA']
    if os.path.exists(delta):
        os.remove(delta)


def cfg_bytes():
    with open(CFG, 'rb') as f:
        return f.read()


def cfg_text():
    with open(CFG, encoding='utf-8') as f:
        return f.read()


def backups():
    if not os.path.isdir(BACKUP_DIR):
        return []
    return sorted(os.listdir(BACKUP_DIR))


def perm_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def expect_error(fn, *args, **kw):
    """调 fn，期望抛 DhcpWriteError。返回 (错误对象 或 None)。"""
    try:
        fn(*args, **kw)
    except dhcp_hosts.DhcpWriteError as e:
        return e
    except Exception as e:  # 抛别的异常也算失败（判据要能断言而不是崩）
        return 'WRONG_EXCEPTION:%s:%s' % (type(e).__name__, e)
    return None


# ══════════════════════════════════════════════════════════════
# 1. 写之前的校验 —— 校验不过就**一个字节都不许动**
# ══════════════════════════════════════════════════════════════
sec('1. 写前校验（非法输入必须被拒，且文件一个字节都不动）')

BAD_CASES = [
    ('设备名为空', '', 'aa:bb:cc:dd:ee:01', '192.168.100.11'),
    ('设备名超长（64 字符）', 'x' * 64, 'aa:bb:cc:dd:ee:01', '192.168.100.11'),
    ('设备名含换行', '客厅\n电视', 'aa:bb:cc:dd:ee:01', '192.168.100.11'),
    ('设备名含回车', '客厅\r电视', 'aa:bb:cc:dd:ee:01', '192.168.100.11'),
    ('设备名含制表符', '客厅\t电视', 'aa:bb:cc:dd:ee:01', '192.168.100.11'),
    ('MAC 少一段', '设备', 'aa:bb:cc:dd:ee', '192.168.100.11'),
    ('MAC 不是十六进制', '设备', 'aa:bb:cc:dd:ee:gg', '192.168.100.11'),
    ('IP 段数不对', '设备', 'aa:bb:cc:dd:ee:01', '192.168.100'),
    ('IP 段大于 255', '设备', 'aa:bb:cc:dd:ee:01', '192.168.100.999'),
    ('IP 为空', '设备', 'aa:bb:cc:dd:ee:01', ''),
    # ⚠️ 下面两条专治 Unicode 数字：
    #    '²'.isdigit() 是 True，但 int('²') 抛 ValueError ⇒ 未捕获异常 ⇒ 500；
    #    '٣'.isdigit() 也是 True，但 int('٣') == 3 ⇒ 非法的 IP 被当合法值写进去。
    ('IP 段含上标数字', '设备', 'aa:bb:cc:dd:ee:01', '192.168.100.²'),
    ('IP 段含阿拉伯数字', '设备', 'aa:bb:cc:dd:ee:01', '192.168.100.٣'),
]

for label, name, mac, ip in BAD_CASES:
    reset_cfg()
    before = cfg_bytes()
    e = expect_error(dhcp_hosts.add_dhcp_host, name, mac, ip)
    ok_err = isinstance(e, dhcp_hosts.DhcpWriteError)
    check('%s ⇒ 被拒绝' % label, ok_err,
          (str(e) if ok_err else '没有抛 DhcpWriteError（实际抛了 %r）' % (e,)))
    check('%s ⇒ 文件一个字节都没动' % label, cfg_bytes() == before)
    check('%s ⇒ 连备份都没生成（说明真的没写）' % label,
          not backups(), '备份目录里有: %s' % backups())

# 名字为空也要拒（uci set 空值会 rc=1，别走到那一步）
reset_cfg()
e = expect_error(dhcp_hosts.add_dhcp_host, '   ', 'aa:bb:cc:dd:ee:01',
                  '192.168.100.11')
check('设备名只有空白 ⇒ 被拒绝', isinstance(e, dhcp_hosts.DhcpWriteError),
      str(e) if e else '没抛异常')


# ══════════════════════════════════════════════════════════════
# 2. 新增成功 —— 写对、备份对、权限对
# ══════════════════════════════════════════════════════════════
sec('2. 新增绑定（中文显示名 + 派生段名）')

reset_cfg()
before = cfg_bytes()
res = dhcp_hosts.add_dhcp_host('我的NAS', 'AA:BB:CC:DD:EE:01',
                               '192.168.100.11')
txt = cfg_text()

check('写入成功且返回 section', bool(res.get('section')),
      'section=%r' % res.get('section'))
check('段名由 MAC 派生且是纯 ASCII',
      res.get('section') == 'host_aabbccddee01', 'section=%r' % res.get('section'))
check('返回值里显示名保留中文', res.get('name') == '我的NAS',
      'name=%r' % res.get('name'))
check('返回值里 MAC 已转小写', res.get('mac') == 'aa:bb:cc:dd:ee:01',
      'mac=%r' % res.get('mac'))
check('返回值里 IP 正确', res.get('ip') == '192.168.100.11',
      'ip=%r' % res.get('ip'))

check('配置里出现了新段', "config host 'host_aabbccddee01'" in txt)
check('显示名原样写进 option name（中文 + 不加引号污染）',
      "\toption name '我的NAS'" in txt)
check('MAC 写进 option mac', "\toption mac 'aa:bb:cc:dd:ee:01'" in txt)
check('IP 写进 option ip', "\toption ip '192.168.100.11'" in txt)
check('原有段没被弄坏（old 段还在）',
      "config host 'existing'" in txt and
      "\toption name '旧设备'" in txt)

check('写完文件权限仍是 0600', perm_of(CFG) == 0o600,
      '实际 %o' % perm_of(CFG))

bk = backups()
check('备份文件生成了', len(bk) == 1, '备份目录: %s' % bk)
if bk:
    with open(os.path.join(BACKUP_DIR, bk[0]), 'rb') as f:
        bdata = f.read()
    check('备份内容 == 写前内容', bdata == before)
    check('备份文件权限 0600',
          perm_of(os.path.join(BACKUP_DIR, bk[0])) == 0o600)

check('reload 段存在', isinstance(res.get('reload'), dict))
check('reload 成功时 ok=True', res.get('reload', {}).get('ok') is True,
      str(res.get('reload')))

# ══════════════════════════════════════════════════════════════
# 3. 显示名 与 uci 段名 的分离（.232 实测的硬约束）
# ══════════════════════════════════════════════════════════════
sec('3. 显示名与段名分离（uci 不接受非 ASCII 段名）')

reset_cfg()
res = dhcp_hosts.add_dhcp_host('客厅 电视', 'aa:bb:cc:dd:ee:02',
                               '192.168.100.12')
check('带空格的显示名能写进去', res.get('name') == '客厅 电视')
check('段名仍然是 ASCII（uci 才吃得下）',
      all(ord(c) < 128 for c in res.get('section', '')),
      'section=%r' % res.get('section'))
check('带空格的值在文件里被引号包住',
      "\toption name '客厅 电视'" in cfg_text())

reset_cfg()
res = dhcp_hosts.add_dhcp_host("O'Brien", 'aa:bb:cc:dd:ee:03',
                               '192.168.100.13')
check('含单引号的显示名能写进去（uci 自己转义）',
      res.get('name') == "O'Brien", 'name=%r' % res.get('name'))
check('文件里单引号被转义（不是裸单引号）',
      "option name 'O'\\''Brien'" in cfg_text())


# ══════════════════════════════════════════════════════════════
# 4. 查重 —— 同一个 MAC 不能绑两次
# ══════════════════════════════════════════════════════════════
sec('4. 查重')

reset_cfg()
dhcp_hosts.add_dhcp_host('设备一', 'aa:bb:cc:dd:ee:04', '192.168.100.14')
before = cfg_bytes()
e = expect_error(dhcp_hosts.add_dhcp_host, '设备二', 'aa:bb:cc:dd:ee:04',
                 '192.168.100.15')
check('同 MAC 再绑一次 ⇒ 被拒绝', isinstance(e, dhcp_hosts.DhcpWriteError),
      str(e) if e else '没抛异常')
check('同 MAC 再绑 ⇒ 文件没变', cfg_bytes() == before)

# 大小写不同也要认出来（手写配置里 MAC 可能带大写）
reset_cfg()
BASE_UPPER = BASE.replace("option mac 'aa:bb:cc:dd:ee:00'",
                          "option mac 'AA:BB:CC:DD:EE:0A'")
reset_cfg(BASE_UPPER)
before = cfg_bytes()
e = expect_error(dhcp_hosts.add_dhcp_host, '撞车', 'aa:bb:cc:dd:ee:0a',
                 '192.168.100.16')
check('MAC 大小写不同 ⇒ 同样认作重复', isinstance(e, dhcp_hosts.DhcpWriteError),
      str(e) if e else '没抛异常')
check('MAC 大小写不同 ⇒ 文件没变', cfg_bytes() == before)


# ══════════════════════════════════════════════════════════════
# 5. 语法校验失败 ⇒ 自动回滚
# ══════════════════════════════════════════════════════════════
sec('5. 写坏了要自动回滚')

reset_cfg()
before = cfg_bytes()
# 显示名写这个值 ⇒ 假 uci 会故意写出没闭合引号的坏配置
e = expect_error(dhcp_hosts.add_dhcp_host, '__CORRUPT__',
                 'aa:bb:cc:dd:ee:05', '192.168.100.17')
check('配置写坏 ⇒ 抛 DhcpWriteError', isinstance(e, dhcp_hosts.DhcpWriteError),
      str(e) if e else '没抛异常')
check('写坏 ⇒ 文件自动恢复成写前内容', cfg_bytes() == before,
      '当前内容: %r' % cfg_text()[:120])
check('写坏 ⇒ 错误信息说明已回滚', '已回滚' in str(e), str(e))
check('写坏 ⇒ rolled_back 标志为 True',
      getattr(e, 'rolled_back', None) is True)
check('回滚后权限仍是 0600', perm_of(CFG) == 0o600)

# 回滚本身也失败 ⇒ 必须如实上报 rolled_back=False
reset_cfg()
before = cfg_bytes()
orig_restore = dhcp_hosts._restore
dhcp_hosts._restore = lambda backup: False
try:
    e = expect_error(dhcp_hosts.add_dhcp_host, '__CORRUPT__',
                     'aa:bb:cc:dd:ee:06', '192.168.100.18')
finally:
    dhcp_hosts._restore = orig_restore
check('回滚失败 ⇒ rolled_back 标志为 False',
      getattr(e, 'rolled_back', None) is False, str(e))
check('回滚失败 ⇒ 错误信息提示手工恢复',
      '回滚失败' in str(e) and '恢复' in str(e), str(e))


# ══════════════════════════════════════════════════════════════
# 6. 删除
# ══════════════════════════════════════════════════════════════
sec('6. 删除绑定')

reset_cfg()
dhcp_hosts.add_dhcp_host('临时设备', 'aa:bb:cc:dd:ee:07', '192.168.100.19')
check('删除前新段在', "config host 'host_aabbccddee07'" in cfg_text())
res = dhcp_hosts.delete_dhcp_host('host_aabbccddee07')
check('删除成功返回 section', res.get('section') == 'host_aabbccddee07')
check('删除后段没了', "config host 'host_aabbccddee07'" not in cfg_text())
check('删除后原有段还在', "config host 'existing'" in cfg_text())
check('删除也留了备份', len(backups()) >= 1)

before = cfg_bytes()
# ⚠️ 段名必须是合法 ASCII —— 否则会被「格式校验」先拦下，
#    就测不到「段不存在」这条路径了（那是另一个失败模式）。
e = expect_error(dhcp_hosts.delete_dhcp_host, 'no_such_section')
check('删不存在的段 ⇒ 被拒绝', isinstance(e, dhcp_hosts.DhcpWriteError),
      str(e) if e else '没抛异常')
check('删不存在的段 ⇒ 文件没变', cfg_bytes() == before)

for bad in ('a/b', '..', '@host[0]', '中文名', 'has space', ''):
    before = cfg_bytes()
    e = expect_error(dhcp_hosts.delete_dhcp_host, bad)
    check('段名 %r ⇒ 被拒绝（不能拿它当 uci 参数使）' % bad,
          isinstance(e, dhcp_hosts.DhcpWriteError),
          str(e) if e else '没抛异常')
    check('段名 %r ⇒ 文件没变' % bad, cfg_bytes() == before)

# ⚠️ 中文段名必须被**格式校验**挡住，而不是拖到 uci 才失败。
#    判据看的是错误信息：若格式校验被删掉，这里会变成
#    「没有名为「中文名」的绑定」（因为段本来就不存在）⇒ 这条会红。
reset_cfg()
e = expect_error(dhcp_hosts.delete_dhcp_host, '中文名')
check('中文段名 ⇒ 报「标识不合法」（说明格式校验真的在拦）',
      isinstance(e, dhcp_hosts.DhcpWriteError) and '不合法' in str(e),
      str(e) if e else '没抛异常')

# 删掉之后同 MAC 可以再绑（说明没留下残留）
reset_cfg()
dhcp_hosts.add_dhcp_host('先建后删', 'aa:bb:cc:dd:ee:08', '192.168.100.20')
dhcp_hosts.delete_dhcp_host('host_aabbccddee08')
res = dhcp_hosts.add_dhcp_host('再建一次', 'aa:bb:cc:dd:ee:08',
                               '192.168.100.20')
check('删掉后同 MAC 可以再绑', bool(res.get('section')),
      'section=%r' % res.get('section'))


# ══════════════════════════════════════════════════════════════
# 7. 重载 dnsmasq —— 失败**不算写失败**，但必须如实告知
# ══════════════════════════════════════════════════════════════
sec('7. 重载 dnsmasq')

reset_cfg()
os.environ['FAKE_DNSMASQ_RC'] = '1'
res = None
e = None
try:
    # ⚠️ 这里**必须**把异常接住 ——
    #   「重载失败不算写失败」这条判据，测的正是「不该抛异常」。
    #   直接调用的话，变异把这里改成抛异常 ⇒ 测试脚本自己崩了
    #   ⇒ 崩了不等于断言失败（2026-11-11 审查 M8）⇒ 那条变异会变成假漏网。
    try:
        res = dhcp_hosts.add_dhcp_host('重载失败设备', 'aa:bb:cc:dd:ee:09',
                                       '192.168.100.21')
    except dhcp_hosts.DhcpWriteError as exc:
        e = exc
finally:
    os.environ.pop('FAKE_DNSMASQ_RC', None)
check('重载失败 ⇒ 没有抛异常（文件是对的）', e is None,
      ('抛了异常: %s' % e) if e else '')
check('重载失败 ⇒ reload.ok=False',
      bool(res) and res.get('reload', {}).get('ok') is False,
      str(res.get('reload')) if res else '没有返回值')
check('重载失败 ⇒ 提示绑定已写入',
      bool(res) and '已写入' in res.get('reload', {}).get('message', ''),
      str(res.get('reload')) if res else '没有返回值')
check('重载失败 ⇒ 绑定确实写进文件了',
      "config host 'host_aabbccddee09'" in cfg_text())

reset_cfg()
saved_init = dhcp_hosts.DNSMASQ_INIT
dhcp_hosts.DNSMASQ_INIT = os.path.join(SANDBOX, 'no-such-dnsmasq')
res = None
e = None
try:
    try:
        res = dhcp_hosts.add_dhcp_host('没有 dnsmasq', 'aa:bb:cc:dd:ee:0b',
                                       '192.168.100.22')
    except dhcp_hosts.DhcpWriteError as exc:
        e = exc
finally:
    dhcp_hosts.DNSMASQ_INIT = saved_init
check('设备上没有 dnsmasq ⇒ 也不算写失败', e is None,
      ('抛了异常: %s' % e) if e else '')
check('设备上没有 dnsmasq ⇒ reload.ok=False',
      bool(res) and res.get('reload', {}).get('ok') is False,
      str(res.get('reload')) if res else '没有返回值')


# ══════════════════════════════════════════════════════════════
# 8. 环境不具备时必须拒绝写
# ══════════════════════════════════════════════════════════════
sec('8. 环境不具备 ⇒ 拒绝写')

reset_cfg()
before = cfg_bytes()
saved_path = os.environ['PATH']
os.environ['PATH'] = EMPTY_BIN_DIR
try:
    e = expect_error(dhcp_hosts.add_dhcp_host, '没 uci', 'aa:bb:cc:dd:ee:0c',
                     '192.168.100.23')
finally:
    os.environ['PATH'] = saved_path
check('没有 uci 命令 ⇒ 被拒绝', isinstance(e, dhcp_hosts.DhcpWriteError),
      str(e) if e else '没抛异常')
check('没有 uci ⇒ 文件没变', cfg_bytes() == before)

reset_cfg()
before = cfg_bytes()
# 备份目录建不出来（它的父级是个普通文件）
not_a_dir = os.path.join(SANDBOX, 'notadir')
with open(not_a_dir, 'w', encoding='utf-8') as f:
    f.write('x')
saved_backup = dhcp_hosts.BACKUP_DIR
dhcp_hosts.BACKUP_DIR = os.path.join(not_a_dir, 'backup')
try:
    e = expect_error(dhcp_hosts.add_dhcp_host, '没备份', 'aa:bb:cc:dd:ee:0d',
                     '192.168.100.24')
finally:
    dhcp_hosts.BACKUP_DIR = saved_backup
check('备份目录建不出来 ⇒ 被拒绝（没有备份就不许改）',
      isinstance(e, dhcp_hosts.DhcpWriteError), str(e) if e else '没抛异常')
check('备份目录建不出来 ⇒ 文件没变', cfg_bytes() == before)

reset_cfg()
before = cfg_bytes()
os.environ['FAKE_UCI_FAIL_COMMIT'] = '1'
try:
    e = expect_error(dhcp_hosts.add_dhcp_host, 'commit 失败',
                     'aa:bb:cc:dd:ee:0e', '192.168.100.25')
finally:
    os.environ.pop('FAKE_UCI_FAIL_COMMIT', None)
check('uci commit 失败 ⇒ 被拒绝', isinstance(e, dhcp_hosts.DhcpWriteError),
      str(e) if e else '没抛异常')
check('uci commit 失败 ⇒ 文件恢复成写前内容', cfg_bytes() == before,
      '当前内容: %r' % cfg_text()[:120])
check('uci commit 失败 ⇒ 错误信息说明已回滚',
      isinstance(e, dhcp_hosts.DhcpWriteError) and '已回滚' in str(e), str(e))


# ══════════════════════════════════════════════════════════════
# 9. 配置根本不存在
# ══════════════════════════════════════════════════════════════
sec('9. 没有配置文件')

reset_cfg()
os.remove(CFG)
before_exists = os.path.exists(CFG)
e = expect_error(dhcp_hosts.add_dhcp_host, '没文件', 'aa:bb:cc:dd:ee:0f',
                 '192.168.100.26')
check('配置文件不存在 ⇒ 被拒绝', isinstance(e, dhcp_hosts.DhcpWriteError),
      str(e) if e else '没抛异常')
check('配置文件不存在 ⇒ 没有被凭空创建',
      os.path.exists(CFG) == before_exists)


# ── 收尾 ─────────────────────────────────────────────────────
shutil.rmtree(SANDBOX, ignore_errors=True)

print('\n' + '=' * 60)
print('  合计: [PASS] %d   [FAIL] %d' % (len(PASS), len(FAIL)))
if FAIL:
    print('  失败项:')
    for n in FAIL:
        print('    - %s' % n)
    print('=' * 60)
    sys.exit(1)
print('  全部通过')
print('=' * 60)
