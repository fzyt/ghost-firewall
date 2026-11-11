#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批 B（部署语义）的行为级测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_deploy_semantics_batch_b.py

测三条
------
S2  部署换完文件后，面板服务必须**重启** —— 否则新代码根本没进到运行中的进程里
L7  生成 DDNS 脚本失败时，接口要如实回报「配置已保存，但脚本生成失败」
L11 面板侧写脚本要**原子替换**，不能把旧脚本截断成半截

为什么这三条都必须是行为级判据
------------------------------
S2：2026-11-11 在 .232 真机实测过 —— app.py 落盘时刻 12:54，
    面板进程启动时刻 12:34（进程比文件还早 20 分钟）⇒ **新代码没进到运行中的
    进程里**。面板侧改的东西在真机上一样没生效，现象照旧 ⇒ 极易被误判成「没修好」。
    ⚠ 服务阶段的判据是「端口在听」—— 旧进程也在听 ⇒ 判成「已完成」⇒ 跳过 ⇒ 不重启。
    ⇒ 端口在听**证明不了**跑的是新代码。判据只能是「部署之后到底有没有执行 restart」。

L7：原来 `_generate_ddns_update_script()` 抛异常 ⇒ 接口 500 ⇒ 用户以为
    「配置没保存」⇒ 反复重存（还可能覆盖别的字段）；而配置其实**已经落盘**了。
    ⇒ 判据：失败时消息要同时说清「配置已保存」和「脚本生成失败」，
    并且配置文件确实落盘。

L11：原来直接 `open(path,'w')` 覆盖写 —— 写到一半进程被杀 / 磁盘满 ⇒
    设备上留下**半截脚本**，旧版本也被截断、没法回退 ⇒ 下次 cron 直接报错，
    DDNS 从此彻底不动，而且现场被毁。
    ⇒ 判据：替换发生时目标文件**仍是旧内容**（证明新内容没直接写进目标路径），
    且替换后目录里没有 .tmp 残留。

⚠ 本文件只读仓库里的源码、只在临时目录里写东西：
  不碰 `/opt/nftables-web-v2`，不碰 `/etc/nftables`，不动 crontab。
"""
import importlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')
BACKEND = os.path.join(ROOT, 'backend')
APP_PY = os.path.join(BACKEND, 'app.py')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name
          + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


# ============================================================
# 沙箱工具
# ============================================================

def make_sandbox(with_initd=True, initd_rc=0):
    """搭一个「设备安装目录」沙箱。

    返回 (沙箱根, INSTALL_DIR, INITD 路径, 重启标记文件)
    """
    d = tempfile.mkdtemp(prefix='batchb-')
    inst = os.path.join(d, 'opt-nftables-web-v2')
    os.makedirs(inst)
    marker = os.path.join(d, 'restart-marker.txt')
    initd = os.path.join(d, 'init.d', 'nftables-web')
    os.makedirs(os.path.dirname(initd))
    if with_initd:
        # 假 init 脚本：把被调用的参数记到标记文件里
        with open(initd, 'w', encoding='utf-8') as f:
            f.write('#!/bin/sh\necho "called: $@" >> "%s"\nexit %d\n'
                    % (marker, initd_rc))
        os.chmod(initd, 0o755)
    return d, inst, initd, marker


def make_source_tree(root):
    """造一个「待部署的项目目录」。

    deploy_project 要求源目录里有 backend/ 和 frontend/，否则直接 die。
    """
    src = os.path.join(root, 'src-project')
    os.makedirs(os.path.join(src, 'backend'))
    os.makedirs(os.path.join(src, 'frontend'))
    with open(os.path.join(src, 'backend', 'app.py'), 'w', encoding='utf-8') as f:
        f.write('# 沙箱里的假 app.py\n')
    with open(os.path.join(src, 'frontend', 'index.html'), 'w', encoding='utf-8') as f:
        f.write('<!doctype html>\n')
    with open(os.path.join(src, 'VERSION'), 'w', encoding='utf-8') as f:
        f.write('0.0.0-batchb-sandbox\n')
    return src


def make_setup_script(inst, initd, extra='', call=None, url_rewrite=None):
    """把 setup.sh 拷进沙箱并改掉**路径常量**，末尾调用指定函数。

    ⚠ 只改路径常量与 URL，被测的函数体一个字节都没动
      （不给生产脚本加测试专用开关 —— 那会让生产代码多出一条分支）。
    """
    src = open(SETUP, encoding='utf-8').read()
    src = src.replace('\nmain "$@"\n', '\n')
    for old, new in (
            ('INSTALL_DIR="/opt/nftables-web-v2"', 'INSTALL_DIR="%s"' % inst),
            ('INITD_SCRIPT="/etc/init.d/nftables-web"', 'INITD_SCRIPT="%s"' % initd)):
        assert src.count(old) == 1, '常量行不唯一（出现 %d 次）: %r' % (src.count(old), old)
        src = src.replace(old, new)
    if url_rewrite:
        old_url, new_url = url_rewrite
        assert src.count(old_url) == 1, 'URL 行不唯一: %r' % old_url
        src = src.replace(old_url, new_url)
    src += extra
    if call:
        src += '\n%s\n' % call
    path = os.path.join(os.path.dirname(inst), 'setup.sh')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    return path


def run_sh(script, env=None, timeout=300):
    """跑沙箱 setup.sh。

    ⚠ stdin 给 DEVNULL ⇒ `[ -t 0 ]` 为假 ⇒ 走非交互分支，
      不会卡在「是否覆盖？」的交互提问上。
    """
    r = subprocess.run(['sh', script], capture_output=True, text=True,
                       timeout=timeout, stdin=subprocess.DEVNULL,
                       env={**os.environ, **(env or {})})
    return r.returncode, (r.stdout + r.stderr)


# ============================================================
# S2：部署之后，面板服务必须重启
# ============================================================

sec('S2-1：本地部署成功后，面板服务确实被重启了')

d1, inst1, initd1, marker1 = make_sandbox(with_initd=True)
src1 = make_source_tree(d1)
script1 = make_setup_script(inst1, initd1,
                             extra='ARG_LOCAL="%s"\n' % src1,
                             call='deploy_project')
rc1, out1 = run_sh(script1)
check('部署脚本退出码为 0', rc1 == 0, out1[-600:])
marker_body1 = (open(marker1, encoding='utf-8').read()
                 if os.path.isfile(marker1) else '')
check('部署后 init 脚本**确实被调用过**（带 restart 参数）',
      'restart' in marker_body1,
      marker_body1.strip() or '标记文件不存在')
check('输出里明确说了「已重启」', '面板服务已重启' in out1, out1[-400:])

sec('S2-2：首次安装（init 脚本还不存在）不报错，也不谎报「已重启」')

d2, inst2, initd2, marker2 = make_sandbox(with_initd=False)
src2 = make_source_tree(d2)
script2 = make_setup_script(inst2, initd2,
                             extra='ARG_LOCAL="%s"\n' % src2,
                             call='deploy_project')
rc2, out2 = run_sh(script2)
check('首次安装时部署退出码为 0', rc2 == 0, out2[-600:])
check('首次安装时**没有**谎报「已重启」', '面板服务已重启' not in out2, out2[-400:])
check('首次安装时**没有**误报「可能未生效」（那时是根本没得重启，不是重启失败）',
      '可能未生效' not in out2, out2[-400:])
check('首次安装时也没留下调用标记', not os.path.exists(marker2))

sec('S2-3：重启失败要如实提示，但**不能**中断安装')

d3, inst3, initd3, marker3 = make_sandbox(with_initd=True, initd_rc=1)
src3 = make_source_tree(d3)
script3 = make_setup_script(inst3, initd3,
                             extra='ARG_LOCAL="%s"\n' % src3,
                             call='deploy_project')
rc3, out3 = run_sh(script3)
check('重启失败时部署仍然算成功（退出码 0）', rc3 == 0, out3[-600:])
check('重启失败时明确提示「新代码可能未生效」', '可能未生效' in out3, out3[-500:])
check('重启失败时**没有**报「已重启」', '面板服务已重启' not in out3, out3[-500:])

sec('S2-4：GitHub 分支（另一条成功路径）同样要重启')

d4, inst4, initd4, marker4 = make_sandbox(with_initd=True)
tarroot = os.path.join(d4, 'tarroot')
os.makedirs(os.path.join(tarroot, 'ghost-firewall-main', 'backend'))
os.makedirs(os.path.join(tarroot, 'ghost-firewall-main', 'frontend'))
with open(os.path.join(tarroot, 'ghost-firewall-main', 'backend', 'app.py'),
          'w', encoding='utf-8') as f:
    f.write('# 沙箱里的假 app.py\n')
with open(os.path.join(tarroot, 'ghost-firewall-main', 'frontend', 'index.html'),
          'w', encoding='utf-8') as f:
    f.write('<!doctype html>\n')
tarball = os.path.join(d4, 'archive.tar.gz')
rc_tar = subprocess.run(['tar', '-czf', tarball, '-C', tarroot,
                          'ghost-firewall-main'],
                         capture_output=True, text=True)
check('沙箱 tar 包制作成功', rc_tar.returncode == 0, rc_tar.stderr[-200:])
script4 = make_setup_script(
    inst4, initd4,
    url_rewrite=('url="https://github.com/${GITHUB_REPO}/archive/refs/heads/main.tar.gz"',
                 'url="file://%s"' % tarball),
    call='deploy_project')
rc4, out4 = run_sh(script4)
check('GitHub 分支部署退出码为 0', rc4 == 0, out4[-700:])
marker_body4 = (open(marker4, encoding='utf-8').read()
                 if os.path.isfile(marker4) else '')
check('GitHub 分支部署后**也**重启了面板服务', 'restart' in marker_body4,
      marker_body4.strip() or ('标记文件不存在：' + out4[-400:]))

sec('S2-5：接线 —— 两个成功分支都得接上重启')

src5 = open(SETUP, encoding='utf-8').read()
m5 = src5.find('\ndeploy_project() {')
if m5 >= 0:
    depth, end = 0, None
    for j in range(m5, len(src5)):
        if src5[j] == '{':
            depth += 1
        elif src5[j] == '}':
            depth -= 1
            if depth == 0:
                end = j
                break
    body5 = src5[m5:end] if end else ''
    check('deploy_project 函数体里 restart_panel_service 出现 **2 次**'
          '（本地分支 + GitHub 分支各一次）',
          body5.count('restart_panel_service') == 2,
          '实际 %d 次' % body5.count('restart_panel_service'))
else:
    check('setup.sh 里能找到 deploy_project()', False)
check('setup.sh 里定义了 restart_panel_service()',
      '\nrestart_panel_service() {' in src5)


# ============================================================
# 面板侧：加载 app 模块
# ============================================================

def load_app():
    """加载面板模块，所有会落盘的路径都指向临时目录。

    照抄 tests/test_aliyun_ddns_update.py 的做法：面板的来源白名单取自
    配置文件，而且是 fail-closed（取不到就拒绝一切来源）⇒ 测试机上没有那份
    配置时，所有请求都会被 403 挡在门外，根本测不到接口本身。
    """
    sys.path.insert(0, os.path.abspath(BACKEND))
    sys.modules.pop('app', None)
    mod = importlib.import_module('app')
    d = tempfile.mkdtemp(prefix='batchb-panel-')
    cfg = os.path.join(d, 'cfg.json')
    with open(cfg, 'w', encoding='utf-8') as f:
        json.dump({
            'lan_subnet4': '127.0.0.0/8',
            'panel_allowed_nets': ['127.0.0.0/8'],
            'auth_session_timeout': 1800,
            'auth_token_epoch': 1,
        }, f)
    mod.CONFIG_PATH = cfg
    mod.LISTS_PATH = os.path.join(d, 'lists.json')
    mod.RULES_PATH = os.path.join(d, 'rules.nft')
    mod.ALIYUN_DDNS_CONFIG_PATH = os.path.join(d, 'aliyun-ddns-config.json')
    return mod


def login(client, appmod):
    """预设一个已登录且世代号匹配的会话（面板接口要登录态）"""
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['username'] = 'admin'
        sess['auth_epoch'] = appmod._current_token_epoch()
        sess['last_active'] = time.time()


def post_save(client, payload):
    """POST 保存接口，返回 (状态码, 响应体)。

    ⚠ 为什么要 try 包住：
      Flask 在测试配置下会把路由里抛出的异常**直接抛给调用方** ——
      那样整个测试脚本会当场崩掉。崩掉虽然也算「变异被捕获」，
      但看不出**是哪条判据**抓到的，也没法继续跑后面的断言。
      包住之后，异常会变成「状态码=None + 响应体为空」，
      判据照样能指出「接口没如实回报」。
    """
    try:
        resp = client.post('/api/aliyun-ddns/save', json=payload)
        return resp.status_code, (resp.get_json(silent=True) or {})
    except Exception as exc:
        return None, {'__exception__': '%s: %s' % (type(exc).__name__, exc)}


# ============================================================
# L7：生成脚本失败时的接口兜底
# ============================================================

sec('L7：生成脚本失败时，接口如实回报，且配置确实落盘')

app = load_app()
saved_api = app._aliyun_api
saved_cron = app._manage_ddns_cron
saved_gen = app._generate_ddns_update_script
try:
    app._aliyun_api = lambda action, *a, **k: {}
    # ⚠ cron 管理必须打桩：它会真去读改 root 的 crontab
    app._manage_ddns_cron = lambda cfg: (True, 'ok')
    client = app.app.test_client()
    login(client, app)

    payload = {
        'access_key_id': 'AK-batchb',
        'access_key_secret': 'SK-batchb-secret',
        'domain': 'example.com',
        'records': [],
    }

    # ── 失败路径 ────────────────────────────────────────
    def boom():
        raise OSError(28, 'No space left on device')

    app._generate_ddns_update_script = boom
    status, body = post_save(client, payload)
    msg = str(body.get('message', ''))
    check('生成失败时返回非 200', status != 200,
          '实际 %s' % status)
    check('生成失败时 success 为 False', body.get('success') is False, str(body))
    check('消息里说明了「配置已保存」', '配置已保存' in msg, msg)
    check('消息里说明了「脚本生成失败」', '生成失败' in msg, msg)
    check('错误码是 ALIYUN_SCRIPT_GENERATE_FAILED',
          body.get('code') == 'ALIYUN_SCRIPT_GENERATE_FAILED', str(body))
    saved_cfg = {}
    if os.path.isfile(app.ALIYUN_DDNS_CONFIG_PATH):
        with open(app.ALIYUN_DDNS_CONFIG_PATH, encoding='utf-8') as f:
            saved_cfg = json.load(f)
    check('失败时配置**照样落盘了**（access_key_id 在文件里）',
          saved_cfg.get('access_key_id') == 'AK-batchb', str(saved_cfg)[:200])

    # ── 正常路径 ────────────────────────────────────────
    gen_calls = []

    def ok_gen():
        gen_calls.append(1)

    app._generate_ddns_update_script = ok_gen
    status2, body2 = post_save(client, payload)
    check('正常路径返回 200', status2 == 200,
          '实际 %s / %s' % (status2, body2))
    check('正常路径 success 为 True', body2.get('success') is True, str(body2))
    check('正常路径调用了生成函数一次', len(gen_calls) == 1,
          '实际 %d 次' % len(gen_calls))
    check('正常路径消息是「配置已保存」',
          '配置已保存' in str(body2.get('message', '')), str(body2))
finally:
    app._aliyun_api = saved_api
    app._manage_ddns_cron = saved_cron
    app._generate_ddns_update_script = saved_gen


# ============================================================
# L11：面板侧写脚本要原子替换
# ============================================================

sec('L11：面板侧写脚本是原子替换，不会把旧脚本截断成半截')


class OsProxy:
    """包一层 os，专门盯 `os.replace` 被调用的那一刻。

    记下 replace 发生**之前**目标文件的内容 ——
    那是「原子替换」与「直接覆盖写」唯一可观察的差别：
      · 原子替换：replace 之前目标还是**旧内容**（新内容在临时文件里）；
      · 覆盖写：  根本不会调用 replace（内容直接写进了目标）。
    """

    def __init__(self, real):
        self._real = real
        self.replace_calls = []

    def __getattr__(self, name):
        return getattr(self._real, name)

    def replace(self, src, dst):
        try:
            with open(dst, encoding='utf-8') as f:
                before = f.read()
        except OSError:
            before = None
        self.replace_calls.append((src, dst, before))
        return self._real.replace(src, dst)


def load_generate_fn(appmod, script_path, os_module):
    """把面板的 `_generate_ddns_update_script()` 抽出来，改掉输出路径后在沙箱里跑。

    ⚠ 为什么不能直接调 app._generate_ddns_update_script()：
      它写死 `/opt/nftables-web-v2/aliyun-ddns-update.py` ——
      在测试机上那要么不存在（抛错），要么真存在（**污染真实路径**）。
    ⚠ 只改**输出路径常量**这一行，函数其余部分原样执行 ——
      判据落在真实行为上，不是「源码里有没有某段文字」。
    """
    src = inspect.getsource(appmod._generate_ddns_update_script)
    old = 'script_path = "/opt/nftables-web-v2/aliyun-ddns-update.py"'
    assert src.count(old) == 1, '找不到唯一的 script_path 行（生产代码变了？）'
    src = src.replace(old, 'script_path = "%s"' % script_path)
    ns = {'os': os_module}
    exec(compile(src, '<generate>', 'exec'), ns)
    return ns['_generate_ddns_update_script']


d11 = tempfile.mkdtemp(prefix='batchb-gen-')
out11 = os.path.join(d11, 'aliyun-ddns-update.py')
with open(out11, 'w', encoding='utf-8') as f:
    f.write('#!/bin/sh\necho OLD-STALE\n')
os.chmod(out11, 0o755)

proxy11 = OsProxy(os)
fn11 = load_generate_fn(app, out11, proxy11)
fn11()

check('写盘走了 os.replace（原子替换），不是直接覆盖',
      len(proxy11.replace_calls) >= 1,
      'os.replace 调用 %d 次' % len(proxy11.replace_calls))
if proxy11.replace_calls:
    _tmp11, _dst11, before11 = proxy11.replace_calls[0]
    check('替换发生时目标文件**仍是旧内容**（新内容没直接写进目标路径）',
          before11 is not None and 'OLD-STALE' in str(before11),
          repr(before11)[:160])

body11 = open(out11, encoding='utf-8').read()
check('目标文件被换成了新内容', 'OLD-STALE' not in body11)
check('新内容是完整的 cron 脚本', 'UpdateDomainRecord' in body11)
try:
    compile(body11, 'aliyun-ddns-update.py', 'exec')
    ok11, detail11 = True, ''
except SyntaxError as e:
    ok11, detail11 = False, str(e)
check('新内容能被 python3 解析（cron 跑得起来）', ok11, detail11)
mode11 = os.stat(out11).st_mode & 0o777
check('权限是 0755（cron 跑得起来）', mode11 == 0o755, oct(mode11))
leftovers11 = [f for f in os.listdir(d11) if f.endswith('.tmp')]
check('没有 .tmp 残留', not leftovers11, str(leftovers11))

sec('L11-2：目标是软链时，软链本身不能被替换成普通文件')

d11b = tempfile.mkdtemp(prefix='batchb-gen-link-')
real11b = os.path.join(d11b, 'real-ddns.py')
with open(real11b, 'w', encoding='utf-8') as f:
    f.write('#!/bin/sh\necho OLD\n')
link11b = os.path.join(d11b, 'aliyun-ddns-update.py')
os.symlink(real11b, link11b)
fn11b = load_generate_fn(app, link11b, OsProxy(os))
fn11b()
check('软链本身**没有被替换成普通文件**（替换了会写到别处去）',
      os.path.islink(link11b))
tgt11b = open(real11b, encoding='utf-8').read() if os.path.isfile(real11b) else ''
check('真实目标文件被更新了', 'OLD\n' not in tgt11b and 'UpdateDomainRecord' in tgt11b,
      tgt11b[:120])


print('\n' + '=' * 60)
print('  通过 %d / 失败 %d' % (len(PASS), len(FAIL)))
if FAIL:
    print('  失败项: %s' % FAIL)
print('=' * 60)
sys.exit(1 if FAIL else 0)
