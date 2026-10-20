"""uhttpd 版 LuCI 的开关：面板必须能真的关掉 80/443，也必须如实报告状态。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_luci_uhttpd.py

背景
----
2026-10-20 在 `192.168.100.166`（OpenWrt 25.12.5）实测到的事实：

  · 80/443 被 **uhttpd** 占着（`netstat` 显示 `0.0.0.0:80 uhttpd`）
  · `/etc/config/nginx` 里**只有** `config main global`，
    **没有** `_lan` / `_redirect2ssl` 段 —— LuCI 不再由 nginx 提供
  · 面板的 `/api/config` 报 `luci_actual = False`，
    但同一份响应里 `luci_ports_listening = [80, 443]` ⇒ **误报**

误报不只是显示难看：`_luci_reconcile()` 一看「实际 == 期望」就直接返回，
**什么都不做** ⇒ 面板永远关不掉 uhttpd 版 LuCI，而用户以为已经关了。
更糟的是 `setup.sh` 的 `close_luci_ports()` 在这台机器上会打印
「✅ LuCI 80/443 已关闭」——**假的成功**。

修法：`_luci_actual_state()` 与 `_apply_luci_toggle()` 都要认 uhttpd 这条路。

机制（实测自 .166 的 `/etc/init.d/uhttpd`）：

    config_get_bool enabled "$cfg" 'enabled' 1
    [ $enabled -gt 0 ] || return

⇒ `uci set uhttpd.<段>.enabled=0` + `uci commit uhttpd` ⇒ 开机也不起；
再 stop 掉当前实例，80/443 立刻释放。
"""
import importlib.util as ilu
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
# app.py 顶上 `from template_engine import ...` —— 后端目录必须在 sys.path 上
for _p in (os.path.join(ROOT, 'tests'), BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    detail = detail.replace('❌', '[x]').replace('✅', '[v]')
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


# uhttpd 版的典型配置（照抄 .166 实测的形态）
UHTTPD_CONF = """\
config uhttpd 'main'
	list listen_http '0.0.0.0:80'
	list listen_http '[::]:80'
	list listen_https '0.0.0.0:443'
	list listen_https '[::]:443'
	option redirect_https '0'
	option home '/www'
	option rfc1918_filter '1'
	option cgi_prefix '/cgi-bin'
	list lua_prefix '/cgi-bin/luci=/usr/lib/lua/luci/sgi/uhttpd.lua'
	option ubus_prefix '/ubus'

config cert 'defaults'
	option days '397'
"""

# 两个 uhttpd 段（uhttpd 的 init 是 config_foreach，每个段一个实例）
UHTTPD_CONF_TWO = UHTTPD_CONF.replace(
    "config cert 'defaults'",
    "config uhttpd 'extra'\n"
    "\tlist listen_http '0.0.0.0:8080'\n"
    "\toption lua_prefix '/cgi-bin/luci=/usr/lib/lua/luci/sgi/uhttpd.lua'\n"
    "\nconfig cert 'defaults'")

NGINX_CONF_LAN = """\
config server '_lan'
	list listen '0.0.0.0:80'
	option ssl '0'

config server '_redirect2ssl'
	option redirect 'https://$host$request_uri'
"""


class FakeProc:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Recorder:
    """替换 subprocess.run，记录所有发出去的命令。"""

    def __init__(self, uci_values=None):
        self.calls = []
        self.uci_values = uci_values or {}   # {'uhttpd.main.enabled': '1'}

    def __call__(self, args, **kwargs):
        argv = list(args) if isinstance(args, (list, tuple)) else [str(args)]
        self.calls.append(argv)
        if not argv:
            return FakeProc()
        exe = os.path.basename(argv[0])
        if exe == 'uci':
            if len(argv) >= 3 and argv[1] == 'get':
                key = argv[2]
                if key in self.uci_values:
                    return FakeProc(0, self.uci_values[key] + '\n')
                return FakeProc(1, '', 'uci: Entry not found')
            if len(argv) >= 3 and argv[1] == 'set':
                # ⚠️ 照抄真 uci 的行为：`set` 的参数是 **`name=value` 一个**，
                # 写成 `uci set name value`（两个参数）真 uci 会直接打 usage 报错。
                # 2026-10-20 在 .166 真机上就是这么暴露的 —— 单测里的假 uci
                # 不校验参数个数，于是放过去了。
                if '=' not in argv[2]:
                    return FakeProc(1, '',
                                    'Usage: /sbin/uci [<options>] <command> [<arguments>]')
                return FakeProc(0)
            return FakeProc(0)
        return FakeProc(0)

    def matched(self, needle):
        """出现过包含 needle 的命令吗"""
        return any(needle in ' '.join(c) for c in self.calls)

    def uci_set_args(self):
        """`uci set` 的参数原文（看得出是 name=value 还是 name value）"""
        return [c[2] for c in self.calls
                if len(c) >= 3 and os.path.basename(c[0]) == 'uci' and c[1] == 'set']

    def uci_set_values(self):
        out = {}
        for c in self.calls:
            if len(c) >= 3 and os.path.basename(c[0]) == 'uci' and c[1] == 'set':
                k, _, v = c[2].partition('=')
                out[k] = v
        return out


def load_app(tmpdir, uhttpd_conf=None, nginx_conf=None):
    """把模块的路径常量指到临时目录后加载 app 模块。"""
    os.environ['NFTABLES_WEB_UHTTPD_CONF'] = os.path.join(tmpdir, 'uhttpd')
    os.environ['NFTABLES_WEB_UHTTPD_INIT'] = os.path.join(tmpdir, 'init.d-uhttpd')
    os.environ['NFTABLES_WEB_UCI_BIN'] = os.path.join(tmpdir, 'uci')
    os.environ['NFTABLES_WEB_LUCI_CONF'] = os.path.join(tmpdir, 'nginx')
    os.environ['NFTABLES_WEB_LUCI_SNAPSHOT'] = os.path.join(tmpdir, 'snapshot')
    os.environ['NFTABLES_WEB_NGINX_UTIL'] = os.path.join(tmpdir, 'nginx-util')
    os.environ['NFTABLES_WEB_NGINX_INIT'] = os.path.join(tmpdir, 'init.d-nginx')
    with open(os.environ['NFTABLES_WEB_UHTTPD_CONF'], 'w') as f:
        f.write(uhttpd_conf if uhttpd_conf is not None else UHTTPD_CONF)
    with open(os.environ['NFTABLES_WEB_LUCI_CONF'], 'w') as f:
        f.write(nginx_conf if nginx_conf is not None else 'config main global\n')
    # uci / init 脚本 / nginx-util：只要"存在"即可（命令本身被 Recorder 顶掉）。
    # nginx-util 必须存在 —— _luci_reload_nginx() 先 os.path.exists 它，
    # 不存在就直接判失败（那是"没装 nginx-full"，不是"LuCI 关不掉"）。
    for p in (os.environ['NFTABLES_WEB_UHTTPD_INIT'],
              os.environ['NFTABLES_WEB_UCI_BIN'],
              os.environ['NFTABLES_WEB_NGINX_UTIL'],
              os.environ['NFTABLES_WEB_NGINX_INIT']):
        with open(p, 'w') as f:
            f.write('#!/bin/sh\nexit 0\n')
        os.chmod(p, 0o755)

    spec = ilu.spec_from_file_location('_luciapp_uhttpd', os.path.join(BACKEND, 'app.py'))
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    tmp = tempfile.mkdtemp(prefix='luci-uhttpd-')

    # ── 1. 识别：uhttpd 是不是 LuCI 的提供方 ───────────────────
    sec('1. 识别 uhttpd 版 LuCI')
    app = load_app(tmp)
    check('uhttpd 配置带 lua_prefix /cgi-bin/luci ⇒ 认得出来',
          app._uhttpd_serves_luci() is True)
    check('uhttpd 段名解析正确',
          app._uhttpd_sections() == ['main'], str(app._uhttpd_sections()))

    app2 = load_app(tmp, uhttpd_conf="config uhttpd 'main'\n\toption home '/www'\n")
    check('没有 lua_prefix ⇒ 不认成 LuCI 提供方',
          app2._uhttpd_serves_luci() is False)

    # ── 2. 多段：uhttpd 的 init 是 config_foreach，每段一个实例 ──
    sec('2. 多个 uhttpd 段都要认（关了就得全关）')
    app3 = load_app(tmp, uhttpd_conf=UHTTPD_CONF_TWO)
    check('两个 uhttpd 段都解析出来了',
          app3._uhttpd_sections() == ['main', 'extra'], str(app3._uhttpd_sections()))

    # ── 3. enabled 语义：没有这一项 = 启用（init 脚本默认 1）────
    sec('3. uhttpd.main.enabled 的语义')
    rec = Recorder({'uhttpd.main.enabled': '1'})
    app.subprocess.run = rec
    check('enabled=1 ⇒ 启用', app._uhttpd_enabled() is True)
    rec = Recorder({})          # uci get 读不到（选项不存在）
    app.subprocess.run = rec
    check('没有 enabled 选项 ⇒ 视为**启用**（init 脚本默认 1）',
          app._uhttpd_enabled() is True)
    rec = Recorder({'uhttpd.main.enabled': '0'})
    app.subprocess.run = rec
    check('enabled=0 ⇒ 禁用', app._uhttpd_enabled() is False)

    # ── 4. 误报修复：uhttpd 提供 LuCI 且在听 ⇒ actual 必须 True ──
    sec('4. 状态判定不许误报（.166 的真 bug）')
    rec = Recorder({'uhttpd.main.enabled': '1'})
    app.subprocess.run = rec
    app._luci_ports_listening = lambda: {80, 443}
    check('uhttpd 在提供 LuCI 且 80/443 在听 ⇒ luci_actual=True',
          app._luci_actual_state() is True,
          f'实际={app._luci_actual_state()}')

    app._luci_ports_listening = lambda: set()
    check('端口没在听 ⇒ luci_actual=False',
          app._luci_actual_state() is False)

    rec = Recorder({'uhttpd.main.enabled': '0'})
    app.subprocess.run = rec
    app._luci_ports_listening = lambda: {80, 443}
    check('enabled=0 ⇒ 即使端口还在听也判 False（已要求关闭）',
          app._luci_actual_state() is False)

    # ── 5. 关闭：uci set 0 + commit + stop ─────────────────────
    sec('5. 关闭 uhttpd 版 LuCI')
    rec = Recorder({'uhttpd.main.enabled': '1'})
    app.subprocess.run = rec
    app._luci_ports_listening = lambda: set()
    ok, msg = app._apply_luci_toggle(False)
    check('关闭返回 ok', ok is True, msg)
    check('uci set uhttpd.main.enabled 0',
          rec.uci_set_values().get('uhttpd.main.enabled') == '0',
          str(rec.uci_set_values()))
    check('uci set 用的是 name=value **一个**参数（真 uci 的语法）',
          all('=' in a for a in rec.uci_set_args()),
          str(rec.uci_set_args()))
    check('uci commit uhttpd', rec.matched('uci commit uhttpd'))
    check('调用了 /etc/init.d/uhttpd stop',
          rec.matched('uhttpd stop'))

    # ── 6. 打开：uci set 1 + commit + start ────────────────────
    sec('6. 重新打开 uhttpd 版 LuCI')
    rec = Recorder({'uhttpd.main.enabled': '0'})
    app.subprocess.run = rec
    app._luci_ports_listening = lambda: {80, 443}
    ok, msg = app._apply_luci_toggle(True)
    check('打开返回 ok', ok is True, msg)
    check('uci set uhttpd.main.enabled 1',
          rec.uci_set_values().get('uhttpd.main.enabled') == '1',
          str(rec.uci_set_values()))
    check('uci commit uhttpd', rec.matched('uci commit uhttpd'))
    check('调用了 uhttpd start', rec.matched('uhttpd start'))

    # ── 7. 两套机制并存时都要处理 ──────────────────────────────
    sec('7. nginx 版 + uhttpd 版并存 ⇒ 两个都处理')
    app4 = load_app(tmp, uhttpd_conf=UHTTPD_CONF, nginx_conf=NGINX_CONF_LAN)
    rec = Recorder({'uhttpd.main.enabled': '1'})
    app4.subprocess.run = rec
    app4._luci_ports_listening = lambda: set()
    ok, msg = app4._apply_luci_toggle(False)
    check('返回 ok', ok is True, msg)
    check('uhttpd 那条路也动了（uci set enabled=0）',
          rec.uci_set_values().get('uhttpd.main.enabled') == '0',
          str(rec.uci_set_values()))
    check('nginx 那条路也动了（_lan 段被摘掉）',
          '_lan' not in app4._uci_conf_text(),
          app4._uci_conf_text()[:80].replace('\n', '|'))

    # ── 8. 机器上根本没有 LuCI ⇒ 如实说「无需处理」 ────────────
    sec('8. 机器上没有 LuCI ⇒ 不谎报')
    app5 = load_app(tmp, uhttpd_conf="config uhttpd 'main'\n\toption home '/www'\n",
                     nginx_conf='config main global\n')
    rec = Recorder({})
    app5.subprocess.run = rec
    app5._luci_ports_listening = lambda: set()
    ok, msg = app5._apply_luci_toggle(False)
    check('返回 ok', ok is True, msg)
    check('说明里讲清楚了「没什么可做」（不许谎报已关闭）',
          '无需' in msg, msg)
    check('**没有**去动 uhttpd（它不是 LuCI 提供方）',
          not rec.matched('uhttpd'), str(rec.calls))

    # ── 9. setup.sh 也得有 uhttpd 分支 ────────────────────────
    #
    # 不然装机时 setup.sh 依然会打「✅ LuCI 80/443 已关闭」——
    # 那是**假的成功**：它 grep 的是 /etc/config/nginx 里的 _lan 段，
    # 而 25.12 的 LuCI 由 uhttpd 提供，那个段压根不存在。
    sec('9. setup.sh 必须认 uhttpd 版 LuCI')
    sh_path = os.path.join(ROOT, 'setup', 'setup.sh')
    sh = open(sh_path, encoding='utf-8').read()
    check('setup.sh 里认得出 uhttpd 版 LuCI（找 /cgi-bin/luci）',
          '/cgi-bin/luci' in sh)
    # ⚠️ 断言要落在**入口那一行**上，不能只查 "/cgi-bin/luci" 这个字符串：
    # 变异脚本把入口改成 `if false; then` 之后，那串 grep 仍然留在块里 ——
    # 只查字符串的断言会**放它过去**（2026-10-20 实测：这条变异就是这么漏过的）。
    check('setup.sh 的 uhttpd 分支入口还在',
          'if [ -f "$uhconf" ] && grep -q "/cgi-bin/luci" "$uhconf" 2>/dev/null; then' in sh)
    check('setup.sh 会把 uhttpd.main.enabled 设成 0',
          'uci set uhttpd.main.enabled=0' in sh)
    check('setup.sh 会 commit uhttpd（开机也不起）',
          'uci commit uhttpd' in sh)
    check('setup.sh 会停掉 uhttpd 实例',
          '/etc/init.d/uhttpd stop' in sh)
    check('setup.sh 不再只认 nginx 的 _lan 段',
          'close_luci_ports' in sh and '_redirect2ssl' in sh)

    print('\n' + '=' * 60)
    print(f' 合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        print(' 有失败')
    else:
        print(' 全部通过')
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
