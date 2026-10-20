#!/usr/bin/env python3
"""变异验证：LuCI 80/443 开关。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_luci.py
"""
import os
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
HTML = os.path.join(ROOT, 'frontend', 'index.html')
SH = os.path.join(ROOT, 'setup', 'setup.sh')
TEST = os.path.join(ROOT, 'tests', 'test_luci_toggle.py')
# 2026-10-20 新增：uhttpd 版 LuCI（OpenWrt 24.10+/25.12）的开关。
# 两个测试文件都要跑 —— 变异可能只被其中一个抓住。
TEST2 = os.path.join(ROOT, 'tests', 'test_luci_uhttpd.py')

SRC = open(APP, encoding='utf-8').read()
HSRC = open(HTML, encoding='utf-8').read()
SSRC = open(SH, encoding='utf-8').read()

APP_MUTANTS = [
    ('只摘 _lan，漏掉 _redirect2ssl（80 仍在监听）',
     "            skipping = nm in drop",
     "            skipping = nm == '_lan'"),

    ('摘除时不以 config 行为块界（会连用户自己的段一起吞掉）',
     "        if s.startswith('config '):\n"
     "            parts = s.split(None, 2)\n"
     "            nm = parts[2].strip() if len(parts) >= 3 else ''\n"
     "            if nm.startswith(\"'\") and nm.endswith(\"'\") and len(nm) >= 2:\n"
     "                nm = nm[1:-1]\n"
     "            skipping = nm in drop",
     "        skipping = False"),

    ('渲染目标退回删软链本身（nginx_init 会静默回落到 nginx.conf）',
     # 锚点必须匹配**当前**的赋值形态。路径常量已改成 os.environ.get(...)，
     # 锚点还停在旧的字面量上 → 变异根本没被应用，脚本会报「锚点未命中」。
     # 这里替换**整条**赋值语句，语义跟改造前完全一致，也不依赖环境变量。
     "LUCI_RENDERED_PATH = os.environ.get(\n"
     "    \"NFTABLES_WEB_LUCI_RENDERED\", \"/var/lib/nginx/uci.conf\")",
     "LUCI_RENDERED_PATH = '/etc/nginx/uci.conf'"),

    ('去掉「端口仍在监听就判失败」的复核（会谎报已关闭）',
     "        left = _luci_ports_listening()\n"
     "        if left:",
     "        left = set()\n"
     "        if left:"),

    ('没有快照时也报「已打开」（实际什么都没做）',
     "    if not os.path.exists(LUCI_SNAPSHOT_PATH):\n"
     "        return False, (f'没有 {LUCI_SNAPSHOT_PATH} 快照",
     "    if False:\n"
     "        return False, (f'没有 {LUCI_SNAPSHOT_PATH} 快照"),

    ('快照每次都覆盖（用户改过的 LuCI 配置会被冲掉）',
     "    if os.path.exists(LUCI_SNAPSHOT_PATH):\n"
     "        return True",
     "    if False:\n"
     "        return True"),

    ('关 LuCI 时不检查网关是否还活着',
     "        if (bool(new_cfg.get('gateway_enabled')) and not want_luci\n"
     "                and not _gateway_port_alive(config=new_cfg)):",
     "        if False:"),

    # 2026-10-15 外部代码审查抓到：守卫没先问「网关启用了没有」。
    # 默认配置 gateway_enabled=False 时，勾掉 LuCI 恒被 500 GATEWAY_DOWN 拒绝，
    # 且 luci_enabled 被改回 True —— 用户想收掉的公网监听口被重新打开。
    ('去掉 gateway_enabled 前置条件（网关未启用时关 LuCI 恒失败并反转用户意图）',
     "        if (bool(new_cfg.get('gateway_enabled')) and not want_luci\n"
     "                and not _gateway_port_alive(config=new_cfg)):",
     "        if (not want_luci\n"
     "                and not _gateway_port_alive(config=new_cfg)):"),

    ('判据退回「配置变没变」（漏掉实际状态不一致的升级场景）',
     "    if luci_actual is not None and luci_actual != want_luci:",
     "    if bool(new_cfg.get('luci_enabled', False)) != bool(old_cfg.get('luci_enabled', False)):"),

    # 锚点跟着源码走：_luci_actual_state 2026-10-20 改成"两种实现都看"，
    # 锚点还停在旧的单行写法上 → 变异根本没被应用（脚本会报「锚点未命中」）。
    ('_luci_actual_state 恒返回 False（读不出真实状态）',
     "    names = set(_uci_section_names(_uci_conf_text()))\n"
     "    if names & set(LUCI_SECTIONS):\n"
     "        return True\n"
     "    return _uhttpd_luci_open()",
     "    return False"),

    ('启动时不再对齐 LuCI',
     "        _moved, _msg = _luci_reconcile(load_config().get('luci_enabled', False))",
     "        _moved, _msg = (False, '跳过')"),

    ('切换失败不回滚配置项（面板显示已关、实际没关）',
     "            new_cfg['luci_enabled'] = old_cfg.get('luci_enabled', False)\n"
     "            try:\n"
     "                save_config(new_cfg)\n"
     "            except OSError:\n"
     "                pass",
     "            pass"),

    ('默认改成开启',
     '    "luci_enabled": False,',
     '    "luci_enabled": True,'),

    ('去掉布尔校验（字符串 "false" 会被当真值 → 用户选了关却被打开）',
     "        if not isinstance(lv, bool):\n"
     "            errs.append(f'luci_enabled 必须是布尔 true/false，实际收到 '",
     "        if False:\n"
     "            errs.append(f'luci_enabled 必须是布尔 true/false，实际收到 '"),

    ('默认参数在定义时求值（路径改不动）',
     "def _uci_conf_text(path=None):",
     "def _uci_conf_text(path=LUCI_CONF_PATH):"),

    # ── uhttpd 版 LuCI（2026-10-20 在 .166 实测挖到）──────────
    ('_luci_actual_state 退回只看 nginx 段（uhttpd 机器上误报"LuCI 没开"）',
     "    names = set(_uci_section_names(_uci_conf_text()))\n"
     "    if names & set(LUCI_SECTIONS):\n"
     "        return True\n"
     "    return _uhttpd_luci_open()",
     "    names = set(_uci_section_names(_uci_conf_text()))\n"
     "    return bool(names & set(LUCI_SECTIONS))"),

    ('_apply_luci_toggle 不再处理 uhttpd（面板永远关不掉 uhttpd 版 LuCI）',
     "    if uhttpd_luci:\n"
     "        ok, msg = _uhttpd_luci_toggle(enabled)\n"
     "        ok_all = ok_all and ok\n"
     "        msgs.append(msg)",
     "    if False:\n"
     "        ok, msg = _uhttpd_luci_toggle(enabled)\n"
     "        ok_all = ok_all and ok\n"
     "        msgs.append(msg)"),

    ('认不出 uhttpd 提供的 LuCI（lua_prefix 判断写错）',
     "    return '/cgi-bin/luci' in _uhttpd_conf_text()",
     "    return False"),

    ('关闭时 uci set 的值写成 1（等于没关）',
     "        val = '1' if enabled else '0'",
     "        val = '1'"),

    ('_uhttpd_enabled 读不到 enabled 时返回 False（误判成"已关"）',
     "    if not vals:\n"
     "        return True          # 没有 enabled 选项 ⇒ 按 init 脚本默认（启用）",
     "    if not vals:\n"
     "        return False"),

    # 2026-10-20 在 .166 真机上暴露：uci set 的语法是 **`name=value` 一个参数**，
    # 写成两个参数（name value）真 uci 直接打 usage。
    # 单测里的假 uci 一开始不校验参数个数 ⇒ 放过去了 ⇒ 现在假 uci 照抄真 uci 的行为。
    ('uci set 用错语法（name value 两个参数 ⇒ 真 uci 打 usage）',
     "f'uhttpd.{s}.enabled={val}'",
     "f'uhttpd.{s}.enabled', val"),
]

SH_MUTANTS = [
    ('setup.sh 不再调 close_luci_ports',
     "    setup_nftables\n    close_luci_ports\n    show_summary",
     "    setup_nftables\n    show_summary"),
    # 兜底从「无条件查 8443」改成「按配置的 gateway_port 查，且只在网关启用时查」。
    # 锚点跟着源码走 —— 锚点对不上时变异会被静默跳过，等于让变异名存实亡。
    ('setup.sh 关完不按配置的网关端口兜底确认',
     'if ! netstat -lnt 2>/dev/null | grep -q ":$gw_port "; then',
     'if ! netstat -lnt 2>/dev/null | grep -q \':8443 \'; then'),

    # 这条正是外部代码审查抓出来的那个：默认 gateway_enabled=false 时
    # 无条件检查 8443，会把刚关掉的 LuCI 又还原回去，部署期自动关闭静默失效。
    ('setup.sh 去掉「网关启用才检查」的前置条件（刚关的 LuCI 会被自己还原）',
     '    if [ "$gw_enabled" = "yes" ] && [ -f /etc/nginx/conf.d/00-nftables-web-gateway.conf ]; then',
     '    if [ -f /etc/nginx/conf.d/00-nftables-web-gateway.conf ]; then'),

    # 2026-10-20 在 .166（OpenWrt 25.12.5）实测：LuCI 由 uhttpd 提供，
    # /etc/config/nginx 里没有 _lan 段 ⇒ setup.sh 会打「✅ LuCI 80/443 已关闭」，
    # 那是**假的成功**（uhttpd 正开着 80/443）。
    ('setup.sh 不再认 uhttpd 版 LuCI（装机时照样报假的"已关闭"）',
     '    if [ -f "$uhconf" ] && grep -q "/cgi-bin/luci" "$uhconf" 2>/dev/null; then',
     '    if false; then'),
]

HTML_MUTANTS = [
    ('前端删掉 luci_enabled 开关',
     '<input type="checkbox" x-model="config.luci_enabled" class="mt-1">',
     '<input type="checkbox" class="mt-1">'),
]


def run_test():
    """跑 LuCI 相关的**全部**测试文件。

    两个文件都要跑：nginx 版那套（test_luci_toggle）和 uhttpd 版那套
    （test_luci_uhttpd）。只跑一个的话，另一套的变异会**漏过** ——
    2026-10-20 扩 uhttpd 支持时就是这么差点漏掉。
    """
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    out, fails, rc = [], [], 0
    for t in (TEST, TEST2):
        r = subprocess.run([sys.executable, t], capture_output=True,
                           text=True, timeout=240, env=env)
        out.append(r.stdout)
        if r.returncode != 0:
            rc = r.returncode
            fails += [l.strip() for l in r.stdout.splitlines() if '❌' in l]
    class _R:
        returncode = rc
        stdout = '\n'.join(out)
        stderr = ''
    return _R()


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print('=' * 74)
    print('变异验证：LuCI 80/443 开关')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('❌ 基线没过：')
        print(base.stdout[-3000:])
        return 1
    print(f'基线通过 {base.stdout.count("✅")} 条断言\n')

    caught, noanchor = 0, []
    try:
        for name, old, new in APP_MUTANTS:
            if old not in SRC:
                print(f'  ⚠️  锚点未命中: {name}')
                noanchor.append(name)
                continue
            open(APP, 'w', encoding='utf-8').write(SRC.replace(old, new, 1))
            r = run_test()
            fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
            if r.returncode != 0 and fails:
                caught += 1
                print(f'  ✅ 抓住 {name}（{len(fails)} 条）')
                print(f'        首个失败: {fails[0][:84]}')
            else:
                print(f'  ❌ 漏过 {name}')
                if r.stderr:
                    print('        ', r.stderr.strip().splitlines()[-1][:84])
            open(APP, 'w', encoding='utf-8').write(SRC)
        for name, old, new in SH_MUTANTS:
            if old not in SSRC:
                print(f'  ⚠️  锚点未命中: {name}')
                noanchor.append(name)
                continue
            open(SH, 'w', encoding='utf-8').write(SSRC.replace(old, new, 1))
            r = run_test()
            fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
            if r.returncode != 0 and fails:
                caught += 1
                print(f'  ✅ 抓住 {name}（{len(fails)} 条）')
                print(f'        首个失败: {fails[0][:84]}')
            else:
                print(f'  ❌ 漏过 {name}')
            open(SH, 'w', encoding='utf-8').write(SSRC)
        for name, old, new in HTML_MUTANTS:
            if old not in HSRC:
                print(f'  ⚠️  锚点未命中: {name}')
                noanchor.append(name)
                continue
            open(HTML, 'w', encoding='utf-8').write(HSRC.replace(old, new, 1))
            r = run_test()
            fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
            if r.returncode != 0 and fails:
                caught += 1
                print(f'  ✅ 抓住 {name}（{len(fails)} 条）')
                print(f'        首个失败: {fails[0][:84]}')
            else:
                print(f'  ❌ 漏过 {name}')
            open(HTML, 'w', encoding='utf-8').write(HSRC)
    finally:
        open(APP, 'w', encoding='utf-8').write(SRC)
        open(SH, 'w', encoding='utf-8').write(SSRC)
        open(HTML, 'w', encoding='utf-8').write(HSRC)

    total = len(APP_MUTANTS) + len(SH_MUTANTS) + len(HTML_MUTANTS)
    print('\n' + '=' * 74)
    print(f'变异 {total} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
    if noanchor:
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    return 0 if caught == total else 1


if __name__ == '__main__':
    sys.exit(main())
