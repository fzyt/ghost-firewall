#!/usr/bin/env python3
"""变异验证：LuCI 80/443 开关。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_luci.py
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
HTML = os.path.join(ROOT, 'frontend', 'index.html')
SH = os.path.join(ROOT, 'setup', 'setup.sh')
TEST = os.path.join(ROOT, 'tests', 'test_luci_toggle.py')

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
     "LUCI_RENDERED_PATH = '/var/lib/nginx/uci.conf'",
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
     "        if not want_luci and not _gateway_port_alive():",
     "        if False:"),

    ('判据退回「配置变没变」（漏掉实际状态不一致的升级场景）',
     "    if luci_actual is not None and luci_actual != want_luci:",
     "    if bool(new_cfg.get('luci_enabled', False)) != bool(old_cfg.get('luci_enabled', False)):"),

    ('_luci_actual_state 恒返回 False（读不出真实状态）',
     "    names = set(_uci_section_names(_uci_conf_text()))\n"
     "    return bool(names & set(LUCI_SECTIONS))",
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
]

SH_MUTANTS = [
    ('setup.sh 不再调 close_luci_ports',
     "    setup_nftables\n    close_luci_ports\n    show_summary",
     "    setup_nftables\n    show_summary"),
    ('setup.sh 关完不兜底确认 8443',
     'if ! netstat -lnt 2>/dev/null | grep -q \':8443 \'; then',
     'if false; then'),
]

HTML_MUTANTS = [
    ('前端删掉 luci_enabled 开关',
     '<input type="checkbox" x-model="config.luci_enabled" class="mt-1">',
     '<input type="checkbox" class="mt-1">'),
]


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, timeout=240, env=env)


def main():
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
