#!/usr/bin/env python3
"""变异验证：认证网关「唯一公网入口」守卫。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_gateway_guard.py

改的是 tests/test_gateway_entry_guard.py（含前端行为测试）。
判定标准只有一条：**旧代码必然让断言失败**。
断言如果改个变量名就绕过，等于没测。
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
JS = os.path.join(ROOT, 'frontend', 'app.js')
HTML = os.path.join(ROOT, 'frontend', 'index.html')
TEST = os.path.join(ROOT, 'tests', 'test_gateway_entry_guard.py')

SRC = open(APP, encoding='utf-8').read()
JSRC = open(JS, encoding='utf-8').read()
HSRC = open(HTML, encoding='utf-8').read()

APP_MUTANTS = [
    # ── 缺陷本体：/api/config 不再剔除网关字段 ─────────────────────────
    ('/api/config 不再剔除 gateway_enabled（缺陷本体第 2 步）',
     "    ignored = sorted(k for k in incoming if k in GATEWAY_OWNED_CONFIG_KEYS)\n"
     "    for k in GATEWAY_OWNED_CONFIG_KEYS:\n"
     "        incoming.pop(k, None)",
     "    ignored = []"),

    # ── 只读键不剔除：GET 多给的视图会随前端回传落盘 ──────────────────
    ('/api/config 不再丢弃只读键',
     "    for k in READONLY_CONFIG_KEYS:\n"
     "        incoming.pop(k, None)",
     "    pass"),

    # ── 下发后不校验端口：.224 那次「回 200 但入口已死」 ────────────────
    # 校验点在 _deploy_gateway_nginx 内部（两个调用点共用），端点只负责
    # 把失败原因翻译成错误码。这两组变异分别打这两层。
    ('_deploy_gateway_nginx 内部的端口校验被整个拿掉（反代 CRUD 那条路失守）',
     "        if enabled:\n"
     "            actual = _gateway_actual_state(config, settle=True)\n"
     "            if not actual['enabled']:",
     "        if False:\n"
     "            actual = _gateway_actual_state(config, settle=True)\n"
     "            if not actual['enabled']:"),

    # 2026-10-15 外部代码审查抓到：紧挨 nginx -s reload 就探测端口会误报。
    # 首次启用 / 改 gateway_port 时那是个**新增监听口**，master 还要
    # 建 socket、起 worker，探测会撞在 ECONNREFUSED 窗口里，
    # 把一次成功的部署误判成失败并回滚。
    ('端口探测去掉退避重试（首次启用/改端口时会误报部署失败）',
     "            actual = _gateway_actual_state(config, settle=True)\n"
     "            if not actual['enabled']:",
     "            actual = _gateway_actual_state(config, settle=False)\n"
     "            if not actual['enabled']:"),

    ('内部校验只认文件在不在（端口没人监听也算部署成功）',
     "            if not actual['enabled']:\n"
     "                why = []",
     "            if not actual['nginx_conf_exists']:\n"
     "                why = []"),

    ('端点不检查 deploy 结果就落盘（分叉被固化）',
     "    deploy_ok, deploy_msg = _deploy_gateway_nginx(new_cfg)\n"
     "    if not deploy_ok:",
     "    deploy_ok, deploy_msg = _deploy_gateway_nginx(new_cfg)\n"
     "    if False:"),

    ('端点不再把失败归类成 GATEWAY_NOT_LISTENING（前端看不出是哪种坏）',
     "        not_listening = deploy_msg.startswith(GATEWAY_NOT_LISTENING_MSG.split('{')[0])",
     "        not_listening = False"),

    # ── actual 判据：只看文件在不在，就会漏掉「文件在但没 reload」 ─────
    ('_gateway_actual_state 只看文件在就不算「文件在但没人听」（.224 那次）',
     "        'enabled': bool(exists and listening),",
     "        'enabled': bool(exists),"),

    ('_gateway_actual_state 不看端口，只看文件',
     "    listening = _gateway_port_alive(port=port)",
     "    listening = True"),

    # ── 端口查错：回到硬编码 8443 ─────────────────────────────────────
    ('_gateway_port_alive 退回硬编码 GATEWAY_PORT（用户改端口后查错对象）',
     "        port = _safe_port(config.get('gateway_port'), 8443)\n"
     "    try:\n"
     "        with socket.create_connection(('127.0.0.1', int(port)), timeout=3):",
     "        port = GATEWAY_PORT\n"
     "    try:\n"
     "        with socket.create_connection(('127.0.0.1', int(port)), timeout=3):"),

    # ── 状态接口不揭穿分叉 ─────────────────────────────────────────────
    ('/api/gateway/status 不返回 actual',
     '            "actual": actual,',
     '            "actual": None,'),

    ('divergent 恒为 False（面板继续骗人）',
     '            "divergent": bool(config.get("gateway_enabled")) != bool(actual.get("enabled")),',
     '            "divergent": False,'),

    # ── 字段归属表不完整 ───────────────────────────────────────────────
    ('GATEWAY_OWNED_CONFIG_KEYS 漏掉 gateway_port（端口可被绕过下发改掉）',
     "    'gateway_enabled',\n    'gateway_port',",
     "    'gateway_enabled',"),

    ('GATEWAY_OWNED_CONFIG_KEYS 漏掉 auth_lan_bypass',
     "    'auth_lan_bypass',\n})",
     "})"),

    # ── /api/config GET 不给只读视图，前端无从显示分叉 ─────────────────
    ('/api/config GET 不再带 luci_actual',
     "                       luci_actual=luci_actual,",
     "                       luci_actual=None,"),

    # ── 2026-10-16：「网关开着 + LAN 内免登录」的警告被拿掉 ────────────
    # fresh install 实测：全新装出来的机器天然落在这个组合上（DEFAULT_CONFIG
    # 的 auth_lan_bypass 默认 True，setup.sh 不写这个键），无凭据访问
    # /auth/portal 返 200 并吐出完整门户数据。这条警告是用户拍板要的唯一防线，
    # 拿掉它等于回到「装出来什么用户不知道」。
    ('/api/gateway/config 不再对「LAN 内免登录」发出警告',
     "    if new_cfg.get(\"gateway_enabled\") and new_cfg.get(\"auth_lan_bypass\"):",
     "    if False:"),

    # 只判 gateway_enabled、不看 bypass —— 会漏掉「已开的网关上单独打开
    # 免登录」这一路，那才是更危险的一次（拿掉一层已经生效的保护）。
    ('警告只判网关开没开，漏掉单独打开免登录的情况',
     "    if new_cfg.get(\"gateway_enabled\") and new_cfg.get(\"auth_lan_bypass\"):",
     "    if new_cfg.get(\"gateway_enabled\"):"),
]

JS_MUTANTS = [
    # ── 前端守卫被删：回到「表单默认值当用户意图」 ─────────────────────
    ('saveGatewayConfig 不再检查 gwLoaded（硬编码默认值又流进破坏性写）',
     "      if (!this.gwLoaded) {\n"
     "        this.showToast('网关状态还没加载完成，刷新状态后再保存', 'error');\n"
     "        return;\n"
     "      }",
     "      // guard removed"),

    # ── 关闭网关的确认退回旧条件（只在没服务时才问） ───────────────────
    ('关闭网关的确认退回旧条件「只有没服务时才问」',
     "      if (!this.gw.gateway_enabled) {",
     "      if (!this.gw.gateway_enabled && !this.rp.rules.length) {"),

    ('确认框不再点明「唯一公网入口」',
     "          + '它是本项目唯一的公网入口 —— 一旦关闭，除非你人在局域网内，'\n"
     "          + '否则将无法再连回这台机器。\\n\\n确定要关闭吗？'",
     "          + '确定要关闭吗？'"),

    # ── 读取失败不再锁死提交 ───────────────────────────────────────────
    ('状态读取失败后仍放行提交',
     "        this.gwLoaded = false;\n"
     "        this.gwActual = null;\n"
     "        this.gwStatus = '状态读取失败：' + e.message;",
     "        this.gwLoaded = true;\n"
     "        this.gwActual = null;\n"
     "        this.gwStatus = '状态读取失败：' + e.message;"),

    # ── 加载成功后不置 gwLoaded（守卫永远锁死，功能反而坏了） ──────────
    ('loadGatewayStatus 成功后不置 gwLoaded',
     "        this.gwLoaded = true;\n"
     "        this.gwActual = g.actual || null;",
     "        this.gwLoaded = false;\n"
     "        this.gwActual = g.actual || null;"),

    # ── 只读视图不剥离，随 config 回传 ─────────────────────────────────
    ('loadConfig 不剥离只读键（它们会被原样回传）',
     "        delete data.luci_actual;\n"
     "        delete data.luci_ports_listening;\n"
     "        delete data.gateway_actual;",
     "        // not stripped"),

    # ── 状态文案不再提「未监听」 ───────────────────────────────────────
    ('gwStatus 不再点明公网入口未监听',
     "          + (a ? (a.enabled ? ' · 公网入口在线' : ' · ⚠️ 公网入口实际未监听') : '');",
     "          + '';"),

    # ── 2026-10-16：启用侧的 LAN 免登录确认被拿掉 ──────────────────────
    # 后端也会独立判一次，但那只是响应里多一句 warning —— 走面板的人
    # 点一下保存就已经把网关开起来了，警告只是 toast。这道 confirm 才是
    # 真正停下来让人看一眼的那一步。
    ('saveGatewayConfig 不再就「LAN 内免登录」要求确认',
     "      if (this.gw.gateway_enabled && this.gw.auth_lan_bypass) {",
     "      if (false) {"),

    # 只判 enabled 不判 bypass，warning 的 toast 也就不再触发
    ('保存后不再显示后端返回的 warning',
     "        const warned = (r && r.data && r.data.warning)",
     "        const warned = null && (r && r.data && r.data.warning)"),
]

HTML_MUTANTS = [
    ('网关开关不再受 gwLoaded 约束',
     '                <input type="checkbox" x-model="gw.gateway_enabled"\n'
     '                       :disabled="!gwLoaded || gwSaving" class="mt-1">',
     '                <input type="checkbox" x-model="gw.gateway_enabled" class="mt-1">'),

    ('保存按钮不再受 gwLoaded 约束',
     '                :disabled="gwSaving || !gwLoaded"',
     '                :disabled="gwSaving"'),

    ('网关分叉告警区被删（界面继续骗人）',
     '          <div x-show="gwActual && gw.gateway_enabled && !gwActual.enabled"',
     '          <div x-show="false"'),

    ('LuCI 分叉告警区被删',
     '          <div x-show="luciActual !== null && !!config.luci_enabled !== luciActual"',
     '          <div x-show="false"'),

    ('说明里不再点明唯一公网入口',
     '而且这是本项目唯一的公网入口 —— 不在局域网内就再也连不回来。',
     '关掉也没关系。'),
]


def run_test():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, TEST], capture_output=True,
                          text=True, timeout=300, env=env)


def report(name, r):
    fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
    # 变异让代码自己崩掉也算抓到 —— 崩掉正是要防的事。
    if r.returncode != 0 and (fails or r.stderr.strip()):
        detail = (fails[0][:86] if fails
                  else ('测试崩溃: ' + r.stderr.strip().splitlines()[-1][:70]))
        print(f'  ✅ 抓住 {name}')
        print(f'        首个失败: {detail}')
        return True
    print(f'  ❌ 漏过 {name}')
    return False


def main():
    print('=' * 74)
    print('变异验证：认证网关公网入口守卫')
    print('=' * 74)
    base = run_test()
    if base.returncode != 0:
        print('❌ 基线没过：')
        print(base.stdout[-3000:])
        if base.stderr:
            print(base.stderr[-1500:])
        return 1
    print(f'基线通过 {base.stdout.count("✅")} 条断言\n')

    caught, noanchor = 0, []
    try:
        for label, path, src, mutants in (
            ('后端', APP, SRC, APP_MUTANTS),
            ('前端 JS', JS, JSRC, JS_MUTANTS),
            ('前端 HTML', HTML, HSRC, HTML_MUTANTS),
        ):
            for name, old, new in mutants:
                if old not in src:
                    print(f'  ⚠️  锚点未命中 [{label}]: {name}')
                    noanchor.append(name)
                    continue
                open(path, 'w', encoding='utf-8').write(src.replace(old, new, 1))
                caught += report(name, run_test())
                open(path, 'w', encoding='utf-8').write(src)
    finally:
        open(APP, 'w', encoding='utf-8').write(SRC)
        open(JS, 'w', encoding='utf-8').write(JSRC)
        open(HTML, 'w', encoding='utf-8').write(HSRC)

    total = len(APP_MUTANTS) + len(JS_MUTANTS) + len(HTML_MUTANTS)
    print('\n' + '=' * 74)
    print(f'变异 {total} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
    if noanchor:
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    print('全部变异均被捕获' if caught == total else '有变异漏过')
    return 0 if caught == total else 1


if __name__ == '__main__':
    sys.exit(main())
