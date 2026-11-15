#!/usr/bin/env python3
"""e2e 点击器的按钮档位守卫。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_e2e_button_guards.py

背景（2026-11-08 .232 真机 e2e 实测）
------------------------------------
``tests/e2e_buttons.js`` 用两条正则给按钮分档：

  · ``NETWORK_PAT``     —— 会改网络/系统状态 ⇒ 默认档**必须跳过**
  · ``DESTRUCTIVE_PAT`` —— 会删数据/改防火墙规则 ⇒ 要显式 --destructive

这两条正则原来是**中文标签 + 少量英文动作名**混着写的，凡是英文动作名和
中文标签对不上就漏网。实测 .232 上 click 档真执行了四个本该跳过的：

  saveNetworkConfig()  → POST /api/network/config 400（.232 无 PPPoE 被按设计拒）
  installIpv6Cron()    → POST /api/network/install-ipv6-cron 200
  restartDdns()        → POST /api/ddns/restart 200
  reloadNginx()        → POST /api/reverse-proxy/nginx/reload 200

前两个归网络级、后两个归破坏性级 —— 也就是说两档防线**各漏了两个**。
静态核对还挖出另外 7 个（运行时不可见，但按钮所在 tab 一激活就会漏）：
uploadRpCert / pickRpReupload / requestRpCert / renewRpCert /
confirmSaveConfig / applyPreset / updateChinaIps。
两条正则合计补了 11 个动作。

其中 saveNetworkConfig 最严重：脚本自己的注释写着 2026-10-06 那次把 .224
搞到整机失联的事故元凶是「togglePppoe() / saveNetworkConfig() / restartNetwork()」
三，**但保护里只有两个**（saveNetworkConfig 从来没进过 NETWORK_PAT）。

所以本文件不只测「某个动作名在不在正则里」，还测**注释与代码是否一致**：
注释里点名要保护的动作，必须真的被保护。这样下次再有人加动作、
顺手在注释里提一句却忘了加进正则，测试会直接失败。

纯静态，不碰浏览器、不碰设备。
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E2E = os.path.join(ROOT, 'tests', 'e2e_buttons.js')

PASS, FAIL = [], []

# JS 内置 / 与按钮分档无关的调用，不参与「注释声明的防线」核对
JS_BUILTINS = {
    'confirm', 'alert', 'prompt', 'if', 'for', 'while', 'switch', 'function',
    'return', 'parseInt', 'parseFloat', 'isNaN', 'Number', 'String', 'Boolean',
    'Array', 'Object', 'Math', 'Date', 'JSON', 'RegExp', 'Error', 'Promise',
    'window', 'document', 'console', 'setTimeout', 'setInterval', 'fetch',
    'encodeURIComponent', 'decodeURIComponent', 'require', 'process',
    # DOM 内置（index.html 里也会出现，但不是应用动作）
    'focus', 'blur', 'click', 'submit', 'open', 'close', 'print',
    'querySelector', 'querySelectorAll', 'getElementById', 'addEventListener',
    'scrollTo', 'scrollIntoView',
}


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def extract_pats(src):
    """取出两条正则的**模式串**（去掉首尾的 / 与 /i;）。"""
    pats = {}
    for line in src.splitlines():
        for name in ('NETWORK_PAT', 'DESTRUCTIVE_PAT'):
            prefix = f'const {name} = /'
            if line.startswith(prefix):
                pats[name] = line[len(prefix):].rsplit('/i;', 1)[0]
    return pats


def strip_js_comments(src):
    """去掉 JS 行注释与块注释（保留字符串字面量里的内容）。"""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            while i < n and src[i] != '\n':
                i += 1
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            i += 2
            while i + 1 < n and not (src[i] == '*' and src[i + 1] == '/'):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def comments_only(src):
    """只保留注释文本（行注释 + 块注释）。"""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            if j == -1:
                j = n
            out.append(src[i:j])
            i = j
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i)
            j = n if j == -1 else j + 2
            out.append(src[i:j])
            i = j
            continue
        i += 1
    return '\n'.join(out)


def index_html_actions():
    """frontend/index.html 里 @click/@submit 真实调用到的动作名集合。

    为什么要「真实存在」这个限定：注释里也会提到 nth()、confirm() 这些
    JS/Playwright 的东西，它们不是应用动作，不该要求被分档保护。
    """
    path = os.path.join(ROOT, 'frontend', 'index.html')
    try:
        with open(path, encoding='utf-8') as f:
            html = f.read()
    except OSError:
        return set()
    exprs = re.findall(r'@click="([^"]*)"', html) + re.findall(r'@submit="([^"]*)"', html)
    names = set()
    for e in exprs:
        for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', e):
            name = m.group(1)
            if name in JS_BUILTINS:
                continue
            names.add(name)
    return names


# 动作名 → (期望档位, 运行时中文标签)
# 档位：net = 网络/系统级（默认档必须跳过）
#       des = 破坏性（要显式 --destructive）
#       normal = 普通（默认档应当执行）
#
# 这张表必须**覆盖 frontend/index.html 里出现的每一个动作**（第 5 组会查）。
# 表里少一个，就等于少一个被审视的按钮 —— 那正是 B1 漏网的土壤。
EXPECT = {
    # ── 网络/系统级：会改网络或系统自身状态 ─────────────────────
    'restartNetwork':     ('net', '重启网络'),
    'saveNetworkConfig':  ('net', '保存网络配置'),
    'saveLanMembers':     ('net', '保存 LAN 成员口'),
    'togglePppoe':        ('net', 'PPPoE 拨号'),
    'installIpv6Cron':    ('net', '安装定时更新'),
    'installChinaIps':    ('net', '安装中国IP'),
    'updateChinaIps':     ('net', '立即刷新中国IP'),
    'repairInitScript':   ('net', '修复 init 脚本'),
    'updateIpv6':         ('net', '立即刷新 IPv6'),
    # ── 破坏性：删数据 / 改防火墙规则 / 改 nginx 运行时 ──────────
    'applyRules':         ('des', '应用规则'),
    'restoreConfig':      ('des', '恢复配置'),
    'flushList':          ('des', '全部清空'),
    'removeDdnsService':  ('des', '删除'),
    'removeForwardRule':  ('des', '删除'),
    'deleteRpRule':       ('des', '删除'),
    'deleteRpCert':       ('des', '删除'),
    'deletePreset':       ('des', '删除'),
    'deleteFromList':     ('des', '删除'),
    'clearListHistory':   ('des', '清空历史'),
    'restartDdns':        ('des', '重启服务'),
    'uploadRpCert':       ('des', '上传证书'),
    'pickRpReupload':     ('des', '重新上传'),
    'requestRpCert':      ('des', '申请证书'),
    'renewRpCert':        ('des', '续期'),
    'reloadNginx':        ('des', '重载 Nginx'),
    'confirmSaveConfig':  ('des', '确认保存'),
    'applyPreset':        ('des', '应用预设'),
    # ── 普通：加载 / 保存 / 打开弹窗 / 编辑 ──────────────────────
    'saveConfig':         ('normal', '保存配置'),
    'saveGatewayConfig':  ('normal', '保存网关配置'),
    'saveRpRule':         ('normal', '保存'),
    'saveRpSettings':     ('normal', '保存'),
    'saveLogdConfig':     ('normal', '保存'),
    'saveDdns':           ('normal', '保存'),
    'saveDdnsService':    ('normal', '保存'),
    'saveAliyunConfig':   ('normal', '保存'),
    'savePreset':         ('normal', '保存预设'),
    'addForwardRule':     ('normal', '添加端口转发规则'),
    'addFwConsole':       ('normal', '添加防火墙控制入口'),
    'addDdnsService':     ('normal', '添加记录'),
    'addToList':          ('normal', '添加'),
    'applyLogFilter':     ('normal', '应用'),
    'cancelDdnsEdit':     ('normal', '取消'),
    'cancelRpEdit':       ('normal', '取消'),
    'cancelSaveConfig':   ('normal', '取消'),
    'closePresetModal':   ('normal', '关闭'),
    'detectRpApiPrefix':  ('normal', '自动探测'),
    'detectRpProtocolRelative': ('normal', '检测协议相对 URL'),
    'doLogout':           ('normal', '退出登录'),
    'downloadRpCert':     ('normal', '下载'),
    'editDdnsService':    ('normal', '编辑'),
    'editRpRule':         ('normal', '编辑'),
    'exportLogs':         ('normal', '导出'),
    'clearLogFilters':    ('normal', '清除筛选'),
    'getLogTotalPages':   ('normal', '末页'),
    'goToLogPage':        ('normal', '下一页'),
    'loadAliyunRecords':  ('normal', '加载'),
    'loadAliyunStatus':   ('normal', '加载'),
    'loadDdns':           ('normal', '通用 DDNS'),
    # 系统信息页的加载（2026-11-08 新增）。
    # 它是**只读采集**，不改任何状态 ⇒ 归 normal 档（不是网络级/破坏性级）。
    'loadDeviceInfo':     ('normal', '刷新'),
    # ── 系统信息页的 DHCP 静态绑定（2026-11-12 新增）──────────
    # saveDhcpHost 会写设备的 /etc/config/dhcp 并重载 dnsmasq
    # deleteDhcpHost 会删掉一条绑定
    # ⇒ 两个都是破坏性档（默认档必须跳过，要显式 --destructive）。
    # ⚠️ saveDhcpHost 的中文标签就是「保存」⇒ 判据靠**英文动作名**
    #   才能把它归到破坏性档（中文「保存」太泛，加进正则会误伤普通保存按钮）。
    'saveDhcpHost':       ('des', '保存'),
    'deleteDhcpHost':     ('des', '删除'),
    # 只读与开窗 ⇒ 普通档
    'loadPublicIp':       ('normal', '查询'),
    'openDhcpHostForm':   ('normal', '新增静态绑定'),
    'loadFirewallStatus': ('normal', '加载'),
    'loadGatewayStatus':  ('normal', '刷新状态'),
    'loadLists':          ('normal', '加载'),
    'loadReverseProxy':   ('normal', '加载'),
    'loadRules':          ('normal', '刷新预览'),
    'loadRulesHealth':    ('normal', '刷新'),
    'loadSystemLogs':     ('normal', '刷新'),
    'loadWanIpv6':        ('normal', '重新查询'),
    'newRpRule':          ('normal', '添加规则'),
    'openPasswordModal':  ('normal', '修改密码'),
    'openPresetModal':    ('normal', '新增预设'),
    'previewRpNginx':     ('normal', '配置预览'),
    'rpAutoHost':         ('normal', '自动生成'),
    'setDefaultCert':     ('normal', '设为默认'),
    'setupAliyun':        ('normal', '初始化'),
    'showDdnsStatus':     ('normal', '查看状态'),
    'testAliyunRecord':   ('normal', '测试'),
    'testNginxConfig':    ('normal', '测试配置'),
    'testRpRule':         ('normal', '测试'),
    'toggleAliyunRecord': ('normal', '启用'),
    'toggleLogLevel':     ('normal', '日志级别'),
}


def main():
    with open(E2E, encoding='utf-8') as f:
        src = f.read()
    pats = extract_pats(src)
    net_pat = pats.get('NETWORK_PAT', '')
    des_pat = pats.get('DESTRUCTIVE_PAT', '')

    # ──────────────────────────────────────────────────────────────
    sec('第 1 组：两条正则都提取得到')
    # ──────────────────────────────────────────────────────────────
    check('NETWORK_PAT 提取到', bool(net_pat), f'长度 {len(net_pat)}')
    check('DESTRUCTIVE_PAT 提取到', bool(des_pat), f'长度 {len(des_pat)}')
    if not net_pat or not des_pat:
        print('\n正则没提取到，后面没法判 —— 直接判失败。')
        print(f'  通过 {len(PASS)} / 失败 {len(FAIL)}')
        return 1

    # ──────────────────────────────────────────────────────────────
    sec('第 2 组：每个动作落在期望档位')
    # ──────────────────────────────────────────────────────────────
    for fn in sorted(EXPECT):
        want, label = EXPECT[fn]
        desc = f'{label} [{fn}()]'
        is_net = bool(re.search(net_pat, desc, re.I))
        is_des = bool(re.search(des_pat, desc, re.I))
        got = 'net' if is_net else ('des' if is_des else 'normal')
        check(f'{fn} 期望 {want}', got == want, f'实际 {got}')

    # ──────────────────────────────────────────────────────────────
    sec('第 3 组：注释与代码必须一致')
    # ──────────────────────────────────────────────────────────────
    # 注释里点名要保护的动作（形如 xxxYyy()），必须真的被两条正则之一覆盖。
    # 这是本文件最重要的一条：2026-10-06 事故的元凶 saveNetworkConfig()
    # 就是「注释里写了三个、代码只保护两个」漏出来的。
    #
    # 口径：**只认 index.html 里真实存在的动作**。注释里提到的 nth()、confirm()
    # 这些是 JS/Playwright 的东西，不是应用动作，不该拿来要求保护。
    real_actions = index_html_actions()
    ctext = comments_only(src)
    mentioned = set()
    for m in re.finditer(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\(\)', ctext):
        name = m.group(1)
        if name in JS_BUILTINS or name not in real_actions:
            continue
        mentioned.add(name)
    uncovered = []
    for name in sorted(mentioned):
        desc = f'{name} [{name}()]'
        if not re.search(net_pat, desc, re.I) and not re.search(des_pat, desc, re.I):
            uncovered.append(name)
    check('注释里提到的每个应用动作都被某条正则覆盖',
          not uncovered,
          f'未覆盖: {uncovered}' if uncovered else f'共核对 {len(mentioned)} 个')

    # 2026-10-06 事故元凶必须三个都在网络级保护里
    trio = ['togglePppoe', 'saveNetworkConfig', 'restartNetwork']
    missing = [t for t in trio
               if not re.search(net_pat, f'{t} [{t}()]', re.I)]
    check('2026-10-06 事故的三个元凶全在 NETWORK_PAT 里',
          not missing,
          f'缺: {missing}' if missing else 'togglePppoe / saveNetworkConfig / restartNetwork')

    # ──────────────────────────────────────────────────────────────
    sec('第 4 组：正则没被写得过宽')
    # ──────────────────────────────────────────────────────────────
    # 「过宽」会让普通保存类按钮被误跳过 —— 看起来是安全，实际是漏测。
    ordinary = [fn for fn, (w, _) in EXPECT.items() if w == 'normal']
    wrongly = []
    for fn in ordinary:
        desc = f'{fn} [{fn}()]'
        if re.search(net_pat, desc, re.I) or re.search(des_pat, desc, re.I):
            wrongly.append(fn)
    check('普通保存/加载类动作没有被误判成破坏性或网络级',
          not wrongly,
          f'误判: {wrongly}' if wrongly else f'共核对 {len(ordinary)} 个')

    # ──────────────────────────────────────────────────────────────
    sec('第 5 组：EXPECT 表不能漏项')
    # ──────────────────────────────────────────────────────────────
    # 表里漏一个动作 = 少一个被审视的按钮 —— B1 漏网正是这么来的。
    unlisted = sorted(set(real_actions) - set(EXPECT))
    check('index.html 里的每个应用动作都在 EXPECT 表里',
          not unlisted,
          f'漏了 {len(unlisted)} 个: {unlisted}' if unlisted
          else f'共核对 {len(real_actions)} 个')
    stale = sorted(set(EXPECT) - set(real_actions))
    check('EXPECT 表里没有 index.html 里已不存在的动作',
          not stale,
          f'多余: {stale}' if stale else '')

    print()
    print('=' * 60)
    print(f'  通过 {len(PASS)} / 失败 {len(FAIL)}')
    if FAIL:
        for f in FAIL:
            print(f'  [FAIL] {f}')
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
