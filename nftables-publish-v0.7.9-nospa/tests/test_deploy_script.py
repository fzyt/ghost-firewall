"""一键部署脚本（tools/deploy.sh）与装机脚本（setup/setup.sh）的硬性约束。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_deploy_script.py

背景
----
2026-10-30 在 `192.168.100.232`（全新 OpenWrt 25.12.5）上跑全新安装路径，
连续踩了四类坑，每一类都足以让一次**本来成功**的部署变成"看起来失败"：

1. **协议用错** —— 认证网关是 Flask 开发服务器，监听 `http://127.0.0.1:8444`
   （**纯 HTTP**，没有 TLS）。自检里对它用 `https://` ⇒ TLS 握手被当成
   HTTP 请求打成 400，body 为空 ⇒ 拿不到任何字段。
   现场证据（设备网关日志）：
       code 400, message Bad request version ('...\\x16\\x03\\x03...')
   ⇒ 一条每次必现、而且**指向错误方向**的假警报。

2. **问错对象** —— `password_set` 这个字段只在**面板**的
   `/api/auth/status` 里（backend/app.py 的 `auth_status()`），
   网关的 `/auth/status` 只返回 `{"authenticated": ...}`，压根没这个字段。
   第一版去问网关 ⇒ 永远问不到。

3. **索引被截断当成"包不存在"** —— 弱网下 apk 把索引文件 `packages.adb`
   拉到一半断线：
       WARNING: fetching .../packages.adb: unexpected end of file
       ERROR: unable to select packages:
         python3-flask (no such package)
   注意它报的是 **no such package** 而不是网络错误 —— 一个纯网络问题
   被伪装成了"这个包不存在"。旧版 `pkg_install` 只试一次就 `warn` 跳过
   ⇒ 这个包**永远**装不上 ⇒ 面板起不来，而报错指向 nginx / 端口，
   跟真正缺的东西八竿子打不着。

4. **单包失败只 warn 不中断** ⇒ setup.sh 一路走到「✅ 依赖安装完成」，
   把一台装不成的机器报成装好了。

这个文件把上面四类坑固化成断言 —— 它们都不是"风格偏好"，
每一条都对应一次**已经发生过的**错误部署。
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(ROOT, 'tools', 'deploy.sh')
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')
APP = os.path.join(ROOT, 'backend', 'app.py')
GATEWAY = os.path.join(ROOT, 'backend', 'auth_gateway.py')

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    detail = detail.replace('❌', '[x]').replace('✅', '[v]')
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


def _regen_body_of(deploy_src):
    """抠出 phase_regen_ddns 的函数体。

    ⚠️ 必须**只**看这个函数体 ——
      deploy.sh 别处（phase_precheck 的语法预检、phase_apply 的应用规则集）
      故意要 `import app`，那两处是 --apply 场景，与生成 cron 脚本无关。
      拿整个文件去搜 `import app` 会把那两个正当用法也算进来 ⇒ 假红。
    """
    m = re.search(r'phase_regen_ddns\(\)\s*\{(.*?)\n\}', deploy_src, re.S)
    return m.group(1) if m else ''


def main():
    deploy = read(DEPLOY)
    setup = read(SETUP)
    app = read(APP)
    gateway = read(GATEWAY)

    # ── 1. 自检里每一次 curl 的协议必须对 ────────────────────────────
    #
    # 三个监听点，三个协议，互不相同：
    #   面板 5443        → https（面板自带自签证书）
    #   网关 8443 (nginx) → https
    #   认证 API 8444    → http（Flask 开发服务器，**没有** TLS）
    sec('1. 自检的协议：三个监听点三个协议')

    curl_lines = [(i + 1, ln) for i, ln in enumerate(deploy.splitlines())
                   if 'curl' in ln and ('http://' in ln or 'https://' in ln)]

    check('deploy.sh 里确实有 curl 调用（否则下面的断言是空的）',
          len(curl_lines) >= 4, f'{len(curl_lines)} 处')

    bad_auth = [(n, ln) for n, ln in curl_lines
                if re.search(r'127\.0\.0\.1:\$\{?auth_port_cfg', ln)
                and 'https://' in ln]
    check('认证 API（8444）的请求一律用 http://（网关是纯 HTTP，没有 TLS）',
          not bad_auth,
          f'违规 {bad_auth[0][0]} 行' if bad_auth else '')

    bad_panel = [(n, ln) for n, ln in curl_lines
                 if re.search(r'PANEL_PORT\}', ln) and 'http://' in ln
                 and 'https://' not in ln]
    check('面板（5443）的请求一律用 https://',
          not bad_panel,
          f'违规 {bad_panel[0][0]} 行' if bad_panel else '')

    # ── 2. password_set 必须问面板，不能问网关 ──────────────────────
    sec('2. password_set 问对对象')

    check('password_set 字段只存在于面板（app.py）',
          'password_set' in app)
    check('网关（auth_gateway.py）里没有 password_set 这个字段',
          'password_set' not in gateway,
          '网关的 /auth/status 只返回 {"authenticated": ...}')

    pset_lines = [(n, ln) for n, ln in enumerate(deploy.splitlines())
                  if 'password_set' in ln and 'curl' in ln]
    check('deploy.sh 取 password_set 的地方存在', len(pset_lines) == 1,
          f'{len(pset_lines)} 处')

    if pset_lines:
        n, ln = pset_lines[0]
        check('取 password_set 的请求打的是面板（/api/auth/status + PANEL_PORT）',
              '/api/auth/status' in ln and 'PANEL_PORT' in ln,
              f'第 {n} 行')
        check('取 password_set 的请求**没有**打网关的 /auth/status',
              not re.search(r'\$\{?AUTH_PORT\}?/auth/status', ln),
              f'第 {n} 行')
        check('取 password_set 的请求没有再用 https 打网关端口',
              'https://127.0.0.1:${AUTH_PORT}' not in deploy)

    # ── 3. 自检不能把"配置未开启"判成失败 ──────────────────────────
    sec('3. 公网入口默认关闭时，自检不得判失败')

    check('自检按 gateway_enabled 开关分支（全新装默认关）',
          'gw_on' in deploy and 'gateway_enabled' in deploy)
    check('网关端口的检查在开关分支里（不在分支外无条件执行）',
          re.search(r'if \[ "\$gw_on" = "1" \].*?gw_port_cfg.*?\n.*?fi', deploy, re.S) is not None)

    # ── 4. setup.sh 的装包必须带重试 + 索引自愈 ─────────────────────
    sec('4. 装包必须重试（索引被截断 ≠ 包不存在）')

    check('pkg_install 不再是"一次就放弃"的写法',
          'apk add --no-cache "$pkg" || warn "安装失败: ${pkg}"' not in setup,
          '旧的一次性写法已消失')
    check('pkg_install 不再是 opkg 的一次性写法',
          'opkg install "$pkg" || warn "安装失败: ${pkg}"' not in setup)

    check('apk 的安装走带重试的 pkg_install_apk',
          re.search(r'apk\)\s+.*?pkg_install_apk\s+"\$pkg"', setup, re.S) is not None)
    check('opkg 的安装走带重试的 pkg_install_opkg',
          re.search(r'opkg\)\s+.*?pkg_install_opkg\s+"\$pkg"', setup, re.S) is not None)

    check('pkg_install_apk 存在且有重试循环',
          'pkg_install_apk()' in setup and 'PKG_RETRY' in setup)
    check('pkg_install_opkg 存在且有重试循环',
          'pkg_install_opkg()' in setup)

    # 关键：重试之前必须先刷索引。坏的 .adb 还在的话，
    # 重试多少次都是 "no such package"。
    apk_fn = setup[setup.index('pkg_install_apk()'):] if 'pkg_install_apk()' in setup else ''
    apk_fn = apk_fn[:apk_fn.index('\n}\n')] if '\n}\n' in apk_fn else apk_fn
    check('apk 重试前会刷新索引（apk update），否则坏索引会让重试全部落空',
          'apk update' in apk_fn,
          '索引自愈是这一段的关键')

    # ── 5. 关键依赖必须"能用"，不能只看"装过了" ────────────────────
    sec('5. 关键依赖的可用性硬校验（不能只 warn）')

    check('setup.sh 有 check_critical_deps', 'check_critical_deps()' in setup)
    check('install_deps 里真的调用了 check_critical_deps',
          re.search(r'install_deps\(\).*?check_critical_deps', setup, re.S) is not None)

    cd_fn = setup[setup.index('check_critical_deps()'):] if 'check_critical_deps()' in setup else ''
    cd_fn = cd_fn[:cd_fn.index('\n}\n')] if '\n}\n' in cd_fn else cd_fn
    check('校验函数里缺依赖时是 die（中断），不是 warn（放过）',
          'die ' in cd_fn and 'import flask' in cd_fn and 'import requests' in cd_fn)
    check('校验函数里也查 nginx（网关的承载体）',
          'nginx' in cd_fn)

    check('「依赖安装完成」不再无条件打印（校验通过后才打）',
          re.search(r'check_critical_deps\s*\n\s*}\s*\n\s*ok "✅ 依赖安装完成"', setup) is None)

    # ── 6. 装机脚本里那几个只在重置机器上暴露的修正 ──────────────────
    sec('6. 重置机器上暴露过的坑（回归护栏）')

    check('配置写成 0640（网关是独立进程读同一份配置，0600 它读不到）',
          'chmod 640' in setup and 'chgrp nftweb' in setup)
    check('版本号从同级的 VERSION 文件读，不是写死的',
          re.search(r'_VERSION_FILE=.*\n.*_v=.*cat|_VERSION_FILE=.*VERSION', setup) is not None
          and 'VERSION="unknown"' in setup,
          '兜底值是 unknown，不是某个具体版本号')
    check('版本号不是写死的字面量 0.7.9.1',
          not any('0.7.9.1' in ln for ln in setup.splitlines()
                  if not ln.strip().startswith('#')),
          '注释里可以举这个例子说明为什么不能写死')

    init_path = os.path.join(ROOT, 'backend', 'nftables-web-auth.init')
    init = read(init_path)
    check('网关的 init 脚本放行 nftables-web-config.json（组可读名单里）',
          'nftables-web-config.json' in init)
    # 组可读名单就是那行 `for f in ...; do` —— 名单里**不能**有 session-secret
    grp_loop = re.search(r'for f in ([^;]+); do', init)
    check('网关的 init 脚本里找得到组可读名单', grp_loop is not None)
    if grp_loop:
        names = grp_loop.group(1)
        check('组可读名单里有 nftables-web-config.json（网关要读共享配置）',
              'nftables-web-config.json' in names, names.strip())
        check('组可读名单里有 nftables-web-password（网关要校验口令）',
              'nftables-web-password' in names, names.strip())
        check('组可读名单里**没有** nftables-web-session-secret',
              'session-secret' not in names,
              '会话签名密钥必须只有 root 能读')
    check('session-secret 被显式 chown 0:0 + chmod 600',
          re.search(r'chown 0:0 "\$_sesssecret"', init) is not None
          and re.search(r'chmod 600 "\$_sesssecret"', init) is not None)

    # ── 7. deploy.sh 的硬规矩 ───────────────────────────────────────
    sec('7. deploy.sh 的硬规矩')

    check('部署前后比对令牌密钥 md5（变了 = 所有设备令牌作废）',
          'TOKEN_SECRET_MD5_BEFORE' in deploy
          and re.search(r'if \[ "\$after" = "\$TOKEN_SECRET_MD5_BEFORE" \]', deploy) is not None)
    check('不删配置目录（只覆盖不删除）',
          not re.search(r'rm -rf\s+[\'"]?\$?\{?CFG_DIR', deploy),
          '配置/口令/密钥一个都不能碰')
    # 注释里可以出现 `rm -rf $APP`（那是在说明**不能**这么干），
    # 所以只看真正会执行的命令行。
    exec_lines = [ln for ln in deploy.splitlines()
                  if not ln.strip().startswith('#')]
    exec_text = '\n'.join(exec_lines)
    check('没有 rm -rf 掉整个 APP_DIR',
          not re.search(r'rm -rf\s+[\'"]?\$?\{?APP_DIR[\'"]?(\s|$)', exec_text)
          and 'rm -rf $APP ' not in exec_text
          and 'rm -rf $APP"' not in exec_text)
    check('不重启路由器（只重启两个服务）',
          'reboot' not in deploy and 'restart' in deploy)
    check('失败会自动回滚',
          'do_rollback' in deploy and 'restore.sh' in deploy)
    check('升级路径默认不动线上规则（--apply 才应用）',
          'APPLY' in deploy and 'phase_apply' in deploy)

    # ── 8. acme.sh DNS 插件的下载不能白烧时间 ────────────────────────
    #
    # 2026-10-30 在 .232 实测：raw.githubusercontent.com 在国内是**间歇性**可达的
    # （同一台机器 12:07 一次 curl 0.365 秒通了，12:11 同样命令连接直接超时）。
    # 旧版 `--max-time 60 --retry 2` ⇒ 一个插件最坏 3 分钟，6 个 = 18 分钟纯等待，
    # 最后还一个都没下下来。而 acme.sh 在 Gitee 上有官方镜像，实测 200 / 0~1 秒。
    sec('8. acme.sh DNS 插件：多源 + 快速失败 + 有界耗时')

    # 只切**插件下载循环**那一段（acme 主脚本的下载是另一回事，
    # 参数不同，别混进来）
    acme_fn = setup[setup.index('base_list='):] if 'base_list=' in setup else ''
    acme_fn = acme_fn[:acme_fn.index('acme.sh 就绪')] if 'acme.sh 就绪' in acme_fn else acme_fn

    check('插件清单还是那 6 个（少一个，那个 DNS 提供商就不可用）',
          all(p in setup for p in
              ('dns_ali', 'dns_tencent', 'dns_cf', 'dns_huaweicloud', 'dns_porkbun', 'dns_gd')))

    check('插件下载有**多个源**（base_list）',
          'base_list' in acme_fn and acme_fn.count('http') >= 2)
    check('至少有一个非 GitHub 的源（国内镜像）',
          'gitee.com' in acme_fn or 'mirror' in acme_fn,
          'acme.sh 官方镜像在 Gitee 上，实测 200 / 0~1 秒')
    check('源是按顺序试的（第一个通的就算数）',
          re.search(r'for base in \$\{?base_list', acme_fn) is not None)

    mt = re.search(r'--max-time (\d+)', acme_fn)
    check('单次下载的超时被压住（≤30s，不是 60s）',
          mt is not None and int(mt.group(1)) <= 30,
          f'--max-time {mt.group(1) if mt else "?"}')
    rt = re.search(r'--retry (\d+)', acme_fn)
    check('重试次数被压住（≤1，不是 2）',
          rt is not None and int(rt.group(1)) <= 1,
          f'--retry {rt.group(1) if rt else "?"}')

    check('连续失败会跳过剩余插件（源不可达就别硬试）',
          re.search(r'consec_fail"?\s*-ge\s*2', acme_fn) is not None
          and re.search(r'consec_fail"?\s*-ge\s*2.*?break', acme_fn, re.S) is not None)
    check('跳过时会告诉用户怎么修（不能默默跳过）',
          'gitee.com' in acme_fn and 'raw.githubusercontent.com' in acme_fn)
    check('强制 IPv4（OpenWrt 设备通常没有 IPv6 默认路由）',
          'curl -4' in acme_fn)
    check('落地后校验非空（防止下到的是错误页）',
          '-s "${dnsapi_dir}/${p}.sh.part"' in acme_fn)

    # ── 9. 部署产物必须只含 git 跟踪的文件 ──────────────────────────
    #
    # 2026-10-30 在 .232 实测：frontend/index.html.bak（8 月的旧版管理 SPA
    # 完整副本，107KB）在设备上，面板的 web 根目录正是 frontend/ ⇒
    # 它被当静态文件对外提供（带会话 HTTP 200 直接能下）。
    # 它是被 .gitignore 挡掉的，只因为部署脚本拷的是**整个目录**才上了设备。
    #
    # 连带问题：tar 覆盖只加/改不删 ⇒ 已从仓库删掉的文件会永远留在设备上，
    # 变成跑着旧逻辑的死代码。
    sec('9. 部署产物只含 git 跟踪的文件（且要清掉陈旧文件）')

    check('传输由 git ls-files 清单驱动（不是 tar 整个目录）',
          'git -C "$SRC" ls-files' in deploy)
    check('tar 用 -T 读清单（--null 与 ls-files -z 配套）',
          '--null -T "$track_list"' in deploy)
    check('不再 tar 整个目录（. 会把 .gitignore 挡掉的东西一起带上）',
          "-czf - . \\" not in deploy and 'tar -C "$SRC" --exclude' not in deploy)

    # busybox 的 sort 不支持 -o：会把内容打到 stdout，混进差集输出里
    # （踩过：114 个正常文件全被当成「陈旧」删掉，靠预检+回滚救回来）
    check('设备侧不用 `sort -o`（busybox 不支持，会打到 stdout）',
          'sort "$EXPECT" -o' not in deploy and 'sort $EXPECT -o' not in deploy)
    check('设备侧差集用 grep -vxF -f（busybox 没有 comm）',
          'grep -vxF -f "$EXPECT"' in deploy)
    check('差集两边用 LC_ALL=C 排序（locale 不同会让差集失真）',
          'LC_ALL=C sort' in deploy)
    check('差集结果先写文件再 cat（stdout 里只该有差集本身）',
          '/tmp/nftables-web-stale.list' in deploy)

    # 安全网：差集超过上限就中止，绝不继续删
    check('清理有数量上限（差集算法出错时中止而不是继续删）',
          re.search(r'if \[ "\$N" -gt "\$LIMIT" \]', deploy) is not None)
    check('删除动作在设备侧完成（清单不来回传 stdout）',
          'device_remove_stale' in deploy and 'rm -f "$APP_DIR/$f"' in deploy)

    # 自检：运行时产物不参与比对
    check('自检排除 __pycache__ / *.pyc（运行时产物，判失败是误报）',
          '__pycache__' in deploy and '\\.pyc$' in deploy)
    check('自检用同一个差集函数（别写第二套逻辑）',
          'stale="$(device_stale_files' in deploy)
    check('源码目录必须在 git 仓库里（否则拿不到跟踪清单）',
          '不在 git 仓库里' in deploy)

    # ── 10. 升级路径必须把 setup/ 一起更新 ──────────────────────────
    #
    # 2026-11-11 在 .232 真机部署时发现（不是推理，是实测）：
    #   deploy.sh 的**升级路径**传输清单只有 backend frontend tools tests VERSION
    #   ⇒ 设备上 `/opt/nftables-web-v2/setup/setup.sh` 永远是**装机器时那份旧的**。
    #   ⇒ 批 B 的 S2 修复（部署后无条件重启面板服务）到不了设备：
    #      那份旧 setup.sh 里没有 `restart_panel_service` ⇒
    #      用户在设备上跑 `setup.sh --local` 二次部署 ⇒ 部署完**不重启** ⇒
    #      新代码不生效 —— 正是 S2 要修的那个 bug 原样复发。
    #
    # 判据不能只查「文本里有没有 setup」——
    #   那太弱：注释里写一句「setup 也要传」就假绿了。
    # ⇒ 这里**解析出脚本里真正用的那组路径参数**，再用它跑 git ls-files，
    #   验证结果里真的有 setup/setup.sh。
    #   将来清单的写法变了（换顺序、加目录），判据照样有效。
    sec('10. 升级路径的传输清单必须含 setup/（否则 S2 修复到不了设备）')

    # 从 deploy.sh 里抠出「升级路径」那一支的 ls-files 路径参数。
    # 认的是 `ls-files -z -- <路径...>` 这一行里 `--` 后面的部分。
    # ⚠️ 必须把 shell 的重定向/续行符切掉（`> "$track_list"` / `2>/dev/null` / `\`）
    #   —— 它们不是路径参数，混进来会让「清单包含 X」的判断看错位置。
    upgrade_paths = []
    for ln in deploy.splitlines():
        s = ln.strip()
        if s.startswith('#'):
            continue
        m = re.search(r'ls-files\s+-z\s+--\s+(.+)$', s)
        if not m:
            continue
        # 只取到第一个重定向/续行符之前
        tail = re.split(r'[>|]', m.group(1))[0]
        args = [a for a in tail.split() if a and a != '\\']
        # 升级路径那一支必然含 VERSION（全新安装那一支是 `ls-files -z -- .`）
        if 'VERSION' in args:
            upgrade_paths = args
            break

    check('deploy.sh 里找得到升级路径的 ls-files 清单（判据不能空转）',
          bool(upgrade_paths),
          '实际：%s' % (upgrade_paths or '没解析到'))

    if upgrade_paths:
        # 清单必须**逐个目录**都在 —— 不能只查 setup。
        #   只查 setup 的话，去掉 tools 或 tests 的退化就漏过去了
        #   （而那意味着设备上的工具脚本/测试永远停在旧版）。
        for d in ('backend', 'frontend', 'tools', 'tests', 'setup'):
            check('升级路径的清单包含 %s/' % d,
                  d in upgrade_paths,
                  '实际清单：%s' % ' '.join(upgrade_paths))
        check('升级路径的清单包含 VERSION',
              'VERSION' in upgrade_paths,
              '实际清单：%s' % ' '.join(upgrade_paths))

        # 清单必须**只含**这几个（多出来的会把本机的东西泄到设备）
        extra = [p for p in upgrade_paths
                 if p not in ('backend', 'frontend', 'tools', 'tests',
                              'setup', 'VERSION')]
        check('升级路径的清单没有多余的目录（不能整个仓库都传）',
              not extra,
              '多出来的：%s' % extra)

        # 真实跑一遍 git ls-files，用的就是脚本里那组参数。
        try:
            import subprocess
            r = subprocess.run(
                ['git', '-C', ROOT, 'ls-files', '-z', '--'] + upgrade_paths,
                capture_output=True, text=True, timeout=120)
            tracked = [x for x in r.stdout.split('\0') if x]
        except Exception as e:
            tracked = []
            print('  [x] git ls-files 执行失败：%s' % e)

        check('清单能真的列出文件（判据不能空转）',
              len(tracked) > 0,
              '列出 %d 个' % len(tracked))
        check('清单里确实有 setup/setup.sh',
              'setup/setup.sh' in tracked,
              'setup 相关：%s' % [t for t in tracked if t.startswith('setup/')][:5])
        check('清单里确实有 setup/vendor/（第三方插件也得更新）',
              any(t.startswith('setup/vendor/') for t in tracked),
              'vendor 文件数：%d' % len([t for t in tracked if t.startswith('setup/vendor/')]))
        check('清单里确实有 tools/deploy.sh 本身（工具脚本也要更新）',
              'tools/deploy.sh' in tracked)
        check('清单里确实有 tests/ 下的测试（设备上跑的是新测试）',
              any(t.startswith('tests/') for t in tracked),
              'tests 文件数：%d' % len([t for t in tracked if t.startswith('tests/')]))

        # 反向：清单里不能混进**未跟踪**的文件（那会把本机的东西泄到设备）
        check('清单里没有未跟踪的文件（setup-lib.sh 之类的不该被带上去）',
              'setup/setup-lib.sh' not in tracked,
              'setup-lib.sh 不在 git 跟踪清单里 ⇒ 不会传、设备上那份保留')

    # ── 11. 部署必须重新生成 cron 脚本 ──────────────────────────────
    #
    # 2026-11-11 在 .232 真机部署时实测发现：
    #   设备上的 `aliyun-ddns-update.py` 是**装机器时生成的那一份**，
    #   它不随 backend/app.py 的模板更新 ⇒ 模板里修好的东西
    #   （Line/TTL 回传、TXT/CNAME 归一化、RecordId 处理…）
    #   **在真正被 cron 执行的那份脚本里根本没有**。
    #
    #   ⇒ 部署完自检照样全过、版本号照样更新，但 cron 跑的还是旧逻辑
    #   ⇒ 面板上看到的「已修复」与 cron 实际做的事不是一回事。
    #   （实测：设备上那份 `_norm_value` 只有 IPv6 归一化，
    #     而模板里已经有 TXT 去引号 + CNAME 去尾点 —— 两侧不一致。）
    #
    # 判据必须落在**行为**上：deploy.sh 得**真的调** regen，
    # 而且自检里得**真的验** cron 脚本与模板一致。
    sec('11. 部署必须重新生成 cron 脚本（否则 cron 跑的是旧逻辑）')

    check('deploy.sh 里有重新生成 DDNS 脚本的阶段',
          'phase_regen_ddns' in deploy)
    check('该阶段调用的是 backend/regen_ddns_script.py',
          'regen_ddns_script.py' in deploy)
    check('regen 用的是零副作用的 AST 提取版（不 import app.py）',
          'regen_ddns_script.py' in deploy
          and not re.search(r'import\s+app\b', _regen_body_of(deploy)),
          '不能 import app.py（顶层可能起后台线程 ⇒ 有失联风险）')

    # ⚠️ 生成失败**不能中断部署**：面板上点一次「保存配置并生成脚本」是等价兜底。
    regen_body = ''
    if 'phase_regen_ddns()' in deploy:
        m = re.search(r'phase_regen_ddns\(\)\s*\{(.*?)\n\}', deploy, re.S)
        if m:
            regen_body = m.group(1)
    check('能抠出 phase_regen_ddns 的函数体（判据不能空转）',
          bool(regen_body), '长度 %d' % len(regen_body))
    if regen_body:
        check('生成失败只 warn 不 die（不能中断部署）',
              re.search(r'warn\s+".*失败', regen_body) is not None
              and not re.search(r'\bdie\b', regen_body),
              'die 会中断整个部署')
        check('生成时清掉测试专用环境变量（设备上要走 app.py 真源路径）',
              'env -u NFTABLES_WEB_DDNS_SCRIPT' in regen_body)

    # 顺序：regen 必须在**重启之前** ——
    #   否则重启后用户点「保存配置」，面板会用新模板再生成一份，
    #   而 regen 生成的是另一处 ⇒ 两边不一致。
    main_body = ''
    m = re.search(r'\nmain\(\)\s*\{(.*?)\n\}', deploy, re.S)
    if m:
        main_body = m.group(1)
    check('能抠出 main() 的函数体（判据不能空转）',
          bool(main_body), '长度 %d' % len(main_body))
    if main_body:
        i_regen = main_body.find('phase_regen_ddns')
        i_restart = main_body.find('phase_restart')
        check('main() 里调用了重新生成阶段',
              i_regen >= 0, '位置 %d' % i_regen)
        check('main() 里调用了重启阶段',
              i_restart >= 0, '位置 %d' % i_restart)
        check('重新生成在**重启之前**（顺序不能反）',
              i_regen >= 0 and i_restart >= 0 and i_regen < i_restart,
              'regen 位置 %d / restart 位置 %d' % (i_regen, i_restart))

    # 自检必须**真的比对** cron 脚本与模板一致 ——
    #   只调 regen 不够：regen 失败时（warn 不 die）部署照样「成功」，
    #   而 cron 还是旧的 ⇒ 必须在自检里抓出来。
    check('自检里取了设备上 cron 脚本的 md5',
          re.search(r'cron_md5_real=.*md5sum', deploy) is not None)
    check('自检里取了重新生成那份的 md5',
          re.search(r'cron_md5_gen=.*md5sum', deploy) is not None)
    # 自检把两个 md5 做了比对。
    # ⚠️ 不能靠「两个变量各出现两次」来判 —— 那分不清是「取值 + 比对」
    #   还是「取了两次值、从没比对」。必须确认它们出现在**同一个 check_eq** 里。
    #   check_eq 的实参可能跨行续写（行尾是 `\` + 换行）⇒ 先把续行拼起来再匹配。
    joined = re.sub(r'\\\n\s*', ' ', deploy)
    # ⚠️ 实参是带引号的 "$cron_md5_gen"（shell 里展开变量的标准写法）
    #   —— 匹配时必须把那对引号算进去，否则永远匹配不上。
    _md5_cmp = re.search(
        r'check_eq\s+"[^"]*cron[^"]*"\s+"\$cron_md5_gen"\s+"\$cron_md5_real"',
        joined)
    check('自检把两个 md5 做了比对',
          _md5_cmp is not None,
          '两个变量都要出现在同一个 check_eq 里')
    check('自检项的文案点明「不是装机器时那份旧的」',
          '不是装机器时那份旧的' in deploy)

    # ── 11b. deploy.sh 里用到的辅助函数必须真的存在 ────────────────
    #
    # 2026-11-11 首次真机部署就踩了：新写的阶段里用了 `info` ——
    # 但 deploy.sh 的辅助函数叫 `step`（`info` 是 setup.sh 里的那个）。
    # ⇒ 「info: 未找到命令」⇒ **整个部署中断并回滚**（设备停在半路）。
    #
    # 判据口径（**只能窄**，否则全是误报）：
    #   只看「辅助函数调用」这种形态 —— `名字 "字符串"`（名字后面紧跟引号）。
    #   这种形态在 shell 里几乎只可能是本脚本定义的辅助函数在用
    #   （外部命令不会带中文说明字符串）。
    #   ⚠ 不能扫「所有裸命令名」：那会把变量赋值、heredoc 正文、
    #     python 代码、中文注释全算进来 ⇒ 几百条误报 ⇒ 判据等于没有。
    defined = set(re.findall(r'^(\w+)\(\)\s*\{', deploy, re.M))
    # 本脚本里已知合法的「带字符串参数」调用（外部命令 / 特殊形态）
    known_callers = {
        'say', 'step', 'ok', 'warn', 'err', 'die', 'info', 'check_eq',
        'printf', 'echo', 'local', 'return', 'exit', 'read', 'export',
        'command', 'set', 'trap', 'source', 'eval', 'declare',
        'case', 'esac', 'else', 'elif', 'then', 'do', 'done', 'fi',
        'for', 'while', 'if', 'function',
        # 外部命令（OpenWrt busybox 自带）：不是本脚本的辅助函数
        'chgrp', 'chmod', 'chown', 'find', 'sed', 'awk', 'grep', 'cut',
        'tr', 'sort', 'uniq', 'head', 'tail', 'wc', 'md5sum', 'tar',
        'gzip', 'ssh', 'curl', 'wget', 'git', 'python3', 'python', 'sh',
        'bash', 'seq', 'sleep', 'date', 'cp', 'mv', 'rm', 'mkdir', 'cat',
        'ls', 'test', 'true', 'false', 'env', 'id', 'uname', 'kill',
        'netstat', 'jsonfilter', 'nft', 'uci', 'opkg', 'apk',
    }
    callers = set()
    for ln in deploy.splitlines():
        s = ln.strip()
        if not s or s.startswith('#'):
            continue
        # 命令位置：行首，或 ; && || 后
        for m in re.finditer(r'(?:^|[;|&]\s*)(\w+)\s+"', s):
            callers.add(m.group(1))
    undefined_callers = sorted(c for c in callers
                               if c not in defined
                               and c not in known_callers)
    check('deploy.sh 里用到的辅助函数都定义了（不存在「未找到命令」）',
          not undefined_callers,
          '疑似未定义：%s' % undefined_callers)

    # 退出码必须**直接从命令取**，不能写成 `out="$(cmd || true)"; rc=$?`
    #   —— 那样 $? 取到的是 true 的退出码，永远是 0 ⇒ 失败被当成成功。
    check('重新生成阶段的退出码是直接从命令取的（没被 || true 吃掉）',
          not re.search(r'out="\$\(rssh[^)]*\|\|\s*true\)"\s*\n\s*rc=\$\?',
                        regen_body),
          '`|| true` 会让 rc 永远是 0')
    check('重新生成阶段没有用不存在的 info（deploy.sh 里叫 step）',
          not re.search(r'(^|[^.\w])info\s+"', regen_body),
          'info 是 setup.sh 的辅助函数，deploy.sh 里没有')

    print('\n' + '=' * 60)
    print(f' 合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        print(' 有失败:')
        for f in FAIL:
            print('   - ' + f)
    else:
        print(' 全部通过')
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
