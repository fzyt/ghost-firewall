"""一键装机脚本（setup/setup.sh）的「一步到位 + 断点续装」硬性约束。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_setup_resume.py

背景
----
2026-10-31 用户提出：装机脚本要能「一个命令完成安装」，
而且「走到哪一步报错了，就提示可以重新执行 sh 安装程序继续重试，
之前完成的检测到就直接跳过」。

这个诉求拆成四个可验证的机制：

1. **阶段化 + 幂等检测** —— 每个阶段配一个 check 函数，
   返回 0 表示「这一步的产物已经在位」⇒ 重跑时跳过。
2. **失败提示带出口** —— 任何失败路径都要告诉用户「重跑这条命令即可续装」，
   并说明卡在哪一阶段。
3. **apk 不会卡死/白等** —— `apk update` 必须有超时，
   源不可用时自动切国内镜像；单包下载失败要有本地文件兜底。
4. **重装不是假成功** —— 目标目录已存在时不能静默跳过（那会让用户
   以为装的是新版本，设备上跑的却是旧代码）。

为什么有一半断言是**真跑 shell**而不是 grep 源码
----------------------------------------------------
这一批机制里最危险的退化是「看起来还在、其实已经不生效了」：
比如 `run_with_timeout` 的超时分支被改掉、`switch_apk_mirror`
把路径也一起换掉、`run_stage` 永远跳过 —— 这些在纯文本断言下
很容易写得"看起来对"。所以下面第 2 节用**真的把 setup.sh 的函数
source 起来跑**来验证行为，锚点失配和"实现了但没生效"都能被逮住。

保险丝
------
本文件**只读** setup/setup.sh，不改任何文件。
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')

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


# ------------------------------------------------------------
# 真跑 shell 的测试台
# ------------------------------------------------------------
#
# 把 setup.sh 去掉最后的 `main "$@"` 调用后 source 起来，
# 就能在本地直接调用它的函数 —— 验证的是**行为**，不是文本形状。
#
# ⚠️ 必须去掉 main 调用：source 时它会真的开始装东西。
# ⚠️ source 会带上 setup.sh 里的 `set -e`，所以测试片段里
#    任何一条命令失败都会终止脚本 —— 断言一律写成
#    `if <坏>; then echo FAIL; exit 1; fi` 的形式。


def make_lib(tmpdir):
    """生成一份去掉 main 调用的 setup.sh 副本，供 source 用。"""
    src = read(SETUP)
    lines = src.split('\n')
    # 去掉末尾的空行 + `main "$@"`
    while lines and lines[-1].strip() == '':
        lines.pop()
    assert lines[-1].strip() == 'main "$@"', f'末行不是 main 调用，而是: {lines[-1]!r}'
    lines.pop()
    lib = os.path.join(tmpdir, 'setup-lib.sh')
    with open(lib, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    return lib


def sh_snippet(lib, body, timeout=60):
    """source setup.sh 的函数后执行 body，返回 (rc, 输出)。"""
    with tempfile.TemporaryDirectory() as td:
        script = os.path.join(td, 'snippet.sh')
        with open(script, 'w', encoding='utf-8') as f:
            f.write(
                f'. "{lib}"\n'
                # ⚠️ set +e 必须在 source **之后**：setup.sh 开头自带 set -e，
                #    source 会把它带回来。放在前面等于没放。
                'set +e\n'
                # 日志重定向到临时目录：非 root 写 /var/log 会 Permission denied，
                # 那会污染断言（虽然 setup.sh 里已经 || true 兜住了）。
                f'LOG_FILE="{td}/setup.log"\n'
                # 阶段名固定，避免不同用例互相干扰
                'CURRENT_STAGE="单元测试阶段"\n'
                + body + '\n'
            )
        r = subprocess.run(['sh', script], capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, (r.stdout + r.stderr)


def run_case(name, lib, body, must_contain=(), must_not_contain=()):
    """跑一个行为用例：期望退出码 0，且输出里出现/不出现指定字样。"""
    rc, out = sh_snippet(lib, body)
    ok = (rc == 0)
    detail = ''
    if not ok:
        detail = f'退出码 {rc}'
    for s in must_contain:
        if s not in out:
            ok = False
            detail = f'输出里缺 {s!r}'
    for s in must_not_contain:
        if s in out:
            ok = False
            detail = f'输出里不该有 {s!r}'
    check(name, ok, detail)
    if not ok and out.strip():
        print('      ↓ ' + out.strip().replace('\n', '\n        ')[:600])


# ------------------------------------------------------------
# 从 setup.sh 里切出某个函数的源码（做结构断言用）
# ------------------------------------------------------------
def strip_comments(src):
    """去掉整行 shell 注释。

    项目老教训：注释里出现的函数名会被 `in` / 正则当成**调用点**，
    断言就会因为一句"这里不能这么写"的说明而误判。
    """
    return '\n'.join(ln for ln in src.split('\n') if not ln.strip().startswith('#'))


def fn_body(src, name):
    key = f'{name}() {{'
    i = src.find(key)
    if i < 0:
        return ''
    j = src.find('\n}\n', i)
    return src[i:j] if j > 0 else src[i:]


# ------------------------------------------------------------
# LuCI 判据的行为片段
# ------------------------------------------------------------
# 用双引号包裹：片段里有大量单引号（uci 配置里的 option enabled '0'），
# 用 Python 单引号串写会把自己绕进去。
LUCI_OPEN_BODY = r"""
d=$(mktemp -d)
mkdir -p "$d/bin"
printf '#!/bin/sh\necho "tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN"\n' > "$d/bin/netstat"
chmod +x "$d/bin/netstat"
PATH="$d/bin:$PATH"
UHTTPd_CONF="$d/uhttpd"
printf "config uhttpd main\n\toption enabled '1'\n\toption list '/cgi-bin/luci/*'\n" > "$UHTTPd_CONF"
if stage_luci_done; then echo "LuCI 还开着却判成已完成"; exit 1; fi
echo OK-LUCI
"""

LUCI_CLOSED_BODY = r"""
d=$(mktemp -d)
mkdir -p "$d/bin"
printf '#!/bin/sh\n' > "$d/bin/netstat"
chmod +x "$d/bin/netstat"
PATH="$d/bin:$PATH"
UHTTPd_CONF="$d/uhttpd"
printf "config uhttpd main\n\toption enabled '0'\n\toption list '/cgi-bin/luci/*'\n" > "$UHTTPd_CONF"
stage_luci_done || { echo "LuCI 已关却判成没装"; exit 1; }
echo OK-LUCI2
"""


def main():
    setup = read(SETUP)

    with tempfile.TemporaryDirectory() as td:
        lib = make_lib(td)

        # ── 1. 阶段框架 ───────────────────────────────────────
        sec('1. 阶段化：每个阶段都有「已完成」判据')

        check('有 run_stage（阶段调度器）',
              'run_stage() {' in setup)
        check('有 mark_stage（阶段流水账）',
              'mark_stage() {' in setup)

        stages = [
            ('依赖安装', 'stage_deps_done', 'install_deps'),
            ('acme.sh 证书组件', 'stage_acme_done', 'install_acme'),
            ('nginx 配置', 'stage_nginx_done', 'setup_nginx'),
            ('项目文件部署', 'stage_deploy_done', 'deploy_project'),
            ('配置初始化', 'stage_config_done', 'init_config'),
            ('ubus 服务', 'stage_ubus_done', 'ensure_ubus'),
            ('服务注册与启动', 'stage_service_done', 'setup_service'),
            ('nftables 引导规则', 'stage_nftables_done', 'setup_nftables'),
            ('关闭 LuCI 80/443', 'stage_luci_done', 'close_luci_ports'),
        ]
        for label, chk, act in stages:
            check(f'阶段「{label}」有判据函数 {chk}()',
                  f'{chk}() {{' in setup)
            check(f'阶段「{label}」在 main 里走 run_stage',
                  re.search(rf'run_stage\s+"{re.escape(label)}"\s+{chk}\s+{act}',
                            setup) is not None)

        rs = fn_body(setup, 'run_stage')
        check('run_stage 先问判据再决定跑不跑（判据在函数体里）',
              'check_fn' in rs and re.search(r'"\$check_fn"', rs) is not None)
        check('run_stage 的判据失败时**不能**当成"已完成"',
              re.search(r'"\$\w+"\s*>/dev/null\s*2>&1', rs) is not None)
        check('run_stage 不用 `if ! act_fn` 包住动作（set -e 会失效）',
              not re.search(r'if\s+!\s+"\$act_fn"', strip_comments(rs)),
              '包住会让 act_fn 内部的失败被吞掉')
        check('--force 时不跳过任何阶段',
              re.search(r'"\$ARG_FORCE"\s+-eq\s+0', rs) is not None)

        # ── 2. 失败提示：任何失败都要有出口 ────────────────────
        sec('2. 失败提示：告诉用户「重跑即可续装」')

        check('有 print_retry_hint（重试指引）',
              'print_retry_hint() {' in setup)
        hint = fn_body(setup, 'print_retry_hint')
        check('指引里出现「重新执行」',
              '重新执行' in hint)
        check('指引里出现「断点」',
              '断点' in hint)
        check('指引里说明已完成阶段会自动跳过',
              '跳过' in hint)
        check('指引里带上了 --local 参数（重跑命令必须能原样复现）',
              'ARG_LOCAL' in hint)
        check('指引里报出卡在哪个阶段',
              'CURRENT_STAGE' in hint)

        d = fn_body(setup, 'die')
        check('die 会打重试指引',
              'print_retry_hint' in d)

        check('有 EXIT 兜底（set -e 撞上的失败也要有指引）',
              'on_exit() {' in setup and "trap 'on_exit $?' EXIT" in setup)
        oe = fn_body(setup, 'on_exit')
        check('EXIT 兜底只在失败时出声（退出码 0 不刷屏）',
              re.search(r'"\$rc"\s+-ne\s+0', oe) is not None)
        check('EXIT 兜底在已经打过指引时不重复打',
              'RETRY_HINT_SHOWN' in oe)
        check('全部完成后会标记 INSTALL_COMPLETED（不该再打指引）',
              'INSTALL_COMPLETED=1' in setup)

        # ── 3. apk 不会卡死 / 不会白等 ─────────────────────────
        sec('3. apk：超时保护 + 自动换源 + 本地文件兜底')

        check('有 run_with_timeout（OpenWrt 没有 timeout 命令）',
              'run_with_timeout() {' in setup)
        rwt = fn_body(setup, 'run_with_timeout')
        check('超时用 /proc/<pid> 判存活（busybox 的 kill 不支持 -0）',
              '/proc/$pid' in rwt)
        check('超时会杀掉那个进程并返回 124',
              'kill -9' in rwt and '124' in rwt)
        check('run_with_timeout 会把被包命令的退出码带出来',
              re.search(r'wait\s+"\$pid".*\|\|\s*rc=\$\?', rwt, re.S) is not None)

        check('有 apk_update_with_failover（当前源失败就换国内镜像）',
              'apk_update_with_failover() {' in setup)
        check('候选镜像含中科大/南大/清华',
              all(h in setup for h in
                  ('mirrors.ustc.edu.cn', 'mirror.nju.edu.cn',
                   'mirrors.tuna.tsinghua.edu.cn')))
        sw = fn_body(setup, 'switch_apk_mirror')
        check('换源只替换 URL 的主机部分（路径不动）',
              re.search(r'sed\s+"s#://\[\^/\]\*/#://\$\{host\}/#"', sw) is not None,
              '只换 host ⇒ 不依赖 OpenWrt 的仓库布局')
        check('换源前先备份原始仓库清单',
              '.orig' in sw)
        fo = fn_body(setup, 'apk_update_with_failover')
        check('换源全失败会把仓库清单还原（不能把设备留在随手挑的源上）',
              re.search(r'cp\s+"\$\{repo\}\.orig"\s+"\$repo"', fo) is not None)
        check('还原那一步不是死代码（有条件判断包着）',
              'if [ -n "$repo" ] && [ -f "${repo}.orig" ]; then' in fo,
              '否则 M19 那种"把 if 换成 false"的变异会漏网')

        au = fn_body(setup, 'apk_update_once')
        check('apk update 的结果不只看退出码（截断时它可能仍返回 0）',
              'unexpected end of file' in au)
        check('apk update 有超时上限',
              re.search(r'run_with_timeout\s+"\$timeout"\s+apk update', au) is not None)

        pu = fn_body(setup, 'pkg_update')
        check('pkg_update 走镜像 failover（不再是裸 apk update）',
              'apk_update_with_failover' in pu)
        check('pkg_update 里没有裸的 `apk update ;;`',
              not re.search(r'apk\)\s+apk update\s*;;', pu))

        check('有 apk_install_via_local_file（换下载器的兜底）',
              'apk_install_via_local_file() {' in setup)
        lf = fn_body(setup, 'apk_install_via_local_file')
        check('兜底用 apk fetch（apk 自带下载器，绕开坏掉的 wget）',
              'apk fetch' in lf)
        check('兜底装的是本地 .apk 文件',
              re.search(r'apk add --no-cache --allow-untrusted\s+"\$f"', lf) is not None)
        pia = fn_body(setup, 'pkg_install_apk')
        check('pkg_install_apk 重试耗尽后会走本地文件兜底',
              'apk_install_via_local_file' in pia)
        check('pkg_install_apk 重试时刷索引用的是带 failover 的那个',
              'apk_update_with_failover' in pia and
              not re.search(r'apk update\s*>/dev/null', pia))

        check('有 free_package_cache（apk 包体会撑爆小 overlay）',
              'free_package_cache() {' in setup)
        fpc = fn_body(setup, 'free_package_cache')
        check('只删 *.apk 包体，保留索引（删了索引每个包都要重下全量索引）',
              '/var/cache/apk/*.apk' in fpc and 'APKINDEX' not in fpc)

        # ── 4. 重装不是假成功 ───────────────────────────────────
        sec('4. 重装：目标目录已存在时不能静默跳过')

        check('不再有「非交互模式就跳过项目部署」的老逻辑',
              '跳过项目部署（目标目录 ${INSTALL_DIR} 已存在且非空，非交互模式）'
              not in setup)
        dp = fn_body(setup, 'deploy_project')
        check('目录已存在时改为覆盖安装（并说明配置不受影响）',
              '将覆盖安装目录' in dp and 'CONFIG_DIR' in dp)
        # ⚠️ 必须只查**本地路径分支**：GitHub 分支也写 VERSION，
        #    拿整个函数去查的话，本地分支不写版本也照样能过（这正是 M29 漏网的原因）。
        local_branch = dp[dp.find('if [ -n "$ARG_LOCAL" ]; then'):dp.find('# GitHub 安装')]
        check('部署后记录版本（供「已完成」判据比对）',
              'INSTALL_DIR}/VERSION' in local_branch,
              '查的是本地路径分支，不是整个函数')

        # ── 5. 各阶段判据的强度 ────────────────────────────────
        sec('5. 判据强度：不能把「坏状态」判成「已完成」')

        sd = fn_body(setup, 'stage_deploy_done')
        check('部署判据会比对版本（版本不同 ⇒ 重装）',
              'VERSION' in sd and re.search(r'"\$v"\s*=\s*"\$VERSION"', sd) is not None)
        check('部署判据要比对**这次要装的源**（同版本号不同内容也不能算已完成）',
              'ARG_LOCAL' in sd and 'deploy_tree_matches' in sd,
              '只看版本号 ⇒ 改了代码没 bump 版本号时会静默跳过部署')
        check('源比对是**整棵树**逐文件 md5（只比一个代表文件会漏）',
              'deploy_tree_matches() {' in setup and 'md5sum' in setup)
        check('源比对排除运行时产物（__pycache__/*.pyc 不该算进来）',
              '__pycache__' in setup and "*.pyc" in setup)
        check('部署判据要求 VERSION 文件存在（老版装出来的目录没这文件 ⇒ 不能判成已完成）',
              re.search(r'\[\s*-f\s+"\$\{INSTALL_DIR\}/VERSION"\s*\]\s*\|\|\s*return 1',
                        strip_comments(sd)) is not None,
              '否则老目录会被判成"已完成"，新代码永远装不上')

        sc = fn_body(setup, 'stage_config_done')
        check('配置判据验 JSON 合法性（截断的配置会让面板静默回退默认值）',
              'json.load' in sc)

        ss = fn_body(setup, 'stage_service_done')
        check('服务判据查端口监听（文件在 ≠ 服务活着）',
              'netstat' in ss and 'PANEL_PORT' in ss)
        check('服务判据也要求认证服务的 init 脚本在位',
              'AUTH_INITD_SCRIPT' in ss)

        sa = fn_body(setup, 'stage_acme_done')
        check('acme 判据要求 6 个 DNS 插件都在',
              'ACME_DNSAPI_PLUGINS' in sa)
        check('acme 判据要求 DEFAULT_ACME_SERVER 已固定（否则走 ZeroSSL 必失败）',
              'DEFAULT_ACME_SERVER' in sa)

        sl = fn_body(setup, 'stage_luci_done')
        check('LuCI 判据认 uhttpd 版（25.x 的 LuCI 不由 nginx 提供）',
              'UHTTPd_CONF' in sl and '/cgi-bin/luci' in sl)
        check('LuCI 判据也认 nginx 老版',
              'NGINX_UCI_CONF' in sl)
        check('LuCI 判据要求的路径都在脚本顶部定义成变量（可注入 ⇒ 可测）',
              'UHTTPd_CONF="/etc/config/uhttpd"' in setup
              and 'NGINX_UCI_CONF="/etc/config/nginx"' in setup)

        # ── 6. 依赖顺序 ────────────────────────────────────────
        sec('6. 依赖顺序：curl 必须在 nginx-full 之前，wget-ssl 最后')

        dep = fn_body(setup, 'install_deps')
        curl_at = dep.find('curl \\')
        nginx_at = dep.find('nginx-full \\')
        wget_at = dep.find('pkg_install wget-ssl')
        check('curl 排在 nginx-full 前面（它是下载器自愈的首选后端）',
              curl_at > 0 and nginx_at > 0 and curl_at < nginx_at,
              f'curl@{curl_at} nginx@{nginx_at}')
        check('wget-ssl 单独放在最后（它的 postinst 会替换 /usr/bin/wget）',
              wget_at > 0 and wget_at > nginx_at)
        check('install_deps 会先清 apk 包缓存',
              'free_package_cache' in dep)

        # ── 7. 行为验证：真把函数跑起来 ────────────────────────
        sec('7. 行为验证：真跑 shell（不是 grep 源码）')

        run_case(
            'run_with_timeout 真的会超时（2s 上限跑 sleep 30）→ 返回 124',
            lib,
            'rc=0\n'
            'run_with_timeout 2 sleep 30 || rc=$?\n'
            'if [ "$rc" -ne 124 ]; then echo "期望 124，实际 $rc"; exit 1; fi\n'
            'echo OK-TIMEOUT\n',
            must_contain=['OK-TIMEOUT'])

        run_case(
            'run_with_timeout 会把被包命令的退出码带出来（7 → 7）',
            lib,
            'rc=0\n'
            'run_with_timeout 10 sh -c "exit 7" || rc=$?\n'
            'if [ "$rc" -ne 7 ]; then echo "期望 7，实际 $rc"; exit 1; fi\n'
            'echo OK-RC\n',
            must_contain=['OK-RC'])

        run_case(
            'switch_apk_mirror 只换主机、路径不动、且留 .orig 备份',
            lib,
            'd=$(mktemp -d)\n'
            'mkdir -p "$d/repositories.d"\n'
            'f="$d/repositories.d/distfeeds.list"\n'
            'printf "%s\\n" \\\n'
            '  "https://mirror.nju.edu.cn/openwrt/releases/25.12.5/packages/x86_64/base/packages.adb" \\\n'
            '  "https://mirror.nju.edu.cn/openwrt/releases/25.12.5/targets/x86/64/packages/packages.adb" \\\n'
            '  > "$f"\n'
            'apk_repo_file() { echo "$f"; }\n'
            'switch_apk_mirror mirrors.ustc.edu.cn || { echo "切换失败"; exit 1; }\n'
            'grep -q "https://mirrors.ustc.edu.cn/openwrt/releases/25.12.5/packages/x86_64/base/packages.adb" "$f" \\\n'
            '  || { echo "主机没换掉"; cat "$f"; exit 1; }\n'
            'if grep -q "nju" "$f"; then echo "旧主机还在"; cat "$f"; exit 1; fi\n'
            'if [ ! -f "$f.orig" ]; then echo "没有 .orig 备份"; exit 1; fi\n'
            'echo OK-MIRROR\n',
            must_contain=['OK-MIRROR'])

        run_case(
            'run_stage：判据通过就跳过（动作不执行）',
            lib,
            'RAN=0\n'
            'check_ok() { return 0; }\n'
            'act() { RAN=1; }\n'
            'run_stage "单元测试阶段" check_ok act\n'
            'if [ "$RAN" != "0" ]; then echo "判据通过却还是跑了"; exit 1; fi\n'
            'echo OK-SKIP\n',
            must_contain=['OK-SKIP'])

        run_case(
            'run_stage：判据不通过就执行动作',
            lib,
            'RAN=0\n'
            'check_no() { return 1; }\n'
            'act() { RAN=1; }\n'
            'run_stage "单元测试阶段" check_no act\n'
            'if [ "$RAN" != "1" ]; then echo "判据不通过却没跑"; exit 1; fi\n'
            'echo OK-RUN\n',
            must_contain=['OK-RUN'])

        run_case(
            'run_stage：--force 时即使判据通过也要重做',
            lib,
            'RAN=0\n'
            'ARG_FORCE=1\n'
            'check_ok() { return 0; }\n'
            'act() { RAN=1; }\n'
            'run_stage "单元测试阶段" check_ok act\n'
            'if [ "$RAN" != "1" ]; then echo "--force 仍然跳过了"; exit 1; fi\n'
            'echo OK-FORCE\n',
            must_contain=['OK-FORCE'])

        run_case(
            'print_retry_hint 真的打出了「重新执行…断点…」',
            lib,
            'out="$(print_retry_hint 2>&1)"\n'
            'echo "$out" | grep -q "重新执行" || { echo "缺 重新执行"; exit 1; }\n'
            'echo "$out" | grep -q "断点" || { echo "缺 断点"; exit 1; }\n'
            'echo "$out" | grep -q "单元测试阶段" || { echo "缺阶段名"; exit 1; }\n'
            'echo OK-HINT\n',
            must_contain=['OK-HINT'])

        run_case(
            'die 会打出重试指引（用户拿得到出口）',
            lib,
            'out="$( (die "故意失败") 2>&1 )"\n'
            'echo "$out" | grep -q "重新执行" || { echo "die 没打指引"; exit 1; }\n'
            'echo OK-DIE\n',
            must_contain=['OK-DIE'])

        run_case(
            'on_exit：退出码非 0 才给指引，退出码 0 保持安静',
            lib,
            'out="$(on_exit 3 2>&1)"\n'
            'echo "$out" | grep -q "重新执行" || { echo "rc=3 没打指引"; exit 1; }\n'
            'out2="$(on_exit 0 2>&1)"\n'
            'if [ -n "$out2" ]; then echo "rc=0 也刷屏了"; exit 1; fi\n'
            'echo OK-EXIT\n',
            must_contain=['OK-EXIT'])

        run_case(
            'stage_config_done：非法 JSON 不算「已完成」',
            lib,
            'd=$(mktemp -d)\n'
            'printf "{\\"a\\":1}" > "$d/good.json"\n'
            'printf "{\\"a\\":" > "$d/bad.json"\n'
            'CONFIG_FILE="$d/good.json"\n'
            'stage_config_done || { echo "合法 JSON 被拒"; exit 1; }\n'
            'CONFIG_FILE="$d/bad.json"\n'
            'if stage_config_done; then echo "非法 JSON 被当成已完成"; exit 1; fi\n'
            'CONFIG_FILE="$d/none.json"\n'
            'if stage_config_done; then echo "缺失的文件被当成已完成"; exit 1; fi\n'
            'echo OK-CONFIG\n',
            must_contain=['OK-CONFIG'])

        run_case(
            'stage_deploy_done：版本不同 ⇒ 不算「已完成」',
            lib,
            'd=$(mktemp -d)\n'
            'mkdir -p "$d/backend" "$d/frontend"\n'
            'echo x > "$d/backend/app.py"\n'
            'echo x > "$d/frontend/index.html"\n'
            'INSTALL_DIR="$d"\n'
            'VERSION=0.8.8\n'
            'printf "0.8.8" > "$d/VERSION"\n'
            'stage_deploy_done || { echo "同版本被判成没装"; exit 1; }\n'
            'printf "0.9.9" > "$d/VERSION"\n'
            'if stage_deploy_done; then echo "旧版本被判成已完成"; exit 1; fi\n'
            'rm -f "$d/VERSION"\n'
            'if stage_deploy_done; then echo "没有 VERSION 记录被判成已完成"; exit 1; fi\n'
            'echo OK-VERSION\n',
            must_contain=['OK-VERSION'])

        run_case(
            'stage_deploy_done：--local 的源与已装的有任何一处不同 ⇒ 不算「已完成」',
            lib,
            'd=$(mktemp -d)\n'
            'mkdir -p "$d/app/backend" "$d/app/frontend" "$d/src/backend" "$d/src/frontend"\n'
            'echo SAME > "$d/app/backend/app.py"\n'
            'echo SAME > "$d/app/frontend/index.html"\n'
            'echo SAME > "$d/src/backend/app.py"\n'
            'echo SAME > "$d/src/frontend/index.html"\n'
            'printf "0.8.8" > "$d/app/VERSION"\n'
            'INSTALL_DIR="$d/app"\n'
            'ARG_LOCAL="$d/src"\n'
            'VERSION=0.8.8\n'
            'stage_deploy_done || { echo "完全一致却被判成没装"; exit 1; }\n'
            # ⚠️ 只改 frontend（backend/app.py 不变）—— 这正是只比一个\n'
            '# 代表文件会漏掉的情况。\n'
            'echo DIFFERENT > "$d/src/frontend/index.html"\n'
            'if stage_deploy_done; then echo "frontend 不同被判成已完成"; exit 1; fi\n'
            'echo DIFF > "$d/src/backend/app.py"\n'
            'if stage_deploy_done; then echo "backend 不同被判成已完成"; exit 1; fi\n'
            'echo OK-SRCMATCH\n',
            must_contain=['OK-SRCMATCH'])

        run_case(
            'stage_service_done：init 脚本在但服务没起来 ⇒ 不算「已完成」',
            lib,
            'd=$(mktemp -d)\n'
            'mkdir -p "$d/bin"\n'
            '# 假的 netstat：一个端口都不监听\n'
            'printf "#!/bin/sh\\nexit 0\\n" > "$d/bin/netstat"\n'
            'chmod +x "$d/bin/netstat"\n'
            'PATH="$d/bin:$PATH"\n'
            'INITD_SCRIPT="$d/nftables-web"\n'
            'AUTH_INITD_SCRIPT="$d/nftables-web-auth"\n'
            'touch "$INITD_SCRIPT" "$AUTH_INITD_SCRIPT"\n'
            'if stage_service_done; then echo "服务没起来却判成已完成"; exit 1; fi\n'
            'echo OK-SERVICE\n',
            must_contain=['OK-SERVICE'])

        run_case(
            'stage_service_done：端口在监听 ⇒ 算「已完成」',
            lib,
            'd=$(mktemp -d)\n'
            'mkdir -p "$d/bin"\n'
            'printf "#!/bin/sh\\necho \\"tcp 0 0 0.0.0.0:5443 0.0.0.0:* LISTEN\\"\\n" \\\n'
            '  > "$d/bin/netstat"\n'
            'chmod +x "$d/bin/netstat"\n'
            'PATH="$d/bin:$PATH"\n'
            'INITD_SCRIPT="$d/nftables-web"\n'
            'AUTH_INITD_SCRIPT="$d/nftables-web-auth"\n'
            'touch "$INITD_SCRIPT" "$AUTH_INITD_SCRIPT"\n'
            'stage_service_done || { echo "服务在跑却判成没装"; exit 1; }\n'
            'echo OK-SERVICE2\n',
            must_contain=['OK-SERVICE2'])

        run_case(
            'apk_update_with_failover：所有源都失败 ⇒ 还原原始仓库清单',
            lib,
            'd=$(mktemp -d)\n'
            'mkdir -p "$d/repositories.d"\n'
            'f="$d/repositories.d/distfeeds.list"\n'
            'printf "%s\\n" "https://mirror.nju.edu.cn/openwrt/releases/x/packages.adb" > "$f"\n'
            'cp "$f" "$f.orig"\n'
            'apk_repo_file() { echo "$f"; }\n'
            '# 让 apk update 永远失败 ⇒ 逼它把候选镜像全试一遍\n'
            'apk_update_once() { return 1; }\n'
            'apk_update_with_failover || true\n'
            'if ! grep -q "mirror.nju.edu.cn" "$f"; then\n'
            '  echo "换源全失败后没有还原原始清单"; cat "$f"; exit 1\n'
            'fi\n'
            'echo OK-RESTORE\n',
            must_contain=['OK-RESTORE'])

        run_case(
            'deploy_project：本地部署后必须留下 VERSION 记录',
            lib,
            'd=$(mktemp -d)\n'
            'mkdir -p "$d/src/backend" "$d/src/frontend"\n'
            'echo x > "$d/src/backend/app.py"\n'
            'echo x > "$d/src/frontend/index.html"\n'
            'INSTALL_DIR="$d/dst"\n'
            'ARG_LOCAL="$d/src"\n'
            'ARG_FORCE=1\n'
            'deploy_project >/dev/null 2>&1\n'
            'if [ ! -f "$INSTALL_DIR/VERSION" ]; then echo "部署后没记版本"; exit 1; fi\n'
            'echo OK-DEPLOYVER\n',
            must_contain=['OK-DEPLOYVER'])

        run_case(
            'stage_luci_done：uhttpd 还开着 80 ⇒ 不算「已完成」',
            lib,
            LUCI_OPEN_BODY,
            must_contain=['OK-LUCI'])

        run_case(
            'stage_luci_done：uhttpd 已停且 enabled=0 ⇒ 算「已完成」',
            lib,
            LUCI_CLOSED_BODY,
            must_contain=['OK-LUCI2'])

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
