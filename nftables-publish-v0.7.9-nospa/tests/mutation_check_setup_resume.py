#!/usr/bin/env python3
"""一键装机脚本「一步到位 + 断点续装」机制的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_setup_resume.py

测什么有效
----------
这一轮给 setup.sh 加的是**机制**：阶段调度、失败指引、超时、换源、本地兜底。
这类机制最危险的退化不是"写错了"，而是**看起来还在、其实已经不生效了**：

  · `run_with_timeout` 的超时分支被摘掉 ⇒ 官方源卡 4 分钟的老问题回来
  · `switch_apk_mirror` 把路径也换掉 ⇒ 换成不存在的目录，索引全空
  · `run_stage` 永远执行 / 永远跳过 ⇒ 「检测到就跳过」根本没实现
  · `pkg_install_apk` 不走本地兜底 ⇒ 大包下载一失败就永久卡住
  · `print_retry_hint` 不提"断点" ⇒ 用户还是拿不到出口

这些退化在纯文本断言下极易蒙混过关 —— 所以对应的测试里有一半是
**真把 setup.sh 的函数 source 起来跑**（见 test_setup_resume.py 第 7 节），
变异脚本专门去拆这些真跑的部分。

对应关系
--------
  阶段跳过    M1 M2 M3 M4        超时     M5 M6 M7
  失败指引    M8 M9 M10 M11      换源     M12 M13
  本地兜底    M14 M15 M16        判据     M17 M18 M19 M20
  其它        M21 M22 M23 M24

保险丝：只备份 / 还原**我自己会改的那一个文件**
------------------------------------------------
本仓库多个批次会并行改同一棵树。这个脚本**只**碰 setup/setup.sh，
不扫描 /tmp/mutguard-*，不还原任何快照目录 —— 别人的 backend/app.py、
frontend/** 一概不动。

锚点
----
每条变异用成对的精确字符串，且必须在源码里**唯一**。匹配不上就当场
报错并算作漏网 —— 「锚点没命中」不等于「变异没生效」，那比漏网更糟。
"""
import atexit
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')
TEST = os.path.join(ROOT, 'tests', 'test_setup_resume.py')

# 我独占、也只有我会改的那一个文件。
ORIG = {SETUP: open(SETUP, encoding='utf-8').read()}


def restore():
    """把 setup.sh 还原成脚本启动时的内容。幂等，可反复调用。"""
    for path, content in ORIG.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except OSError:
            pass


def _restore_and_exit(signum, frame):
    restore()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    try:
        signal.signal(_sig, _restore_and_exit)
    except (ValueError, OSError):
        pass
atexit.register(restore)


def run_tests():
    r = subprocess.run([sys.executable, TEST], capture_output=True, text=True,
                       cwd=ROOT, timeout=900,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


# ─────────────────────────────────────────────────────────────
# 变异定义：(名称, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

MUTATIONS = [
    # ── 阶段跳过：run_stage ───────────────────────────────────
    ('M1  run_stage 永远执行（判据通过也重做 = 没实现"检测到就跳过"）',
     [('    if [ "$ARG_FORCE" -eq 0 ] && "$check_fn" >/dev/null 2>&1; then',
       '    if false; then')]),

    ('M2  run_stage 永远跳过（判据失败也不做 = 装到一半就当装好了）',
     [('    if [ "$ARG_FORCE" -eq 0 ] && "$check_fn" >/dev/null 2>&1; then',
       '    if true; then')]),

    ('M3  run_stage 用 `if ! act_fn` 包住动作（set -e 失效，失败被吞）',
     [('    "$act_fn"\n    mark_stage "${name}: done"',
       '    if ! "$act_fn"; then warn "阶段失败"; fi\n    mark_stage "${name}: done"')]),

    ('M4  --force 不再生效（用户要求重做却还是跳过）',
     [('    if [ "$ARG_FORCE" -eq 0 ] && "$check_fn" >/dev/null 2>&1; then',
       '    if "$check_fn" >/dev/null 2>&1; then')]),

    # ── 失败指引 ─────────────────────────────────────────────
    ('M5  print_retry_hint 不再提"断点"（用户不知道能续装）',
     [('  已完成的阶段会自动跳过，重新执行下面这条命令即可从断点继续：',
       '  已完成的阶段会自动跳过，重新执行下面这条命令即可：')]),

    ('M6  print_retry_hint 不再提"重新执行"（用户拿不到出口）',
     [('  已完成的阶段会自动跳过，重新执行下面这条命令即可从断点继续：',
       '  后续步骤：')]),

    ('M7  print_retry_hint 不报当前阶段（用户不知道卡在哪一步）',
     [('  ❌ 安装未完成 —— 停在【${CURRENT_STAGE}】阶段',
       '  ❌ 安装未完成')]),

    ('M8  print_retry_hint 丢掉 --local 参数（重跑命令复现不出来）',
     [('    if [ -n "$ARG_LOCAL" ]; then\n        cmd="${cmd} --local ${ARG_LOCAL}"\n    fi',
       '    :')]),

    ('M9  die 不再打重试指引（只剩一句"安装中止"）',
     [('die() {\n    error "$@"\n    error "安装中止。"\n    print_retry_hint',
       'die() {\n    error "$@"\n    error "安装中止。"')]),

    ('M10 去掉 EXIT 兜底（set -e 撞上的失败没有指引）',
     [("trap 'on_exit $?' EXIT", ': # trap 已摘掉')]),

    ('M11 on_exit 对退出码 0 也出声（成功安装也刷一段"安装未完成"）',
     [('    if [ "$rc" -ne 0 ] && [ "$INSTALL_COMPLETED" -eq 0 ] && [ "$RETRY_HINT_SHOWN" -eq 0 ]; then',
       '    if [ "$INSTALL_COMPLETED" -eq 0 ] && [ "$RETRY_HINT_SHOWN" -eq 0 ]; then')]),

    # ── 超时保护 ─────────────────────────────────────────────
    ('M12 run_with_timeout 不再超时（官方源卡 4 分钟的老问题回来）',
     [('        if [ "$waited" -ge "$limit" ]; then\n            warn "命令超时（${limit}s），已终止: $*"',
       '        if false; then\n            warn "命令超时（${limit}s），已终止: $*"')]),

    ('M13 run_with_timeout 改用 kill -0 判存活（busybox 不支持 -0）',
     [('    while [ -d "/proc/$pid" ]; do', '    while kill -0 "$pid" 2>/dev/null; do')]),

    ('M14 run_with_timeout 吞掉被包命令的退出码（失败被当成成功）',
     [('    wait "$pid" 2>/dev/null || rc=$?\n    return $rc',
       '    wait "$pid" 2>/dev/null || true\n    return 0')]),

    # ── 换源 ─────────────────────────────────────────────────
    ('M15 switch_apk_mirror 把整个 URL 都换掉（路径也变了 = 索引全空）',
     [('    sed "s#://[^/]*/#://${host}/#" "$repo" > "$tmp" 2>/dev/null || return 1',
       '    sed "s#.*#https://${host}/#g" "$repo" > "$tmp" 2>/dev/null || return 1')]),

    ('M16 switch_apk_mirror 不留 .orig 备份（失败后还原不回去）',
     [('    if [ ! -f "${repo}.orig" ]; then\n        cp "$repo" "${repo}.orig" 2>/dev/null || true\n    fi',
       '    :')]),

    ('M17 apk_update_once 不看"unexpected end of file"（截断当成功）',
     [('    bad="$(grep -E "unexpected end of file|ERROR:" "$out" 2>/dev/null | head -1)"',
       '    bad=""')]),

    ('M18 pkg_update 回到裸 apk update（坏源上卡 4 分钟）',
     [('        apk)\n            apk_update_with_failover\n            ;;',
       '        apk)\n            apk update\n            ;;')]),

    ('M19 换源全失败后不还原仓库清单（设备被留在随手挑的源上）',
     [('    if [ -n "$repo" ] && [ -f "${repo}.orig" ]; then\n        cp "${repo}.orig" "$repo" 2>/dev/null || true',
       '    if false; then\n        cp "${repo}.orig" "$repo" 2>/dev/null || true')]),

    # ── 本地文件兜底 ─────────────────────────────────────────
    ('M20 pkg_install_apk 不走本地文件兜底（大包一失败就永久卡住）',
     [('    if apk_install_via_local_file "$pkg"; then',
       '    if false; then')]),

    ('M21 apk_install_via_local_file 不用 apk fetch（退回会坏的 wget 通道）',
     [('    if ! ( cd "$work" && apk fetch "$pkg" >/dev/null 2>&1 ); then',
       '    if ! ( cd "$work" && apk add --no-cache "$pkg" >/dev/null 2>&1 ); then')]),

    ('M22 pkg_install_apk 重试时刷索引用回裸 apk update（重试白等 12 分钟）',
     [('            apk_update_with_failover || true',
       '            apk update >/dev/null 2>&1 || true')]),

    ('M23 free_package_cache 连索引一起删（每个包都要重下全量索引）',
     [('        rm -f /var/cache/apk/*.apk 2>/dev/null || true',
       '        rm -f /var/cache/apk/*.apk /var/cache/apk/APKINDEX.* 2>/dev/null || true')]),

    # ── 判据强度 ─────────────────────────────────────────────
    ('M24 stage_config_done 不验 JSON 合法性（截断的配置被当成已完成）',
     [('    python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$CONFIG_FILE" >/dev/null 2>&1 || return 1',
       '    :')]),

    # ⚠️ 这里原来还有一条 M25「不比对版本」，锚点写的是重构**之前**的代码形态
    #    （`if [ -n "$v" ] && [ "$v" != "$VERSION" ]; then ... fi`）——
    #    stage_deploy_done 改成 `[ "$v" = "$VERSION" ] || return 1` 之后它就再也
    #    匹配不上 ⇒ 变异被静默跳过 ⇒ 回归显示"漏过 1 条"却查不出是哪条。
    #    它与 M34 完全等价，已删除 —— 保留一条**锚点有效**的等价变异更有价值。
    #    （这条注释本身就是教训：锚点失配 = 变异名存实亡。）

    ('M26 stage_service_done 不查端口（服务没起来也判成已完成）',
     [('    if netstat -lnt 2>/dev/null | grep -q ":${PANEL_PORT} "; then\n        return 0\n    fi\n    return 1',
       '    return 0')]),

    ('M27 stage_luci_done 不认 uhttpd 版 LuCI（25.x 上判成"已关"）',
     [('    if [ -f "$UHTTPd_CONF" ] && grep -q "/cgi-bin/luci" "$UHTTPd_CONF" 2>/dev/null; then',
       '    if false; then')]),

    # ── 其它 ─────────────────────────────────────────────────
    ('M28 deploy_project 回到"非交互就跳过"（重装成假成功）',
     [('        else\n            info "目标目录已存在，将覆盖安装目录（配置与凭据在 ${CONFIG_DIR}，不受影响）"\n        fi',
       '        else\n            warn "跳过项目部署（目标目录 ${INSTALL_DIR} 已存在且非空，非交互模式）"\n            return\n        fi')]),

    ('M29 部署后不记录版本（下次判不出"要不要重装"）',
     [('        if [ -f "${ARG_LOCAL}/VERSION" ]; then\n            cp "${ARG_LOCAL}/VERSION" "${INSTALL_DIR}/VERSION"\n        else\n            printf \'%s\\n\' "$VERSION" > "${INSTALL_DIR}/VERSION"\n        fi',
       '        :')]),

    ('M30 curl 排到 nginx-full 后面（下载器自愈时 curl 还没装上）',
     [('    pkg_install \\\n        curl \\\n        nftables \\',
       '    pkg_install \\\n        nftables \\')]),

    ('M31 wget-ssl 不再单独放最后（postinst 抢先替换 wget = 下载器自己坏掉）',
     [('    # wget-ssl 单独放最后（理由见上）\n    pkg_install wget-ssl',
       '    # wget-ssl 单独放最后（理由见上）\n    :')]),

    ('M32 install_deps 不清 apk 包缓存（小 overlay 被撑爆）',
     [('    free_package_cache\n', '    :\n')]),

    ('M33 stage_deploy_done 不要求 VERSION 存在（老目录被判成已完成 = 新代码永远装不上）',
     [('    [ -f "${INSTALL_DIR}/VERSION" ] || return 1', '    :')]),

    ('M34 stage_deploy_done 不比对版本内容（装了旧代码也判成已完成）',
     [('    [ "$v" = "$VERSION" ] || return 1', '    :')]),

    ('M35 stage_deploy_done 不比对源内容（同版本号不同代码被静默跳过 = 重装成假成功）',
     [('    [ "$src_sum" = "$dst_sum" ] || return 1', '    :')]),

    ('M36 deploy_tree_matches 只比 backend（frontend 坏了也判成已完成）',
     [('    list="$(cd "$src" 2>/dev/null && find backend frontend -type f \\',
       '    list="$(cd "$src" 2>/dev/null && find backend -type f \\')]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    restore()
    rc, out = run_tests()
    if rc != 0:
        print('❌ 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-3000:])
        return 1
    print('  ✅ 基线通过\n')

    caught = missed = 0
    for name, edits in MUTATIONS:
        src = ORIG[SETUP]
        bad = [old for old, _ in edits if old not in src]
        dup = [old for old, _ in edits if src.count(old) != 1]
        if bad or dup:
            print(f'  ⚠️  {name}')
            if bad:
                print('      ↓ 变异锚点没匹配上（源码变了？），跳过')
            if dup:
                print(f'      ↓ 变异锚点在源码里出现 {src.count(dup[0])} 次，'
                      f'不是唯一 —— 跳过')
            missed += 1
            continue
        try:
            mutated = src
            for old, new in edits:
                mutated = mutated.replace(old, new, 1)
            with open(SETUP, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if rc != 0:
                first = next((l.strip() for l in out.splitlines()
                              if '❌' in l), '')
                print(f'  ✅ {name}  —— 被捕获')
                if first:
                    print(f'      ↓ {first}')
                caught += 1
            else:
                print(f'  ❌ {name}  —— 漏网！测试没抓住')
                missed += 1
        finally:
            # 无条件还原 —— 哪怕测试抛了异常，源码也不能停在变异态。
            restore()

    print()
    print(f'════════ 结果：捕获 {caught} / {caught + missed} ════════')
    if missed:
        print('源码已全部还原，但有漏网项 —— 上面标 ❌ 的测试是假测试')
    else:
        print('源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
