#!/usr/bin/env python3
"""设备端 init 脚本的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_init_scripts.py

测什么有效
----------
这一轮改的都是 init 脚本 —— 最危险的退化不是「写错了」，而是**看起来
更稳妥、实际上把护栏拆了**：校验被去掉、复核被去掉、失败被当成成功。
那种代码读起来完全正常，单测很容易全绿 —— 只有真的把护栏拆掉，
测试才会变红。所以下面每条变异都往「拆护栏」这个方向改；抓不住就说明
测试是假测试。

对应关系（每条修复至少一条变异）：

  P1-32  M1 先校验再停      M2 disable 的时机      M3 deploy_mode
  P1-33  M4 功能性复核
  P1-34  M5 降级如实上报    M6 失败恢复平台防火墙  M7 回退 .lastgood
  P2-4   M8 坏 JSON 重播    M9 合法 JSON 不被重播
  P2-28  M10 目录权限归一化
  P1-46  M11 配置端口真的用上  M12 端口范围校验
  P1-35  M13 setup.sh 仍建 /etc/nftables
  P1-36  M14 轮询里检查进程存活
  P1-37  M15 setup.sh 播种即 640 + nftweb 组
  P1-48  M16 setup.sh 不碰 crontab

保险丝：只备份 / 还原**我自己会改的那三个文件**
------------------------------------------------
这个仓库里多个批次在并行改同一棵树：backend/app.py、backend/auth_gateway.py、
frontend/** 都有别人在动。所以这里**刻意不用** tests/_mutation_guard.py 的
MutationGuard —— 它启动时会做「上次被硬杀的残留快照」清理，把整个快照里的
所有文件写回去（别人的 app.py / auth_gateway.py、我的 init 脚本都在里面），
而且它还原时会把**脚本运行之后**别人做的改动一起吞掉。

本脚本的保险丝只做三件事：
  1. 启动时把三个文件的原文读进内存（ORIG）
  2. 每条变异跑完**无条件**写回 ORIG（finally + atexit + SIGTERM/SIGINT）
  3. 全程**不碰其它任何文件**，不扫描 /tmp/mutguard-*，不还原任何快照目录

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
PANEL = os.path.join(ROOT, 'backend', 'nftables-web.init')
AUTH = os.path.join(ROOT, 'backend', 'nftables-web-auth.init')
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')
TEST = os.path.join(ROOT, 'tests', 'test_init_scripts.py')

# 我独占、也只有我会改的三个文件。
ORIG = {
    PANEL: open(PANEL, encoding='utf-8').read(),
    AUTH: open(AUTH, encoding='utf-8').read(),
    SETUP: open(SETUP, encoding='utf-8').read(),
}


def restore():
    """把三个文件还原成脚本启动时的内容。幂等，可反复调用。"""
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
# 变异定义：(名称, 目标文件, [(原串, 替换串), ...])
# ─────────────────────────────────────────────────────────────

MUTATIONS = [
    # ── P1-32：先校验、再停 ───────────────────────────────────
    ('M1  去掉 nft -c 校验（没校验就停 fw4、就加载规则集）',
     PANEL, [('    if ! nft -c -f "$RULES_FILE" >>"$RECOVERY_LOG" 2>&1; then',
              '    if false; then')]),

    ('M2  复核通过后也不永久 disable 平台防火墙（fw4 下次开机又起来）',
     PANEL, [('''            if [ "$_takeover" = "1" ]; then
                /etc/init.d/firewall disable 2>/dev/null
            fi''',
              '''            if [ "$_takeover" = "1" ]; then
                :
            fi''')]),

    ('M3  无视 deploy_mode（linux_gateway 也去停平台防火墙）',
     PANEL, [('    if [ "$_mode" = "linux_gateway" ]; then',
              '    if false; then')]),

    # ── P1-33：功能性复核 ─────────────────────────────────────
    ('M4  去掉功能性复核（nft 退出码 0 就算装上了）',
     PANEL, [('''_ruleset_usable() {
    _out=$(nft list table inet fw4 2>/dev/null) || return 1''',
              '''_ruleset_usable() {
    return 0
    _out=$(nft list table inet fw4 2>/dev/null) || return 1''')]),

    # ── P1-34：失败即回滚并如实上报 ───────────────────────────
    ('M5  回退到 .lastgood 之后报成 ok（面板仍报成功 = 钉死在过期策略）',
     PANEL, [('_recovery_state degraded "${_why}；已回退到 .lastgood（上一版策略）"',
              '_recovery_state ok "${_why}；已回退到 .lastgood（上一版策略）"')]),

    ('M6  失败时不把平台防火墙拉回来（设备裸奔）',
     PANEL, [('''    if [ "$_takeover" = "1" ]; then
        /etc/init.d/firewall enable 2>/dev/null
        /etc/init.d/firewall start 2>/dev/null
    fi''',
              '''    if false; then
        /etc/init.d/firewall enable 2>/dev/null
        /etc/init.d/firewall start 2>/dev/null
    fi''')]),

    ('M7  失败时不回退 .lastgood（直接判死，设备没有可用规则集）',
     PANEL, [('        if nft -c -f "$LASTGOOD_FILE" >>"$RECOVERY_LOG" 2>&1; then',
              '        if false; then')]),

    # ── P2-4：非法 JSON 重播 ──────────────────────────────────
    ('M8  非空但非法 JSON 不重播（吊销表读不出来 = 全员已吊销 = 登不进）',
     AUTH, [('        elif ! _json_object_ok "$_cfgdir/$f"; then',
             '        elif false; then')]),

    ('M9  合法 JSON 也被重播（把限流记录抹掉）',
     AUTH, [('        if [ ! -s "$_cfgdir/$f" ]; then',
             '        if true; then')]),

    # ── P2-28：目录权限归一化 ─────────────────────────────────
    ('M10 /etc/nftables 的模式位不归一化（只 chgrp + g+s）',
     AUTH, [('    chmod 2750 "$_cfgdir" || return 1', '    :')]),

    # ── P1-46：auth_api_port 运行时生效 ───────────────────────
    ('M11 配置里的端口不校验（一律回落 8444 = 配置写了也不生效）',
     AUTH, [('''            if awk -v v="$p" 'BEGIN { exit !(v ~ /^[0-9]+$/ && v+0 >= 1 && v+0 <= 65535) }'; then''',
              '''            if false; then''')]),

    ('M12 端口范围不校验（65536 也照用 = 网关 bind 失败直接退出）',
     AUTH, [('''v+0 >= 1 && v+0 <= 65535) }'; then''',
              '''v+0 >= 1 && v+0 <= 99999) }'; then''')]),

    # ── 已过时条目的回归守卫（防止有人「改回来」）──────────────
    ('M13 setup.sh 不再 mkdir -p /etc/nftables（网关会因目录缺失而中止）',
     SETUP, [('    mkdir -p "$CONFIG_DIR"', '    :')]),

    ('M14 网关 init 的轮询不再检查进程存活（空等 150 次才判失败）',
     AUTH, [('        kill -0 "$pid" 2>/dev/null || break          # 进程自己退了，交给下面的失败分支',
             '        :')]),

    ('M15 setup.sh 播种配置时不再是 640 + nftweb 组（网关读不到）',
     SETUP, [('    if ! chgrp nftweb "$CONFIG_FILE" 2>/dev/null; then',
              '    if ! true; then')]),

    ('M16 setup.sh 又去写 crontab（证书续期 cron 的老坑回来了）',
     SETUP, [('    mkdir -p "$CONFIG_DIR"',
              '    mkdir -p "$CONFIG_DIR"\n    crontab - <<EOF\n* * * * * /opt/nftables-web/renew-certs.sh\nEOF')]),
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
    for name, path, edits in MUTATIONS:
        src = ORIG[path]
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
            with open(path, 'w', encoding='utf-8') as f:
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
