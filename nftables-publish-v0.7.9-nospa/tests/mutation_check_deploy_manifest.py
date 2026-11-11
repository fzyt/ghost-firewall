#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""「部署脚本的传输清单」的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_deploy_manifest.py

测什么有效
----------
2026-11-11 在 .232 真机部署时实测发现（不是推理）：

  deploy.sh 的**升级路径**传输清单只有 backend frontend tools tests VERSION
  ⇒ 设备上 `/opt/nftables-web-v2/setup/setup.sh` 永远是装机器时那份旧的
  ⇒ 批 B 的 S2 修复（部署后无条件重启面板服务）到不了设备：
     用户在设备上跑 `setup.sh --local` 二次部署 ⇒ 部署完**不重启**
  ⇒ 新代码不生效 —— 正是 S2 要修的那个 bug 原样复发。

这条链路的失败模式全是「**看起来完全正常**」：
  · 清单少一个目录 ⇒ 部署照样成功、版本号照样更新、自检照样全过
    （自检只查「版本 = 本地版本」，查不到「某个文件是旧的」）；
  · 清单多收几个文件 ⇒ 同样一切正常，只是把本机的东西泄到设备上。

所以判据不能只查「文本里有没有 setup」——
  注释里写一句「setup 也要传」就假绿了。
⇒ 判据是**真的跑一遍** deploy.sh 里那组 git ls-files 参数，
  再看结果里到底有没有 setup/setup.sh。

每条变异都往「退化」方向改
--------------------------
  G1  升级路径的清单去掉 setup（S2 修复到不了设备）
  G2  清单去掉 tools（工具脚本永远停在旧版）
  G3  清单去掉 tests（设备上跑的是旧版测试）
  G4  清单改成 tar 整个目录（把 .gitignore 挡掉的东西一起带上）
  G5  清单用 `ls-files` 不带 `--` 限目录（等于传整个仓库）

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。所以这里直接把未命中记成漏网。

保险丝：只备份 / 还原 **tools/deploy.sh** 一个文件。
还原后比对 sha256 —— 源码没还原干净时**必须**当成失败，
不能把「测试假红」误报成「变异被捕获」。
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY_SH = os.path.join(ROOT, 'tools', 'deploy.sh')
TEST = os.path.join(ROOT, 'tests', 'test_deploy_script.py')

ORIG = open(DEPLOY_SH, encoding='utf-8').read()
ORIG_SHA = hashlib.sha256(ORIG.encode('utf-8')).hexdigest()


def _judge_capture(rc, out):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」
      （2026-11-11 审查 M8：崩了也被记成「捕获」⇒ 那个捕获是假的）。
    ⇒ 只有输出里真的出现**断言失败**的标记行才算捕获；
      只有崩溃、没有失败行的 ⇒ 算漏网（宁可漏判，不可假捕获）。
    """
    if rc == 0:
        return False
    for line in out.splitlines():
        s = line.strip()
        # 失败标记用 Unicode 转义写：源码里不出现符号本身（AGENTS.md 禁 emoji）
        if ('[FAIL]' in s and '[PASS]' not in s) or \
                ('❌' in s and '✅' not in s):
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    """把 deploy.sh 还原成启动时的内容。幂等，可反复调用。"""
    try:
        with open(DEPLOY_SH, 'w', encoding='utf-8') as f:
            f.write(ORIG)
    except OSError:
        pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    try:
        with open(DEPLOY_SH, 'rb') as f:
            got = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        got = None
    if got != ORIG_SHA:
        return False, '%s 还原后 sha256 不一致（%s != %s）' % (
            os.path.basename(DEPLOY_SH), got, ORIG_SHA)
    return True, '源码已还原，sha256 一致'


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
                       cwd=ROOT, timeout=600,
                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    return r.returncode, (r.stdout + r.stderr)


def apply_edits(src, edits):
    """按顺序应用编辑。锚点必须在源码里**唯一**，否则报错（不静默跳过）。"""
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点出现 %d 次（要求唯一）: %r' % (n, old[:70]))
        src = src.replace(old, new)
    return src


# 升级路径那一支的清单原文（改动 deploy.sh 时必须同步更新这里）
_UPGRADE_LIST = ('        git -C "$SRC" ls-files -z -- backend frontend tools '
                 'tests setup VERSION > "$track_list" 2>/dev/null \\\n')

MUTATIONS = [
    ('G1  升级路径的清单去掉 setup（S2 修复到不了设备）',
     [(_UPGRADE_LIST,
       '        git -C "$SRC" ls-files -z -- backend frontend tools '
       'tests VERSION > "$track_list" 2>/dev/null \\\n')]),

    ('G2  清单去掉 tools（设备上的工具脚本永远停在旧版）',
     [(_UPGRADE_LIST,
       '        git -C "$SRC" ls-files -z -- backend frontend '
       'tests setup VERSION > "$track_list" 2>/dev/null \\\n')]),

    ('G3  清单去掉 tests（设备上跑的是旧版测试）',
     [(_UPGRADE_LIST,
       '        git -C "$SRC" ls-files -z -- backend frontend tools '
       'setup VERSION > "$track_list" 2>/dev/null \\\n')]),

    ('G4  退回 tar 整个目录（把 .gitignore 挡掉的东西一起带上）',
     [(_UPGRADE_LIST,
       '        git -C "$SRC" ls-files -z -- . > "$track_list" 2>/dev/null \\\n')]),

    ('G5  清单不限定目录（等于传整个仓库，含本机文件）',
     [(_UPGRADE_LIST,
       '        git -C "$SRC" ls-files -z > "$track_list" 2>/dev/null \\\n')]),

    # ── 重新生成 cron 脚本（2026-11-11 真机实测发现的缺口）──────────
    #
    # 设备上的 aliyun-ddns-update.py 是「装机器时生成的那一份」，
    # 它不随 app.py 模板更新 ⇒ 模板里修好的东西在 cron 实际跑的那份里没有。
    ('H1  部署时不重新生成 cron 脚本（cron 跑的是旧逻辑）',
     [('    phase_regen_ddns\n    phase_restart\n',
       '    phase_restart\n')]),

    ('H2  重新生成放到重启**之后**（顺序反了）',
     [('    phase_regen_ddns\n    phase_restart\n',
       '    phase_restart\n    phase_regen_ddns\n')]),

    ('H3  自检里不比对 cron 脚本与模板一致（漏了也不会知道）',
     [('            check_eq "cron 脚本与当前模板一致（不是装机器时那份旧的）" \\\n'
       '                     "$cron_md5_gen" "$cron_md5_real"\n',
       '')]),

    ('H4  重新生成失败时 die（整个部署被中断，用户设备停在半路）',
     [('        warn "阿里云 DDNS 自动更新脚本重新生成失败（退出码 ${rc}）；面板上点一次「保存配置并生成脚本」即可"\n',
       '        die "阿里云 DDNS 自动更新脚本重新生成失败（退出码 ${rc}）"\n')]),

    ('H5  用了 setup.sh 的辅助函数 info（deploy.sh 里没这个 ⇒ 部署中断并回滚）',
     [('    [ -n "$out" ] && step "${out}"\n',
       '    [ -n "$out" ] && info "${out}"\n')]),

    ('H6  退出码被 || true 吃掉（regen 失败会被当成成功）',
     [('    out="$(rssh "cd \'$APP_DIR/backend\' && env -u NFTABLES_WEB_DDNS_SCRIPT python3 ./regen_ddns_script.py 2>&1")"\n'
       '    rc=$?\n',
       '    out="$(rssh "cd \'$APP_DIR/backend\' && env -u NFTABLES_WEB_DDNS_SCRIPT python3 ./regen_ddns_script.py 2>&1" || true)"\n'
       '    rc=$?\n')]),

    # ── 新增后端模块是否真的到位（2026-11-12 补）────────────────
    #
    # 传输清单走 `git ls-files` ⇒ **新文件没 git add 就不会传过去**，
    # 设备上 backend/dhcp_hosts.py 不存在 ⇒ app.py 的 import 直接炸
    # ⇒ 面板整个打不开。
    # 「版本号对上了」证明不了新文件到位 ⇒ 必须逐个比 md5。
    ('I1  自检里不比对 dhcp_hosts.py 的 md5（模块没传过去也不知道）',
     [('        check_eq "设备上的 dhcp_hosts.py 与本地一致（写操作模块确实到位）" \\\n'
       '                 "$mod_md5_local" "$mod_md5_real"\n',
       '')]),

    ('I2  自检里把本地 md5 换成设备上的（自己跟自己比，永远相等）',
     [('        check_eq "设备上的 dhcp_hosts.py 与本地一致（写操作模块确实到位）" \\\n'
       '                 "$mod_md5_local" "$mod_md5_real"\n',
       '        check_eq "设备上的 dhcp_hosts.py 与本地一致（写操作模块确实到位）" \\\n'
       '                 "$mod_md5_real" "$mod_md5_real"\n')]),

    ('I3  传输清单去掉 backend（新增的后端模块永远传不过去）',
     [(_UPGRADE_LIST,
       '        git -C "$SRC" ls-files -z -- frontend tools '
       'tests setup VERSION > "$track_list" 2>/dev/null \\\n')]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    ok, detail = restore_verified()
    if not ok:
        print('[FAIL] %s —— 变异验证无意义' % detail)
        return 1
    rc, out = run_tests()
    if rc != 0:
        print('[FAIL] 基线就不绿，变异验证无意义 —— 先修测试')
        print(out[-3000:])
        return 1
    print('  [PASS] 基线通过\n')

    caught = missed = 0
    for name, edits in MUTATIONS:
        src = ORIG
        bad = [old for old, _ in edits if old not in src]
        dup = [old for old, _ in edits if src.count(old) != 1]
        if bad or dup:
            why = []
            if bad:
                why.append('锚点没匹配上（源码变了？）')
            if dup:
                why.append('锚点出现 %d 次，不是唯一' % src.count(dup[0]))
            print('  [FAIL] %s  —— ' % name + '；'.join(why) + ' ⇒ 算漏网')
            missed += 1
            continue
        try:
            mutated = apply_edits(src, edits)
            with open(DEPLOY_SH, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if _judge_capture(rc, out):
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l and '[PASS]' not in l), '')
                if not first:
                    first = next((l.strip() for l in out.splitlines()
                                  if '❌' in l and '✅' not in l), '')
                print('  [PASS] %s  —— 被捕获' % name)
                if first:
                    print('      ↓ %s' % first)
                caught += 1
            else:
                print('  [FAIL] %s  —— 漏网！测试没抓住' % name)
                missed += 1
        finally:
            ok, detail = restore_verified()
            if not ok:
                print('  [FAIL] %s  —— %s ⇒ 后续变异全部作废' % (name, detail))
                print('=' * 60)
                print('  捕获 %d / %d（本次中止：源码没还原干净）'
                      % (caught, caught + missed + 1))
                return 1

    print()
    print('=' * 60)
    print('  捕获 %d / %d' % (caught, caught + missed))
    if missed:
        print('  源码已全部还原，但有漏网项 —— 上面标 [FAIL] 的测试是假测试')
    else:
        print('  源码已全部还原')
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
