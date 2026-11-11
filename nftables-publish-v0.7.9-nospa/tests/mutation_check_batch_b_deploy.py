#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批 B（部署语义）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_batch_b_deploy.py

测什么有效
----------
这三条（S2 部署后重启 / L7 生成失败兜底 / L11 原子写）的失败模式
**全都是「看起来完全正常」**：

  · 部署换了 app.py 却不重启面板 ⇒ 设备上跑的还是旧代码，现象照旧，
    极易被误判成「没修好」；
  · 重启失败被报成「已重启」⇒ 用户以为生效了，其实没有；
  · 生成脚本失败被吞掉 ⇒ 接口回「配置已保存」，用户以为 DDNS 在跑；
  · 写脚本退回覆盖写 ⇒ 平时看不出差别，直到某次写到一半被打断，
    设备上留下半截脚本、旧版本也被毁。

所以判据必须落在**行为**上：跑完之后设备上的服务/文件到底是什么。

每条变异都往「退化」方向改
--------------------------
  D1  删掉部署后的重启调用（这一步等于没做）
  D2  把重启调用改成有条件执行（条件不满足就不重启）
  D3  重启失败时报成功（失败被吞掉）
  D4  去掉「init 脚本不存在就跳过」的守卫（首次安装就误报失败）
  D5  把 ${INITD_SCRIPT} 写死成绝对路径（换机器/换路径就失灵）
  E1  去掉生成脚本的异常兜底（接口 500，用户以为配置没保存）
  E2  生成失败时不回报（假装成功）
  F1  原子写退回覆盖写（会留下半截脚本）
  F2  不解软链（内容写到别处去）
  F3  不设可执行权限（cron 跑不起来）

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。所以这里直接把未命中记成漏网。

保险丝：只备份 / 还原 **setup/setup.sh 与 backend/app.py** 两个文件，
一个字节都不碰别的。还原后逐个比对 sha256 —— 源码没还原干净时
**必须**当成失败，不能把「测试假红」误报成「变异被捕获」。
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP_SH = os.path.join(ROOT, 'setup', 'setup.sh')
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_deploy_semantics_batch_b.py')

TARGETS = {SETUP_SH: open(SETUP_SH, encoding='utf-8').read(),
           APP_PY: open(APP_PY, encoding='utf-8').read()}
ORIG_SHA = {p: hashlib.sha256(s.encode('utf-8')).hexdigest()
            for p, s in TARGETS.items()}


def restore():
    """把两个文件还原成脚本启动时的内容。幂等，可反复调用。"""
    for path, src in TARGETS.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(src)
        except OSError:
            pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    for path, want in ORIG_SHA.items():
        with open(path, 'rb') as f:
            got = hashlib.sha256(f.read()).hexdigest()
        if got != want:
            return False, '%s 还原后 sha256 不一致（%s != %s）' % (
                os.path.basename(path), got, want)
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
                       cwd=ROOT, timeout=1800,
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


# ── 锚点原文（改动生产代码时必须同步更新这里，否则会被记成漏网）──────

_A_LOCAL = ('        ok "✅ 本地部署完成"\n'
            '        remove_obsolete_files\n'
            '        restart_panel_service\n'
            '        return\n')

_A_GITHUB = ('        ok "✅ 项目部署完成 (${tag})"\n'
             '        remove_obsolete_files\n'
             '        restart_panel_service\n')

_GEN_TRY = ('    try:\n'
            '        _generate_ddns_update_script()\n'
            '    except Exception as e:\n')

_APP_ATOMIC = ('    real_path = os.path.realpath(script_path)\n'
               '    tmp_path = real_path + ".tmp"\n'
               '    with open(tmp_path, \'w\') as f:\n'
               '        f.write(script_content)\n'
               '    os.chmod(tmp_path, 0o755)\n'
               '    os.replace(tmp_path, real_path)\n')


MUTATIONS = [
    # ── S2：部署后重启 ────────────────────────────────────
    ('D1  删掉本地分支的重启调用（这一步等于没做）',
     SETUP_SH,
     [(_A_LOCAL,
       '        ok "✅ 本地部署完成"\n'
       '        remove_obsolete_files\n'
       '        return\n')]),

    ('D1b 删掉 GitHub 分支的重启调用（另一条路径同样漏掉）',
     SETUP_SH,
     [(_A_GITHUB,
       '        ok "✅ 项目部署完成 (${tag})"\n'
       '        remove_obsolete_files\n')]),

    ('D2  把重启调用改成有条件执行（条件不满足就不重启）',
     SETUP_SH,
     [(_A_LOCAL,
       '        ok "✅ 本地部署完成"\n'
       '        remove_obsolete_files\n'
       '        if [ -f /nonexistent-restart-guard ]; then\n'
       '            restart_panel_service\n'
       '        fi\n'
       '        return\n')]),

    ('D3  重启失败时报成功（失败被吞掉）',
     SETUP_SH,
     [('    if "${INITD_SCRIPT}" restart >/dev/null 2>&1; then\n'
       '        ok "面板服务已重启（已加载本次部署的新代码）"\n'
       '        return 0\n'
       '    fi\n',
       '    "${INITD_SCRIPT}" restart >/dev/null 2>&1 || true\n'
       '    ok "面板服务已重启（已加载本次部署的新代码）"\n'
       '    return 0\n')]),

    ('D4  去掉「init 脚本不存在就跳过」的守卫（首次安装就误报失败）',
     SETUP_SH,
     [('    if [ ! -f "$INITD_SCRIPT" ]; then\n'
       '        # 首次安装：init 脚本这时还没装（服务阶段才装）⇒ 没得重启。\n'
       '        # 服务阶段本来就会启动它，所以这里跳过**不算漏**。\n'
       '        return 0\n'
       '    fi\n',
       '')]),

    ('D5  把 ${INITD_SCRIPT} 写死成绝对路径（换机器/换路径就失灵）',
     SETUP_SH,
     [('    if "${INITD_SCRIPT}" restart >/dev/null 2>&1; then',
       '    if /etc/init.d/nftables-web restart >/dev/null 2>&1; then')]),

    # ── L7：生成失败兜底 ──────────────────────────────────
    ('E1  去掉生成脚本的异常兜底（接口 500，用户以为配置没保存）',
     APP_PY,
     [(_GEN_TRY,
       '    _generate_ddns_update_script()\n')]),

    ('E2  生成失败时不回报（假装成功）',
     APP_PY,
     [('    if not script_ok:\n', '    if False:\n')]),

    # ── L11：原子写 ───────────────────────────────────────
    ('F1  原子写退回覆盖写（会留下半截脚本）',
     APP_PY,
     [(_APP_ATOMIC,
       '    with open(real_path, \'w\') as f:\n'
       '        f.write(script_content)\n'
       '    os.chmod(real_path, 0o755)\n')]),

    ('F2  不解软链（内容写到别处去）',
     APP_PY,
     [('    real_path = os.path.realpath(script_path)\n',
       '    real_path = script_path\n')]),

    ('F3  不设可执行权限（cron 跑不起来）',
     APP_PY,
     [('    os.chmod(tmp_path, 0o755)\n', '')]),
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
    for name, target, edits in MUTATIONS:
        src = TARGETS[target]
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
            with open(target, 'w', encoding='utf-8') as f:
                f.write(mutated)
            rc, out = run_tests()
            if rc != 0:
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l and '[PASS]' not in l), '')
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
