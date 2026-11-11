#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""「部署后自动重新生成阿里云 DDNS 脚本」这一步的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_setup_regen_ddns.py

测什么有效
----------
这一步（D9）的失败模式全是「**看起来完全正常**」：

  · 调用点被删掉 / 被改成有条件执行 ⇒ 部署照常成功，设备上那份脚本
    永远是旧的 ⇒ 修复等于没修，现象照旧；
  · 失败被报成「已重新生成」⇒ 用户以为好了，其实没生成；
  · 软链被替换成普通文件 ⇒ 内容写到了别的地方去。

「setup.sh 里包含 regen_ddns_script」这种文本断言在上面三种改法下
**照样通过** —— 所以判据必须落在**行为**上：跑完之后设备上那份脚本
到底是什么。

每条变异都往「退化」方向改
--------------------------
  A1  删掉 main 流程里的调用点（这一步等于没做）
  A2  把调用改成有条件执行（跳过时就不重新生成）
  A3  去掉 [SKIP] 分支（没生成也报成功）
  A4  生成失败时报成功（失败被吞掉）
  A5  丢掉 python3 的退出码（失败当成功）
  B1  不解软链（内容写到别处去）
  B2  不设可执行权限（cron 跑不起来）
  B3  写入前不编译（坏模板覆盖旧脚本，留半截文件）
  B4  去掉「app.py 不存在」守卫（崩溃 + traceback）
  B5  异常类型收窄（traceback 泄到终端）
  B6  提取函数名写错（模板提取不到，静默什么都不做）
  C1  输出路径忽略 app.py 的真源（退回按目录推导，写到别处去）
  C2  AST 取不到 script_path（真源提取失败，静默写到别处去）
  C3  setup.sh 不清掉测试用环境变量（设备上会被环境变量带偏）

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。所以这里直接把未命中记成漏网。

保险丝：只备份 / 还原 **setup/setup.sh 与 backend/regen_ddns_script.py**
两个文件，一个字节都不碰别的。还原后逐个比对 sha256 —— 源码没还原
干净时**必须**当成失败，不能把「测试假红」误报成「变异被捕获」。
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
REGEN_PY = os.path.join(ROOT, 'backend', 'regen_ddns_script.py')
TEST = os.path.join(ROOT, 'tests', 'test_setup_regen_ddns.py')

TARGETS = {SETUP_SH: open(SETUP_SH, encoding='utf-8').read(),
           REGEN_PY: open(REGEN_PY, encoding='utf-8').read()}
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
                       cwd=ROOT, timeout=900,
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


MUTATIONS = [
    # ── setup.sh：接线 ─────────────────────────────────────
    ('A1  删掉 main 流程里的调用点（这一步等于没做）',
     SETUP_SH,
     [('    regen_ddns_script\n', '')]),

    ('A2  把调用改成有条件执行（跳过时就不重新生成）',
     SETUP_SH,
     [('    regen_ddns_script\n',
       '    if [ -f /nonexistent-regen-guard ]; then\n'
       '        regen_ddns_script\n'
       '    fi\n')]),

    ('A3  去掉 [SKIP] 分支（没生成也报成功）',
     SETUP_SH,
     [('    case "$out" in\n'
       '        *"[SKIP]"*) warn "阿里云 DDNS 自动更新脚本未重新生成；面板上点一次「保存配置并生成脚本」即可" ;;\n'
       '        *) ok "阿里云 DDNS 自动更新脚本已重新生成" ;;\n'
       '    esac\n',
       '    ok "阿里云 DDNS 自动更新脚本已重新生成"\n')]),

    ('A4  生成失败时报成功（失败被吞掉）',
     SETUP_SH,
     [('        warn "阿里云 DDNS 自动更新脚本重新生成失败（退出码 ${rc}）；面板上点一次「保存配置并生成脚本」即可"',
       '        ok "阿里云 DDNS 自动更新脚本已重新生成"')]),

    ('A5  丢掉 python3 的退出码（失败当成功）',
     SETUP_SH,
     [('    out="$(env -u NFTABLES_WEB_DDNS_SCRIPT python3 "$gen" 2>&1)" || rc=$?',
       '    out="$(env -u NFTABLES_WEB_DDNS_SCRIPT python3 "$gen" 2>&1)"')]),

    # ⚠ 这条专门盯「调用点被挪进**别的顶层函数**」——
    #   别的顶层函数体也是 4 空格缩进，只看缩进抓不住它；
    #   而 setup_service 是走 run_stage 的，阶段被判成「已完成」时不会执行。
    ('A12 把调用点挪进 setup_service（阶段被跳过时不执行）',
     SETUP_SH,
     [('    regen_ddns_script\n', ''),
      ('setup_service() {\n    info "========== 配置服务 =========="\n',
       'setup_service() {\n    info "========== 配置服务 =========="\n'
       '    regen_ddns_script\n')]),

    # ── backend/regen_ddns_script.py：生成逻辑 ────────────
    ('B1  不解软链（内容写到别处去）',
     REGEN_PY,
     [('    real = os.path.realpath(out_path)',
       '    real = out_path')]),

    ('B2  不设可执行权限（cron 跑不起来）',
     REGEN_PY,
     [('    os.chmod(tmp, 0o755)\n', '')]),

    ('B3  写入前不编译（坏模板覆盖旧脚本，留半截文件）',
     REGEN_PY,
     [('        compile(script, out_path, "exec")\n', '')]),

    ('B4  去掉「app.py 不存在」守卫（崩溃 + traceback）',
     REGEN_PY,
     [('        if not os.path.exists(APP_PY):\n'
       '            print("[SKIP] 找不到 %s" % APP_PY)\n'
       '            return 0\n',
       '')]),

    ('B5  异常类型收窄（traceback 泄到终端）',
     REGEN_PY,
     [('    except Exception as exc:', '    except ValueError as exc:')]),

    ('B6  提取函数名写错（模板提取不到，静默什么都不做）',
     REGEN_PY,
     [('and node.name == "_generate_ddns_update_script"',
       'and node.name == "_generate_ddns_update_script_XXX"')]),

    # ── L1：输出路径的单一真源 ───────────────────────────
    ('C1  resolve_out 忽略 app.py 的真源（退回按目录推导）',
     REGEN_PY,
     [('    return script_path or DEFAULT_OUT', '    return DEFAULT_OUT')]),

    ('C2  AST 取不到 script_path（真源提取失败，静默写到别处）',
     REGEN_PY,
     [('                elif target == "script_path":',
       '                elif target == "script_path_XXX":')]),

    ('C3  setup.sh 不清掉测试用环境变量（设备上会被环境变量带偏）',
     SETUP_SH,
     [('    out="$(env -u NFTABLES_WEB_DDNS_SCRIPT python3 "$gen" 2>&1)" || rc=$?',
       '    out="$(python3 "$gen" 2>&1)" || rc=$?')]),
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
