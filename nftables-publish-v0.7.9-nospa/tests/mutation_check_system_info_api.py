#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""系统信息页**接口层**（backend/app.py）的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_system_info_api.py

测什么有效
----------
写路径的判据（tests/test_dhcp_hosts_write.py）验的是**模块**；
这一份验的是**接口层** —— 两者是不同的失败模式：

  **一、请求体形状**
    · body 不是对象时不拦（`body.get` 抛 AttributeError ⇒ 500）
      ⇒ 客户端发错了却收到「服务端错误」，排查方向完全错。

  **二、认证门控**
    · 漏掉 `_is_authenticated()` ⇒ 新接口变成匿名可写
      ⇒ 这是**能改路由器配置**的接口，漏门控的后果比漏校验严重得多。

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。

⚠️ 语法错误的变异不是行为变异
------------------------------
落地后先 py_compile 一次，语法不过直接算漏网（2026-11-11 审查 M8）。

保险丝：只备份 / 还原 backend/app.py 一个文件。
还原后比对 sha256 —— 源码没还原干净时**必须**当成失败。
"""
import atexit
import hashlib
import os
import py_compile
import signal
import subprocess
import sys
import tempfile

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'backend', 'app.py')
TEST = os.path.join(ROOT, 'tests', 'test_system_info_endpoint.py')

ORIG = open(SCRIPT, encoding='utf-8').read()
ORIG_SHA = hashlib.sha256(ORIG.encode('utf-8')).hexdigest()


def _judge_capture(rc, out):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」
      ⇒ 只有输出里真的出现**断言失败**的标记行才算捕获。
    """
    if rc == 0:
        return False
    for line in out.splitlines():
        s = line.strip()
        if ('[FAIL]' in s and '[PASS]' not in s):
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def restore():
    """把源码还原成启动时的内容。幂等，可反复调用。"""
    try:
        with open(SCRIPT, 'w', encoding='utf-8') as f:
            f.write(ORIG)
    except OSError:
        pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    try:
        with open(SCRIPT, 'rb') as f:
            got = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        got = None
    if got != ORIG_SHA:
        return False, '%s 还原后 sha256 不一致（%s != %s）' % (
            os.path.basename(SCRIPT), got, ORIG_SHA)
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
    # ── 一、请求体形状 ────────────────────────────────────────
    ('A1  POST body 不是对象时不拦（客户端发错却回 500）',
     [('    if not isinstance(body, dict):\n'
       '        return jsonify({\n'
       '            \'success\': False,\n'
       '            \'code\': \'BAD_REQUEST\',\n'
       '            \'message\': \'请求体必须是 JSON 对象（含 name / mac / ip 字段）\',\n'
       '        }), 400',
       '    if False:\n'
       '        return jsonify({\n'
       '            \'success\': False,\n'
       '            \'code\': \'BAD_REQUEST\',\n'
       '            \'message\': \'请求体必须是 JSON 对象（含 name / mac / ip 字段）\',\n'
       '        }), 400')]),

    # ── 二、认证门控 ──────────────────────────────────────────
    #
    # ⚠️ 认证是**双层**的：全局 `before_request` 先拦一道，
    #    端点里还有一道 `_is_authenticated()`。
    #    ⇒ 只拆掉端点里那道是**等价变异**（全局那道照样拦）
    #    ⇒ 必须**同时**放开全局拦截器对这条路径的放行，才是真变异。
    ('A2  新增绑定接口漏掉认证门控（全局拦截器也放开 ⇒ 匿名可写）',
     [('    # 未登录：API 返回 401 JSON；其他也返回 401（前端拦截后跳登录）\n'
       '    return jsonify({\'success\': False, \'code\': \'AUTH_REQUIRED\', \'message\': \'未登录\'}), 401',
       '    # 未登录：API 返回 401 JSON；其他也返回 401（前端拦截后跳登录）\n'
       '    if path.startswith(\'/api/system/dhcp-hosts\'):\n'
       '        return None\n'
       '    return jsonify({\'success\': False, \'code\': \'AUTH_REQUIRED\', \'message\': \'未登录\'}), 401'),
      ('def system_dhcp_hosts_add():\n'
       '    """新增一条 DHCP 静态绑定。"""\n'
       '    if not _is_authenticated():',
       'def system_dhcp_hosts_add():\n'
       '    """新增一条 DHCP 静态绑定。"""\n'
       '    if False:')]),

    ('A3  删除绑定接口漏掉认证门控（全局拦截器也放开 ⇒ 匿名可删）',
     [('    # 未登录：API 返回 401 JSON；其他也返回 401（前端拦截后跳登录）\n'
       '    return jsonify({\'success\': False, \'code\': \'AUTH_REQUIRED\', \'message\': \'未登录\'}), 401',
       '    # 未登录：API 返回 401 JSON；其他也返回 401（前端拦截后跳登录）\n'
       '    if path.startswith(\'/api/system/dhcp-hosts\'):\n'
       '        return None\n'
       '    return jsonify({\'success\': False, \'code\': \'AUTH_REQUIRED\', \'message\': \'未登录\'}), 401'),
      ('def system_dhcp_hosts_delete(section):\n'
       '    """删除一条 DHCP 静态绑定。"""\n'
       '    if not _is_authenticated():',
       'def system_dhcp_hosts_delete(section):\n'
       '    """删除一条 DHCP 静态绑定。"""\n'
       '    if False:')]),
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
            with open(SCRIPT, 'w', encoding='utf-8') as f:
                f.write(mutated)
            # ⚠ 语法错误的变异不是行为变异 —— 测试会崩，而崩溃不等于断言失败。
            try:
                py_compile.compile(SCRIPT, cfile=os.path.join(
                    tempfile.gettempdir(), 'app_system_info_mut_check.pyc'),
                    doraise=True)
            except py_compile.PyCompileError as e:
                print('  [FAIL] %s  —— 变异后语法错误（不是行为变异）⇒ 算漏网' % name)
                print('      ↓ %s' % str(e).splitlines()[-1][:100])
                missed += 1
                continue
            rc, out = run_tests()
            if _judge_capture(rc, out):
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
