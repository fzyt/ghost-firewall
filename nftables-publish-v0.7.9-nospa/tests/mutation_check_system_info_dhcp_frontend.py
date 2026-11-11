#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""系统信息页 v0.19.18 新增功能的**前端**变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_system_info_dhcp_frontend.py

测什么有效
----------
这批前端代码的风险不是「报错」「白屏」，而是
「**页面照常显示，但显示的是错的东西**」——
按钮还在、表格还在，用户却点了没反应，或者被误导。

盯的是：

  **一、提示条的位置（DOM 嵌套）**
    · 把提示条塞回表单容器里 ⇒ 保存成功后表单一关，提示跟着消失
      ⇒ 用户以为「什么都没发生」。源码里两处写法长得几乎一样，
      只有嵌套关系不同 ⇒ 判据查的是嵌套。

  **二、删除只用段名**
    · 拿显示名兜底（显示名可能是中文，uci 段名不接受非 ASCII）
    · 不检查段名（`@host[0]` 这种能当 uci 参数使）

  **三、自动刷新不能冲掉表单**
    · 刷新时整个替换 deviceInfo ⇒ 用户填了一半的表单没了

  **四、失败要如实说**
    · 后端报错时自己编一句「保存失败」（把真原因藏了）
    · 重载 dnsmasq 失败时不提示（用户以为生效了，其实没有）

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去。

⚠️ 语法错误的变异不是行为变异
------------------------------
app.js 落地后先 `node --check` 一次；不过就记成漏网
（2026-11-11 审查 M8：崩了不等于断言失败）。

保险丝：只备份 / 还原 frontend/app.js 与 frontend/index.html 两个文件。
还原后逐个比对 sha256 —— 源码没还原干净时**必须**当成失败。
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_JS = os.path.join(ROOT, 'frontend', 'app.js')
INDEX_HTML = os.path.join(ROOT, 'frontend', 'index.html')
TESTS = [
    os.path.join(ROOT, 'tests', 'test_frontend_system_info_dhcp.js'),
    os.path.join(ROOT, 'tests', 'test_frontend_system_info.js'),
    os.path.join(ROOT, 'tests', 'test_frontend_system_info_render.js'),
]

FILES = (APP_JS, INDEX_HTML)
ORIG = {p: open(p, encoding='utf-8').read() for p in FILES}
ORIG_SHA = {p: hashlib.sha256(ORIG[p].encode('utf-8')).hexdigest()
            for p in FILES}


def restore():
    for p in FILES:
        try:
            with open(p, 'w', encoding='utf-8') as f:
                f.write(ORIG[p])
        except OSError:
            pass


def restore_verified():
    restore()
    for p in FILES:
        try:
            with open(p, 'rb') as f:
                got = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            got = None
        if got != ORIG_SHA[p]:
            return False, '%s 还原后 sha256 不一致' % os.path.basename(p)
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
    """跑全部前端判据。任一失败 ⇒ 算捕获。

    ⚠️ JS 判据的失败标记是 [FAIL]（与 Python 判据一致），
       rc != 0 且输出里有 [FAIL] 行才算捕获（崩了不算）。
    """
    caught = False
    outs = []
    for t in TESTS:
        r = subprocess.run(['node', t], capture_output=True, text=True,
                           cwd=ROOT, timeout=300)
        out = (r.stdout or '') + (r.stderr or '')
        outs.append(out)
        if r.returncode != 0:
            for line in out.splitlines():
                s = line.strip()
                if '[FAIL]' in s and '[PASS]' not in s:
                    caught = True
                    break
    return caught, outs


def apply_edits(src, edits):
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点出现 %d 次（要求唯一）: %r' % (n, old[:70]))
        src = src.replace(old, new)
    return src


MUTATIONS = [
    # ── 一、提示条的位置 ──────────────────────────────────────
    ('F1  提示条被塞回表单容器里（表单一关，提示跟着消失）',
     [(INDEX_HTML,
       '              <!-- 提示条\n'
       '                   ⚠️ 必须放在表单**外面**：保存成功后表单会关闭，\n'
       '                      而「已保存，但未重载 dnsmasq」这类提示\n'
       '                      如果写在表单里 ⇒ 表单一关，提示也跟着没了，\n'
       '                      用户只看到「什么都没发生」。 -->\n'
       '              <div x-show="deviceInfo.dhcpFormError"\n'
       '                   class="mb-3 text-xs text-red-600"\n'
       '                   x-text="deviceInfo.dhcpFormError"></div>\n'
       '\n'
       '              <!-- 新增/编辑表单 -->\n'
       '              <div x-show="deviceInfo.dhcpFormOpen"\n'
       '                   x-transition\n'
       '                   class="mt-4 bg-white border rounded p-4">\n',
       '              <!-- 新增/编辑表单 -->\n'
       '              <div x-show="deviceInfo.dhcpFormOpen"\n'
       '                   x-transition\n'
       '                   class="mt-4 bg-white border rounded p-4">\n'
       '                <div x-show="deviceInfo.dhcpFormError"\n'
       '                     class="mt-3 text-xs text-red-600"\n'
       '                     x-text="deviceInfo.dhcpFormError"></div>\n')]),

    # ── 二、删除只用段名 ──────────────────────────────────────
    ('F2  删除时拿显示名兜底（uci 不接受非 ASCII 段名）',
     [(APP_JS,
       '      const section = h.section || \'\';\n',
       '      const section = h.section || h.name || \'\';\n')]),

    ('F3  删除时不检查段名（@host[0] 能当 uci 参数使）',
     [(APP_JS,
       '      if (!section) {\n'
       '        // 匿名段（config host 没起名）没有可传的标识 ⇒ 只能手改配置文件。\n'
       '        this.deviceInfo.dhcpFormError = \'这条绑定没有标识（匿名段），面板删不了，请手动编辑 /etc/config/dhcp\';\n'
       '        return;\n'
       '      }\n',
       '')]),

    # ── 三、刷新不能冲掉表单 ──────────────────────────────────
    ('F4  刷新时整个替换 deviceInfo（表单被冲掉）',
     [(APP_JS,
       '        this.deviceInfo = {\n'
       '          ...this.deviceInfo,\n'
       '          loading: false,\n'
       '          loaded: true,\n'
       '          error: \'\',\n'
       '          data: info || null,\n'
       '        };',
       '        this.deviceInfo = {\n'
       '          loading: false,\n'
       '          loaded: true,\n'
       '          error: \'\',\n'
       '          data: info || null,\n'
       '        };')]),

    # ── 四、失败要如实说 ──────────────────────────────────────
    ('F5  后端报错时自己编一句「保存失败」（把真原因藏了）',
     [(APP_JS,
       '      } catch (e) {\n'
       '        this.deviceInfo.dhcpFormError = e.message || \'保存失败\';\n'
       '      } finally {\n'
       '        this.deviceInfo.dhcpSaving = false;\n'
       '      }',
       '      } catch (e) {\n'
       '        this.deviceInfo.dhcpFormError = \'保存失败\';\n'
       '      } finally {\n'
       '        this.deviceInfo.dhcpSaving = false;\n'
       '      }')]),

    ('F6  重载 dnsmasq 失败时不提示（用户以为生效了）',
     [(APP_JS,
       '        const reloadMsg = (j.reload && j.reload.message) || \'\';\n'
       '        if (!j.reload || j.reload.ok === false) {\n'
       '          this.deviceInfo.dhcpFormError = \'已保存，但\' + (reloadMsg || \'未重载 dnsmasq，可能未生效\');\n'
       '        }',
       '        const reloadMsg = (j.reload && j.reload.message) || \'\';\n'
       '        if (false) {\n'
       '          this.deviceInfo.dhcpFormError = \'已保存，但\' + (reloadMsg || \'未重载 dnsmasq，可能未生效\');\n'
       '        }')]),

    ('F7  提交时不 trim（多一个空格就写不进去）',
     [(APP_JS,
       '          name: (f.name || \'\').trim(),\n'
       '          ip: (f.ip || \'\').trim(),\n'
       '          mac: (f.mac || \'\').trim(),',
       '          name: (f.name || \'\'),\n'
       '          ip: (f.ip || \'\'),\n'
       '          mac: (f.mac || \'\'),')]),

    ('F8  删除时重载失败不提示',
     [(APP_JS,
       '        const reloadMsg = (j.reload && j.reload.message) || \'\';\n'
       '        if (!j.reload || j.reload.ok === false) {\n'
       '          this.deviceInfo.dhcpFormError = \'已删除，但\' + (reloadMsg || \'未重载 dnsmasq\');\n'
       '        }',
       '        const reloadMsg = (j.reload && j.reload.message) || \'\';\n'
       '        if (false) {\n'
       '          this.deviceInfo.dhcpFormError = \'已删除，但\' + (reloadMsg || \'未重载 dnsmasq\');\n'
       '        }')]),
]


def main():
    print('=== 基线：未变异时测试必须全绿 ===')
    ok, detail = restore_verified()
    if not ok:
        print('[FAIL] %s —— 变异验证无意义' % detail)
        return 1
    caught, outs = run_tests()
    if caught:
        print('[FAIL] 基线就不绿，变异验证无意义 —— 先修测试')
        print(outs[-1][-3000:])
        return 1
    print('  [PASS] 基线通过\n')

    caught = missed = 0
    for name, edits in MUTATIONS:
        srcs = dict(ORIG)
        bad = []
        for path, old, _new in edits:
            n = srcs[path].count(old)
            if n != 1:
                bad.append('%s 锚点出现 %d 次' % (os.path.basename(path), n))
        if bad:
            print('  [FAIL] %s  —— %s ⇒ 算漏网' % (name, '；'.join(bad)))
            missed += 1
            continue
        try:
            for path, old, new in edits:
                srcs[path] = apply_edits(srcs[path], [(old, new)])
            for path, text in srcs.items():
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(text)
            # ⚠ 语法错误的变异不是行为变异 —— app.js 跑不起来时，
            #   前端判据会崩，而崩了不等于断言失败。
            r = subprocess.run(['node', '--check', APP_JS],
                               capture_output=True, text=True)
            if r.returncode != 0:
                print('  [FAIL] %s  —— 变异后语法错误（不是行为变异）⇒ 算漏网' % name)
                print('      ↓ %s' % (r.stderr or '').splitlines()[-1][:100]
                      if r.stderr else '')
                missed += 1
                continue
            caught_flag, outs = run_tests()
            if caught_flag:
                first = ''
                for out in outs:
                    for line in out.splitlines():
                        s = line.strip()
                        if '[FAIL]' in s and '[PASS]' not in s:
                            first = s
                            break
                    if first:
                        break
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
