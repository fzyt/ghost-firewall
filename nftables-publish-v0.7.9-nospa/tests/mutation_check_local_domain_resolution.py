#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""「证书域名 → 本机 IP」本地解析的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_local_domain_resolution.py

测什么有效
----------
写 `/etc/config/dhcp` 的失败模式是「DHCP/DNS 整个瘫掉」——
客户端拿不到地址、解析不了域名。
而这类退化在单测里最容易滑过去：单测只看「函数返回了什么」，
看不到「磁盘上现在是什么」。

所以每条变异都往「让这条链退化」的方向改：

  **一、写出的东西是错的**
    · 条目格式少一个斜杠（dnsmasq 认不出来 ⇒ 解析不生效）
    · 条目格式多一个斜杠（域名被当成空）
    · 把用户自己写的 address 也一起删了（用户的解析被面板抹掉）

  **二、状态没跟上**
    · 不写标记 option（域名变了之后旧条目删不掉 ⇒ 残留记录）
    · 域名变了不删旧条目（同一个域名指向两台机器）
    · 同域名 IP 变了不更新（机器换 IP 后域名还指向旧地址）
    · 基础域名为空时不清条目（证书换掉了，域名还指向本机）

  **三、安全网被拆掉**
    · 非法域名/IP 也放行（`/x/1.2.3.4` 这种会被 dnsmasq 误读）
    · 写前不备份（出问题没得恢复）
    · 写坏了不回滚（坏配置留在设备上，dnsmasq 起不来）
    · 重载失败当写失败（文件其实是对的，用户被误导）
    · 不重载 dnsmasq（配置写对了但没生效）

  **四、面板侧的钩子**
    · 钩子不接住异常（保存配置的整个流程被拖垮）
    · 钩子忽略传进来的 LAN 地址（自己探测 ⇒ 探测不到就不写）

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。

⚠️ 语法错误的变异不是行为变异
------------------------------
改出来的代码必须**能跑**，否则测试脚本会崩，而崩溃不等于断言失败。

保险丝：备份 / 还原 backend/dhcp_hosts.py 与 backend/app.py 两个文件。
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
FILES = {
    'dhcp': os.path.join(ROOT, 'backend', 'dhcp_hosts.py'),
    'app': os.path.join(ROOT, 'backend', 'app.py'),
}
TEST = os.path.join(ROOT, 'tests', 'test_local_domain_resolution.py')

ORIG = {k: open(v, encoding='utf-8').read() for k, v in FILES.items()}
ORIG_SHA = {k: hashlib.sha256(s.encode('utf-8')).hexdigest()
            for k, s in ORIG.items()}

# (描述, 文件键, [(旧文本, 新文本), ...])
MUTATIONS = [
    # ── 写出的东西是错的 ──────────────────────────────────────
    ('LD-1 条目格式少一个斜杠（dnsmasq 认不出来）', 'dhcp',
     [("        want = ('/%s/%s' % (domain, ip)) if domain else ''",
       "        want = ('%s/%s' % (domain, ip)) if domain else ''")]),

    ('LD-2 条目格式多一个斜杠（域名被当成空）', 'dhcp',
     [("        want = ('/%s/%s' % (domain, ip)) if domain else ''",
       "        want = ('//%s/%s' % (domain, ip)) if domain else ''")]),

    ('LD-3 把用户自己写的 address 也一起删了', 'dhcp',
     [("        keep = [e for e in current if _address_domain(e) not in ours]",
       "        keep = []")]),

    # ── 状态没跟上 ────────────────────────────────────────────
    ('LD-4 不写标记 option（域名变了旧条目删不掉）', 'dhcp',
     [("                rc, out = _run_uci(['set', 'dhcp.%s.%s=%s'\n"
       "                                    % (section, LOCAL_DOMAIN_OPTION, domain)])",
       "                pass")]),

    ('LD-5 域名变了不删旧条目', 'dhcp',
     [("            for e in current:\n"
       "                if _address_domain(e) in ours:\n"
       "                    # 只删确实在列表里的值 ⇒ del_list 不会 rc=1\n"
       "                    _run_uci(['del_list',\n"
       "                              'dhcp.%s.address=%s' % (section, e)])",
       "            pass")]),

    ('LD-6 基础域名为空时不清条目（域名还指向本机）', 'dhcp',
     [("        want = ('/%s/%s' % (domain, ip)) if domain else ''",
       "        want = ('/%s/%s' % (domain or marker, ip)) if (domain or marker) else ''")]),

    # ── 安全网被拆掉 ──────────────────────────────────────────
    ('LD-7 非法域名也放行', 'dhcp',
     [("        ok, why = _validate_local_domain(domain)\n"
       "        if not ok:\n"
       "            raise DhcpWriteError(why)",
       "        pass")]),

    ('LD-8 非法 IP 也放行', 'dhcp',
     [("        ok, why = _validate_local_ip(ip)\n"
       "        if not ok:\n"
       "            raise DhcpWriteError(why)",
       "        pass")]),

    ('LD-9 写前不备份（出问题没得恢复）', 'dhcp',
     [("        backup = _make_backup('local-domain')",
       "        backup = os.path.join(BACKUP_DIR, 'never-written.bak')")]),

    ('LD-10 写坏了不回滚', 'dhcp',
     [("                    raise DhcpWriteError('uci add_list 失败: %s' % out.strip())\n"
       "            if domain:\n"
       "                rc, out = _run_uci(['set', 'dhcp.%s.%s=%s'\n"
       "                                    % (section, LOCAL_DOMAIN_OPTION, domain)])\n"
       "                if rc != 0:\n"
       "                    raise DhcpWriteError('uci set 标记失败: %s' % out.strip())\n"
       "\n"
       "            rc, out = _run_uci(['commit', 'dhcp'])\n"
       "            if rc != 0:\n"
       "                raise DhcpWriteError('uci commit 失败: %s' % out.strip())\n"
       "\n"
       "            ok, detail = _check_syntax()\n"
       "            if not ok:\n"
       "                raise DhcpWriteError('改完的配置解析不了（已回滚）: %s' % detail)\n"
       "        except DhcpWriteError as e:\n"
       "            pending_ok, pend_detail = _discard_pending()\n"
       "            rolled = _restore(backup)\n"
       "            if not rolled:\n"
       "                raise DhcpWriteError('%s；**且回滚失败**，请手工从 %s 恢复'\n"
       "                                     % (e, backup), rolled_back=False)",
       "                    raise DhcpWriteError('uci add_list 失败: %s' % out.strip())\n"
       "            if domain:\n"
       "                rc, out = _run_uci(['set', 'dhcp.%s.%s=%s'\n"
       "                                    % (section, LOCAL_DOMAIN_OPTION, domain)])\n"
       "                if rc != 0:\n"
       "                    raise DhcpWriteError('uci set 标记失败: %s' % out.strip())\n"
       "\n"
       "            rc, out = _run_uci(['commit', 'dhcp'])\n"
       "            if rc != 0:\n"
       "                raise DhcpWriteError('uci commit 失败: %s' % out.strip())\n"
       "\n"
       "            ok, detail = _check_syntax()\n"
       "            if not ok:\n"
       "                raise DhcpWriteError('改完的配置解析不了（已回滚）: %s' % detail)\n"
       "        except DhcpWriteError as e:\n"
       "            pending_ok, pend_detail = _discard_pending()\n"
       "            rolled = True\n"
       "            if not rolled:\n"
       "                raise DhcpWriteError('%s；**且回滚失败**，请手工从 %s 恢复'\n"
       "                                     % (e, backup), rolled_back=False)")]),

    ('LD-11 重载失败当写失败（文件其实是对的）', 'dhcp',
     [("        reload_result = reload_dnsmasq()\n"
       "\n"
       "    return {'domain': domain, 'ip': ip, 'changed': True,",
       "        reload_result = reload_dnsmasq()\n"
       "        if not reload_result.get('ok'):\n"
       "            raise DhcpWriteError(reload_result.get('message', ''))\n"
       "\n"
       "    return {'domain': domain, 'ip': ip, 'changed': True,")]),

    ('LD-12 不重载 dnsmasq（写对了但没生效）', 'dhcp',
     [("        reload_result = reload_dnsmasq()\n"
       "\n"
       "    return {'domain': domain, 'ip': ip, 'changed': True,",
       "        reload_result = {'ok': True, 'message': '假装重载了'}\n"
       "\n"
       "    return {'domain': domain, 'ip': ip, 'changed': True,")]),

    # ── 面板侧的钩子 ──────────────────────────────────────────
    ('LD-13 钩子不接住异常（保存配置的流程被拖垮）', 'app',
     [("    except dhcp_hosts.DhcpWriteError as e:\n"
       "        print('[WARN] 本地解析同步失败（不影响其它功能）: %s' % e, flush=True)\n"
       "        return {'ok': False, 'message': str(e)}",
       "    except dhcp_hosts.DhcpWriteError as e:\n"
       "        raise")]),

    ('LD-14 钩子忽略传进来的 LAN 地址（探测不到就不写）', 'app',
     [("    domain = _rp_base_domain(config)\n"
       "    if not lan_ip:\n"
       "        lan_if = str(config.get('lan_if') or 'br-lan').strip() or 'br-lan'\n"
       "        lan_ip = _lan_bind_address(lan_if, retries=1, wait=0)",
       "    domain = _rp_base_domain(config)\n"
       "    lan_if = str(config.get('lan_if') or 'br-lan').strip() or 'br-lan'\n"
       "    lan_ip = _lan_bind_address(lan_if, retries=1, wait=0)")]),
]


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
    for key, path in FILES.items():
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(ORIG[key])
        except OSError:
            pass


def restore_verified():
    """还原 + 校验 sha256。返回 (是否还原干净, 详情)。"""
    restore()
    for key, path in FILES.items():
        try:
            with open(path, 'rb') as f:
                got = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            got = None
        if got != ORIG_SHA[key]:
            return False, '%s 还原后 sha256 不一致（%s != %s）' % (
                os.path.basename(path), got, ORIG_SHA[key])
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
                       timeout=600, cwd=ROOT)
    return r.returncode, r.stdout + r.stderr


def main():
    print('=== 变异验证：本地解析（域名 → 本机 IP） ===')
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

    caught = missed = skipped = 0
    missed_list = []
    for name, key, edits in MUTATIONS:
        src = ORIG[key]
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
            missed_list.append(name)
            continue
        mutated = src
        for old, new in edits:
            mutated = mutated.replace(old, new, 1)
        try:
            with open(FILES[key], 'w', encoding='utf-8') as f:
                f.write(mutated)
            # ⚠ 语法错误的变异不是行为变异 —— 测试会崩，而崩溃不等于断言失败。
            try:
                py_compile.compile(FILES[key], cfile=os.path.join(
                    tempfile.gettempdir(), 'localdomain_mut_check.pyc'),
                    doraise=True)
            except py_compile.PyCompileError as e:
                print('  [FAIL] %s  —— 变异后语法错误（不是行为变异）⇒ 算漏网' % name)
                print('      ↓ %s' % str(e).splitlines()[-1][:100])
                missed += 1
                missed_list.append(name)
                restore()
                continue
            rc, out = run_tests()
            if _judge_capture(rc, out):
                first = next((l.strip() for l in out.splitlines()
                              if '[FAIL]' in l and '[PASS]' not in l), '')
                print('  [PASS] %s  —— 被捕获' % name)
                caught += 1
            else:
                print('  [FAIL] %s  —— 测试仍然全绿（无效变异！）' % name)
                missed += 1
                missed_list.append(name)
        finally:
            restore()

    ok, detail = restore_verified()
    if not ok:
        print('[FAIL] %s' % detail)
        missed += 1

    total = caught + missed
    print('\n=== 结果：捕获 %d / %d ===' % (caught, total))
    for m in missed_list:
        print('  未捕获: ' + m)
    return 0 if missed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
