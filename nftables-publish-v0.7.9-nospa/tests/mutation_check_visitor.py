#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""网关访客页 + 白名单时效分离的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_visitor.py

测什么有效
----------
这批功能的失败模式分两类：

  一、**时效分离名存实亡**
    手动加的白名单靠 nft 的**元素级** timeout；敲门的靠 set 的**默认** timeout。
    两者混在一起时最典型的症状是「用户加了 10 分钟，点一次应用规则就变 5 小时」
    —— 因为名单文件里只存了裸 IP，回填时元素级 timeout 丢了。
    这类变异必须一条不漏地被抓住。

  二、**访客列表读错**
    访问日志解析错一个字段（host / uri / auth_dev）、时间窗不生效、
    聚合计数不累加、文件不存在就报错 —— 每一个都会让「谁来过」变成
    「看起来有人来过，但说的不是真话」。

⚠️ 「锚点未命中」必须当失败
--------------------------
锚点匹配不上说明源码变了、这批变异根本没打出去 ——
静默跳过就会伪装成「全部捕获」。

⚠️ 语法错误的变异不是行为变异
------------------------------
改出来的代码必须**能跑**，否则测试脚本会崩，而崩溃不等于断言失败
（判定只看输出里有没有真正的断言失败行）。

保险丝：备份 / 还原本脚本会动的那几个文件。
还原后比对 sha256 —— 源码没还原干净时**必须**当成失败。
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = {
    'te': os.path.join(ROOT, 'backend', 'template_engine.py'),
    'app': os.path.join(ROOT, 'backend', 'app.py'),
    'appjs': os.path.join(ROOT, 'frontend', 'app.js'),
    'index': os.path.join(ROOT, 'frontend', 'index.html'),
}
TESTS = [
    os.path.join(ROOT, 'tests', 'test_visitor_whitelist.py'),
]

ORIG = {k: open(v, encoding='utf-8').read() for k, v in FILES.items()}
ORIG_SHA = {k: hashlib.sha256(s.encode('utf-8')).hexdigest()
            for k, s in ORIG.items()}

# (描述, 文件键, [(旧文本, 新文本), ...])
MUTATIONS = [
    # ── 一、名单元素的 timeout 子句解析（注入面）─────────────────
    ('V-1 全角数字也放行（isdigit 认 Unicode 数字）', 'te',
     [("        if not (secs.isascii() and secs.isdigit()):",
       "        if not secs.isdigit():")]),

    ('V-2 去掉时效上限（超大秒数会让 nft 拒收整份规则集）', 'te',
     [("        if n <= 0 or n > LIST_ELEM_MAX_TIMEOUT:",
       "        if n < 0:")]),

    ('V-3 timeout 关键字不校验（任何关键字都当子句放行）', 'te',
     [("    if len(parts) == 3 and parts[1] == 'timeout':",
       "    if len(parts) == 3 and parts[1] != 'timeout':")]),

    ('V-4 丢掉 timeout 子句（元素级时效静默失效）', 'te',
     [("        return parts[0], f' timeout {n}s'",
       "        return parts[0], ''")]),

    ('V-5 接受 0 秒（0 秒 = 立刻过期，等于没加）', 'te',
     [("        if n <= 0 or n > LIST_ELEM_MAX_TIMEOUT:",
       "        if n < 0 or n > LIST_ELEM_MAX_TIMEOUT:")]),

    # ── 二、时效套用（分离的落点）──────────────────────────────
    ('V-6 根本不套时效（手动加的 10 分钟退回 5 小时）', 'app',
     [("    if not ttls or not isinstance(ttls, dict):\n        return list_elements",
       "    if not ttls or not isinstance(ttls, dict):\n        return list_elements\n"
       "    # 变异：下面的套用整体不执行\n    return list_elements")]),

    ('V-7 黑名单也套时效（黑名单 set 没有 timeout 标志 ⇒ nft 拒收）', 'app',
     [("        if not name.startswith('allowed'):\n"
       "            out[name] = list(items or [])\n"
       "            continue",
       "        if False:\n"
       "            out[name] = list(items or [])\n"
       "            continue")]),

    ('V-8 就地改原对象（别处统计白名单条数会数错）', 'app',
     [("    out = {}\n    for name, items in (list_elements or {}).items():",
       "    out = list_elements\n    for name, items in (list_elements or {}).items():")]),

    ('V-9 布尔值也当秒数（True ⇒ 1 秒）', 'app',
     [("            if (isinstance(ttl, int) and not isinstance(ttl, bool)\n"
       "                    and 0 < ttl <= LIST_ELEM_MAX_TIMEOUT):",
       "            if (isinstance(ttl, int)\n"
       "                    and 0 < ttl <= LIST_ELEM_MAX_TIMEOUT):")]),

    # ── 三、加白名单接口 ───────────────────────────────────────
    ('V-10 timeout 不传给内核（元素级时效当场失效）', 'app',
     [("        elem = ['{', ip]\n"
       "        if timeout_s:\n"
       "            # OpenWrt 自带 nft 不支持 'timeout <N> s' 的空格 + 单位写法，\n"
       "            # 必须用 'timeout <N>s'（无空格、无单位后缀视为秒）\n"
       "            elem += ['timeout', f'{timeout_s}s']\n"
       "        elem.append('}')",
       "        elem = ['{', ip, '}']")]),

    ('V-11 时效不落 config（重建规则后必丢）', 'app',
     [("        if timeout_s:\n            _set_list_timeout(ip, timeout_s)",
       "        if False:\n            _set_list_timeout(ip, timeout_s)")]),

    ('V-12 黑名单也接受 timeout（nft 会拒收整个 set）', 'app',
     [("        if timeout_s and not set_name.startswith('allowed'):",
       "        if False:")]),

    ('V-13 非法 timeout 不拦（负数/越界直接进 nft 命令）', 'app',
     [("        if timeout_s < 0 or timeout_s > LIST_ELEM_MAX_TIMEOUT:",
       "        if False:")]),

    # ── 四、时效的清理 ─────────────────────────────────────────
    ('V-14 删成员时不清时效（再加一次带上了用户没填过的时效）', 'app',
     [("        _set_list_timeout(ip, None)",
       "        pass  # 变异：不清时效")]),

    ('V-15 清空名单时不清时效（字典无限膨胀）', 'app',
     [("        _clear_list_timeouts(cleared)",
       "        pass  # 变异：不清时效")]),

    # ── 五、规则回填（分离的落点）──────────────────────────────
    ('V-16 生成规则时不套时效（点应用规则 ⇒ 时效变 5 小时）', 'app',
     [("    list_elements = _apply_list_timeouts(load_lists(),\n"
       "                                          config.get('whitelist_ttls') or {})",
       "    list_elements = load_lists()")]),

    ('V-17 规则集文件不套时效（设备重启后时效丢失）', 'app',
     [("    timed = _apply_list_timeouts(lists, load_config().get('whitelist_ttls') or {})",
       "    timed = lists")]),

    # ── 六、访客列表 ───────────────────────────────────────────
    ('V-18 日志正则漏掉 auth_dev（设备 ID 丢了）', 'app',
     [("    r'auth_user=\"(?P<auth_user>[^\"]*)\"\\s+auth_dev=\"(?P<auth_dev>[^\"]*)\"\\s*$'",
       "    r'auth_user=\"(?P<auth_user>[^\"]*)\"\\s*$'")]),

    ('V-19 时间窗不生效（几周前的记录也当今天的访客）', 'app',
     [("        if epoch < cutoff:\n            continue",
       "        if False:\n            continue")]),

    ('V-20 聚合计数不累加（每个 IP 都显示只有 1 次）', 'app',
     [("        item['count'] += 1", "        pass  # 变异：不计数")]),

    ('V-21 日志文件读不出来就崩（网关没开过时整个页面报错）', 'app',
     [("    except (IOError, OSError):\n"
       "        return []          # 文件不存在 = 网关没开过 = 正常情况",
       "    except (IOError, OSError):\n"
       "        raise")]),

    ('V-22 永久白名单被当成「不在白名单」', 'app',
     [("        v['whitelisted'] = v['ip'] in wl",
       "        v['whitelisted'] = wl.get(v['ip']) is not None")]),

    ('V-26 不校验 IP 真伪（字符交织的坏行变成假访客）', 'app',
     [("        try:\n"
       "            ipaddress.ip_address(ip)\n"
       "        except ValueError:\n"
       "            continue",
       "        # 变异：不校验")]),

    ('V-27 整个日志读进来（access_log 只增不减 ⇒ 早晚是内存问题）', 'app',
     [("        size = os.path.getsize(GATEWAY_ACCESS_LOG)\n"
       "        with open(GATEWAY_ACCESS_LOG, 'rb') as f:\n"
       "            if size > GATEWAY_LOG_TAIL_BYTES:\n"
       "                f.seek(size - GATEWAY_LOG_TAIL_BYTES)\n"
       "                f.readline()      # 丢掉被截断的那半行（它一定不完整）\n"
       "            raw = f.read()",
       "        with open(GATEWAY_ACCESS_LOG, 'r', errors='replace') as f:\n"
       "            raw = f.read()")]),

    # ── 七、前端接线 ───────────────────────────────────────────
    ('V-23 导航里没有「访客」这一项', 'appjs',
     [("      { id: 'visitors', label: '访客' },", "")]),

    ('V-24 加白名单不传时效（退回敲门的 5 小时）', 'appjs',
     [("          timeout: seconds,", "          // 变异：不传时效")]),

    ('V-25 时效单位换算错（10 分钟被当成 10 秒）', 'appjs',
     [("        const seconds = Math.max(1, Math.round(this.visitors.ttlMinutes * 60));",
       "        const seconds = Math.max(1, Math.round(this.visitors.ttlMinutes));")]),

    ('V-28 option 改回 :value 动态绑定（x-model 匹配不上默认值）', 'index',
     [('                <option value="60">最近 1 小时</option>',
       '                <option :value="60">最近 1 小时</option>')]),
]


def _judge_capture(rc, msg):
    """判定这次变异算不算「被捕获」。

    ⚠ 不能只看 rc != 0 —— 那分不清「断言失败」和「测试脚本自己崩了」
      ⇒ 只有输出里真的出现**断言失败**的标记行才算捕获。
    """
    if rc == 0:
        return False
    for line in msg.splitlines():
        s = line.strip()
        if '[FAIL]' in s and '[PASS]' not in s:
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
    """跑本批判据，输出合并。"""
    outs = []
    rc_all = 0
    for t in TESTS:
        cmd = [sys.executable, t]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                           cwd=ROOT)
        outs.append(r.stdout + r.stderr)
        if r.returncode != 0:
            rc_all = r.returncode
    return rc_all, '\n'.join(outs)


def apply_edits(key, edits):
    """edits: [(old, new)]，每条都必须**唯一**匹配 —— 匹配不上就报错。

    为什么必须唯一：变异脚本按「第一个匹配」替换；
    old 片段不唯一 ⇒ 改到哪一处全看运气 ⇒ 「漏网」被伪装成「捕获」。
    """
    src = ORIG[key]
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError('锚点出现 %d 次，必须唯一：%r' % (n, old[:70]))
        src = src.replace(old, new, 1)
    with open(FILES[key], 'w', encoding='utf-8') as f:
        f.write(src)


def main():
    print('=== 变异验证：网关访客页 + 白名单时效分离 ===')
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

    caught, missed = 0, []
    for desc, key, edits in MUTATIONS:
        restore()
        try:
            apply_edits(key, edits)
        except ValueError as e:
            print('  [脚本错] %s' % desc)
            print('      ↓ %s' % e)
            missed.append('%s（变异脚本自身的错）' % desc)
            continue
        rc, out = run_tests()
        if _judge_capture(rc, out):
            caught += 1
            first = ''
            for line in out.splitlines():
                s = line.strip()
                if '[FAIL]' in s and '[PASS]' not in s:
                    first = s
                    break
            print('  [捕获] %s' % desc)
            if first:
                print('      ↓ %s' % first[:150])
        else:
            missed.append(desc)
            print('  [漏网] %s  ← 测试没变红！' % desc)

    restore()
    ok, detail = restore_verified()
    print()
    print('=' * 60)
    print('  变异 %d 条，捕获 %d 条，漏网 %d 条' %
          (len(MUTATIONS), caught, len(missed)))
    if missed:
        print('  漏网的变异：')
        for m in missed:
            print('    - ' + m)
        print('=' * 60)
        return 1
    if not ok:
        print('  [FAIL] %s' % detail)
        print('=' * 60)
        return 1
    print('  全部捕获')
    print('=' * 60)
    return 0


if __name__ == '__main__':
    sys.exit(main())
