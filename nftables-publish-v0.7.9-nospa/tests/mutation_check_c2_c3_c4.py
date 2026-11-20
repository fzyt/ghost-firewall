#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C2 / C3 / C4 三处修复的变异验证。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_c2_c3_c4.py

测什么有效
----------
「修好了」不等于「守得住」。这个脚本把三处修复各自**拆成几种退化**，
逐条改坏源码，确认测试会红。

每条变异钉住一个具体退化：

  C2（IPv6 scope-id 必须判非法）
    M1  _valid_ip 的 scope-id 检查被摘掉
    M2  _valid_ip 的检查改成「只挡开头的 %」
    M3  _detect_ip_version 的 scope-id 检查被摘掉
    M4  _detect_ip_version 的检查改成「只挡同时含 / 和 % 的」
    M14 _format_list_elements 的 scope-id 检查被摘掉
    M15 _format_list_elements 的检查改成「只挡开头的 %」
    M16 template_engine 回填名单时 scope-id 检查被摘掉
    M17 template_engine 回填名单时检查改成「只挡开头的 %」

    ⚠️ C2 有**四个**入口，不是两个：
      `_valid_ip`（配置路径）、`_detect_ip_version`（名单添加路径）、
      `_format_list_elements`（名单 → 已落盘规则集文件的同步）、
      `template_engine._inject_list_elements`（名单 → **生成的**规则集文件，
      「点应用规则」走的就是这条）。
      后两个是 2026-11-08 复核时才发现的 ——
      它们**既不走** `_valid_ip` 也不走 `_detect_ip_version`，
      自己直接调 `ipaddress.ip_address()`，而 Python 3.9+ 的 ipaddress
      **认** scope-id ⇒ 只堵前面两个入口的话，lists.json 里的脏值
      （root 手工编辑 / 老版本留下的）照样会被写进 `elements = { ... }` 行
      ⇒ nft 加载失败 ⇒ apply 永久失败。
      ⇒ 「以为只有两处」本身就是这条 finding 最容易漏的地方。

  C3（恢复配置前必须校验）
    M5  restore_config 根本不调 validate_config
    M6  调了，但判定条件几乎不成立（len(errs) > 99）
    M7  校验挪到落盘（os.replace）之后
    M8  调了，但结果被丢掉（errs = []）

  C4（规则集完整备份必须 0600）
    M9  chmod 被摘掉 ⇒ 权限回到 umask 派生的 0644
    M10 chmod 用错权限位（0644）
    M11 chmod 失败时不删文件 ⇒ 留下漏权限的备份
    M12 chmod 挪到 nft 往里写之后 ⇒ 留了窗口

为什么 M8 / M12 也要有
----------------------
它们是「看起来修了、其实没修」的两种典型：
  · M8：调用了校验函数，但**结果没用** —— 静态断言「代码里调用了
    validate_config」照样通过，行为上却完全没校验。
  · M12：最终权限位对，但**写完之后才 chmod** —— 有一个「内容已完整、
    权限还松着」的窗口。行为上看不出来，只有源码不变式能抓。

⇒ 所以这三处修复必须**行为级 + 源码不变式**两层都有。

沙箱
----
备份/还原 `backend/app.py` 与 `backend/template_engine.py` **两个**文件
（C2 的第四个入口在模板引擎里 —— 它是独立模块，不依赖 app.py）。
每条变异独立重写源文件，并强制 PYTHONDONTWRITEBYTECODE=1：
否则连续写入时 Python 只按 mtime+size 判过期，两条大小相近的变异
会复用上一条的 .pyc，把「漏网」伪装成「捕获」。
"""
import atexit
import os
import signal
import subprocess
import sys

os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
TEMPLATE_PY = os.path.join(ROOT, 'backend', 'template_engine.py')
TEST = os.path.join(ROOT, 'tests', 'test_c2_c3_c4_fixes.py')

ORIG = open(APP_PY, encoding='utf-8').read()
ORIG_TE = open(TEMPLATE_PY, encoding='utf-8').read()

# ── 各条变异的锚点（全部经过唯一性核对）────────────────────────────
# 格式：(名称, 旧串, 新串)
#
# ⚠ 每条变异的「旧串」必须**在 app.py 里只出现一次** ——
#   否则替换会改到别处去，变异就变成了「改了个不相干的地方」，
#   测试当然全绿 ⇒ 会被误判成「漏网」，而实际上那条变异根本无效。
#   本文件下面有一道**锚点未命中即失败**的闸门，
#   但「出现多次」它抓不到 ⇒ 唯一性必须在这里先核对。

SCOPE_CHECK_VALID_IP = (
    "    # '%' 只可能出现在 IPv6 的 scope-id 后缀里（IPv4 不接受 '%'）\n"
    "    if '%' in s:\n"
    "        return False\n"
)
SCOPE_CHECK_DETECT = (
    "        if '%' in s:      # IPv6 scope-id 后缀 ⇒ 判非法\n"
    "            return None\n"
)
VALIDATE_CALL = "        errs = validate_config(restored)\n"
IF_ERRS = (
    "        if errs:\n"
    "            raise ValueError('备份配置未通过校验，已拒绝恢复: '\n"
)
BACKUP_CHMOD = "                    os.chmod(_rules_backup, 0o600)\n"
BACKUP_UNLINK = "                    _unlink_quiet(_rules_backup)\n"
NFT_LIST_RUN = "                r = subprocess.run(['nft', 'list', 'ruleset'], stdout=bf,\n"
SCOPE_CHECK_FORMAT_ELEMS = (
    "        if '%' in text:    # IPv6 scope-id 后缀 ⇒ nft 不认，丢弃\n"
    '            dropped += 1\n'
    '            continue\n'
)
SCOPE_CHECK_INJECT = (
    "            if '%' in s:       # IPv6 scope-id 后缀 ⇒ nft 不认，丢弃\n"
    '                dropped += 1\n'
    '                continue\n'
)


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
                ('\u274c' in s and '\u2705' not in s):
            return True
    print('      [注意] 测试脚本崩溃（输出里没有断言失败行）=> 不算捕获')
    return False


def _m12_swap(src):
    """构造 M12 的 (old, new)：把 chmod 块挪到 nft 往备份里写**之后**。

    为什么用**动态切片**而不是手抄那一整段：
      那一段里夹着中文注释（还带引号），手抄必然出错，
      而锚点一旦对不上就是「锚点未命中」⇒ 变异无效。
      这里从源码里按锚点切出来，注释怎么改都不会失效。

    返回的 old 是源码里**连续**的一段（try/except 块 + run 两行），
    new 是把这两块对调 —— 语法仍然合法（这很关键：
    首版的 M9/M12 把 try 块改空了 ⇒ 源码成了语法错误 ⇒
    测试 import 失败、退出码非 0 ⇒ 被误判成「被捕获」，
    实际上那条变异根本没测到任何东西）。
    """
    chmod_start = src.index(
        "                try:\n                    os.chmod(_rules_backup, 0o600)\n")
    run_start = src.index(NFT_LIST_RUN)
    run_end = src.index(
        "                                   stderr=subprocess.PIPE, timeout=5)\n",
        run_start) + len("                                   stderr=subprocess.PIPE, timeout=5)\n")
    chmod_block = src[chmod_start:run_start]
    run_block = src[run_start:run_end]
    return chmod_block + run_block, run_block + chmod_block


_M12_OLD, _M12_NEW = _m12_swap(ORIG)

MUTATIONS = [
    # ── C2 ──────────────────────────────────────────────────────
    ('M1  _valid_ip 的 scope-id 检查被摘掉',
     SCOPE_CHECK_VALID_IP,
     "    # （变异：scope-id 检查被摘掉）\n"),

    ('M2  _valid_ip 的检查改成「只挡开头的 %」',
     SCOPE_CHECK_VALID_IP,
     "    # （变异：只挡开头的 %）\n"
     "    if s.startswith('%'):\n"
     "        return False\n"),

    ('M3  _detect_ip_version 的 scope-id 检查被摘掉',
     SCOPE_CHECK_DETECT,
     "        # （变异：scope-id 检查被摘掉）\n"),

    ('M4  _detect_ip_version 的检查改成「只挡同时含 / 和 % 的」',
     SCOPE_CHECK_DETECT,
     "        # （变异：只挡同时含 / 和 % 的）\n"
     "        if '/' in s and '%' in s:\n"
     "            return None\n"),

    # ── C3 ──────────────────────────────────────────────────────
    ('M5  restore_config 根本不调 validate_config',
     VALIDATE_CALL,
     "        errs = []   # （变异：根本没调 validate_config）\n"),

    ('M6  调了但判定条件几乎不成立',
     IF_ERRS,
     "        if errs and len(errs) > 99:   # （变异：几乎不成立）\n"
     "            raise ValueError('备份配置未通过校验，已拒绝恢复: '\n"),

    ('M7  校验挪到落盘之后',
     VALIDATE_CALL + IF_ERRS +
     "                             + '; '.join(errs[:8]))\n",
     "        # （变异：校验被挪到落盘之后）\n"),

    ('M8  调了但结果被丢掉',
     VALIDATE_CALL,
     "        errs = validate_config(restored)\n"
     "        errs = []   # （变异：结果被丢掉）\n"),

    # ── C4 ──────────────────────────────────────────────────────
    ('M9  备份的 chmod 被摘掉',
     BACKUP_CHMOD,
     "                    pass   # （变异：chmod 被摘掉）\n"),

    ('M10 chmod 用错权限位（0644）',
     BACKUP_CHMOD,
     "                    os.chmod(_rules_backup, 0o644)   # （变异：权限位错了）\n"),

    ('M11 chmod 失败时不删文件',
     BACKUP_UNLINK,
     "                    # （变异：不删了）\n"),

    ('M12 chmod 挪到 nft 往里写之后',
     _M12_OLD,
     _M12_NEW),

    ('M13 缺失必填字段不再继承当前配置（老备份连回退都做不了）',
     "                restored[_key] = _effective_cfg.get(_key) or ''\n",
     "                pass   # （变异：不再继承当前生效值）\n"),

    ('M14 _format_list_elements 的 scope-id 检查被摘掉（脏值进规则集）',
     SCOPE_CHECK_FORMAT_ELEMS,
     "            # （变异：scope-id 检查被摘掉）\n"),

    ('M15 _format_list_elements 的检查改成「只挡开头的 %」',
     SCOPE_CHECK_FORMAT_ELEMS,
     "        if text.startswith('%'):   # （变异：只挡开头的 %）\n"
     "            dropped += 1\n"
     "            continue\n"),
]

# ── 模板引擎的变异（第四个入口，独立文件）────────────────────────
# ⚠️ 单独一个列表：这个模块**不依赖 app.py**（模板引擎是独立的），
#   拿不到 `_valid_ip`，所以它的 scope-id 闸门是就地实现的，
#   也必须单独做变异。
MUTATIONS_TE = [
    ('M16 template_engine 回填名单时 scope-id 检查被摘掉',
     SCOPE_CHECK_INJECT,
     "            # （变异：scope-id 检查被摘掉）\n"),

    ('M17 template_engine 回填名单时检查改成「只挡开头的 %」',
     SCOPE_CHECK_INJECT,
     "            if s.startswith('%'):   # （变异：只挡开头的 %）\n"
     "                dropped += 1\n"
     "                continue\n"),
]


def restore():
    """整体还原（保险丝用）。只碰 app.py 与 template_engine.py。"""
    for path, orig in ((APP_PY, ORIG), (TEMPLATE_PY, ORIG_TE)):
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(orig)
        except Exception as e:
            print(f'[ERROR] 还原 {path} 失败: {e}')


def _all_mutations():
    """两个文件的变异合成一张表。

    返回 (名称, 旧串, 新串, 目标文件, 目标文件的原始内容)。
    ⚠️ 每个元素都要带自己那份原始内容 —— 混用会拿 app.py 的原文去改
    template_engine.py（锚点自然对不上 ⇒ 变成「锚点未命中」而不是真变异）。
    """
    items = [(n, o, w, APP_PY, ORIG) for (n, o, w) in MUTATIONS]
    items += [(n, o, w, TEMPLATE_PY, ORIG_TE) for (n, o, w) in MUTATIONS_TE]
    return items


atexit.register(restore)
for _sig in (signal.SIGTERM, signal.SIGINT):
    try:
        signal.signal(_sig, lambda *_: (restore(), sys.exit(1)))
    except Exception:
        pass


def run_tests():
    """跑本批次的测试文件。任何一个红就算变异被抓。"""
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    r = subprocess.run([sys.executable, TEST],
                       capture_output=True, text=True, cwd=ROOT,
                       timeout=600, env=env)
    return r.returncode, r.stdout + r.stderr


def main():
    print('=' * 66)
    print('C2 / C3 / C4 修复的变异验证')
    print('=' * 66)

    # ── 锚点唯一性自查（脚本自己先核对一遍）─────────────────────
    all_muts = _all_mutations()
    dup = []
    for name, old, _new, _path, orig in all_muts:
        c = orig.count(old)
        if c != 1:
            dup.append((name, c))
    if dup:
        print('\n[FAIL] 锚点不唯一 —— 这些变异无效，必须先修锚点：')
        for name, c in dup:
            print(f'    {name}: 旧串出现 {c} 次（要求恰好 1 次）')
        return 2

    print('\n=== 基线：未变异时测试必须全绿 ===')
    rc, out = run_tests()
    if rc != 0:
        print(out)
        print('\n[FAIL] 基线就不绿 —— 先修好再谈变异')
        return 2
    print('  [PASS] 基线通过')

    caught, missed, noanchor = 0, 0, []
    for name, old, new, path, orig in all_muts:
        src = orig
        if src.count(old) != 1:
            print(f'  [FAIL] {name}  —— 锚点未命中（旧串出现 {src.count(old)} 次）')
            noanchor.append(name)
            continue
        src = src.replace(old, new, 1)

        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(src)
        except OSError as e:
            print(f'  [FAIL] {name}  —— 写不进去: {e}')
            missed += 1
            restore()
            continue

        rc, out = run_tests()
        if _judge_capture(rc, out):
            # ⚠ 汇总行「合计: [PASS] 47 [FAIL] 1」里也含 [FAIL] ⇒ 要排除，
            #   否则打印出来的"捕获来源"是汇总而不是具体断言。
            fails = [l.strip() for l in out.splitlines()
                     if '[FAIL]' in l and '合计' not in l]
            if fails:
                print(f'  [PASS] {name}  —— 被捕获')
                for f in fails[:3]:
                    print(f'      ↓ {f}')
                caught += 1
            else:
                # ⚠ rc != 0 但**没有任何 [FAIL] 行** ⇒ 测试自己崩了
                #   （traceback / 语法错 / 导入失败），不是断言抓住了它。
                #   这种「捕获」是假的：它只说明变异把测试搞坏了，
                #   不说明防线在起作用 ⇒ 判为无效。
                #   （首版 M9/M12 就落在这里 —— 靠 rc 就判捕获是蒙的。）
                print(f'  [FAIL] {name}  —— 测试崩了而非断言失败（不算捕获）')
                tail = [l for l in out.splitlines() if l.strip()][-3:]
                for t in tail:
                    print(f'      ↓ {t.strip()}')
                missed += 1
        else:
            print(f'  [FAIL] {name}  —— **漏网**（测试照样全绿）')
            missed += 1

        restore()

    # 最后再整体还原一次，确保干净
    restore()

    total = len(all_muts)
    print(f'\n变异 {total} 处  捕获 {caught}  漏网 {missed}  锚点未命中 {len(noanchor)}')
    if caught == total and not missed and not noanchor:
        print('全部变异均被捕获')
        return 0
    print('有变异漏过')
    return 1


if __name__ == '__main__':
    sys.exit(main())
