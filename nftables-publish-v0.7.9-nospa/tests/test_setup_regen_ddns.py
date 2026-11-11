#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
「部署后自动重新生成阿里云 DDNS 脚本」的行为级测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_setup_regen_ddns.py

测什么有效
----------
2026-11-11 在 .232 真机踩到过一个坑：**部署换了 app.py，设备上那份
`aliyun-ddns-update.py` 还是旧的**（它是生成物，不会跟着 app.py 一起变）。
结果本地测试全绿、真机跑出来仍是旧行为 —— 修复等于没修，现象照旧，
很容易被误判成「没修好」。

这轮把「重新生成」接进 setup.sh，判据落在**行为**上：
  · 把 setup.sh 拷进沙箱、去掉 main 调用、把 INSTALL_DIR 换成临时目录，
    然后**真的执行** regen_ddns_script，看设备上那份脚本最后长什么样；
  · 再单独跑 backend/regen_ddns_script.py，覆盖软链、缺文件、幂等这些边界。

⚠ 为什么不用文本匹配
--------------------
「setup.sh 里包含 regen_ddns_script」这种断言，在下面两种改法下**照样通过**：
  · 把调用点删掉；
  · 把调用点挪进 deploy_project 里面 —— 部署阶段被判定成「已完成」
    而跳过时就不会执行（而「装好了再跑一遍」正是最常见的场景）。
⇒ 这里断言的是「跑完之后，设备上那份脚本的内容是什么」。

⚠ 判据要比被测对象强
--------------------
本测试跑的是**真 app.py**（不是替身）：生成物里必须出现 `UpdateDomainRecord`
且**不得**出现 `DeleteDomainRecord` —— 那是「修好的脚本」的可观察特征。
用替身 app.py 只能证明「字符串被搬过去了」，证明不了「搬的是对的东西」。
"""
import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETUP = os.path.join(ROOT, 'setup', 'setup.sh')
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
REGEN = os.path.join(ROOT, 'backend', 'regen_ddns_script.py')

PASS, FAIL = [], []


def strip_docstrings(source):
    """去掉 docstring 后再 unparse —— 拿「真正被执行的代码」。

    ⚠ 为什么必须去 docstring：
    cron 脚本模板的**开头注释里就写着**「脚本从不调用 DeleteDomainRecord」
    （那是给人看的解释）。直接对原文做「不该出现」的断言，会被这段解释
    文字打中 ⇒ 判据失真（假红），而且真正的「调用了 Delete」反而抓不到。
    ⇒ 只看**代码**（去掉 docstring 后 unparse 的结果）。
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        body = getattr(node, 'body', None)
        if not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def func_span(src, name):
    """返回某个 shell 函数体在源码里的 (起, 止) 偏移；找不到返回 None。

    用大括号配平来截 —— setup.sh 是 POSIX sh，没有语法树可用。
    """
    m = re.search(r'^%s\(\) \{' % re.escape(name), src, re.M)
    if not m:
        return None
    depth, end = 0, None
    for j in range(m.start(), len(src)):
        if src[j] == '{':
            depth += 1
        elif src[j] == '}':
            depth -= 1
            if depth == 0:
                end = j
                break
    return (m.start(), end) if end else None


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def make_sandbox(app_py_src=APP_PY, with_regen=True, script_path=None):
    """搭一个「设备安装目录」的沙箱。

    返回 (沙箱根, INSTALL_DIR 路径)

    ⚠ 必须改掉 app.py **副本**里的 script_path
    ----------------------------------------
    新机制下 app.py 的 `script_path` 是**输出路径的唯一真源**
    （regen_ddns_script.py 用 AST 把它取出来当目标路径）。
    不改的话，regen 会照着副本里的 `/opt/nftables-web-v2/aliyun-ddns-update.py`
    去写真实路径 —— 那就**测试污染生产目录**了。

    这里只改**副本**里的那一行常量，被测代码一个字节都没动
    （不给生产脚本加测试专用开关 —— 那会让生产代码多出一条分支）。
    """
    d = tempfile.mkdtemp(prefix='regen-ddns-')
    inst = os.path.join(d, 'opt-nftables-web-v2')
    backend = os.path.join(inst, 'backend')
    os.makedirs(backend)

    src = open(app_py_src, encoding='utf-8').read()
    old = 'script_path = "/opt/nftables-web-v2/aliyun-ddns-update.py"'
    assert src.count(old) == 1, (
        'app.py 副本里找不到唯一的 script_path 行（出现 %d 次）—— '
        '生产代码变了，本沙箱的前提不成立' % src.count(old))
    target = script_path or os.path.join(inst, 'aliyun-ddns-update.py')
    src = src.replace(old, 'script_path = "%s"' % target)
    with open(os.path.join(backend, 'app.py'), 'w', encoding='utf-8') as f:
        f.write(src)

    if with_regen:
        shutil.copy(REGEN, os.path.join(backend, 'regen_ddns_script.py'))
    return d, inst


def make_setup_script(inst, call='regen_ddns_script'):
    """把 setup.sh 拷进沙箱并改掉路径常量，末尾调用指定函数。

    ⚠ 只改**路径常量**，被测的函数体一个字节都没动
      （不给生产脚本加测试专用开关 —— 那会让生产代码多出一条分支）。
    """
    src = open(SETUP, encoding='utf-8').read()
    src = src.replace('\nmain "$@"\n', '\n')
    old = 'INSTALL_DIR="/opt/nftables-web-v2"'
    assert src.count(old) == 1, 'INSTALL_DIR 常量行不唯一，装配沙箱失败'
    src = src.replace(old, 'INSTALL_DIR="%s"' % inst)
    if call:
        src += '\n%s\n' % call
    path = os.path.join(os.path.dirname(inst), 'setup.sh')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    return path


def run_sh(script, env=None):
    r = subprocess.run(['sh', script], capture_output=True, text=True, timeout=120,
                       env={**os.environ, **(env or {})})
    return r.returncode, (r.stdout + r.stderr)


def run_regen(app_py=None, out=None, cwd=None):
    """直接跑 backend/regen_ddns_script.py，返回 (rc, 输出)。"""
    env = {}
    if app_py:
        env['NFTABLES_WEB_APP_PY'] = app_py
    if out:
        env['NFTABLES_WEB_DDNS_SCRIPT'] = out
    r = subprocess.run([sys.executable, REGEN], capture_output=True, text=True,
                       timeout=120, cwd=cwd or ROOT,
                       env={**os.environ, **env})
    return r.returncode, (r.stdout + r.stderr)


# ============================================================
# 第 1 组：setup.sh 跑完之后，设备上那份脚本确实是「修好的那一版」
# ============================================================
sec('第 1 组：真跑 setup.sh 的 regen_ddns_script（真 app.py）')

d1, inst1 = make_sandbox()
script1 = make_setup_script(inst1)
rc1, out1 = run_sh(script1)

ddns1 = os.path.join(inst1, 'aliyun-ddns-update.py')
check('脚本执行成功（rc=0）', rc1 == 0, out1[-500:])
check('设备上生成了 aliyun-ddns-update.py', os.path.isfile(ddns1),
      str(os.listdir(inst1)))
if os.path.isfile(ddns1):
    body1 = open(ddns1, encoding='utf-8').read()
    code1 = strip_docstrings(body1)
    check('生成物的**代码**里用的是 UpdateDomainRecord（原地更新）',
          'UpdateDomainRecord' in code1)
    check('生成物的**代码**里**没有** DeleteDomainRecord（永不删除）',
          'DeleteDomainRecord' not in code1)
    check('生成物里读的是设备上的配置文件',
          'aliyun-ddns-config.json' in body1)
    try:
        compile(body1, 'aliyun-ddns-update.py', 'exec')
        ok = True
        detail = ''
    except SyntaxError as e:
        ok = False
        detail = str(e)
    check('生成物能被 python3 解析（cron 跑得起来）', ok, detail)
    mode = os.stat(ddns1).st_mode & 0o777
    check('生成物是可执行权限 0755', mode == 0o755, oct(mode))
check('输出里说明了已重新生成', '已重新生成' in out1, out1[-300:])


# ============================================================
# 第 2 组：生成物来自「设备上那份 app.py」，并且真的覆盖了旧脚本
# ============================================================
sec('第 2 组：生成物来自设备上的 app.py，且覆盖旧脚本')

# 造一份带特征标记的 app.py：模板里写死一个只有它才有的标记。
# ⚠ 模板必须是**合法 Python** —— 生成器会先 compile 再写，
#   语法坏掉时它会拒绝写入（这是刻意的：宁可保留旧脚本，也不留半截）。
marker = 'NFTW_DDNS_MARKER_7F3A91'
fake_app = os.path.join(tempfile.mkdtemp(), 'app.py')
with open(fake_app, 'w', encoding='utf-8') as f:
    f.write(
        'def _generate_ddns_update_script():\n'
        '    script_path = "/opt/nftables-web-v2/aliyun-ddns-update.py"\n'
        '    script_content = """#!/usr/bin/env python3\n'
        'MARKER = "%s"\n'
        'print(MARKER)\n'
        '"""\n'
        '    write(script_content)\n' % marker)

d2, inst2 = make_sandbox(app_py_src=fake_app)
# 先放一份「旧脚本」：跑完必须被覆盖，否则说明写到了别处
old_ddns = os.path.join(inst2, 'aliyun-ddns-update.py')
with open(old_ddns, 'w', encoding='utf-8') as f:
    f.write('#!/bin/sh\necho OLD-STALE-CONTENT\n')
os.chmod(old_ddns, 0o755)

script2 = make_setup_script(inst2)
rc2, out2 = run_sh(script2)
body2 = open(old_ddns, encoding='utf-8').read() if os.path.isfile(old_ddns) else ''

check('脚本执行成功（rc=0）', rc2 == 0, out2[-400:])
check('生成物内容来自**设备上那份 app.py** 的模板',
      marker in body2, body2[:200])
check('旧脚本内容被覆盖掉了（不是新写了一份别处的）',
      'OLD-STALE-CONTENT' not in body2)


# ============================================================
# 第 2.5 组：输出路径的**唯一真源**是 app.py 里的 script_path
# ============================================================
#
# 为什么要有这一组
# --------------
# 2026-11-11 修 L1 之前，regen_ddns_script.py 按**目录层级推导**输出路径
# （regen 脚本自己所在目录的上一级），而面板侧
# `_generate_ddns_update_script()` 是**硬编码**
# `/opt/nftables-web-v2/aliyun-ddns-update.py`。
# 两套机制今天相等**只是布局巧合** —— 哪天 INSTALL_DIR 改名、或者 Docker 变体
# 把 app.py 放在别处，重新生成就写到别处去了，而 cron 跑的还是旧文件
# ⇒ **修复静默失效**，regen 还报「已重新生成」。
#
# ⇒ 真源必须是 app.py 里的 script_path（面板写盘用的那个路径）。
sec('第 2.5 组：输出路径来自 app.py 的 script_path（不是目录推导）')

# 先把「自定义位置」建好 —— 它刻意**不在**安装目录里，
# 这样「写到了 app.py 指定的地方」才是确凿的证据。
d25 = tempfile.mkdtemp(prefix='regen-ddns-custom-')
custom_dir = os.path.join(d25, 'custom-place')
os.makedirs(custom_dir)
custom_out = os.path.join(custom_dir, 'ddns.py')

d25, inst25 = make_sandbox(script_path=custom_out)
gen25 = os.path.join(inst25, 'backend', 'regen_ddns_script.py')
r25 = subprocess.run([sys.executable, gen25], capture_output=True, text=True,
                     timeout=120, cwd=ROOT,
                     env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
out25 = r25.stdout + r25.stderr
check('regen 执行成功（rc=0）', r25.returncode == 0, out25[-300:])
check('生成物写到了 **app.py 里指定的路径**', os.path.isfile(custom_out),
      custom_out)
# 「按目录推导」的那个位置 = regen 脚本所在目录的上一级
default_guess25 = os.path.join(inst25, 'aliyun-ddns-update.py')
check('生成物**没有**落到「按目录推导」的位置',
      not os.path.exists(default_guess25), default_guess25)

# 走 setup.sh 一遍（部署时的真实路径）也必须落在同一个地方
script25 = make_setup_script(inst25)
rc25, out25s = run_sh(script25)
check('setup.sh 走一遍后退出码为 0', rc25 == 0, out25s[-300:])
check('setup.sh 走一遍后，生成物仍在 app.py 指定的路径',
      os.path.isfile(custom_out))
check('setup.sh 走一遍后，也没有落到目录推导的位置',
      not os.path.exists(default_guess25))

# 环境变量优先（**只给测试用**）
d25c, inst25c = make_sandbox()
trap25c = os.path.join(d25c, 'trap25c.py')
rc25c, out25c = run_regen(app_py=os.path.join(inst25c, 'backend', 'app.py'),
                          out=trap25c)
check('环境变量指定的路径被写入了（测试专用入口仍可用）',
      os.path.isfile(trap25c), out25c[-200:])
check('环境变量优先于 app.py 的 script_path（app.py 的位置没被写）',
      not os.path.exists(os.path.join(inst25c, 'aliyun-ddns-update.py')))

# setup.sh 必须把这个「只给测试用」的环境变量**清掉**
d25d, inst25d = make_sandbox()
trap25d = os.path.join(d25d, 'trap25d.py')
script25d = make_setup_script(inst25d)
rc25d, out25d = run_sh(script25d, env={'NFTABLES_WEB_DDNS_SCRIPT': trap25d})
check('setup.sh 跑完退出码为 0', rc25d == 0, out25d[-300:])
check('setup.sh **清掉了**测试用环境变量（没写到 trap 路径）',
      not os.path.exists(trap25d), trap25d)
check('setup.sh 写到了 app.py 指定的路径（真源生效）',
      os.path.isfile(os.path.join(inst25d, 'aliyun-ddns-update.py')))


# ============================================================
# 第 3 组：regen_ddns_script.py 单独跑时的边界
# ============================================================
sec('第 3 组：缺文件 / 模板提取不到 / 软链 / 坏模板 / 幂等')

# 3.1 app.py 不在
d31 = tempfile.mkdtemp()
rc31, out31 = run_regen(app_py=os.path.join(d31, 'nope.py'),
                        out=os.path.join(d31, 'out.py'))
check('app.py 不存在时退出码为 0（不是崩溃）', rc31 == 0, out31[-300:])
check('app.py 不存在时给出 [SKIP] 提示', '[SKIP]' in out31, out31[-200:])
check('app.py 不存在时**没有**写出文件',
      not os.path.exists(os.path.join(d31, 'out.py')))

# 3.2 app.py 里没有那个函数
d32 = tempfile.mkdtemp()
no_tpl = os.path.join(d32, 'app.py')
with open(no_tpl, 'w', encoding='utf-8') as f:
    f.write('def something_else():\n    pass\n')
rc32, out32 = run_regen(app_py=no_tpl, out=os.path.join(d32, 'out.py'))
check('模板提取不到时退出码为 0', rc32 == 0, out32[-300:])
check('模板提取不到时给出 [SKIP] 提示', '[SKIP]' in out32, out32[-200:])

# 3.3 输出路径是软链：内容要落到**真实目标**上，软链本身保留
d33, inst33 = make_sandbox()
real_target = os.path.join(inst33, 'real-ddns.py')
with open(real_target, 'w', encoding='utf-8') as f:
    f.write('#!/bin/sh\necho OLD\n')
link = os.path.join(inst33, 'aliyun-ddns-update.py')
os.symlink(real_target, link)
rc33, out33 = run_regen(app_py=os.path.join(inst33, 'backend', 'app.py'),
                        out=link)
check('软链场景退出码为 0', rc33 == 0, out33[-300:])
check('软链本身**没有被替换成普通文件**（替换了会写到别处去）',
      os.path.islink(link))
tgt = open(real_target, encoding='utf-8').read() if os.path.isfile(real_target) else ''
try:
    tgt_code = strip_docstrings(tgt)
except SyntaxError:
    tgt_code = tgt
check('真实目标文件被写入了新内容',
      'UpdateDomainRecord' in tgt_code and 'OLD' not in tgt, tgt[:120])

# 3.4 模板语法坏掉：不能留下半截文件（旧脚本还能继续跑）
d34, inst34 = make_sandbox()
broken_app = os.path.join(d34, 'broken_app.py')
with open(broken_app, 'w', encoding='utf-8') as f:
    f.write('def _generate_ddns_update_script():\n'
            '    script_path = "/opt/nftables-web-v2/aliyun-ddns-update.py"\n'
            '    script_content = """def broken(:\n"""\n'
            '    write(script_content)\n')
keep = os.path.join(inst34, 'aliyun-ddns-update.py')
with open(keep, 'w', encoding='utf-8') as f:
    f.write('#!/bin/sh\necho GOOD-OLD-SCRIPT\n')
rc34, out34 = run_regen(app_py=broken_app, out=keep)
check('模板语法坏掉时退出码非 0（调用方能感知失败）', rc34 != 0, out34[-300:])
check('模板语法坏掉时给出 [FAIL] 提示（不是 traceback）',
      '[FAIL]' in out34 and 'Traceback' not in out34, out34[-300:])
check('模板语法坏掉时**旧脚本没被破坏**（不留半截文件）',
      'GOOD-OLD-SCRIPT' in open(keep, encoding='utf-8').read())

# 3.5 幂等
d35, inst35 = make_sandbox()
o35 = os.path.join(inst35, 'aliyun-ddns-update.py')
run_regen(app_py=os.path.join(inst35, 'backend', 'app.py'), out=o35)
first35 = open(o35, encoding='utf-8').read()
run_regen(app_py=os.path.join(inst35, 'backend', 'app.py'), out=o35)
second35 = open(o35, encoding='utf-8').read()
check('重复跑两次内容一致（幂等）', first35 == second35)


# ============================================================
# 第 4 组：兜底路径 —— 缺东西也不能把安装流程带崩
# ============================================================
sec('第 4 组：缺文件时只提示、不中断；清理步骤不会误删')

d4, inst4 = make_sandbox(with_regen=False)
script4 = make_setup_script(inst4)
rc4, out4 = run_sh(script4)
check('缺少 regen_ddns_script.py 时退出码仍是 0（不中断安装）',
      rc4 == 0, out4[-400:])
check('给出了「面板上点一次保存配置并生成脚本」的提示',
      '保存配置并生成脚本' in out4, out4[-300:])

# remove_obsolete_files 是白名单式清理：确认它不会删掉新文件
d4b, inst4b = make_sandbox()
target4b = os.path.join(inst4b, 'backend', 'regen_ddns_script.py')
script4b = make_setup_script(inst4b, call='remove_obsolete_files')
rc4b, out4b = run_sh(script4b)
check('清理步骤执行成功（rc=0）', rc4b == 0, out4b[-300:])
check('清理步骤**没有**删掉 backend/regen_ddns_script.py',
      os.path.isfile(target4b))

# 4.3 app.py 不在：生成器会打 [SKIP] ⇒ **不能**报「已重新生成」
d4c, inst4c = make_sandbox()
os.remove(os.path.join(inst4c, 'backend', 'app.py'))
script4c = make_setup_script(inst4c)
rc4c, out4c = run_sh(script4c)
check('app.py 缺失时退出码仍是 0', rc4c == 0, out4c[-400:])
check('app.py 缺失时如实报「未重新生成」',
      '未重新生成' in out4c, out4c[-300:])
check('app.py 缺失时**没有**报「已重新生成」（假成功）',
      '已重新生成' not in out4c, out4c[-300:])

# 4.4 模板语法坏掉：生成器返回非 0 ⇒ **不能**报「已重新生成」
d4d, inst4d = make_sandbox()
bad_app = os.path.join(d4d, 'broken.py')
with open(bad_app, 'w', encoding='utf-8') as f:
    f.write('def _generate_ddns_update_script():\n'
            '    script_path = "%s"\n'
            '    script_content = """def broken(:\n"""\n'
            '    write(script_content)\n' % os.path.join(inst4d, 'aliyun-ddns-update.py'))
shutil.copy(bad_app, os.path.join(inst4d, 'backend', 'app.py'))
script4d = make_setup_script(inst4d)
rc4d, out4d = run_sh(script4d)
check('模板坏掉时退出码仍是 0（不中断安装）', rc4d == 0, out4d[-400:])
check('模板坏掉时如实报「重新生成失败」',
      '重新生成失败' in out4d, out4d[-300:])
check('模板坏掉时**没有**报「已重新生成」（假成功）',
      '已重新生成' not in out4d, out4d[-300:])


# ============================================================
# 第 5 组：接线 —— 调用点在哪、会不会被部署跳过带掉
# ============================================================
sec('第 5 组：setup.sh 里的接线')

src5 = open(SETUP, encoding='utf-8').read()
lines5 = src5.splitlines()

check('setup.sh 里定义了 regen_ddns_script()',
      re.search(r'^regen_ddns_script\(\) \{', src5, re.M) is not None)

calls5 = [(i, l) for i, l in enumerate(lines5) if l.strip() == 'regen_ddns_script']
check('main 流程里调用了 regen_ddns_script', len(calls5) >= 1,
      '找到 %d 处' % len(calls5))
if calls5:
    idx, line = calls5[0]
    check('调用点是**顶层**调用（4 空格缩进），不是塞在别的函数里',
          line.startswith('    ') and not line.startswith('     '),
          repr(line))
    # ⚠ 光看缩进不够：别的**顶层函数**的函数体也是 4 空格缩进
    #   （setup_service 之类）⇒ 调用点被挪进去，缩进检查照样通过。
    #   ⇒ 还要确认它在 main() 的函数体范围内。
    main_span = func_span(src5, 'main')
    off = sum(len(l) + 1 for l in lines5[:idx])
    check('调用点在 main() 的函数体内（不是挪到别的顶层函数里）',
          main_span is not None and main_span[0] < off < main_span[1],
          'main=%s 调用偏移=%s' % (main_span, off))
    dep = next((i for i, l in enumerate(lines5)
                if 'run_stage "项目文件部署"' in l), None)
    cfg = next((i for i, l in enumerate(lines5)
                if 'run_stage "配置初始化"' in l), None)
    check('调用点在「项目文件部署」阶段**之后**',
          dep is not None and idx > dep,
          '部署=%s 调用=%s' % (dep, idx))
    check('调用点在「配置初始化」阶段之前',
          cfg is not None and idx < cfg,
          '调用=%s 配置=%s' % (idx, cfg))
    # ⚠ 关键：调用点不能挂在 deploy_project 里面 ——
    #   部署阶段被判定成「已完成」而跳过时，那个函数根本不会被调用。
    m = re.search(r'^deploy_project\(\) \{', src5, re.M)
    if m:
        # 用大括号配平截出 deploy_project 的函数体
        depth, end = 0, None
        for j in range(m.start(), len(src5)):
            if src5[j] == '{':
                depth += 1
            elif src5[j] == '}':
                depth -= 1
                if depth == 0:
                    end = j
                    break
        body = src5[m.start():end] if end else ''
        check('deploy_project 函数体里**没有**这个调用点',
              'regen_ddns_script\n' not in body)

check('backend/regen_ddns_script.py 存在（部署包里有它）',
      os.path.isfile(REGEN))

print('\n' + '=' * 60)
print('  通过 %d / 失败 %d' % (len(PASS), len(FAIL)))
if FAIL:
    print('  失败项: %s' % FAIL)
print('=' * 60)
sys.exit(1 if FAIL else 0)
