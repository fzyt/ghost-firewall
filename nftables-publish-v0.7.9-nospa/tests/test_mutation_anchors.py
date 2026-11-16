#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""变异脚本锚点体检：确认每个变异脚本的 old 锚点在源码里还找得到。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_mutation_anchors.py

为什么需要（2026-11-17）
------------------------
变异脚本靠**字符串锚点**改源码。锚点一旦失配（上游改了被改的那段代码），
`apply_edits` 会抛 ValueError ⇒ 那条变异被判「脚本自身的错」⇒ 计入漏网
⇒ 整个脚本 rc=1。

⇒ 表现出来是「这条变异没被抓住」，**实际上这条变异压根没跑过** ——
   守门形同虚设，而且**每次都要跑满一小时的全量回归才看得见**。

本项目已经在这条路上栽过两次：

  · `mutation_check_setup_resume.py` 的 M15 锚点 —— 换源那行早改成两行了，
    锚点还是旧版单行 ⇒ 0 次命中 ⇒ 那条变异一直被「跳过」而不是「被捕获」
    ⇒ 全量回归一直不是全绿（2026-11-16 修）。
  · `mutation_check_c_batch.py` 的 C-02 锚点 —— 本地解析功能把新代码插在
    「router_ip4 自愈」与「_ensure_https_cert()」之间，而那两者的**相邻关系**
    正是 C-02 守着的 ⇒ 锚点失配 ⇒ 整脚本 rc=1（2026-11-17 修）。

⇒ 这个判据把「一小时才发现」变成「几秒钟就知道」。

判定口径
--------
只认 (old, new) 二元组：old 是「当前源码里必须存在的原文」，
new 是变异之后的样子 —— 只检查 old 侧。

锚点去哪找
----------
按**优先级**：
  1. 该脚本自己声明要改的目标文件（从 AST 解析路径常量）
     —— 大多数锚点只可能出现在那里。
  2. 兜底语料：backend/ frontend/ setup/ tools/ 下的所有文本文件。
     （tests/ 不进语料：锚点原文就躺在变异脚本自己的源码里，
       放进去等于「拿自己证明自己」。）

⚠️ 读的是**工作区**内容 ⇒ 变异脚本运行期间跑这个判据会误报
   （那时源码正被临时改写）。全量回归里它在变异阶段之前跑，不会撞上。
"""

import ast
import glob
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_DIRS = ['backend', 'frontend', 'setup', 'tools']

PASS = []
FAIL = []


def check(name, cond, detail=''):
    """记录一条判定。cond 为假时 detail 作为失败说明。"""
    if cond:
        PASS.append(name)
        print('  [PASS] %s%s' % (name, (' — ' + detail) if detail else ''))
    else:
        FAIL.append(name)
        print('  [FAIL] %s%s' % (name, (' — ' + detail) if detail else ''))


def resolve_target_files(tree):
    """解析脚本里的路径常量 → 该脚本要改的文件列表。

    认这两种写法：
        APP_PY = os.path.join(ROOT, 'backend', 'app.py')
        SOME  = 'backend/app.py'
    """
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            if not isinstance(t, ast.Name):
                continue
            v = node.value
            path = None
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                path = v.value
            elif isinstance(v, ast.Call) and getattr(v.func, 'attr', '') == 'join':
                # os.path.join(ROOT, 'tests', 'x.py') —— ROOT 是占位
                parts = []
                for a in v.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        parts.append(a.value)
                    else:
                        parts.append(ROOT)
                path = os.path.join(*parts)
            if not path:
                continue
            if path.startswith('/'):
                path = os.path.relpath(path, ROOT)
            if path.startswith('..'):
                continue
            if os.path.isfile(os.path.join(ROOT, path)) and path not in out:
                out.append(path)
    return out


def corpus_files():
    """兜底语料：源码目录下的所有文本文件。"""
    out = []
    for d in CORPUS_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames
                           if x not in ('__pycache__', '.git', 'node_modules')]
            for fn in filenames:
                out.append(os.path.relpath(
                    os.path.join(dirpath, fn), ROOT))
    return out


_cache = {}


def read_text(rel):
    if rel not in _cache:
        try:
            with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
                _cache[rel] = f.read()
        except (OSError, UnicodeDecodeError):
            _cache[rel] = None
    return _cache[rel]


def looks_like_code(s):
    """像源码片段：多行 + 含代码符号。

    ⇒ 排除掉描述性文本（变异名字、注释片段），那些当然不在源码里。
    """
    return '\n' in s and len(s) >= 25 and ('=' in s or '(' in s or '{' in s)


def main():
    scripts = sorted(glob.glob(os.path.join(ROOT, 'tests', 'mutation_check*.py')))
    if not scripts:
        print('[FAIL] 一个变异脚本都没找到 —— 判据本身没生效')
        sys.exit(1)

    corpus = [(p, read_text(p)) for p in corpus_files()]
    corpus = [(p, c) for p, c in corpus if c]

    total_anchors = 0
    for sp in scripts:
        name = os.path.basename(sp)
        try:
            tree = ast.parse(open(sp, encoding='utf-8').read())
        except SyntaxError as e:
            check('%s 自身语法正确' % name, False, str(e))
            continue
        own = resolve_target_files(tree)
        own_texts = [(read_text(p) or '') for p in own]

        broken = []
        seen = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Tuple) or len(node.elts) != 2:
                continue
            a, b = node.elts
            if not (isinstance(a, ast.Constant) and isinstance(a.value, str)
                    and isinstance(b, ast.Constant)
                    and isinstance(b.value, str)):
                continue
            s = a.value
            if not looks_like_code(s) or s in seen:
                continue
            seen.add(s)
            total_anchors += 1
            hit = any(s in t for t in own_texts)
            if not hit:
                hit = any(s in c for _, c in corpus)
            if not hit:
                broken.append(s)

        if broken:
            check('%s 的 %d 条锚点都能在源码里找到' % (name, len(seen)),
                  False,
                  '失效 %d 条：%s' % (len(broken),
                                     ' / '.join(repr(s[:60]) for s in broken)))
        else:
            check('%s 的 %d 条锚点都能在源码里找到' % (name, len(seen)),
                  True)

    print()
    print('共体检 %d 个变异脚本、%d 条锚点' % (len(scripts), total_anchors))
    if FAIL:
        print('[FAIL] 失败 %d 项：' % len(FAIL))
        for f in FAIL:
            print('   - ' + f)
        sys.exit(1)
    print('[PASS] 通过 %d / %d' % (len(PASS), len(PASS)))
    print('全部通过')


if __name__ == '__main__':
    main()
