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

    认这几种写法：
        APP_PY = os.path.join(ROOT, 'backend', 'app.py')
        SOME  = 'backend/app.py'
        FILES = {'app': os.path.join(ROOT, 'backend', 'app.py')}   ← 字典里也要认

    ⚠ 字典/列表/元组里的路径常量**必须**认（2026-11-18 修）：
    绝大多数变异脚本用 FILES = {...} 映射表，而 AST 里字典的值不是顶层
    Assign ⇒ 旧版解析不到 ⇒ 那些脚本的锚点被误判成「在错的地方」。
    一次误判就会把真正失配的锚点淹在噪声里。
    """
    out = []

    def _path_of(node):
        """从一个 AST 节点里解析出仓库内的相对路径，认不到返回 None。"""
        path = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            path = node.value
        elif isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'join':
            # os.path.join(ROOT, 'tests', 'x.py') —— ROOT 是占位
            parts = []
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    parts.append(a.value)
                else:
                    parts.append(ROOT)
            path = os.path.join(*parts)
        if not path:
            return None
        if path.startswith('/'):
            path = os.path.relpath(path, ROOT)
        if path.startswith('..'):
            return None
        if os.path.isfile(os.path.join(ROOT, path)) and path not in out:
            out.append(path)
            return path
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if not isinstance(t, ast.Name):
                    continue
                _path_of(node.value)
        elif isinstance(node, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            # 容器里的路径常量（变量名引用由顶层 Assign 负责，这里只认字面量）
            for v in ast.walk(node):
                _path_of(v)
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


def _resolve_str(node, consts):
    """把一个 AST 节点解析成字符串字面量的值，解析不出返回 None。

    认两种形态：
        ast.Constant（字面量）           —— 直接取 value
        ast.Name（引用模块级常量）      —— 查 consts 映射

    ⚠ 认 Name 是必须的（2026-11-18 修）：变异脚本把复用锚点提成命名常量
      是本项目的既有写法，而旧版体检只认字面量 ⇒ 65 条锚点从未被体检。
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in consts:
        return consts[node.id]
    return None


def _resolve_alt_shape(node, consts):
    """认「非标准形态」的变异元组，返回其中的旧串，认不出返回 None。

    两种（2026-11-18 补）：

      1. `(old, new, nth, count)` 四元组 —— secret_perms.py 用：
         旧串在**第一个**位置，不是倒数第二个。
      2. `(name, path, lambda s: s.replace(old, new), expect)` 四元组 ——
         security.py 用：旧串藏在 lambda 里的 `str.replace()` 调用里，
         第一个参数是 old、第二个是 new。

    ⚠ 这两种形态原先都认不出 ⇒ 那两个脚本的锚点**一条都没体检过**
      （工具却报「全部通过」）。security.py 的失配后果尤其隐蔽：
      它的变异函数是 `s.replace(...)`，模式没匹配上时 `mutated == original`
      ⇒ 脚本自己**跳过**这条变异 ⇒ 看起来绿，其实那条变异从没跑过。
    """
    elts = node.elts
    # 形态 1：(old, new, nth, count) —— old 在首位，且第 3 位是整数
    if len(elts) == 4:
        s = _resolve_str(elts[0], consts)
        nth = elts[2]
        if s is not None and isinstance(nth, ast.Constant) \
                and isinstance(nth.value, int) \
                and not isinstance(nth.value, bool):
            return s
    # 形态 2：元组里含 lambda，lambda 体内有 str.replace(old, new)
    for e in elts:
        if not isinstance(e, ast.Lambda):
            continue
        for call in ast.walk(e):
            if not isinstance(call, ast.Call):
                continue
            fn = call.func
            if not (isinstance(fn, ast.Attribute) and fn.attr == 'replace'):
                continue
            if not call.args:
                continue
            old = _resolve_str(call.args[0], consts)
            if old is None:
                continue
            # 必须有两个字符串参数才是 replace(old, new) 形态
            if len(call.args) < 2:
                continue
            new = _resolve_str(call.args[1], consts)
            if new is None:
                continue
            return old
    return None


def looks_like_code(s):
    """像源码片段（而不是描述性文字）。

    ⚠ 单行**也算**：旧版要求 '\\n' in s，把**所有单行锚点**排除在外 ——
    而单行锚点恰恰是最容易因为上游改一行就失配的那些。
    2026-11-18 实测：mutation_check_functional.py 的 FIX-11 锚点就是这样
    失配的（上游把 list_add 的 nft 调用改成拼接 elem），而体检却报「全命中」。
    """
    t = s.strip()
    if len(t) < 10:
        return False
    # 代码符号：等号/括号/引号/中括号。纯自然语言的描述性文字一个都没有。
    return any(ch in t for ch in ('=', '(', '{', '[', '"', "'"))


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

        # 模块级字符串常量名 → 值。
        # ⚠ 必须认（2026-11-18 修）：变异脚本常把锚点提成命名常量再复用，
        #   例如 SCOPE_CHECK_FORMAT_ELEMS = ("...", "...", "...")。
        #   旧版只认「元组里的字面量」⇒ 这类锚点在 AST 里是 ast.Name
        #   ⇒ 整条被跳过 ⇒ **65 条锚点（13 个脚本）一条都没体检过**，
        #   而工具照样报「全通过」。
        #   代价是实打实的：mutation_check_c2_c3_c4.py 的 4 条锚点失配
        #   （上游改了注释缩进）本该几秒钟查出来，却拖到跑满一小时
        #   的全量回归才暴露。
        consts = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) \
                    and isinstance(n.value.value, str):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        consts[t.id] = n.value.value

        # 常量**定义**用的元组（NAME = ("a", "b")）不是变异表 ⇒ 排除。
        # 否则它的 elts[-2] 会被当成一条锚点，凭空造出「锚点必须存在于源码」
        # 的假要求（锚点定义本身当然不在源码里）。
        def_tuples = {id(n.value) for n in ast.walk(tree)
                      if isinstance(n, ast.Assign) and isinstance(n.value, ast.Tuple)}

        broken = []
        wrong_place = []
        seen = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Tuple) or len(node.elts) < 2:
                continue
            if id(node) in def_tuples:
                continue
            # old 永远是**倒数第二个**元素：
            #   2 元组 (old, new)
            #   3 元组 (target, old, new)
            #   4 元组 (id, desc, old, new)
            #   5 元组 (name, target, old, new, expect)
            # ⇒ 统一取 elts[-2]，一次覆盖全部形状。
            #
            # ⚠ 旧版只认 2 元组（`len(node.elts) != 2` 就跳过）⇒ 5 元组脚本
            #   （functional / portal_frontend / fw_recovery / iface_pin）的
            #   锚点**一条都没被体检过**。2026-11-18 实测就是这么漏的。
            old_node, new_node = node.elts[-2], node.elts[-1]
            s = _resolve_str(old_node, consts)
            new_s = _resolve_str(new_node, consts)
            if s is None or new_s is None:
                # 这不是「标准形态」的变异元组 ⇒ 换别的形态认（见下）。
                s = _resolve_alt_shape(node, consts)
                if s is None:
                    continue
            if not looks_like_code(s) or s in seen:
                continue
            seen.add(s)
            total_anchors += 1
            if any(s in t for t in own_texts):
                continue          # 脚本要改的文件里有 = 这条没问题
            if any(s in c for _, c in corpus):
                # 语料里有、但**脚本要改的那个文件里没有** ⇒ 变异脚本照样
                # 失配（它替换的是 FILES[key] 指向的文件的内容）。
                # 这种比「完全找不到」更隐蔽：看着像命中，跑起来才发现。
                wrong_place.append(s)
                continue
            broken.append(s)

        if broken or wrong_place:
            detail = '失效 %d 条：%s' % (
                len(broken), ' / '.join(repr(s[:60]) for s in broken))
            if wrong_place:
                detail += '；位置不对 %d 条：%s' % (
                    len(wrong_place),
                    ' / '.join(repr(s[:60]) for s in wrong_place))
            check('%s 的 %d 条锚点都能在源码里找到' % (name, len(seen)),
                  False, detail)
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
