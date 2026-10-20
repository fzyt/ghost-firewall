#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
后端返回形状 × 前端取值 —— 契约测试

为什么要有这个测试（第十七节的教训）
------------------------------------
后端 70+ 个路由里，**返回结构分两种**：

  信封式  {"success": true, "data": {...}}      ← 多数
  平铺式  {"success": true, "presets": [...]}   ← 少数

而 `frontend/app.js` 的 `api.request` 只剥掉**顶层**的 `success`/`message`，
`data` 信封原样留在返回值里。于是：

  - 信封式端点 → 前端必须写 `x.data.字段`（或用 `unwrap(x).字段`）
  - 平铺式端点 → 前端必须写 `x.字段`

写错一层的**后果不是报错**，而是 `undefined` 被 `|| []` 兜成空值 ——
页面上安静地显示「暂无预设」，后端数据其实好好地存着。

第十七节真机复现过：用户在面板里加了预设、toast 也提示「预设已添加」，
但列表永远空。根因就是 `data.presets` 少读了一层（应为 `data.data.presets`）。

**为什么之前一直没被测出来**：
`tests/test_frontend.js` 里零处提到 `api.request` / `.data` / `presets`；
`func_test.py` 读预设用的是**裸 HTTP**（`.get('data',{}).get('presets')`），
它**正确地**钻进了信封——它走裸 HTTP，不经过 `api.request`。
于是测试与前端对「字段在哪一层」的认知正好错开：
**测试永远是对的，前端永远是错的，整套测试对这一类 bug 完全失明。**

这个测试就是来补这个洞的：把后端每个 (路由,方法) 的返回形状，与前端每个
调用点实际取的字段做对账，对不上就红。以后新增/修改端点，前端读错层
**立刻**变红，而不是等用户在界面上发现。

判定规则
--------
  后端=信封式 + 前端读 `x.字段`        → ❌ 少读一层
  后端=平铺式 + 前端读 `x.data.字段`    → ❌ 多读一层
  后端=信封式 + 前端读 `x.data.字段`    → ✅
  后端=平铺式 + 前端读 `x.字段`        → ✅
  前端读 `unwrap(x).字段`              → ✅（unwrap 对两种都对）
  同一行是 `a || a.data || a` 这种回退链 → 任一分支能解析就算 ✅

用法: python3 tests/test_api_contract.py
"""
import ast
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'backend', 'app.py')
APP_JS = os.path.join(ROOT, 'frontend', 'app.js')

P = 0
F = 0
FAILURES = []


def ok(name, cond, detail=''):
    global P, F
    if cond:
        P += 1
        print('  ✅ ' + name)
    else:
        F += 1
        FAILURES.append(name)
        print('  ❌ ' + name + ('  ' + detail if detail else ''))


# ══════════════════════════════════════════════════════════════
# 一、后端：每个 (路由, 方法) 的"成功返回"形状
# ══════════════════════════════════════════════════════════════

def _shape_of_arg(a):
    """看 jsonify 的第一个参数，判断成功返回的形状。

    只认 success=True 的返回 —— 错误分支会抛异常，根本走不到前端取值。
    `jsonify(dict(config, success=True, ...))` 也算平铺式（配置字段在顶层）。
    """
    if isinstance(a, ast.Dict):
        keys = [k.value for k in a.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        if 'success' not in keys:
            return None
        succ = None
        for k, v in zip(a.keys, a.values):
            if isinstance(k, ast.Constant) and k.value == 'success':
                succ = v
        if not (isinstance(succ, ast.Constant) and succ.value is True):
            return None
        return 'envelope' if 'data' in keys else 'flat'
    if isinstance(a, ast.Call) and getattr(a.func, 'id', None) == 'dict':
        for kw in a.keywords:
            if kw.arg == 'success':
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return 'flat'
    return None


def backend_shapes():
    """返回 {(路径, 方法): 'envelope' | 'flat' | 'mixed'}

    键里**必须带方法**：同一个路径的 GET 和 POST 形状可以不同
    （实测 /api/config：GET 是平铺式，POST 是信封式）。
    只按路径建键会让两个处理器互相覆盖 —— 那样扫出来的结论是假的。
    """
    src = open(APP_PY, encoding='utf-8').read()
    tree = ast.parse(src)

    def route_of(node):
        for d in node.decorator_list:
            if isinstance(d, ast.Call) and getattr(d.func, 'attr', None) == 'route':
                if d.args and isinstance(d.args[0], ast.Constant):
                    path = d.args[0].value
                    methods = None
                    for kw in d.keywords:
                        if kw.arg == 'methods':
                            try:
                                methods = [e.value for e in kw.value.elts]
                            except Exception:
                                methods = None
                    if not methods:
                        methods = ['GET']
                    return path, [m.upper() for m in methods]
        return None, []

    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        path, methods = route_of(node)
        if not path:
            continue
        found = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Call):
                fn = sub.value.func
                nm = getattr(fn, 'id', None) or getattr(fn, 'attr', None)
                if nm != 'jsonify' or not sub.value.args:
                    continue
                s = _shape_of_arg(sub.value.args[0])
                if s:
                    found.add(s)
        if not found:
            continue
        kind = found.pop() if len(found) == 1 else 'mixed'
        for m in methods:
            out[(path, m)] = kind
    return out


# ══════════════════════════════════════════════════════════════
# 二、前端：调用点 → 变量 → 作用域内读到的字段
# ══════════════════════════════════════════════════════════════

CALL_RE = re.compile(r"api\.(get|post|put|delete)\(\s*([^)]*?)\s*(?:,|\))")
ASSIGN_RE = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*await\s+api\.\w+\(")
DESTRUCT_RE = re.compile(r"const\s*\[([^\]]+)\]\s*=\s*await\s*Promise\.all\(")
METHOD_START_RE = re.compile(r"^ {4}(?:async\s+)?\w+\s*\(")
METHOD_END_RE = re.compile(r"^ {4}\},?\s*$")
DERIVE_RE = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*([^;]+);")


def _split_top_level(text, sep):
    """按顶层分隔符切分（括号/引号内部的不算）"""
    out, depth, cur, quote = [], 0, '', None
    for ch in text:
        if quote:
            cur += ch
            if ch == quote:
                quote = None
            continue
        if ch in '"\'':
            quote = ch
            cur += ch
            continue
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == sep and depth == 0:
            out.append(cur)
            cur = ''
            continue
        cur += ch
    if cur.strip():
        out.append(cur)
    return out


def path_from_arg(argtext):
    """从 api 调用实参还原出路径。

    实参可能是纯字面量（'/api/x'），也可能是**动态拼接**
    （'/api/reverse-proxy/certificates/' + cert.id + '/renew'）。
    拼接里的变量段一律记成 `<expr>`，让它跟后端路由里的 `<cert_id>` 占位符对上 ——
    证书续期/删除就是这么被漏掉的。
    """
    first = _split_top_level(argtext, ',')[0]
    out = ''
    for seg in _split_top_level(first, '+'):
        seg = seg.strip()
        m = re.match(r"^'([^']*)'$", seg) or re.match(r'^"([^"]*)"$', seg)
        if m:
            out += m.group(1)
        else:
            out += '<expr>'
    return out


def strip_js_comments(src):
    """去掉 JS 注释（保留行数，便于按行号定位）。

    必须去注释 —— 注释里出现 `data.authenticated` 这种字样是**说明文字**，
    不是真的取值。第十七节那段注释就写着一句"直接读 data.authenticated
    永远是 undefined"，不剥注释的话它会被当成一处真 bug。

    ⚠️ 难点在 JS 的四种"看起来像代码"的东西：
       1. 普通字符串  '...'  "..."
       2. 模板字符串  `...`   ← app.js:807 有 `...replace(/"/g, '""')...`，
          模板里套着正则、正则里套着引号。不认反引号的话，那个 " 会把
          后面的代码整段当成字符串，注释就剥不掉了。
       3. 正则字面量  /.../  —— 里面的引号不是字符串的开始。
       4. 注释        //...  /*...*/
    """
    out = []
    i, n = 0, len(src)
    in_block = False
    prev_sig = ''      # 上一个有效字符，用来判断 '/' 是正则还是除号
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ''
        if in_block:
            if c == '*' and nxt == '/':
                in_block = False
                i += 2
                continue
            out.append('\n' if c == '\n' else ' ')
            i += 1
            continue
        if c == '/' and nxt == '*':
            in_block = True
            i += 2
            out.append('  ')
            continue
        if c == '/' and nxt == '/':
            while i < n and src[i] != '\n':
                out.append(' ')
                i += 1
            continue
        if c in '"\'':
            q = c
            out.append(c)
            i += 1
            while i < n:
                if src[i] == '\\':
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                out.append(src[i])
                if src[i] == q:
                    i += 1
                    break
                if src[i] == '\n':     # 没闭合就到行尾，放弃
                    break
                i += 1
            prev_sig = 'x'
            continue
        if c == '`':
            out.append(c)
            i += 1
            while i < n:
                if src[i] == '\\':
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                out.append(src[i])
                if src[i] == '`':
                    i += 1
                    break
                i += 1
            prev_sig = 'x'
            continue
        # 正则字面量：'/' 出现在「可以开始表达式」的位置
        if c == '/' and (prev_sig == '' or prev_sig in '(,=:[!&|?{};+-*%<>~^'):
            out.append(c)
            i += 1
            in_class = False
            while i < n:
                ch = src[i]
                if ch == '\\':
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                if ch == '\n':
                    break
                if ch == '[':
                    in_class = True
                elif ch == ']':
                    in_class = False
                out.append(ch)
                i += 1
                if ch == '/' and not in_class:
                    break
            # 正则后面的 flag
            while i < n and src[i].isalpha():
                out.append(src[i])
                i += 1
            prev_sig = 'x'
            continue
        out.append(c)
        if not c.isspace():
            prev_sig = c
        i += 1
    return ''.join(out)


def enclosing_method(lines, idx):
    start = 0
    for i in range(idx, -1, -1):
        if METHOD_START_RE.match(lines[i]):
            start = i
            break
    end = len(lines) - 1
    for i in range(idx, len(lines)):
        if i > start and METHOD_END_RE.match(lines[i]):
            end = i
            break
    return start, end


def classify_segment(seg, var, deriv):
    """一个 `||` 分支里对 var 的取值形态。

    返回 'raw' | 'inner' | 'unwrap' | None

    'raw'   = 读的是 api 响应的**顶层**（信封式端点上这一层没有业务字段）
    'inner' = 读的是响应的 `data` 信封**内层**
    'unwrap'= 读的是 unwrap() 的结果（信封式、平铺式**都能**解析）

    `deriv` 是这个变量**本身**的来源形态。派生变量（`const h = unwrap(d)`）
    必须一起跟踪 —— 否则把 `unwrap(d)` 改回 `d` 这样的变异，扫描器会因为
    「d 不再被读到」而查不出任何东西（变异脚本实测漏过 2 处）。
    """
    if re.search(r"unwrap\(\s*" + re.escape(var) + r"\s*\)", seg):
        return 'unwrap'
    if re.search(r"(?<![\w.$])" + re.escape(var) + r"\s*\.\s*data\s*\.", seg):
        return 'inner'
    if re.search(r"(?<![\w.$])" + re.escape(var) + r"\s*\.\s*data(?![\w.$])", seg):
        return 'inner'
    if re.search(r"(?<![\w.$])" + re.escape(var) + r"\s*\.\s*\w+", seg):
        return deriv
    # 裸变量引用（如 `providers.data || providers` 的后半截）：
    # 拿到的就是这个变量本身的值，形态跟变量一致。
    bare = re.sub(r"[\s();,]", "", seg)
    if bare == var:
        return deriv
    return None


def _deriv_of(rhs, derivs):
    """求派生变量的来源形态。

    `const h = unwrap(d);` → 'unwrap'（d 是 raw 时）
    `const h = d.data;`  → 'inner'
    `const h = d;`       → 继承 d 的形态
    其它表达式（`d || {}`、`d.foo` 之类）→ None（不跟踪）
    """
    rhs = rhs.strip()
    m = re.match(r"^unwrap\(\s*(\w+)\s*\)$", rhs)
    if m:
        base = derivs.get(m.group(1))
        return 'unwrap' if base == 'raw' else base
    m = re.match(r"^(\w+)\s*\.\s*data$", rhs)
    if m:
        return 'inner' if m.group(1) in derivs else None
    m = re.match(r"^(\w+)$", rhs)
    if m:
        return derivs.get(m.group(1))
    return None


def frontend_sites():
    lines = strip_js_comments(open(APP_JS, encoding='utf-8').read()).split('\n')

    # 0) 源码里 api 调用出现的次数（按「前端路径 + 方法」计）
    #
    # 用途：做「源码出现几次，就必须被解析几次」的自我证明（见 main()）。
    # 端点覆盖**不等于**调用点覆盖 —— 同一个端点有两个调用点时，
    # 漏掉一个，端点集看起来还是齐的，盲区就被掩盖了。
    src_calls = {}
    for ln in lines:
        for mm in CALL_RE.finditer(ln):
            k = (path_from_arg(mm.group(2)), mm.group(1).upper())
            src_calls[k] = src_calls.get(k, 0) + 1

    # 1) 先找 api 结果变量（形态 raw）
    raw_defs = []
    # ── 扫描器自己的盲区计数 ──────────────────────────────────
    #
    # 「结果被绑定到变量、但扫描器没解析出它对应哪个端点」的调用点。
    #
    # 为什么必须显式数出来：2026-10-20 实测踩过 —— 前端把 api.get 包进了
    # `loadOne('/api/lists/xxx', fallback)` 这种包装函数，扫描器的
    # CALL_RE（只认 `api.get('/api/...')` 字面量）就看不见那 4 个调用点了。
    # 而端点覆盖集**没变**（loadListPresets 里还有同一个端点），
    # 所以「覆盖到 /api/lists/presets」那条自我证明照样全绿 ——
    # 「读错一层」重新变成零不匹配的**假绿**（变异脚本实测漏过 2 处）。
    #
    # ⇒ 盲区必须**自己报数**，不能靠端点覆盖去间接推断。
    misses = []

    for i, ln in enumerate(lines):
        m = ASSIGN_RE.search(ln)
        if m:
            var = m.group(1)
            blob, j = ln, i
            while not CALL_RE.search(blob) and j + 1 < len(lines) and j - i < 3:
                j += 1
                blob += '\n' + lines[j]
            cm = CALL_RE.search(blob)
            if cm:
                raw_defs.append((i, var, path_from_arg(cm.group(2)), cm.group(1).upper()))
            else:
                # 绑定了变量却认不出是哪个 api 调用 —— 盲区
                misses.append(f'L{i + 1}  {var} = await api.…(认不出端点)')

        dm = DESTRUCT_RE.search(ln)
        if dm:
            names = [x.strip() for x in dm.group(1).split(',') if x.strip()]
            blob, j = ln, i
            eps = [(path_from_arg(mm.group(2)), mm.group(1).upper())
                   for mm in CALL_RE.finditer(blob)]
            # ⚠️ 结束条件是「找到的 api 调用数够了」，**不是**方括号计数 ——
            #    `const [a, b] = await Promise.all([` 这一行里已经有两个 '['，
            #    按括号计数判断会以为已经收全，结果一个 api 调用都没抓到，
            #    loadLists 里那 4 个调用点会被静默漏掉。
            while len(eps) < len(names) and j + 1 < len(lines) and j - i < 12:
                j += 1
                blob += '\n' + lines[j]
                eps = [(path_from_arg(mm.group(2)), mm.group(1).upper())
                       for mm in CALL_RE.finditer(blob)]
            if len(eps) < len(names):
                # 少认出了几个 —— 每个少认出的变量都是盲区
                for nm in names[len(eps):]:
                    misses.append(f'L{i + 1}  {nm} (Promise.all 里认不出对应的 api 调用)')
            for idx, nm in enumerate(names):
                if idx < len(eps):
                    raw_defs.append((i, nm, eps[idx][0], eps[idx][1]))

    # 2) 逐个方法作用域：收集派生变量 + 读取
    sites = []
    scopes = []
    i = 0
    while i < len(lines):
        if METHOD_START_RE.match(lines[i]):
            j = i
            while j < len(lines) and not (j > i and METHOD_END_RE.match(lines[j])):
                j += 1
            scopes.append((i, min(j, len(lines) - 1)))
            i = j
        else:
            i += 1

    for s, e in scopes:
        scope_lines = lines[s:e + 1]

        # 作用域内的变量表：var -> (形态, 端点, 方法)
        vars_in_scope = {}
        for dline, var, endpoint, method in raw_defs:
            if s <= dline <= e:
                vars_in_scope[var] = ('raw', endpoint, method)

        # 派生变量：反复迭代，直到没有新的（`const h = unwrap(d)` 里 d 得先在表里）
        for _ in range(4):
            changed = False
            for k, ln in enumerate(scope_lines):
                m = DERIVE_RE.search(ln)
                if not m:
                    continue
                nm = m.group(1)
                if nm in vars_in_scope:
                    continue
                d = _deriv_of(m.group(2), {v: t[0] for v, t in vars_in_scope.items()})
                if d is None:
                    continue
                base = None
                for v, t in vars_in_scope.items():
                    if re.search(r"(?<![\w.$])" + re.escape(v) + r"(?![\w$])", m.group(2)):
                        base = t
                        break
                if base is None:
                    continue
                vars_in_scope[nm] = (d, base[1], base[2])
                changed = True
            if not changed:
                break

        # 读取：每个变量在作用域内被读了哪些字段
        for var, (deriv, endpoint, method) in vars_in_scope.items():
            reads = []
            for k, ln in enumerate(scope_lines):
                abs_line = s + k + 1
                if not re.search(r"(?<![\w.$])" + re.escape(var) + r"(?![\w$])", ln):
                    continue
                forms = set()
                for seg in ln.split('||'):
                    f = classify_segment(seg, var, deriv)
                    if f:
                        forms.add(f)
                if forms:
                    reads.append((abs_line, forms))
            if reads:
                sites.append({'line': s + 1, 'var': var, 'endpoint': endpoint,
                              'method': method, 'deriv': deriv, 'reads': reads})
    resolved_calls = {}
    for _dline, _var, _ep, _m in raw_defs:
        k = (_ep, _m)
        resolved_calls[k] = resolved_calls.get(k, 0) + 1
    return sites, src_calls, resolved_calls, misses


def norm_endpoint(path, method, shapes):
    """把前端路径映射到后端 (路由, 方法)。

    前端路径经常是**动态拼接**的（`'/api/reverse-proxy/certificates/' + cert.id + '/renew'`），
    而后端路由里对应位置写的是占位符（`/api/reverse-proxy/certificates/<cert_id>/renew`）。
    所以匹配时后端的 `<...>` 段要当**通配**用 —— 否则这类端点会被静默漏掉
    （证书续期/删除就是这么漏的）。
    """
    p = path.split('?')[0]
    if (p, method) in shapes:
        return p, method
    pseg = p.split('/')
    best = None
    for (r, m) in shapes:
        if m != method:
            continue
        rseg = r.split('/')
        if len(rseg) != len(pseg):
            continue
        ok = True
        for a, b in zip(pseg, rseg):
            if a == b:
                continue
            # 后端是占位符 → 当通配
            if b.startswith('<') and b.endswith('>'):
                continue
            ok = False
            break
        if ok:
            best = (r, m)
            break
    if best:
        return best
    # 退一步：前缀匹配（前端路径比后端路由长，且前缀全对）
    for (r, m) in shapes:
        if m == method and p.startswith(r) and len(p) > len(r):
            return r, m
    return None, None


# ══════════════════════════════════════════════════════════════
# 三、对账
# ══════════════════════════════════════════════════════════════

def main():
    print('=' * 70)
    print(' API 契约测试（后端返回形状 × 前端取值）')
    print('=' * 70)

    shapes = backend_shapes()
    env_n = sum(1 for v in shapes.values() if v == 'envelope')
    flat_n = sum(1 for v in shapes.values() if v == 'flat')
    print(f'  后端 (路由,方法) 组合：{len(shapes)} 个有确定形状'
          f'（信封式 {env_n} / 平铺式 {flat_n}）')

    sites, src_calls, resolved_calls, misses = frontend_sites()
    checked = 0
    violations = []
    endpoints_seen = set()

    for s in sites:
        ep, method = norm_endpoint(s['endpoint'], s['method'], shapes)
        if ep is None:
            continue
        kind = shapes.get((ep, method))
        if kind in (None, 'mixed'):
            continue
        endpoints_seen.add(ep)
        for line, forms in s['reads']:
            checked += 1
            good = (
                ('unwrap' in forms)
                or (kind == 'envelope' and 'inner' in forms)
                or (kind == 'flat' and 'raw' in forms)
            )
            if not good:
                violations.append((line, s['var'], sorted(forms), ep, method, kind))

    print(f'  前端调用点：{len(sites)} 个，实际对账 {checked} 处字段读取')
    print()

    if violations:
        print('  ── 读错层的调用点 ──')
        for line, var, forms, ep, method, kind in violations:
            print(f'    ❌ app.js:{line}  {var}.…  形态={forms}  '
                  f'← {ep} [{method}]  后端={kind}')
        print()

    ok('没有读错层的调用点', not violations, f'{len(violations)} 处不匹配')

    # ── 自我证明：光"没报错"不算通过，必须真的检查到了东西 ──
    # 这一条是本测试自己的保险丝：扫描器哪天失灵（正则改坏、文件挪位、
    # 注释剥离写错），会变成"零不匹配"—— 那和第十七节
    # 「测试永远是对的、前端永远是错的」是同一种失明。
    ok('扫描器确实检查到了足够多的字段读取（自我证明）', checked >= 25,
       f'实际只检查了 {checked} 处（阈值 25）—— 扫描器可能失灵了')
    ok('覆盖到了所有已知的易错端点', {
        '/api/lists/presets', '/api/lists/history', '/api/rules/health',
    } <= endpoints_seen, f'已覆盖: {sorted(endpoints_seen)}')
    ok('预设端点确实被对账过（第十七节的原始 bug 所在）',
       '/api/lists/presets' in endpoints_seen)

    # ── 自我证明 2：扫描器不能有盲区 ─────────────────────────
    #
    # 「结果被绑定到变量、但扫描器认不出它是哪个 api 调用」的调用点 = 盲区。
    # 盲区里的调用点**根本没被对账** —— 那里读错一层也不会被发现。
    #
    # 2026-10-20 实测踩过：前端把 api.get 包进了 loadOne('/api/lists/xxx', …)
    # 这种包装函数，扫描器就看不见那 4 个调用点了。而端点覆盖集**没变**
    # （loadListPresets 里还有同一个端点），所以上面那条「覆盖到
    # /api/lists/presets」的自我证明照样全绿 ——「读错一层」重新变成
    # 零不匹配的**假绿**（变异脚本实测漏过 2 处）。
    #
    # ⇒ 端点覆盖 ≠ 调用点覆盖。盲区必须自己报数。
    print(f'  源码里的 api 调用：{sum(src_calls.values())} 处，'
          f'扫描器解析到 {sum(resolved_calls.values())} 处，'
          f'盲区 {len(misses)} 处')
    ok('扫描器没有盲区（每个绑定了变量的 api 调用都认出了端点）', not misses,
       '；'.join(misses[:6]))

    print()
    print('=' * 70)
    print(f' 合计: ✅ {P}   ❌ {F}')
    if F:
        print(' 失败: ' + ', '.join(FAILURES))
    else:
        print(' 全部通过')
    print('=' * 70)
    return 1 if F else 0


if __name__ == '__main__':
    sys.exit(main())
