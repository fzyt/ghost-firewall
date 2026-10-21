#!/usr/bin/env python3
"""变异验证：网关「路径前缀」改写（宽模式 sub_filter + proxy_redirect）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_gateway_path_rewrite.py

改的是 backend/app.py + frontend/app.js + frontend/index.html。
判定标准只有一条：**旧代码必然让断言失败**。
断言如果改个变量名就绕过，等于没测。

**这个脚本会改写并还原源码，运行期间不能编辑源码、不能部署。**
"""
import os
import subprocess
import sys

# 保险丝：被取消 / 被 kill 时也别把变异留在源码里（见 _mutation_guard.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _mutation_guard import MutationGuard  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
JS = os.path.join(ROOT, 'frontend', 'app.js')
HTML = os.path.join(ROOT, 'frontend', 'index.html')

PY_TEST = os.path.join(ROOT, 'tests', 'test_gateway_path_rewrite.py')
JS_TEST = os.path.join(ROOT, 'tests', 'test_gateway_path_rewrite_frontend.js')

SRC = open(APP, encoding='utf-8').read()
JSRC = open(JS, encoding='utf-8').read()
HSRC = open(HTML, encoding='utf-8').read()

PY = 'py'
JS_KEY = 'js'

APP_MUTANTS = [
    # ── 宽模式开关被忽略 ────────────────────────────────────────
    ('宽模式开关被忽略（永远不生成 sub_filter）',
     "        if isinstance(_rrp, (bool, int)) and _rrp:",
     "        if False:"),

    # ── 形态漏掉一种 ────────────────────────────────────────────
    ('宽模式漏掉 action 形态（表单提交会跑到别的服务去）',
     '            for _attr in ("href", "src", "action"):',
     '            for _attr in ("href", "src"):'),

    ('宽模式把 href 形态写成 src（链接全改不对）',
     """            for _attr in ("href", "src", "action"):
                sf_rules.append((f'{_attr}="/', f'{_attr}="{prefix}/'))""",
     """            for _attr in ("src", "action"):
                sf_rules.append((f'{_attr}="/', f'{_attr}="{prefix}/'))"""),

    # ── 前缀拼接错 ──────────────────────────────────────────────
    ('宽模式前缀后面少一个斜杠（改写出来的路径少一层）',
     """                sf_rules.append((f'{_attr}="/', f'{_attr}="{prefix}/'))""",
     """                sf_rules.append((f'{_attr}="/', f'{_attr}="{prefix}'))"""),

    # ── proxy_redirect 被拿掉（302 跳转又丢前缀）─────────────────
    ('proxy_redirect 不生成（302 跳转会丢路径前缀）',
     """        _lit = _nginx_regex_literal(prefix)
        if _lit:""",
     """        _lit = _nginx_regex_literal(prefix)
        if False:"""),

    ('proxy_redirect 少了负向先行断言（会给已带前缀的 Location 重复加前缀）',
     """            L.append(f"        proxy_redirect ~^/(?!{_bare}/)(.*)$ {prefix}/$1;")""",
     """            L.append(f"        proxy_redirect ~^/(.*)$ {prefix}/$1;")"""),

    ('proxy_redirect 的前缀写错（跳到别的服务去）',
     """            L.append(f"        proxy_redirect ~^/(?!{_bare}/)(.*)$ {prefix}/$1;")""",
     """            L.append(f"        proxy_redirect ~^/(?!{_bare}/)(.*)$ /wrong/$1;")"""),

    # ── proxy_redirect 的两个真机坑（2026-10-20 .166 实测）────────
    ('负向先行断言里带上开头的斜杠（断言恒成立，已带前缀的 Location 被重复加前缀）',
     """            _bare = _lit[1:] if _lit.startswith('/') else _lit""",
     """            _bare = _lit"""),

    ('绝对 URL 规则里端口用捕获组（$1 取到端口，路径整个丢掉）',
     '''f"        proxy_redirect ~^https?://{_host_lit}(?::[0-9]+)?"''',
     '''f"        proxy_redirect ~^https?://{_host_lit}(:[0-9]+)?"'''),

    ('宽泛的「匹配任意 host」规则又回来了（外站跳转被劫持到网关自己）',
     '''            L.append(f"        proxy_redirect ~^/(?!{_bare}/)(.*)$ {prefix}/$1;")''',
     '''            L.append(f"        proxy_redirect ~^/(?!{_bare}/)(.*)$ {prefix}/$1;")\n'''
     '''            L.append(f"        proxy_redirect ~^https?://[^/]+/(?!{_bare}/)(.*)$ "\n'''
     '''                     f"$scheme://$http_host{prefix}/$1;")'''),

    ('上游 host 的点没转义（192.168.100.218 会匹配到 192x168x100x218）',
     """    return host.replace('.', '\\\\.')""",
     """    return host"""),

    # ── 字段校验失效 ────────────────────────────────────────────
    ('非法开关值不再降级（字符串 "false" 会被当成开启）',
     """    rrp = pick("rewrite_root_paths", False)
    clean["rewrite_root_paths"] = bool(rrp) if isinstance(rrp, (bool, int)) else False""",
     """    rrp = pick("rewrite_root_paths", False)
    clean["rewrite_root_paths"] = bool(rrp)"""),

    ('字段清洗不写 rewrite_root_paths（前端传了也存不进去）',
     """    clean["rewrite_root_paths"] = bool(rrp) if isinstance(rrp, (bool, int)) else False""",
     """    clean["rewrite_root_paths"] = False"""),

    # ── 迁移白名单丢字段 ────────────────────────────────────────
    # 2026-10-20 真机踩的坑：_migrate_rp_rules 是字段白名单，漏列的键被
    # 无声丢弃，而它被 load_config() 和 _deploy_all_rules() 各调一次。
    # 后果：开关存进去了、界面也显示开了，生成器读到的却是迁移后的规则。
    ('迁移白名单漏掉 rewrite_root_paths（存进去了但生成器读不到，开关永远不生效）',
     '''            "rewrite_root_paths": bool(r.get("rewrite_root_paths", False)),
            "websocket_enabled": bool(r.get("websocket_enabled", True)),''',
     '''            "websocket_enabled": bool(r.get("websocket_enabled", True)),'''),

    # ── 生成期辅助函数失效 ──────────────────────────────────────
    ('_nginx_regex_literal 不再校验（path_prefix 里的括号能改写整条正则）',
     """    if not s or not _RE_NGINX_LITERAL.match(s):
        return None
    return s""",
     """    if not s:
        return None
    return s"""),

    ('_nginx_dquote 不转义双引号（生成的 nginx 配置语法就坏了）',
     """    return str(s).replace('\\\\', '\\\\\\\\').replace('"', '\\\\"')""",
     """    return str(s)"""),

    # ── 预检失效 ────────────────────────────────────────────────
    ('协议相对 URL 检测恒返回 0（预检变成永远说「安全」）',
     """    hits = _RE_PROTO_RELATIVE.findall(text)""",
     """    hits = []"""),

    ('协议相对 URL 的正则只认 href（漏掉 src/action）',
     r"""_RE_PROTO_RELATIVE = re.compile(
    r'(?:href|src|action)\s*=\s*["\']//[^"\'\s>]{0,120}')""",
     r"""_RE_PROTO_RELATIVE = re.compile(
    r'(?:href)\s*=\s*["\']//[^"\'\s>]{0,120}')"""),
]

JS_MUTANTS = [
    ('前端不再对 rewrite_root_paths 做 === true 归一',
     "      r.rewrite_root_paths = r.rewrite_root_paths === true;",
     "      r.rewrite_root_paths = r.rewrite_root_paths;"),

    ('newRpRule 不带 rewrite_root_paths 字段',
     "        rewrite_root_paths: false,",
     "        // 少了这个字段"),

    ('前端不再读 res.data 这一层（预检结果永远读不到）',
     "        const d = (res && res.data) || {};",
     "        const d = res || {};"),

    ('前端把预检端点路径写错（探测会打到不存在的路由）',
     "api.post('/api/reverse-proxy/detect-protocol-relative', {",
     "api.post('/api/reverse-proxy/detect-proto-relative', {"),
]

HTML_MUTANTS = [
    ('表单里 checkbox 不再绑定 rewrite_root_paths（开关打不开）',
     '<input type="checkbox" x-model="rpEditingRule.rewrite_root_paths" class="mt-1">',
     '<input type="checkbox" x-model="rpEditingRule.rewriteRootPaths" class="mt-1">'),

    ('表单里删掉了预检按钮（用户没法知道会不会误伤）',
     '@click="detectRpProtocolRelative()"',
     '@click="detectRpProtoRel()"'),

    ('列表里不再显示「根绝对路径改写」这一项',
     '<div x-show="rule.rewrite_root_paths">',
     '<div x-show="false">'),
]


def run_py():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, PY_TEST], capture_output=True,
                          text=True, timeout=300, env=env)


def run_js():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run(['node', JS_TEST], capture_output=True,
                          text=True, timeout=300, env=env)


RUNNERS = {PY: run_py, JS_KEY: run_js}


def report(name, results):
    """results = [(label, CompletedProcess), ...]"""
    caught = False
    detail = ''
    for label, r in results:
        fails = [l.strip() for l in r.stdout.splitlines() if '❌' in l]
        # 变异让代码自己崩掉也算抓到 —— 崩掉正是要防的事。
        if r.returncode != 0 and (fails or r.stderr.strip()):
            caught = True
            detail = (fails[0][:86] if fails
                      else ('测试崩溃: ' + r.stderr.strip().splitlines()[-1][:70]))
            break
    if caught:
        print(f'  ✅ 抓住 {name}')
        print(f'        首个失败: {detail}')
    else:
        print(f'  ❌ 漏过 {name}')
    return caught


def main():
    MutationGuard(ROOT).snapshot()   # 保险丝：中断也会还原源码
    print('=' * 74)
    print('变异验证：网关路径前缀改写（宽模式 sub_filter + proxy_redirect）')
    print('=' * 74)

    base_py = run_py()
    base_js = run_js()
    if base_py.returncode != 0:
        print('❌ 基线（Python）没过：')
        print(base_py.stdout[-3000:])
        if base_py.stderr:
            print(base_py.stderr[-1500:])
        return 1
    if base_js.returncode != 0:
        print('❌ 基线（前端契约）没过：')
        print(base_js.stdout[-3000:])
        if base_js.stderr:
            print(base_js.stderr[-1500:])
        return 1
    print(f'基线通过  Python {base_py.stdout.count("✅")} 条  '
          f'前端契约 {base_js.stdout.count("✅")} 条\n')

    caught, noanchor = 0, []
    try:
        for label, path, src, mutants, which in (
            ('后端', APP, SRC, APP_MUTANTS, (PY, JS_KEY)),
            ('前端 JS', JS, JSRC, JS_MUTANTS, (JS_KEY,)),
            ('前端 HTML', HTML, HSRC, HTML_MUTANTS, (JS_KEY,)),
        ):
            for name, old, new in mutants:
                if old not in src:
                    print(f'  ⚠️  锚点未命中 [{label}]: {name}')
                    noanchor.append(name)
                    continue
                mutated = src.replace(old, new, 1)
                if mutated == src:
                    print(f'  ⚠️  变异没改到内容 [{label}]: {name}')
                    noanchor.append(name)
                    continue
                open(path, 'w', encoding='utf-8').write(mutated)
                # 闸：变异必须真的落到这个文件上。写完立刻回读比对。
                on_disk = open(path, encoding='utf-8').read()
                if on_disk != mutated:
                    print(f'  ❌ 变异没落到 [{label}]: {name}')
                    noanchor.append(name)
                    open(path, 'w', encoding='utf-8').write(src)
                    continue
                try:
                    results = [(w, RUNNERS[w]()) for w in which]
                finally:
                    open(path, 'w', encoding='utf-8').write(src)
                caught += report(name, results)
    finally:
        open(APP, 'w', encoding='utf-8').write(SRC)
        open(JS, 'w', encoding='utf-8').write(JSRC)
        open(HTML, 'w', encoding='utf-8').write(HSRC)

    total = len(APP_MUTANTS) + len(JS_MUTANTS) + len(HTML_MUTANTS)
    print('\n' + '=' * 74)
    print(f'变异 {total} 处  捕获 {caught}  锚点未命中 {len(noanchor)}')
    if noanchor:
        for m in noanchor:
            print('  锚点未命中:', m)
        return 1
    print('全部变异均被捕获' if caught == total else '有变异漏过')
    return 0 if caught == total else 1


if __name__ == '__main__':
    sys.exit(main())
