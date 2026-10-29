#!/usr/bin/env python3
"""变异验证：上游绝对 API 路径前缀（sub_filter 窄模式）。

运行: PYTHONDONTWRITEBYTECODE=1 python3 tests/mutation_check_api_prefix.py

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

PY_TEST = os.path.join(ROOT, 'tests', 'test_api_path_prefix.py')
JS_TEST = os.path.join(ROOT, 'tests', 'test_api_prefix_frontend.js')

SRC = open(APP, encoding='utf-8').read()
JSRC = open(JS, encoding='utf-8').read()
HSRC = open(HTML, encoding='utf-8').read()

PY = 'py'
JS_KEY = 'js'      # ⚠️ 别叫 JS —— 上面 JS 已经是 frontend/app.js 的路径了，
                   #    覆盖掉的话前端 JS 根本不会被变异，变异全「漏过」
                   #    （这个坑真踩过：runner 键名把文件路径变量顶掉了）

APP_MUTANTS = [
    # ── 校验被拿掉：非法值直接进 nginx 配置 ──────────────────────────
    ('_sanitize_api_path_prefix 不再拒绝非法值（静默清空 = 用户以为配好了）',
     "    if not _RE_API_PATH_PREFIX.match(s):\n"
     "        raise ValueError(\n"
     "            f\"无效的 API 路径前缀: {value!r}\"\n"
     "            f\"（必须形如 /api/ 或 /api/v1/，只允许字母数字与 . _ ~ -）\")",
     "    if not _RE_API_PATH_PREFIX.match(s):\n"
     "        return ''"),

    # 用户最常填的就是带斜杠的 /api/，不认它等于「按提示抄一个」都被拒
    ('正则不允许尾斜杠（用户填 /api/ 直接被拒 —— 这条真的踩到过）',
     'r"^/[A-Za-z0-9][A-Za-z0-9._~-]*(?:/[A-Za-z0-9][A-Za-z0-9._~-]*)*/?$")',
     'r"^/[A-Za-z0-9][A-Za-z0-9._~-]*(?:/[A-Za-z0-9][A-Za-z0-9._~-]*)*$")'),

    # 不补尾斜杠 → sub_filter 把 '/api' 换成 '/logcenter/api'，
    # 后面接的是 'search' 而不是 '/search'，改出来的路径是错的
    ('_sanitize_api_path_prefix 不再补尾斜杠（改写出来的路径缺分隔符）',
     "    return s.rstrip('/') + '/'",
     "    return s"),

    # ── 接线被拿掉 ──────────────────────────────────────────────────
    ('_validate_rp_service 不再校验 api_path_prefix（非法值直达 nginx 配置）',
     '    try:\n'
     '        clean["api_path_prefix"] = _sanitize_api_path_prefix(\n'
     '            pick("api_path_prefix", ""))\n'
     '    except ValueError as e:\n'
     '        return None, str(e)',
     '    clean["api_path_prefix"] = str(pick("api_path_prefix", "") or "")'),

    ('_validate_rp_service 把非法值静默清空（用户以为配了，其实没生效）',
     '        clean["api_path_prefix"] = _sanitize_api_path_prefix(\n'
     '            pick("api_path_prefix", ""))\n'
     '    except ValueError as e:\n'
     '        return None, str(e)',
     '        clean["api_path_prefix"] = _sanitize_api_path_prefix(\n'
     '            pick("api_path_prefix", ""))\n'
     '    except ValueError as e:\n'
     '        clean["api_path_prefix"] = ""'),

    ('_migrate_rp_rules 丢掉 api_path_prefix（升级后配置静默失效）',
     '            "api_path_prefix": r.get("api_path_prefix", "") or "",',
     '            "api_path_prefix": "",'),

    # ── 配置生成：功能本体 ──────────────────────────────────────────
    ('网关配置不再生成 sub_filter 块（功能完全没生效）',
     '    if api_prefix:\n        L.append(f"        # ── 上游绝对路径改写：{api_prefix}... -> "',
     '    if False:\n        L.append(f"        # ── 上游绝对路径改写：{api_prefix}... -> "'),

    # 通用规则：实测会把页面里 /var/log/syslog 这类普通路径也改掉
    ('sub_filter 退化成通用规则（把页面里普通路径一起改坏）',
     '        sf_rules.append((f"\'{api_prefix}", f"\'{prefix}{api_prefix}"))\n        sf_rules.append((f\'"{api_prefix}\', f\'"{prefix}{api_prefix}\'))',
     '        sf_rules.append((f"\'/", f"\'{prefix}/"))\n        sf_rules.append((f\'"/\', f\'"{prefix}/\'))'),

    # ── 生成期二次净化：落盘值不可信 ──────────────────────────────
    # 配置文件可能被手工改过；这个值要拼进 nginx 的引号字符串，
    # 不再净化一次 = nginx 指令注入。
    ('生成期不再二次净化（手工改过的配置能注入 nginx 指令）',
     '        api_prefix = _sanitize_api_path_prefix(rule.get("api_path_prefix", ""))',
     '        api_prefix = str(rule.get("api_path_prefix", "") or "").strip()'),

    # 非法值时让异常冒泡 → 整份网关配置生成失败 → **所有**服务一起挂
    # （比一个 404 严重得多，也违背「窄模式降级安全」的承诺）
    ('非法值时让异常冒泡（一份坏配置拖垮整个网关）',
     '    except ValueError as e:\n        # 非法值：**只放弃「改写」这一项，不放弃整条服务**。',
     '    except ValueError as e:\n        raise\n        # 非法值：**只放弃「改写」这一项，不放弃整条服务**。'),

    # 回显进 nginx 注释时不做单行化 → 值里的换行把注释劈开
    # → 后半行变成一条 nginx 指令
    #
    # ⚠️ 这里必须直接把 repr 换成**裸插值**才有杀伤力：
    # 只删掉后面的 .replace('\n','\\n') 是**等价变异** —— repr 本身
    # 就已经把换行转义成 \n 了，删不删行为一样，断言抓不到。
    # 真正的漏洞是「用裸 f-string 插值原值」。
    ('回显原值时用裸插值（换行把 nginx 注释劈开 → 后半行变成指令）',
     "        _bad = repr(rule.get('api_path_prefix')).replace('\\n', '\\\\n')",
     '        _bad = f"{rule.get(\'api_path_prefix\')}"'),

    ('sub_filter 只改单引号形式（双引号写的 API 路径漏改 → 照样 404）',
     '        sf_rules.append((f"\'{api_prefix}", f"\'{prefix}{api_prefix}"))\n        sf_rules.append((f\'"{api_prefix}\', f\'"{prefix}{api_prefix}\'))',
     '        sf_rules.append((f"\'{api_prefix}", f"\'{prefix}{api_prefix}"))'),

    # 默认 sub_filter_once on = 只改第一处，页面里第二处引用还是裸路径
    ('sub_filter_once off 被拿掉（页面里只有第一处被改）',
     '        L.append("        sub_filter_once off;")',
     '        # sub_filter_once removed'),

    # JSON 响应被改写 → 解析直接炸
    ('sub_filter_types 把 application/json 也算进去（改坏 JSON 响应）',
     '        L.append("        sub_filter_types application/javascript text/css;")',
     '        L.append("        sub_filter_types application/javascript text/css application/json;")'),

    # nginx 的 sub_filter_types 默认已含 text/html，重复写会报
    # [warn] duplicate MIME type "text/html" —— 每次 nginx -t / reload 刷一行
    ('sub_filter_types 重复写 text/html（nginx 每次 reload 都报 duplicate MIME type）',
     '        L.append("        sub_filter_types application/javascript text/css;")',
     '        L.append("        sub_filter_types text/html application/javascript text/css;")'),

    # 上游压缩了正文 → sub_filter 匹配不到 → 功能静默失效
    ('不再清掉上游压缩（sub_filter 在压缩正文上匹配不到）',
     '        L.append(\'        proxy_set_header Accept-Encoding "";\')',
     '        # Accept-Encoding not cleared'),

    # ── 探测：读 openapi.json 的正确性 ──────────────────────────────
    ('探测把单段路径也算成 API 前缀（/health 会被当成前缀）',
     '        if len(parts) >= 2:',
     '        if len(parts) >= 1:'),

    ('探测返回完整路径而不是第一段（拿到 /api/search/html/ 这种没法用）',
     '            segs.add(parts[0])',
     "            segs.add('/'.join(parts))"),

    ('探测失败时不给出原因（前端只能显示「没探测到」）',
     '    except Exception as e:\n'
     '        return [], f"读取 {url} 失败：{type(e).__name__}: {e}"',
     '    except Exception as e:\n'
     '        return [], ""'),

    # ── 端点契约 ────────────────────────────────────────────────────
    # 前端读 res.data.prefixes；后端一平铺，前端就永远读到 undefined
    ('探测端点不再把结果放在 data 信封里（前端读到 undefined）',
     '    return jsonify({"success": True,\n'
     '                    "data": {"prefixes": prefixes, "error": err}})',
     '    return jsonify({"success": True,\n'
     '                    "prefixes": prefixes, "error": err})'),

    ('探测失败时返回 500（前端拿不到原因，只看到「请求失败」）',
     '    prefixes, err = _detect_upstream_api_prefixes(host, port, proto)\n'
     '    return jsonify({"success": True,\n'
     '                    "data": {"prefixes": prefixes, "error": err}})',
     '    prefixes, err = _detect_upstream_api_prefixes(host, port, proto)\n'
     '    if err:\n'
     '        return jsonify({"success": False, "message": err}), 500\n'
     '    return jsonify({"success": True,\n'
     '                    "data": {"prefixes": prefixes, "error": err}})'),

    ('探测端点不再校验协议（非法协议能进来）',
     '    if proto not in (\'http\', \'https\'):\n'
     '        return jsonify({"success": False,\n'
     '                        "message": "target_protocol 只允许 http 或 https"}), 400',
     '    if False:\n'
     '        return jsonify({"success": False,\n'
     '                        "message": "target_protocol 只允许 http 或 https"}), 400'),

    ('探测端点不再校验地址格式（空 body 会 500 而不是 400）',
     '    if not host or not _is_port(port):\n'
     '        return jsonify({"success": False,\n'
     '                        "message": "target_address 必须是 内网IP:端口"}), 400',
     '    if False:\n'
     '        return jsonify({"success": False,\n'
     '                        "message": "target_address 必须是 内网IP:端口"}), 400'),
]

JS_MUTANTS = [
    # 第十七节那个 bug 的同款：读错 JSON 层级
    ('前端读 res.prefixes 而不是 res.data.prefixes（探测定成功了却显示「没探测到」）',
     '        const prefixes = (res.data && res.data.prefixes) || [];\n'
     '        const err = (res.data && res.data.error) || \'\';',
     '        const prefixes = (res.prefixes) || [];\n'
     '        const err = (res.error) || \'\';'),

    ('探测结果不回填到表单字段（用户看不到也存不进去）',
     '          r.api_path_prefix = prefixes[0];',
     '          // not applied'),

    ('newRpRule 不带 api_path_prefix 字段（新建时是 undefined）',
     "        client_max_body_size: '1M',\n"
     "        api_path_prefix: '',",
     "        client_max_body_size: '1M',"),

    ('editRpRule 不归一化 api_path_prefix（老规则编辑时是 undefined）',
     "      r.api_path_prefix = r.api_path_prefix || '';",
     '      // not normalized'),

    ('探测没有 pending 状态（连点会并发打探测）',
     '      this.rpDetectingPrefix = true;',
     '      // no pending state'),

    ('探测异常被静默吞掉（用户看不到任何提示）',
     "        this.rpApiPrefixHint = '探测失败: ' + e.message;",
     "        this.rpApiPrefixHint = '';"),
]

HTML_MUTANTS = [
    ('API 路径前缀输入框不再绑定这个字段（填了也不生效）',
     '                  <input type="text" x-model="rpEditingRule.api_path_prefix"\n'
     '                    placeholder="例如 /api/" class="flex-1 nf-mono">',
     '                  <input type="text" x-model="rpEditingRule.some_other_field"\n'
     '                    placeholder="例如 /api/" class="flex-1 nf-mono">'),

    ('「自动探测」按钮不再调 detectRpApiPrefix',
     '<button type="button" @click="detectRpApiPrefix()"',
     '<button type="button" @click="noop()"'),

    ('列表里不再显示已配置的 API 路径前缀',
     '                        x-text="rule.api_path_prefix"></dd>',
     '                        x-text=""></dd>'),
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
    print('变异验证：上游绝对 API 路径前缀（sub_filter 窄模式）')
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
                    # 理论上不可能（old 在 src 里），但留着当保险
                    print(f'  ⚠️  变异没改到内容 [{label}]: {name}')
                    noanchor.append(name)
                    continue
                open(path, 'w', encoding='utf-8').write(mutated)
                # 闸：变异必须真的落到这个文件上。
                # 上一个版本踩过：runner 键名把文件路径变量顶掉了，
                # 于是「变异前端 JS」其实写到了另一个文件，前端一个字没改，
                # 6 个变异全「漏过」还看不出来。写完立刻回读比对。
                on_disk = open(path, encoding='utf-8').read()
                if on_disk != mutated:
                    print(f'  ❌ 变异没落到 [{label}]: {name}（写到了 {path}，'
                          f'实际路径 {os.path.abspath(path)}）')
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
