"""网关「路径前缀」相关缺陷的回归测试。

运行:  python3 tests/test_gateway_path_rewrite.py

背景（2026-10-20）：
   路径前缀方案（一个端口 + /xxx/ 前缀分发多个服务）有个固有陷阱 ——
   **应用吐出来的根绝对路径会跑出前缀**。

   浏览器解析 URL 时，以 "/" 开头的路径是 absolute-path reference
   （RFC 3986 §5.2.2）：它**替换** base 的整个 path，只保留 scheme+authority。
   所以在 https://host/ght/ 页面上，href="/static/style.css" 会被解析成
   https://host/static/style.css —— /ght/ 前缀被整个丢掉。
   而网关按前缀分发，根路径没有规则 → nginx 直接 404。

   两个出口，性质不同：
     ① 正文里的路径  → nginx sub_filter（改响应正文）
     ② 302 跳转的 Location → nginx proxy_redirect（改响应头）
   两者互不替代：sub_filter 只处理正文，碰不到响应头。

   真机实测的两个事实（本文件的断言都建立在它们之上）：
     A. nginx 的 sub_filter **不支持正则**，只能字面量替换。
     B. nginx 的多条 sub_filter 指令是**一次扫描、多规则竞争、配置里
        靠前的优先** —— 既不是「各规则独立作用于原文」，也不是「逐条链式」。
        ⇒ 「先保护再改写再还原」那套（想保护协议相对 URL）走不通。

沙箱运行：只 import app 并打补丁，不碰真实路径、不执行 nft/nginx、不访问外网。
"""
import importlib
import json
import os
import re
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def fresh():
    """独立加载一份 app 模块，避免模块级状态互相污染"""
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    app.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'cfg.json')
    app.LISTS_PATH = os.path.join(tempfile.mkdtemp(), 'lists.json')
    app.RULES_PATH = os.path.join(tempfile.mkdtemp(), 'rules.nft')
    return app


def rule(prefix, **kw):
    r = {"id": "rp_" + prefix.strip('/'), "name": prefix.strip('/'), "enabled": True,
         "path_prefix": prefix, "target_address": "192.168.100.218:8095",
         "target_protocol": "http", "public_access": True,
         "client_max_body_size": "1M", "api_path_prefix": "",
         "websocket_enabled": True}
    r.update(kw)
    return r


def gen_conf(app, rules):
    cfg = {"gateway_enabled": True, "gateway_port": 8443, "auth_api_port": 8444,
           "lan_subnet4": "192.168.100.0/24", "router_ip4": "192.168.100.1",
           "wan_if": "eth1", "lan_if": "br-lan",
           "reverse_proxy": {"rules": rules, "settings": {}, "certificates": []}}
    return app._generate_gateway_nginx_conf(cfg)


# ── nginx sub_filter 行为模拟器 ─────────────────────────────────
#
# 真机实测（nginx:alpine 容器，2026-10-20）确认的模型：
#   **一次扫描整个 body；多个规则竞争同一个匹配点时，用配置里靠前的那条；
#   替换后从替换点之后继续扫。**
#
# 这既不是「各规则独立作用于原文」，也不是「逐条链式 replace」。
# 差别很要紧 —— 链式模型下「先保护再改写再还原」是可行的，
# 真实模型下不可行：三个规则的匹配点是同一个，扫到时只有最靠前那条生效。
#
# 实测对照（原始 HTML: <link href="//cdn/x.css">）：
#   A（保护+还原）        → href="~~P~~cdn/x.css"   保护生效、还原没机会
#   B（只有改写）        → href="/ght//cdn/x.css"   误伤协议相对 URL
#   C（保护+改写+还原）  → 与 B 完全相同            保护被更靠前的改写抢先
#
# 复刻这个模型，才能让单测的结论跟真机一致。
def nginx_sub_filter(text, rules):
    out = []
    p = 0
    n = len(text)
    while p < n:
        best_i, best_pos = -1, -1
        for i, (old, _new) in enumerate(rules):
            j = text.find(old, p)
            if j < 0:
                continue
            if best_i < 0 or j < best_pos or (j == best_pos and i < best_i):
                best_i, best_pos = i, j
        if best_i < 0:
            out.append(text[p:])
            break
        out.append(text[p:best_pos])
        out.append(rules[best_i][1])
        p = best_pos + len(rules[best_i][0])
    return ''.join(out)


# 从生成的 nginx conf 里把 sub_filter 规则抠出来（模拟器需要）
_SUB_FILTER_RE = re.compile(r'^\s*sub_filter\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"\s*;',
                             re.M)


def parse_sub_filters(conf):
    rules = []
    for m in _SUB_FILTER_RE.finditer(conf):
        old = m.group(1).replace('\\"', '"').replace('\\\\', '\\')
        new = m.group(2).replace('\\"', '"').replace('\\\\', '\\')
        rules.append((old, new))
    return rules


# ── proxy_redirect 行为模拟器 ─────────────────────────────────
#
# nginx 的 proxy_redirect：多条规则里**第一条匹配上的生效**，
# 一条都匹配不上就**原样返回** Location。
# 替换串里 $1/$2… 是正则捕获组，$scheme / $host 是 nginx 变量。
#
# 为什么必须模拟：真机实测（2026-10-20）证明「匹配任意 host」的写法
# 会把外站跳转劫持到网关自己 —— 这在单元测试里只看生成文本是发现不了的，
# 必须真的拿 Location 值过一遍规则。
_PROXY_REDIRECT_RE = re.compile(r'^\s*proxy_redirect\s+~(\S+)\s+(\S+);', re.M)


def parse_proxy_redirects(conf):
    return [(m.group(1), m.group(2)) for m in _PROXY_REDIRECT_RE.finditer(conf)]


def apply_proxy_redirect(location, rules, scheme='https', host='gw.example'):
    """模拟 nginx 的 proxy_redirect：按顺序找第一条匹配的规则。"""
    for pat, rep in rules:
        m = re.match(pat, location)
        if not m:
            continue
        out = rep
        for i in range(1, (m.re.groups or 0) + 1):
            out = out.replace('$' + str(i), m.group(i) or '')
        out = out.replace('$scheme', scheme).replace('$host', host)
        return out
    return location


def main():
    app = fresh()

    print('=== 1. nginx sub_filter 行为模拟器必须复刻真机 ===')
    SL = '/' * 2
    html = ('<link href="/a.css">\n'
            '<link href="' + SL + 'cdn/x.css">\n'
            '<script>var s = "' + SL + 'zz";</script>\n')
    A = [('="' + SL, '="~~P~~'), ('="~~P~~', '="' + SL)]
    B = [('href="/', 'href="/ght/')]
    C = A[:1] + B + A[1:]
    check('模型 A：保护生效、还原没机会',
          nginx_sub_filter(html, A).count('~~P~~cdn') == 1
          and '="//cdn' not in nginx_sub_filter(html, A),
          repr(nginx_sub_filter(html, A).splitlines()[1]))
    check('模型 B：协议相对 URL 被误伤（这就是宽模式的边界）',
          '/ght//cdn/x.css' in nginx_sub_filter(html, B))
    check('模型 C：与 B 完全相同（保护被更靠前的改写抢先）',
          nginx_sub_filter(html, C) == nginx_sub_filter(html, B))
    check('模型：JS 里的普通字符串不受影响',
          'var s = "' + SL + 'zz";' in nginx_sub_filter(html, C))

    print()
    print('=== 2. 宽模式（rewrite_root_paths）把根绝对路径改写回前缀 ===')
    conf = gen_conf(app, [rule('/ght', rewrite_root_paths=True)])
    check('开关打开时生成了 sub_filter', 'sub_filter ' in conf)
    sf = parse_sub_filters(conf)
    check('恰好三条（href/src/action）', len(sf) == 3, str(sf))
    page = ('<link rel="stylesheet" href="/static/style.css">\n'
            '<script src="/app.js"></script>\n'
            '<form action="/submit"></form>\n'
            '<a href="/b/daily">日榜</a>\n'
            '<a href="/">总览</a>\n'
            '<link rel="stylesheet" href="css/rel.css">\n')
    out = nginx_sub_filter(page, sf)
    check('CSS 链接带上前缀', 'href="/ght/static/style.css"' in out, out.splitlines()[0])
    check('脚本 src 带上前缀', 'src="/ght/app.js"' in out)
    check('表单 action 带上前缀', 'action="/ght/submit"' in out)
    check('页面链接带上前缀', 'href="/ght/b/daily"' in out)
    check('首页链接 href="/" 变成 href="/ght/"', 'href="/ght/"' in out)
    check('相对路径原样保留（不被误伤）',
          'href="css/rel.css"' in out and 'href="/ght/css/rel.css"' not in out)

    print()
    print('=== 3. 窄模式（api_path_prefix）的既有输出逐字不变 ===')
    conf_old = gen_conf(app, [rule('/logce', api_path_prefix='/api/')])
    check("窄模式仍是 sub_filter \"'/api/\" \"'/logce/api/\"",
          'sub_filter "\'/api/" "\'/logce/api/";' in conf_old)
    check('窄模式仍是双引号形式',
          'sub_filter "\\"/api/" "\\"/logce/api/";' in conf_old)
    check('Accept-Encoding 只出现一次',
          conf_old.count('proxy_set_header Accept-Encoding "";') == 1)

    print()
    print('=== 4. 两种模式同开时互不干扰 ===')
    conf_both = gen_conf(app, [rule('/x', api_path_prefix='/api/',
                                     rewrite_root_paths=True)])
    sf_both = parse_sub_filters(conf_both)
    check('共五条（2 窄 + 3 宽）', len(sf_both) == 5, str(len(sf_both)))
    check('Accept-Encoding 仍然只出现一次',
          conf_both.count('proxy_set_header Accept-Encoding "";') == 1)
    out_both = nginx_sub_filter(page, sf_both)
    check('宽模式照常生效', 'href="/x/static/style.css"' in out_both)
    check('窄模式照常生效',
          "'/x/api/" in nginx_sub_filter("fetch('/api/tick')", sf_both))

    print()
    print('=== 5. 开关关闭时不得有任何 sub_filter ===')
    conf_off = gen_conf(app, [rule('/y')])
    check('默认不生成 sub_filter', 'sub_filter ' not in conf_off)
    check('但 proxy_redirect 仍在（302 跳转是路径前缀方案的必要配套）',
          'proxy_redirect' in conf_off)

    print()
    print('=== 6. proxy_redirect：修 302 跳转丢前缀，且不许劫持外站 ===')
    conf_r = gen_conf(app, [rule('/siy')])
    pr = parse_proxy_redirects(conf_r)
    check('生成了相对 Location 的改写',
          'proxy_redirect ~^/(?!siy/)(.*)$ /siy/$1;' in conf_r,
          [l for l in conf_r.splitlines() if 'proxy_redirect' in l][0].strip())
    check('生成了上游自身 host 的绝对 URL 改写',
          'proxy_redirect ~^https?://192\\.168\\.100\\.218(?::[0-9]+)?'
          '/(?!siy/)(.*)$ $scheme://$host:8443/siy/$1;' in conf_r,
          [l.strip() for l in conf_r.splitlines() if 'proxy_redirect' in l][-1])
    check('负向先行断言防止重复加前缀',
          '(?!siy/)' in conf_r)
    check('断言里**不能**带开头的斜杠（否则恒成立，已带前缀的会被重复加前缀）',
          '(?!/siy/)' not in conf_r,
          [l.strip() for l in conf_r.splitlines() if 'proxy_redirect' in l])
    check('端口用非捕获组（捕获组会让 $1 取到端口而不是路径）',
          '(?::[0-9]+)?' in conf_r and '(:[0-9]+)?' not in conf_r)
    check('**不得**出现「匹配任意 host」的那条规则（会劫持外站跳转）',
          '~^https?://[^/]+/' not in conf_r,
          [l.strip() for l in conf_r.splitlines() if 'proxy_redirect' in l])

    # 真机实测过的四种 Location 形态，逐个过一遍规则
    check('① 相对 Location 补上前缀',
          apply_proxy_redirect('/check-auth?to=%2F', pr) == '/siy/check-auth?to=%2F',
          apply_proxy_redirect('/check-auth?to=%2F', pr))
    check('② 上游自身 host 的绝对 URL：host 换成对外地址并补前缀',
          apply_proxy_redirect('http://192.168.100.218:8095/check-auth', pr)
          == 'https://gw.example:8443/siy/check-auth',
          apply_proxy_redirect('http://192.168.100.218:8095/check-auth', pr))
    check('② 上游 host 不带端口也认',
          apply_proxy_redirect('http://192.168.100.218/check-auth', pr)
          == 'https://gw.example:8443/siy/check-auth',
          apply_proxy_redirect('http://192.168.100.218/check-auth', pr))
    check('③ **外站绝对 URL 原样放过**（不许劫持到网关自己）',
          apply_proxy_redirect('https://external.example.com/page', pr)
          == 'https://external.example.com/page',
          apply_proxy_redirect('https://external.example.com/page', pr))
    check('③ 相对 Location 一律补前缀（相对形态无法区分指向谁，按设计如此）',
          apply_proxy_redirect('/oauth/callback', pr) == '/siy/oauth/callback',
          apply_proxy_redirect('/oauth/callback', pr))
    check('④ 已经带前缀的 Location 不会被重复加前缀',
          apply_proxy_redirect('/siy/check-auth', pr) == '/siy/check-auth',
          apply_proxy_redirect('/siy/check-auth', pr))
    check('④ 网关自己 host 的绝对 URL 原样放过（已知取舍，见报告）',
          apply_proxy_redirect('https://gw.example/check-auth', pr)
          == 'https://gw.example/check-auth',
          'nginx 的 proxy_redirect 正则不支持变量，无法只匹配「自己的 host」')

    print()
    print('=== 7. 非法开关值必须安全降级 ===')
    for bad in ('yes-please', 1, [], {}, None, 'true'):
        c = gen_conf(app, [rule('/z', rewrite_root_paths=bad)])
        # 只有 Python 的 True / 1 才算开；字符串 'true' 不算
        if bad == 1:
            check(f'非法值 {bad!r}：整数 1 按开启处理',
                  'sub_filter "href=' in c)
        else:
            check(f'非法值 {bad!r}：降级为不改写',
                  'sub_filter ' not in c)

    print()
    print('=== 8. 字段清洗 ===')
    clean, err = app._validate_rp_service(
        {"name": "ght", "path_prefix": "/ght",
         "target_address": "192.168.100.218:8095", "rewrite_root_paths": True},
        existing={}, all_rules=[])
    check('合法值 True 被接受', err is None and clean.get('rewrite_root_paths') is True)
    clean2, err2 = app._validate_rp_service(
        {"name": "ght", "path_prefix": "/ght",
         "target_address": "192.168.100.218:8095", "rewrite_root_paths": "nope"},
        existing={}, all_rules=[])
    check('非法值降级为 False（不报错，不影响整条规则）',
          err2 is None and clean2.get('rewrite_root_paths') is False)
    clean3, err3 = app._validate_rp_service(
        {"name": "ght", "path_prefix": "/ght",
         "target_address": "192.168.100.218:8095"},
        existing={}, all_rules=[])
    check('缺省为 False', err3 is None and clean3.get('rewrite_root_paths') is False)

    print()
    print('=== 9. 生成期辅助函数 ===')
    check('_nginx_regex_literal 接受正常前缀',
          app._nginx_regex_literal('/ght') == '/ght')
    for bad in ('/gh(t)', '/a b', '/a;b', '/a$b', '', None, '/a"b'):
        check(f'_nginx_regex_literal 拒绝 {bad!r}',
              app._nginx_regex_literal(bad) is None)
    check('_nginx_dquote 转义双引号',
          app._nginx_dquote('href="/') == 'href=\\"/')
    check('_nginx_dquote 转义反斜杠',
          app._nginx_dquote('a\\b') == 'a\\\\b')
    # 主机名字面量：点的转义是**安全相关**的 —— 不转义的话
    # 192.168.100.218 里的 '.' 是正则的「任意字符」，
    # 匹配面会被悄悄放大到 192x168x100x218 这种不存在的主机。
    check('_nginx_host_literal 把点转义',
          app._nginx_host_literal('192.168.100.218') == '192\\.168\\.100\\.218',
          repr(app._nginx_host_literal('192.168.100.218')))
    check('_nginx_host_literal 接受普通域名',
          app._nginx_host_literal('ght.internal') == 'ght\\.internal')
    for bad in ('a b', 'a;b', 'a$b', 'a/b', '', None, 'a|b', 'a(b)'):
        check(f'_nginx_host_literal 拒绝 {bad!r}',
              app._nginx_host_literal(bad) is None)

    print()
    print('=== 10. 协议相对 URL 预检 ===')
    # 起一个本地 HTTP server，返回带协议相对 URL 的页面
    body = ('<link href="/a.css">\n'
            '<link href="' + SL + 'cdn/x.css">\n'
            '<script src="' + SL + 'y.js"></script>\n')

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            b = body.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass

    srv = HTTPServer(('127.0.0.1', 0), H)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        cnt, samples, err = app._detect_upstream_protocol_relative(
            '127.0.0.1', port, 'http')
        check('检测到协议相对 URL', err is None and cnt == 2, f'count={cnt} err={err}')
        check('样本里能看到 href 形态',
              any('href=' in s for s in samples), str(samples))
        cnt2, _, err2 = app._detect_upstream_protocol_relative(
            '127.0.0.1', 1, 'http', timeout=0.5)
        check('连不上时如实报错，不假装干净', err2 is not None, str(err2))
    finally:
        srv.shutdown()

    print()
    print('=== 11. 接线回归：磁盘配置 → load_config → 生成器 ===')
    # 这一节是 2026-10-20 真机验证逼出来的。
    #
    # 背景：单元测试全部通过、变异测试全捕，但 .166 真机上开关怎么都不生效。
    # 根因是 _migrate_rp_rules —— 它是**字段白名单**，漏列的键被无声丢弃；
    # 而它被 load_config() 和 _deploy_all_rules() 各调一次。
    # 于是：校验通过 → 存盘成功 → 但生成器读到的是迁移后的规则，开关已抹掉。
    #
    # 前面 1~10 节测的都是**单个环节**（清洗 / 生成 / 辅助函数），
    # 唯独没测「这些环节串起来」—— 这类缺陷必须靠端到端接线测试兜住。
    disk_cfg = {
        "gateway_enabled": True,
        "gateway_port": 8443,
        "auth_api_port": 8444,
        "lan_subnet4": "192.168.100.0/24",
        "router_ip4": "192.168.100.1",
        "wan_if": "eth1",
        "lan_if": "br-lan",
        "reverse_proxy": {
            "rules": [{
                "id": "rp_ght", "name": "ght", "enabled": True,
                "path_prefix": "/ght", "target_address": "192.168.100.218:8095",
                "target_protocol": "http", "public_access": True,
                "client_max_body_size": "1M", "api_path_prefix": "",
                "rewrite_root_paths": True, "websocket_enabled": True,
                "icon": "", "updated_at": "2026-10-20T19:00:00+08:00",
            }],
            "settings": {}, "certificates": [],
        },
    }
    with open(app.CONFIG_PATH, 'w') as f:
        json.dump(disk_cfg, f, ensure_ascii=False)
    loaded = app.load_config()
    loaded_rules = loaded["reverse_proxy"]["rules"]
    check('读盘后规则仍在', len(loaded_rules) == 1, str(len(loaded_rules)))
    check('读盘后 rewrite_root_paths 没被迁移抹掉',
          loaded_rules[0].get('rewrite_root_paths') is True,
          repr(loaded_rules[0].get('rewrite_root_paths')))
    conf_loaded = app._generate_gateway_nginx_conf(loaded)
    check('读盘→生成 这条链路上确实产出了 sub_filter',
          'sub_filter "href=' in conf_loaded,
          [l.strip() for l in conf_loaded.splitlines() if 'sub_filter' in l][:1])

    # 迁移后的规则仍然要能直接喂给生成器（_deploy_all_rules 拿到的是迁移结果）
    migrated_cfg = {"gateway_enabled": True, "gateway_port": 8443,
                    "auth_api_port": 8444, "lan_subnet4": "192.168.100.0/24",
                    "router_ip4": "192.168.100.1", "wan_if": "eth1",
                    "lan_if": "br-lan",
                    "reverse_proxy": {"rules": loaded_rules, "settings": {},
                                      "certificates": []}}
    conf_migrated = app._generate_gateway_nginx_conf(migrated_cfg)
    check('迁移后的规则喂给生成器仍产出 sub_filter',
          'sub_filter "href=' in conf_migrated)

    print()
    print('=== 12. 白名单契约：新增字段不许被迁移吃掉 ===')
    # 通用防线：_validate_rp_service 产出的每一个字段，都必须能活过
    # _migrate_rp_rules。以后再加字段忘了加白名单，这里立刻红。
    full_clean, err_f = app._validate_rp_service(
        {"name": "ght", "path_prefix": "/ght",
         "target_address": "192.168.100.218:8095",
         "rewrite_root_paths": True, "api_path_prefix": "/api/"},
        existing={}, all_rules=[])
    check('校验通过', err_f is None, str(err_f))
    probe = {"reverse_proxy": {"rules": [{**full_clean, "id": "rp_probe"}]}}
    app._migrate_rp_rules(probe)
    migrated_keys = set(probe["reverse_proxy"]["rules"][0].keys())
    lost = sorted(set(full_clean.keys()) - migrated_keys)
    check('迁移白名单不丢任何字段', not lost, '丢失: ' + str(lost))
    check('迁移后 rewrite_root_paths 仍为 True',
          probe["reverse_proxy"]["rules"][0].get('rewrite_root_paths') is True)

    print()
    print('=' * 60)
    print(f'合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        for f in FAIL:
            print('  ❌ ' + f)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
