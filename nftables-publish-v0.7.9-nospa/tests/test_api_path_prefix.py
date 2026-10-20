"""上游绝对 API 路径前缀（sub_filter 窄模式）的回归测试。

运行:  python3 tests/test_api_path_prefix.py

背景（2026-10-20 修复）：
   经网关反代 logcenter 时，页面能打开但所有 /api/* 接口 404。
   根因是 logcenter 页面里写死了绝对路径 '/api/search/html'，
   而网关按 path 前缀（/logcenter/）分发，/api/xxx 匹配不到任何
   location → nginx 内置 404。

   修法：在网关上用 nginx sub_filter 把「上游自己声明的那一段前缀」
   改写成带网关前缀的版本。

   为什么必须是**窄模式**：
   通用规则（任何根绝对路径都加前缀）实测会把页面里普通的路径字符串
   （'/var/log/syslog'、'/etc/nginx/nginx.conf'）也一起改掉，直接改坏应用。
   窄模式只替换用户明确填写的那一段，失败模式是「没改写 → 404（跟改之前
   一样）」，绝不会比不装更糟。

   为什么靠 openapi.json 探测而不是扫 HTML：
   扫 HTML 只能靠猜「哪些绝对路径是 API 前缀」，猜宽了就是上面那个通用
   规则的坑。openapi.json 是上游自己声明的路由表，读它没有猜测成分。

沙箱运行：只 import app 并打补丁，不碰真实路径、不执行 nft/nginx、
不访问外网（探测用本地临时 HTTP server）。
"""
import importlib
import json
import os
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


def fresh(cfg=True):
    """独立加载一份 app 模块，避免模块级状态互相污染"""
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    if cfg:
        app.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'cfg.json')
        app.LISTS_PATH = os.path.join(tempfile.mkdtemp(), 'lists.json')
        app.RULES_PATH = os.path.join(tempfile.mkdtemp(), 'rules.nft')
    return app


def base_cfg():
    return json.loads(json.dumps(importlib.import_module('app').DEFAULT_CONFIG))


def sec(title):
    print(f'\n=== {title} ===')


# ─────────────────────────────────────────────────────────────
sec('1  _sanitize_api_path_prefix —— 规整与拒绝')

app = fresh()

# 空值合法：绝大多数服务不需要改写，「清空这个字段」是正常操作
check('空串是合法的（= 不做改写）', app._sanitize_api_path_prefix('') == '')
check('None 是合法的（= 不做改写）', app._sanitize_api_path_prefix(None) == '')
check('全空白是合法的（= 不做改写）', app._sanitize_api_path_prefix('   ') == '')

# 规范化：统一补上尾斜杠
check("'/api' → '/api/'", app._sanitize_api_path_prefix('/api') == '/api/')
check("'/api/' → '/api/'（幂等）", app._sanitize_api_path_prefix('/api/') == '/api/')
check("'/api/v1' → '/api/v1/'", app._sanitize_api_path_prefix('/api/v1') == '/api/v1/')
check("'/api/v1/' → '/api/v1/'", app._sanitize_api_path_prefix('/api/v1/') == '/api/v1/')
check("两侧空白被裁掉", app._sanitize_api_path_prefix('  /api/  ') == '/api/')

# 拒绝：这些值一旦进 nginx 配置就是注入或误伤
BAD = [
    ('api', '不以 / 开头'),
    ('/', '就是根路径（= 通用规则，必须拒）'),
    ('/api//x', '含 //'),
    ('/api/../x', '含 ..'),
    ('/api/..', '含 ..'),
    ('/api x', '含空格'),
    ('/api/*', '含通配符'),
    ('*', '纯通配符'),
    ('/api/x?y=1', '含查询串'),
    ('/api/x#f', '含锚点'),
    ('/api/x;rm -rf /', '含分号（nginx 指令注入）'),
    ('/api/$uri', '含 nginx 变量'),
    ('/api/"x"', '含双引号（会破坏 sub_filter 引号）'),
    ("/api/'x'", '含单引号（会破坏 sub_filter 引号）'),
    ('/api\\x', '含反斜杠'),
    ('/api/x\nproxy_pass', '含换行（指令注入）'),
]
for val, why in BAD:
    try:
        got = app._sanitize_api_path_prefix(val)
        check(f'拒绝非法值 {val!r}（{why}）', False, f'返回了 {got!r}')
    except ValueError:
        check(f'拒绝非法值 {val!r}（{why}）', True)

# 错误信息要能让人看懂怎么改
try:
    app._sanitize_api_path_prefix('api')
except ValueError as e:
    msg = str(e)
    check('错误信息点明是 API 路径前缀', 'API 路径前缀' in msg, msg[:60])
    check('错误信息给出正确写法示例', '/api/' in msg, msg[:80])

# ─────────────────────────────────────────────────────────────
sec('2  _validate_rp_service —— 接线（不是只看 helper）')

app = fresh()
base = {
    'name': 'logcenter', 'path_prefix': '/logcenter',
    'target_address': '127.0.0.1:5080', 'target_protocol': 'http',
    'enabled': True, 'public_access': True,
}

clean, err = app._validate_rp_service({**base, 'api_path_prefix': '/api/'})
check('合法值被接收', err is None, str(err))
check('clean 里带上 api_path_prefix', (clean or {}).get('api_path_prefix') == '/api/',
      str((clean or {}).get('api_path_prefix')))

clean, err = app._validate_rp_service({**base, 'api_path_prefix': '/api'})
check('值被规范化后写入', (clean or {}).get('api_path_prefix') == '/api/',
      str((clean or {}).get('api_path_prefix')))

clean, err = app._validate_rp_service(base)
check('不传时默认空串（不改写）', err is None and (clean or {}).get('api_path_prefix') == '',
      f"err={err} val={(clean or {}).get('api_path_prefix')!r}")

clean, err = app._validate_rp_service({**base, 'api_path_prefix': '/api//x'})
check('非法值被拒（不是静默丢弃）', clean is None and err is not None, f'clean={clean}')
check('拒绝时给出可读原因', 'API 路径前缀' in (err or ''), (err or '')[:60])

# 关键：非法值不能被「静默变成空串」—— 那等于让用户以为配好了
clean, err = app._validate_rp_service({**base, 'api_path_prefix': '/api/*'})
check('通配符前缀被拒（通用规则的入口）', clean is None, f'clean={clean}')

# 显式空串（用户主动清空）必须放行
clean, err = app._validate_rp_service({**base, 'api_path_prefix': ''})
check('显式清空被放行（正常操作）', err is None, str(err))

# PUT 语义：existing 里的旧值要能被继承
clean, err = app._validate_rp_service(
    {k: v for k, v in base.items() if k != 'api_path_prefix'},
    existing={'id': 'rp_x', 'api_path_prefix': '/api/'})
check('PUT 不传该字段时继承旧值', (clean or {}).get('api_path_prefix') == '/api/',
      str((clean or {}).get('api_path_prefix')))

# ─────────────────────────────────────────────────────────────
sec('3  _migrate_rp_rules —— 迁移时不能丢字段')

app = fresh()
mig = app._migrate_rp_rules({'reverse_proxy': {'rules': [
    {'id': 'rp_1', 'name': 'logcenter', 'path_prefix': '/logcenter',
     'target_address': '127.0.0.1:5080', 'target_protocol': 'http',
     'api_path_prefix': '/api/'}]}})
rules = mig.get('reverse_proxy', {}).get('rules', [])
check('迁移后保留 api_path_prefix',
      len(rules) == 1 and rules[0].get('api_path_prefix') == '/api/',
      str(rules[0].get('api_path_prefix') if rules else 'no rules'))

mig2 = app._migrate_rp_rules({'reverse_proxy': {'rules': [
    {'id': 'rp_2', 'name': 'nas', 'path_prefix': '/nas',
     'target_address': '127.0.0.1:5000', 'target_protocol': 'http'}]}})
r2 = mig2.get('reverse_proxy', {}).get('rules', [])
check('老规则（无该字段）迁移后为空串而不是 KeyError',
      len(r2) == 1 and r2[0].get('api_path_prefix') == '',
      str(r2[0].get('api_path_prefix') if r2 else 'no rules'))

# ─────────────────────────────────────────────────────────────
sec('4  _generate_gateway_nginx_conf —— 生成的 nginx 配置')


def gen_conf(rules):
    a = fresh()
    cfg = {**base_cfg(), 'gateway_enabled': True, 'gateway_port': 8443,
           'reverse_proxy': {'rules': rules, 'certificates': [],
                             'settings': dict(a.RP_DEFAULT_SETTINGS)}}
    return a._generate_gateway_nginx_conf(cfg)


rule_with = {
    'id': 'rp_1', 'name': 'logcenter', 'enabled': True,
    'path_prefix': '/logcenter', 'target_address': '127.0.0.1:5080',
    'target_protocol': 'http', 'public_access': True,
    'client_max_body_size': '', 'api_path_prefix': '/api/',
    'websocket_enabled': True, 'icon': ''}
rule_without = {k: v for k, v in rule_with.items() if k != 'api_path_prefix'}

conf_with = gen_conf([rule_with])
check('填了前缀 → 生成 sub_filter 块', 'sub_filter' in conf_with)
check('sub_filter_once off（页面里多处引用都要改）',
      'sub_filter_once off;' in conf_with)
check('sub_filter_types 只含文本类型（不动 JSON）',
      'sub_filter_types application/javascript text/css;' in conf_with)
# nginx 的 sub_filter_types 默认已含 text/html，重复写会报
# [warn] duplicate MIME type "text/html" —— 每次 nginx -t / reload 都刷一行
check('sub_filter_types 不重复写 text/html（避免 nginx 警告）',
      'sub_filter_types text/html' not in conf_with)
check("单引号形式被改写：'/api/ → '/logcenter/api/",
      """sub_filter "'/api/" "'/logcenter/api/";""" in conf_with)
check('双引号形式被改写："/api/ → "/logcenter/api/',
      'sub_filter "\\"/api/" "\\"/logcenter/api/";' in conf_with)
check('清掉上游压缩（sub_filter 只在明文正文上生效）',
      'proxy_set_header Accept-Encoding "";' in conf_with)

# 反向断言：绝不能出现通用规则
check('不含通用规则 sub_filter "/"，（会把页面里普通路径也改掉）',
      'sub_filter "/"' not in conf_with)
check('不含 sub_filter "/*"（通配符通用规则）',
      'sub_filter "/*"' not in conf_with)
check('不含 sub_filter ".*"（正则通用规则）',
      'sub_filter ".*"' not in conf_with)
# 只允许出现两条 sub_filter（单引号 + 双引号各一条）
n_sub = conf_with.count('sub_filter "')
check('sub_filter 恰好 2 条（单/双引号各一），没有多出来的通用规则',
      n_sub == 2, f'实际 {n_sub} 条')

conf_without = gen_conf([rule_without])
check('没填前缀 → 行为完全不变（向后兼容）',
      'sub_filter' not in conf_without)
check('没填前缀 → 不加 Accept-Encoding 空头（不多余副作用）',
      'proxy_set_header Accept-Encoding "";' not in conf_without)

# 前缀里的特殊字符不能逃出引号
conf_weird = gen_conf([{**rule_with, 'api_path_prefix': '/api/v1/'}])
check('多段前缀也正确改写',
      """sub_filter "'/api/v1/" "'/logcenter/api/v1/";""" in conf_weird)

# ── 生成期二次净化：落盘值不可信 ────────────────────────────────
# 配置文件可能被手工改过。这个值最终要拼进 nginx 的**引号字符串**，
# 带引号/分号/换行的值能逃出引号 → nginx 指令注入。
#
# 注：非法值会被**回显在生成的注释里**（有意为之 —— 让运维看得见
# 「有人填了坏值」）。所以断言不能是「整份配置里不含该字符串」，
# 而必须是「**指令行**里不含该字符串」+「注释里能看到」。
INJECT = '/api/"; evil_directive; #'
conf_inject = gen_conf([{**rule_with, 'api_path_prefix': INJECT}])
sub_lines = [ln for ln in conf_inject.splitlines() if 'sub_filter "' in ln]
check('非法值不会出现在任何 sub_filter 指令里（生成期二次净化）',
      not any('evil_directive' in ln for ln in sub_lines),
      f'实际指令行: {sub_lines}')
check('非法值时该服务仍被生成（不因一个字段放弃整条服务）',
      'location /logcenter/' in conf_inject)
check('非法值时留下说明（运维能看见有人填了坏值）',
      'api_path_prefix 非法' in conf_inject)
check('非法值时原值被回显在注释里（可追溯）',
      'evil_directive' in conf_inject)
check('非法值时不生成任何 sub_filter（退回今天的行为）',
      not sub_lines)
check('非法值时不生成 Accept-Encoding 空头（不多余副作用）',
      'proxy_set_header Accept-Encoding "";' not in conf_inject)

# 换行注入：配置生成必须仍然成功（不能抛异常拖垮整份网关配置）
NL = '/api/\n    return 200;'
conf_nl = gen_conf([{**rule_with, 'api_path_prefix': NL}])
check('带换行的非法值不会让配置生成失败（只跳过改写）',
      'location /logcenter/' in conf_nl
      and not [ln for ln in conf_nl.splitlines() if 'sub_filter "' in ln])
check('带换行的非法值不会把内容写进指令（回显时已转义成单行）',
      'return 200;' not in conf_nl
      or all(ln.strip().startswith('#')
             for ln in conf_nl.splitlines() if 'return 200;' in ln),
      '回显必须落在注释里')

# ─────────────────────────────────────────────────────────────
sec('5  _detect_upstream_api_prefixes —— 读上游自己的路由表')

# 本地起一个假上游，返回固定的 openapi.json
class _Handler(BaseHTTPRequestHandler):
    BODY = b''
    CODE = 200
    CT = 'application/json'

    def do_GET(self):
        self.send_response(self.CODE)
        self.send_header('Content-Type', self.CT)
        self.send_header('Content-Length', str(len(self.BODY)))
        self.end_headers()
        if self.BODY:
            self.wfile.write(self.BODY)

    def log_message(self, *a):
        pass


def start_server(body, code=200, ct='application/json'):
    _Handler.BODY = body
    _Handler.CODE = code
    _Handler.CT = ct
    srv = HTTPServer(('127.0.0.1', 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


srv, port = start_server(json.dumps({
    'openapi': '3.1.0',
    'paths': {
        '/api/search/html': {'get': {}},
        '/api/pinned': {'get': {}},
        '/api/cleanup': {'post': {}},
        '/api/v2/query': {'get': {}},
        '/health': {'get': {}},
        '/': {'get': {}},
    }}).encode())
try:
    app = fresh()
    prefixes, err = app._detect_upstream_api_prefixes('127.0.0.1', port, 'http')
    check('探测成功', err is None, str(err))
    check('提取出 /api/ 这一段前缀', prefixes == ['/api/'], str(prefixes))
    check('单段路径（/health）不算 API 前缀', '/health/' not in prefixes, str(prefixes))
    check('多段路径只取第一段（/api/v2/ → /api/）',
          '/api/v2/' not in prefixes, str(prefixes))
    check('结果带尾斜杠（拼接用）',
          all(p.endswith('/') for p in prefixes), str(prefixes))
finally:
    srv.shutdown()

# 多个前缀时全部返回，由前端/用户挑
srv, port = start_server(json.dumps({
    'paths': {'/api/x': {}, '/admin/y': {}, '/health': {}}}).encode())
try:
    app = fresh()
    prefixes, err = app._detect_upstream_api_prefixes('127.0.0.1', port, 'http')
    check('多个前缀时全部返回（不替用户瞎猜）',
          prefixes == ['/admin/', '/api/'], str(prefixes))
finally:
    srv.shutdown()

# 没有多段路径
srv, port = start_server(json.dumps({'paths': {'/health': {}}}).encode())
try:
    app = fresh()
    prefixes, err = app._detect_upstream_api_prefixes('127.0.0.1', port, 'http')
    check('只有单段路径 → 探测不到前缀', prefixes == [], str(prefixes))
    check('探测不到时给出原因', bool(err), str(err))
finally:
    srv.shutdown()

# 不是 JSON
srv, port = start_server(b'<html>not json</html>', ct='text/html')
try:
    app = fresh()
    prefixes, err = app._detect_upstream_api_prefixes('127.0.0.1', port, 'http')
    check('非 JSON 响应 → 探测不到但不抛异常', prefixes == [], str(prefixes))
    check('非 JSON 时给出原因', bool(err), str(err))
finally:
    srv.shutdown()

# 没有 paths 字段
srv, port = start_server(json.dumps({'info': {'title': 'x'}}).encode())
try:
    app = fresh()
    prefixes, err = app._detect_upstream_api_prefixes('127.0.0.1', port, 'http')
    check('没有 paths 字段 → 探测不到', prefixes == [], str(prefixes))
    check('没有 paths 时给出原因', bool(err), str(err))
finally:
    srv.shutdown()

# 连不上
app = fresh()
prefixes, err = app._detect_upstream_api_prefixes('127.0.0.1', 1, 'http', timeout=1.0)
check('连不上 → 返回空 + 原因，不抛异常', prefixes == [] and bool(err), f'{prefixes} {err}')

# 非法地址
app = fresh()
prefixes, err = app._detect_upstream_api_prefixes('127.0.0.1', 'abc', 'http')
check('非法端口 → 返回空 + 原因', prefixes == [] and bool(err), f'{prefixes} {err}')

# ─────────────────────────────────────────────────────────────
sec('6  POST /api/reverse-proxy/detect-api-prefix —— 端点契约')

app = fresh()
app.app.before_request_funcs[None] = []
app.app.config['TESTING'] = True
cli = app.app.test_client()

srv, port = start_server(json.dumps({
    'paths': {'/api/search/html': {}, '/api/pinned': {}}}).encode())
try:
    r = cli.post('/api/reverse-proxy/detect-api-prefix',
                 json={'target_address': f'127.0.0.1:{port}',
                       'target_protocol': 'http'})
    body = r.get_json() or {}
    check('端点返回 200', r.status_code == 200, str(r.status_code))
    check('顶层有 success=True', body.get('success') is True, str(body)[:120])
    # 关键契约：data 是嵌套的 —— 前端必须读 res.data.prefixes
    check('data 是嵌套对象（不是拍平）', isinstance(body.get('data'), dict), str(body)[:120])
    check('data.prefixes 里有探测结果',
          '/api/' in ((body.get('data') or {}).get('prefixes') or []),
          str((body.get('data') or {}).get('prefixes')))
    check('data.error 为 None（探测成功时）',
          (body.get('data') or {}).get('error') is None,
          str((body.get('data') or {}).get('error')))
finally:
    srv.shutdown()

# 探测失败仍返回 200（这是「探测」，不是「操作」）+ 带原因
r = cli.post('/api/reverse-proxy/detect-api-prefix',
             json={'target_address': '127.0.0.1:1', 'target_protocol': 'http'})
body = r.get_json() or {}
check('探测失败仍返回 200（前端要能读到原因）', r.status_code == 200, str(r.status_code))
check('探测失败时 prefixes 为空数组',
      (body.get('data') or {}).get('prefixes') == [],
      str((body.get('data') or {}).get('prefixes')))
check('探测失败时 error 有内容',
      bool((body.get('data') or {}).get('error')),
      str((body.get('data') or {}).get('error'))[:80])

# 参数校验
r = cli.post('/api/reverse-proxy/detect-api-prefix',
             json={'target_address': '127.0.0.1:5080', 'target_protocol': 'ftp'})
check('非法协议 → 400', r.status_code == 400, str(r.status_code))
check('非法协议时给出原因', bool((r.get_json() or {}).get('message')),
      str((r.get_json() or {}).get('message')))

r = cli.post('/api/reverse-proxy/detect-api-prefix',
             json={'target_address': 'not-an-address', 'target_protocol': 'http'})
check('非法地址 → 400', r.status_code == 400, str(r.status_code))

r = cli.post('/api/reverse-proxy/detect-api-prefix', json={})
check('空 body → 400（不 500）', r.status_code == 400, str(r.status_code))

# 地址里带 scheme 也要能解析
srv, port = start_server(json.dumps({'paths': {'/api/x': {}}}).encode())
try:
    r = cli.post('/api/reverse-proxy/detect-api-prefix',
                 json={'target_address': f'http://127.0.0.1:{port}',
                       'target_protocol': 'http'})
    body = r.get_json() or {}
    check('地址带 scheme 也能探测', r.status_code == 200, str(r.status_code))
    check('带 scheme 时前缀探测正确',
          '/api/' in ((body.get('data') or {}).get('prefixes') or []),
          str((body.get('data') or {}).get('prefixes')))
finally:
    srv.shutdown()

# ─────────────────────────────────────────────────────────────
sec('7  端到端：生成的配置能不能真的把 /api/ 改写掉')

# 纯字符串层面验证：模拟 nginx sub_filter 的字面量替换
def apply_sub_filter(text, api_prefix, gw_prefix):
    """复刻 nginx sub_filter 的行为：把所有出现都替换掉（sub_filter_once off）"""
    return text.replace("'" + api_prefix, "'" + gw_prefix + api_prefix) \
               .replace('"' + api_prefix, '"' + gw_prefix + api_prefix)


HTML = """<html><head><script>
fetch('/api/search/html?since=7d');
fetch("/api/pinned");
const cfg = { logPath: '/var/log/syslog', nginx: '/etc/nginx/nginx.conf' };
</script></head><body>ok</body></html>"""

out = apply_sub_filter(HTML, '/api/', '/logcenter')
check("单引号 '/api/ 被改写", "'/logcenter/api/" in out)
check('双引号 "/api/ 被改写', '"/logcenter/api/' in out)
check('普通路径 /var/log/syslog 未被误伤', "'/var/log/syslog'" in out)
check('普通路径 /etc/nginx/nginx.conf 未被误伤',
      "'/etc/nginx/nginx.conf'" in out)
check('改写后原文里已无裸 /api/ 请求',
      "fetch('/api/" not in out and 'fetch("/api/' not in out)

# 改写后的路径能落回本 location
check('改写后的路径以网关前缀开头（落回本 location）',
      out.count('/logcenter/api/') == 2, out.count('/logcenter/api/'))

# ─────────────────────────────────────────────────────────────
print('\n' + '=' * 70)
print(f'通过 {len(PASS)} / {len(PASS) + len(FAIL)}')
if FAIL:
    print('失败项:')
    for f in FAIL:
        print('  - ' + f)
    sys.exit(1)
print('全部通过')
