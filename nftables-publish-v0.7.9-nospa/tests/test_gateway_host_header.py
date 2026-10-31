"""反代上游 Host 头必须带端口 —— 思源「invalid request origin」的回归测试。

运行:  python3 tests/test_gateway_host_header.py

背景（2026-11-01 真机复现，do:6807 思源 + .232 认证网关）：

    浏览器 → https://siyuan.fzyto.top:8443 → nginx → 思源
        loginAuth                  → 200（拿到 session cookie）
        getConf + cookie + Origin  → 401 {"code":-1,
                                          "msg":"Auth failed: invalid request origin"}

    症状极具迷惑性：**密码页正常显示，输完密码却进不去主界面**，
    前端拿到 401 反复重载，看起来像「思源加载还是有问题」。

根因：上游拿「浏览器发来的 Origin 头」和「自己收到的 Host 头」逐字节比对，
用来挡跨站请求伪造。思源的实现（kernel/util/net.go）：

    func originHostEquals(origin, host string) bool {
        originHost := TrimSuffix(TrimSuffix(u.Host, ":80"), ":443")
        host      := TrimSuffix(TrimSuffix(host,      ":80"), ":443")
        return originHost == host
    }
    // 调用点：IsSessionOriginAllowed(origin, r.Host)

它只剥 :80 / :443，**其余端口必须原样相等**。而面板的 nginx 转发写的是
`proxy_set_header Host $host;` —— $host **不带端口**：

    浏览器 Origin : https://siyuan.fzyto.top:8443
    上游收到 Host : siyuan.fzyto.top
    ⇒ 不相等 ⇒ 401 invalid request origin

修法：`proxy_set_header Host $host:$server_port;`
    · 主机名部分仍是 nginx 校验过的 $host ⇒ 不引入 Host Header Injection
    · 端口部分来自**服务端配置常量** $server_port ⇒ 同样不可被客户端控制

本测试刻意做成**行为级**而不是字符串级：
真的起一个本地 HTTP 服务实现思源那套判定，真的把**生成的 nginx 配置**
里的 Host 表达式按 nginx 语义求值后转发过去 —— 上游收不收，由上游说了算。

沙箱运行：只 import app 并生成配置文本，不碰真实路径、不执行 nft/nginx、
不访问外网。
"""
import importlib
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else ' ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n── {title} ──')


def fresh():
    """独立加载一份 app 模块，避免模块级状态互相污染"""
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    app.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'cfg.json')
    app.LISTS_PATH = os.path.join(tempfile.mkdtemp(), 'lists.json')
    app.RULES_PATH = os.path.join(tempfile.mkdtemp(), 'rules.nft')
    return app


# ── 移植自思源 kernel/util/net.go 的判定 ──────────────────────────
# 逐行照抄思源语义，改成 Python：只剥 :80 / :443，其余端口必须原样相等。
def _trim_port(host, port):
    if host.endswith(port):
        return host[:-len(port)]
    return host


def siyuan_origin_host_equals(origin, host):
    """思源 originHostEquals 的 Python 等价实现。

    返回 True = 上游会放行；False = 上游回 401 invalid request origin。
    """
    if not origin:
        # 思源：未携带 Origin 视为非浏览器客户端，放行
        return True
    u = urlparse(origin)
    origin_host = (u.netloc or '').lower()
    origin_host = _trim_port(origin_host, ':80')
    origin_host = _trim_port(origin_host, ':443')
    host = (host or '').strip().lower()
    host = _trim_port(host, ':80')
    host = _trim_port(host, ':443')
    return bool(origin_host) and origin_host == host


def nginx_eval_host(expr, client_host, server_port):
    """按 nginx 语义求出「转发给上游的 Host 头」。

    $host       —— 客户端 Host 去掉端口、小写（nginx 校验过）
    $http_host  —— 客户端发来的原始 Host 头（含端口，可控）
    $server_port—— 本 server 块实际命中的监听端口（服务端常量）
    $http_port  —— 客户端 Host 里的端口（可控）
    """
    client_host = client_host or ''
    mport = client_host.rsplit(':', 1)[1] if ':' in client_host else '80'
    vals = [
        ('$http_host', client_host.lower()),
        ('$http_port', mport),
        ('$server_port', str(server_port)),
        ('$host', client_host.split(':')[0].lower()),
    ]
    out = expr
    for k, v in vals:
        out = out.replace(k, v)
    return out


# ── 生成的 nginx 配置解析 ─────────────────────────────────────────
def _collect_block(lines, start):
    """从 lines[start]（一行含 '{'）开始收集一个 {...} 块的正文行。

    注释行**不参与花括号计数** —— 注释里出现「location / {」这类字样
    会让深度算错，把整个 server 块截断。
    """
    depth = 0
    out = []
    for ln in lines[start:]:
        out.append(ln)
        s = ln.strip()
        if s.startswith('#'):
            continue
        depth += ln.count('{') - ln.count('}')
        if depth <= 0:
            break
    return out


def all_server_blocks(conf_text):
    """把生成的 nginx conf 拆成若干 server 块

    返回 [{'name': server_name, 'port': listen 端口, 'body': 块内所有行}, ...]
    """
    lines = conf_text.splitlines()
    blocks = []
    for i, ln in enumerate(lines):
        if ln.strip() != 'server {':
            continue
        body = _collect_block(lines, i)
        name = ''
        for b in body:
            m = b.strip()
            if m.startswith('server_name '):
                name = m[len('server_name '):].rstrip(';')
                break
        port = None
        for b in body:
            m = b.strip()
            if m.startswith('listen ') and 'ssl' in m:
                port = m.split()[1].rstrip(';').split(':')[-1]
                break
        blocks.append({'name': name, 'port': port, 'body': body})
    return blocks


def location_host_expr(body, loc_path):
    """从 server 块正文里取出某个 location 的 Host 转发表达式"""
    lines = body
    for i, ln in enumerate(lines):
        if ln.strip() == f'location {loc_path} {{':
            blk = _collect_block(lines, i)
            for b in blk:
                m = b.strip()
                if m.startswith('proxy_set_header Host '):
                    return m[len('proxy_set_header Host '):].rstrip(';')
    return None


# ── 假的上游：实现思源那套 origin 判定 ────────────────────────────
class _UpstreamHandler(BaseHTTPRequestHandler):
    """收到请求就按思源的规则判定 Origin / Host 是否自洽"""

    def log_message(self, *a):
        pass

    def do_POST(self):
        origin = self.headers.get('Origin', '')
        host = self.headers.get('Host', '')
        if not siyuan_origin_host_equals(origin, host):
            body = json.dumps({"code": -1,
                               "msg": "Auth failed: invalid request origin"}).encode()
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({"code": 0, "msg": ""}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST


def _start_upstream():
    srv = HTTPServer(('127.0.0.1', 0), _UpstreamHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


def _post_upstream(port, origin, upstream_host):
    """按 nginx 的行为把请求转给上游：Host 头 = 表达式求值结果"""
    import http.client
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    h = {'Content-Type': 'application/json'}
    if origin is not None:
        h['Origin'] = origin
    if upstream_host is not None:
        h['Host'] = upstream_host
    c.request('POST', '/api/system/getConf', body=b'{}', headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data.decode('utf-8', 'replace')


def build_config(app, gw_port=8443, rp_host='siyuan.fzyto.top'):
    return {
        'gateway_enabled': True,
        'gateway_port': gw_port,
        'auth_api_port': 8444,
        'lan_subnet4': '192.168.0.0/16',
        'reverse_proxy': {
            'settings': {},
            'certificates': [],
            'rules': [{
                'id': 'rp_001', 'name': '思源-测试', 'enabled': True,
                'path_prefix': '/siyuan', 'host': rp_host,
                'target_address': '192.168.100.218:6807',
                'target_protocol': 'http',
                'public_access': False, 'websocket_enabled': True,
            }],
        },
    }


def main():
    app = fresh()

    sec('① 生成的配置里，反代上游的 Host 转发')
    conf = app._generate_gateway_nginx_conf(build_config(app))
    check('网关配置生成成功', isinstance(conf, str) and len(conf) > 0)

    blocks = all_server_blocks(conf)
    host_block = next((b for b in blocks if b['name'] == 'siyuan.fzyto.top'), None)
    path_block = next((b for b in blocks
                       if location_host_expr(b['body'], '/siyuan/')), None)
    check('找到了 host 分发的 server 块', host_block is not None,
          f'name={host_block and host_block["name"]!r}')
    check('server 块监听的是网关端口 8443',
          host_block and host_block['port'] == '8443',
          f'port={host_block and host_block["port"]!r}')
    check('path 前缀入口在主 server 块里', path_block is not None)

    expr_host = location_host_expr(host_block['body'], '/') if host_block else None
    expr_host_path = (location_host_expr(path_block['body'], '/siyuan/')
                      if path_block else None)
    check('host 入口（域名根路径）的 Host 转发存在', expr_host is not None,
          f'expr={expr_host!r}')
    check('path 入口（/siyuan/）的 Host 转发存在', expr_host_path is not None,
          f'expr={expr_host_path!r}')
    check('两种入口用的是同一个表达式（否则 path 入口仍然是坏的）',
          expr_host == expr_host_path, f'{expr_host!r} vs {expr_host_path!r}')

    sec('② 安全性：不能用客户端可控的原始 Host 头')
    check('Host 转发不含 $http_host（防 Host Header Injection）',
          '$http_host' not in (expr_host or ''), f'expr={expr_host!r}')
    check('Host 转发不含 $http_port（端口必须来自服务端常量）',
          '$http_port' not in (expr_host or ''), f'expr={expr_host!r}')
    check('端口由服务端常量 $server_port 提供',
          '$server_port' in (expr_host or ''), f'expr={expr_host!r}')

    xfh = None
    for ln in conf.splitlines():
        if 'proxy_set_header X-Forwarded-Host ' in ln:
            xfh = ln.strip().split('X-Forwarded-Host ')[1].rstrip(';')
            break
    check('X-Forwarded-Host 也带端口（上游拼绝对 URL 才指得对）',
          xfh is not None and '$server_port' in xfh, f'expr={xfh!r}')

    sec('③ 行为级：上游（思源那套判定）收不收？')
    srv, up_port = _start_upstream()
    try:
        client_host = 'siyuan.fzyto.top:8443'
        origin = 'https://siyuan.fzyto.top:8443'

        # 按生成的表达式求值，模拟 nginx 转发给上游的 Host
        upstream_host = nginx_eval_host(expr_host, client_host, host_block['port'])
        check('求值出的上游 Host 与浏览器 Origin 自洽',
              siyuan_origin_host_equals(origin, upstream_host),
              f'host={upstream_host!r} origin={origin!r}')

        st, body_txt = _post_upstream(up_port, origin, upstream_host)
        check('上游接受请求（不报 invalid request origin）',
              st == 200, f'status={st} body={body_txt[:120]}')

        # 对照组：退回旧写法（$host，丢端口）必须被上游拒绝 ——
        # 这条断言保证「判定逻辑」本身是有效的，不是恒真。
        old_host = nginx_eval_host('$host', client_host, host_block['port'])
        check('对照组：旧写法（丢端口）会被上游拒绝',
              not siyuan_origin_host_equals(origin, old_host),
              f'host={old_host!r}')
        st_old, body_old = _post_upstream(up_port, origin, old_host)
        check('对照组：旧写法真的收到 401 invalid request origin',
              st_old == 401 and 'invalid request origin' in body_old,
              f'status={st_old} body={body_old[:120]}')

        # IP 直连（用户现场的用法）：客户端 Host 是 IP:端口
        ip_origin = 'https://192.168.100.1:8443'
        ip_host = nginx_eval_host(expr_host, '192.168.100.1:8443',
                                  host_block['port'])
        check('IP 直连时同样自洽',
              siyuan_origin_host_equals(ip_origin, ip_host),
              f'host={ip_host!r} origin={ip_origin!r}')

        # 端口是 443 时：思源会剥掉 :443，仍然必须相等
        conf443 = app._generate_gateway_nginx_conf(
            build_config(app, gw_port=443))
        b443 = next((b for b in all_server_blocks(conf443)
                     if b['name'] == 'siyuan.fzyto.top'), None)
        e443 = location_host_expr(b443['body'], '/') if b443 else None
        h443 = nginx_eval_host(e443, 'siyuan.fzyto.top', b443['port'] if b443 else 443)
        check('网关跑在 443 时也自洽（思源会剥掉 :443）',
              siyuan_origin_host_equals('https://siyuan.fzyto.top', h443),
              f'host={h443!r}')

        # 端口必须跟着网关端口走，不能写死
        conf9000 = app._generate_gateway_nginx_conf(
            build_config(app, gw_port=9000))
        b9000 = next((b for b in all_server_blocks(conf9000)
                      if b['name'] == 'siyuan.fzyto.top'), None)
        e9000 = location_host_expr(b9000['body'], '/') if b9000 else None
        h9000 = nginx_eval_host(e9000, 'siyuan.fzyto.top:9000',
                                b9000['port'] if b9000 else 9000)
        check('网关换端口后，Host 里的端口跟着变（不是写死的）',
              h9000 == 'siyuan.fzyto.top:9000', f'host={h9000!r}')
    finally:
        srv.shutdown()

    print('\n' + '=' * 66)
    print(f' 合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        print(' 有失败:')
        for f in FAIL:
            print('   - ' + f)
    else:
        print(' 全部通过')
    print('=' * 66)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
