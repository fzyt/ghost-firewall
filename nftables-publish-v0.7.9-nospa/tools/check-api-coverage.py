"""前后端接口覆盖度比对 —— 功能性审查的横切视角。

找出三类问题：
  1. 后端有路由、前端从不调用  -> 死接口（功能做了但用户碰不到）
  2. 前端调用、后端没有路由    -> 死调用（点了会 404）
  3. 两侧都有但参数/方法不匹配 -> 隐性断裂
"""
import os
import re
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'backend', 'app.py')
AUTH = os.path.join(ROOT, 'backend', 'auth_gateway.py')
FE_JS = os.path.join(ROOT, 'frontend', 'app.js')
FE_HTML = os.path.join(ROOT, 'frontend', 'index.html')

src_app = open(APP, encoding='utf-8').read()
src_auth = open(AUTH, encoding='utf-8').read()
src_fe = open(FE_JS, encoding='utf-8').read() + open(FE_HTML, encoding='utf-8').read()


def norm(p):
    """把 <rule_id> / ${id} / 拼接出来的尾段 归一成 :id，并剥掉查询串。"""
    p = p.split('?')[0].split('#')[0]          # 查询串不是路径的一部分
    p = re.sub(r'<[a-z_]+>', ':id', p)
    p = re.sub(r'\$\{[^}]+\}', ':id', p)
    p = re.sub(r'<path:[a-z_]+>', ':file', p)
    p = re.sub(r'/+', '/', p)
    return p.rstrip('/') or '/'


# 后端路由。
# ⚠️ 必须同时匹配单引号和双引号：仓库里两种写法都有
#    （例如 /api/logd/config 用双引号），只认单引号会漏掉一批路由，
#    漏掉的会被判成「前端调用了但后端没有」—— 假结论比没结论更糟。
routes = {}
for src, tag in ((src_app, 'app'), (src_auth, 'auth')):
    for m in re.finditer(
            r"@app\.route\(\s*(['\"])([^'\"]+)\1\s*"
            r"(?:,\s*methods=\[([^\]]*)\])?", src):
        path, methods = m.group(2), m.group(3) or 'GET'
        ms = {x.strip().strip("'\"") for x in methods.split(',') if x.strip()}
        ms.add('GET')      # Flask 默认
        for meth in ms:
            routes.setdefault(norm(path), set()).add(meth.upper())

def first_arg(src, i):
    """从实参列表起点 i 起取出第一个实参的原文，正确处理引号与嵌套。

    正则抓不住拼接形式：`fetch('/api/x/' + c.id + '/renew', {...})` 里，
    字符类 [^`'"]* 会在第一个闭合引号处停下，于是 URL 被截成 '/api/x/'，
    后面那段 '/renew' 整个丢失 —— 凭空白造出一批「前端调了但后端没有」的假结论。
    """
    depth = 0
    quote = None
    j = i
    while j < len(src):
        c = src[j]
        if quote:
            if c == '\\':
                j += 2
                continue
            if c == quote:
                quote = None
        elif c in '`"\'':
            quote = c
        elif c in '([{':
            depth += 1
        elif c in ')]}':
            if depth == 0:
                return src[i:j], j          # 实参列表结束
            depth -= 1
        elif c == ',' and depth == 0:
            return src[i:j], j              # 第一个实参结束
        j += 1
    return src[i:j], j


def arg_to_path(arg):
    """把实参表达式归一成路径：拼接的变量段 → :id。"""
    parts = [p.strip() for p in arg.split('+')]
    out = ''
    for p in parts:
        if len(p) >= 2 and p[0] in '`"\'' and p[-1] == p[0]:
            out += p[1:-1]
        elif p.startswith('`') and p.endswith('`'):
            out += p[1:-1]
        elif out.endswith('/'):
            out += ':id'                    # 中间变量段：'/a/' + id + '/b'
    return out


# 前端调用。两种写法都要抓：
#   api.get('/api/x')                /  api.delete('/api/x/' + rule.id)
#   fetch('/api/x', {method:'POST'}) ← multipart 上传走的是裸 fetch
# ⚠️ 只抓 api.* 会把整条证书上传链路误判成「后端有路由但前端从不调用」——
#    假阳性比漏报更糟，它会让人去删一个其实在用的接口。
calls = defaultdict(set)
for m in re.finditer(r"(?:api\.(get|post|put|delete)|fetch)\(\s*", src_fe):
    tail = src_fe[m.end():]
    if m.group(1) is None:          # 匹配到的是裸 fetch，方法在 options 里
        mm = re.search(r"method\s*:\s*['\"]([A-Za-z]+)['\"]", tail[:300])
        meth = mm.group(1).upper() if mm else 'GET'
    else:
        meth = m.group(1).upper()
    arg, _ = first_arg(src_fe, m.end())
    path = arg_to_path(arg)
    if '${' in path:
        path = re.sub(r'\$\{[^}]+\}', ':id', path)
    if path.startswith('`') and '${' in path:      # 模板字符串：'/a/${id}/b'
        path = re.sub(r'\$\{[^}]+\}', ':id', path)
    if path.count('/') < 2:
        continue
    calls[norm(path)].add(meth)

print('═' * 62)
print(f'后端路由 {len(routes)} 条 · 前端调用点 {len(calls)} 条')
print('═' * 62)

orphan = []
for p, ms in sorted(calls.items()):
    if p not in routes:
        orphan.append((p, ms))

# 「后端有、前端不调」不等于「缺 UI」。有几类端点本来就不该有界面，
# 把它们和真缺口混在一张清单里报出来，久而久之整份报告就没人看了 ——
# 假阳性比漏报更糟，它会让人去给一个刻意不做的功能编个界面。
#
# 三类：
#   1. 静态文件路由       —— nginx/Flask 直接给浏览器，不是 API
#   2. 脚本下载端点       —— 给外部 crontab / shell 用 URL 取，界面没意义
#   3. 给外部客户端用的   —— 刻意匿名或半匿名，且要求内网来源
#   4. 已废弃但保留的     —— 保留是为了不打断可能存在的 curl 调用方
INTENTIONAL_NO_UI = {
    '/:file': '静态文件路由，不是 API',
    '/api/firewall/china-ips-script': '脚本下载端点，供外部 crontab 取用',
    '/api/scripts/update-ipv6.sh': '脚本下载端点，供外部 crontab 取用',
    '/api/knock-info': '供 LAN 内客户端脚本读敲门端口，刻意无面板入口',
    '/api/rules/save': '已废弃，转发到 /api/rules/apply；保留是为了不打断 curl 调用方',
}

dead = []
intentional = []
for p, ms in sorted(routes.items()):
    if p.startswith('/auth') or p in ('/', '/_auth'):
        continue          # 网关路径，由 nginx 转发，不经前端
    if p in INTENTIONAL_NO_UI:
        intentional.append((p, ms, INTENTIONAL_NO_UI[p]))
        continue
    if p not in calls:
        dead.append((p, ms))

print('\n【A】前端调用但后端无对应路由（点了会 404）')
if not orphan:
    print('  无')
for p, ms in orphan:
    print(f'  ⚠️  {p}  [{",".join(sorted(ms))}]')

print('\n【B】后端有路由但前端从不调用（功能做了但用户碰不到）')
if not dead:
    print('  无')
for p, ms in dead:
    print(f'  ⚠️  {p}  [{",".join(sorted(ms))}]')

if intentional:
    print('\n【D】刻意不做界面（不是缺口，报出来只是解释为什么）')
    for p, ms, why in intentional:
        print(f'  ·  {p}  [{",".join(sorted(ms))}]  —— {why}')

print('\n【C】方法不匹配')
bad = 0
for p, ms in sorted(calls.items()):
    if p in routes:
        miss = ms - routes[p]
        if miss:
            print(f'  ⚠️  {p}  前端用 {"+".join(sorted(ms))}，后端只有 {sorted(routes[p])}')
            bad += 1
if not bad:
    print('  无')