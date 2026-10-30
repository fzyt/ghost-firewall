"""静态资源白名单批次的回归测试（P2-21）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_static_whitelist.py

背景（2026-10-30）：
   面板的 web 根目录（frontend/）里躺着完整的旧版管理 SPA 副本
   —— frontend/index.html.bak（107KB，8 月的旧版）。

   deploy.sh 已经在**部署侧**清了这件事（只发布 git 跟踪的文件 + 差集清理），
   但**代码侧**的静态路由没设防：原本只挡了 '..' 和前导 '/'，
   '.bak' '.py' '.json' '.sh' 一律放行。

   面板是 Flask 直连 5443 提供静态文件的（不经过 nginx），所以这道路由
   就是唯一的一道关 —— 源码跑起来时 /index.html.bak 直接可拿。

   注意暴露面有两层：
     - **未认证**：before_request 的静态放行名单（_STATIC_EXTENSIONS）
       本来就不含 .bak，所以未登录拿不到（401）—— 这一层原本就是安全的。
     - **已认证**：会话一建立，静态路由就把目录里**任何**带点当扩展名的
       文件都给了出去，包括 index.html.bak。这才是要补的那一层。

   修法：静态路由改成**扩展名白名单**。白名单比黑名单稳：以后目录里
   再出现 .bak / .env / .py，不用记得回来补黑名单。
   白名单从 before_request 的 _STATIC_EXTENSIONS 派生，两处不会漂移。

沙箱：只用 Flask 测试客户端打请求，不碰真实系统路径、不执行 nft/nginx、
不访问外网。
"""
import importlib.util as ilu
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
FRONTEND = os.path.join(ROOT, 'frontend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []

TEST_PASSWORD = 'static-whitelist-test-pw'


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    detail = detail.replace('❌', '[x]').replace('✅', '[v]')
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def load_app():
    """加载 app 模块，配置与凭据路径全部指到临时目录。"""
    tmp = tempfile.mkdtemp(prefix='nftstatic-')
    paths = {
        'AUTH_CONFIG_PATH': os.path.join(tmp, 'config.json'),
        'AUTH_PASSWORD_FILE': os.path.join(tmp, 'password.json'),
        'AUTH_SECRET_FILE': os.path.join(tmp, 'secret'),
        'AUTH_SESSION_SECRET_FILE': os.path.join(tmp, 'session-secret'),
        'NFTABLES_WEB_LISTS_PATH': os.path.join(tmp, 'lists.json'),
        'NFTABLES_WEB_RULES_PATH': os.path.join(tmp, 'rules.nft'),
        'NFTABLES_WEB_SSL_DIR': os.path.join(tmp, 'ssl'),
        'NFTABLES_WEB_NGINX_CONF_DIR': os.path.join(tmp, 'nginx-conf'),
    }
    os.environ.update(paths)
    os.makedirs(paths['NFTABLES_WEB_SSL_DIR'], exist_ok=True)

    sys.modules.pop('app', None)
    spec = ilu.spec_from_file_location('app', os.path.join(BACKEND, 'app.py'))
    app = ilu.module_from_spec(spec)
    sys.modules['app'] = app
    spec.loader.exec_module(app)

    app._write_password_hash(app._hash_password(TEST_PASSWORD))
    with open(paths['AUTH_CONFIG_PATH'], 'w', encoding='utf-8') as f:
        json.dump({
            'lan_subnet4': '192.168.100.0/24',
            'wan_if': 'eth0',
            'lan_if': 'br-lan',
            'router_ip4': '192.168.100.1',
            'reverse_proxy': {'rules': [], 'certificates': [], 'settings': {}},
        }, f)
    return app, paths


def main():
    app, paths = load_app()
    client = app.app.test_client()
    client.environ_base['REMOTE_ADDR'] = '192.168.100.50'

    # ── SW-1  白名单判定本身 ──────────────────────────────────────
    sec('SW-1  _static_path_allowed 的判定')
    allow = app._static_path_allowed

    # 前端真正需要的资源类型必须放行（放行错了 = 前端白屏）
    for good in ('index.html', 'app.js', 'fx.js', 'styles.css',
                 'assets/alpine.js', 'assets/tailwind.js',
                 'assets/fonts/JetBrainsMono-Regular.ttf',
                 'assets/image-20260319104747-jbgsgdq.png'):
        check(f'放行前端资源 {good}', allow(good) is True)

    # 必须挡住的东西
    for bad, why in (
        ('index.html.bak', '旧版管理 SPA 完整副本'),
        ('app.js.bak', '旧版脚本副本'),
        ('app.py', '后端源码'),
        ('config.json', '配置（含凭据）'),
        ('setup.sh', '安装脚本'),
        ('.env', '隐藏文件'),
        ('assets/.env', '子目录里的隐藏文件'),
        # ⚠️ 这两个是**专门用来区分两道防线**的：
        #   .env.js 的扩展名是 .js（在白名单里）⇒ 只有「隐藏文件检查」能挡它；
        #   .gitignore.txt 同理。
        # 只测 .env 是不够的 —— .env 的扩展名是空，不在白名单里，
        # 白名单就把它挡了，隐藏文件检查删掉也测不出来（会变成等价变异）。
        ('.env.js', '隐藏文件 + 白名单扩展名'),
        ('.gitignore.txt', '隐藏文件 + 白名单扩展名'),
        ('../backend/app.py', '路径穿越'),
        ('..%2fbackend/app.py', 'URL 编码的穿越（解码后仍要挡）'),
        ('/etc/passwd', '绝对路径'),
        ('', '空路径'),
    ):
        check(f'挡住 {bad}（{why}）', allow(bad) is False)

    # 扩展名大小写不能成为绕过口
    check('大小写不敏感：INDEX.HTML.BAK 仍被挡',
          allow('INDEX.HTML.BAK') is False)
    check('大小写不敏感：App.JS 放行', allow('App.JS') is True)

    # ── SW-2  两处白名单必须一致（漂移 = 白屏或登录页打不开）────────
    sec('SW-2  与 before_request 的放行名单一致')
    before = {f'.{e}' for e in app._STATIC_EXTENSIONS}
    missing = before - app._STATIC_ALLOWED_EXT
    check('before_request 放行的扩展名，静态路由也放行（否则正常资源 403）',
          not missing, f'缺 {sorted(missing)}')
    check('before_request 放行的扩展名确实被静态路由包含',
          app._STATIC_ALLOWED_EXT >= before)

    # ── SW-3  未认证：拿不到任何敏感静态文件 ───────────────────────
    sec('SW-3  未认证时拿不到 .bak')
    r = client.get('/index.html.bak')
    check('未认证 GET /index.html.bak 被拒', r.status_code in (401, 403),
          f'实际 {r.status_code}')

    r = client.get('/app.js')
    check('未认证 GET /app.js 放行（前端要能加载）', r.status_code == 200,
          f'实际 {r.status_code}')

    r = client.get('/')
    check('未认证 GET / 放行（登录页要能加载）', r.status_code == 200,
          f'实际 {r.status_code}')

    # ── SW-4  已认证：旧版 SPA 副本仍然拿不到（这才是要补的一层）───
    sec('SW-4  已认证后 .bak 依然拿不到')
    r = client.post('/api/auth/login', json={'password': TEST_PASSWORD})
    check('登录成功（后续用例的前提）',
          r.status_code == 200 and (r.get_json() or {}).get('success'),
          f'HTTP {r.status_code}')

    r = client.get('/index.html.bak')
    check('已认证 GET /index.html.bak 被拒', r.status_code == 403,
          f'实际 {r.status_code}')
    check('被拒的响应体很小（没有把 107KB 的旧版 SPA 吐出来）',
          len(r.data) < 1024, f'{len(r.data)} 字节')

    # ⚠️ 这里要求的是 **403**，不是「403 或 404」。
    # 404 是 Werkzeug 的 safe_join 兜底（找不到文件）—— 那说明**我们的路由
    # 没挡下来**，是靠框架兜的底。应用层自己判掉的才叫防线成立。
    for p in ('/app.py', '/../backend/app.py', '/../app.py'):
        r = client.get(p)
        check(f'已认证 GET {p} 拿不到源码（且是路由自己挡的 403）',
              r.status_code == 403 and b'import app' not in r.data,
              f'实际 {r.status_code}')

    # 正常资源在已认证后照样能拿
    for p in ('/app.js', '/styles.css', '/fx.js'):
        r = client.get(p)
        check(f'已认证 GET {p} 正常返回', r.status_code == 200,
              f'实际 {r.status_code}')

    r = client.get('/assets/fonts/JetBrainsMono-Regular.ttf')
    check('已认证 GET 字体文件正常返回', r.status_code == 200,
          f'实际 {r.status_code}')

    # ── SW-5  /api/ 命名空间保持 404 语义 ─────────────────────────
    sec('SW-5  /api/ 前缀仍是 404（不是 403）')
    r = client.get('/api/definitely-not-a-real-endpoint')
    check('未知 API 路径返回 404', r.status_code == 404,
          f'实际 {r.status_code}')

    # api 前缀下的穿越也必须拿不到东西
    r = client.get('/api/../backend/app.py')
    check('api 前缀下的穿越拿不到源码',
          r.status_code == 404 and b'import' not in r.data,
          f'实际 {r.status_code}')

    # ── SW-6  仓库里那个 .bak 确实会被挡住 ────────────────────────
    sec('SW-6  仓库里真实存在的 index.html.bak')
    bak = os.path.join(FRONTEND, 'index.html.bak')
    if os.path.exists(bak):
        r = client.get('/index.html.bak')
        check('真实存在的 index.html.bak 通过 HTTP 拿不到',
              r.status_code == 403 and len(r.data) < 1024,
              f'实际 {r.status_code}，{len(r.data)} 字节')
        # 直接看文件大小，确认「本来是有东西的」
        check('那个 .bak 确实不是空文件（否则这条用例没意义）',
              os.path.getsize(bak) > 50000,
              f'{os.path.getsize(bak)} 字节')
    else:
        print('  ⚠️  仓库里已无 index.html.bak（已被清理），跳过实测')

    print('\n' + '=' * 60)
    print(f'  合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        print('  失败项:')
        for f in FAIL:
            print('    - ' + f)
        print('  有失败')
        return 1
    print('  全部通过')
    return 0


if __name__ == '__main__':
    sys.exit(main())
