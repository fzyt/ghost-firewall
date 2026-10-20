"""反代服务「上传大小限制」（client_max_body_size）的默认值回归测试。

运行:  python3 tests/test_rp_body_limit.py

背景（2026-10-20 用户要求）
--------------------------
用户原话：「上传大小限制 默认为1把。你改下，需要就我自己手动增加。」

这个字段是 nginx 的 `client_max_body_size`，它限制的是**该 location 允许的
请求体（body）上限**，不是「上传文件大小」：
  - 算进去：HTTP 头之后的全部 body 字节（表单 POST、JSON、multipart）
  - 算不进去：请求头、URL、Cookie
  - 判定依据是 Content-Length 声明或累积的 body 大小

第十八节的 413 就是这个字段的另一头：值太小会把**登录表单**一起挡掉
（GET 不带 body 所以页面能开，POST 带 body 所以登录被拒）。

默认值选 1M 而不是 0（不限）的理由：
  1. 1M 正是 nginx 自己的编译期默认值（client_max_body_size 默认 1m），
     足以覆盖绝大多数表单 / JSON 提交；
  2. 0（不限）等于把公网入口的请求体上限完全敞开 —— 网关后面是
     auth_gateway 和上游服务，一个超大 POST 就能把内存顶爆；
  3. 需要传大文件时用户在面板里改大即可（填 0 = 不限，填 100M/1G 都行）。

⚠️ 之前这个值是「空 → 0（不限）」，而 `_sanitize_client_max_body_size`
的注释却写着「空值 = 走 nginx 默认 1M」—— 注释和行为对不上，
以行为为准（不限）读了注释的人会以为默认是 1M。现在两边对齐了。
"""
import importlib
import json
import os
import sys
import tempfile

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def fresh():
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    app.CONFIG_PATH = os.path.join(tempfile.mkdtemp(), 'cfg.json')
    app.LISTS_PATH = os.path.join(tempfile.mkdtemp(), 'lists.json')
    app.RULES_PATH = os.path.join(tempfile.mkdtemp(), 'rules.nft')
    return app


def base_cfg(app):
    return json.loads(json.dumps(app.DEFAULT_CONFIG))


def gen_conf(app, rules):
    cfg = {**base_cfg(app), 'gateway_enabled': True, 'gateway_port': 8443,
           'reverse_proxy': {'rules': rules, 'certificates': [],
                             'settings': dict(app.RP_DEFAULT_SETTINGS)}}
    return app._generate_gateway_nginx_conf(cfg)


RULE = {
    'id': 'rp_1', 'name': 'demo', 'enabled': True,
    'path_prefix': '/demo', 'target_address': '127.0.0.1:5080',
    'target_protocol': 'http', 'public_access': True,
    'client_max_body_size': '', 'api_path_prefix': '',
    'websocket_enabled': True, 'icon': ''}


def body_size_of(conf):
    """从生成的 nginx 配置里取出**反代 location** 的 client_max_body_size

    ⚠️ 不能直接取第一个 —— 网关自己的 /auth/* location 也有这个指令
    （固定 8K，那是 AUTH-VULN-04 的防 OOM 加固），跟反代服务无关。
    """
    for line in conf.splitlines():
        s = line.strip()
        if s.startswith('client_max_body_size') and '8K' not in s:
            return s.split()[1].rstrip(';')
    return None


def main():
    app = fresh()

    print('\n▶ 默认值：空 → 1M（不是 0 不限）')
    conf = gen_conf(app, [dict(RULE)])
    got = body_size_of(conf)
    check('空值 → 生成 1M', got == '1M', f'实际={got!r}')
    check('默认值常量存在且是 1M',
          getattr(app, 'DEFAULT_CLIENT_MAX_BODY', None) == '1M',
          f"实际={getattr(app, 'DEFAULT_CLIENT_MAX_BODY', None)!r}")

    print('\n▶ 用户显式填的值照旧生效')
    for val, want in (('0', '0'), ('100M', '100M'), ('1G', '1G'), ('512K', '512K'),
                      ('10m', '10M')):
        conf = gen_conf(app, [dict(RULE, client_max_body_size=val)])
        got = body_size_of(conf)
        check(f'填 {val} → 生成 {want}', got == want, f'实际={got!r}')

    print('\n▶ 非法值不能让整份配置生成失败')
    conf = gen_conf(app, [dict(RULE, client_max_body_size='10 MB; drop table')])
    got = body_size_of(conf)
    check('非法值 → 退回默认 1M', got == '1M', f'实际={got!r}')
    check('非法值 → 配置照样生成得出来', 'location /demo/' in conf)

    print('\n▶ 网关自身的认证端点仍是 8K（不能被这次改动带偏）')
    check('认证端点仍限 8K', 'client_max_body_size 8K;' in conf)

    print('\n▶ 前端文案与默认值')
    js = open(os.path.join(os.path.dirname(BACKEND), 'frontend', 'app.js'),
              encoding='utf-8').read()
    html = open(os.path.join(os.path.dirname(BACKEND), 'frontend', 'index.html'),
                encoding='utf-8').read()
    check("新建规则的默认值是 '1M'", "client_max_body_size: '1M'," in js)
    check("编辑老规则时归一化成 '1M'", "r.client_max_body_size = r.client_max_body_size || '1M';" in js)
    check('列表里空值显示 1M（默认）', "'1M（默认）'" in html)
    check('表单提示写明默认 1M', '默认 1M（1MB）' in html)
    check('表单提示写明 0 = 不限制', '填 0 = 不限制' in html)

    print('\n' + '=' * 66)
    print(f' 合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        for f in FAIL:
            print('  失败:', f)
    else:
        print(' 全部通过')
    print('=' * 66)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
