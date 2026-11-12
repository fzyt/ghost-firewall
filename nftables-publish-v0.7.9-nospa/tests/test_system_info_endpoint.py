#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
`/api/system/info` 端点的测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_system_info_endpoint.py

测什么有效
----------
这个端点采的是**设备信息**，其中包含网段、地址、接口名 ——
虽然都不是敏感值，但它是一个**新增的对外接口**，
必须有和既有接口一样的门控与失败语义。

三个必须验的点
--------------
1. **未登录必须 401** —— 新接口不能漏掉认证门控。
   这是最容易出的错：复制粘贴一个既有端点时把 `_is_authenticated()`
   那一行漏掉，接口就成了匿名可读。
2. **采集器抛异常时不能 500 裸奔** —— 要给出明确 code 与提示。
3. **返回结构固定** —— 前端按 `data.os.pretty_name` 这样的路径取值，
   结构变了前端就是一片空白（而且是静默的）。

沙箱：配置与规则路径全部指向临时目录，不碰真设备。
"""
import importlib
import json
import os
import sys
import tempfile
import time
import unittest

BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def fresh_app():
    """加载一个面板模块副本，配置路径指向临时目录。"""
    sys.modules.pop('app', None)
    app = importlib.import_module('app')
    d = tempfile.mkdtemp()
    cfg = os.path.join(d, 'cfg.json')
    with open(cfg, 'w') as f:
        json.dump({
            'lan_subnet4': '127.0.0.0/8',
            'panel_allowed_nets': ['127.0.0.0/8'],
            'auth_session_timeout': 1800,
            'auth_token_epoch': 1,
        }, f)
    app.CONFIG_PATH = cfg
    app.LISTS_PATH = os.path.join(d, 'lists.json')
    app.RULES_PATH = os.path.join(d, 'rules.nft')
    return app


def login(client, appmod):
    """预设一个已登录且世代号匹配的会话。"""
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['username'] = 'admin'
        sess['auth_epoch'] = appmod._current_token_epoch()
        sess['last_active'] = time.time()


def main():
    appmod = fresh_app()
    client = appmod.app.test_client()

    sec('第 1 组：认证门控 —— 新接口不能漏掉')
    r = client.get('/api/system/info')
    check('未登录访问返回 401', r.status_code == 401,
          '状态码 %d' % r.status_code)
    body = r.get_json() or {}
    check('未登录返回 code=AUTH_REQUIRED', body.get('code') == 'AUTH_REQUIRED',
          '实际 %r' % body.get('code'))

    sec('第 2 组：登录后返回结构')
    login(client, appmod)
    r = client.get('/api/system/info')
    check('登录后返回 200', r.status_code == 200, '状态码 %d' % r.status_code)
    body = r.get_json() or {}
    check('success=true', body.get('success') is True)

    data = body.get('data')
    check('有 data 字段', isinstance(data, dict))
    if not isinstance(data, dict):
        print('\n' + '=' * 60)
        print('  通过 %d / 失败 %d' % (len(PASS), len(FAIL)))
        return 1

    # 前端按这些路径取值，缺一个就是静默空白
    for key in ('model', 'os', 'cpu', 'memory', 'storage',
                'uptime_seconds', 'interfaces'):
        check('data.%s 存在' % key, key in data)

    for key in ('pretty_name', 'version', 'distro', 'kernel'):
        check('data.os.%s 存在' % key, key in data.get('os', {}))
    for key in ('model', 'cores', 'mhz', 'arch'):
        check('data.cpu.%s 存在' % key, key in data.get('cpu', {}))
    for key in ('total_kb', 'free_kb', 'used_kb'):
        check('data.memory.%s 存在' % key, key in data.get('memory', {}))
    for key in ('total_kb', 'used_kb', 'free_kb', 'path'):
        check('data.storage.%s 存在' % key, key in data.get('storage', {}))

    check('data.interfaces 是数组', isinstance(data.get('interfaces'), list))

    sec('第 3 组：采集器抛异常时不能裸奔')
    real_collect = appmod.device_info.collect_all

    def boom():
        raise RuntimeError('模拟采集器崩溃')

    appmod.device_info.collect_all = boom
    try:
        r = client.get('/api/system/info')
        check('采集器抛异常时返回 500', r.status_code == 500,
              '状态码 %d' % r.status_code)
        b = r.get_json() or {}
        check('返回 code=COLLECT_FAILED', b.get('code') == 'COLLECT_FAILED',
              '实际 %r' % b.get('code'))
        check('不把异常原文回显给请求方', '模拟采集器崩溃' not in json.dumps(b, ensure_ascii=False),
              '响应体=%r' % b)
    finally:
        appmod.device_info.collect_all = real_collect

    sec('第 4 组：恢复后仍然正常')
    r = client.get('/api/system/info')
    check('采集器恢复正常后返回 200', r.status_code == 200,
          '状态码 %d' % r.status_code)

    # ── 第 5 组：面板自身的开关 ─────────────────────────────────
    #
    # 这一组盯的是**副作用边界**，不只是结构。
    #
    # 系统信息页是最"无害"的页面 —— 用户点开看一眼设备信息。
    # 它绝不能顺手把配置文件移走。
    #
    # ⚠️ app.py 的 load_config() 在配置损坏时会 `os.replace` 把配置文件
    # **移走**（load_config 的 1048~1053 行）⇒ 接口里必须用
    # `_read_config_readonly()` 自己读，不能调 load_config()。
    # 这一条不测就会漏 —— 漏了之后，用户点一次系统信息页，
    # 面板自己这一层就把配置移走了。
    #
    # ⚠️ 这里**单测 `_read_config_readonly()`**、而不是从端点层面断言
    #    「文件还在」：端点请求会先过访问守卫，而守卫本来就调
    #    load_config()（配置损坏时 fail-closed 拒绝所有来源，
    #    同时把损坏文件移走）—— 那是**既有设计**，与本接口无关。
    #    端点层面的断言放到第 6 组（配置正常时）。

    sec('第 5 组：只读读配置 —— 不能有副作用')
    d2 = tempfile.mkdtemp()
    broken = os.path.join(d2, 'broken.json')
    with open(broken, 'w') as f:
        f.write('{ this is not json')
    appmod.CONFIG_PATH = broken
    ro = appmod._read_config_readonly()
    check('★ 配置损坏时 _read_config_readonly 返回 None', ro is None,
          '实际 %r' % (ro,))
    check('★ 配置文件没有被移走（_read_config_readonly 是只读的）',
          os.path.exists(broken), '文件已消失 —— 说明它内部调了 load_config()')

    # 缺文件 ⇒ None，且不能凭空造出默认配置
    appmod.CONFIG_PATH = os.path.join(d2, 'nope.json')
    check('配置文件不存在时返回 None',
          appmod._read_config_readonly() is None)

    # 正常文件 ⇒ 原样读出来
    ok_cfg = os.path.join(d2, 'ok.json')
    with open(ok_cfg, 'w') as f:
        json.dump({'access_mode': 'trust', 'gateway_enabled': True}, f)
    appmod.CONFIG_PATH = ok_cfg
    ro2 = appmod._read_config_readonly()
    check('正常配置能读出来', isinstance(ro2, dict))
    check('读出来的就是磁盘上的内容',
          (ro2 or {}).get('access_mode') == 'trust')

    # 顶层不是对象（被手工改坏）⇒ None，不能当 dict 用
    bad_shape = os.path.join(d2, 'list.json')
    with open(bad_shape, 'w') as f:
        json.dump([1, 2, 3], f)
    appmod.CONFIG_PATH = bad_shape
    check('顶层不是对象时返回 None',
          appmod._read_config_readonly() is None)

    sec('第 6 组：面板开关的结构与取值')
    d3 = tempfile.mkdtemp()
    cfgpath = os.path.join(d3, 'cfg.json')
    with open(cfgpath, 'w') as f:
        json.dump({
            'lan_subnet4': '127.0.0.0/8',
            'panel_allowed_nets': ['127.0.0.0/8'],
            'auth_session_timeout': 1800,
            'auth_token_epoch': 1,
            'access_mode': 'trust',
            'deploy_mode': 'linux_gateway',
            'gateway_enabled': True,
            'china_ip_block': True,
            'forward_rules': [{'proto': 'tcp', 'src_port': 8080}],
            'reverse_proxy': {
                # ⚠️ 最后那个「不是对象」是**故意**放进去的：
                #    _migrate_rp_rules 会把非 dict 的规则丢掉，
                #    计数口径必须和它一致 ⇒ 有效规则仍是 2 条。
                #    （放一个空的黑名单 IPv6 集合也不行 ——
                #      那样「黑名单只算 IPv4」的退化就测不出来。）
                'rules': [{'id': 'rp_001'}, {'id': 'rp_002'}, '不是对象'],
                'certificates': [{'id': 'c1'}],
            },
        }, f)
    appmod.CONFIG_PATH = cfgpath
    with open(appmod.LISTS_PATH, 'w') as f:
        json.dump({
            'allowed4': ['1.1.1.1', '2.2.2.2'],
            'allowed6': ['fd00::1'],
            'blacklist4': ['3.3.3.3'],
            'blacklist6': ['fd00::2'],
        }, f)

    r = client.get('/api/system/info')
    data = (r.get_json() or {}).get('data') or {}
    panel = data.get('panel')
    check('data.panel 是对象', isinstance(panel, dict), '实际 %r' % (panel,))
    if isinstance(panel, dict):
        check('panel.access_mode', panel.get('access_mode') == 'trust',
              '实际 %r' % panel.get('access_mode'))
        check('panel.deploy_mode', panel.get('deploy_mode') == 'linux_gateway',
              '实际 %r' % panel.get('deploy_mode'))
        check('panel.switches 是数组', isinstance(panel.get('switches'), list))
        sw = {s.get('key'): s for s in (panel.get('switches') or [])}
        check('gateway_enabled 反映配置为开',
              sw.get('gateway_enabled', {}).get('on') is True)
        check('china_ip_block 反映配置为开',
              sw.get('china_ip_block', {}).get('on') is True)
        check('未写的开关默认为关',
              sw.get('dns_lan_resolver_enabled', {}).get('on') is False)
        check('每个开关都带中文标签',
              all(s.get('label') for s in (panel.get('switches') or [])))
        counts = panel.get('counts') or {}
        check('转发规则条数', counts.get('forward_rules') == 1,
              '实际 %r' % counts.get('forward_rules'))
        check('白名单条数（v4+v6）', counts.get('whitelist') == 3,
              '实际 %r' % counts.get('whitelist'))
        check('黑名单条数（v4+v6）', counts.get('blacklist') == 2,
              '实际 %r' % counts.get('blacklist'))
        check('反向代理条数', counts.get('reverse_proxies') == 2,
              '实际 %r' % counts.get('reverse_proxies'))
        check('证书条数', counts.get('certificates') == 1,
              '实际 %r' % counts.get('certificates'))

    sec('第 7 组：面板开关的边界')
    # 缺 reverse_proxy 键（全新安装的样子）⇒ 不能抛
    d4 = tempfile.mkdtemp()
    cfg4 = os.path.join(d4, 'cfg.json')
    with open(cfg4, 'w') as f:
        json.dump({'lan_subnet4': '127.0.0.0/8', 'auth_token_epoch': 1}, f)
    appmod.CONFIG_PATH = cfg4
    p4 = appmod._panel_switches(appmod._read_config_readonly())
    check('缺 reverse_proxy 键不抛', isinstance(p4, dict))
    check('缺 reverse_proxy 时反代条数为 0',
          (p4 or {}).get('counts', {}).get('reverse_proxies') == 0)

    # reverse_proxy 结构非法（被手工改坏）⇒ 不能抛
    p5 = appmod._panel_switches({'reverse_proxy': '不是对象',
                                 'forward_rules': '也不是数组'})
    check('reverse_proxy 结构非法不抛', isinstance(p5, dict))
    check('结构非法时计数为 0',
          (p5 or {}).get('counts', {}).get('reverse_proxies') == 0)
    check('forward_rules 不是数组时计数为 0',
          (p5 or {}).get('counts', {}).get('forward_rules') == 0)

    # 非布尔值 ⇒ 当 False（关是安全默认）
    p6 = appmod._panel_switches({'gateway_enabled': 'yes'})
    sw6 = {s['key']: s for s in p6['switches']}
    check('非布尔值不当成「开」', sw6['gateway_enabled']['on'] is False,
          '实际 %r' % sw6['gateway_enabled']['on'])

    # config 不是 dict ⇒ 返回 None
    check('config 不是 dict 时返回 None', appmod._panel_switches(None) is None)

    # 旧格式的转发规则 ⇒ 迁移后是 1 条（不迁移就会显示 0 条）
    p7 = appmod._panel_switches({'tcp_services': '8080,9090',
                                 'dsm_ip4': '192.168.1.5'})
    check('旧格式转发规则迁移后算 1 条',
          (p7 or {}).get('counts', {}).get('forward_rules') == 1,
          '实际 %r' % (p7 or {}).get('counts', {}).get('forward_rules'))

    # 证书与 DDNS：按文件在不在判定
    d5 = tempfile.mkdtemp()
    appmod.NFTABLES_WEB_CERT = os.path.join(d5, 'fullchain.pem')
    appmod.NFTABLES_WEB_KEY = os.path.join(d5, 'privkey.pem')
    appmod.ALIYUN_DDNS_CONFIG_PATH = os.path.join(d5, 'ddns.json')
    p8 = appmod._panel_switches({})
    check('证书不存在时 cert_ready 为 False',
          (p8 or {}).get('cert_ready') is False)
    check('DDNS 配置不存在时为 False',
          (p8 or {}).get('ddns_configured') is False)
    for _p in (appmod.NFTABLES_WEB_CERT, appmod.NFTABLES_WEB_KEY,
               appmod.ALIYUN_DDNS_CONFIG_PATH):
        with open(_p, 'w') as f:
            f.write('x')
    p9 = appmod._panel_switches({})
    check('证书与私钥都在时 cert_ready 为 True',
          (p9 or {}).get('cert_ready') is True)
    check('DDNS 配置存在时为 True',
          (p9 or {}).get('ddns_configured') is True)
    # 只缺私钥 ⇒ 不能算就绪
    os.unlink(appmod.NFTABLES_WEB_KEY)
    p10 = appmod._panel_switches({})
    check('缺私钥时 cert_ready 为 False',
          (p10 or {}).get('cert_ready') is False)

    # ══════════════════════════════════════════════════════════
    sec('第 8 组：DHCP 绑定接口的请求体校验')
    # ⚠️ body 是数组/字符串时，`body.get(...)` 会抛 AttributeError
    #    ⇒ 变成 500（服务端错误）。但这是**客户端发错了** ⇒ 应该是 400。
    # ⚠️ 这几条**不会碰任何文件** —— 请求体在进模块之前就被拒了。
    for label, payload in (('数组', ['a', 'b']),
                            ('字符串', '不是对象'),
                            ('数字', 123),
                            ('null', None)):
        r = client.post('/api/system/dhcp-hosts', json=payload)
        check('POST body 是%s ⇒ 返回 400（不是 500）' % label,
              r.status_code == 400, '状态码 %d' % r.status_code)
        b = r.get_json() or {}
        check('POST body 是%s ⇒ code=BAD_REQUEST' % label,
              b.get('code') == 'BAD_REQUEST', '实际 %r' % b.get('code'))
        check('POST body 是%s ⇒ 不把异常原文回显给请求方' % label,
              'Traceback' not in json.dumps(b, ensure_ascii=False))

    # 未登录时同样不能因为 body 形状而泄露别的信息
    c2 = appmod.app.test_client()
    r = c2.post('/api/system/dhcp-hosts', json=['a'])
    check('未登录 + 非法 body ⇒ 仍然是 401（认证优先）',
          r.status_code == 401, '状态码 %d' % r.status_code)
    r = c2.delete('/api/system/dhcp-hosts/host_aabbccddee01')
    check('未登录删除绑定 ⇒ 401（删除能改路由器配置，门控不能漏）',
          r.status_code == 401, '状态码 %d' % r.status_code)

    print('\n' + '=' * 60)
    print('  通过 %d / 失败 %d' % (len(PASS), len(FAIL)))
    if FAIL:
        print('  失败项: %s' % FAIL)
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
