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

    print('\n' + '=' * 60)
    print('  通过 %d / 失败 %d' % (len(PASS), len(FAIL)))
    if FAIL:
        print('  失败项: %s' % FAIL)
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
