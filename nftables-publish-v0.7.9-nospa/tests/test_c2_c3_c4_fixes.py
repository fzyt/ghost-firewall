#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C2 / C3 / C4 三处残留的行为级测试（2026-11-08 面板侧 53 条静态判定对账挖出）。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_c2_c3_c4_fixes.py

这三处是什么
------------
C2（Shannon #60 / P2-15）：IPv6 的 **scope-id** 没被严格解析。
    `fe80::1%br-lan` 里 `%br-lan` 那截叫 scope-id，是链路本地地址的
    **接口标识**，不是地址本身。
    ⚠️ Python 3.9+ 的 `ipaddress` **认**它 —— `IPv6Address('fe80::1%br-lan')`
    解析成功、`str()` 还原样保留 ⇒ 宽松判定会放行。
    ⚠️ 但 **nft 不认** ⇒ 写进规则集就是非法语法，`nft -f` 整份加载失败。
    名单/白名单都是**按地址匹配**的，带 scope-id 毫无意义 ⇒ 判非法。

C3：恢复配置那条路**绕过了 validate_config**。
    保存配置（save_config）会调 validate_config，非法值当场被拒；
    `restore_config` 不调 ⇒ 一个被改坏的 backup 里的非法值会被原样恢复。
    最要命的是 `panel_allowed_nets` 里的 `0.0.0.0/0` ——
    它等价于「不设访问边界」，而这正是 validate_config 明确要挡的。

C4：规则集的**完整备份**文件没有 chmod。
    `open(...,'w')` 的权限由 umask 派生 ⇒ 默认 0644 ⇒ 设备上任何本地用户
    都能把防火墙规则集（内含白/黑名单 IP 与信任 IP）读走。
    同段的 `.lastgood` 早就 chmod 0600 了，配置备份也做了 ⇒ 这是漏网。

为什么每处都要**行为级**测试
--------------------------
C2：静态断言「代码里有 '%' 检查」挡不住「检查写在了错误的位置」
    （比如写在校验之后、或只挡了 IPv4 分支）。
C3：静态断言「调用了 validate_config」挡不住「调用了但结果没用」
    （errs 收了却没 return，照样恢复）。
C4：静态断言「有 os.chmod」挡不住「chmod 写在写完之后」（有窗口）
    与「chmod 用了错误的权限位」。

沙箱
----
全部在临时目录里跑：CONFIG_PATH / LISTS_PATH / RULES_PATH 都指到 tmpdir，
subprocess.run 一律打桩 ⇒ **绝不碰本机 /etc、绝不碰真设备**。
"""
import importlib.util as ilu
import json
import os
import shutil
import stat
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  [PASS] ' if ok else '  [FAIL] ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def load_app(tag):
    """加载一份**独立的** app 模块实例（不同 tag ⇒ 不同模块名，不共享全局状态）。"""
    spec = ilu.spec_from_file_location('_nftapp_' + tag, os.path.join(BACKEND, 'app.py'))
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_te(tag):
    """加载一份**独立的** template_engine 模块实例。

    为什么单独加载：模板引擎是**独立模块**（不 import app.py），
    所以它的 scope-id 闸门是就地实现的，拿不到 `_valid_ip`。
    """
    spec = ilu.spec_from_file_location('_nftte_' + tag,
                                       os.path.join(BACKEND, 'template_engine.py'))
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeProc:
    """冒充 subprocess.run 的返回值。"""

    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def make_client(app, cfg_extra=None):
    """起一个已登录的 test client（绕开密码文件/限流那堆无关依赖）。"""
    client = app.app.test_client()
    # ⚠⚠ 这份配置必须**自洽**，三个字段每一个都有讲究：
    #
    # ① trusted_ip4 / router_ip4 要在 ——
    #    C3 要测「备份里缺字段时用**当前配置**的值补上」，
    #    当前配置里压根没有 ⇒ 无值可继承 ⇒ 测到的就不是继承这条语义。
    #
    # ② auth_token_epoch 必须**显式写死** ——
    #    缺省时 load_config() 会用 DEFAULT_CONFIG 里的 0 兜底，
    #    而测试里任何一次重写配置都可能把 epoch 改掉 ⇒ 会话当场失效。
    #
    # ③ ②的后果特别阴：会话失效后所有接口返回 401，
    #    而「被拒」类断言写的是 `status >= 400` ⇒ **401 也算通过** ⇒
    #    假通过。这坑踩过一次：2.3/2.5/2.6 三条当时全是 401 蒙过去的，
    #    测的根本不是被测逻辑。所以下面还有 session_alive() 探针兜着。
    cfg = {'panel_allowed_nets': '127.0.0.1/32',
           'lan_subnet4': '127.0.0.1/32',
           'trusted_ip4': '192.168.100.50',
           'router_ip4': '192.168.100.1',
           'auth_token_epoch': 1}
    cfg.update(cfg_extra or {})
    with open(app.CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f)
    app._NETS_CACHE.update(mtime=None, nets=None)
    # ⚠️ last_active 必须写：before_request 里有 idle 超时检查，
    #    缺了它 = 0 ⇒ 直接回 AUTH_EXPIRED「会话过期」。
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['auth_epoch'] = app._current_token_epoch()
        sess['last_active'] = time.time()
    return client


def resync_session(client, app):
    """把会话的世代号对齐到当前配置。

    测试**故意**改了配置里的 auth_token_epoch 之后必须调它 ——
    世代号对不上 ⇒ before_request 直接清会话回 401（'密码已修改，请重新登录'）。
    """
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['auth_epoch'] = app._current_token_epoch()
        sess['last_active'] = time.time()


def session_alive(client):
    """探针：会话现在还有效吗（用来排除「401 冒充测试结果」）。

    用 GET /api/config —— 它是面板自己的只读数据源，
    内部的 LuCI / 网关状态读取都包在 try 里（读不到就返回 None），
    本机没有 uci/nft 也不会 500。
    """
    try:
        return client.get('/api/config').status_code == 200
    except Exception:
        return False


def is_auth_error(resp, body=None):
    """这个响应是「认证/会话失效」而不是「被测逻辑拒绝」吗？

    认证失效有两个出口：401 + code=AUTH_REQUIRED（没登录）
    与 401 + code=AUTH_EXPIRED（世代号对不上）。
    凡是断言「应当被拒」的用例，都必须排除这两种 ——
    否则 401 会让 `status >= 400` 成立 ⇒ 假通过。
    """
    if resp.status_code != 401:
        return False
    if body is None:
        body = resp.get_json(silent=True) or {}
    return body.get('code') in ('AUTH_REQUIRED', 'AUTH_EXPIRED')


# ══════════════════════════════════════════════════════════════════
# 第 1 组：C2 —— IPv6 scope-id 必须判非法
# ══════════════════════════════════════════════════════════════════
def group_c2():
    sec('1. C2：IPv6 scope-id 必须判非法（nft 不认，写进规则集是非法语法）')

    app = load_app('c2')

    # ── 1.1 单元级：_valid_ip ────────────────────────────────────
    check('_valid_ip 拒绝 fe80::1%br-lan',
          app._valid_ip('fe80::1%br-lan') is False)
    check('_valid_ip 拒绝 2001:db8::1%eth0',
          app._valid_ip('2001:db8::1%eth0') is False)
    check('_valid_ip 拒绝 fe80::1%25br-lan（百分号编码形态）',
          app._valid_ip('fe80::1%25br-lan') is False)
    check('_valid_ip 拒绝 2001:db8::1%eth0%bad（多个 %）',
          app._valid_ip('2001:db8::1%eth0%bad') is False)
    check('_valid_ip 拒绝 "fe80::1%br-lan "（带空格也一样）',
          app._valid_ip('fe80::1%br-lan ') is False)

    # ── 1.2 单元级：_valid_ip 的正常路径没被带坏 ─────────────────
    check('_valid_ip 仍然接受普通 IPv6（fe80::1）',
          app._valid_ip('fe80::1') is True)
    check('_valid_ip 仍然接受全局 IPv6（2001:db8::1）',
          app._valid_ip('2001:db8::1') is True)
    check('_valid_ip 仍然接受 IPv4（192.168.100.1）',
          app._valid_ip('192.168.100.1') is True)
    check('_valid_ip 仍然接受 IPv4-mapped（::ffff:192.168.100.1）',
          app._valid_ip('::ffff:192.168.100.1') is True)
    check('_valid_ip 的版本判定仍然生效（version=4 拒 IPv6）',
          app._valid_ip('2001:db8::1', 4) is False)
    check('_valid_ip 的版本判定仍然生效（version=6 拒 IPv4）',
          app._valid_ip('192.168.100.1', 6) is False)
    check('_valid_ip 仍然拒绝垃圾输入',
          app._valid_ip('not-an-ip') is False)

    # ── 1.3 单元级：_detect_ip_version（名单自己的入口）─────────
    check('_detect_ip_version 拒绝 fe80::1%br-lan',
          app._detect_ip_version('fe80::1%br-lan') is None)
    check('_detect_ip_version 拒绝 2001:db8::1%eth0',
          app._detect_ip_version('2001:db8::1%eth0') is None)
    check('_detect_ip_version 仍然接受 2001:db8::1',
          app._detect_ip_version('2001:db8::1') == 6)
    check('_detect_ip_version 仍然接受 192.168.100.1',
          app._detect_ip_version('192.168.100.1') == 4)
    check('_detect_ip_version 仍然拒绝 CIDR（192.168.100.0/24）',
          app._detect_ip_version('192.168.100.0/24') is None)

    # ── 1.4 行为级：名单 add 接口 ────────────────────────────────
    # 行为级才是这次的重点：静态断言挡不住「检查写在了校验之后」。
    sec('1.4 行为级：POST /api/lists/add 带 scope-id 必须被拒且不落盘')

    d = tempfile.mkdtemp(prefix='nftc2-')
    app.CONFIG_PATH = os.path.join(d, 'config.json')
    app.LISTS_PATH = os.path.join(d, 'lists.json')
    client = make_client(app)

    # 桩掉 nft：记录调用次数，并**假装成功** ——
    # 只有这样才能测出「校验到底有没有在 nft 之前挡住」。
    nft_calls = []

    def fake_run(cmd, *a, **k):
        nft_calls.append(cmd)
        return FakeProc(returncode=0, stdout='')

    real_run = app.subprocess.run
    app.subprocess.run = fake_run
    try:
        # (a) 带 scope-id ⇒ 必须 400
        nft_calls.clear()
        r = client.post('/api/lists/add',
                        json={'set_name': 'allowed6', 'ip': 'fe80::1%br-lan'})
        body = r.get_json(silent=True) or {}
        check('带 scope-id 的 IPv6 被名单接口拒绝（400）',
              r.status_code == 400, f'实际 {r.status_code}')
        check('拒绝消息里带上了那个地址（便于用户看懂）',
              'fe80::1%br-lan' in str(body.get('message', '')),
              str(body.get('message', ''))[:80])
        check('被拒时**没有**调用 nft（校验在 nft 之前）',
              len(nft_calls) == 0, f'调用了 {len(nft_calls)} 次')
        check('被拒时名单文件没被写脏（lists.json 不存在或没这条）',
              (not os.path.exists(app.LISTS_PATH))
              or 'fe80::1%br-lan' not in open(app.LISTS_PATH, encoding='utf-8').read())

        # (b) 正常 IPv6 ⇒ 必须仍然能加（别把功能改坏了）
        nft_calls.clear()
        r = client.post('/api/lists/add',
                        json={'set_name': 'allowed6', 'ip': '2001:db8::1'})
        check('正常 IPv6 仍能加进名单（200）',
              r.status_code == 200, f'实际 {r.status_code}')
        check('正常 IPv6 会真的调 nft（说明校验放行了）',
              len(nft_calls) > 0, f'调用了 {len(nft_calls)} 次')
        check('正常 IPv6 落盘进了名单文件',
              os.path.exists(app.LISTS_PATH)
              and '2001:db8::1' in open(app.LISTS_PATH, encoding='utf-8').read())

        # (c) 正常 IPv4 ⇒ 不受影响
        r = client.post('/api/lists/add',
                        json={'set_name': 'allowed4', 'ip': '203.0.113.10'})
        check('正常 IPv4 仍能加进名单（200）',
              r.status_code == 200, f'实际 {r.status_code}')
    finally:
        app.subprocess.run = real_run
        shutil.rmtree(d, ignore_errors=True)

    # ── 1.5 第三个入口：lists.json 里的脏值不许进规则集 ────────────
    # 为什么必须单独立一组：`_format_list_elements` **既不走** `_valid_ip`
    #   **也不走** `_detect_ip_version` —— 它自己直接调 `ipaddress.ip_address()`。
    #   而 Python 3.9+ 的 ipaddress **认** scope-id ⇒ 只堵前两个入口的话，
    #   lists.json 里的脏值（root 手工编辑、老版本留下的文件）照样会被写进
    #   `elements = { ... }` 行 ⇒ nft 加载失败。
    #   而这个函数是名单进规则集的**最后一道闸** ⇒ 必须是 fail-closed。
    sec('1.5 行为级：lists.json 里的 scope-id 不许进规则集文件')

    app2 = load_app('c2b')
    d2 = tempfile.mkdtemp(prefix='nftc2b-')
    app2.RULES_PATH = os.path.join(d2, '99-custom-rules.nft')
    rules_text = (
        'table inet fw4 {\n'
        '    set allowed6 {\n'
        '        type ipv6_addr\n'
        '    }\n'
        '    set allowed4 {\n'
        '        type ipv4_addr\n'
        '    }\n'
        '}\n'
    )
    with open(app2.RULES_PATH, 'w', encoding='utf-8') as f:
        f.write(rules_text)

    try:
        # ── 单元级 ────────────────────────────────────────────────
        elems, dropped = app2._format_list_elements(['fe80::1%br-lan'], want6=True)
        check('_format_list_elements 丢弃带 scope-id 的元素',
              elems == [] and dropped == 1,
              f'实际 elems={elems} dropped={dropped}')
        elems, dropped = app2._format_list_elements(['2001:db8::1'], want6=True)
        check('_format_list_elements 仍然接受正常 IPv6',
              elems == ['2001:db8::1'] and dropped == 0, f'实际 {elems}')
        elems, dropped = app2._format_list_elements(['203.0.113.10'], want6=False)
        check('_format_list_elements 仍然接受正常 IPv4',
              elems == ['203.0.113.10'] and dropped == 0, f'实际 {elems}')
        elems, dropped = app2._format_list_elements(['2001:db8::1'], want6=False)
        check('_format_list_elements 仍然按版本分流（IPv6 不进 v4 名单）',
              elems == [] and dropped == 1, f'实际 {elems}')

        # ── 行为级：脏值不许进规则集文件 ───────────────────────────
        lists = {'allowed6': ['fe80::1%br-lan', '2001:db8::1'],
                 'allowed4': ['203.0.113.10']}
        ok = app2._persist_list_elements_to_ruleset(lists)
        with open(app2.RULES_PATH, encoding='utf-8') as f:
            after = f.read()
        check('名单同步进规则集返回成功', ok is True, str(ok))
        check('规则集文件里**没有** scope-id（nft 加载失败的直接原因）',
              '%' not in after,
              str([l for l in after.splitlines() if '%' in l][:3]))
        check('正常 IPv6 仍然写进了规则集', '2001:db8::1' in after)
        check('正常 IPv4 仍然写进了规则集', '203.0.113.10' in after)
        elem_lines = [l.strip() for l in after.splitlines()
                      if l.strip().startswith('elements')]
        check('elements 行形态正常（两行、都是 {...} 包裹）',
              len(elem_lines) == 2
              and all(l.startswith('elements = {') and l.endswith('}')
                      for l in elem_lines),
              str(elem_lines))
        # 规则集文件里除 set 块外的内容不能被改坏（只动 elements 行）
        check('规则集文件的表头没被改坏',
              after.startswith('table inet fw4 {') and 'type ipv6_addr' in after)
    finally:
        shutil.rmtree(d2, ignore_errors=True)

    # ── 1.6 第四个入口：模板引擎回填名单元素 ──────────────────────
    # 这条是「点应用规则」时**生成整份规则集**的路径 ——
    # 也就是说 lists.json 里的一个脏值能让面板从此**每一次 apply 都失败**
    # （`nft -c -f` 语法预检直接挂；预检在 os.replace 之前，
    #   所以已生效的规则不变，但面板失去了对防火墙的控制能力）。
    sec('1.6 行为级：模板引擎回填名单时也要挡住 scope-id')

    te = load_te('c2c')
    tpl = te.load_template()
    out = te._inject_list_elements(tpl, {
        'allowed6': ['fe80::1%br-lan', '2001:db8::1'],
        'allowed4': ['203.0.113.10'],
        'blacklist6': ['fd00::1%eth0'],
    })
    check('模板回填后的规则集里**没有** scope-id',
          '%' not in out,
          str([l for l in out.splitlines() if '%' in l][:3]))
    check('正常 IPv6 仍然回填进模板', '2001:db8::1' in out)
    check('正常 IPv4 仍然回填进模板', '203.0.113.10' in out)
    check('名单占位符没残留在规则集里',
          '# ALLOWED6_ELEMENTS' not in out and '# ALLOWED4_ELEMENTS' not in out
          and '# BLACKLIST6_ELEMENTS' not in out)
    # 单元级：版本分流没被带坏
    only6 = te._inject_list_elements(tpl, {'allowed6': ['2001:db8::1']})
    check('模板回填仍然按版本分流（IPv6 不进 v4 名单）',
          '2001:db8::1' in only6)
    only4 = te._inject_list_elements(tpl, {'allowed4': ['203.0.113.10']})
    check('模板回填的 v4 名单正常', '203.0.113.10' in only4)


# ══════════════════════════════════════════════════════════════════
# 第 2 组：C3 —— restore_config 恢复前必须校验
# ══════════════════════════════════════════════════════════════════
def group_c3():
    sec('2. C3：恢复配置前必须跑 validate_config（否则 0.0.0.0/0 会被恢复）')

    app = load_app('c3')

    d = tempfile.mkdtemp(prefix='nftc3-')
    app.CONFIG_PATH = os.path.join(d, 'config.json')
    backup_path = app.CONFIG_PATH + '.backup'
    client = make_client(app)

    good_cfg = {'panel_allowed_nets': '127.0.0.1/32',
                'lan_subnet4': '127.0.0.1/32',
                'trusted_ip4': '192.168.100.50',
                'router_ip4': '192.168.100.1',
                'auth_token_epoch': 1}

    # ⚠ 先确认会话是有效的。
    #   这一组里所有「应当被拒」的用例都靠 `status >= 400` 判定 ——
    #   一旦会话失效，全部返回 401，全部「通过」⇒ 整组变成假通过。
    #   所以开跑前先探一次，后面每个关键节点再探一次。
    check('会话有效（否则后面的 401 会冒充测试结果）', session_alive(client))

    def write_backup(cfg):
        with open(backup_path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f)

    def read_config():
        with open(app.CONFIG_PATH, encoding='utf-8') as f:
            return json.load(f)

    # ── 2.1 坏备份：panel_allowed_nets 含 0.0.0.0/0 ⇒ 必须拒绝 ──
    bad = dict(good_cfg)
    bad['panel_allowed_nets'] = ['0.0.0.0/0']
    write_backup(bad)
    r = client.post('/api/config/restore')
    body = r.get_json(silent=True) or {}
    check('恢复被拒（0.0.0.0/0 的备份不能恢复）',
          r.status_code >= 400 and body.get('success') is False
          and not is_auth_error(r, body),
          f'实际 {r.status_code} {body.get("message", "")[:60]}')
    check('拒绝消息里说明了「未通过校验」',
          '校验' in str(body.get('message', '')),
          str(body.get('message', ''))[:100])
    check('原配置没被动过（还是 127.0.0.1/32）',
          read_config().get('panel_allowed_nets') == '127.0.0.1/32',
          str(read_config().get('panel_allowed_nets')))

    # ── 2.2 坏备份：trusted_ip4 是**非法值** ⇒ 必须拒绝 ─────────
    # ⚠ 这里刻意用**非法值**而不是空值：
    #    「缺失」会被继承当前配置补上（老版本备份也能回退），
    #    「非法/过宽」才是要拒的 —— 缺失 ≠ 放宽边界。
    bad2 = dict(good_cfg)
    bad2['trusted_ip4'] = 'not-an-ip'
    write_backup(bad2)
    r = client.post('/api/config/restore')
    body = r.get_json(silent=True) or {}
    check('恢复被拒（trusted_ip4 是非法值的备份不能恢复）',
          r.status_code >= 400 and body.get('success') is False
          and not is_auth_error(r, body),
          f'实际 {r.status_code} {body.get("message", "")[:60]}')

    # ── 2.2b 备份里**缺**必填字段 ⇒ 应当能用当前配置补上后恢复 ──
    # 老版本存的备份可能压根没有这些字段 ⇒ 直接判非法 = 连回退都做不了。
    partial = dict(good_cfg)
    partial.pop('trusted_ip4', None)
    partial.pop('router_ip4', None)
    write_backup(partial)
    r = client.post('/api/config/restore')
    body = r.get_json(silent=True) or {}
    check('备份缺必填字段时仍能恢复（继承当前配置的值，而不是判非法）',
          r.status_code == 200 and body.get('success') is True,
          f'实际 {r.status_code} {str(body.get("message", ""))[:70]}')
    check('继承后 trusted_ip4 是当前配置里的值',
          read_config().get('trusted_ip4') == good_cfg['trusted_ip4'],
          str(read_config().get('trusted_ip4')))
    # 恢复完把当前配置补回去，后面的用例继续用 good_cfg 做基准
    with open(app.CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(good_cfg, f)

    # ── 2.2c 当前配置**也**缺这两个字段 ⇒ 用当前**生效值**补上 ──────
    # 场景：设备上压根没写过这两个字段（老版本 / 全新安装）。
    # 此时「当前生效值」就是 DEFAULT_CONFIG 里的值（load_config 就是这么合并的）
    # ⇒ 补上它 = **保持现状**，不是放宽边界 ⇒ 恢复必须成功。
    #
    # ⚠ 判据用 `load_config()` 读**生效值**，不能用原始文件 ——
    #   原始文件里本来就没有这两个字段，读它等于什么也没断言。
    with open(app.CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump({'panel_allowed_nets': '127.0.0.1/32',
                   'lan_subnet4': '127.0.0.1/32',
                   'auth_token_epoch': 1}, f)
    effective_trusted = app.load_config().get('trusted_ip4')
    effective_router = app.load_config().get('router_ip4')
    check('当前配置缺字段时，生效值确实存在（否则这条用例没意义）',
          bool(effective_trusted) and bool(effective_router),
          f'trusted={effective_trusted} router={effective_router}')
    write_backup({'panel_allowed_nets': '127.0.0.1/32',
                  'lan_subnet4': '127.0.0.1/32',
                  'auth_token_epoch': 0})
    r = client.post('/api/config/restore')
    body = r.get_json(silent=True) or {}
    check('当前配置也缺字段时仍能恢复（用当前生效值补上，不是判非法）',
          r.status_code == 200 and body.get('success') is True,
          f'实际 {r.status_code} {str(body.get("message", ""))[:70]}')
    check('补上的 trusted_ip4 等于当前生效值',
          read_config().get('trusted_ip4') == effective_trusted,
          f'落盘={read_config().get("trusted_ip4")} 生效值={effective_trusted}')
    # 恢复当前配置，后面的用例继续用 good_cfg 做基准
    with open(app.CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(good_cfg, f)

    # ── 2.3 坏备份：access_mode 是那个"从未实现"的 knock ────────
    bad3 = dict(good_cfg)
    bad3['access_mode'] = 'knock'
    write_backup(bad3)
    r = client.post('/api/config/restore')
    body = r.get_json(silent=True) or {}
    check('恢复被拒（access_mode=knock 的备份不能恢复）',
          r.status_code >= 400 and body.get('success') is False
          and not is_auth_error(r, body)
          and '校验' in str(body.get('message', '')),
          f'实际 {r.status_code} {body.get("message", "")[:70]}')

    # ── 2.4 好备份 ⇒ 必须仍然能恢复（别把功能改坏了）────────────
    write_backup(good_cfg)
    r = client.post('/api/config/restore')
    body = r.get_json(silent=True) or {}
    check('正常备份仍能恢复（200）',
          r.status_code == 200 and body.get('success') is True
          and not is_auth_error(r, body),
          f'实际 {r.status_code} {body.get("message", "")[:60]}')
    check('恢复后配置内容与备份一致',
          read_config().get('panel_allowed_nets') == '127.0.0.1/32',
          str(read_config().get('panel_allowed_nets')))

    # ── 2.5 既有行为不回归：备份不是 dict ⇒ 仍拒绝 ──────────────
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write('[1,2,3]')
    r = client.post('/api/config/restore')
    body = r.get_json(silent=True) or {}
    check('备份不是配置对象时仍被拒（既有行为没被带坏）',
          r.status_code >= 400 and not is_auth_error(r, body)
          and '不是配置对象' in str(body.get('message', '')),
          f'实际 {r.status_code} {body.get("message", "")[:70]}')

    # ── 2.6 既有行为不回归：epoch 从当前配置继承，不从备份继承 ──
    # 这是 2026-11-08 真机 e2e 发现的：恢复把 epoch 从 1 回退到 0
    # ⇒ 所有旧令牌复活 + 当前会话当场失效。
    cur = read_config()
    cur['auth_token_epoch'] = 7
    with open(app.CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cur, f)
    # ⚠ 改了 epoch 就要重签会话，否则请求全被 401 挡掉 ——
    #   那样这条断言会「因为文件里本来就是 7」而通过 ⇒ 假通过。
    resync_session(client, app)
    stale = dict(good_cfg)
    stale['auth_token_epoch'] = 1
    write_backup(stale)
    r = client.post('/api/config/restore')
    body = r.get_json(silent=True) or {}
    check('这一轮恢复确实执行了（不是 401 蒙过去的）',
          r.status_code == 200 and body.get('success') is True,
          f'实际 {r.status_code} {body.get("message", "")[:60]}')
    check('恢复后 epoch 仍继承当前值（不从备份回退）',
          read_config().get('auth_token_epoch') == 7,
          f'实际 {read_config().get("auth_token_epoch")}')

    shutil.rmtree(d, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════
# 第 3 组：C4 —— 规则集完整备份的权限位
# ══════════════════════════════════════════════════════════════════
def group_c4():
    sec('3. C4：规则集完整备份必须 0600（open() 的权限由 umask 派生 ⇒ 默认 0644）')

    app = load_app('c4')

    d = tempfile.mkdtemp(prefix='nftc4-')
    rules_path = os.path.join(d, '99-custom-rules.nft')
    app.RULES_PATH = rules_path
    backup_path = rules_path + '.backup'

    # ⚠️ umask 必须**显式固定**，否则「权限由 umask 派生」这件事测不准：
    #   umask 022 ⇒ open() 建出来是 0644；umask 077 ⇒ 建出来就是 0600。
    #   若测试机的 umask 恰好是 077，那么「没有 chmod」这个退化**根本测不出来**
    #   （权限照样是 0600，断言照样绿）⇒ 变异 M9 会被误判成漏网。
    #   固定成 022 = 绝大多数发行版的默认值，也让这条断言的前提是显式的。
    old_umask = os.umask(0o022)

    # 桩掉 build_rules 与 subprocess.run：
    #   · build_rules 需要真实配置才能生成规则，这里给一份最小假规则
    #   · subprocess.run 覆盖 nft -c / nft -f / nft list ruleset 三处
    real_build = app.build_rules
    real_run = app.subprocess.run
    app.build_rules = lambda cfg: 'table inet fw4 { }\n'

    def fake_run(cmd, *a, **k):
        return FakeProc(returncode=0, stdout='')

    app.subprocess.run = fake_run
    try:
        check('umask 已固定成 022（保证「权限由 umask 派生」这条前提成立）',
              os.umask(0o022) == 0o022)
        app._apply_ruleset_locked({'china_ip_block': False})
        check('规则集完整备份被创建了', os.path.exists(backup_path))
        if os.path.exists(backup_path):
            mode = stat.S_IMODE(os.stat(backup_path).st_mode)
            check('备份权限是 0600（不是 umask 派生的 0644）',
                  mode == 0o600, oct(mode))
    finally:
        app.build_rules = real_build
        app.subprocess.run = real_run
        os.umask(old_umask)
        shutil.rmtree(d, ignore_errors=True)

    # ── 3.2 退化路径：chmod 失败 ⇒ 文件必须被删掉 ───────────────
    # 为什么必须删：留一个「内容完整但对本地用户可读」的文件，
    # 比没有这个备份更糟 —— 它看起来像备份，实际在漏权限。
    sec('3.2 退化路径：chmod 失败 ⇒ 文件被丢弃，不留漏权限的备份')

    app2 = load_app('c4b')
    d2 = tempfile.mkdtemp(prefix='nftc4b-')
    rules2 = os.path.join(d2, '99-custom-rules.nft')
    app2.RULES_PATH = rules2
    backup2 = rules2 + '.backup'

    real_build2 = app2.build_rules
    real_run2 = app2.subprocess.run
    real_chmod = app2.os.chmod
    app2.build_rules = lambda cfg: 'table inet fw4 { }\n'
    app2.subprocess.run = lambda cmd, *a, **k: FakeProc(returncode=0, stdout='')

    def boom_chmod(path, mode, *a, **k):
        # ⚠ 只让**备份那次** chmod 失败，其余路径走真 chmod ——
        #   否则连规则集本体（.tmp）的权限都收不了口，
        #   测的就不是「备份权限收口失败」这一条了。
        if str(path).endswith('.backup'):
            raise OSError(13, 'Permission denied', str(path))
        return real_chmod(path, mode, *a, **k)

    app2.os.chmod = boom_chmod
    try:
        app2._apply_ruleset_locked({'china_ip_block': False})
        check('chmod 失败时备份文件被删掉了（不留漏权限的文件）',
              not os.path.exists(backup2),
              '还在' if os.path.exists(backup2) else '已删除')
    finally:
        app2.os.chmod = real_chmod
        app2.build_rules = real_build2
        app2.subprocess.run = real_run2
        shutil.rmtree(d2, ignore_errors=True)


def strip_py_comments(src):
    """去掉 Python 注释与 docstring（保留普通字符串字面量里的 #）。

    为什么必须去：注释里会**引用代码原文**（说明「原来怎么错的」），
    不剥掉的话 `indexOf` 那种子串判断会把注释里的字当成真的代码，
    断言方向完全反过来 —— 而且改一次注释就翻车。
    """
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        # 三引号：docstring，整块跳过
        if src[i:i + 3] in ('"""', "'''"):
            q = src[i:i + 3]
            j = src.find(q, i + 3)
            i = (j + 3) if j != -1 else n
            out.append(' ')
            continue
        if c == '#':
            while i < n and src[i] != '\n':
                i += 1
            continue
        if c in ('"', "'"):
            q = c
            out.append(c)
            i += 1
            while i < n:
                if src[i] == '\\' and i + 1 < n:
                    out.append(src[i:i + 2])
                    i += 2
                    continue
                out.append(src[i])
                if src[i] == q:
                    i += 1
                    break
                i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def func_body(src, name):
    """取出某个顶层函数的源码（含 def 行到下一个顶层 def 之前）。"""
    lines = src.split('\n')
    start = None
    for i, l in enumerate(lines):
        if l.startswith('def %s(' % name):
            start = i
            break
    if start is None:
        return None
    for j in range(start + 1, len(lines)):
        if lines[j].startswith('def ') or lines[j].startswith('@'):
            return '\n'.join(lines[start:j])
    return '\n'.join(lines[start:])


# ══════════════════════════════════════════════════════════════════
# 第 4 组：源码不变式（挡「检查写在了错误的位置」）
# ══════════════════════════════════════════════════════════════════
def group_invariants():
    sec('4. 源码不变式：检查必须写在正确的位置')

    app_path = os.path.join(BACKEND, 'app.py')
    with open(app_path, encoding='utf-8') as f:
        raw = f.read()
    clean = strip_py_comments(raw)

    # ── 4.1 C2：scope-id 检查必须真的在两个入口里 ────────────────
    # ⚠ detail 只在**失败时**给信息 —— 早先写成「PASS 也显示缺少」，
    #   读日志的人会以为哪里不对。
    vi = func_body(clean, '_valid_ip')
    ok = vi is not None and "'%' in s" in vi
    check('_valid_ip 的函数体里存在 scope-id 检查', ok,
          '' if ok else ('没读到函数体' if vi is None
                        else '函数体里没有 ' + repr("'%' in s")))
    dv = func_body(clean, '_detect_ip_version')
    ok = dv is not None and "'%' in s" in dv
    check('_detect_ip_version 的函数体里存在 scope-id 检查', ok,
          '' if ok else ('没读到函数体' if dv is None
                        else '函数体里没有 ' + repr("'%' in s")))
    # 第三个入口：名单 → 规则集文件的最后一道闸。
    # 它既不走 _valid_ip 也不走 _detect_ip_version ⇒ 必须单独钉住。
    fe = func_body(clean, '_format_list_elements')
    ok = fe is not None and "'%' in text" in fe
    check('_format_list_elements 的函数体里存在 scope-id 检查', ok,
          '' if ok else ('没读到函数体' if fe is None
                        else '函数体里没有 ' + repr("'%' in text")))
    # 第四个入口在**独立文件**里（模板引擎不 import app.py）。
    te_path = os.path.join(BACKEND, 'template_engine.py')
    with open(te_path, encoding='utf-8') as f:
        te_clean = strip_py_comments(f.read())
    inj = func_body(te_clean, '_inject_list_elements')
    ok = inj is not None and "'%' in s" in inj
    check('template_engine 的 _inject_list_elements 里有 scope-id 检查', ok,
          '' if ok else ('没读到函数体' if inj is None
                        else '函数体里没有 ' + repr("'%' in s")))

    # ── 4.2 C3：校验必须在 replace（落盘）之前 ───────────────────
    rc = func_body(clean, 'restore_config')
    check('restore_config 的函数体里能读到', rc is not None)
    if rc:
        i_call = rc.find('validate_config(restored)')
        i_replace = rc.find('os.replace(tmp_path, CONFIG_PATH)')
        check('restore_config 里调用了 validate_config(restored)',
              i_call != -1, f'位置 {i_call}')
        check('校验发生在落盘（os.replace）**之前**',
              i_call != -1 and i_replace != -1 and i_call < i_replace,
              f'校验@{i_call} 落盘@{i_replace}')
        # 「调用了但结果没用」也要挡住：errs 必须被判
        check('校验结果 errs 必须被判定（if errs:）',
              'if errs:' in rc)
        # 「缺失必填字段」要能被当前配置补上 —— 否则老版本备份连回退都做不了。
        # 这条是**功能**的一部分（不只是漏洞的修补），所以也要钉住。
        check('restore_config 里存在「缺失字段继承当前配置」的逻辑',
              'router_ip4' in rc and 'trusted_ip4' in rc
              and '_current_cfg' in rc)

    # ── 4.3 C4：chmod 必须在 nft 往里写之前 ─────────────────────
    ar = func_body(clean, '_apply_ruleset_locked')
    check('_apply_ruleset_locked 的函数体里能读到', ar is not None)
    if ar:
        i_chmod = ar.find('os.chmod(_rules_backup, 0o600)')
        i_write = ar.find("subprocess.run(['nft', 'list', 'ruleset']")
        check('备份文件有显式 chmod 0600',
              i_chmod != -1, f'位置 {i_chmod}')
        check('chmod 发生在 nft 往备份里写**之前**（不留窗口）',
              i_chmod != -1 and i_write != -1 and i_chmod < i_write,
              f'chmod@{i_chmod} 写入@{i_write}')
        check('备份路径用 RULES_PATH + .backup（不写死绝对路径）',
              "RULES_PATH + '.backup'" in ar
              and '/etc/nftables.d/99-custom-rules.nft.backup' not in ar)


def main():
    print('=' * 66)
    print('C2 / C3 / C4 三处残留 —— 行为级测试')
    print('=' * 66)

    group_c2()
    group_c3()
    group_c4()
    group_invariants()

    print('\n' + '=' * 66)
    print(f'  合计: [PASS] {len(PASS)}   [FAIL] {len(FAIL)}')
    if FAIL:
        print('  失败项:')
        for f in FAIL:
            print('    - ' + f)
    else:
        print('  全部通过')
    print('=' * 66)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
