"""配置归属与版本闸 —— 回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_config_ownership.py

2026-10-21 .1 真机事故的根因：**POST /api/config 整份覆盖 + 前端陈旧快照**。

    13:20:31  .110  GET  /api/config                    ← 快照：0 规则 0 证书
    13:41:37  .105  POST /api/reverse-proxy/rules       ← 建 rp_001
    13:42:01  .105  PUT  rp_001 + POST /rules           ← 磁盘 2 条规则
    13:42:38  .105  upload + set-default                ← 磁盘 2 条规则 + 1 张阿里云证书
    14:06:22  .110  POST /api/config                    ← 带 13:20 的旧快照
                                                            ⇒ 磁盘变成 0 条 0 张
    14:12 现场：主文件 0 规则 0 证书、.backup 2 规则 1 证书
    （.backup 是 save_config 落盘前拷的 ⇒ 那段时间里唯一的写者就是那一次 POST）

前端之所以会带旧快照，是因为它把整份 config（含 reverse_proxy）原样回传，
而反代页只更新 this.rp、**从不**回写 this.config.reverse_proxy
（`grep reverse_proxy frontend/` 命中 0 处）。

这个文件把三道防线钉住：
  1. /api/config **无条件**不收 reverse_proxy（主防线）
  2. config_rev 版本闸：快照过期就 409 拒收（纵深防御，挡住将来新增的字段）
  3. 上传证书 / 设默认证书必须真的下发 nginx（否则「传了不生效」）
外加两条相邻缺陷：_migrate_rp_rules 保留 created_at、损坏配置不再被删除。
"""
import importlib.util as ilu
import io
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.abspath(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def load_app():
    spec = ilu.spec_from_file_location('_nftapp_cfgown', os.path.join(BACKEND, 'app.py'))
    m = ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mod = load_app()

print('=' * 74)
print('配置归属与版本闸回归测试（2026-10-21 .1 事故）')
print('=' * 74)

# ── 公共脚手架 ───────────────────────────────────────────────────────────
TD = tempfile.mkdtemp()
CFG = os.path.join(TD, 'config.json')
SSL_DIR = os.path.join(TD, 'ssl')

# 系统相关的两个：换证书时nginx 要 reload、规则要下发 nft。
# 这里是纯逻辑测试，一律替换掉，不碰真机。
deploy_calls = []
ruleset_calls = []


def fake_deploy(config=None):
    deploy_calls.append(config)
    return True, 'ok'


def fake_ruleset(config=None):
    ruleset_calls.append(config)
    return True, 'ok'


ORIG = {
    'CONFIG_PATH': mod.CONFIG_PATH,
    'RULES_PATH': mod.RULES_PATH,
    'NGINX_SSL_DIR': mod.NGINX_SSL_DIR,
    '_deploy_all_rules': mod._deploy_all_rules,
    '_apply_ruleset': mod._apply_ruleset,
    '_luci_actual_state': mod._luci_actual_state,
    '_apply_luci_toggle': mod._apply_luci_toggle,
    '_gateway_port_alive': mod._gateway_port_alive,
    '_cert_key_pair_ok': mod._cert_key_pair_ok,
    '_get_cert_expiry': mod._get_cert_expiry,
    '_harden_key_for_nginx_worker': mod._harden_key_for_nginx_worker,
}
HOOKS = list(mod.app.before_request_funcs[None])


def base_config(**extra):
    """一份合法的基础配置（含一条反代规则 + 一张证书由调用方追加）"""
    cfg = dict(mod.DEFAULT_CONFIG)
    cfg['trusted_ip4'] = '192.168.100.1'
    cfg['luci_enabled'] = False
    cfg.update(extra)
    return cfg


def write_config(cfg):
    with open(CFG, 'w') as f:
        json.dump(cfg, f, ensure_ascii=False)


def read_config():
    with open(CFG) as f:
        return json.load(f)


def make_client():
    c = mod.app.test_client()
    with c.session_transaction() as sess:
        sess['authenticated'] = True
        sess['login_time'] = 9e9
    return c


mod.CONFIG_PATH = CFG
mod.RULES_PATH = os.path.join(TD, 'no-such-rules.nft')
mod.NGINX_SSL_DIR = SSL_DIR
mod._deploy_all_rules = fake_deploy
mod._apply_ruleset = fake_ruleset
mod._luci_actual_state = lambda: False
mod._apply_luci_toggle = lambda enabled: (True, 'ok')
mod._gateway_port_alive = lambda port=None, config=None: True
mod._cert_key_pair_ok = lambda cert_path, key_path: (True, '')
mod._get_cert_expiry = lambda path: ('2027-01-16T00:00:00+08:00', 88)
mod._harden_key_for_nginx_worker = lambda path: None
mod.app.before_request_funcs[None] = []

try:
    # ── 1. 主防线：/api/config 绝不收 reverse_proxy ───────────────────────
    sec('1. POST /api/config 不收 reverse_proxy（.1 事故原样复现）')
    write_config(base_config(reverse_proxy={
        'rules': [], 'certificates': [], 'settings': {}}))
    client = make_client()

    # ① 前端在「页面打开时」拿到的那份快照（此刻磁盘上还没有反代数据）
    stale = client.get('/api/config').get_json()
    check('GET /api/config 返回 config_rev',
          bool(stale.get('config_rev')), f"config_rev={stale.get('config_rev')!r}")

    # ② 用户在反代页建规则 + 传证书（走的是反代自己的端点）
    r = client.post('/api/reverse-proxy/rules', json={
        'name': 'nas', 'path_prefix': '/nas',
        'target_address': '192.168.100.11:8096', 'target_protocol': 'http',
        'public_access': False})
    check('反代端点建规则成功', r.status_code == 200,
          f'status={r.status_code} body={r.get_json()}')
    r = client.post('/api/reverse-proxy/rules', json={
        'name': 'siy', 'path_prefix': '/siy',
        'target_address': '192.168.100.12:8095', 'target_protocol': 'http',
        'public_access': False})
    check('再建一条规则成功', r.status_code == 200, f'status={r.status_code}')
    r = client.post('/api/reverse-proxy/certificates/upload', data={
        'domain': 'fzyto.top',
        'cert_file': (io.BytesIO(b'-----BEGIN CERTIFICATE-----\nX\n'), 'c.pem'),
        'key_file': (io.BytesIO(b'-----BEGIN PRIVATE KEY-----\nX\n'), 'k.pem')})
    check('上传证书成功', r.status_code == 200, f'status={r.status_code}')
    cert_id = (r.get_json().get('data') or {}).get('cert_id')
    r = client.post(f'/api/reverse-proxy/certificates/{cert_id}/set-default')
    check('设为默认证书成功', r.status_code == 200, f'status={r.status_code}')

    on_disk = read_config()['reverse_proxy']
    check('磁盘上此刻是 2 条规则 + 1 张证书',
          len(on_disk.get('rules') or []) == 2
          and len(on_disk.get('certificates') or []) == 1,
          f"rules={len(on_disk.get('rules') or [])} "
          f"certs={len(on_disk.get('certificates') or [])}")

    # ③ 用户没刷新页面，回到配置页点「保存」——带的是 ① 那份旧快照
    r = client.post('/api/config', json={**stale, 'confirm': True})
    check('保存返回 200', r.status_code == 200,
          f'status={r.status_code} body={r.get_json()}')

    after = read_config()['reverse_proxy']
    check('★ 反代规则没被清空（2 条还在）',
          len(after.get('rules') or []) == 2,
          f"实际={len(after.get('rules') or [])}")
    check('★ 证书没被清空（1 张还在）',
          len(after.get('certificates') or []) == 1,
          f"实际={len(after.get('certificates') or [])}")
    check('★ 默认证书没被抹掉',
          (after.get('settings') or {}).get('default_cert_id') == cert_id,
          f"实际={(after.get('settings') or {}).get('default_cert_id')!r} 期望={cert_id!r}")

    # ④ 显式传一个空 reverse_proxy 也一样不能覆盖
    r = client.post('/api/config', json={
        'reverse_proxy': {'rules': [], 'certificates': [], 'settings': {}},
        'confirm': True})
    after = read_config()['reverse_proxy']
    check('★ 显式传空 reverse_proxy 也不能覆盖磁盘',
          len(after.get('rules') or []) == 2
          and len(after.get('certificates') or []) == 1,
          f"rules={len(after.get('rules') or [])} "
          f"certs={len(after.get('certificates') or [])}")

    # ⑤ 响应里要说明「反代字段被忽略了」
    body = client.post('/api/config', json={
        'reverse_proxy': {'rules': []}, 'confirm': True}).get_json()
    check('响应里报告了被忽略的反代字段',
          (body.get('data') or {}).get('ignored_rp_fields') == ['reverse_proxy'],
          f"ignored_rp_fields={(body.get('data') or {}).get('ignored_rp_fields')}")

    # ⑥ config_rev 绝不能落盘
    check('config_rev 没有落盘',
          'config_rev' not in read_config(),
          f"落盘的键里含 config_rev={('config_rev' in read_config())}")

    # ── 2. 版本闸 ────────────────────────────────────────────────────────
    sec('2. config_rev 版本闸：快照过期就拒收')
    client = make_client()
    fresh = client.get('/api/config').get_json()
    rev = fresh.get('config_rev')
    check('GET 带回的 config_rev 非空', bool(rev), f'rev={rev!r}')

    # 磁盘上的配置被别人改了一处（非反代子树）
    cfg = read_config()
    cfg['whitelist_timeout'] = 99999
    write_config(cfg)

    r = client.post('/api/config', json={**fresh, 'confirm': True})
    body = r.get_json()
    check('过期快照被拒：409', r.status_code == 409, f'status={r.status_code}')
    check('错误码是 CONFIG_STALE', body.get('code') == 'CONFIG_STALE',
          f"code={body.get('code')}")
    check('拒收时没有落盘',
          read_config()['whitelist_timeout'] == 99999,
          f"落盘={read_config()['whitelist_timeout']}")

    # 拿新快照再存 → 放行
    fresh2 = client.get('/api/config').get_json()
    r = client.post('/api/config', json={**fresh2, 'whitelist_timeout': 12345,
                                         'confirm': True})
    check('新快照放行：200', r.status_code == 200, f'status={r.status_code}')
    check('新值落盘', read_config()['whitelist_timeout'] == 12345,
          f"落盘={read_config()['whitelist_timeout']}")

    # 保存成功后返回的新版本号必须能连着用（连点两次保存不该撞 409）
    new_rev = ((r.get_json().get('data') or {}).get('config_rev'))
    check('保存响应里有新的 config_rev', bool(new_rev), f'rev={new_rev!r}')
    r2 = client.post('/api/config', json={**fresh2, 'whitelist_timeout': 12346,
                                           'config_rev': new_rev, 'confirm': True})
    check('用新版本号再存一次：200', r2.status_code == 200,
          f'status={r2.status_code} body={r2.get_json()}')

    # 不带 config_rev 的调用（curl / 第三方脚本）不拦
    r = client.post('/api/config', json={'log_size': 512, 'confirm': True})
    check('不带 config_rev 仍然放行（向后兼容）', r.status_code == 200,
          f'status={r.status_code} body={r.get_json()}')

    # 反代页的写操作**不能**让配置页的快照失效
    # （reverse_proxy 不参与版本号计算 —— 否则改一条规则就莫名 409）
    fresh3 = client.get('/api/config').get_json()
    r = client.post('/api/reverse-proxy/rules', json={
        'name': 'ght', 'path_prefix': '/ght',
        'target_address': '192.168.100.13:3000', 'target_protocol': 'http',
        'public_access': False})
    check('反代端点加规则成功', r.status_code == 200, f'status={r.status_code}')
    r = client.post('/api/config', json={**fresh3, 'confirm': True})
    check('★ 反代页改过之后，配置页用原快照保存仍然放行',
          r.status_code == 200, f'status={r.status_code} body={r.get_json()}')

    # ── 3. 预览必须与实际保存一致 ────────────────────────────────────────
    sec('3. preview-changes 忽略 reverse_proxy（预览 = 实际会保存的内容）')
    client = make_client()
    snapshot = client.get('/api/config').get_json()
    # 用间谍函数抓「预览实际拿去生成规则的那份 config」——
    # 源码 grep 只能证明代码长什么样，抓不到它到底传了什么进去。
    captured = []
    orig_build = mod.build_rules
    mod.build_rules = lambda cfg: (captured.append(cfg), orig_build(cfg))[1]
    try:
        r = client.post('/api/rules/preview-changes', json={'proposed': {
            **snapshot,
            'reverse_proxy': {'rules': [], 'certificates': [], 'settings': {}},
        }})
    finally:
        mod.build_rules = orig_build
    check('预览返回 200', r.status_code == 200, f'status={r.status_code}')
    check('★ 预览用的 reverse_proxy 来自磁盘，不是前端那份空快照',
          bool(captured) and len((captured[0].get('reverse_proxy') or {}).get('rules') or []) == 3,
          f"预览看到的规则数="
          f"{len((captured[0].get('reverse_proxy') or {}).get('rules') or []) if captured else 'N/A'}")
    d = r.get_json().get('data') or {}
    # 预览算出来的规则必须与「真正保存后」的规则一致：
    # 如果预览用了前端的空 reverse_proxy，而保存时用磁盘上的，
    # 两者就会不一致 —— 用户看到的变更是假的。
    r2 = client.post('/api/config', json={**snapshot, 'confirm': True})
    check('预览后保存也是 200', r2.status_code == 200, f'status={r2.status_code}')
    check('保存后规则数据没丢',
          len(read_config()['reverse_proxy'].get('rules') or []) == 3,
          f"实际={len(read_config()['reverse_proxy'].get('rules') or [])}")

    # ── 4. 证书上传 / 设默认必须真的下发 nginx ──────────────────────────
    sec('4. 证书变更必须触发部署（.1 上「传了证书不生效」的根因）')
    deploy_calls.clear()
    client = make_client()
    r = client.post('/api/reverse-proxy/certificates/upload', data={
        'domain': 'example.com',
        'cert_file': (io.BytesIO(b'-----BEGIN CERTIFICATE-----\nX\n'), 'c.pem'),
        'key_file': (io.BytesIO(b'-----BEGIN PRIVATE KEY-----\nX\n'), 'k.pem')})
    check('上传证书成功', r.status_code == 200, f'status={r.status_code}')
    check('★ 上传证书触发了部署', len(deploy_calls) >= 1,
          f'deploy_calls={len(deploy_calls)}')
    new_cert = (r.get_json().get('data') or {}).get('cert_id')
    check('上传响应里带 nginx_reloaded',
          (r.get_json().get('data') or {}).get('nginx_reloaded') is True,
          f"nginx_reloaded={(r.get_json().get('data') or {}).get('nginx_reloaded')}")

    deploy_calls.clear()
    r = client.post(f'/api/reverse-proxy/certificates/{new_cert}/set-default')
    check('设默认成功', r.status_code == 200, f'status={r.status_code}')
    check('★ 设默认触发了部署', len(deploy_calls) >= 1,
          f'deploy_calls={len(deploy_calls)}')
    check('★ 设默认后 default_cert_id 落盘',
          (read_config()['reverse_proxy'].get('settings') or {}).get('default_cert_id')
          == new_cert)

    # ── 5. _migrate_rp_rules 必须保留 created_at ───────────────────────
    sec('5. _migrate_rp_rules 保留 created_at')
    src = open(os.path.join(BACKEND, 'app.py'), encoding='utf-8').read()
    check('白名单里列了 created_at',
          '"created_at": r.get("created_at", "")' in src,
          '漏了它，每次 load→save 都会抹掉这个时间戳')
    migrated = mod._migrate_rp_rules({'reverse_proxy': {'rules': [{
        'id': 'rp_001', 'name': 'nas', 'path_prefix': '/nas',
        'target_address': '192.168.100.11:8096',
        'created_at': '2026-10-21T13:41:37+08:00',
    }]}})
    got = migrated['reverse_proxy']['rules'][0].get('created_at')
    check('迁移后 created_at 还在', got == '2026-10-21T13:41:37+08:00', f'实际={got!r}')

    # ── 6. 损坏的配置不再被删除 ──────────────────────────────────────────
    sec('6. load_config 损坏兜底：移走而不是删除')
    broken_cfg = os.path.join(TD, 'broken.json')
    with open(broken_cfg, 'w') as f:
        f.write('{"trusted_ip4": "192.168.100.1", ')   # 截断的 JSON
    mod.CONFIG_PATH = broken_cfg
    mod._LAST_LOAD_ERROR = None
    res = mod.load_config()
    check('损坏时返回默认值（UI 还能用）', isinstance(res, dict) and res)
    check('★ 损坏原文件被**改名移走**（.broken.*），不是「复制一份再删原件」',
          not os.path.exists(broken_cfg)
          and any(n.startswith('broken.json.broken.') for n in os.listdir(TD)),
          f"目录={os.listdir(TD)}")
    moved = [n for n in os.listdir(TD) if n.startswith('broken.json.broken.')]
    check('★ 现场内容被完整保留下来（可人工修复）',
          bool(moved)
          and open(os.path.join(TD, moved[0])).read() == '{"trusted_ip4": "192.168.100.1", ',
          f"移走的文件={moved}")
    check('损坏状态被记下来（写盘会被拒）',
          mod._config_corrupted()[0] is True,
          f"corrupted={mod._config_corrupted()}")
    # 移走之后，"曾经配过"这件事必须还能被认出来。
    # RULES_PATH 指向临时目录里一个不存在的文件，把本机上的真机产物排除掉，
    # 否则这条断言会因为「碰巧存在历史产物」而假通过。
    mod.CONFIG_PATH = broken_cfg
    check('★ 移走之后仍判定为「配过又丢」（不会当成全新安装）',
          mod._config_lost_after_setup() is True,
          f"_config_lost_after_setup()={mod._config_lost_after_setup()}")
    # 对照：真正全新安装（没有任何历史产物）仍然判 False ——
    # 否则所有新机器都会被当成「配置丢了」而拒绝用默认值。
    fresh_dir = os.path.join(TD, 'fresh')
    os.makedirs(fresh_dir, exist_ok=True)
    mod.CONFIG_PATH = os.path.join(fresh_dir, 'config.json')
    check('对照：全新安装仍判定为「没配过」（不误报）',
          mod._config_lost_after_setup() is False,
          f"_config_lost_after_setup()={mod._config_lost_after_setup()}")

finally:
    mod.CONFIG_PATH = ORIG['CONFIG_PATH']
    mod.RULES_PATH = ORIG['RULES_PATH']
    mod.NGINX_SSL_DIR = ORIG['NGINX_SSL_DIR']
    mod._deploy_all_rules = ORIG['_deploy_all_rules']
    mod._apply_ruleset = ORIG['_apply_ruleset']
    mod._luci_actual_state = ORIG['_luci_actual_state']
    mod._apply_luci_toggle = ORIG['_apply_luci_toggle']
    mod._gateway_port_alive = ORIG['_gateway_port_alive']
    mod._cert_key_pair_ok = ORIG['_cert_key_pair_ok']
    mod._get_cert_expiry = ORIG['_get_cert_expiry']
    mod._harden_key_for_nginx_worker = ORIG['_harden_key_for_nginx_worker']
    mod.app.before_request_funcs[None] = HOOKS
    shutil.rmtree(TD, ignore_errors=True)

print()
print(f'  合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
if FAIL:
    for name in FAIL:
        print(f'  ❌ {name}')
    sys.exit(1)
print('  全部通过')
