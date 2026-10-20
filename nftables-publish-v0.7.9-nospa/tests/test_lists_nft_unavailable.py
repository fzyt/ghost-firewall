"""名单端点「nft 不可用」必须与「真故障」区分开的回归测试。

运行:  PYTHONDONTWRITEBYTECODE=1 python3 tests/test_lists_nft_unavailable.py

背景
----
2026-10-20 用户在 Docker 测试环境里点「名单管理」，页面上弹了一条红色提示：

    部分名单读取失败，界面上可能是空的而不是真的没有：
    whitelist（[Errno 2] No such file or directory: 'nft'）；blacklist（同上）

而实际上**预设是正常的**，只有白名单/黑名单读不到 —— 因为 Docker 镜像
**刻意不装 nftables**（规则集是 policy drop 且只认 br-lan/eth1，容器里接口
叫 eth0，两条都不匹配，流量会落到链尾的
`limit rate 2/minute burst 5 packets drop`，发 5 个包容器就把自己锁死）。

问题在于「**环境固有**」和「**真故障**」被混在一起报：
前者每次都这样、且完全无害，后者是真出事了。用户看到红色报错会以为面板坏了。

所以后端给 nft **二进制缺失**单独一个 code：

    FileNotFoundError → 503 + code='NFT_UNAVAILABLE'

前端据此不弹红色 toast，改成在白/黑名单卡片里显示一句说明。

本测试锁住后端这个分支 —— 前端靠它区分，改错了前端会静默失效
（前端那边由 tests/test_lists_partial_failure.js 负责）。
"""
import importlib.util as ilu
import os
import sys
import time
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
sys.path.insert(0, os.path.join(ROOT, 'tests'))
sys.path.insert(0, os.path.join(BACKEND))

PASS, FAIL = [], []


def check(name, ok, detail=''):
    (PASS if ok else FAIL).append(name)
    print(('  ✅ ' if ok else '  ❌ ') + name + (f'  — {detail}' if detail else ''))


def sec(title):
    print(f'\n=== {title} ===')


def load_app():
    spec = ilu.spec_from_file_location('_nftapp_nftunavail', os.path.join(BACKEND, 'app.py'))
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeProc:
    """冒充 subprocess.run 的返回值。"""

    def __init__(self, returncode=0, stdout=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ''


NFT_SET_OUT = """table inet fw4 {
	set allowed4 {
		type ipv4_addr
		flags timeout
		elements = { 203.0.113.10 expires 3h500s }
	}
}
"""


def main():
    app = load_app()
    client = app.app.test_client()

    # 名单端点要登录。直接写 session（面板的判定就是 session['authenticated']
    # 加上世代号与当前一致）—— 走真实 /api/auth/login 会把测试拖进密码文件、
    # 限流落盘那一堆无关依赖里。
    #
    # ⚠️ last_active **必须**写：before_request 里有 idle 超时检查
    # （backend/app.py 的 `session.get('last_active', 0)`），
    # 缺了它 = 0 → time.time() - 0 远大于超时阈值 → 回 AUTH_EXPIRED
    # 「会话过期，请重新登录」。这个坑我自己踩过一次。
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['auth_epoch'] = app._current_token_epoch()
        sess['last_active'] = time.time()

    # ── 1. nft 二进制不存在 ───────────────────────────────────
    sec('1. nft 不存在（FileNotFoundError）→ 503 + code=NFT_UNAVAILABLE')

    def raise_fnf(*a, **k):
        raise FileNotFoundError(2, 'No such file or directory', 'nft')

    real_run = app.subprocess.run
    app.subprocess.run = raise_fnf
    try:
        for ep in ('/api/lists/whitelist', '/api/lists/blacklist'):
            r = client.get(ep)
            body = r.get_json()
            check(f'{ep} 返回 503', r.status_code == 503, f'实际={r.status_code}')
            check(f'{ep} 带 code=NFT_UNAVAILABLE',
                  body.get('code') == 'NFT_UNAVAILABLE', f'实际={body.get("code")}')
            check(f'{ep} success=false', body.get('success') is False)
            check(f'{ep} 有可读的中文说明',
                  'nft' in (body.get('message') or ''),
                  body.get('message') or '(空)')
    finally:
        app.subprocess.run = real_run

    # ── 2. nft 在，但 set 读不出来（returncode != 0）──────────
    # 这不是"nft 不可用"，是"规则集里没有这个 set" —— 200 + 空，不该报错。
    sec('2. nft 在但 set 读不到（returncode != 0）→ 200 + 空，不报错')

    app.subprocess.run = lambda *a, **k: FakeProc(returncode=1, stdout='')
    try:
        for ep in ('/api/lists/whitelist', '/api/lists/blacklist'):
            r = client.get(ep)
            body = r.get_json()
            check(f'{ep} 返回 200', r.status_code == 200, f'实际={r.status_code}')
            check(f'{ep} success=true', body.get('success') is True)
            check(f'{ep} 不带 NFT_UNAVAILABLE',
                  body.get('code') != 'NFT_UNAVAILABLE')
    finally:
        app.subprocess.run = real_run

    # ── 3. 正常读到了 ─────────────────────────────────────────
    sec('3. nft 正常 → 200 + 真实内容')

    app.subprocess.run = lambda *a, **k: FakeProc(returncode=0, stdout=NFT_SET_OUT)
    try:
        r = client.get('/api/lists/whitelist')
        body = r.get_json()
        check('/api/lists/whitelist 返回 200', r.status_code == 200)
        check('/api/lists/whitelist 读到 203.0.113.10',
              '203.0.113.10' in (body.get('allowed4') or {}),
              str(body.get('allowed4')))
        check('/api/lists/whitelist 不带 code', 'code' not in body)
    finally:
        app.subprocess.run = real_run

    # ── 4. 其它异常 → 500，且**不能**冒充 NFT_UNAVAILABLE ──────
    sec('4. 其它异常（超时等）→ 500 通用错误，不许冒充环境固有')

    def raise_timeout(*a, **k):
        raise TimeoutError('nft 超时')

    app.subprocess.run = raise_timeout
    try:
        for ep in ('/api/lists/whitelist', '/api/lists/blacklist'):
            r = client.get(ep)
            body = r.get_json()
            check(f'{ep} 返回 500', r.status_code == 500, f'实际={r.status_code}')
            check(f'{ep} 不带 NFT_UNAVAILABLE（真故障不能被当成环境固有）',
                  body.get('code') != 'NFT_UNAVAILABLE',
                  f'实际={body.get("code")}')
            check(f'{ep} success=false', body.get('success') is False)
    finally:
        app.subprocess.run = real_run

    # ── 5. 写路径：没有 nft 时也要给人能读懂的句子 ───────────
    #
    # 原始实现让 FileNotFoundError 掉进笼统的 `except Exception`，
    # 用户看到的是 "[Errno 2] No such file or directory: 'nft'" ——
    # 那不是给人看的。写路径**仍然要报错**（操作确实没做成），
    # 但必须是能读懂的句子 + 可识别的 code。
    sec('5. 写路径（add/delete/flush）：没有 nft → 503 + NFT_UNAVAILABLE + 可读文案')

    app.subprocess.run = raise_fnf
    try:
        for ep, payload in (
            ('/api/lists/add', {'set_name': 'allowed4', 'ip': '203.0.113.5'}),
            ('/api/lists/delete', {'set_name': 'allowed4', 'ip': '203.0.113.5'}),
            ('/api/lists/flush', {'set_name': 'allowed4'}),
        ):
            r = client.post(ep, json=payload)
            body = r.get_json()
            check(f'{ep} 返回 503', r.status_code == 503, f'实际={r.status_code}')
            check(f'{ep} 带 code=NFT_UNAVAILABLE',
                  body.get('code') == 'NFT_UNAVAILABLE', f'实际={body.get("code")}')
            check(f'{ep} success=false', body.get('success') is False)
            msg = body.get('message') or ''
            check(f'{ep} 文案是人能读懂的（不含原始 errno）',
                  'nft' in msg and 'Errno' not in msg and 'No such file' not in msg,
                  msg)
    finally:
        app.subprocess.run = real_run

    print('\n' + '=' * 60)
    print(f' 合计: ✅ {len(PASS)}   ❌ {len(FAIL)}')
    if FAIL:
        print(' 有失败')
    else:
        print(' 全部通过')
    print('=' * 60)
    return 1 if FAIL else 0


if __name__ == '__main__':
    sys.exit(main())
