#!/usr/bin/env python3
"""真实浏览器验证：「没有 nft 命令」环境下，名单页面的表现必须说得清楚。

**不属于 `tests/run_all.sh`** —— 需要一台**跑着的**面板（本项目默认指向
Docker 测试环境）和本机 firefox。

用法
----
    # 1) 先起面板（见 docker/README.md），再起本地代理
    python3 tests/tools/ui_proxy.py &

    # 2) 跑验证
    NFTWEB_TEST_PASSWORD=TestGW2026 \
    NFTWEB_TEST_URL=http://127.0.0.1:15443/ \
        python3 tests/tools/ui_verify_nft_unavailable.py

验的是什么
----------
2026-10-20 用户实测报了两条：

  ① 进「名单管理」弹一条红色提示「部分名单读取失败…[Errno 2] No such file
     or directory: 'nft'」—— 但其实只是**这台机器没有 nft**（Docker 刻意不装），
     是环境固有，不是故障，不该报红；
  ② 「管理」按钮点不动，是个死按钮。

修完之后必须成立（缺一不可）：

  · 读不到白/黑名单 → **不弹红色 toast**，改在内联说明里讲清楚
  · 写不进名单     → **仍然报错**（操作确实没做成），但必须是**人能读懂的句子**，
                     不能是 `[Errno 2] No such file or directory: 'nft'`
  · 「管理」按钮   → 没了
  · 用户的预设数据 → 一个字都不能动

⚠️ 本脚本**只读 + 点「一键加入」**（那条路在无 nft 环境必然失败，不会写数据），
**不会新增/删除任何预设** —— 用户的测试数据不能被测试脚本污染。
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ui_smoke_marionette import Marionette, PROFILE, FF, URL, PASSWORD  # noqa: E402

SHOT = '/tmp/verify_nft_unavailable.png'


def start_browser():
    subprocess.run(['rm', '-rf', PROFILE], check=False)
    subprocess.run(['mkdir', '-p', PROFILE], check=True)
    with open(PROFILE + '/user.js', 'w') as f:
        f.write('user_pref("marionette.enabled", true);\n')
        f.write('user_pref("network.dangerous_insecure_accept_insecure_certs", true);\n')
        f.write('user_pref("browser.shell.checkDefaultBrowser", false);\n')
        f.write('user_pref("datareporting.policy.dataSubmissionEnabled", false);\n')
        f.write('user_pref("toolkit.telemetry.enabled", false);\n')
    proc = subprocess.Popen(
        [FF, '--headless', '--marionette', '--profile', PROFILE, 'about:blank'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    m = None
    for _ in range(60):
        try:
            m = Marionette()
            break
        except OSError:
            time.sleep(1)
    return proc, m


def main():
    proc, m = start_browser()
    if not m:
        proc.kill()
        print('❌ 连不上 Marionette（2828）')
        return 1

    results = {}
    try:
        m.cmd('WebDriver:NewSession', {'capabilities': {
            'acceptInsecureCerts': True,
            'moz:firefoxOptions': {'args': ['-headless']},
        }})
        m.cmd('WebDriver:SetTimeouts', {'pageLoad': 60000, 'script': 60000,
                                        'implicit': 5000})
        m.cmd('WebDriver:Navigate', {'url': URL})
        time.sleep(2)

        # 登录
        m.script('''
            return fetch('/api/auth/login', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({password: arguments[0]})
            }).then(r => r.text());
        ''', [PASSWORD])
        m.cmd('WebDriver:Navigate', {'url': URL})
        time.sleep(3)

        # 切到「名单管理」
        m.script('''
            const items = Array.from(document.querySelectorAll('button, a, li, div'));
            const hit = items.find(el => {
              const t = (el.textContent || '').trim();
              return t === '名单管理' || t === '名单';
            });
            if (hit) hit.click();
            return !!hit;
        ''')
        time.sleep(4)

        # ── 读路径 ────────────────────────────────────────────
        results['read'] = m.script('''
            const body = document.body.innerText;
            const noteShown = body.includes('当前环境没有 nft 命令');
            const manageBtn = Array.from(document.querySelectorAll('button'))
              .some(b => (b.textContent || '').trim() === '管理');
            return {
              red_toast_shown: body.includes('部分名单读取失败'),
              inline_note_shown: noteShown,
              manage_button_exists: manageBtn,
              empty_preset_shown: body.includes('暂无预设'),
              body_len: body.length
            };
        ''')

        # 记下预设现状（后面要确认一个都没动）
        before = m.script('''
            const rows = Array.from(document.querySelectorAll('*'))
              .filter(el => el.children.length === 0
                && /\\d+\\.\\d+\\.\\d+\\.\\d+/.test(el.textContent || ''));
            return rows.map(r => (r.textContent || '').trim())
                      .filter(t => t.length < 120);
        ''')

        # ── 写路径：点「一键加入」 ────────────────────────────
        clicked = m.script('''
            // ⚠️ 不能用「textContent === '一键加入'」精确匹配：
            // 按钮里有两个 span（"一键加入" 和 "…"），x-show 只是隐藏不删除，
            // textContent 会把两个都算上 → 实际是「一键加入…」。
            const btn = Array.from(document.querySelectorAll('button'))
              .find(b => (b.textContent || '').includes('一键加入'));
            if (!btn) return 'no-button';
            btn.click();
            return 'clicked';
        ''')
        results['write_click'] = clicked
        # ⚠️ toast 3 秒自动消失（frontend/app.js 的 showToast：
        #    setTimeout(() => { this.toast.show = false; }, 3000)）
        #    等太久再去看，就只剩"没弹过"这个假象了。1.2 秒内取样。
        time.sleep(1.2)

        results['write'] = m.script('''
            const body = document.body.innerText;
            // toast 元素本身：x-text="toast.message"，用 x-show 控制显隐
            const toastEl = Array.from(document.querySelectorAll('div'))
              .filter(d => d.offsetParent !== null
                           && (d.getAttribute('x-text') || '') === 'toast.message')
              .map(d => (d.textContent || '').trim());
            return {
              toast_shown: toastEl.length > 0,
              toast_text: toastEl.length ? toastEl[0].slice(0, 200) : '',
              has_readable_msg: body.includes('无法修改防火墙规则集'),
              has_raw_errno: body.includes('Errno') || body.includes('No such file'),
              has_read_msg: body.includes('无法读取防火墙规则集')
            };
        ''')
        m.shot(SHOT)

        # ── 数据没被动过？ ────────────────────────────────────
        after = m.script('''
            const rows = Array.from(document.querySelectorAll('*'))
              .filter(el => el.children.length === 0
                && /\\d+\\.\\d+\\.\\d+\\.\\d+/.test(el.textContent || ''));
            return rows.map(r => (r.textContent || '').trim())
                      .filter(t => t.length < 120);
        ''')
        results['data_untouched'] = (before == after)

    finally:
        try:
            m.cmd('Marionette:Quit', {})
        except Exception:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except Exception:
            proc.kill()

    print('\n▶ 真实浏览器验证结果（无 nft 环境）:')
    print(json.dumps(results, ensure_ascii=False, indent=2))
    print(f'\n✓ 截图: {SHOT}')

    checks = [
        ('读不到时不弹红色 toast', results.get('read', {}).get('red_toast_shown') is False),
        ('内联说明出现', results.get('read', {}).get('inline_note_shown') is True),
        ('「管理」死按钮已删', results.get('read', {}).get('manage_button_exists') is False),
        ('写路径弹出了 toast（操作确实没做成，要让人看见）',
         results.get('write', {}).get('toast_shown') is True),
        ('写路径给出可读句子', results.get('write', {}).get('has_readable_msg') is True),
        ('写路径不再出现原始 errno', results.get('write', {}).get('has_raw_errno') is False),
        ('用户的预设数据一个都没动', results.get('data_untouched') is True),
    ]
    print()
    ok = True
    for name, passed in checks:
        print(('  ✅ ' if passed else '  ❌ ') + name)
        ok = ok and passed
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
