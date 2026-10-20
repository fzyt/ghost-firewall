#!/usr/bin/env python3
"""UI 冒烟测试：用 Firefox 的 Marionette 协议驱动真实浏览器，验证面板 UI。

**不属于 `tests/run_all.sh`** —— 它需要一台**跑着的**面板（本项目默认指向
Docker 测试环境），而且要本机有 firefox。单元/契约测试跑它没有意义。

用法
----
    # 1) 先起面板（见 docker/README.md），再起本地代理
    python3 tests/tools/ui_proxy.py &

    # 2) 跑冒烟测试
    NFTWEB_TEST_PASSWORD=TestGW2026 \
    NFTWEB_TEST_URL=http://127.0.0.1:15443/ \
        python3 tests/tools/ui_smoke_marionette.py

环境变量
--------
    NFTWEB_TEST_PASSWORD  面板密码（默认 TestGW2026，仅 Docker 测试环境用）
    NFTWEB_TEST_URL       面板地址（默认经本地代理的明文地址）
    NFTWEB_TEST_FF        firefox 可执行文件路径


为什么需要这个
--------------
本会话没有内置浏览器能力（mcp_browser 不可用，Connector 目录里也没有浏览器工具），
而 `firefox --screenshot` 只能截**未登录**的登录页 —— 预设列表是登录后才渲染的。

Marionette 是 Firefox 自带的远程控制协议（`--marionette` 打开 2828 端口），
能用「页面内 fetch 登录 → 刷新 → 点导航 → 截图」把**真实渲染**拿到手。

协议格式：`<长度>:<JSON>`，长度是 JSON 的字节数。
"""
import base64
import json
import os
import socket
import subprocess
import sys
import time

PROFILE = '/tmp/ffmarionette'
PORT = 2828
URL = os.environ.get('NFTWEB_TEST_URL', 'http://127.0.0.1:15443/')
PASSWORD = os.environ.get('NFTWEB_TEST_PASSWORD', 'TestGW2026')
FF = os.environ.get('NFTWEB_TEST_FF', '/usr/bin/firefox')


class Marionette:
    def __init__(self, host='127.0.0.1', port=PORT):
        self.sock = socket.create_connection((host, port), timeout=120)
        self.sock.settimeout(120)
        self.buf = b''
        self.msgid = 0
        self._read_packet()          # 握手包：{"applicationType":"gecko",...}

    def _read_packet(self):
        while b':' not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError('连接关闭')
            self.buf += chunk
        head, _, rest = self.buf.partition(b':')
        n = int(head)
        self.buf = rest
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError('连接关闭')
            self.buf += chunk
        body, self.buf = self.buf[:n], self.buf[n:]
        return json.loads(body.decode('utf-8'))

    def cmd(self, name, params=None):
        self.msgid += 1
        payload = json.dumps([0, self.msgid, name, params or {}]).encode('utf-8')
        self.sock.sendall(str(len(payload)).encode() + b':' + payload)
        while True:
            msg = self._read_packet()
            if isinstance(msg, list) and len(msg) >= 4 and msg[0] == 1:
                if msg[1] != self.msgid:
                    continue
                if msg[2]:
                    raise RuntimeError(f'{name} 失败: {msg[2]}')
                return msg[3]

    def script(self, src, args=None):
        r = self.cmd('WebDriver:ExecuteScript',
                     {'script': src, 'args': args or [], 'newSandbox': False})
        return r.get('value') if isinstance(r, dict) else r

    def shot(self, path):
        r = self.cmd('WebDriver:TakeScreenshot', {'full': True, 'hash': False})
        b64 = r.get('value') if isinstance(r, dict) else r
        with open(path, 'wb') as f:
            f.write(base64.b64decode(b64))
        return path


def main():
    subprocess.run(['rm', '-rf', PROFILE], check=False)
    subprocess.run(['mkdir', '-p', PROFILE], check=True)
    with open(PROFILE + '/user.js', 'w') as f:
        f.write('user_pref("marionette.enabled", true);\n')
        f.write('user_pref("network.dangerous_insecure_accept_insecure_certs", true);\n')
        f.write('user_pref("browser.shell.checkDefaultBrowser", false);\n')
        f.write('user_pref("datareporting.policy.dataSubmissionEnabled", false);\n')
        f.write('user_pref("toolkit.telemetry.enabled", false);\n')
        f.write('user_pref("browser.startup.homepage_override.mstone", "ignore");\n')

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
    if not m:
        proc.kill()
        print('❌ 连不上 Marionette（2828）')
        return 1

    try:
        m.cmd('WebDriver:NewSession', {'capabilities': {
            'acceptInsecureCerts': True,
            'moz:firefoxOptions': {'args': ['-headless']},
        }})
        print('✓ Marionette 会话建立')

        m.cmd('WebDriver:SetTimeouts', {'pageLoad': 60000, 'script': 60000,
                                        'implicit': 5000})
        m.cmd('WebDriver:Navigate', {'url': URL})
        time.sleep(2)
        print('✓ 已打开面板:', m.script('return document.title'))

        # 登录（页面内同源 fetch，Cookie 会被浏览器正常存下）
        # ⚠️ Marionette 的 ExecuteScript 不允许顶层 await，要返回 Promise
        r = m.script('''
            return fetch('/api/auth/login', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({password: arguments[0]})
            }).then(res => res.text().then(t => ({status: res.status, body: t})));
        ''', [PASSWORD])
        print('✓ 登录:', json.dumps(r, ensure_ascii=False)[:160])

        # 刷新，让 SPA 以已登录状态初始化
        m.cmd('WebDriver:Navigate', {'url': URL})
        time.sleep(3)

        # 切到「名单管理」页签（触发 loadLists()）
        clicked = m.script('''
            const items = Array.from(document.querySelectorAll('button, a, li, div'));
            const hit = items.find(el => {
              const t = (el.textContent || '').trim();
              return t === '名单管理' || t === '名单';
            });
            if (hit) { hit.click(); return 'clicked: ' + hit.textContent.trim(); }
            return 'not-found';
        ''')
        print('✓ 切页签:', clicked)
        time.sleep(4)

        # 读出真实渲染结果
        state = m.script('''
            const body = document.body.innerText;
            const emptyShown = Array.from(document.querySelectorAll('div')).some(d => {
              const t = (d.textContent || '').trim();
              return t.startsWith('暂无预设') && d.offsetParent !== null;
            });
            return {
              empty_visible: emptyShown,
              has_203: body.includes('203.0.113.10'),
              has_198: body.includes('198.51.100.77'),
              has_label1: body.includes('测试预设'),
              has_label2: body.includes('docker测试'),
              has_toast: body.includes('部分名单读取失败'),
              body_len: body.length
            };
        ''')
        print('\n▶ 真实浏览器渲染结果:')
        print(json.dumps(state, ensure_ascii=False, indent=2)[:1400])

        m.shot('/tmp/panel_lists.png')
        print('\n✓ 截图: /tmp/panel_lists.png')

        # ── 走一遍用户原话路径：新增预设 → 列表里立刻出现 ──────
        print('\n▶ 用户原话路径：「新增预设」→ 列表里立刻显示')
        opened = m.script('''
            const btn = Array.from(document.querySelectorAll('button'))
              .find(b => (b.textContent || '').trim() === '+ 新增预设');
            if (!btn) return 'no-button';
            btn.click();
            return 'clicked';
        ''')
        time.sleep(2)
        print('  打开弹窗:', opened)

        filled = m.script('''
            const setVal = (el, v) => {
              const setter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value').set;
              setter.call(el, v);
              el.dispatchEvent(new Event('input', {bubbles: true}));
            };
            const label = document.querySelector('input[x-model="presetEditing.label"]');
            const ip = document.querySelector('input[x-model="presetEditing.ip"]');
            if (!label || !ip) return 'no-inputs';
            setVal(label, '浏览器实测');
            setVal(ip, '203.0.113.99');
            return 'filled';
        ''')
        time.sleep(1)
        print('  填表:', filled)

        saved = m.script('''
            const btn = Array.from(document.querySelectorAll('button'))
              .find(b => (b.textContent || '').trim() === '保存');
            if (!btn) return 'no-save';
            btn.click();
            return 'clicked';
        ''')
        time.sleep(3)
        print('  点保存:', saved)

        after = m.script('''
            const body = document.body.innerText;
            return {
              new_label_shown: body.includes('浏览器实测'),
              new_ip_shown: body.includes('203.0.113.99'),
              old_still_shown: body.includes('203.0.113.10'),
              count_presets: (body.match(/203\\.0\\.113|198\\.51\\.100/g) || []).length
            };
        ''')
        print('  新增后:', json.dumps(after, ensure_ascii=False))
        m.shot('/tmp/panel_after_add.png')
        print('  截图: /tmp/panel_after_add.png')
        return 0
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


if __name__ == '__main__':
    sys.exit(main())
