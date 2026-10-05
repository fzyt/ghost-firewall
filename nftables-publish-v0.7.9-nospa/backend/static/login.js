/* 登录页逻辑。独立成文件是为了让 CSP 能用 script-src 'self' 严格禁止内联脚本。 */
(function () {
  'use strict';

  var form = document.getElementById('form');
  var pw = document.getElementById('pw');
  var msg = document.getElementById('msg');
  var btn = document.getElementById('submit');
  var devEl = document.getElementById('device');

  /* ── next 参数防开放重定向 ──────────────────────────────
   * 只接受站内相对路径 `/foo`。
   * 拒绝 `//evil.com`（协议相对）、拒绝带 scheme 的、拒绝反斜杠
   * （部分浏览器会把 `/\evil.com` 归一成 `//evil.com`）。 */
  function safeNext() {
    var raw = new URLSearchParams(location.search).get('next') || '/';
    if (raw.charAt(0) !== '/') return '/';
    if (raw.charAt(1) === '/') return '/';
    if (raw.indexOf('\\') !== -1) return '/';
    if (/^[a-z][a-z0-9+.-]*:/i.test(raw)) return '/';
    return raw;
  }

  function say(text, kind) {
    msg.textContent = text;
    msg.className = 'msg' + (kind ? ' ' + kind : '');
    msg.hidden = !text;
  }

  function busy(on) {
    btn.disabled = on;
    btn.textContent = on ? '验证中…' : '进入';
  }

  /* 已登录（或内网豁免）就别停在登录页 */
  window.DevFingerprint.fetch('/auth/status', { method: 'GET' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d && (d.authenticated || d.via === 'lan-bypass')) {
        location.replace(safeNext());
      }
    })
    .catch(function () { /* 探测失败就老实显示登录表单 */ });

  window.DevFingerprint.get().then(function (fp) {
    if (!fp) { devEl.parentNode.hidden = true; return; }
    devEl.textContent = '设备标识 ' + fp.slice(0, 8);
  });

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var password = pw.value;
    if (!password) { say('请输入密码', 'warn'); pw.focus(); return; }

    say('');
    busy(true);

    window.DevFingerprint.fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: password })
    })
      .then(function (r) {
        return r.json().then(function (j) { return { s: r.status, j: j }; });
      })
      .then(function (res) {
        if (res.s === 200 && res.j && res.j.success) {
          say('验证通过，正在进入…', 'ok');
          location.replace(safeNext());
          return;
        }
        var code = (res.j && res.j.code) || '';
        if (res.s === 429 || code === 'RATE_LIMITED') {
          say('失败次数过多，已锁定，请稍后再试', 'err');
        } else if (res.s === 403 || code === 'BAD_ORIGIN') {
          say('请求来源不被信任，请直接访问本网关地址', 'err');
        } else if (res.j && typeof res.j.remaining === 'number') {
          say('密码错误' + (res.j.remaining > 0 ? '，还可尝试 ' + res.j.remaining + ' 次' : ''), 'err');
        } else {
          say((res.j && res.j.message) || '验证失败', 'err');
        }
        pw.value = '';
        pw.focus();
        busy(false);
      })
      .catch(function () {
        say('网络异常，请检查连接后重试', 'err');
        busy(false);
      });
  });
})();
