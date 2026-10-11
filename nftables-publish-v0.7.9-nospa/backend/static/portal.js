/* 门户页逻辑。独立成文件以配合 CSP script-src 'self'。 */
(function () {
  'use strict';

  var main = document.getElementById('main');
  var empty = document.getElementById('empty');
  var who = document.getElementById('who');
  var timer = document.getElementById('timer');
  var left = document.getElementById('left');
  var tick = null;
  var deadline = 0;

  function goLogin() {
    location.replace('/auth/login?next=' + encodeURIComponent(
      location.pathname + location.search));
  }

  function fmt(sec) {
    if (sec < 0) sec = 0;
    var m = Math.floor(sec / 60), s = sec % 60;
    return (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
  }

  function paint(sec) {
    left.textContent = fmt(sec);
    timer.className = 'pill' + (sec <= 60 ? ' crit' : (sec <= 300 ? ' low' : ''));
  }

  function startCountdown(sec) {
    deadline = Math.floor(Date.now() / 1000) + sec;
    paint(sec);
    timer.hidden = false;
    if (tick) clearInterval(tick);
    tick = setInterval(function () {
      var s = deadline - Math.floor(Date.now() / 1000);
      if (s <= 0) {
        clearInterval(tick);
        paint(0);
        goLogin();
        return;
      }
      paint(s);
    }, 1000);
  }

  /* 全部用 textContent 拼 DOM，不拼 innerHTML ——
   * 服务名是用户自己配的，但门户页没必要给它任何 HTML 解释能力。 */
  function card(s) {
    var a = document.createElement('a');
    a.className = 'tile';
    a.href = s.path + '/';

    var ico = document.createElement('div');
    ico.className = 'ico';
    ico.textContent = s.icon || '◆';

    var nm = document.createElement('div');
    nm.className = 'nm';
    nm.textContent = s.name || s.path;

    var pt = document.createElement('div');
    pt.className = 'pt';
    pt.textContent = s.path;

    var tg = document.createElement('span');
    tg.className = 'tag ' + (s.public ? 'pub' : 'lan');
    tg.textContent = s.public ? '公网 · 需认证' : '仅内网';

    a.appendChild(ico); a.appendChild(nm); a.appendChild(pt); a.appendChild(tg);
    return a;
  }

  function render(services) {
    main.textContent = '';
    if (!services || !services.length) { empty.hidden = false; return; }
    services.forEach(function (s) { main.appendChild(card(s)); });
  }

  function loadServices() {
    return window.DevFingerprint.fetch('/auth/portal', { method: 'GET' })
      .then(function (r) {
        if (r.status === 401) { goLogin(); throw new Error('unauth'); }
        return r.json();
      })
      .then(function (j) { render(j && j.services); })
      .catch(function () { /* 已跳转登录或网络异常，保持空态 */ });
  }

  function load() {
    window.DevFingerprint.fetch('/auth/status', { method: 'GET' })
      .then(function (r) { return r.json().then(function (j) { return { s: r.status, j: j }; }); })
      .then(function (res) {
        var d = res.j || {};
        if (!d.authenticated) { goLogin(); return; }

        // 判据是「有没有会话倒计时」，不是「走的哪条认证路」。
        // 后端不再返回 via=lan-bypass（那等于把内网豁免这套机制讲给
        // 任何能连到这里的人听），expires_in 在不在就是等价的信号。
        if (typeof d.expires_in === 'number') {
          who.textContent = '已登录为 ' + (d.user || '-') +
            (d.device_id ? ' · 设备 ' + String(d.device_id).slice(0, 8) : '');
          startCountdown(d.expires_in);
        } else {
          who.textContent = '内网来源 · 免认证访问';
          timer.hidden = true;
          if (tick) clearInterval(tick);
        }
        return loadServices();
      })
      .catch(function () { goLogin(); });
  }

  document.getElementById('logout').addEventListener('click', function () {
    window.DevFingerprint.fetch('/auth/logout', { method: 'POST' })
      .catch(function () {})
      .then(function () {
        if (tick) clearInterval(tick);
        location.replace('/auth/login');
      });
  });

  /* 页面从后台切回来时重新对账：倒计时可能因系统休眠而不准，
   * 问服务端比本地算更可信。 */
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible' && !timer.hidden) load();
  });

  load();
})();
