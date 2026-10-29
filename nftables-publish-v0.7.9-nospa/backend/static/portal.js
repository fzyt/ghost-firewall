/* 门户页逻辑。独立成文件以配合 CSP script-src 'self'。
 *
 * 2026-10-21 视觉重做时只动了「呈现层」：
 *   · 服务卡片逐个入场（CSS nth-child，不靠 JS 设 style ——
 *     CSP style-src 'self' 会拦 HTML 的 style="..." 属性）
 *   · 点卡片 / 点退出时播一次「门」转场再跳转
 *   · 从登录页「推门」进来时，页面一加载就把门收开露出内容
 *
 * **鉴权相关的逻辑一个字没改**：/auth/status、/auth/portal、/auth/logout
 * 的路径与载荷、401 跳登录、倒计时对账、textContent 拼 DOM（不拼 innerHTML）
 * 全部原样。门转场只负责「盖住屏幕 + 等一小会儿」，
 * 跳转目标依然只来自服务端给的 s.path 或固定路径，动效不拼装 URL。
 */
(function () {
  'use strict';

  var main = document.getElementById('main');
  var empty = document.getElementById('empty');
  var who = document.getElementById('who');
  var timer = document.getElementById('timer');
  var left = document.getElementById('left');
  var gate = document.getElementById('gate');
  var gateLabel = document.getElementById('gateLabel');
  var tick = null;
  var deadline = 0;

  /* ── 像素场背景 ───────────────────────────────────────────
   * 和门脸页同一个引擎（pixelfield.js），纯装饰。
   * 用月白（moonstone）那套配色 —— 跟门脸页、登录页对齐，
   * 整站是同一种银白语言，不是三页三种色。
   * createStyle 会连配色带波形参数一起套上；引擎不存在或接口对不上
   * 就退回 mount()，再不行就什么都不画 —— 背景画不出来无所谓，
   * 页面照常用。 */
  (function mountField() {
    var canvas = document.getElementById('pix');
    if (!canvas || !window.GhostPixelField) return;
    try {
      var reduce = !!(window.matchMedia &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches);
      var opt = {
        columns: 118,
        params: { lit: 0.12 },
        static: reduce,
      };
      if (window.GhostPixelField.createStyle) {
        window.GhostPixelField.createStyle(canvas, 'moonstone', opt);
      } else if (window.GhostPixelField.mount) {
        window.GhostPixelField.mount(canvas, opt);
      }
    } catch (e) { /* 背景画不出来无所谓，页面照常用 */ }
  })();

  /* 跨页面传递「上一个页面是用门关进来的」这个状态。
   * 同源 sessionStorage，浏览器标签页独立 —— 刚好符合「上一页→本页」的语义。
   * 只存一个标记，不含任何凭证。 */
  var GATE_KEY = 'gf_gate_in';

  function reducedMotion() {
    return !!(window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }

  /* ── 光之门时序：读 gate.css 的 CSS 变量 ─────────────────────
   * 唯一真源在 CSS（.gate 上的 --gate-hold / --gate-total）。
   * JS 不写死数字 —— 早先 CSS 与 JS 各写一份 430/100，改一处
   * 忘另一处就脱节，表现为「门缝还没张开就闪白了」。 */
  function gateMs(name, fallback) {
    if (!gate) return fallback;
    var n = parseFloat(getComputedStyle(gate).getPropertyValue(name));
    return (isFinite(n) && n > 0) ? n : fallback;
  }
  function gateHold() { return gateMs('--gate-hold', 1080); }
  function gateTotal() { return gateMs('--gate-total', 1220); }

  /* 光之门开关：<html data-gate="off"> 就完全不演，直接跳转。
     代码留着不删 —— 想去掉 html 上的那个属性就能开回来。 */
  function gateEnabled() {
    var el = document.documentElement;
    return !(el && el.getAttribute('data-gate') === 'off');
  }

  /* ── 门转场 ─────────────────────────────────────────────── */

  /* 光之门：一道窄光从中心炸开 → 光潮淹没整屏 → 闪白 → 跳转。
     动画本体在 gate.css（门脸页共用同一份），时序的数字也由
     CSS 给（见上面的 gateHold / gateTotal）。 */
  function gateClose(text, then) {
    if (!gate || reducedMotion() || !gateEnabled()) { then(); return; }
    if (gateLabel && text) gateLabel.textContent = text;
    gate.classList.add('on');
    /* 时序的唯一真源是 gate.css 的 --gate-hold / --gate-total。 */
    var hold = gateHold(), total = gateTotal();
    setTimeout(function () {
      gate.classList.add('settled');
      setTimeout(then, Math.max(0, total - hold));
    }, hold);
  }

  /* 门开：页面加载时先把门摆成关着的样子，再收开让路 */
  function gateOpen() {
    if (!gate || reducedMotion() || !gateEnabled()) return;
    try {
      if (sessionStorage.getItem(GATE_KEY) !== '1') return;
      sessionStorage.removeItem(GATE_KEY);
    } catch (e) {
      return;                       /* 隐私模式下 sessionStorage 可能不可用 */
    }
    gate.classList.add('preclosed', 'on', 'settled');
    /* 强制重排，让「盖满」这一帧先落地，再撤掉 preclosed 触发收缩 */
    void gate.offsetWidth;
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        gate.classList.remove('preclosed', 'settled');
        gate.classList.remove('on');
      });
    });
  }

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

  /* 图标取**路径首字母**。
   * 服务名是给人看的，随时会改；路径是这条服务唯一的稳定标识，
   * 首字母跟着路径走，改名不会让卡片换图标。
   * 路径首字母可能撞车（/file 与 /firefox 都是 F）—— 撞了就往后多取一位，
   * 再撞才用服务名兜底，让一屏卡片至少能一眼分清。
   * 拿不到字母（路径全是符号）才退回方块记号。 */
  function glyph(s, used) {
    var path = String((s && s.path) || '');
    var name = String((s && s.name) || '');
    var cands = [];
    var mp = path.match(/[A-Za-z0-9一-龥]/);
    if (mp) {
      var i = path.indexOf(mp[0]);
      cands.push(path.substr(i, 1));
      cands.push(path.substr(i, 2));
      cands.push(path.substr(i, 3));
    }
    var mn = name.match(/[A-Za-z0-9一-龥]/);
    if (mn) cands.push(mn[0]);
    for (var ci = 0; ci < cands.length; ci++) {
      var g = cands[ci].toUpperCase();
      if (!used[g]) { used[g] = 1; return g; }
    }
    var base = (cands[0] || '◆').toUpperCase();
    used[base] = (used[base] || 0) + 1;
    return used[base] > 1 ? base + used[base] : base;
  }

  /* 全部用 textContent 拼 DOM，不拼 innerHTML ——
   * 服务名是用户自己配的，但门户页没必要给它任何 HTML 解释能力。 */
  function card(s, used) {
    var a = document.createElement('a');
    a.className = 'tile';
    /* 跳转目标**只**来自服务端给的 url。
     *
     * host 分发时服务在另一个域名上（https://siyuan.fzyto.top:8443/），
     * 光靠 path 前缀拼不出来 —— 服务端知道网关端口，也知道那条规则配的
     * host，所以由它给出完整地址。前端不自己拼 URL：拼错了就是
     * 「门户点开是 404 / 串到别的服务」，而这种错在页面上完全看不出来。 */
    a.href = s.url || (s.path + '/');

    var ico = document.createElement('div');
    ico.className = 'ico';
    ico.textContent = glyph(s, used);

    var nm = document.createElement('div');
    nm.className = 'nm';
    nm.textContent = s.name || s.path;

    var pt = document.createElement('div');
    pt.className = 'pt';
    /* 副标题显示真实入口：host 分发时是域名，否则是路径前缀。 */
    pt.textContent = s.host || s.path;

    var tg = document.createElement('span');
    tg.className = 'tag ' + (s.public ? 'pub' : 'lan');
    tg.textContent = s.public ? '公网 · 需认证' : '仅内网';

    a.appendChild(ico); a.appendChild(nm); a.appendChild(pt); a.appendChild(tg);

    /* 点击即时反馈：按下瞬间卡片亮一下（纯 class，不写 style 属性 ——
     * CSP 的 style-src 'self' 会拦 HTML 里的 style="..."）。
     * 松手后延时撤掉，让那一下高亮看得见，不至于一闪而过。 */
    var hitTimer = null;
    function hitOn() {
      a.classList.add('is-hit');
      if (hitTimer) clearTimeout(hitTimer);
    }
    function hitOff() {
      if (hitTimer) clearTimeout(hitTimer);
      hitTimer = setTimeout(function () {
        a.classList.remove('is-hit');
      }, 170);
    }
    a.addEventListener('pointerdown', hitOn);
    a.addEventListener('pointerup', hitOff);
    a.addEventListener('pointercancel', hitOff);
    a.addEventListener('pointerleave', hitOff);

    /* 点卡片：先播门关，再跳。修饰键（Ctrl/⌘/Shift/中键）让浏览器
     * 按原样开新标签页 —— 那种情况不拦，也不播动画。 */
    a.addEventListener('click', function (ev) {
      if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
      if (ev.button !== 0) return;
      ev.preventDefault();
      var href = a.href;
      try { sessionStorage.setItem(GATE_KEY, '1'); } catch (e) { /* 忽略 */ }
      gateClose(s.name || s.path, function () { location.href = href; });
    });

    return a;
  }

  function render(services) {
    main.textContent = '';
    if (!services || !services.length) { empty.hidden = false; return; }
    var used = {};                 /* 已用过的图标字形，用来避让撞车 */
    services.forEach(function (s) { main.appendChild(card(s, used)); });
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

  /* 按下时的冲击波：挂在 pointerdown 上，拿得到按下的真实位置 */
  document.getElementById('logout').addEventListener('pointerdown', function (ev) {
    if (window.GhostPixelField && window.GhostPixelField.ripple) {
      window.GhostPixelField.ripple(this, ev);
    }
  });

  document.getElementById('logout').addEventListener('click', function (ev) {
    window.DevFingerprint.fetch('/auth/logout', { method: 'POST' })
      .catch(function () {})
      .then(function () {
        if (tick) clearInterval(tick);
        /* 退回到登录页是我们自己的页面 ⇒ 让它也走一次「门开」，
         * 两边接得上。 */
        try { sessionStorage.setItem(GATE_KEY, '1'); } catch (e) { /* 忽略 */ }
        gateClose('正在退出', function () { location.replace('/auth/login'); });
      });
  });

  /* 页面从后台切回来时重新对账：倒计时可能因系统休眠而不准，
   * 问服务端比本地算更可信。 */
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible' && !timer.hidden) load();
  });

  gateOpen();
  load();
})();
