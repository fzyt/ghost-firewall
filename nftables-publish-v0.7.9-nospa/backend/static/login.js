/* 登录页逻辑。独立成文件是为了让 CSP 能用 script-src 'self' 严格禁止内联脚本。
 *
 * 2026-10-25 门脸页移植：**只动呈现层**。
 * 页面骨架换成了门脸页（品牌条 + 几何饰件 + 密码闸），视觉规格来自
 * ghost-landing/hero-grid.tsx，零构建手写移植（不用 React / Tailwind / Babel）。
 *
 * 新增的呈现层状态全部挂在 class 上，**不写内联样式**：
 *   · .pw-field.is-busy  校验中：输入区扫描光
 *   · .pw-field.is-bad   密码错误：描红，角标收起
 *   · .pw-field.is-shake 错误抖动（重放时先摘掉再强制重排）
 *   · .pw-lv.on          电平刻度：一位亮一格
 * 聚焦态（框的辉光、上沿流光、四角角标）走 CSS 的 :focus-within，
 * 不需要 JS 参与 —— JS 挂了表单照样能提交。
 *
 * **鉴权相关的逻辑一个字没改**：safeNext() 的开放重定向防护、
 * ?next= 回跳、请求路径 / 载荷、错误码分支、限流处理全部原样。
 * 门转场只做两件事：盖住屏幕、等一小会儿。跳转目标依然只来自
 * safeNext()，动效不参与、不拼装任何 URL。
 */
(function () {
  'use strict';

  var form = document.getElementById('form');
  var pw = document.getElementById('pw');
  var msg = document.getElementById('msg');
  var btn = document.getElementById('submit');
  var btnLabel = document.getElementById('btnLabel');
  var devEl = document.getElementById('device');
  var field = document.getElementById('pwField');
  var portEl = document.getElementById('port');
  var gate = document.getElementById('gate');
  var gateLabel = document.getElementById('gateLabel');

  /* ── 像素场背景 ───────────────────────────────────────────
   * 和门脸页、门户页同一个引擎（pixelfield.js），纯装饰。
   * 用月白（moonstone）那套配色 —— 跟门户页、门脸页对齐。
   * 参数跟门脸页一致（列数 / 亮度都走引擎默认），这样移植过来的
   * 登录页和 demo 门脸页是同一片场。
   * 引擎加载失败也只是少一层背景，登录流程不受影响。 */
  (function mountField() {
    var canvas = document.getElementById('pix');
    if (!canvas || !window.GhostPixelField) return;
    try {
      var reduce = !!(window.matchMedia &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches);
      var opt = {
        static: reduce,
        bloom: true,
      };
      if (window.GhostPixelField.createStyle) {
        window.GhostPixelField.createStyle(canvas, 'moonstone', opt);
      } else if (window.GhostPixelField.mount) {
        window.GhostPixelField.mount(canvas, opt);
      }
    } catch (e) { /* 背景画不出来无所谓，表单照常用 */ }
  })();

  /* ── 品牌条上的端口号 ───────────────────────────────────────
   * 默认 8443（网关的默认端口）。部署时改过端口就按实际的显示 ——
   * 这个数字是给人看的，显示错的比不显示更糟。 */
  (function paintPort() {
    if (!portEl) return;
    var p = (window.location && window.location.port) || '';
    if (/^[0-9]+$/.test(p)) portEl.textContent = ':' + p;
  })();

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

  /* 用户开了「减弱动态效果」就别演了，直接跳 */
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

  /* ── 门转场 ───────────────────────────────────────────────
   * 光之门：一道窄光从中心炸开 → 光潮淹没整屏 → 闪白 → 跳转。
   * 动画本体在 gate.css（门脸页共用同一份），这里只管时序，
   * 而时序的数字也由 CSS 给（见上面的 gateHold / gateTotal）。
   * 纯视觉。setTimeout 而不是 transitionend：后者在元素被
   * display:none / 页面跳转时不一定触发，会把跳转卡死。 */
  function playGate(text) {
    if (!gate || reducedMotion() || !gateEnabled()) { location.replace(safeNext()); return; }
    if (gateLabel && text) gateLabel.textContent = text;
    gate.classList.add('on');
    /* 时序的唯一真源是 gate.css 的 --gate-hold / --gate-total。
       这里只读，不写死数字 —— 早先 CSS 与 JS 各写一份 430/100，
       改一处忘另一处就脱节（门缝还没张开就闪白了）。 */
    var hold = gateHold(), total = gateTotal();
    setTimeout(function () {
      gate.classList.add('settled');
      setTimeout(function () { location.replace(safeNext()); }, Math.max(0, total - hold));
    }, hold);
  }

  function say(text, kind) {
    if (!msg) return;
    msg.textContent = text;
    msg.className = 'pw-msg' + (kind ? ' ' + kind : '');
  }

  /* ── 电平刻度 ───────────────────────────────────────────────
   * 一位亮一格，最多 8 格（页面上就画了 8 格）。
   * 用 getElementById + children 取，不依赖 querySelectorAll ——
   * 测试用的最小 DOM 桩里没有那个 API。 */
  function paintLevels(n) {
    var box = document.getElementById('levels');
    if (!box || !box.children) return;
    var bars = box.children;
    for (var i = 0; i < bars.length; i++) {
      var bar = bars[i];
      if (!bar || !bar.classList) continue;
      if (i < n) bar.classList.add('on');
      else bar.classList.remove('on');
    }
  }

  /* ── 框的状态 ───────────────────────────────────────────────
   * 聚焦态交给 CSS 的 :focus-within（JS 不参与）。
   * 这里只管三个 JS 才知道的态：校验中 / 出错 / 抖动。 */
  function markField(cls, on) {
    if (!field || !field.classList) return;
    if (on) field.classList.add(cls);
    else field.classList.remove(cls);
  }

  function busy(on) {
    btn.disabled = on;
    if (btn.classList) btn.classList.toggle('busy', on);
    if (btnLabel) btnLabel.textContent = on ? '验证中' : '进入';
    if (pw) pw.disabled = on;
    markField('is-busy', on);
  }

  /* 密码错了：抖一下，比干巴巴一行红字有反馈感 */
  function shake() {
    if (!field || !field.classList) return;
    field.classList.remove('is-shake');
    /* 强制重排，保证连续失败时动画能重放 */
    void field.offsetWidth;
    field.classList.add('is-shake');
  }

  /* 已登录（或内网豁免）就别停在登录页。
   * 这条路径不播门动画 —— 内网免认证是常态，每次都卡半秒很烦。 */
  window.DevFingerprint.fetch('/auth/status', { method: 'GET' })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      // 内网豁免同样会返回 authenticated:true，所以只判这一个字段即可，
      // 不需要（也不该）去认「内网免认证」这个机制标记。
      if (d && d.authenticated) {
        location.replace(safeNext());
      }
    })
    .catch(function () { /* 探测失败就老实显示登录表单 */ });

  window.DevFingerprint.get().then(function (fp) {
    if (!fp || !devEl) return;
    devEl.textContent = '设备标识 ' + fp.slice(0, 8);
  });

  /* 输入变化：刻度跟着长；一旦重新输入就撤掉错误态。 */
  if (pw) {
    pw.addEventListener('input', function () {
      paintLevels(pw.value.length);
      markField('is-bad', false);
      markField('is-shake', false);
    });
  }

  /* 按下时的冲击波：挂在 pointerdown 上而不是 submit 上 ——
   * submit 是普通 Event，没有 clientX/clientY，拿不到按下的位置；
   * 而且按下的瞬间就该有反馈，比等提交后再响更跟手。 */
  btn.addEventListener('pointerdown', function (ev) {
    if (window.GhostPixelField && window.GhostPixelField.ripple) {
      window.GhostPixelField.ripple(btn, ev);
    }
  });

  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var password = pw.value;
    if (!password) {
      say('请输入密码', 'warn');
      markField('is-bad', true);
      pw.focus();
      return;
    }

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
          playGate('正在进入');
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
        paintLevels(0);
        /* 先解除禁用再聚焦 —— 反过来的话 focus() 落在 disabled 的
         * 输入框上不生效，输密码得先点一下。 */
        busy(false);
        markField('is-bad', true);
        pw.focus();
        shake();
      })
      .catch(function () {
        say('网络异常，请检查连接后重试', 'err');
        busy(false);
        markField('is-bad', true);
        shake();
      });
  });
})();
