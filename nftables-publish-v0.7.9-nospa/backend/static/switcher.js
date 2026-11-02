/**
 * 变体切换器
 *
 * 三件事：
 *   1. 用 GhostFX 接管背景（代替 portal.js 自己的 pixelfield 挂载）
 *   2. 面板 + 键盘（0-5 / ←→）实时切换变体
 *   3. 反馈层：指针位置跟随 + 卡片悬停的扩散回声
 *
 * 反馈层是刻意加的 —— 用户要的是「反馈感」：
 *   背景不能是贴纸，鼠标移到哪它得知道；卡片被悬停时，
 *   背景里要有一圈亮环扩开，让「点得中」这件事被看见。
 */
(function () {
  'use strict';

  var canvas = document.getElementById('pix');
  if (!canvas || !window.GhostFX) return;

  var order = window.GhostFX.order;
  var field = null;
  var current = 'pixelfield';

  /* 反馈层独立于变体（见 fx.js 的 Feedback）。
     它有自己的画布，所有变体共用 ⇒ 指针反馈在 pixelfield 下也有效。 */
  var feedback = new window.GhostFX.Feedback(canvas);
  feedback.resize();
  feedback.start();
  window.__fxFeedback = function () { return feedback; };

  /* ── 挂载 ────────────────────────────────────────────── */
  function mountVariant(key) {
    if (field) { field.destroy(); field = null; }
    /* pixelfield 变体自己会用原生引擎，直接交给它 */
    field = window.GhostFX.mount(canvas, key, { seed: 20261101 });
    window.__fx = field;
    current = key;
    syncButtons();
  }

  /* ── 面板 ────────────────────────────────────────────── */
  var panel = null;
  var buttons = {};

  function buildPanel() {
    panel = document.createElement('div');
    panel.className = 'fx-switcher';
    panel.setAttribute('role', 'group');
    panel.setAttribute('aria-label', '背景变体切换');

    var title = document.createElement('div');
    title.className = 'fx-switcher__title';
    title.textContent = '背景变体 · 共 ' + order.length + ' 种';
    /* 点标题收起/展开。变体多了以后面板会长到 4 行，
       评审时先收起来更省心。 */
    title.title = '点击收起 / 展开';
    title.addEventListener('click', function () {
      panel.classList.toggle('fx-switcher--collapsed');
    });

    var row = document.createElement('div');
    row.className = 'fx-switcher__row';

    order.forEach(function (key, i) {
      var def = window.GhostFX.VARIANTS[key] || {};
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'fx-btn';
      b.textContent = i + ' ' + (def.label || key);
      b.setAttribute('aria-pressed', 'false');
      b.title = def.hint || '';
      b.addEventListener('click', function () { switchTo(key); });
      buttons[key] = b;
      row.appendChild(b);
    });

    var hint = document.createElement('div');
    hint.className = 'fx-switcher__hint';
    /* ⚠️ 变体超过 10 个后，数字键只能覆盖 0-9 ——
       提示语必须写实际能用的范围，否则用户按 1 2 会以为面板坏了。
       10 号及以后用 ←→ 或直接点按钮。 */
    var maxDigit = Math.min(9, order.length - 1);
    hint.textContent = '按 0-' + maxDigit + ' 或 ←→ 切换 · 鼠标移动会点亮背景 · 悬停卡片有回声';

    panel.appendChild(title);
    panel.appendChild(row);
    panel.appendChild(hint);
    document.body.appendChild(panel);
  }

  function syncButtons() {
    Object.keys(buttons).forEach(function (k) {
      buttons[k].setAttribute('aria-pressed', k === current ? 'true' : 'false');
    });
  }

  /* ── 切换（带一次淡出淡入，硬切会闪） ────────────────── */
  var switching = false;
  function switchTo(key) {
    if (switching || key === current) return;
    switching = true;
    canvas.classList.add('fx-fade');
    setTimeout(function () {
      canvas.classList.remove('fx-fade');
      mountVariant(key);
      requestAnimationFrame(function () {
        canvas.classList.add('is-out');
        requestAnimationFrame(function () {
          canvas.classList.remove('is-out');
          setTimeout(function () { switching = false; }, 200);
        });
      });
    }, 120);
  }

  /* ── 键盘 ────────────────────────────────────────────── */
  document.addEventListener('keydown', function (ev) {
    if (ev.metaKey || ev.ctrlKey || ev.altKey) return;
    var tag = (ev.target && ev.target.tagName) || '';
    if (tag === 'INPUT' || tag === 'TEXTAREA') return;
    var n = parseInt(ev.key, 10);
    if (!isNaN(n) && n >= 0 && n < order.length) {
      switchTo(order[n]);
      ev.preventDefault();
      return;
    }
    if (ev.key === 'ArrowRight' || ev.key === 'ArrowLeft') {
      var i = order.indexOf(current);
      i = (i + (ev.key === 'ArrowRight' ? 1 : order.length - 1)) % order.length;
      switchTo(order[i]);
      ev.preventDefault();
    }
  });

  /* ── 反馈层：指针跟随 ────────────────────────────────── */
  function toCell(ev) {
    var r = canvas.getBoundingClientRect();
    var gx = Math.floor((ev.clientX - r.left) / feedback.cell);
    var gy = Math.floor((ev.clientY - r.top) / feedback.cell);
    window.GhostFX.setPointer(feedback, gx, gy);
  }
  document.addEventListener('pointermove', toCell, { passive: true });
  document.addEventListener('pointerleave', function () {
    window.GhostFX.clearPointer(feedback);
  });

  /* ── 反馈层：卡片悬停的扩散回声 ──────────────────────── */
  document.addEventListener('pointerover', function (ev) {
    var tile = ev.target && ev.target.closest ? ev.target.closest('.tile') : null;
    if (!tile) return;
    var r = tile.getBoundingClientRect();
    var cr = canvas.getBoundingClientRect();
    var gx = Math.floor((r.left + r.width / 2 - cr.left) / feedback.cell);
    var gy = Math.floor((r.top + r.height / 2 - cr.top) / feedback.cell);
    feedback.ping(gx, gy);
  });

  /* ── 尺寸变化 ────────────────────────────────────────── */
  var pending = false;
  function onResize() {
    if (pending) return;
    pending = true;
    requestAnimationFrame(function () {
      pending = false;
      if (field) field.resize();
      if (feedback) feedback.resize();
    });
  }
  window.addEventListener('resize', onResize);

  /* ── 起步 ────────────────────────────────────────────── */
  buildPanel();
  mountVariant(current);
  /* 自动化验收用：让截图 / 回归脚本能直接切变体，不必模拟按键 */
  window.__fxSwitch = switchTo;
  window.__fxField = function () { return field; };
})();
