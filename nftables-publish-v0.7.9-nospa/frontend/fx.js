/* ==========================================================================
   fx.js — 指针动效引擎
   --------------------------------------------------------------------------
   目标机器是 2 核 OpenWrt 路由器，不是工作站。所以这个文件的第一原则是
   **少干活**：

   1. 全局只有一个 requestAnimationFrame 循环。不是「每个卡片一个循环」——
      十几个元素各自开 rAF 在弱机上等于十几个定时器互相抢 CPU。
   2. 事件全部委托在 document 上，不用给每个元素单独挂监听器。
   3. getBoundingClientRect() 会强制同步布局，是指针事件里最贵的一步。
      所以只在「指针进入新元素」和「滚动/缩放」时测一次，之后复用缓存。
   4. 只写 transform 相关属性（--lx/--ly/--mx/--my/--tilt-*），这些走合成层，
      不触发布局也不触发重绘。
   5. 帧率无关的插值：按 dt 修正系数，低帧率设备上不会变慢或变抖。

   降级顺序（任一命中就整体停用，不做「半吊子播放」）：
     prefers-reduced-motion: reduce  →  完全停用
     触屏 (hover: none)              →  停用追光/磁性/倾斜（没有 hover 可跟随）
     页面切到后台                    →  暂停 rAF
   ========================================================================== */
(function () {
  'use strict';

  // ── 降级判定 ────────────────────────────────────────────────────────────
  var reduceMotion = window.matchMedia
    ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
  var coarsePointer = window.matchMedia
    ? window.matchMedia('(hover: none)') : null;

  function disabled() {
    if (reduceMotion && reduceMotion.matches) return true;
    if (coarsePointer && coarsePointer.matches) return true;
    return false;
  }

  // ── 全局指针状态 ────────────────────────────────────────────────────────
  var px = window.innerWidth * 0.5;   // 当前（平滑后的）指针位置
  var py = window.innerHeight * 0.3;
  var tx = px, ty = py;               // 目标位置
  var hasPointer = false;

  // ── 当前命中的元素缓存 ──────────────────────────────────────────────────
  var spotEl = null, spotRect = null;    // 追光
  var tiltEl = null, tiltRect = null;    // 倾斜
  var magEl = null, magRect = null;      // 磁性

  var magX = 0, magY = 0, magTX = 0, magTY = 0;
  var tiltX = 0, tiltY = 0, tiltTX = 0, tiltTY = 0;

  /* 主光源写入器。
     --lx/--ly 的消费者只有 .nf-light 一个（styles.css 里它的 transform）。
     写在 documentElement 上等于每帧让整棵 2000+ 元素的子树样式失效重算；
     写在光源元素上只失效它自己（它没有子节点）。副光源从一开始就是这么写的，
     这里让主光源对齐成同一套写法。
     值没变化时直接跳过 —— 指针不动但磁性/倾斜还在跑的帧，不该白付这次失效。 */
  var mainLight = null, lastLightX = null, lastLightY = null;
  function writeMain(x, y) {
    var xs = x.toFixed(1) + 'px', ys = y.toFixed(1) + 'px';
    if (xs === lastLightX && ys === lastLightY) return;
    lastLightX = xs; lastLightY = ys;
    if (mainLight) {
      mainLight.style.setProperty('--lx', xs);
      mainLight.style.setProperty('--ly', ys);
    } else {
      document.documentElement.style.setProperty('--lx', xs);
      document.documentElement.style.setProperty('--ly', ys);
    }
  }

  var rafId = 0;
  var lastT = 0;

  /* 帧率无关插值：把「每帧固定比例」换成「按真实经过时间换算」。
     60fps 下 dt≈16.7ms 系数 0.18；掉到 20fps（dt≈50ms）时系数自动降到 0.43，
     观感一致 —— 用固定系数的话弱机上动画会明显变慢。 */
  function lerp(cur, target, base, dt) {
    var k = 1 - Math.pow(1 - base, dt / 16.667);
    return cur + (target - cur) * k;
  }

  function nearest(cx, cy, sel) {
    var hit = document.elementFromPoint(cx, cy);
    while (hit) {
      if (hit.matches && hit.matches(sel)) return hit;
      hit = hit.parentElement;
    }
    return null;
  }

  // ── 帧循环 ──────────────────────────────────────────────────────────────
  function frame(now) {
    rafId = 0;
    var dt = lastT ? Math.min(now - lastT, 48) : 16.667;
    lastT = now;

    var moved = false;

    // 环境光：主光源跟手，副光源慢半拍并向外偏移，制造纵深
    px = lerp(px, tx, 0.14, dt);
    py = lerp(py, ty, 0.14, dt);
    if (Math.abs(px - tx) > 0.1 || Math.abs(py - ty) > 0.1) moved = true;
    writeMain(px, py);

    // 磁性按钮
    if (magEl) {
      magX = lerp(magX, magTX, 0.20, dt);
      magY = lerp(magY, magTY, 0.20, dt);
      if (Math.abs(magX - magTX) > 0.05 || Math.abs(magY - magTY) > 0.05) moved = true;
      else { magX = magTX = 0; magY = magTY = 0; }
      magEl.style.setProperty('--mag-x', magX.toFixed(2) + 'px');
      magEl.style.setProperty('--mag-y', magY.toFixed(2) + 'px');
    }

    // 倾斜卡片
    if (tiltEl) {
      tiltX = lerp(tiltX, tiltTX, 0.18, dt);
      tiltY = lerp(tiltY, tiltTY, 0.18, dt);
      if (Math.abs(tiltX - tiltTX) > 0.02 || Math.abs(tiltY - tiltTY) > 0.02) moved = true;
      else { tiltX = tiltTX = 0; tiltY = tiltTY = 0; }
      tiltEl.style.setProperty('--tilt-x', tiltX.toFixed(2) + 'deg');
      tiltEl.style.setProperty('--tilt-y', tiltY.toFixed(2) + 'deg');
    }

    // 还有未收敛的目标值就继续跑；都归零了就彻底停 —— 不留空转循环
    if (moved || magEl || tiltEl) {
      rafId = requestAnimationFrame(frame);
    } else {
      lastT = 0;
    }
  }

  function kick() {
    if (!rafId && !disabled() && !document.hidden) {
      rafId = requestAnimationFrame(frame);
    }
  }

  // ── 指针移动 ────────────────────────────────────────────────────────────
  function onMove(ev) {
    if (disabled()) return;
    var x = ev.clientX, y = ev.clientY;

    if (!hasPointer) {
      hasPointer = true;
      document.documentElement.classList.add('nf-pointer');
    }
    tx = x; ty = y;

    // 追光：只在进入新元素时重测矩形
    var s = nearest(x, y, '.nf-spot');
    if (s !== spotEl) {
      spotEl = s;
      spotRect = s ? s.getBoundingClientRect() : null;
    }
    if (spotEl && spotRect) {
      spotEl.style.setProperty('--mx', (x - spotRect.left) + 'px');
      spotEl.style.setProperty('--my', (y - spotRect.top) + 'px');
    }

    // 磁性：只在进入新按钮时重测
    var m = nearest(x, y, '.nf-btn--magnetic');
    if (m !== magEl) {
      magEl = m;
      magRect = m ? m.getBoundingClientRect() : null;
      if (!magEl) { magTX = magTY = 0; }
    }
    if (magEl && magRect) {
      var cx = magRect.left + magRect.width / 2;
      var cy = magRect.top + magRect.height / 2;
      // 0.3 = 吸引力系数。超过 0.4 会开始显得「甩」，手感变廉价。
      magTX = (x - cx) * 0.3;
      magTY = (y - cy) * 0.3;
    }

    // 倾斜
    var t = nearest(x, y, '.nf-tilt');
    if (t !== tiltEl) {
      tiltEl = t;
      tiltRect = t ? t.getBoundingClientRect() : null;
      if (!tiltEl) { tiltTX = tiltTY = 0; }
    }
    if (tiltEl && tiltRect) {
      var nx = (x - tiltRect.left) / tiltRect.width;   // 0..1
      var ny = (y - tiltRect.top) / tiltRect.height;
      // ±7°：再大就会在弱机上露出明显的多边形边缘
      tiltTY = (nx - 0.5) * 14;
      tiltTX = (0.5 - ny) * 14;
    }

    kick();
  }

  // 指针离开窗口：所有元素归位
  function onLeave() {
    hasPointer = false;
    tx = window.innerWidth * 0.5;
    ty = window.innerHeight * 0.3;
    spotEl = null; spotRect = null;
    tiltEl = null; tiltRect = null;
    magEl = null; magRect = null;
    magTX = magTY = tiltTX = tiltTY = 0;
    kick();
  }

  // ── 滚动 / 缩放：矩形缓存失效 ───────────────────────────────────────────
  function invalidate() {
    spotRect = spotEl ? spotEl.getBoundingClientRect() : null;
    tiltRect = tiltEl ? tiltEl.getBoundingClientRect() : null;
    magRect = magEl ? magEl.getBoundingClientRect() : null;
  }

  // ── 页面隐藏：停 rAF，省电 ──────────────────────────────────────────────
  function onVisibility() {
    if (document.hidden) {
      if (rafId) { cancelAnimationFrame(rafId); rafId = 0; lastT = 0; }
    } else {
      kick();
    }
  }

  // ── 初始化 ──────────────────────────────────────────────────────────────
  function init() {
    if (disabled()) return;   // 降级时连监听器都不挂

    var lights = document.querySelectorAll('.nf-light:not(.nf-light--drift)');
    mainLight = lights[0] || null;
    var cool = lights[1];

    document.addEventListener('pointermove', onMove, { passive: true });
    document.addEventListener('pointerleave', onLeave, { passive: true });
    document.addEventListener('pointercancel', onLeave, { passive: true });
    window.addEventListener('scroll', invalidate, { passive: true });
    window.addEventListener('resize', invalidate, { passive: true });
    document.addEventListener('visibilitychange', onVisibility);

    // 副光源单独一个 rAF：它不需要跟手，慢速插值即可，
    // 混进主循环会让主光源也被拉慢。
    var cx = window.innerWidth * 0.7, cy = window.innerHeight * 0.6;
    var cTx = cx, cTy = cy, cRaf = 0, cLast = 0;
    function cFrame(now) {
      cRaf = 0;
      var dt = cLast ? Math.min(now - cLast, 48) : 16.667;
      cLast = now;
      cx = lerp(cx, cTx, 0.06, dt);
      cy = lerp(cy, cTy, 0.06, dt);
      if (cool) {
        cool.style.setProperty('--lx', cx.toFixed(1) + 'px');
        cool.style.setProperty('--ly', cy.toFixed(1) + 'px');
      }
      if (Math.abs(cx - cTx) > 0.1 || Math.abs(cy - cTy) > 0.1) {
        cRaf = requestAnimationFrame(cFrame);
      } else { cLast = 0; }
    }
    function cKick() {
      if (!cRaf && !document.hidden) cRaf = requestAnimationFrame(cFrame);
    }

    // 用捕获阶段在 document 上监听，这样主循环不需要等它
    document.addEventListener('pointermove', function (ev) {
      cTx = ev.clientX;
      cTy = ev.clientY;
      cKick();
    }, { passive: true });

    // 首帧点亮，避免光源以 opacity:0 状态闪一下才出现
    requestAnimationFrame(function () {
      var l = document.querySelector('.nf-light:not(.nf-light--drift)');
      if (l) l.classList.add('is-lit');
      if (cool) cool.classList.add('is-lit');
    });

    document.documentElement.classList.add('nf-fx');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();