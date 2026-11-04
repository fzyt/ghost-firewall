/* ==========================================================================
   pixelbg.js — 面板背景：像素场选档与挂载（2026-11-04）
   --------------------------------------------------------------------------
   面板（5443）此前只有「环境光 + 细网格」两层 CSS 背景；这一份把它接上
   **与服务门户同一套像素场引擎**（backend/static/pixelfield.js），
   并且用**同一份候选表**：每次打开在两档原版之间随机。

     'moonstone' —— 原版月白几何（三道波 + 遮罩 + 余晖 + 辉光）
     'trae'      —— TRAE 原版（7px 晶格 + 5×5 绿白方块 + 指针泛绿）

   为什么是「随机两档」而不是挑一档：
   用户看过门户那边「原版 / TRAE 原版 / 两个混合方案」四种观感后，
   明确否掉了两个混合方案，选了「两档原版随机」。面板照办，
   不再自己发明第三种观感。

   ⚠ 候选表与服务门户 portal.js 里的 BG_STYLES 是**两份**（这里与那里）。
     为什么不共用一份文件：门户那份已经随 v0.17.0 提交并跑过完整变异验证
     （194/194），再动它就要把整轮验证重跑一遍；这里只有 12 行、行为完全
     一致，靠两边的测试各自钉住（tests/test_panel_pixelbg.js 与
     tests/test_portal_bgstyle.js）。
     ⇒ **要加第三档时，两边都要改**（这是有意留的坑，不是忘了）。

   ⚠ 引擎那份源码不在本目录：它在 backend/static/pixelfield.js，
     面板的静态服务回退到那里取（见 backend/app.py 的 SHARED_STATIC_FILES）。
     146KB / 2700+ 行放两份拷贝必然漂移。
   ========================================================================== */
(function () {
  'use strict';

  /* 与门户一致的候选表（顺序也一致：顺序不影响概率，只影响随机值映射） */
  var CANDIDATES = ['moonstone', 'trae'];

  /* 从 URL 查询串取参数（?pfstyle=xxx），取不到返回 ''。
     面板本身不用这个参数，它是给「截图/对比时钉死某一档」用的。 */
  function queryParam(name) {
    var search = '';
    try { search = (window.location && window.location.search) || ''; }
    catch (e) { return ''; }
    if (search.charAt(0) === '?') search = search.slice(1);
    var parts = search.split('&');
    for (var i = 0; i < parts.length; i++) {
      if (!parts[i]) continue;
      var kv = parts[i].split('=');
      if (kv[0] !== name) continue;
      var v = kv.slice(1).join('=');
      try { return decodeURIComponent(v); } catch (e) { return v; }
    }
    return '';
  }

  /* 挑这一次的档位：
     1) URL 显式指定（?pfstyle=moonstone / ?pfstyle=trae）⇒ 用它；
     2) 否则在两档里随机挑一个 —— 每次打开重新挑，不记在存储里。
     ⚠ 指定的档位必须**在候选里**才认：档名写错时传一个不存在的档位给
       引擎，背景会整片空掉，而且页面上看不出是哪里错了。 */
  function pickStyle(rnd) {
    var want = queryParam('pfstyle');
    if (want) {
      for (var i = 0; i < CANDIDATES.length; i++) {
        if (CANDIDATES[i] === want) return want;
      }
    }
    var r = (typeof rnd === 'function') ? rnd() : Math.random();
    return CANDIDATES[Math.floor(r * CANDIDATES.length)];
  }

  function boot() {
    var cv = document.getElementById('nf-pix');
    if (!cv || !window.GhostPixelField) return;
    try {
      /* 尊重系统的「减少动态效果」设置：引擎的 static 模式画一帧就不动了。
         面板是给人盯着看的后台界面，动效必须有降级路径。 */
      var reduce = !!(window.matchMedia &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches);
      var opt = { static: reduce };
      if (window.GhostPixelField.createStyle) {
        window.GhostPixelField.createStyle(cv, pickStyle(), opt);
      } else if (window.GhostPixelField.mount) {
        window.GhostPixelField.mount(cv, opt);
      }
    } catch (e) {
      /* 背景画不出来无所谓 —— 面板照常用（这条与门户同款） */
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  /* 暴露给测试与调试（不在页面里显示任何东西） */
  window.__panelPixelBg = { pickStyle: pickStyle, candidates: CANDIDATES };
})();
