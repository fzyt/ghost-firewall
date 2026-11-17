/* ==========================================================================
   极简模式：把磨砂、动效、像素场背景一起关掉（2026-11-17）
   --------------------------------------------------------------------------
   为什么要这个开关：
   面板（5443）默认那套观感是「玻璃 + 动效」——
     · 磨砂（backdrop-filter）铺在 7 个选择器上：侧栏、顶栏、页面容器、
       所有 .bg-white 元素、弹窗遮罩、整页登录页、玻璃卡片基元；
     · 像素场背景（backend/static/pixelfield.js）每帧重绘一次全屏画布。

   实测（headless Chromium + SwiftShader 软件光栅，登录页 1600×1000，6 秒采样）：
     只去磨砂   → 帧率 7.8 → 54.8，脚本耗时不变
     只去像素场 → 帧率不变（仍 7.8），脚本耗时 1.109s → 0.001s
   ⇒ **磨砂是帧率的瓶颈，像素场是 CPU 的瓶颈**（headless 没有 GPU，
     磨砂走软件光栅，绝对数字被夸大；像素场那 14ms/帧是纯 JS，不受影响）。

   有人只想要最简的元素页面，不要这些 ⇒ 做一个**能记住**的开关。

   为什么状态存在浏览器本地（localStorage）而不是服务端配置：
   这是**观感偏好**，不是设备状态。存服务端要动共享配置、要加接口、
   多设备还得同步 —— 为一个开关不值得。localStorage 一行搞定，
   刷新后保持（用户要的「可缓存」）。
   ⇒ 代价：换浏览器/换设备不跟随。这是观感偏好该有的行为。

   ⚠️ 必须**同步加载、且排在 styles.css 之前**：
   浏览器解析到 <script> 时立刻执行 ⇒ <html> 上的 class 在样式生效前就位
   ⇒ 极简模式的用户每次打开面板**不会先看到一帧动效再卡住**。
   （塞进 defer 脚本就晚了，会闪。）
   ========================================================================== */
(function () {
  'use strict';

  var KEY = 'nf_plain_mode';
  var CLASS = 'nf-plain';

  /* localStorage 在隐私模式/存储被禁用时会抛异常 —— 那也不能让页面崩 */
  function read() {
    try {
      return window.localStorage.getItem(KEY) === '1';
    } catch (e) {
      return false;
    }
  }

  function write(on) {
    try {
      window.localStorage.setItem(KEY, on ? '1' : '0');
    } catch (e) {
      /* 存不了就只在本次会话生效 */
    }
  }

  /* 真相源是 <html> 上的 class：它才是「当前是不是极简模式」的实际状态。
     localStorage 只是「下次打开时要不要先把这个 class 摆上」的备忘。 */
  function isOn() {
    try {
      return !!document.documentElement.classList.contains(CLASS);
    } catch (e) {
      return false;
    }
  }

  function apply(on) {
    var el = document.documentElement;
    if (!el || !el.classList) return;
    if (on) el.classList.add(CLASS);
    else el.classList.remove(CLASS);
  }

  function set(on) {
    on = !!on;
    write(on);
    apply(on);
    /* 像素场引擎自己管挂载/停摆。它在 defer 脚本里，可能还没就绪，
       所以这里只「通知」，不假设它存在。 */
    try {
      if (window.__panelPixelBg && window.__panelPixelBg.apply) {
        window.__panelPixelBg.apply(on);
      }
    } catch (e) {
      /* 引擎那边自己会兜住，这里不影响开关本身生效 */
    }
  }

  window.NfPlain = { isOn: isOn, set: set, KEY: KEY, CLASS: CLASS };

  /* 首屏：同步应用一次。此刻 <body> 还没解析，只动 <html> 上的 class 就够
     —— 像素场挂不挂载由 frontend/pixelbg.js 自己读 isOn() 决定。 */
  apply(read());
})();
