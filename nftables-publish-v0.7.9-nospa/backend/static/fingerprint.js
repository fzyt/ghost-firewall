/* 设备指纹采集
 *
 * ⚠️ 能力边界，说在前面（免得后面误解）：
 *   浏览器指纹能区分「设备 / 浏览器实例」，**区分不了「人」**。
 *   同一个人的两台电脑指纹不同；同一个人的两台电脑上的两个不同用户可能…
 *   实际上指纹也可能不同也可能相同，取决于是否同浏览器同配置。
 *   真正能区分「谁」只有多账号。它的价值是：
 *     1. 审计日志里区分访问来源设备
 *     2. 发现「同一账号短时间内多个陌生设备登录」这类异常
 *     3. 登录后可以按设备做「信任此设备」等后续策略
 *
 * 不采集：Canvas 原图、字体列表、已安装插件等原始数据。
 * 全部在本地聚合成一个不可逆的哈希后才随请求头发出，服务端只拿到定长串。
 */
(function (global) {
  'use strict';

  function pad2(n) { return n < 10 ? '0' + n : '' + n; }

  /* ── 各特征采集 ───────────────────────────────────────── */

  function screenKey() {
    if (!global.screen) return 'na';
    var s = global.screen;
    return [
      s.width, s.height,
      s.availWidth, s.availHeight,
      s.colorDepth, s.pixelDepth,
      global.devicePixelRatio || 1
    ].join('x');
  }

  function tzKey() {
    try {
      var d = new Date();
      // 用实际偏移量而不是 getTimezoneName()，后者受 locale 影响
      return String(-d.getTimezoneOffset()) + '|' +
        (Intl.DateTimeFormat().resolvedOptions().timeZone || 'na');
    } catch (e) { return 'na'; }
  }

  function langKey() {
    try {
      return [
        navigator.language || 'na',
        (navigator.languages || []).join(',')
      ].join('|');
    } catch (e) { return 'na'; }
  }

  function hardwareKey() {
    return [
      navigator.hardwareConcurrency || 0,
      navigator.deviceMemory || 0,
      navigator.maxTouchPoints || 0,
      'ontouchstart' in global ? 1 : 0
    ].join('x');
  }

  /* Canvas 指纹：画一段固定文本再取像素摘要。
   * 不外传图片本身，只把它压成一段十六进制。 */
  function canvasKey() {
    try {
      var c = document.createElement('canvas');
      if (!c.getContext) return 'na';
      c.width = 220; c.height = 40;
      var g = c.getContext('2d');
      g.textBaseline = 'top';
      g.font = '14px "Arial"';
      // 混排不同字形/字重，各平台渲染差异最大的地方
      g.fillStyle = '#f60';
      g.fillRect(10, 5, 60, 20);
      g.fillStyle = '#069';
      g.fillText('Cwm fjordbank glyphs vext quiz 😃', 2, 12);
      g.fillStyle = 'rgba(102,204,0,0.7)';
      g.fillText('Cwm fjordbank glyphs vext quiz 😃', 4, 20);
      var d = g.getImageData(0, 0, c.width, c.height).data;
      var h = 2166136261 >>> 0;      // FNV-1a
      for (var i = 0; i < d.length; i += 4) {
        h ^= d[i]; h = Math.imul(h, 16777619) >>> 0;
        h ^= d[i + 1]; h = Math.imul(h, 16777619) >>> 0;
        h ^= d[i + 2]; h = Math.imul(h, 16777619) >>> 0;
      }
      return h.toString(16);
    } catch (e) {
      // 隐私模式 / 禁用 canvas 时可能抛错，不能因此让整个流程挂掉
      return 'na';
    }
  }

  /* ── 聚合 + 哈希 ──────────────────────────────────────── */

  function rawMaterial() {
    return [
      navigator.userAgent || 'na',
      langKey(),
      screenKey(),
      tzKey(),
      hardwareKey(),
      canvasKey(),
      String(global.location && global.location.protocol || 'na')
    ].join('##');
  }

  function fnv1a(str) {
    var h = 2166136261 >>> 0;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h >>> 0;
  }

  function toHex32(n) { return ('0000000' + (n >>> 0).toString(16)).slice(-8); }

  /* 返回 32 位十六进制串。
   * 优先 SubtleCrypto(SHA-256)——需要安全上下文（HTTPS/localhost，本项目满足）。
   * 拿不到就退到 FNV-1a 组合，仍然是稳定定长的，只是不如 SHA 抗碰撞。 */
  function computeFingerprint() {
    var material = rawMaterial();
    if (global.crypto && global.crypto.subtle && global.TextEncoder) {
      try {
        return global.crypto.subtle
          .digest('SHA-256', new TextEncoder().encode(material))
          .then(function (buf) {
            var a = new Uint8Array(buf);
            return toHex32(fnv1a(String.fromCharCode.apply(null, a.subarray(0, 8)))) +
                   toHex32(fnv1a(String.fromCharCode.apply(null, a.subarray(8, 16)))) +
                   toHex32(fnv1a(String.fromCharCode.apply(null, a.subarray(16, 24)))) +
                   toHex32(fnv1a(String.fromCharCode.apply(null, a.subarray(24, 32))));
          })
          .catch(function () { return fallback(material); });
      } catch (e) { /* 落到下面 */ }
    }
    return Promise.resolve(fallback(material));
  }

  function fallback(material) {
    var parts = [];
    for (var i = 0; i < 4; i++) {
      parts.push(toHex32(fnv1a(material + '#' + i)));
    }
    return parts.join('');
  }

  var cached = null;
  function getFingerprint() {
    if (!cached) {
      cached = computeFingerprint().catch(function () { return ''; });
    }
    return cached;
  }

  /* 给 fetch 包装一层，自动带上指纹头。 */
  function authFetch(url, options) {
    options = options || {};
    options.credentials = options.credentials || 'same-origin';
    return getFingerprint().then(function (fp) {
      options.headers = options.headers || {};
      if (fp) options.headers['X-Device-Fingerprint'] = fp;
      return fetch(url, options);
    });
  }

  global.DevFingerprint = {
    get: getFingerprint,
    fetch: authFetch
  };
})(window);
