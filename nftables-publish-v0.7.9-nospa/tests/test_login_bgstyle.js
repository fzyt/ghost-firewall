/* 网关登录页背景选档的行为级测试（Node + 最小 DOM 桩）
 *
 * 运行: node tests/test_login_bgstyle.js
 * 零依赖：只用 Node 内置模块（fs / path / vm）。
 *
 * 这一批是什么（2026-11-04 第十五轮）
 * ---------------------------------
 * 用户拍板：「遮罩调淡 + 两边登录页都随机」——
 *   面板（5443）登录页自 v0.18.0 起就是随机两档，
 *   网关登录页这一轮之前**写死** 'moonstone' ⇒ 现在也改成随机两档
 *   （原版月白 / TRAE 原版），与门户、面板完全一致。
 *
 * 为什么这个文件**必须真跑 login.js**
 * ------------------------------------
 * 「随机」这件事静态断言钉不住：
 *   把 `Math.floor(Math.random() * n)` 写成 0，登录页就永远显示同一档，
 *   **页面上完全看不出异常**，静态断言照样全绿。
 *   候选表少写一档（只留 moonstone）也是同一种退化。
 *   连「档名写错时回退随机」这种防呆逻辑，写成
 *   `if (BG_STYLES[i] === want) return want;` 少一个分号都能被静态断言放过。
 *
 * ⇒ 这里真把 login.js 塞进 vm 沙箱跑一遍，桩掉 document / window /
 *   DevFingerprint，把 createStyle 收到的**档位参数**记下来，
 *   用可控的随机值把「抽到哪一档」钉死。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'backend', 'static', 'login.js'), 'utf8');

let P = 0, F = 0;
const ok = (n, c, x) => {
  if (c) { P++; console.log('  [PASS] ' + n); }
  else { F++; console.log('  [FAIL] ' + n + '  ' + (x || '')); }
};
const sec = (t) => console.log('\n== ' + t);

const CANDIDATES = ['moonstone', 'trae'];

/* ── 最小 DOM 桩 ───────────────────────────────────────────── */
function mkEl(id) {
  const el = {
    id: id,
    value: '',
    textContent: '',
    disabled: false,
    offsetWidth: 0,
    style: {},
    children: [],
    className: '',
    classList: {
      _s: {},
      add(c) { this._s[c] = true; },
      remove(c) { delete this._s[c]; },
      toggle(c, on) { if (on) { this._s[c] = true; } else { delete this._s[c]; } },
      contains(c) { return !!this._s[c]; },
    },
    addEventListener() {},
    removeEventListener() {},
    focus() {},
    getAttribute() { return null; },
    getBoundingClientRect() { return { width: 1440, height: 900, left: 0, top: 0 }; },
  };
  return el;
}

/**
 * 跑一遍 login.js，返回它挂到引擎上的档位。
 * @param {object} opt
 *   rnd         随机值（0 ≤ rnd < 1）
 *   search      URL 查询串（含前导 '?' 或空串）
 *   reduce      是否 prefers-reduced-motion
 *   noCanvas    画布不存在（测降级）
 *   noEngine    引擎不存在（测降级）
 *   throwOnCreate 引擎抛异常（测降级）
 */
function runLogin(opt) {
  opt = opt || {};
  const calls = [];
  const els = {};
  let thrown = null;

  const doc = {
    readyState: 'complete',
    getElementById(id) {
      if (opt.noCanvas && id === 'pix') return null;
      if (!els[id]) els[id] = mkEl(id);
      return els[id];
    },
    addEventListener() {},
    createElement() { return mkEl('x'); },
    documentElement: mkEl('html'),
  };

  const M = Object.create(Math);
  M.random = () => (opt.rnd === undefined || opt.rnd === null ? 0.5 : opt.rnd);

  const loc = {
    search: opt.search || '',
    pathname: '/',
    href: '/',
    port: '8443',
    replace() { loc._replaced = (loc._replaced || 0) + 1; },
  };

  const sandbox = {
    console: console,
    document: doc,
    location: loc,
    matchMedia: () => ({ matches: !!opt.reduce }),
    requestAnimationFrame: () => 0,
    cancelAnimationFrame() {},
    performance: { now() { return 0; } },
    getComputedStyle: () => ({ getPropertyValue: () => '' }),
    setTimeout: () => 0,
    clearTimeout: () => {},
    URLSearchParams: URLSearchParams,
    Math: M,
    /* 设备指纹：登录页启动时会探一次 /auth/status 与设备标识。
     * 这里给一个「永不完成」的 Promise，避免异步链在测试里乱跑。 */
    DevFingerprint: {
      fetch: () => new Promise(() => {}),
      get: () => new Promise(() => {}),
    },
  };
  if (!opt.noEngine) {
    sandbox.GhostPixelField = {
      createStyle(canvas, style, o) {
        if (opt.throwOnCreate) throw new Error('引擎炸了');
        calls.push({ canvas: canvas, style: style, opt: o });
        return { stop() {} };
      },
      mount() { calls.push({ canvas: null, style: null, opt: null }); },
      ripple() {},
    };
  }
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  try {
    vm.runInContext(SRC, sandbox, { filename: 'login.js' });
  } catch (e) {
    thrown = e;
  }
  return { calls: calls, thrown: thrown, sandbox: sandbox };
}

/* ── LB-1 登录页用的也是「原版 / TRAE 原版」两档 ─────────── */
sec('LB-1 候选表就是两档原版');

{
  const a = runLogin({ rnd: 0.0 });
  ok('挂载到了引擎（createStyle 被调用）', a.calls.length === 1,
    JSON.stringify(a.calls.map((c) => c.style)));
  ok('档位在候选表里', a.calls.length && CANDIDATES.indexOf(a.calls[0].style) >= 0,
    a.calls.length ? String(a.calls[0].style) : '没挂上');
  ok('脚本自己没抛异常', a.thrown === null, String(a.thrown || ''));
}

{
  const a = runLogin({ rnd: 0.0 });
  const b = runLogin({ rnd: 0.999999 });
  ok('random≈0 落在候选的第一个',
    a.calls.length && a.calls[0].style === CANDIDATES[0],
    a.calls.length ? String(a.calls[0].style) : '没挂上');
  ok('random≈1 落在候选的最后一个',
    b.calls.length && b.calls[0].style === CANDIDATES[CANDIDATES.length - 1],
    b.calls.length ? String(b.calls[0].style) : '没挂上');
}

{
  const a = runLogin({ rnd: 0.0, search: '?pfstyle=trae' });
  ok('?pfstyle=trae 压过随机', a.calls.length && a.calls[0].style === 'trae',
    a.calls.length ? String(a.calls[0].style) : '没挂上');
  const b = runLogin({ rnd: 0.999999, search: '?pfstyle=moonstone' });
  ok('?pfstyle=moonstone 压过随机', b.calls.length && b.calls[0].style === 'moonstone',
    b.calls.length ? String(b.calls[0].style) : '没挂上');
  const c = runLogin({ rnd: 0.0, search: '?pfstyle=moonstone-trae' });
  ok('不存在的档名被忽略、回退到候选里',
    c.calls.length && CANDIDATES.indexOf(c.calls[0].style) >= 0,
    c.calls.length ? String(c.calls[0].style) : '没挂上');
  const d = runLogin({ rnd: 0.0, search: '?next=%2Fportal' });
  ok('next 参数不影响选档（只看 pfstyle）',
    d.calls.length && CANDIDATES.indexOf(d.calls[0].style) >= 0,
    d.calls.length ? String(d.calls[0].style) : '没挂上');
}

/* ── LB-2 两档都不含被否掉的混合方案 ─────────────────────── */
sec('LB-2 候选表里不含被否掉的混合方案');

{
  const a = runLogin({ rnd: 0.5 });
  ok('抽到的那档不是 trae-orig / moonstone-trae',
    a.calls.length && a.calls[0].style !== 'trae-orig' &&
    a.calls[0].style !== 'moonstone-trae',
    a.calls.length ? String(a.calls[0].style) : '没挂上');
  ok('候选表正好两档', CANDIDATES.length === 2);
}

/* ── LB-3 降级路径：背景画不出来不影响登录 ───────────────── */
sec('LB-3 降级：引擎缺失 / 画布缺失 / 引擎抛异常');

{
  const a = runLogin({ rnd: 0.5, noEngine: true });
  ok('引擎不存在时不抛异常', a.thrown === null, String(a.thrown || ''));
  const b = runLogin({ rnd: 0.5, noCanvas: true });
  ok('画布不存在时不抛异常', b.thrown === null, String(b.thrown || ''));
  const c = runLogin({ rnd: 0.5, throwOnCreate: true });
  ok('引擎抛异常时不外溢（登录表单照常用）', c.thrown === null, String(c.thrown || ''));
}

/* ── LB-4 尊重 prefers-reduced-motion ────────────────────── */
sec('LB-4 引擎静态模式');

{
  const a = runLogin({ rnd: 0.5, reduce: true });
  ok('开了「减弱动态效果」时引擎收到 static: true',
    a.calls.length && a.calls[0].opt && a.calls[0].opt.static === true,
    a.calls.length ? JSON.stringify(a.calls[0].opt) : '没挂上');
}

console.log('');
if (F) {
  console.log('失败 ' + F + ' 项：');
  process.exit(1);
}
console.log('通过 ' + P + ' / ' + P);
console.log('全部通过');
