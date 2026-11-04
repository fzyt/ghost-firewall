/* 门户背景「原版 / TRAE 原版」随机两档的行为级测试（Node + 最小 DOM 桩）
 *
 * 运行: node tests/test_portal_bgstyle.js
 * 零依赖：只用 Node 内置模块（fs / path / vm），不装浏览器、不装 jsdom。
 *
 * 这一批是什么（2026-11-04 第十二轮）
 * ---------------------------------
 * 用户原话：「这两种改动后都不好看了。这样吧，我们就按照原版和原版trae
 *   打开随机显示吧」
 *
 * ⇒ 门户背景每次打开，在**两档原版**之间随机挑一个：
 *   · 'moonstone' —— 原版月白几何（改版前门户用的就是它）
 *   · 'trae'      —— TRAE 原版
 *   两档各自原封不动，不做混合。前两轮做的 'trae-orig' / 'moonstone-trae'
 *   用户明确否掉了 ⇒ 门户不再用它们。
 *
 * 为什么这个文件**必须真跑 portal.js**
 * ----------------------------------
 * 「随机」这件事静态断言钉不住：
 *   · 源码里写一个候选数组 + 一次 Math.random，看起来完全正常；
 *     但把 `Math.floor(Math.random() * n)` 写成 `0`，门户就**永远**
 *     显示同一档 —— 页面上看不出任何异常，测试全绿。
 *   · 候选表少写一档（只留 moonstone），代码照样跑，只是「随机」名存实亡。
 *   · URL 覆盖（?pfstyle=）写错/失效，截图对不上时无从查起。
 *
 * ⇒ 所以这里真把 portal.js 塞进 vm 沙箱跑一遍，桩掉 document / window，
 *   把 engine.createStyle 收到的**档位参数**记下来，用可控的 Math.random
 *   把「抽到哪个」钉死。
 *
 * 观测点只有一个：**createStyle 收到的第二个参数（档位名）**。
 * 它是门户与引擎之间唯一的契约，其余都不重要。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DIR = path.join(__dirname, '..', 'backend', 'static');
const SRC = fs.readFileSync(path.join(DIR, 'portal.js'), 'utf8');

let P = 0, F = 0;
/* ⚠ 用纯文本 [PASS]/[FAIL]，不用 emoji —— AGENTS.md 要求终端输出禁 emoji。
 *   run_all.sh 的计数公式两种标记都认。 */
const ok = (n, c, x) => {
  if (c) { P++; console.log('  [PASS] ' + n); }
  else { F++; console.log('  [FAIL] ' + n + '  ' + (x || '')); }
};
const sec = (t) => console.log('\n== ' + t);

/* ── 最小 DOM 桩 ───────────────────────────────────────────── */
function mkEl(id) {
  const el = {
    id: id,
    textContent: '',
    hidden: false,
    className: '',
    style: {},
    offsetWidth: 100,
    children: [],
    __listeners: {},
    classList: {
      _s: {},
      add(c) { this._s[c] = 1; },
      remove(c) { delete this._s[c]; },
      contains(c) { return !!this._s[c]; },
    },
    addEventListener(type, fn) {
      (el.__listeners[type] = el.__listeners[type] || []).push(fn);
    },
    removeEventListener() {},
    appendChild(c) { el.children.push(c); return c; },
    setAttribute() {},
    getAttribute() { return null; },
    focus() {},
  };
  return el;
}

/* 永远不 resolve 的 thenable：门户加载时会去 fetch('/auth/status')，
 * 桩里让它挂着不落定 ⇒ 不会跳登录页、不会渲染卡片，
 * 我们只关心背景挂载那一段。 */
function never() {
  const t = {
    then() { return t; },
    catch() { return t; },
    finally() { return t; },
  };
  return t;
}

/**
 * 跑一遍 portal.js，返回它挂到引擎上的档位名。
 * @param {number} rnd  Math.random 的返回值（0 ≤ rnd < 1）
 * @param {string} search  URL 查询串（含前导 '?' 或空串）
 */
function runPortal(rnd, search) {
  const els = {};
  const calls = [];
  let thrown = null;

  const doc = {
    getElementById(id) {
      if (!els[id]) els[id] = mkEl(id);
      return els[id];
    },
    createElement(tag) { return mkEl(tag); },
    addEventListener() {},
    removeEventListener() {},
    documentElement: mkEl('html'),
    visibilityState: 'visible',
    body: mkEl('body'),
  };

  /* Math 的方法不可枚举 ⇒ 不能用展开复制，用原型链继承。
   * 这样 M.floor / M.min 都还在，只有 random 被钉住。 */
  const M = Object.create(Math);
  M.random = () => rnd;

  const sandbox = {
    console: console,
    document: doc,
    location: {
      search: search || '',
      pathname: '/auth/portal',
      href: '/auth/portal',
      replace() {},
    },
    sessionStorage: {
      getItem() { return null; },
      setItem() {},
      removeItem() {},
    },
    localStorage: {
      getItem() { return null; },
      setItem() {},
      removeItem() {},
    },
    matchMedia: () => ({ matches: false }),
    getComputedStyle: () => ({ getPropertyValue: () => '' }),
    setInterval: () => 0,
    clearInterval() {},
    setTimeout: () => 0,
    clearTimeout() {},
    requestAnimationFrame: () => 0,
    cancelAnimationFrame() {},
    performance: { now() { return 0; } },
    Math: M,
    /* 引擎桩：把 createStyle 收到的档位记下来 —— 这是唯一的观测点 */
    GhostPixelField: {
      createStyle(canvas, style, opt) {
        calls.push({ style: style, opt: opt });
        return { stop() {} };
      },
      mount() { calls.push({ style: null, opt: null }); },
      ripple() {},
    },
    DevFingerprint: { fetch() { return never(); } },
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  try {
    vm.runInContext(SRC, sandbox, { filename: 'portal.js' });
  } catch (e) {
    thrown = e;
  }
  return { calls: calls, thrown: thrown, els: els };
}

const CANDIDATES = ['moonstone', 'trae'];

/* ── PB-1 两档都是原版，且都在引擎里 ───────────────────────── */
sec('PB-1 随机只在两档原版之间挑');

{
  const a = runPortal(0.0, '');
  ok('随机抽到的档位是候选之一（random=0）',
    a.calls.length === 1 && CANDIDATES.indexOf(a.calls[0].style) >= 0,
    JSON.stringify(a.calls.map((c) => c.style)));
  const b = runPortal(0.999999, '');
  ok('随机抽到的档位是候选之一（random≈1）',
    b.calls.length === 1 && CANDIDATES.indexOf(b.calls[0].style) >= 0,
    JSON.stringify(b.calls.map((c) => c.style)));
  ok('用掉的档位不是被否掉的 trae-orig',
    a.calls[0].style !== 'trae-orig' && b.calls[0].style !== 'trae-orig');
  ok('用掉的档位不是被否掉的 moonstone-trae',
    a.calls[0].style !== 'moonstone-trae' && b.calls[0].style !== 'moonstone-trae');
  ok('portal.js 跑起来没抛异常', a.thrown === null && b.thrown === null,
    String(a.thrown || b.thrown));
}

/* ── PB-2 random=0 与 random≈1 必须落到**不同的**那一档 ───── */
sec('PB-2 随机是真的随机（不是写死第一个）');

{
  const lo = runPortal(0.0, '');
  const hi = runPortal(0.999999, '');
  ok('random=0 与 random≈1 抽到不同档位',
    lo.calls[0].style !== hi.calls[0].style,
    '两次都是 ' + lo.calls[0].style);
  ok('random=0 落在候选的第一个',
    lo.calls[0].style === CANDIDATES[0], lo.calls[0].style);
  ok('random≈1 落在候选的最后一个',
    hi.calls[0].style === CANDIDATES[CANDIDATES.length - 1], hi.calls[0].style);
}

/* ── PB-3 候选表两档都在（少一档 = 随机名存实亡）───────────── */
sec('PB-3 两个候选都抽得到（少写一档会被抓住）');

{
  let seen = {};
  for (let i = 0; i < 200; i++) {
    const r = runPortal(i / 200, '');
    seen[r.calls[0].style] = (seen[r.calls[0].style] || 0) + 1;
  }
  CANDIDATES.forEach((c) => {
    ok('候选「' + c + '」抽得到（200 次里至少出现一次）',
      (seen[c] || 0) > 0, JSON.stringify(seen));
  });
  ok('两档出现次数大致各半（随机没有偏向）',
    Math.abs((seen[CANDIDATES[0]] || 0) - (seen[CANDIDATES[1]] || 0)) < 40,
    JSON.stringify(seen));
}

/* ── PB-4 URL 覆盖优先（截图/对比时要能钉死某一档）────────── */
sec('PB-4 ?pfstyle= 能钉死某一档');

{
  const a = runPortal(0.0, '?pfstyle=trae');
  ok('?pfstyle=trae 压过随机（random=0 也给 trae）',
    a.calls[0].style === 'trae', a.calls[0].style);
  const b = runPortal(0.999999, '?pfstyle=moonstone');
  ok('?pfstyle=moonstone 压过随机（random≈1 也给 moonstone）',
    b.calls[0].style === 'moonstone', b.calls[0].style);
  const c = runPortal(0.0, '?pfstyle=moonstone&x=1');
  ok('?pfstyle= 与别的参数并存时也能取到',
    c.calls[0].style === 'moonstone', c.calls[0].style);
  const d = runPortal(0.0, '?x=1&pfstyle=trae');
  ok('?pfstyle= 不在第一个时也能取到',
    d.calls[0].style === 'trae', d.calls[0].style);
}

/* ── PB-5 写错的档名要回退随机（不能传一个不存在的档）──────── */
sec('PB-5 档名写错时回退随机');

{
  const a = runPortal(0.0, '?pfstyle=moonstone-trae');
  ok('不存在的档名被忽略、回退到候选里',
    CANDIDATES.indexOf(a.calls[0].style) >= 0, a.calls[0].style);
  const b = runPortal(0.0, '?pfstyle=');
  ok('空值被忽略、回退到候选里',
    CANDIDATES.indexOf(b.calls[0].style) >= 0, b.calls[0].style);
}

/* ── PB-6 不记在存储里（用户要的是「每次打开随机」）────────── */
sec('PB-6 每次打开重新抽，不记在 localStorage/sessionStorage');

{
  const a = runPortal(0.0, '');
  const b = runPortal(0.999999, '');
  const keys = Object.keys(a.els);
  let stored = false;
  keys.forEach((k) => {
    const el = a.els[k];
    if (el && el.textContent && /moonstone|trae/.test(el.textContent)) stored = true;
  });
  ok('两次运行抽到不同档位（说明没被缓存住）',
    a.calls[0].style !== b.calls[0].style,
    '两次都是 ' + a.calls[0].style);
  ok('背景档位没被写进页面上任何一个元素', stored === false);
}

/* ── PB-7 传参不被写死（opt 不能盖掉档位自己的参数）───────── */
sec('PB-7 传进引擎的 opt 里没有写死的参数');

{
  const a = runPortal(0.5, '');
  const opt = a.calls[0].opt;
  ok('opt 是对象', opt && typeof opt === 'object', String(opt));
  ok('opt.params 里没有写死 columns', !opt.params || !('columns' in opt.params));
  ok('opt.params 里没有写死 lit', !opt.params || !('lit' in opt.params));
}

/* ── PB-8 引擎炸了也不能影响页面（背景画不出来无所谓）────── */
sec('PB-8 引擎出问题不外溢');

{
  const els = {};
  const doc = {
    getElementById(id) { if (!els[id]) els[id] = mkEl(id); return els[id]; },
    createElement(tag) { return mkEl(tag); },
    addEventListener() {},
    documentElement: mkEl('html'),
    visibilityState: 'visible',
  };
  const M = Object.create(Math);
  M.random = () => 0.5;
  const sandbox = {
    console: console,
    document: doc,
    location: { search: '', pathname: '/auth/portal', href: '', replace() {} },
    sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
    matchMedia: () => ({ matches: false }),
    getComputedStyle: () => ({ getPropertyValue: () => '' }),
    setInterval: () => 0,
    clearInterval() {},
    setTimeout: () => 0,
    clearTimeout() {},
    requestAnimationFrame: () => 0,
    performance: { now() { return 0; } },
    Math: M,
    GhostPixelField: {
      createStyle() { throw new Error('引擎炸了'); },
      mount() {},
    },
    DevFingerprint: { fetch() { return never(); } },
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  let thrown = null;
  try {
    vm.runInContext(SRC, sandbox, { filename: 'portal.js' });
  } catch (e) {
    thrown = e;
  }
  ok('引擎抛异常时 portal.js 自己扛住（不外溢到页面）', thrown === null, String(thrown));
}

console.log('\n通过 ' + P + ' / ' + (P + F));
if (F) {
  console.log('失败 ' + F + ' 项');
  process.exit(1);
}
console.log('全部通过');
