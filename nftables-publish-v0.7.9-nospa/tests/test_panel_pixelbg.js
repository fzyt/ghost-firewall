/* 面板（5443）像素场背景的行为级测试（Node + 最小 DOM 桩）
 *
 * 运行: node tests/test_panel_pixelbg.js
 * 零依赖：只用 Node 内置模块（fs / path / vm）。
 *
 * 这一批是什么（2026-11-04 第十三轮）
 * ---------------------------------
 * 用户原话：「这个5443界面你要么也做一套」
 * ⇒ 面板（管理面板，5443）接上**与服务门户同一套**像素场引擎
 *   （backend/static/pixelfield.js，面板从那里取，不留拷贝），
 *   并且用**同一份候选表**：每次打开在两档原版之间随机。
 *
 * 为什么这个文件**必须真跑 pixelbg.js**
 * ------------------------------------
 * 「随机」这件事静态断言钉不住：
 *   把 `Math.floor(Math.random() * n)` 写成 `0`，面板就永远显示同一档，
 *   页面上完全看不出异常，静态断言照样全绿。
 *   候选表少写一档（只留 moonstone）也是同一种退化。
 *
 * ⇒ 这里真把 pixelbg.js 塞进 vm 沙箱跑一遍，桩掉 document / window，
 *   把 createStyle 收到的**档位参数**记下来，用可控的随机值把
 *   「抽到哪一档」钉死。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(ROOT, 'frontend', 'pixelbg.js'), 'utf8');

let P = 0, F = 0;
const ok = (n, c, x) => {
  if (c) { P++; console.log('  [PASS] ' + n); }
  else { F++; console.log('  [FAIL] ' + n + '  ' + (x || '')); }
};
const sec = (t) => console.log('\n== ' + t);

const CANDIDATES = ['moonstone', 'trae'];

/* ── 最小 DOM 桩 ───────────────────────────────────────────── */
function mkEl(id) {
  return {
    id: id,
    style: {},
    classList: { _s: {}, add() {}, remove() {}, contains() { return false; } },
    addEventListener() {},
    removeEventListener() {},
    getBoundingClientRect() { return { width: 1440, height: 900, left: 0, top: 0 }; },
  };
}

/**
 * 跑一遍 pixelbg.js，返回它挂到引擎上的档位。
 * @param {object} opt
 *   rnd      随机值（0 ≤ rnd < 1），null 表示用真随机
 *   search   URL 查询串（含前导 '?' 或空串）
 *   reduce   是否 prefers-reduced-motion
 *   noCanvas 画布不存在（测降级）
 *   noEngine 引擎不存在（测降级）
 *   throwOnCreate 引擎抛异常（测降级）
 */
function runPanel(opt) {
  opt = opt || {};
  const calls = [];
  const els = {};
  let thrown = null;

  const doc = {
    readyState: 'complete',
    getElementById(id) {
      if (opt.noCanvas) return null;
      if (!els[id]) els[id] = mkEl(id);
      return els[id];
    },
    addEventListener() {},
    createElement() { return mkEl('x'); },
    documentElement: mkEl('html'),
  };

  const M = Object.create(Math);
  M.random = () => (opt.rnd === undefined || opt.rnd === null ? 0.5 : opt.rnd);

  const sandbox = {
    console: console,
    document: doc,
    location: { search: opt.search || '', pathname: '/', href: '/' },
    matchMedia: () => ({ matches: !!opt.reduce }),
    requestAnimationFrame: () => 0,
    cancelAnimationFrame() {},
    performance: { now() { return 0; } },
    Math: M,
  };
  if (!opt.noEngine) {
    sandbox.GhostPixelField = {
      createStyle(canvas, style, o) {
        if (opt.throwOnCreate) throw new Error('引擎炸了');
        calls.push({ canvas: canvas, style: style, opt: o });
        return { stop() {} };
      },
      mount() { calls.push({ canvas: null, style: null, opt: null }); },
    };
  }
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  try {
    vm.runInContext(SRC, sandbox, { filename: 'pixelbg.js' });
  } catch (e) {
    thrown = e;
  }
  return { calls: calls, thrown: thrown, sandbox: sandbox };
}

/* ── PP-1 面板用的是「原版 / TRAE 原版」两档 ───────────────── */
sec('PP-1 候选表就是两档原版');

{
  const a = runPanel({ rnd: 0.0 });
  ok('挂载到了引擎（createStyle 被调用）', a.calls.length === 1,
    JSON.stringify(a.calls.map((c) => c.style)));
  ok('random=0 落在候选的第一个',
    a.calls.length && a.calls[0].style === CANDIDATES[0], a.calls[0] && a.calls[0].style);
  const b = runPanel({ rnd: 0.999999 });
  ok('random≈1 落在候选的最后一个',
    b.calls.length && b.calls[0].style === CANDIDATES[CANDIDATES.length - 1],
    b.calls[0] && b.calls[0].style);
  ok('两档都不含被否掉的混合方案',
    CANDIDATES.indexOf('trae-orig') < 0 && CANDIDATES.indexOf('moonstone-trae') < 0);
  ok('面板脚本自己没抛异常', a.thrown === null && b.thrown === null,
    String(a.thrown || b.thrown));
}

/* ── PP-2 两档都抽得到（少写一档会被抓住）─────────────────── */
sec('PP-2 候选表少一档 = 随机名存实亡');

{
  const seen = {};
  for (let i = 0; i < 200; i++) {
    const r = runPanel({ rnd: i / 200 });
    if (r.calls[0]) seen[r.calls[0].style] = (seen[r.calls[0].style] || 0) + 1;
  }
  CANDIDATES.forEach((c) => {
    ok('候选「' + c + '」抽得到', (seen[c] || 0) > 0, JSON.stringify(seen));
  });
  ok('两档次数大致各半', Math.abs((seen[CANDIDATES[0]] || 0) - (seen[CANDIDATES[1]] || 0)) < 40,
    JSON.stringify(seen));
}

/* ── PP-3 ?pfstyle= 能钉死某一档 ──────────────────────────── */
sec('PP-3 ?pfstyle= 能钉死某一档');

{
  const a = runPanel({ rnd: 0.0, search: '?pfstyle=trae' });
  ok('?pfstyle=trae 压过随机', a.calls[0] && a.calls[0].style === 'trae',
    a.calls[0] && a.calls[0].style);
  const b = runPanel({ rnd: 0.999999, search: '?pfstyle=moonstone' });
  ok('?pfstyle=moonstone 压过随机', b.calls[0] && b.calls[0].style === 'moonstone',
    b.calls[0] && b.calls[0].style);
  const c = runPanel({ rnd: 0.0, search: '?pfstyle=moonstone-trae' });
  ok('不存在的档名被忽略、回退到候选里',
    c.calls[0] && CANDIDATES.indexOf(c.calls[0].style) >= 0,
    c.calls[0] && c.calls[0].style);
}

/* ── PP-4 画布与动效降级 ─────────────────────────────────── */
sec('PP-4 画布、动效降级');

{
  const a = runPanel({ rnd: 0.5 });
  ok('画布就是页面里那个 nf-pix',
    a.calls[0] && a.calls[0].canvas && a.calls[0].canvas.id === 'nf-pix',
    a.calls[0] && a.calls[0].canvas && a.calls[0].canvas.id);
  const b = runPanel({ rnd: 0.5, reduce: true });
  ok('prefers-reduced-motion 时引擎走静态模式',
    b.calls[0] && b.calls[0].opt && b.calls[0].opt.static === true,
    JSON.stringify(b.calls[0] && b.calls[0].opt));
  const c = runPanel({ rnd: 0.5 });
  ok('默认不是静态模式（画面要动）',
    c.calls[0] && c.calls[0].opt && c.calls[0].opt.static === false,
    JSON.stringify(c.calls[0] && c.calls[0].opt));
  ok('opt 里没有写死 columns/lit（档位自己说了算）',
    c.calls[0] && c.calls[0].opt && !c.calls[0].opt.params);
}

/* ── PP-5 降级路径：画布/引擎/引擎异常都不许炸页面 ───────── */
sec('PP-5 背景画不出来，页面照常用');

{
  const a = runPanel({ rnd: 0.5, noCanvas: true });
  ok('没有画布时安静跳过', a.calls.length === 0 && a.thrown === null);
  const b = runPanel({ rnd: 0.5, noEngine: true });
  ok('引擎不存在时安静跳过', b.calls.length === 0 && b.thrown === null,
    String(b.thrown));
  const c = runPanel({ rnd: 0.5, throwOnCreate: true });
  ok('引擎抛异常时被自己扛住（不外溢）', c.thrown === null, String(c.thrown));
}

/* ── PP-6 脚本自己暴露的接口与候选表一致 ─────────────────── */
sec('PP-6 暴露出来的候选表与实际行为一致');

{
  const a = runPanel({ rnd: 0.5 });
  const api = a.sandbox.__panelPixelBg;
  ok('暴露了 pickStyle 与候选表', !!api && Array.isArray(api.candidates));
  if (api) {
    ok('候选表正好是两档原版',
      api.candidates.length === 2 &&
      api.candidates.indexOf('moonstone') >= 0 &&
      api.candidates.indexOf('trae') >= 0,
      JSON.stringify(api.candidates));
    ok('pickStyle 可以直接指定随机源',
      api.pickStyle(function () { return 0.999999; }) === 'trae',
      api.pickStyle(function () { return 0.999999; }));
  }
}

console.log('\n通过 ' + P + ' / ' + (P + F));
if (F) {
  console.log('失败 ' + F + ' 项');
  process.exit(1);
}
console.log('全部通过');
