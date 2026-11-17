/* 极简模式开关的行为级测试（Node + 最小 DOM 桩）
 *
 * 运行: node tests/test_plain_mode.js
 * 零依赖：只用 Node 内置模块（fs / path / vm）。
 *
 * 这一批是什么（2026-11-17）
 * ---------------------------------
 * 面板（5443）默认那套观感是「玻璃 + 动效」：磨砂铺在 7 个选择器上，
 * 像素场背景每帧重绘一次全屏画布。实测（headless + 软件光栅）：
 *
 *   只去磨砂   → 帧率 7.8 → 54.8（磨砂是帧率瓶颈）
 *   只去像素场 → 帧率不变，脚本耗时 1.109s → 0.001s（像素场是 CPU 瓶颈）
 *
 * ⇒ 做了一个**能记住**的开关：打开后磨砂、动效、像素场全不要，
 *   页面只剩最简元素。开关本体在 frontend/plainmode.js。
 *
 * 为什么这个文件**必须真跑脚本**
 * ---------------------------------
 * 开关最要紧的两条性质都是「跑起来才知道」的：
 *   · 首屏就要生效 —— 状态得在 <html> 的 class 上摆好，迟一步就会闪一帧动效；
 *   · 极简模式下像素场**不许挂载** —— 藏起来没用，rAF 还在跑，
 *     每帧照样 putImageData（实测每帧约 14ms JS），CPU 一分都不省。
 * 静态断言钉不住这两条 ⇒ 这里把 plainmode.js 与 pixelbg.js 塞进 vm 沙箱真跑。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const PLAIN_SRC = fs.readFileSync(path.join(ROOT, 'frontend', 'plainmode.js'), 'utf8');
const PIX_SRC = fs.readFileSync(path.join(ROOT, 'frontend', 'pixelbg.js'), 'utf8');

let P = 0, F = 0;
const ok = (n, c, x) => {
  if (c) { P++; console.log('  [PASS] ' + n); }
  else { F++; console.log('  [FAIL] ' + n + '  ' + (x || '')); }
};
const sec = (t) => console.log('\n== ' + t);

/* ── 最小 DOM 桩 ───────────────────────────────────────────── */
function mkClassList() {
  const s = new Set();
  return {
    _s: s,
    add(c) { s.add(c); },
    remove(c) { s.delete(c); },
    contains(c) { return s.has(c); },
  };
}

function mkEl(id) {
  return {
    id: id,
    style: {},
    classList: mkClassList(),
    addEventListener() {},
    removeEventListener() {},
    getBoundingClientRect() { return { width: 1440, height: 900, left: 0, top: 0 }; },
  };
}

/**
 * 跑一遍 plainmode.js。
 * @param {object} opt
 *   stored   localStorage 里预置的值（null = 没有这个键）
 *   noStore  localStorage 抛异常（隐私模式/存储被禁用）
 */
function runPlain(opt) {
  opt = opt || {};
  const store = {};
  if (opt.stored !== undefined && opt.stored !== null) store.nf_plain_mode = opt.stored;

  const localStorage = {
    getItem(k) { return (k in store) ? store[k] : null; },
    setItem(k, v) { store[k] = String(v); },
  };
  const doc = { documentElement: mkEl('html') };

  const sandbox = {
    console: console,
    document: doc,
    localStorage: opt.noStore ? {
      getItem() { throw new Error('存储被禁用'); },
      setItem() { throw new Error('存储被禁用'); },
    } : localStorage,
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);

  let thrown = null;
  try {
    vm.runInContext(PLAIN_SRC, sandbox, { filename: 'plainmode.js' });
  } catch (e) {
    thrown = e;
  }
  return {
    thrown: thrown,
    sandbox: sandbox,
    store: store,
    html: doc.documentElement,
    hasClass: (c) => doc.documentElement.classList.contains(c),
  };
}

/**
 * 跑一遍 pixelbg.js。
 * @param {object} opt
 *   plain   极简模式是否开着（往 sandbox.NfPlain.isOn 里塞）
 */
function runPixel(opt) {
  opt = opt || {};
  const calls = [];
  const els = {};
  let stopped = 0, started = 0;

  const doc = {
    readyState: 'complete',
    getElementById(id) {
      if (!els[id]) els[id] = mkEl(id);
      return els[id];
    },
    addEventListener() {},
    createElement() { return mkEl('x'); },
    documentElement: mkEl('html'),
  };

  const sandbox = {
    console: console,
    document: doc,
    location: { search: '', pathname: '/', href: '/' },
    matchMedia: () => ({ matches: false }),
    requestAnimationFrame: () => 0,
    cancelAnimationFrame() {},
    performance: { now() { return 0; } },
    Math: Object.assign(Object.create(Math), { random: () => 0.5 }),
    GhostPixelField: {
      createStyle(canvas, style, o) {
        calls.push({ canvas: canvas, style: style, opt: o });
        return {
          stop() { stopped++; },
          start() { started++; },
        };
      },
      mount() { calls.push({ canvas: null, style: null, opt: null }); },
    },
  };
  if (opt.plain !== undefined) {
    sandbox.NfPlain = { isOn: () => !!opt.plain, set() {} };
  }
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);

  let thrown = null;
  try {
    vm.runInContext(PIX_SRC, sandbox, { filename: 'pixelbg.js' });
  } catch (e) {
    thrown = e;
  }
  return {
    calls: calls, thrown: thrown, sandbox: sandbox,
    get stopped() { return stopped; },
    get started() { return started; },
    canvas: els['nf-pix'],
  };
}

/* ── PM-1 首屏就要生效（迟一步就会闪一帧动效）───────────── */
sec('PM-1 首屏同步生效');

{
  const on = runPlain({ stored: '1' });
  ok('本地存着开启 ⇒ <html> 立刻带上 nf-plain',
    on.hasClass('nf-plain'), JSON.stringify([...on.html.classList._s]));
  ok('加载过程不抛异常', on.thrown === null, String(on.thrown));

  const off = runPlain({ stored: '0' });
  ok('本地存着关闭 ⇒ 不带 nf-plain', !off.hasClass('nf-plain'));
  ok('加载过程不抛异常', off.thrown === null, String(off.thrown));

  const fresh = runPlain({});
  ok('第一次访问（没存过）⇒ 默认不是极简', !fresh.hasClass('nf-plain'));
}

/* ── PM-2 开关能切、且记住 ────────────────────────────────── */
sec('PM-2 开关能切、且记住');

{
  const a = runPlain({});
  a.sandbox.NfPlain.set(true);
  ok('切到开 ⇒ class 加上', a.hasClass('nf-plain'));
  ok('切到开 ⇒ 本地记下', a.store.nf_plain_mode === '1', String(a.store.nf_plain_mode));
  ok('isOn() 跟着走', a.sandbox.NfPlain.isOn() === true);

  a.sandbox.NfPlain.set(false);
  ok('切到关 ⇒ class 去掉', !a.hasClass('nf-plain'));
  ok('切到关 ⇒ 本地记下', a.store.nf_plain_mode === '0', String(a.store.nf_plain_mode));
  ok('isOn() 跟着走', a.sandbox.NfPlain.isOn() === false);

  /* 再开一次，确认不是「只认第一次」 */
  a.sandbox.NfPlain.set(true);
  ok('反复切都灵', a.hasClass('nf-plain') && a.store.nf_plain_mode === '1');
}

/* ── PM-3 存不了也不能崩（隐私模式）──────────────────────── */
sec('PM-3 localStorage 不可用时不崩');

{
  const a = runPlain({ noStore: true });
  ok('加载不抛异常', a.thrown === null, String(a.thrown));
  let thrown = null;
  try {
    a.sandbox.NfPlain.set(true);
  } catch (e) {
    thrown = e;
  }
  ok('切开关不抛异常', thrown === null, String(thrown));
  ok('存不了也要把 class 摆上（本次会话仍生效）', a.hasClass('nf-plain'));
}

/* ── PM-4 极简模式下像素场不许挂载 ───────────────────────── */
sec('PM-4 极简模式下像素场不挂载');

{
  const plain = runPixel({ plain: true });
  ok('极简模式下引擎没被调用（藏起来不算）',
    plain.calls.length === 0, JSON.stringify(plain.calls.map((c) => c.style)));
  ok('画布被藏起来', plain.canvas && plain.canvas.style.display === 'none',
    plain.canvas && plain.canvas.style.display);
  ok('脚本不抛异常', plain.thrown === null, String(plain.thrown));

  const normal = runPixel({});
  ok('普通模式下照旧挂载', normal.calls.length === 1,
    JSON.stringify(normal.calls.map((c) => c.style)));
  ok('普通模式下画布可见',
    !normal.canvas || normal.canvas.style.display !== 'none');
}

/* ── PM-5 切换时像素场要跟着停 / 起 ─────────────────────── */
sec('PM-5 切换时像素场跟着停 / 起');

{
  const a = runPixel({});
  ok('先挂上了', a.calls.length === 1);
  a.sandbox.__panelPixelBg.apply(true);
  ok('切到极简 ⇒ 引擎被停掉', a.stopped === 1, String(a.stopped));
  ok('切到极简 ⇒ 画布被藏', a.canvas.style.display === 'none', a.canvas.style.display);

  a.sandbox.__panelPixelBg.apply(false);
  ok('切回普通 ⇒ 引擎重新跑起来', a.started === 1, String(a.started));
  ok('切回普通 ⇒ 画布可见', a.canvas.style.display === '', a.canvas.style.display);
  ok('切回普通 ⇒ 没有重复挂载', a.calls.length === 1, String(a.calls.length));

  /* 首屏就是极简（引擎从没挂过）⇒ 切回普通时才第一次挂 */
  const b = runPixel({ plain: true });
  ok('首屏极简 ⇒ 没挂过', b.calls.length === 0);
  b.sandbox.__panelPixelBg.apply(false);
  ok('切回普通 ⇒ 这时才第一次挂', b.calls.length === 1,
    JSON.stringify(b.calls.map((c) => c.style)));
  ok('切回普通 ⇒ 画布可见（尺寸才量得到）', b.canvas.style.display === '',
    b.canvas.style.display);
}

/* ── PM-6 开关要通知得到像素场 ───────────────────────────── */
sec('PM-6 开关通知得到像素场');

{
  const a = runPlain({});
  let got = null;
  a.sandbox.__panelPixelBg = { apply: (v) => { got = v; } };
  a.sandbox.NfPlain.set(true);
  ok('切开关 ⇒ 通知了像素场', got === true, String(got));

  /* 像素场还没就绪（defer 脚本没跑）时也不能炸 */
  const b = runPlain({});
  let thrown = null;
  try {
    b.sandbox.NfPlain.set(true);
  } catch (e) {
    thrown = e;
  }
  ok('像素场还没就绪时切开关不抛异常', thrown === null, String(thrown));
  ok('像素场还没就绪时 class 照样摆上', b.hasClass('nf-plain'));
}

console.log('\n通过 ' + P + ' / ' + (P + F));
if (F) {
  console.log('失败 ' + F + ' 项');
  process.exit(1);
}
console.log('全部通过');
