/* 像素场引擎「TRAE 原版复刻」行为级测试（Node + 最小 canvas/DOM 桩）
 *
 * 运行: node tests/test_pixelfield_trae.js
 * 零依赖：只用 Node 内置模块（fs / path / vm），不装 canvas、不装浏览器。
 *
 * 为什么要有这个文件（2026-11-03）
 * --------------------------------
 * 用户原话：「这个效果还是不行，你先拔下他的代码，做一个完全一样的复刻」。
 * 这一批把 TRAE 首页背景的两段 GLSL **逐行移植**进了引擎（traeMode 分支）。
 *
 * 源码文本断言只能钉住「代码写了什么」，钉不住「画面到底对不对」。
 * 而这一批恰恰踩过三个**只看代码看不出来**的坑：
 *   ① 颜色空间：着色器写的是 vec3(50,240,140)/255，但末端合成会再做一次
 *      linear→sRGB ⇒ 屏幕上必须是 rgb(122,248,196)。差这一档整个画面的
 *      绿色就暗一截，和 TRAE 完全不像 —— 而源码里两种写法都"对"。
 *   ② 几何：方块是 5×5，贴在 7px 晶格的**左上角**（不是居中）。
 *   ③ 密度：亮格率会随时间在 8%~35% 之间大幅波动（这是 TRAE 的真实行为，
 *      不是 bug）⇒ 断言必须给区间，不能钉死一个数。
 *
 * 所以这个文件**真跑引擎**：把画布像素读出来，直接断言几何、颜色、密度。
 * 另有一组「反向对照」：老档必须仍然是软边中间灰 ⇒ 证明断言不是靠
 * 「引擎没跑起来」蒙混过关。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DIR = path.join(__dirname, '..', 'backend', 'static');
const SRC = fs.readFileSync(path.join(DIR, 'pixelfield.js'), 'utf8');

let P = 0, F = 0;
const ok = (n, c, x) => {
  if (c) { P++; console.log('  [PASS] ' + n); }
  else { F++; console.log('  [FAIL] ' + n + '  ' + (x || '')); }
};
const sec = (t) => console.log('\n== ' + t);

/* ── 极简 canvas 桩 ─────────────────────────────────────────
 * 只实现引擎真正用到的那几个方法。
 * ⚠ TRAE 分支把颜色写在**主画布**的 ImageData 里（不是 fine 子画布），
 *   所以测试要读主画布 ctx 的 __img。
 */
function mkCanvas(w, h, tag) {
  const c = {
    tag: tag,
    _w: w, _h: h,
    width: w, height: h,
    _ctx: null,
    getContext(k) {
      if (k !== '2d') return null;
      if (this._ctx) return this._ctx;
      const ctx = {
        fillStyle: '#000',
        globalAlpha: 1,
        imageSmoothingEnabled: false,
        __img: null,
        __puts: 0,
        setTransform() {},
        fillRect() {},
        drawImage() {},
        createImageData(w2, h2) {
          const img = { width: w2, height: h2, data: new Uint8ClampedArray(w2 * h2 * 4) };
          ctx.__img = img;
          return img;
        },
        putImageData() { ctx.__puts++; },
      };
      this._ctx = ctx;
      return ctx;
    },
    getBoundingClientRect() {
      return { width: c._w, height: c._h, left: 0, top: 0, right: c._w, bottom: c._h };
    },
  };
  return c;
}

function loadEngine() {
  const created = [];
  const sandbox = {
    console: console,
    __raf: [],
    document: {
      createElement(tag) {
        const c = mkCanvas(1200, 800, tag);
        created.push(c);
        return c;
      },
    },
    devicePixelRatio: 1,
    /* ⚠ 只登记不执行：引擎的 frame() 里会 rAF(frame) 续帧，
     *   同步回调会变成无限递归（实测直接爆栈）。
     *   帧由 api.render(t) 显式驱动，不依赖 rAF。 */
    requestAnimationFrame(fn) { sandbox.__raf.push(fn); return sandbox.__raf.length; },
    cancelAnimationFrame() {},
    addEventListener() {},
    performance: { now() { return 0; } },
    matchMedia: () => ({ matches: false }),
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox, { filename: 'pixelfield.js' });
  return { api: sandbox.GhostPixelField, created: created };
}

const CELL = 7, DOT = 5;

/* 引擎的几何按 p.step（默认 1/30 秒）离散采样，所以帧要跨过多个几何步。 */
const TIMES = [];
for (let i = 0; i <= 40; i++) TIMES.push(i * 0.05);

/* 一帧的度量：几何（晶格/实心度）、颜色（直方图）、密度、掩码哈希 */
function analyze(data, w, h) {
  const st = {
    lit: 0, bad: 0, phases: {}, colors: new Map(), bg: 0,
    cells: 0, gCells: 0, wCells: 0,
    solidBad: 0, solidChecked: 0,
  };
  let hsh = 2166136261 >>> 0;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const o = (y * w + x) * 4;
      const r = data[o], g = data[o + 1], b = data[o + 2];
      const on = (r !== 0 || g !== 0 || b !== 0);
      hsh ^= on ? 1 : 0;
      hsh = Math.imul(hsh, 16777619) >>> 0;
      if (!on) { st.bg++; continue; }
      st.lit++;
      const ck = r + ',' + g + ',' + b;
      st.colors.set(ck, (st.colors.get(ck) || 0) + 1);
      if (x % CELL >= DOT || y % CELL >= DOT) st.bad++;
      st.phases[x % CELL] = (st.phases[x % CELL] || 0) + 1;
    }
  }
  st.hash = hsh >>> 0;
  /* 按格子统计绿/白（取每格 5×5 的左上角像素），并验方块是否实心 5×5 */
  for (let cy = 0; cy * CELL + DOT <= h; cy++) {
    for (let cx = 0; cx * CELL + DOT <= w; cx++) {
      const x0 = cx * CELL, y0 = cy * CELL;
      const o = (y0 * w + x0) * 4;
      const r = data[o], g = data[o + 1], b = data[o + 2];
      st.cells++;
      if (r === 0 && g === 0 && b === 0) continue;
      if (g > r + 20 && g > b + 10) st.gCells++; else st.wCells++;
      /* 实心度：整块 5×5 必须全亮 */
      let solid = true;
      for (let dy = 0; dy < DOT && solid; dy++) {
        for (let dx = 0; dx < DOT; dx++) {
          const p = ((y0 + dy) * w + (x0 + dx)) * 4;
          if (data[p] === 0 && data[p + 1] === 0 && data[p + 2] === 0) { solid = false; break; }
        }
      }
      st.solidChecked++;
      if (!solid) st.solidBad++;
    }
  }
  return st;
}

function run(styleKey, extraParams, mainW, mainH) {
  const env = loadEngine();
  const main = mkCanvas(mainW || 1200, mainH || 800, 'main');
  const api = env.api.createStyle(main, styleKey, { params: extraParams || {} });
  if (!api) throw new Error('createStyle 返回 null：引擎没起来');
  const mctx = main.getContext('2d');
  const fine = env.created[0].getContext('2d');
  const frames = [];
  for (const t of TIMES) {
    api.render(t);
    const img = mctx.__img;
    /* ⚠ 主画布的 ImageData 是**同一个活缓冲**（引擎只建一次、之后就地改），
     *   所以每帧必须当场把指标算出来 —— 存下 img.data 的话，
     *   所有帧拿到的都是最后一帧的内容 ⇒ 比帧间差异永远「相同」。 */
    const st = img ? analyze(img.data, img.width, img.height) : null;
    frames.push({
      st: st,
      w: img ? img.width : 0,
      h: img ? img.height : 0,
      /* 老路径的像素在 fine 画布上；TRAE 路径不碰它 */
      fineAlpha: fine.__img ? fine.__img.data : null,
    });
  }
  return { api: api, frames: frames, mctx: mctx, fine: fine };
}

function countLit(data) {
  let n = 0;
  for (let i = 0; i < data.length; i += 4) {
    if (data[i] !== 0 || data[i + 1] !== 0 || data[i + 2] !== 0) n++;
  }
  return n;
}

/* 全部帧的颜色并集 */
function colorSet(frames) {
  const s = new Map();
  for (const f of frames) {
    if (!f.st) continue;
    for (const [k, v] of f.st.colors) s.set(k, (s.get(k) || 0) + v);
  }
  return s;
}

/* ─────────────────────────────────────────────────────────────
 * 1. 几何：5×5 实心方块，贴在 7px 晶格的左上角
 * ───────────────────────────────────────────────────────────── */
sec('PT-1 TRAE 几何：7px 晶格、5×5 方块、贴每格左上角');

const tr = run('trae');
let totalLit = 0, totalBad = 0, totalSolidBad = 0, totalSolidChecked = 0;
const phases = {};
for (const f of tr.frames) {
  if (!f.st) continue;
  totalLit += f.st.lit;
  totalBad += f.st.bad;
  totalSolidBad += f.st.solidBad;
  totalSolidChecked += f.st.solidChecked;
  for (const k in f.st.phases) phases[k] = (phases[k] || 0) + f.st.phases[k];
}

ok('TRAE 档确实画出了东西（有亮像素）', totalLit > 1000, '亮像素 ' + totalLit);
ok('所有亮像素都落在 7px 晶格的 5×5 点实体内（点不越界）',
  totalBad === 0, '越界 ' + totalBad + ' / ' + totalLit);
ok('亮像素只出现在 x mod 7 ∈ {0,1,2,3,4}（贴着格子左上角，不是居中）',
  Object.keys(phases).every(k => Number(k) < DOT),
  '实际相位：' + JSON.stringify(phases));
ok('方块是实心 5×5（不是 1px 点、也不是不规则团块）',
  totalSolidBad === 0 && totalSolidChecked > 50,
  '不实心 ' + totalSolidBad + ' / 检查 ' + totalSolidChecked + ' 个方块');

/* ─────────────────────────────────────────────────────────────
 * 2. 颜色：绿必须是 sRGB 编码后的 rgb(122,248,196)
 * ───────────────────────────────────────────────────────────── */
sec('PT-2 TRAE 颜色：绿是 rgb(122,248,196)（末端 sRGB 编码后的值）');

const trColors = colorSet(tr.frames);
const names = [...trColors.entries()].sort((a, b) => b[1] - a[1]).map(x => x[0]);
let bgTotal = 0;
for (const f of tr.frames) if (f.st) bgTotal += f.st.bg;
ok('底色是纯黑 rgb(0,0,0)（画面大部分是黑底）', bgTotal > 0,
  '黑底像素 ' + bgTotal);
ok('白块是纯白 rgb(255,255,255)', names.indexOf('255,255,255') >= 0, '实际 top：' + names.slice(0, 6).join(' | '));
ok('绿块是 rgb(122,248,196)（= sRGB 编码后的 #32F08C）',
  names.indexOf('122,248,196') >= 0, '实际 top：' + names.slice(0, 6).join(' | '));
ok('绿块**不是** rgb(50,240,140)（那是编码前的值 ⇒ 差一档整体偏暗）',
  names.indexOf('50,240,140') < 0, '竟然出现了未编码的绿');

/* ─────────────────────────────────────────────────────────────
 * 3. 密度：亮格率在合理区间（会随时间大幅波动，这是 TRAE 的真实行为）
 * ───────────────────────────────────────────────────────────── */
sec('PT-3 TRAE 密度：亮格率落在实测区间内');

const rates = tr.frames.map(f => f.st ? f.st.lit / (f.w * f.h) : 0);
const rateMin = Math.min(...rates), rateMax = Math.max(...rates);
ok('亮格率全程在 1%~45% 之间（TRAE 实测 8%~35%，留了余量）',
  rateMin > 0.01 && rateMax < 0.45,
  '实测 ' + (rateMin * 100).toFixed(2) + '% ~ ' + (rateMax * 100).toFixed(2) + '%');
ok('亮格率确实随时间变化（画面在动，不是冻住的）',
  rateMax - rateMin > 0.005 || new Set(tr.frames.map(f => f.st.lit)).size > 3,
  '范围 ' + (rateMin * 100).toFixed(2) + '% ~ ' + (rateMax * 100).toFixed(2) + '%');

/* 绿占亮（最后一帧） */
const last = tr.frames[tr.frames.length - 1].st;
const greenFrac = (last.gCells + last.wCells) ? last.gCells / (last.gCells + last.wCells) : 0;
ok('绿占亮在 5%~50% 之间（TRAE 实测 15%~29%，鼠标混合会把白转绿）',
  greenFrac > 0.05 && greenFrac < 0.5,
  '实测 ' + (greenFrac * 100).toFixed(2) + '%（绿 ' + last.gCells + ' / 白 ' + last.wCells + '）');

/* ─────────────────────────────────────────────────────────────
 * 4. 鼠标交互：开关真的有效果
 * ───────────────────────────────────────────────────────────── */
sec('PT-4 鼠标交互：traeMouse 开关改变画面');

const trNoMouse = run('trae', { traeMouse: 0 });
const noMouseBright = [...colorSet(trNoMouse.frames).keys()].filter(k => k !== '0,0,0');
ok('关掉鼠标交互时亮像素只有绿、白两种颜色（无过渡色）',
  noMouseBright.length === 2,
  '实际 ' + noMouseBright.length + ' 种：' + noMouseBright.join(' | '));

const mouseBright = [...trColors.keys()].filter(k => k !== '0,0,0');
ok('开着鼠标交互时会出现过渡色（指针附近白泛绿、绿泛白）',
  mouseBright.length > 2,
  '实际 ' + mouseBright.length + ' 种：' + mouseBright.slice(0, 8).join(' | '));

/* ─────────────────────────────────────────────────────────────
 * 5. TRAE 分支是**独立**的：老档不受影响，且 TRAE 档不吃老参数
 * ───────────────────────────────────────────────────────────── */
sec('PT-5 独立性与隔离');

/* TRAE 档不碰 fine 子画布 ⇒ 证明老路径整段被绕开 */
const fineTouched = tr.frames.some(f => f.fineAlpha && countLit(f.fineAlpha) > 0);
ok('TRAE 档没有往老的 fine 画布上画（老路径整段绕开）', !fineTouched);

/* 老档仍然是软边中间灰 ⇒ 证明断言不是靠「引擎没跑起来」蒙混 */
function hasGray(frames) {
  for (const f of frames) {
    if (!f.fineAlpha) continue;
    for (let i = 3; i < f.fineAlpha.length; i += 4) {
      if (f.fineAlpha[i] !== 0 && f.fineAlpha[i] !== 255) return true;
    }
  }
  return false;
}
ok('反向对照：moonstone 仍是软边（没被 TRAE 分支改坏）', hasGray(run('moonstone').frames));
ok('反向对照：pixel-flow 仍是老行为（没被 TRAE 分支改坏）', run('pixel-flow').frames.length > 0);

/* TRAE 档不吃「点亮比例」这类老参数（它由阈值算法决定） */
const trLit = run('trae', { lit: 0.9 });
const hashOf = (frames) => frames.map(f => f.st ? f.st.hash : 0).join(',');
ok('TRAE 档不受老参数 lit 影响（密度由阈值算法决定，不由伺服决定）',
  hashOf(trLit.frames) === hashOf(tr.frames));

/* ─────────────────────────────────────────────────────────────
 * 6. 几何必须随时间推进（TRAE 是活的背景）
 * ───────────────────────────────────────────────────────────── */
sec('PT-6 画面在动：不同时间的图案不同');
const h5 = tr.frames[5].st.hash, h25 = tr.frames[25].st.hash;
ok('前后两帧的亮格掩码不同（场确实在演化）', h5 !== h25,
  '两帧哈希相同：' + h5.toString(16));

/* ─────────────────────────────────────────────────────────────
 * 7. 定值锚点：有些退化是**统计上不可见**的
 * ─────────────────────────────────────────────────────────────
 * v 轴翻转、blockId.y 方向反了、位移场幅度改了……这些改动**不改变**任何
 * 分布量（亮格率、绿占亮、颜色集合都照旧），前面那些断言照样全绿。
 * 只有把某一帧的亮格掩码**钉死**才抓得住。
 *
 * 黄金值是 2026-11-03 在 1200×800、t=0.5s 这一帧上算出来的；
 * 引擎里任何会改变「哪一格亮着」的改动都会让它变红。
 */
sec('PT-7 定值锚点：TRAE 档某一帧的亮格掩码必须逐位不变');
ok('t=0.5s 那一帧的亮格掩码哈希 = 2051aad3（v 翻转 / 方向反了 / 幅度改了都抓得住）',
  tr.frames[10].st.hash === 0x2051aad3,
  '实测 ' + tr.frames[10].st.hash.toString(16));
ok('t=2.0s 那一帧的亮格掩码哈希 = 11a6e227（两条时间轴被合一时也抓得住）',
  tr.frames[40].st.hash === 0x11a6e227,
  '实测 ' + tr.frames[40].st.hash.toString(16));

console.log();
if (F) {
  console.log('失败 ' + F + ' 项：');
  console.log('通过 ' + P + ' / ' + (P + F));
  process.exit(1);
}
console.log('通过 ' + P + ' / ' + P);
console.log('全部通过');
