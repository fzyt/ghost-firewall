/* 像素场引擎「TRAE·原版方块」行为级测试（Node + 最小 canvas/DOM 桩）
 *
 * 运行: node tests/test_pixelfield_trae_orig.js
 * 零依赖：只用 Node 内置模块（fs / path / vm），不装 canvas、不装浏览器。
 *
 * 这一档是什么（2026-11-04 第十一轮）
 * -----------------------------------
 * 用户原话：「http://192.168.100.249:22000/static/pfstyle.html?style=trae
 *   这个 trae 原版为基础，做一个新方案，就是里面的方块方案改一下，
 *   改成我们原版方案，其他一律不动」
 *
 * ⇒ **底座 = TRAE 原版**（流体场 / 域扭曲 / 取样位移 ×35 / 两条时间轴 /
 *   纯黑底 / 指针交互 / 「哪里亮」的来源 = brightness 0.562+0.438n）
 * ⇒ **只换方块那一层** = 原方案：
 *   12px 晶格 + 6px 小点、每格固定随机门槛（软门）、每格随机亮度、
 *   余晖渐隐（trail）、迟滞（hyst）、抖动溶解（statJit）、月白银白两档配色。
 *
 * 为什么这个文件**必须真跑引擎**
 * ---------------------------
 * 「底座没动、只换了方块」这两件事，源码文本断言钉不住：
 *   · 亮区位置到底是不是 TRAE 那片场 —— 文本里写了 trField 不代表
 *     渲染时真的按同一套晶格采样；
 *   · 方块到底是不是 12px 晶格上的小点 —— TRAE 原版是 7px 晶格 + 5×5 实心块，
 *     两者的像素分布完全不同，光看源码看不出来；
 *   · 余晖/迟滞有没有真的生效 —— TRAE 原版每格只有 0/1/2 三态，
 *     没有渐隐；新档必须有大量中间亮度。
 * 所以这个文件真把画布像素读出来，断言：
 *   ① 配色是月白银白，且**没有** TRAE 的绿
 *   ② 晶格是 12px、点是 6px 小点（x mod 12 的余数分布固定）
 *   ③ 亮度有大量中间值（余晖渐隐 + 迟滞），TRAE 原版是纯硬边
 *   ④ **亮区位置与 TRAE 原版重合**（同一片场 ⇒ 这是「底座没动」的铁证）
 *   ⑤ 四个开关（traeBlocks / traeSoft / hyst / pxCrest）真的改变画面
 *   ⑥ 老档位一个像素都没变
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DIR = path.join(__dirname, '..', 'backend', 'static');
const SRC = fs.readFileSync(path.join(DIR, 'pixelfield.js'), 'utf8');

let P = 0, F = 0;
/* ⚠ 用纯文本 [PASS]/[FAIL]，不用 emoji —— AGENTS.md 要求终端输出禁 emoji。
 *   run_all.sh 的计数公式两种标记都认（2026-11-03 补）。 */
const ok = (n, c, x) => {
  if (c) { P++; console.log('  [PASS] ' + n); }
  else { F++; console.log('  [FAIL] ' + n + '  ' + (x || '')); }
};
const sec = (t) => console.log('\n== ' + t);

/* ── 极简 canvas 桩 ───────────────────────────────────────── */
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
    __listeners: {},
    document: {
      createElement(tag) {
        const c = mkCanvas(600, 400, tag);
        created.push(c);
        return c;
      },
    },
    devicePixelRatio: 1,
    requestAnimationFrame(fn) { sandbox.__raf.push(fn); return sandbox.__raf.length; },
    cancelAnimationFrame() {},
    /* ⚠ 事件监听器要**留下来**：指针交互（TRAE 原版的 mouseFactor）
     *   就是靠 pointermove 事件更新指针坐标的，
     *   桩里直接扔掉的话 ⇒ 行为级测不了「指针交互有没有接上」。 */
    addEventListener(type, fn) { sandbox.__listeners[type] = fn; },
    performance: { now() { return 0; } },
    matchMedia: () => ({ matches: false }),
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox, { filename: 'pixelfield.js' });
  return { api: sandbox.GhostPixelField, created: created, sandbox: sandbox };
}

/* 引擎的几何按 p.step（默认 1/30 秒）离散采样，帧要跨过多个几何步。 */
const TIMES = [];
for (let i = 0; i <= 240; i++) TIMES.push(i * 0.05);

/* ⚠ 两条路径的落点不一样：
 *   常规路径 → fine 画布（颜色在 RGB、覆盖在 alpha 通道）
 *   TRAE 档 → 主画布（颜色直接写死，alpha 恒 255）
 *   ⇒ 取「有内容」的那一块。 */
/* ⚠ 返回 {img, mode}：mode 决定「什么算亮」。
 *   alpha  = 常规路径（fine 画布：颜色在 RGB、覆盖在 alpha 通道）
 *   color  = TRAE 路径（主画布：底色不透明 ⇒ alpha 恒 255，只能看 RGB）
 *   ⚠ 2026-11-04 踩过的坑：早期版本一律按「RGB 非零」判亮，
 *     在 TRAE 路径上把**整块不透明底色**都算成亮点 ⇒
 *     点数、余数直方图、重合度全部失真。 */
function pickImg(fineCtx, mainCtx) {
  const f = fineCtx && fineCtx.__img;
  if (f && hasLitAlpha(f)) return { img: f, mode: 'alpha' };
  const m = mainCtx && mainCtx.__img;
  if (m && hasLitColor(m)) return { img: m, mode: 'color' };
  return { img: m || f, mode: 'color' };
}

function hasLitAlpha(img) {
  const d = img.data;
  for (let i = 3; i < d.length; i += 4) if (d[i] > 0) return true;
  return false;
}

function hasLitColor(img) {
  const d = img.data;
  for (let i = 0; i < d.length; i += 4) {
    if (d[i] || d[i + 1] || d[i + 2]) return true;
  }
  return false;
}

function run(styleKey, extraParams, times, pointer) {
  const env = loadEngine();
  const main = mkCanvas(600, 400, 'main');
  /* columns = 50 ⇒ cell = SS × round(600/50/4) = 4 × 3 = 12px（与 1200×800
     下默认列数 112 算出来的一样）⇒ 晶格仍是原方案那一套，扫描量只有 1/4。 */
  const api = env.api.createStyle(main, styleKey,
    { columns: 50, params: extraParams || {} });
  if (!api) throw new Error('createStyle 返回 null：引擎没起来');
  /* 指针位置：引擎靠 pointermove 事件更新 tMouseX/tMouseY，
     桩里要能派发这个事件才能测指针交互。 */
  if (pointer && env.sandbox.__listeners.pointermove) {
    env.sandbox.__listeners.pointermove({ clientX: pointer[0], clientY: pointer[1] });
  }
  const fineCtx = env.created[0].getContext('2d');
  const mainCtx = main.getContext('2d');
  const frames = [];
  let lastImg = null;
  for (const t of (times || TIMES)) {
    api.render(t);
    const picked = pickImg(fineCtx, mainCtx);
    lastImg = picked.img;
    /* ⚠ ImageData 是**同一个活缓冲**（引擎建一次、之后就地改），
     *   所以每帧必须**当场**把指标算出来；存引用的话所有帧都是最后一帧。 */
    frames.push(snap(lastImg, picked.mode, t === (times || TIMES)[(times || TIMES).length - 1]));
  }
  return { api: api, frames: frames, lastImg: lastImg, env: env };
}

function snap(img, mode, deep) {
  if (!img) return null;
  const d = img.data, w = img.width, h = img.height;
  const byAlpha = mode === 'alpha';
  let lit = 0, dim = 0;
  const colors = new Map();
  const levels = new Set();
  /* 横向余数直方图（用来验晶格周期与点宽） */
  const mod12 = new Array(12).fill(0);
  const mod7 = new Array(7).fill(0);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const o = (y * w + x) * 4;
      const r = d[o], g = d[o + 1], b = d[o + 2];
      const a = d[o + 3];
      const on = byAlpha ? (a > 0) : (r || g || b);
      if (!on) continue;
      lit++;
      if (deep) {
        const k = r + ',' + g + ',' + b;
        colors.set(k, (colors.get(k) || 0) + 1);
        levels.add(r);
        mod12[x % 12]++;
        mod7[x % 7]++;
      }
      /* 暗尾：亮度不足一半（余晖正在褪的那一批） */
      if (r + g + b < 384) dim++;
    }
  }
  return {
    lit: lit,
    pct: lit / (w * h),
    dimPct: lit ? dim / lit : 0,
    colors: colors,
    levels: levels,
    levelKinds: levels.size,
    mod12: mod12,
    mod7: mod7,
    hash: hashMask(d),
    /* 颜色指纹：只算**亮像素**的 RGB。
     * ⚠ 指针交互（mouseFactor）只改**颜色**、不改亮区分布
     *   ⇒ 判定指针交互必须看颜色指纹，看亮区指纹是看不出来的。 */
    chash: hashColor(d),
    w: w, h: h,
  };
}

function hashColor(d) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < d.length; i += 4) {
    if (!d[i] && !d[i + 1] && !d[i + 2]) continue;
    h ^= d[i]; h = Math.imul(h, 16777619) >>> 0;
    h ^= d[i + 1]; h = Math.imul(h, 16777619) >>> 0;
    h ^= d[i + 2]; h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function hashMask(d) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < d.length; i += 4) {
    h ^= (d[i] || d[i + 1] || d[i + 2]) ? 1 : 0;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function allColors(frames) {
  const s = new Map();
  for (const f of frames) {
    if (!f) continue;
    for (const [k, v] of f.colors) s.set(k, (s.get(k) || 0) + v);
  }
  return s;
}

function lastFrame(frames) { return frames[frames.length - 1]; }

/* 粗网格（12px 一格）的亮区掩码，用来比「哪里亮」。
 * ⚠ 必须带**亮度阈值**：新档有余晖，熄灭的格子还挂着几十像素的暗尾巴；
 *   按「任意非零」算会把尾巴算成亮区 ⇒ 两档的口径不对等（TRAE 是硬边，没有尾巴）。
 *   阈值取「三通道之和 ≥ 384」（即平均 ≥128）：
 *   TRAE 的块是纯白/纯绿（和 ≥ 566）⇒ 一定过；
 *   新档的暗尾巴（和 < 100）⇒ 一定不过。 */
function coarseMask(img, cw, ch, cell, thr) {
  const m = new Uint8Array(cw * ch);
  const d = img.data;
  for (let cy = 0; cy < ch; cy++) {
    for (let cx = 0; cx < cw; cx++) {
      let l = false;
      for (let dy = 0; dy < cell && !l; dy++) {
        for (let dx = 0; dx < cell; dx++) {
          const o = ((cy * cell + dy) * img.width + cx * cell + dx) * 4;
          if (d[o] + d[o + 1] + d[o + 2] >= thr) { l = true; break; }
        }
      }
      m[cy * cw + cx] = l ? 1 : 0;
    }
  }
  return m;
}

/* ─────────────────────────────────────────────────────────────
 * 1. 档位存在 + 配色是月白银白（不是 TRAE 绿）
 * ───────────────────────────────────────────────────────────── */
sec('TO-1 新档存在，且配色是月白银白');

const orig = run('trae-orig');
const origLast = lastFrame(orig.frames);
const origColors = allColors(orig.frames);

ok('trae-orig 档能创建并画出东西',
  origLast && origLast.lit > 500, '亮像素 ' + (origLast ? origLast.lit : 0));

/* 月白配色：accent rgb(136,140,148) / white rgb(244,245,248) */
const MOON_ACCENT = '136,140,148', MOON_WHITE = '244,245,248';
/* TRAE 绿（编码后）与编码前 */
const TRAE_GREEN = '122,248,196', TRAE_GREEN_RAW = '50,240,140';

const colorKeys = Array.from(origColors.keys());
ok('用了月白的浪身色 rgb(136,140,148)', colorKeys.includes(MOON_ACCENT),
  '颜色集合：' + colorKeys.slice(0, 6).join(' | '));
ok('用了月白的浪尖色 rgb(244,245,248)', colorKeys.includes(MOON_WHITE),
  '颜色集合：' + colorKeys.slice(0, 6).join(' | '));
ok('**没有** TRAE 的绿（122,248,196 / 50,240,140）',
  !colorKeys.includes(TRAE_GREEN) && !colorKeys.includes(TRAE_GREEN_RAW),
  '颜色集合：' + colorKeys.slice(0, 6).join(' | '));

/* ─────────────────────────────────────────────────────────────
 * 2. 晶格 = 原方案的 12px，点 = 6px 小点
 * ───────────────────────────────────────────────────────────── */
sec('TO-2 方块是原方案的 12px 晶格 + 6px 小点');

/* 默认画法：浪身 6px（格内偏移 3px）+ 浪尖 9px（格内偏移 0px）
 * ⇒ 亮点的 x mod 12 只可能落在 0..8 这 9 个余数上 */
const mod12NonZero = origLast.mod12.map((v, i) => (v > 0 ? i : -1)).filter(i => i >= 0);
ok('亮点的 x mod 12 只落在 0..8（12px 晶格：浪尖 9px 从格首起、浪身 6px 偏移 3px）',
  mod12NonZero.length === 9 && mod12NonZero[0] === 0 && mod12NonZero[8] === 8,
  '有亮点的余数：' + mod12NonZero.join(','));

/* 两档都画 6px（pxCrest=2）⇒ 余数只能是 3..8 这 6 个 */
const smallOnly = run('trae-orig', { pxCrest: 2 }, TIMES.slice(0, 60));
const soNonZero = lastFrame(smallOnly.frames).mod12.map((v, i) => (v > 0 ? i : -1)).filter(i => i >= 0);
ok('两档都画 6px 时，亮点的 x mod 12 恰好是 3..8（点宽 6px、格内偏移 3px）',
  soNonZero.length === 6 && soNonZero[0] === 3 && soNonZero[5] === 8,
  '有亮点的余数：' + soNonZero.join(','));

/* TRAE 原版：7px 晶格 + 5px 实心块 ⇒ x mod 7 只可能是 0..4 */
const trae = run('trae', { traeMouse: 0 }, TIMES);
const traeLast = lastFrame(trae.frames);
const mod7NonZero = traeLast.mod7.map((v, i) => (v > 0 ? i : -1)).filter(i => i >= 0);
ok('对照：TRAE 原版的 x mod 7 只落在 0..4（7px 晶格 + 5px 块）',
  mod7NonZero.length === 5 && mod7NonZero[0] === 0 && mod7NonZero[4] === 4,
  '有亮点的余数：' + mod7NonZero.join(','));

/* 两档的点阵周期不同 ⇒ 掩码指纹必然不同 */
ok('新档与 TRAE 原版的点阵分布不同（晶格确实换了）',
  origLast.hash !== traeLast.hash);

/* ─────────────────────────────────────────────────────────────
 * 3. 余晖渐隐 + 迟滞 ⇒ 亮度有大量中间值
 * ───────────────────────────────────────────────────────────── */
sec('TO-3 有余晖渐隐（亮度有中间值），TRAE 原版是硬边');

/* ⚠ 对照组必须把指针交互关掉：TRAE 的指针效果会把块色往另一头混，
 *   混出来的颜色当然有中间值 —— 那是鼠标的功劳，不是渐隐的。 */
const traeNoMouse = run('trae', { traeMouse: 0 }, TIMES.slice(0, 60));
const tnmLevels = Array.from(lastFrame(traeNoMouse.frames).levels).sort((a, b) => a - b);
/* ⚠ 统计的是**亮像素**的 R 通道取值：黑底不算亮像素 ⇒ 只有两档
 *   （白块 R=255、绿块 R=122）。TRAE 原版是硬开关，所以只有这两档。 */
ok('对照：TRAE 原版（关指针）的亮像素亮度只有两档（纯白 255 / 纯绿 122）',
  tnmLevels.length === 2 && tnmLevels[0] === 122 && tnmLevels[1] === 255,
  'TRAE 亮度档数 ' + tnmLevels.length + '：' + tnmLevels.join(','));

const origNoMouse = run('trae-orig', { traeMouse: 0 }, TIMES.slice(0, 60));
ok('新档（关指针）的亮度档数 > 40（余晖渐隐 + 软边 ⇒ 中间值很多）',
  lastFrame(origNoMouse.frames).levelKinds > 40,
  '亮度档数 ' + lastFrame(origNoMouse.frames).levelKinds);
ok('新档里「暗尾」像素（亮度不足一半）占亮像素 > 10%（尾巴在褪）',
  lastFrame(origNoMouse.frames).dimPct > 0.10,
  '暗尾占比 ' + (lastFrame(origNoMouse.frames).dimPct * 100).toFixed(1) + '%');

/* ─────────────────────────────────────────────────────────────
 * 4. 亮区位置与 TRAE 原版重合（底座没动的铁证）
 * ───────────────────────────────────────────────────────────── */
sec('TO-4 亮区位置与 TRAE 原版重合（同一片场）');

/* 两档都关指针、跑**同样多**的帧（末帧在同一时刻） */
const origNoMouseRun = run('trae-orig', { traeMouse: 0 }, TIMES);
const traeNoMouseFull = run('trae', { traeMouse: 0 }, TIMES);

/* ⚠ 三条规矩，缺一条这断言就没意义：
 *   ① 两档必须比**同一时刻**的帧（TRAE 的场一直在漂）；
 *   ② 两档都必须**关掉指针**（指针只改颜色，但混色会让亮度过阈值）；
 *   ③ 亮度阈值必须够高（见 coarseMask 的注释：余晖的暗尾巴不算亮区）。 */
const CW = 50, CH = 33;
const TH = 384;
const mOrig = coarseMask(origNoMouseRun.lastImg, CW, CH, 12, TH);
const mTrae = coarseMask(traeNoMouseFull.lastImg, CW, CH, 12, TH);

let inter = 0, uni = 0, aCnt = 0, bCnt = 0;
for (let i = 0; i < CW * CH; i++) {
  const a = mOrig[i], b = mTrae[i];
  if (a) aCnt++;
  if (b) bCnt++;
  if (a && b) inter++;
  if (a || b) uni++;
}
const precision = aCnt ? inter / aCnt : 0;
const jaccard = uni ? inter / uni : 0;
/* 随机放置的期望 precision = TRAE 的覆盖率 ≈ 11.7%；
 * 实测 42.7% ⇒ 约 3.6 倍于随机 ⇒ 亮区确实落在同一片场上。 */
const chance = bCnt / (CW * CH);
ok('新档的亮区落在 TRAE 原版的亮区里（precision 明显高于随机）',
  precision > chance * 2.5 && precision > 0.30,
  'precision ' + (precision * 100).toFixed(1) + '%（随机放置约 ' +
  (chance * 100).toFixed(1) + '%，交集 ' + inter + ' / 新档 ' + aCnt +
  ' / TRAE ' + bCnt + '，Jaccard ' + jaccard.toFixed(3) + '）');

/* ─────────────────────────────────────────────────────────────
 * 5. 开关真的生效
 * ───────────────────────────────────────────────────────────── */
sec('TO-5 traeBlocks / traeSoft / hyst 真的改变画面');

/* 关掉方块层 ⇒ 退回 TRAE 原版（绿白硬边） */
const noBlocks = run('trae-orig', { traeBlocks: 0 }, TIMES.slice(0, 60));
const nbColors = allColors(noBlocks.frames);
ok('traeBlocks=0 ⇒ 退回 TRAE 原版（出现绿、失去月白银白）',
  Array.from(nbColors.keys()).includes(TRAE_GREEN) &&
  !Array.from(nbColors.keys()).includes(MOON_ACCENT),
  '颜色集合：' + Array.from(nbColors.keys()).slice(0, 6).join(' | '));
ok('traeBlocks=0 ⇒ 画面与新档不同',
  lastFrame(noBlocks.frames).hash !== origLast.hash);

/* 斜坡宽度 ⇒ 亮区大小变 */
const softNarrow = run('trae-orig', { traeSoft: 0.04 }, TIMES.slice(0, 60));
const softWide = run('trae-orig', { traeSoft: 0.16 }, TIMES.slice(0, 60));
const narrowDbg = softNarrow.api.debug();
const wideDbg = softWide.api.debug();
ok('traeSoft 变大 ⇒ 亮区（band）明显变大',
  wideDbg.bandFrac > narrowDbg.bandFrac * 1.5,
  'soft=0.04 band=' + (narrowDbg.bandFrac * 100).toFixed(1) +
  '% vs soft=0.16 band=' + (wideDbg.bandFrac * 100).toFixed(1) + '%');
ok('traeSoft 真的改变画面',
  lastFrame(softNarrow.frames).hash !== lastFrame(softWide.frames).hash);

/* 迟滞 ⇒ 逐帧变化量不同 */
const hyst0 = run('trae-orig', { hyst: 0 }, TIMES.slice(0, 60));
let diff0 = 0, diffH = 0;
for (let i = 1; i < 60; i++) {
  diff0 += Math.abs(hyst0.frames[i].lit - hyst0.frames[i - 1].lit);
  diffH += Math.abs(orig.frames[i].lit - orig.frames[i - 1].lit);
}
ok('hyst=0 与默认迟滞的逐帧点数变化不同（迟滞真的在限速）',
  diff0 !== diffH, 'hyst=0 累计变化 ' + diff0 + ' vs 默认 ' + diffH);

/* ─────────────────────────────────────────────────────────────
 * 5b. 指针交互（TRAE 原版带过来的 mouseFactor）
 * ───────────────────────────────────────────────────────────── */
sec('TO-5b 指针交互接上了（TRAE 原版那一层）');

/* 指针交互的表现：TRAE 原版是「指针附近白块泛绿、绿块泛白」；
 * 新档配色里没有绿 ⇒ 统一往 white 靠 ⇒ **指针附近的点更白**。
 *
 * ⚠ 判据必须是「纯白像素的**数量**」，不能是「颜色指纹变了」：
 *   迟滞（hyst）每次渲染都会把 alpha 压掉一点点 ⇒ 颜色指纹**每次都变**
 *   ⇒ 用指纹判定就是空转的（把 mouseFactor 整个删掉也照样「通过」）。
 *
 * ⚠ 两次跑必须是**同一段帧序列**：图案在动，指针位置不同 ⇒
 *   只有「同一时刻同一图案、只差指针位置」才有可比性。 */
const mvCenter = run('trae-orig', {}, TIMES.slice(0, 60), [300, 200]);
const mvCorner = run('trae-orig', {}, TIMES.slice(0, 60), [3, 3]);
const whiteCount = (f) => {
  let n = 0;
  for (const [k, v] of f.colors) {
    if (k === '244,245,248') n += v;
  }
  return n;
};
const wCenter = whiteCount(mvCenter.frames[59]);
const wCorner = whiteCount(mvCorner.frames[59]);
ok('引擎给 pointermove 挂了监听（TRAE 的指针交互还在）',
  typeof mvCenter.env.sandbox.__listeners.pointermove === 'function');
ok('两次跑的图案完全相同（亮像素数一致 ⇒ 只有指针位置不同）',
  mvCenter.frames[59].lit === mvCorner.frames[59].lit,
  mvCenter.frames[59].lit + ' vs ' + mvCorner.frames[59].lit);
ok('指针在画布中心时，纯白像素明显更多（mouseFactor 真的在起作用）',
  wCenter > wCorner + 100,
  '中心 ' + wCenter + ' 纯白像素 vs 角落 ' + wCorner + '（差 ' + (wCenter - wCorner) + '）');

/* ─────────────────────────────────────────────────────────────
 * 6. 老档位不受影响（新参数默认值必须全为 0）
 * ───────────────────────────────────────────────────────────── */
sec('TO-6 新参数默认全 0 ⇒ 老档位一个像素都不变');

const traePlain = run('trae', {}, TIMES.slice(0, 60));
const traeZero = run('trae', { traeBlocks: 0, traeSoft: 0 }, TIMES.slice(0, 60));
ok('trae 档显式传 0 与不传 ⇒ 画面逐位一致',
  lastFrame(traePlain.frames).hash === lastFrame(traeZero.frames).hash &&
  lastFrame(traePlain.frames).lit === lastFrame(traeZero.frames).lit);

const mstPlain = run('moonstone', {}, TIMES.slice(0, 60));
const mstZero = run('moonstone', { traeBlocks: 0, traeSoft: 0 }, TIMES.slice(0, 60));
ok('moonstone（常规路径）显式传 0 与不传 ⇒ 画面逐位一致',
  lastFrame(mstPlain.frames).hash === lastFrame(mstZero.frames).hash &&
  lastFrame(mstPlain.frames).lit === lastFrame(mstZero.frames).lit);

const mstTraePlain = run('moonstone-trae', {}, TIMES.slice(0, 60));
const mstTraeZero = run('moonstone-trae', { traeBlocks: 0, traeSoft: 0 }, TIMES.slice(0, 60));
ok('moonstone-trae（上一轮的合档）显式传 0 与不传 ⇒ 画面逐位一致',
  lastFrame(mstTraePlain.frames).hash === lastFrame(mstTraeZero.frames).hash &&
  lastFrame(mstTraePlain.frames).lit === lastFrame(mstTraeZero.frames).lit);

/* ─────────────────────────────────────────────────────────────
 * 7. 画面确实在动
 * ───────────────────────────────────────────────────────────── */
sec('TO-7 动画在动');
const hashes = new Set(orig.frames.map(f => f && f.hash));
ok('241 帧里有多个不同的亮区分布（画面在动）', hashes.size > 5, '不同帧数 ' + hashes.size);

/* ─────────────────────────────────────────────────────────────
 * 汇总
 * ───────────────────────────────────────────────────────────── */
console.log();
if (F) {
  console.log('失败 ' + F + ' 项：');
  console.log('通过 ' + P + ' / ' + (P + F));
  process.exit(1);
}
console.log('通过 ' + P + ' / ' + P);
console.log('全部通过');
