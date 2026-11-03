/* 像素场引擎「月白·TRAE」合档行为级测试（Node + 最小 canvas/DOM 桩）
 *
 * 运行: node tests/test_pixelfield_moonstone_trae.js
 * 零依赖：只用 Node 内置模块（fs / path / vm），不装 canvas、不装浏览器。
 *
 * 这一档是什么（2026-11-03 第十轮）
 * ---------------------------------
 * 用户原话：「很好，就这样，然后和我的原方案综合一下」+
 * 「方块使用我们现在网关用的方案（原方案），然后流动保留trae的流动方案」
 *
 * ⇒ 两个方案各取一半：
 *   · 方块 ← 原方案：每格随机门槛（块内随机疏密）、每格随机亮度（明暗参差）、
 *     余晖 trail（尾部逐渐消失）、迟滞 hyst、抖动溶解、密度伺服
 *   · 流动 ← TRAE：域扭曲 FBM（有机等值线）+ 单向取样位移（拖曳）
 *   · 配色 ← 月白（银白单色）
 *
 * 为什么这个文件**必须真跑引擎**
 * ---------------------------
 * 「方块用原方案」和「流动用 TRAE」这两件事，源码文本断言**钉不住**：
 *   · 遮罩源换没换（flowMask 生效没有）—— 文本里写了 flowMask: 1 不代表
 *     渲染时真的走了那条分支；
 *   · 方块还是不是原方案那种「随机疏密 + 软边尾巴」——
 *     TRAE 档的方块是 5×5 规整实心、硬边两态，跟原方案完全两样。
 * 所以这个文件真把画布像素读出来，断言：
 *   ① 颜色是月白银白（**不是** TRAE 的绿）
 *   ② 方块是原方案那种软边随机点群（alpha 有大量中间值），不是 TRAE 硬边
 *   ③ flowMask / flowThresh / flowSolo 三个开关**真的**改变画面
 *   ④ 老档位一个像素都没变
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
    document: {
      createElement(tag) {
        const c = mkCanvas(1200, 800, tag);
        created.push(c);
        return c;
      },
    },
    devicePixelRatio: 1,
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

/* 引擎的几何按 p.step（默认 1/30 秒）离散采样，帧要跨过多个几何步。
 * ⚠ 密度伺服（pickGain）要跑够帧才收敛 —— 只渲一两秒看到的是没收敛的值。 */
const TIMES = [];
for (let i = 0; i <= 240; i++) TIMES.push(i * 0.05);

/* 常规路径的像素画在 **fine 画布**上：颜色在 RGB，覆盖在 alpha 通道。 */
function run(styleKey, extraParams, times) {
  const env = loadEngine();
  const main = mkCanvas(1200, 800, 'main');
  const api = env.api.createStyle(main, styleKey, { params: extraParams || {} });
  if (!api) throw new Error('createStyle 返回 null：引擎没起来');
  const fine = env.created[0].getContext('2d');
  const mctx = main.getContext('2d');
  const frames = [];
  for (const t of (times || TIMES)) {
    api.render(t);
    /* ⚠ 两种路径的落点不一样：
     *   常规路径 → fine 画布（颜色在 RGB、覆盖在 alpha）
     *   TRAE 档 → 主画布（颜色直接写死，alpha 恒 255）
     *   ⇒ 取「有内容」的那一块。 */
    const fimg = fine.__img;
    const mimg = mctx.__img;
    const img = (fimg && hasLit(fimg)) ? fimg : (mimg || fimg);
    /* ⚠ ImageData 是**同一个活缓冲**（引擎建一次、之后就地改），
     *   所以每帧必须**当场**把指标算出来；存引用的话所有帧都是最后一帧。 */
    frames.push(snap(img));
  }
  return { api: api, frames: frames };
}

function hasLit(img) {
  const d = img.data;
  for (let i = 0; i < d.length; i += 4) {
    if (d[i + 3] > 0) return true;
  }
  return false;
}

function snap(img) {
  if (!img) return null;
  const d = img.data, w = img.width, h = img.height;
  let lit = 0, hard = 0, soft = 0;
  const colors = new Map();
  const alphaSet = new Set();
  for (let i = 0; i < d.length; i += 4) {
    const a = d[i + 3];
    if (a <= 0) continue;
    lit++;
    alphaSet.add(a);
    const k = d[i] + ',' + d[i + 1] + ',' + d[i + 2];
    colors.set(k, (colors.get(k) || 0) + 1);
    if (a >= 250) hard++; else soft++;
  }
  return {
    lit: lit,
    pct: lit / (w * h),
    hardPct: lit ? hard / lit : 0,
    softPct: lit ? soft / lit : 0,
    alphaKinds: alphaSet.size,
    colors: colors,
    /* 亮区集合指纹（只看 alpha>0 的分布） */
    hash: hashMask(d),
    w: w, h: h,
  };
}

function hashMask(d) {
  let h = 2166136261 >>> 0;
  for (let i = 3; i < d.length; i += 4) {
    h ^= (d[i] > 0) ? 1 : 0;
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

/* ─────────────────────────────────────────────────────────────
 * 1. 档位存在 + 颜色是月白银白（不是 TRAE 绿）
 * ───────────────────────────────────────────────────────────── */
sec('PM-1 合档存在，且配色是月白银白');

const merged = run('moonstone-trae');
const mergedLast = lastFrame(merged.frames);
const mergedColors = allColors(merged.frames);

ok('moonstone-trae 档能创建并画出东西',
  mergedLast && mergedLast.lit > 500, '亮像素 ' + (mergedLast ? mergedLast.lit : 0));

/* 月白配色：accent rgb(136,140,148) / white rgb(244,245,248) */
const MOON_ACCENT = '136,140,148', MOON_WHITE = '244,245,248';
/* TRAE 绿（编码后）与编码前 */
const TRAE_GREEN = '122,248,196', TRAE_GREEN_RAW = '50,240,140';

const colorKeys = Array.from(mergedColors.keys());
const hasMoonAccent = colorKeys.includes(MOON_ACCENT);
const hasMoonWhite = colorKeys.includes(MOON_WHITE);
const hasTraeGreen = colorKeys.includes(TRAE_GREEN) || colorKeys.includes(TRAE_GREEN_RAW);

ok('用了月白的浪身色 rgb(136,140,148)', hasMoonAccent, '颜色集合：' + colorKeys.slice(0, 6).join(' | '));
ok('用了月白的浪尖色 rgb(244,245,248)', hasMoonWhite, '颜色集合：' + colorKeys.slice(0, 6).join(' | '));
ok('**没有** TRAE 的绿（122,248,196 / 50,240,140）', !hasTraeGreen,
  '颜色集合：' + colorKeys.slice(0, 6).join(' | '));

/* ─────────────────────────────────────────────────────────────
 * 2. 方块是原方案那种（软边随机点群），不是 TRAE 的硬边实心块
 * ───────────────────────────────────────────────────────────── */
sec('PM-2 方块是原方案那一套，不是 TRAE 的硬边点阵');

/* TRAE 档：硬边两态、alpha 只有 0/255 */
const trae = run('trae', {}, TIMES.slice(0, 60));
const traeLast = lastFrame(trae.frames);
ok('对照：TRAE 档的 alpha 是硬边两态（几乎全是满亮）',
  traeLast && traeLast.softPct < 0.05,
  'TRAE 软边占比 ' + (traeLast ? (traeLast.softPct * 100).toFixed(1) + '%' : 'n/a'));

/* 合档：原方案有 alpha 斜坡 + 余晖 ⇒ 中间 alpha 很多 */
ok('合档的 alpha 有大量中间值（原方案的软边 + 余晖尾巴）',
  mergedLast && mergedLast.softPct > 0.20,
  '软边占比 ' + (mergedLast ? (mergedLast.softPct * 100).toFixed(1) + '%' : 'n/a'));
ok('合档的 alpha 取值种类 > 20（TRAE 硬边只有 2 种）',
  mergedLast && mergedLast.alphaKinds > 20,
  'alpha 种类 ' + (mergedLast ? mergedLast.alphaKinds : 0));

/* ─────────────────────────────────────────────────────────────
 * 3. 三个开关真的生效
 * ───────────────────────────────────────────────────────────── */
sec('PM-3 flowMask / flowThresh / flowSolo 真的改变画面');

const mNoMask = run('moonstone-trae', { flowMask: 0 }, TIMES.slice(0, 120));
const mHi = run('moonstone-trae', { flowThresh: 0.95 }, TIMES.slice(0, 120));
const mSolo = run('moonstone-trae', { flowSolo: 1 }, TIMES.slice(0, 120));
const base120 = merged.frames.slice(0, 121);

ok('flowMask=0（退回原方案遮罩）⇒ 画面与合档不同',
  lastFrame(mNoMask.frames).hash !== lastFrame(base120).hash);
ok('flowThresh=0.95（切点抬到顶）⇒ 画面与合档不同',
  lastFrame(mHi.frames).hash !== lastFrame(base120).hash);
ok('flowThresh=0.95 ⇒ 亮区明显变少',
  lastFrame(mHi.frames).lit < lastFrame(base120).lit * 0.8,
  '极端切点 lit=' + lastFrame(mHi.frames).lit + ' vs 合档 lit=' + lastFrame(base120).lit);
ok('flowSolo=1（波带不参与）⇒ 画面与合档不同',
  lastFrame(mSolo.frames).hash !== lastFrame(base120).hash);

/* flowMask=0 时应当与「原版 moonstone + 同一套 flow 参数」无关 —— 也就是
 * 合档的开关闭掉后，遮罩回到两层旋转值噪声。 */
ok('flowMask=0 时密度与合档不同（说明遮罩源确实换了）',
  Math.abs(lastFrame(mNoMask.frames).pct - lastFrame(base120).pct) > 0.002,
  'flowMask=0 lit%=' + (lastFrame(mNoMask.frames).pct * 100).toFixed(2) +
  ' vs 合档 lit%=' + (lastFrame(base120).pct * 100).toFixed(2));

/* ─────────────────────────────────────────────────────────────
 * 4. 密度与原方案同量级（合档不能变成一大坨实心）
 * ───────────────────────────────────────────────────────────── */
sec('PM-4 密度与原方案同量级');

const moon = run('moonstone', {}, TIMES.slice(0, 240));
const moonLast = lastFrame(moon.frames);
ok('合档点亮率在 1%~12% 之间（不是全黑也不是糊成一片）',
  mergedLast.pct > 0.01 && mergedLast.pct < 0.12,
  'lit%=' + (mergedLast.pct * 100).toFixed(2));
ok('合档点亮率与原版 moonstone 同量级（相差不超过 3 倍）',
  mergedLast.pct > moonLast.pct / 3 && mergedLast.pct < moonLast.pct * 3,
  '合档 ' + (mergedLast.pct * 100).toFixed(2) + '% vs 原版 ' + (moonLast.pct * 100).toFixed(2) + '%');

/* ─────────────────────────────────────────────────────────────
 * 5. 老档位不受影响（新增参数的默认值必须全为 0）
 * ───────────────────────────────────────────────────────────── */
sec('PM-5 新参数默认全 0 ⇒ 老档位一个像素都不变');

const moonPlain = run('moonstone', {}, TIMES.slice(0, 60));
const moonZero = run('moonstone', { flowMask: 0, flowThresh: 0, flowSoft: 0, flowSolo: 0 }, TIMES.slice(0, 60));
ok('moonstone 显式传 0 与不传 ⇒ 画面逐位一致',
  lastFrame(moonPlain.frames).hash === lastFrame(moonZero.frames).hash &&
  lastFrame(moonPlain.frames).lit === lastFrame(moonZero.frames).lit);

const pfPlain = run('pixel-flow', {}, TIMES.slice(0, 60));
const pfZero = run('pixel-flow', { flowMask: 0, flowThresh: 0, flowSoft: 0, flowSolo: 0 }, TIMES.slice(0, 60));
ok('pixel-flow（走的是同一套流体场）显式传 0 与不传 ⇒ 画面逐位一致',
  lastFrame(pfPlain.frames).hash === lastFrame(pfZero.frames).hash &&
  lastFrame(pfPlain.frames).lit === lastFrame(pfZero.frames).lit);

/* ─────────────────────────────────────────────────────────────
 * 6. 画面确实在动
 * ───────────────────────────────────────────────────────────── */
sec('PM-6 动画在动');
const hashes = new Set(merged.frames.map(f => f && f.hash));
ok('41 帧里有多个不同的亮区分布（画面在动）', hashes.size > 5, '不同帧数 ' + hashes.size);

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
