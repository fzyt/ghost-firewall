/* 像素场引擎「硬边」行为级测试（Node + 最小 canvas/DOM 桩）
 *
 * 运行: node tests/test_pixelfield_hardedge.js
 * 零依赖：只用 Node 内置模块（fs / path / vm），不装 canvas、不装浏览器。
 *
 * 为什么要有这个文件（2026-11-03）
 * --------------------------------
 * 门户背景原来用「alpha 斜坡 + 余晖衰减 + 迟滞」三件套做柔边。
 * 用户原话是：「我看目前有一些灰度和亮的交接，类似于水打上去的印记一样，
 * 我想要么亮，要么不亮，分界明显一点」。
 *
 * 那三件套全是**渲染行为**。源码文本断言只能钉住「代码写了什么」，
 * 钉不住「画面到底有没有中间灰」—— 哪怕斜坡被改回另一个分支，
 * 文本断言照样全绿。所以这个文件**真跑引擎**：把画布像素读出来，
 * 直接断言「alpha 只有 0 和 255，没有 1..254」。
 *
 * 覆盖的三处硬边改造（缺一不可）
 *   ① alpha 斜坡 → 硬开关：a1 = vv > tLo1 ? 1 : 0
 *   ② 余晖衰减   → 不留痕  ：e = quant ? band : ...
 *   ③ 迟滞限速   → 整段跳过：if (!quant) { ... }
 *
 * 三者的验法不一样：
 *   ①③ 会直接产出非 0/255 的 alpha ⇒ 断言「alpha 集合 == {0,255}」能抓住
 *      （迟滞把 1→0 压成 1→0.965→…，落到像素上就是 246、237 这种灰）
 *   ② 不改 alpha 的取值域，只改「哪一格亮着」⇒ 用不变性来验：
 *      量化模式下 trail 根本不参与计算 ⇒ 改 trail 后画面必须一字节不差。
 *
 * 反向对照也要有（否则「什么都没画」也会全绿）：
 *   老档 moonstone 走的是软边路径 ⇒ 必须**能**找到中间灰，
 *   证明上面那条断言不是靠「引擎没跑起来」蒙混过关的。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DIR = path.join(__dirname, '..', 'backend', 'static');
const SRC = fs.readFileSync(path.join(DIR, 'pixelfield.js'), 'utf8');

let P = 0, F = 0;
const ok = (n, c, x) => {
  if (c) { P++; console.log('  ✅ ' + n); }
  else { F++; console.log('  ❌ ' + n + '  ' + (x || '')); }
};
const sec = (t) => console.log('\n== ' + t);

/* ── 极简 canvas 桩 ─────────────────────────────────────────
 * 只实现引擎真正用到的那几个方法。关键是把 fine 画布的
 * ImageData 留住（ctx.__img）：引擎把颜色和 alpha 写在这里，
 * 最后 putImageData 贴到画布上 —— 测试要读的就是它。
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
    /* ⚠ 必须返回**固定**尺寸：引擎的 resize() 会把 canvas.width 改成
     *   w*dpr，若这里回读 canvas.width，第二次 resize 就会把画布尺寸
     *   越撑越大（dpr 叠 dpr）⇒ 网格算错、断言假红。 */
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

/* 跑一串时刻，返回每帧的像素快照。
 * 引擎的几何按 p.step（默认 1/30 秒）离散采样，所以帧要跨过
 * 多个几何步，否则余晖/插值这几条路径根本走不到。 */
const TIMES = [];
for (let i = 0; i <= 40; i++) TIMES.push(i * 0.05);

function run(styleKey, extraParams) {
  const env = loadEngine();
  const main = mkCanvas(1200, 800, 'main');
  const api = env.api.createStyle(main, styleKey, { params: extraParams || {} });
  if (!api) throw new Error('createStyle 返回 null：引擎没起来');
  /* created[0] = fine 画布（颜色与 alpha 落在这里）
   * created[1] = glow 画布（辉光层，量化模式下是空的） */
  const fine = env.created[0].getContext('2d');
  const frames = [];
  for (const t of TIMES) {
    api.render(t);
    const img = fine.__img;
    frames.push({
      alpha: img.data,
      lit: countLit(img.data),
      w: img.width, h: img.height,
    });
  }
  return { api: api, frames: frames };
}

function countLit(data) {
  let n = 0;
  for (let i = 3; i < data.length; i += 4) if (data[i] > 0) n++;
  return n;
}

function alphaSet(frames) {
  const s = new Set();
  for (const f of frames) {
    const d = f.alpha;
    for (let i = 3; i < d.length; i += 4) s.add(d[i]);
  }
  return s;
}

/* 两段画面是否一字节不差 */
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/* 亮区集合（掩码）是否一致 —— 只看「哪些像素亮着」，不看颜色 */
function sameMask(fa, fb) {
  for (let i = 0; i < fa.length; i += 4) {
    if ((fa[i + 3] > 0) !== (fb[i + 3] > 0)) return false;
  }
  return true;
}

/* ─────────────────────────────────────────────────────────────
 * 1. 硬边：alpha 只有 0 和 255
 * ───────────────────────────────────────────────────────────── */
sec('PH-1 量化档渲染出的 alpha 只有 0 和 255（没有中间灰）');

const pf = run('pixel-flow');
const pfAlphas = alphaSet(pf.frames);
const pfGray = [...pfAlphas].filter(a => a !== 0 && a !== 255).sort((x, y) => x - y);

ok('pixel-flow 的 alpha 集合里没有中间灰（1..254）',
   pfGray.length === 0,
   '实测出现中间灰：' + pfGray.slice(0, 12).join(',') + (pfGray.length > 12 ? ' …' : ''));
ok('pixel-flow 的 alpha 集合同时含 0 与 255（不是全黑也不是全白）',
   pfAlphas.has(0) && pfAlphas.has(255),
   '实际集合大小 ' + pfAlphas.size);
ok('pixel-flow 确实画出了东西（有亮像素）',
   pf.frames.some(f => f.lit > 0));

/* ─────────────────────────────────────────────────────────────
 * 2. 反向对照：老档必须**有**中间灰
 * ───────────────────────────────────────────────────────────── */
sec('PH-2 反向对照：软边档仍然有中间灰（证明 PH-1 不是空过）');

const ms = run('moonstone');
const msAlphas = alphaSet(ms.frames);
const msGray = [...msAlphas].filter(a => a !== 0 && a !== 255);

ok('moonstone（老路径，未开量化）确实存在中间灰 alpha',
   msGray.length > 0,
   '一个中间灰都没找到 ⇒ 引擎可能根本没跑起来，PH-1 就是假绿');
ok('moonstone 的中间灰不止一种（是真的渐变，不是巧合一两格）',
   msGray.length >= 3,
   '只找到 ' + msGray.length + ' 种：' + msGray.slice(0, 8).join(','));

/* ─────────────────────────────────────────────────────────────
 * 3. 余晖：量化模式下 trail 不参与计算
 * ───────────────────────────────────────────────────────────── */
sec('PH-3 余晖分支：量化模式下 trail 不参与（画面不受 trail 影响）');

/* p.trail 全仓库只在余晖那一行用（e = quant ? band : ... 的 else 分支）。
 * 量化模式走的是 band 分支 ⇒ 改 trail 必须一帧都不变。
 * 如果哪天把 `quant ? band` 改回成余晖衰减，这里立刻红。 */
const pfTrail0 = run('pixel-flow', { trail: 0 });
const pfTrail9 = run('pixel-flow', { trail: 0.9 });

let trailSame = true, trailDiffAt = -1;
for (let i = 0; i < pfTrail0.frames.length; i++) {
  if (!sameBytes(pfTrail0.frames[i].alpha, pfTrail9.frames[i].alpha)) {
    trailSame = false; trailDiffAt = i; break;
  }
}
ok('量化模式下改 trail 不改变任何一帧的像素（余晖分支确实被绕开了）',
   trailSame,
   trailDiffAt >= 0 ? ('第 ' + trailDiffAt + ' 帧（t=' + TIMES[trailDiffAt] + 's）开始不一样') : '');

/* 对照：老档的 trail 是真的在起作用（否则 PH-3 就是「两边都没画」蒙混） */
const msTrail0 = run('moonstone', { trail: 0 });
const msTrail9 = run('moonstone', { trail: 0.9 });
let msTrailDiff = false;
for (let i = 0; i < msTrail0.frames.length; i++) {
  if (!sameBytes(msTrail0.frames[i].alpha, msTrail9.frames[i].alpha)) { msTrailDiff = true; break; }
}
ok('反向对照：moonstone 的 trail 是真的在起作用（老路径余晖还在）',
   msTrailDiff,
   '老档改 trail 画面也没变 ⇒ 引擎可能没真跑');

/* ─────────────────────────────────────────────────────────────
 * 4. 迟滞：量化模式下 hyst 不参与计算
 * ───────────────────────────────────────────────────────────── */
sec('PH-4 迟滞分支：量化模式下 hyst 不参与（画面不受 hyst 影响）');

const pfHyst0 = run('pixel-flow', { hyst: 0 });
const pfHyst5 = run('pixel-flow', { hyst: 0.5 });
let hystSame = true, hystDiffAt = -1;
for (let i = 0; i < pfHyst0.frames.length; i++) {
  if (!sameBytes(pfHyst0.frames[i].alpha, pfHyst5.frames[i].alpha)) {
    hystSame = false; hystDiffAt = i; break;
  }
}
ok('量化模式下改 hyst 不改变任何一帧的像素（迟滞分支确实被绕开了）',
   hystSame,
   hystDiffAt >= 0 ? ('第 ' + hystDiffAt + ' 帧（t=' + TIMES[hystDiffAt] + 's）开始不一样') : '');

/* ─────────────────────────────────────────────────────────────
 * 5. 硬边下的亮区集合必须稳定（迟滞会让亮区「粘」着不灭）
 * ───────────────────────────────────────────────────────────── */
sec('PH-5 量化模式的亮区是「即亮即灭」，不会被迟滞粘住');

/* 迟滞的作用是让 alpha 下降按帧限速 ⇒ 亮区会多留几帧。
 * 量化模式下迟滞整段跳过 ⇒ 相邻帧之间不该出现
 * 「上一帧亮、这一帧还亮但只剩一点点」这种半死不活的残留。
 * 用「亮区掩码逐帧变化量」来验：没有迟滞时变化更干脆。 */
let pfMidFade = 0;
for (let i = 0; i < pf.frames.length; i++) {
  const d = pf.frames[i].alpha;
  for (let k = 3; k < d.length; k += 4) if (d[k] !== 0 && d[k] !== 255) pfMidFade++;
}
ok('量化模式所有帧里都没有半亮像素（迟滞没把亮区粘住）',
   pfMidFade === 0, '找到 ' + pfMidFade + ' 个半亮像素');

/* ─────────────────────────────────────────────────────────────
 * 6. 颜色模型：按块随机绿白二选一（不是连续插值）
 * ───────────────────────────────────────────────────────────── */
sec('PH-6 量化档的颜色是「按块随机二选一」，没有第三种色');

function colorSet(frames) {
  const s = new Set();
  for (const f of frames) {
    const d = f.alpha;
    for (let i = 0; i < d.length; i += 4) {
      if (d[i + 3] > 0) s.add(d[i] + ',' + d[i + 1] + ',' + d[i + 2]);
    }
  }
  return s;
}
const pfColors = [...colorSet(pf.frames)];
ok('pixel-flow 的亮像素只有两种颜色（mint 强调色 + 白）',
   pfColors.length === 2,
   '实际 ' + pfColors.length + ' 种：' + pfColors.join(' | '));
ok('pixel-flow 的两种颜色是 TRAE 的青绿 #32F08C 与纯白',
   pfColors.includes('50,240,140') && pfColors.includes('255,255,255'),
   '实际：' + pfColors.join(' | '));

/* ─────────────────────────────────────────────────────────────
 * 7. 硬边不能改到现有各档（逐位一致的保证在行为层面也成立）
 * ───────────────────────────────────────────────────────────── */
sec('PH-7 现有各档没有被硬边改造波及');

const moonstone = run('moonstone');
const gate = run('gate');
const swirl = run('moonstone-swirl');

function hasGray(frames) {
  for (const f of frames) {
    const d = f.alpha;
    for (let i = 3; i < d.length; i += 4) if (d[i] !== 0 && d[i] !== 255) return true;
  }
  return false;
}
ok('moonstone 仍是软边（没有被改成硬边）', hasGray(moonstone.frames));
ok('gate 仍是软边（没有被改成硬边）', hasGray(gate.frames));
ok('moonstone-swirl 仍是软边（没有被改成硬边）', hasGray(swirl.frames));

/* ─────────────────────────────────────────────────────────────
 * 8. TRAE 式显式取样位移：点不动、内容错位
 * ─────────────────────────────────────────────────────────────
sec('PH-8 取样位移：晶格不变，但「哪些格亮着」会变');

/* 我们的点阵：columns=190 ⇒ cell = SS × max(2, round(w/190/SS)) = 4 × 2 = 8 设备px。
 * ⚠ 但读到的缓冲是 **fine 画布**（亚像素分辨率）：宽 = cols × SS = 150 × 4 = 600。
 *   pxBody=3 ⇒ 3 个亚像素、inset=0（(4-3)/2|0）⇒ 贴在格子左上角。
 * ⇒ 在 fine 坐标里，任何亮像素都必须满足 (x mod 4) < 3 且 (y mod 4) < 3。
 * 这一条锁住「点钉在固定晶格上」——TRAE 实测同理（7px 晶格、5px 点、100% 合规）。 */
const SS = 4, DOT = 3;
function latticeViolations(frames) {
  let bad = 0, total = 0;
  for (const f of frames) {
    const d = f.alpha, W = f.w, H = f.h;
    for (let y = 0; y < H; y++) {
      for (let x = 0; x < W; x++) {
        if (d[(y * W + x) * 4 + 3] > 0) {
          total++;
          if (x % SS >= DOT || y % SS >= DOT) bad++;
        }
      }
    }
  }
  return { bad: bad, total: total };
}

const pfDisp = run('pixel-flow');
const pfNoDisp = run('pixel-flow', { flowDispX: 0, flowDispY: 0 });

const vDisp = latticeViolations(pfDisp.frames);
const vNo = latticeViolations(pfNoDisp.frames);
ok('开位移时：所有亮像素都落在 8px 晶格的点实体内（点不动）',
   vDisp.bad === 0, '越界 ' + vDisp.bad + ' / ' + vDisp.total + ' 个亮像素');
ok('关位移时：同样落在晶格的点实体内（老路径也守规矩）',
   vNo.bad === 0, '越界 ' + vNo.bad + ' / ' + vNo.total + ' 个亮像素');
ok('确实量到了亮像素（不是「没东西所以零越界」）',
   vDisp.total > 1000 && vNo.total > 1000,
   '亮像素 ' + vDisp.total + ' / ' + vNo.total);

/* 内容错位：开/关位移 ⇒ 亮格集合必须不同（否则位移分支是死代码） */
function maskHash(frames) {
  let h = 2166136261 >>> 0;
  for (const f of frames) {
    const d = f.alpha;
    for (let i = 0; i < d.length; i += 4) {
      h ^= d[i + 3] > 0 ? 1 : 0;
      h = Math.imul(h, 16777619) >>> 0;
    }
  }
  return h;
}
const hDisp = maskHash(pfDisp.frames);
const hNo = maskHash(pfNoDisp.frames);
ok('开/关位移：亮格集合不同（位移真的把内容挪走了）',
   hDisp !== hNo, '两个哈希一样 ⇒ 位移分支空转');

console.log();
if (F) {
  console.log('失败 ' + F + ' 项：');
  console.log('通过 ' + P + ' / ' + (P + F));
  process.exit(1);
}
console.log('通过 ' + P + ' / ' + P);
console.log('全部通过');
