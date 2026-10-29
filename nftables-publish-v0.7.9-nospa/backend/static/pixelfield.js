/* Ghost Wave Field —— 行进波像素场引擎（B 方案 · v1 骨架 + 随机化 + 丝滑层）
 *
 * 以 AB 对比页「最后一版 B」的 v1 原版为骨架，本轮做了四件事：
 *
 * ══ 1. 点的随机化 ══════════════════════════════════════════
 * v1 原版里，遮罩切出来的块是**实心**的 —— 块内所有格子一起亮，
 * 随机性只体现在块的形状上。用户要「块内点位/明暗也随机」：
 *   · 每格一个**固定**随机门槛 rSel。块越亮（mask 越大），跨过门槛的
 *     格子越多 ⇒ 块内变成随机疏密的点群，而不是整块实心。
 *     门槛固定 ⇒ 点亮/熄灭的顺序稳定，不会闪。
 *   · 每格一个固定亮度因子 rAmp ⇒ 块内明暗参差，不再是一整片同色。
 *
 * ══ 2. 丝滑层（迟滞 + 抖动溶解 + 连续插值）════════════════════
 * v1 原版有三处硬跳：
 *   1. 场按 1/30 秒离散采样 —— 整场每 33ms 跳一帧（最主要的跳跃来源）。
 *      → 改成**几何按 1/30 秒采样、渲染按帧插值**：值在两个采样点之间
 *        线性过渡，位置还是原来那套采样点，但亮度连续。
 *        附带好处：几何从 60 次/秒降到 30 次/秒，**算力反而省一半**。
 *   2. 色阶是硬比较，格子值在阈值附近抖动就来回横跳 —— 闪烁。
 *      → 色阶边界改成**对称 alpha 斜坡**（下沿开始淡入、上沿完全实体），
 *        颜色和出现/消失都是渐变；再叠一层每格固定的**静态抖动**，
 *        边界溶成参差的边而不是一刀切。
 *      → 再加**迟滞**：alpha 下降时按帧限速，不会一帧掉到 0。
 *   3. 余晖按帧衰减，亮度一格一格往下掉。
 *      → 余晖跟几何步走（每个 1/30 秒一步），步与步之间靠插值连续。
 *
 * ══ 3. 色调 ════════════════════════════════════════════════
 * v1 原版的强调色是 Tailwind 400 级（琥珀 #f0b45e / 天蓝 #38bdf8），
 * 饱和度高、明度卡在中间 —— 就是之前被判「廉价感」的那类色。
 * 现在走**低彩度**方向：底色沉到接近页面底 → 浪身低彩度 → 浪尖接近白
 * 但带冷色相；辉光是**独立的一支冷雾色**，不跟格子颜色。
 * 结构仍是三档硬边（底 / 浪身 / 浪尖），这是 B 原版的辨识度所在。
 *
 * ══ 4. 密度伺服 ════════════════════════════════════════════
 * 遮罩阈值写死的话，密度会随屏幕尺寸漂移（同一份代码在 1296px 画布
 * 放行 13%，换个尺寸可能只剩 0.2%）。所以阈值不写死：每帧量一次
 * 实际点亮比例，用比例积分把遮罩窗口推向目标。窗口**整体平移**
 * （A、B 一起动），软边宽度保持不变，块的边缘质感不会走样。
 *
 * 零依赖、无构建、严格 CSP 友好：
 * 不写任何 style 属性、不用 innerHTML、不引外部资源。
 */
(function (global) {
  'use strict';

  var SS = 4;              // 每格拆成 SS×SS 亚像素
  var NOISE_N = 256;       // 噪声图边长（可平铺）

  /* ══════════════════════════════════════════════════════════
     调色板 —— 低彩度三档 + 独立冷雾辉光
     ══════════════════════════════════════════════════════════
     bg / accent（浪身）/ white（浪尖）三档，辉光色独立。
     gate 是产品页专属：底色跟 base.css 的 --bg #05070b 对齐，
     强调色跟 --signal #4cc2e6 同一套青。 */
  var PALETTES = {
    gate:      { bg: [5, 7, 11],    accent: [110, 182, 206],  white: [236, 248, 252], bloom: [86, 204, 238] },
    glacier:   { bg: [8, 10, 14],   accent: [108, 144, 172], white: [235, 242, 248], bloom: [132, 180, 224] },
    moonstone: { bg: [10, 10, 11],  accent: [136, 140, 148], white: [244, 245, 248], bloom: [186, 190, 200] },
    dusk:      { bg: [8, 8, 16],    accent: [106, 104, 176], white: [232, 230, 250], bloom: [130, 128, 214] },
    ember:     { bg: [12, 9, 8],    accent: [162, 122, 76],  white: [247, 232, 210], bloom: [214, 158, 92] },
    violet:    { bg: [9, 7, 15],    accent: [130, 104, 196], white: [240, 236, 252], bloom: [152, 124, 224] },
  };

  /* ══════════════════════════════════════════════════════════
     风格 —— 每套 = 配色 + 少量波形微调，几何以 v1 原版为基准
     ══════════════════════════════════════════════════════════ */
  var STYLES = {
    gate: {
      label: '门青 Gate',
      note: '低彩度青，底色跟 base.css 的 --bg 对齐。产品默认。',
      palette: 'gate',
      params: {},
    },
    glacier: {
      label: '冰川 Glacier',
      note: 'v1 原版几何，波速 +6%、扭曲收敛 ⇒ 稳重、块更大。',
      palette: 'glacier',
      params: {
        waves: [
          { k: 0.00580, om: 0.636, off: 0.00, dir: -0.30, w: 1.00 },
          { k: 0.00625, om: 0.710, off: 2.10, dir: -0.25, w: 0.90 },
          { k: 0.00545, om: 0.572, off: 4.20, dir: -0.35, w: 0.78 },
        ],
        distortAmp: 1.05,
      },
    },
    moonstone: {
      label: '月白 Moonstone',
      note: '银白单色，波速 −16% ⇒ 波长更长、段落更缓。对比最高。',
      palette: 'moonstone',
      params: {
        waves: [
          { k: 0.00580, om: 0.504, off: 0.00, dir: -0.30, w: 1.00 },
          { k: 0.00625, om: 0.563, off: 2.10, dir: -0.25, w: 0.90 },
          { k: 0.00545, om: 0.454, off: 4.20, dir: -0.35, w: 0.78 },
        ],
        distortAmp: 0.85,
      },
    },
    dusk: {
      label: '暮蓝 Dusk',
      note: '蓝紫，波速 +19%、扭曲更强 ⇒ 碎块翻滚得更厉害。',
      palette: 'dusk',
      params: {
        waves: [
          { k: 0.00580, om: 0.714, off: 0.00, dir: -0.30, w: 1.00 },
          { k: 0.00625, om: 0.797, off: 2.10, dir: -0.25, w: 0.90 },
          { k: 0.00545, om: 0.643, off: 4.20, dir: -0.35, w: 0.78 },
        ],
        distortAmp: 1.45,
      },
    },
    ember: {
      label: '熔金 Ember',
      note: '低彩度暖琥珀。edge0 放宽 ⇒ 带更宽更饱满，浪尖更密。',
      palette: 'ember',
      params: {
        edge0: 0.75,
      },
    },
    violet: {
      label: '紫电 Violet',
      note: '深紫罗兰，波速 +30%、扭曲最强 ⇒ 密度最高、最碎。',
      palette: 'violet',
      params: {
        waves: [
          { k: 0.00580, om: 0.780, off: 0.00, dir: -0.30, w: 1.00 },
          { k: 0.00625, om: 0.871, off: 2.10, dir: -0.25, w: 0.90 },
          { k: 0.00545, om: 0.702, off: 4.20, dir: -0.35, w: 0.78 },
        ],
        distortAmp: 1.70,
      },
    },
  };

  /* ══════════════════════════════════════════════════════════
     通用参数
     ══════════════════════════════════════════════════════════ */
  var P = {
    /* ── 波形（v1 原版，一字未改）─────────────────────────
       dir 是法线角：-0.30 ⇒ 带接近竖直。k 很小 ⇒ 波长约 1080px，
       屏幕上就是几道宽光带。三道错相平行浪，互相拍频、互相错开。 */
    waves: [
      { k: 0.00580, om: 0.60, off: 0.00, dir: -0.30, w: 1.00 },
      { k: 0.00625, om: 0.67, off: 2.10, dir: -0.25, w: 0.90 },
      { k: 0.00545, om: 0.54, off: 4.20, dir: -0.35, w: 0.78 },
    ],
    /* 波前窗口：sin(phase) 超过 edge0 开始亮，到 edge1 满亮 */
    edge0: 0.80,
    edge1: 0.99,
    /* 相位扭曲：让波前是曲线而不是直线 */
    distortAmp: 1.25,
    distortScale: 0.0016,
    distortDrift: 0.030,
    /* 分片遮罩：两个中频噪声各自阈值化后相乘 → 不规则块状。
       采样在**屏幕空间**（不是波坐标系）—— 这一条让密度天生稳得多。 */
    patchScale: 0.0027,
    patchDrift: 0.011,
    patchA1: -0.05, patchB1: 0.42,
    patchA2: -0.18, patchB2: 0.34,
    patchGain: 1.0,
    /* 分块遮罩的柔边宽度（越大越糊） */
    patchSoft: 1.0,
    /* 亮度总增益 */
    gain: 1.0,
    /* 色阶切分：band 值 ≥ accentT 给浪身，≥ whiteT 给浪尖 */
    accentT: 0.30,
    whiteT: 0.80,
    /* 余晖：每个几何步（1/30 秒）的衰减系数。
       0.80 ⇒ 半衰期约 3 个步 ≈ 100ms，比 v1 原版略长一点，更耐看。 */
    trail: 0.80,
    /* 几何采样步长（秒）。渲染在帧间插值，所以这个值只决定
       「场多久重算一次」，不决定画面有多跳。 */
    step: 1 / 30,
    /* 辉光：只有浪尖发光（v1 原版就是这样），辉光色独立成一支冷雾 */
    bloomAlpha: 0.22, bloomMin: 2,
    /* ── 点的随机化 ──────────────────────────────────────
       pickGain：块内随机选取率。块越亮（mask 越大），被选中的格子
       越多 ⇒ 块内是随机疏密的点群，而不是整块实心。
       **这个值由密度伺服调**，遮罩阈值保持 v1 原值不动 ——
       块的结构不因为调密度而变形。 */
    pickGain: 0.90,
    /* pickSoft：随机选取门的软边宽度（pOn 单位）。
       硬开关的话点会「啪」地出现（一帧跨 10 个亮度阶）；
       软门 ⇒ 点从暗到亮渐变出来。 */
    pickSoft: 0.18,
    /* jitterAmp：块内明暗随机幅度。1.0 ⇒ 亮度在 1-jitter .. 1 之间随机 */
    jitterAmp: 0.20,
    /* ── 丝滑层 ──────────────────────────────────────────
       fade：色阶边界的 alpha 斜坡宽度（值域）。越大越柔。 */
    fade: 0.06,
    /* ditherAmt：时间抖动的幅度（值域峰值）。每格有固定相位，
       偏移随时间平滑摆动 —— 逐帧随机会更闪。 */
    ditherAmt: 0.05,
    /* ditherSpeed：抖动摆动频率（Hz）。 */
    ditherSpeed: 0.85,
    /* statJit：每格**固定**的值域偏移 —— 让色阶边界溶成参差的边，
       而不是一刀切。因为固定，不会引入闪烁。 */
    statJit: 0.06,
    /* hyst：alpha 下降的限速（每帧最多降这么多）。
       卡在阈值上的格子不会一帧掉到 0 ⇒ 消掉闪烁。 */
    hyst: 0.035,
    /* lit：旧引擎语义 —— **总体**点亮比例（占全画布）。0 = 用下面默认。 */
    lit: 0.10,
  };

  /* ══════════════════════════════════════════════════════════
     噪声
     ══════════════════════════════════════════════════════════ */
  function makeNoise(N) {
    var grid = new Float32Array(N * N);
    var seed = 987654321 >>> 0;
    var i, j;
    for (i = 0; i < N * N; i++) {
      seed ^= seed << 13; seed >>>= 0;
      seed ^= seed >>> 17;
      seed ^= seed << 5; seed >>>= 0;
      grid[i] = seed / 4294967296;
    }
    var out = new Float32Array(N * N);
    var octaves = [4, 9, 21];
    function smooth(t) { return t * t * (3 - 2 * t); }
    for (var o = 0; o < octaves.length; o++) {
      var f = octaves[o], amp = 1 / (o + 1);
      for (j = 0; j < N; j++) {
        var fy = (j / N) * f, y0 = Math.floor(fy), ty = smooth(fy - y0);
        var y0m = y0 % f, y1m = (y0 + 1) % f;
        for (i = 0; i < N; i++) {
          var fx = (i / N) * f, x0 = Math.floor(fx), tx = smooth(fx - x0);
          var x0m = x0 % f, x1m = (x0 + 1) % f;
          var a = grid[y0m * N + x0m], b = grid[y0m * N + x1m];
          var c = grid[y1m * N + x0m], d = grid[y1m * N + x1m];
          out[j * N + i] += amp * (a + (b - a) * tx + (c - a) * ty + (a - b - c + d) * tx * ty);
        }
      }
    }
    var mn = Infinity, mx = -Infinity;
    for (i = 0; i < out.length; i++) { if (out[i] < mn) mn = out[i]; if (out[i] > mx) mx = out[i]; }
    var span = (mx - mn) || 1;
    for (i = 0; i < out.length; i++) out[i] = ((out[i] - mn) / span) * 2 - 1;
    return out;
  }

  function sample(tex, N, u, v) {
    var x = u * N, y = v * N;
    var x0 = Math.floor(x), y0 = Math.floor(y);
    var fx = x - x0, fy = y - y0;
    var i0 = ((x0 % N) + N) % N, i1 = (i0 + 1) % N;
    var j0 = ((y0 % N) + N) % N, j1 = (j0 + 1) % N;
    var a = tex[j0 * N + i0], b = tex[j0 * N + i1];
    var c = tex[j1 * N + i0], d = tex[j1 * N + i1];
    var sx = fx * fx * (3 - 2 * fx), sy = fy * fy * (3 - 2 * fy);
    var top = a + (b - a) * sx, bot = c + (d - c) * sx;
    return top + (bot - top) * sy;
  }

  function sstep(a, b, x) {
    if (b === a) return x < a ? 0 : 1;
    var t = (x - a) / (b - a);
    t = t < 0 ? 0 : (t > 1 ? 1 : t);
    return t * t * (3 - 2 * t);
  }

  function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }

  /* 整数哈希 —— 给每格生成稳定的随机量（换项目可复用） */
  function rnd(i, salt) {
    var h = (i + salt) | 0;
    h = Math.imul(h ^ (h >>> 16), 2246822507);
    h = Math.imul(h ^ (h >>> 13), 3266489909);
    h = (h ^ (h >>> 16)) >>> 0;
    return h / 4294967296;
  }

  /* ══════════════════════════════════════════════════════════
     引擎
     ══════════════════════════════════════════════════════════ */
  function create(canvas, opt) {
    opt = opt || {};
    var COLUMNS = opt.columns || 112;
    var USE_BLOOM = opt.bloom !== false;
    var PAL_KEY = opt.palette || 'gate';

    var p = {};
    for (var pk in P) if (P.hasOwnProperty(pk)) p[pk] = P[pk];
    if (opt.params) {
      for (var ok in opt.params) {
        if (!opt.params.hasOwnProperty(ok)) continue;
        p[ok] = opt.params[ok];
      }
    }
    if (opt.waves) p.waves = opt.waves;

    var ctx = canvas.getContext('2d');
    if (!ctx) return null;

    var pal = PALETTES[PAL_KEY] || PALETTES.gate;

    var tex = makeNoise(NOISE_N);
    var w = 0, h = 0, cell = 12, cols = 0, rows = 0, sw = 0;
    var raf = 0, start = 0, lastT = 0;
    var peak = new Float32Array(0);        /* 当前几何步的余晖值 */
    var prevPeak = new Float32Array(0);    /* 上一几何步的余晖值（插值用） */
    var aPrev = new Float32Array(0);       /* 上一帧的浪身 alpha（迟滞用） */
    var wPrev = new Float32Array(0);       /* 上一帧的浪尖 alpha（迟滞用） */
    var rSel = new Float32Array(0);        /* 每格固定随机门槛 */
    var rAmp = new Float32Array(0);        /* 每格固定亮度因子 */
    var rJit = new Float32Array(0);        /* 每格固定值域偏移 */
    var dphase = new Float32Array(0);      /* 每格抖动相位 */

    var fine = document.createElement('canvas');
    var fctx = fine.getContext('2d');
    var fineImg = null, fineData = null;

    var glow = document.createElement('canvas');
    var gctx = glow.getContext('2d');
    var glowImg = null, glowData = null;

    var stats = { lit: 0, cells: 0, fps: 0, litFrac: 0, bandFrac: 0, litInBand: 0, bandCells: 0 };
    var litFracEma = 0;
    var calibrating = false;
    var resizeCount = 0, roCount = 0, roPending = false;
    var frameCount = 0, geoCount = 0, fpsEma = 0;
    var lastStep = -1;

    function resize() {
      var rect = canvas.getBoundingClientRect();
      w = Math.max(1, Math.floor(rect.width));
      h = Math.max(1, Math.floor(rect.height));
      var dpr = Math.min(global.devicePixelRatio || 1, 1.5);
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.imageSmoothingEnabled = false;

      var newCell = SS * Math.max(2, Math.round(w / COLUMNS / SS));
      var newCols = Math.ceil(w / newCell);
      var newRows = Math.ceil(h / newCell);

      /* ⚠️ 只有网格真的变了才重分配。ResizeObserver 会反复触发
       * （含改 canvas.width 引发的观察），每次都 new 一遍场就把
       * 刚攒起来的画面清零了。 */
      var gridChanged = (newCell !== cell || newCols !== cols || newRows !== rows);
      cell = newCell; cols = newCols; rows = newRows;
      sw = cols * SS;
      var sh = rows * SS;
      resizeCount++;
      if (gridChanged || !peak.length) {
        var n = cols * rows;
        peak = new Float32Array(n);
        prevPeak = new Float32Array(n);
        aPrev = new Float32Array(n);
        wPrev = new Float32Array(n);
        rSel = new Float32Array(n);
        rAmp = new Float32Array(n);
        rJit = new Float32Array(n);
        dphase = new Float32Array(n);
        for (var i = 0; i < n; i++) {
          rSel[i] = rnd(i, 1013904223);
          rAmp[i] = rnd(i, 22695477);
          rJit[i] = (rnd(i, 69069) - 0.5) * 2;
          dphase[i] = rnd(i, 134775813) * 6.2831853;
        }
        lastStep = -1;
      }
      litFracEma = 0;   /* 几何变了，遮罩分布也变了，伺服重新收敛 */
      bandFracEma = 0;
      errFilt = 0;

      fine.width = sw; fine.height = sh;
      if (fctx) { fineImg = fctx.createImageData(sw, sh); fineData = fineImg.data; }
      glow.width = cols; glow.height = rows;
      if (gctx) { glowImg = gctx.createImageData(cols, rows); glowData = glowImg.data; }
    }

    /* ── 几何：波 + 遮罩 + 随机选取 + 余晖 ────────────────
     * 只在**几何步**变化时跑（默认 30 次/秒）。渲染在帧间插值，
     * 所以画面连续，但算力比原来还省一半。 */
    function computeGeometry(tq) {
      var waves = p.waves;
      var nw = waves.length;
      var idx = 0;
      var bandCells = 0;

      for (var cy = 0; cy < rows; cy++) {
        var py = cy * cell + cell * 0.5;
        for (var cx = 0; cx < cols; cx++) {
          var px = cx * cell + cell * 0.5;

          /* ── 相位扭曲：让波前是曲线而不是直线 ───────────── */
          var dz = sample(tex, NOISE_N,
            px * p.distortScale + tq * p.distortDrift,
            py * p.distortScale * 1.25 + tq * p.distortDrift * 0.6);

          /* ── 多道错相平行浪，取最强的一道 ───────────────── */
          var band = 0;
          for (var wi = 0; wi < nw; wi++) {
            var wv = waves[wi];
            var uy = px * Math.sin(wv.dir) + py * Math.cos(wv.dir);
            var ph = wv.k * uy - wv.om * tq + wv.off + dz * p.distortAmp;
            var s = Math.sin(ph);
            if (s <= p.edge0) continue;
            var b = sstep(p.edge0, p.edge1, s) * wv.w;
            if (b > band) band = b;
          }

          /* ── 分片遮罩：把带碎成一块块 ─────────────────── */
          if (band > 0) {
            bandCells++;
            var n1 = sample(tex, NOISE_N,
              px * p.patchScale + tq * p.patchDrift,
              py * p.patchScale * 1.15 + tq * p.patchDrift * 0.8);
            var n2 = sample(tex, NOISE_N,
              px * p.patchScale * 0.77 + 37.1 + tq * p.patchDrift * 0.55,
              py * p.patchScale * 1.05 + 11.3 + tq * p.patchDrift * 0.9);
            var m1 = sstep(p.patchA1, p.patchA1 + (p.patchB1 - p.patchA1) / p.patchSoft, n1);
            var m2 = sstep(p.patchA2, p.patchA2 + (p.patchB2 - p.patchA2) / p.patchSoft, n2);
            var mask = m1 * m2;
            if (mask < 0.08) {
              band = 0;
            } else {
              band *= mask * p.patchGain;
              /* ── 点的随机化 ──────────────────────────────
                 每格一个固定随机门槛：块越亮，被选中的格子越多
                 ⇒ 块内是随机疏密的点群，而不是整块实心。
                 门槛固定 ⇒ 点亮顺序稳定，不会闪。 */
              /* mask^1.6：陡一点 ⇒ 亮块接近满选（块还看得出形状），
                 暗块很稀 ⇒ 块与块之间层次分明。 */
              var pOn = Math.pow(mask, 1.6) * p.pickGain;
              if (pOn > 1) pOn = 1;
              /* ── 随机选取（软门）────────────────────────
                 每格一个固定随机门槛 rSel：块越亮（mask 越大），
                 跨过门槛的格子越多 ⇒ 块内是随机疏密的点群。
                 门槛固定 ⇒ 亮灭顺序稳定，不会闪。
                 门是软的 ⇒ 点从暗到亮渐变出来，不是「啪」地蹦出来。 */
              var sel = (pOn + p.pickSoft - rSel[idx]) / p.pickSoft;
              if (sel < 0) sel = 0; else if (sel > 1) sel = 1;
              if (sel <= 0) {
                band = 0;
              } else {
                band *= sel;
                /* 块内明暗随机（只往下压，不削峰值 ⇒ 浪尖出得来） */
                band *= (1 - p.jitterAmp) + p.jitterAmp * rAmp[idx];
              }
            }
          }

          band *= p.gain;

          /* ── 磷光余晖：保留峰值再衰减 ─────────────────── */
          var prev = peak[idx];
          var e = band > prev ? band : prev * p.trail;
          peak[idx] = e;
          idx++;
        }
      }
      stats.bandCells = bandCells;
      stats.bandFrac = bandCells / Math.max(1, cols * rows);
    }

    /* ── 密度伺服 ────────────────────────────────────────
     * 控制量是「**带内**点亮比例」，不是全屏点亮比例。
     *
     * 为什么不用全屏比例：波的覆盖率本身在动（同一屏上能从 0.1
     * 摆到 0.86），全屏比例跟着它摆，伺服追着它跑就是自激 ——
     * 实测阈值会在 ±0.3 的范围里来回甩，点亮率在 0% 和 20% 之间翻。
     * 带内比例（亮格数 / 带内格数）与覆盖率无关，稳。
     *
     * 执行的量是 pickGain（块内随机选取率），**遮罩阈值保持 v1 原值
     * 不动** —— 块的结构不会因为调密度而变形。
     */
    var bandFracEma = 0;
    var errFilt = 0;

    function servoStep(litInBand, fast) {
      var target = p.lit > 0 ? p.lit : 0.10;
      var tf = bandFracEma > 0.02 ? bandFracEma : 0.5;
      var targetInBand = clamp(target / tf, 0.02, 0.98);
      var err = targetInBand - litInBand;
      if (fast) {
        errFilt = err;
      } else {
        errFilt += (err - errFilt) * 0.02;
      }
      /* 增益必须远小于 1：环路增益 ≈ (d litInBand / d pickGain) × 增益，
       * 前者实测约 0.94，取 0.15 ⇒ 环路增益 0.14，稳定。
       * 之前取 0.8（环路增益 0.75）→ 阈值在 ±0.3 里甩，点亮率 0↔20% 翻。 */
      var adj = clamp(errFilt * 0.15, -0.004, 0.004);
      p.pickGain = clamp(p.pickGain + adj, 0.02, 4);
      return Math.abs(err);
    }

    function render(t, dt) {
      if (!fineData || !fctx || !peak.length) return;

      /* ── 几何步推进 ────────────────────────────────── */
      var stepIdx = Math.floor(t / p.step);
      if (stepIdx !== lastStep) {
        prevPeak.set(peak);
        computeGeometry(stepIdx * p.step);
        lastStep = stepIdx;
        geoCount++;
      }
      var lerp = t / p.step - stepIdx;      /* 0..1，两个几何步之间的位置 */

      fineData.fill(0);
      if (glowData) glowData.fill(0);

      var idx = 0, litCount = 0;
      var dth = p.ditherAmt * 0.5;
      var fade = p.fade > 0.001 ? p.fade : 0.001;
      var half = fade * 0.5;
      var tLo1 = p.accentT - half, tLo2 = p.whiteT - half;
      var hyst = p.hyst;
      var jitAmp = p.statJit * 0.5;
      var acc = pal.accent, wht = pal.white;
      var gc = pal.bloom || acc;
      var dRate = p.ditherSpeed * 6.2831853;

      for (var cy = 0; cy < rows; cy++) {
        var by0 = cy * SS;
        for (var cx = 0; cx < cols; cx++) {
          /* ── 连续插值：几何按 1/30 秒采样，渲染在步间线性过渡 */
          var v = prevPeak[idx] + (peak[idx] - prevPeak[idx]) * lerp;
          /* ── 抖动：每格固定相位的时间平滑摆动 + 每格固定的空间偏移 */
          var off = Math.sin(t * dRate + dphase[idx]) * dth + rJit[idx] * jitAmp;
          var vv = v + off;

          /* ── 色阶的 alpha 斜坡（对称，边界是渐变不是硬切）── */
          var a1 = (vv - tLo1) / fade;
          if (a1 < 0) a1 = 0; else if (a1 > 1) a1 = 1;
          var a2 = (vv - tLo2) / fade;
          if (a2 < 0) a2 = 0; else if (a2 > 1) a2 = 1;

          /* ── 迟滞：alpha 下降按帧限速，卡在阈值上的格子
                不会一帧掉到 0 ⇒ 消掉闪烁。 ─────────────── */
          if (a1 < aPrev[idx]) {
            var lo = aPrev[idx] - hyst;
            if (lo < 0) lo = 0;
            if (a1 < lo) a1 = lo;
          }
          if (a2 < wPrev[idx]) {
            var lo2 = wPrev[idx] - hyst;
            if (lo2 < 0) lo2 = 0;
            if (a2 < lo2) a2 = lo2;
          }
          aPrev[idx] = a1;
          wPrev[idx] = a2;

          if (a1 <= 0.002 && a2 <= 0.002) { idx++; continue; }
          litCount++;

          /* ── 画：浪身铺底，浪尖叠在上面 ─────────────────
             两层都画 ⇒ accent→white 的切换也是渐变，不会闪。 */
          var b1 = 2;
          var inset1 = ((SS - b1) / 2) | 0;
          var bx1 = cx * SS + inset1;
          var by1 = by0 + inset1;
          if (bx1 + b1 <= sw && by1 + b1 <= rows * SS) {
            var a255 = (a1 * 255) | 0;
            var o;
            for (var yy = 0; yy < b1; yy++) {
              o = ((by1 + yy) * sw + bx1) * 4;
              for (var xx = 0; xx < b1; xx++) {
                fineData[o] = acc[0]; fineData[o + 1] = acc[1]; fineData[o + 2] = acc[2]; fineData[o + 3] = a255;
                o += 4;
              }
            }
          }

          if (a2 > 0.002) {
            var b2 = 3;
            var inset2 = ((SS - b2) / 2) | 0;
            var bx2 = cx * SS + inset2;
            var by2 = by0 + inset2;
            if (bx2 + b2 <= sw && by2 + b2 <= rows * SS) {
              var a255w = (a2 * 255) | 0;
              var o2;
              for (var yy2 = 0; yy2 < b2; yy2++) {
                o2 = ((by2 + yy2) * sw + bx2) * 4;
                for (var xx2 = 0; xx2 < b2; xx2++) {
                  fineData[o2] = wht[0]; fineData[o2 + 1] = wht[1]; fineData[o2 + 2] = wht[2]; fineData[o2 + 3] = a255w;
                  o2 += 4;
                }
              }
            }
          }

          /* ── 辉光：独立的一支冷雾色，不跟格子颜色 ──────
             只有**浪尖**发光（bloomMin=2），跟 v1 原版一致 ——
             每个格都发光的话整屏会糊成一层灰雾。 */
          if (glowData && a2 > 0.002) {
            var go = (cy * cols + cx) * 4;
            var ga = (a2 * 255) | 0;
            glowData[go] = gc[0]; glowData[go + 1] = gc[1]; glowData[go + 2] = gc[2]; glowData[go + 3] = ga;
          }

          idx++;
        }
      }

      fctx.putImageData(fineImg, 0, 0);

      ctx.fillStyle = 'rgb(' + pal.bg[0] + ',' + pal.bg[1] + ',' + pal.bg[2] + ')';
      ctx.fillRect(0, 0, w, h);

      if (USE_BLOOM && glowData && gctx) {
        gctx.putImageData(glowImg, 0, 0);
        ctx.globalAlpha = p.bloomAlpha;
        ctx.imageSmoothingEnabled = true;
        ctx.drawImage(glow, 0, 0, w, h);
        ctx.globalAlpha = 1;
        ctx.imageSmoothingEnabled = false;
      }

      ctx.drawImage(fine, 0, 0, w, h);

      var total = cols * rows;
      stats.lit = litCount;
      stats.cells = total;
      stats.litFrac = litCount / Math.max(1, total);
      stats.litInBand = litCount / Math.max(1, stats.bandCells);

      if (!calibrating) {
        bandFracEma = bandFracEma > 0
          ? bandFracEma + (stats.bandFrac - bandFracEma) * 0.002
          : stats.bandFrac;
        litFracEma = litFracEma > 0
          ? litFracEma + (stats.litFrac - litFracEma) * 0.12
          : stats.litFrac;
        servoStep(stats.litInBand, false);
      }
    }

    function frame(now) {
      if (!start) { start = now; lastT = now; }
      var dt = Math.min(0.05, (now - lastT) / 1000);
      lastT = now;
      frameCount++;
      if (dt > 0) {
        fpsEma = fpsEma > 0 ? fpsEma + (1 / dt - fpsEma) * 0.08 : 1 / dt;
        stats.fps = Math.round(fpsEma);
      }
      render((now - start) / 1000, dt);
      raf = global.requestAnimationFrame(frame);
    }

    /* ResizeObserver 会连续触发（改 canvas.width 也会引发一次观察），
       回调里直接 resize 就会形成自激循环。用 rAF 去抖。 */
    function onResize() {
      if (roPending) return;
      roPending = true;
      roCount++;
      global.requestAnimationFrame(function () {
        roPending = false;
        resize();
        renderNow();
      });
    }
    function nowMs() { return (global.performance && global.performance.now) ? global.performance.now() : 0; }
    function currentT() { return start ? (nowMs() - start) / 1000 : 0; }
    function renderNow() { render(currentT(), 0.016); }

    resize();

    /* 静止模式（prefers-reduced-motion）：先把密度标定到位，再定格一帧。 */
    if (opt.static) {
      calibrating = true;
      for (var it = 0; it < 220; it++) {
        lastStep = -1;                 /* 强制重算几何 */
        render(0.016 * (it + 1), 0.016);
        if (servoStep(stats.litInBand, true) < 0.004) break;
      }
      calibrating = false;
      lastStep = -1;
      render(0.016 * 221, 0.016);
    } else {
      renderNow();
    }

    var ro = null;
    if (typeof ResizeObserver !== 'undefined') {
      ro = new ResizeObserver(function () { onResize(); });
      ro.observe(canvas);
    }
    global.addEventListener('resize', onResize);

    var api = {
      start: function () { if (!raf) { start = 0; lastT = 0; raf = global.requestAnimationFrame(frame); } },
      stop: function () { if (raf) { global.cancelAnimationFrame(raf); raf = 0; } },
      render: function (t) { render(t || 0, 0.016); },
      stats: stats,
      setParams: function (next) {
        if (!next) return;
        for (var k in next) if (next.hasOwnProperty(k)) p[k] = next[k];
      },
      setPalette: function (key) {
        if (PALETTES[key]) { pal = PALETTES[key]; PAL_KEY = key; }
      },
      setColors: function (colors) {
        if (!colors) return;
        if (!PALETTES.__custom) {
          PALETTES.__custom = {
            bg: pal.bg.slice(), accent: pal.accent.slice(),
            white: pal.white.slice(), bloom: pal.bloom ? pal.bloom.slice() : null,
          };
        }
        var t = PALETTES.__custom;
        function put(key, val) {
          if (val && val.length >= 3) t[key] = [val[0] | 0, val[1] | 0, val[2] | 0];
        }
        put('bg', colors.bg);
        put('accent', colors.accent || colors.mid);
        put('white', colors.white || colors.crest);
        put('bloom', colors.bloom);
        pal = t;
        PAL_KEY = '__custom';
      },
      getPalette: function () {
        return {
          bg: pal.bg, accent: pal.accent, white: pal.white, bloom: pal.bloom || null,
          deep: pal.accent, mid: pal.accent, crest: pal.white,
        };
      },
      debug: function () {
        var n = peak.length, sum = 0, mx = 0;
        for (var i = 0; i < n; i++) { sum += peak[i]; if (peak[i] > mx) mx = peak[i]; }
        return {
          cols: cols, rows: rows, cell: cell,
          lit: stats.lit, cells: stats.cells, fps: stats.fps,
          litFrac: stats.litFrac, bandFrac: stats.bandFrac, litFracEma: litFracEma,
          litInBand: stats.litInBand, bandCells: stats.bandCells,
          pickGain: p.pickGain, bandFracEma: bandFracEma, errFilt: errFilt,
          waves: p.waves.map(function (x) { return { k: x.k, om: x.om, off: x.off, dir: x.dir, w: x.w }; }),
          fieldMean: n ? sum / n : 0, fieldMax: mx,
          resizeCount: resizeCount, roCount: roCount, frameCount: frameCount, geoCount: geoCount,
          p: {
            edge0: p.edge0, edge1: p.edge1, distortAmp: p.distortAmp,
            patchScale: p.patchScale, patchA1: p.patchA1, patchB1: p.patchB1,
            patchA2: p.patchA2, patchB2: p.patchB2, patchSoft: p.patchSoft,
            accentT: p.accentT, whiteT: p.whiteT, trail: p.trail, step: p.step,
            pickGain: p.pickGain, pickSoft: p.pickSoft, jitterAmp: p.jitterAmp,
            fade: p.fade, ditherAmt: p.ditherAmt, statJit: p.statJit, hyst: p.hyst, lit: p.lit,
          },
          pAll: p,
        };
      },
      destroy: function () {
        api.stop();
        if (ro) ro.disconnect();
        global.removeEventListener('resize', onResize);
      }
    };

    if (!opt.static) api.start();
    return api;
  }

  function mount(canvas, opts) {
    if (!canvas) return null;
    var reduce = false;
    try {
      reduce = !!(global.matchMedia &&
        global.matchMedia('(prefers-reduced-motion: reduce)').matches);
    } catch (e) { reduce = false; }
    var o = {};
    for (var k in (opts || {})) if (opts.hasOwnProperty(k)) o[k] = opts[k];
    o.static = reduce;
    return create(canvas, o);
  }

  /* 按风格创建：样式 = 配色 + 一整套波形参数 */
  function createStyle(canvas, styleKey, opt) {
    opt = opt || {};
    var st = STYLES[styleKey] || STYLES.gate;
    var params = {};
    for (var k in st.params) if (st.params.hasOwnProperty(k)) params[k] = st.params[k];
    if (opt.params) for (var ok in opt.params) if (opt.params.hasOwnProperty(ok)) params[ok] = opt.params[ok];
    var o = {};
    for (var oo in opt) if (opt.hasOwnProperty(oo)) o[oo] = opt[oo];
    o.palette = st.palette;
    o.params = params;
    return create(canvas, o);
  }

  /**
   * 冲击波：按下时从按下的位置炸开一圈。
   *
   * 位置通过 CSS 变量 --rx / --ry 传过去。这是 CSSOM 操作
   * （element.style.setProperty），**不受 CSP style-src 限制** ——
   * style-src 只管内联 <style> 元素和 HTML 里的 style 属性解析。
   * 万一传不了，CSS 里 var(--rx, 50%) 会退化成从中心炸开。
   */
  function ripple(el, ev) {
    if (!el) return;
    var r = el.getBoundingClientRect();
    /* 键盘提交时 clientX/Y 是 0，那就不按坐标算，退化成从中心炸开 */
    var hasPos = ev && ev.clientX != null && (ev.clientX !== 0 || ev.clientY !== 0);
    var x = hasPos ? ev.clientX - r.left : r.width / 2;
    var y = hasPos ? ev.clientY - r.top : r.height / 2;
    try {
      el.style.setProperty('--rx', x + 'px');
      el.style.setProperty('--ry', y + 'px');
    } catch (e) { /* 退化成中心 */ }
    el.classList.remove('rippling');
    void el.offsetWidth;              /* 强制重排，保证连续点击能重放 */
    el.classList.add('rippling');
  }

  global.GhostPixelField = {
    create: create,
    createStyle: createStyle,
    mount: mount,
    ripple: ripple,
    PALETTE: PALETTES,
    PALETTES: PALETTES,
    STYLES: STYLES,
    PARAMS: P
  };
  /* 旧名字也留着，别的地方可能还在用 */
  global.GhostWaveField = global.GhostPixelField;
})(typeof window !== 'undefined' ? window : this);
