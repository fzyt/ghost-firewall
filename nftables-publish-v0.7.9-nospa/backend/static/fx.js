/**
 * 服务门户背景 · 变体引擎
 *
 * 为什么另起一个引擎，而不是给 pixelfield.js 加参数：
 *   pixelfield.js 是「光带扫过方块场」—— 波 + 遮罩 + 余晖，
 *   结构上只有一种运动语法。要做「数据流」「拓扑」「日志流」
 *   这类**生成逻辑完全不同**的效果，硬塞进同一个引擎只会把
 *   那个引擎变成一堆互不相干的开关。
 *   ⇒ 这里另起一套：共用「低分辨率缓冲 + 上色 + 整数放大」的骨架，
 *     每个变体只实现自己的生成逻辑。
 *
 * 为什么用低分辨率缓冲再放大：
 *   1440px 宽按 12px 一格 ⇒ 120×75 = 9000 格。
 *   每帧只更新 9000 个 float，再一次性 putImageData 放大到全屏
 *   （imageSmoothingEnabled = false ⇒ 每格成一个硬边方块）。
 *   这是「方块感」的来源，也比逐格 fillRect 快一个量级。
 *
 * 颜色：只有「浪身 accent」与「浪尖 white」两档。
 *   科技感靠运动结构，不靠色相 —— 这套银白是全站语言，不能换。
 *
 * 零依赖、零构建、CSP 友好：不写 style 属性、不用 innerHTML、不引外部资源。
 */
(function (global) {
  'use strict';

  var DPR_MAX = 1.5;
  var TARGET_CELL = 12;          /* 目标格边长（px） */

  var ACCENT = [136, 140, 148];   /* 浪身 */
  var WHITE = [244, 245, 248];    /* 浪尖 */

  /* ⚠️ 亮度增益：为什么每个变体都要乘这个数
   *   画布之上还压着一层 .pix-scrim（radial + linear 两层 rgba(10,10,11)），
   *   顶部放行 ~10%、底部放行 ~39%。原生像素场靠「满 alpha 的白色方块」
   *   硬扛这层压暗，所以它看着还有亮度。
   *   自研变体的亮格本来就稀疏，再被压一层就几乎全黑（实测 codegen
   *   canvasMeanAlpha 只有 1.68，底部终端条完全看不见）。
   *   ⇒ 这里统一乘一个增益，把「画布上的亮度」拉回到压暗前可看的水平。
   *   逐变体可覆盖：几何复杂的（雷达的环）需要更多，光谱类的少一点。 */
  var GAIN = 2.6;

  /* ── 小工具 ──────────────────────────────────────────────── */
  function clamp(v, a, b) { return v < a ? a : (v > b ? b : v); }

  /* 确定性随机：同一个种子每次刷新出来的画面一样，
     方便前后对比截图（不然后台一变就分不清是效果变了还是随机变了）。 */
  function Rng(seed) {
    this.s = (seed >>> 0) || 1;
  }
  Rng.prototype.next = function () {
    var s = this.s;
    s ^= s << 13; s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5; s >>>= 0;
    this.s = s;
    return s / 4294967296;
  };
  Rng.prototype.range = function (a, b) { return a + this.next() * (b - a); };
  Rng.prototype.int = function (a, b) { return Math.floor(this.range(a, b + 1)); };

  /* ══════════════════════════════════════════════════════════
     场：低分辨率缓冲 + 上色 + 放大
     ══════════════════════════════════════════════════════════ */
  function Field(canvas, variantKey, opts) {
    opts = opts || {};
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.low = document.createElement('canvas');
    this.lctx = this.low.getContext('2d');
    this.img = null; this.data = null;
    this.cols = 0; this.rows = 0; this.w = 0; this.h = 0;
    this.buf = new Float32Array(0);
    this.crest = new Uint8Array(0);
    /* 静态底纹单独一层（网格、距离环这类不随时间变的）。
     * ⚠️ 不能把底纹直接加进 buf 再一起衰减 ——
     *    递推 x ← base + 0.93x 的稳态是 base/(1-0.93) ≈ 7.1 倍，
     *    底纹会被「攒」成 7 倍亮度，整片网格糊成一片亮。
     *    底纹与动态缓冲分开，衰减只作用在动态部分。 */
    this.base = null;
    this.t = 0;
    this.raf = 0;
    this.last = 0;
    this.fps = 0;
    this.frames = 0;
    this.fpsT = 0;
    /* 本变体的亮度增益（见 GAIN 处的说明）。
       默认取全局值；变体可以在 def.gain 里覆盖。 */
    this.gain = GAIN;
    this.reduce = !!(global.matchMedia &&
      global.matchMedia('(prefers-reduced-motion: reduce)').matches);
    this.variant = null;
    this.state = {};
    this.rng = new Rng(opts.seed || 20261101);
    this.resize();
    this.setVariant(variantKey || 'pixelfield');
  }

  Field.prototype.resize = function () {
    var rect = this.canvas.getBoundingClientRect();
    var w = Math.max(1, Math.floor(rect.width));
    var h = Math.max(1, Math.floor(rect.height));
    var dpr = Math.min(global.devicePixelRatio || 1, DPR_MAX);
    this.canvas.width = Math.floor(w * dpr);
    this.canvas.height = Math.floor(h * dpr);
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.ctx.imageSmoothingEnabled = false;
    this.dpr = dpr;
    this.w = w; this.h = h;

    /* 格边长（px）。1440px 宽 ⇒ 120 列，和原生引擎一致。
       ⚠️ 这里是**每格多少像素**，不是**总共有多少格** ——
          早先写成 round(w / TARGET_CELL) = 120px/格，
          结果一格铺满 120×120 像素，整屏 96 格全是亮的。 */
    var cell = TARGET_CELL;
    var cols = Math.ceil(w / cell);
    var rows = Math.ceil(h / cell);
    var changed = (cols !== this.cols || rows !== this.rows);
    this.cell = cell;
    this.cols = cols; this.rows = rows;
    this.low.width = cols; this.low.height = rows;
    if (changed || !this.buf.length) {
      this.buf = new Float32Array(cols * rows);
      this.crest = new Uint8Array(cols * rows);
      this.img = this.lctx.createImageData(cols, rows);
      this.data = this.img.data;
      this.base = null;        /* 底纹尺寸跟着网格走，不能留旧的 */
      /* 网格变了 ⇒ 各变体的预计算（节点表 / 极坐标表）都要重做 */
      this.rebuild = true;
    }
  };

  Field.prototype.setVariant = function (key) {
    var def = VARIANTS[key];
    if (!def) return false;
    if (this.variant === key) return true;
    /* pixelfield 走的是原生引擎（有自己的一套缓冲），切走要先拆掉 */
    if (this.pixelApi) { try { this.pixelApi.destroy(); } catch (e) { /* 忽略 */ } this.pixelApi = null; }
    this.variant = key;
    this.state = {};
    this.rng = new Rng((key.length * 2654435761) >>> 0 || 7);
    this.rebuild = true;
    this.gain = def.gain || GAIN;
    /* ⚠️ 底纹必须随变体一起清掉 ——
     *   上一变体的静态层（拓扑网格 / 仪表网格 / 距离环）会留在 f.base 上，
     *   下一个变体若不设 f.base 就把它继承下去 ⇒ 换变体时屏幕上多出一层
     *   上一家的网格，看着像「没切干净」。 */
    this.base = null;
    if (key === 'pixelfield') {
      this.mountPixelField();
    } else {
      if (def.init) def.init(this, this.state);
      /* ⚠️ rebuild 必须在第一次 update **之前**跑 ——
         多数变体把网格、节点表、极坐标表都放在 rebuild 里算，
         update 直接读它们。早先的顺序（update 先跑）会让后四个
         变体一上来就炸在「读 undefined 的第 0 项」。 */
      if (def.rebuild) { def.rebuild(this, this.state); this.rebuild = false; }
    }
    this.renderOnce();
    return true;
  };

  Field.prototype.mountPixelField = function () {
    if (!global.GhostPixelField) return;
    var reduce = this.reduce;
    var self = this;
    /* 用 'moonstone-swirl' 而不是 'moonstone'：
       门户这一档波速 ×1.9、方块晶向杂乱；登录页那一档（moonstone）
       一个字没动，两边互不影响。 */
    this.pixelApi = global.GhostPixelField.createStyle(this.canvas, 'moonstone-swirl', {
      columns: 118, static: reduce,
    });
    /* 原生引擎自带 rAF 循环，但它只认「几何步 + 插值」，
       不带帧率统计，也没法和别的变体共存 ⇒ 停掉它，自己驱动 render()。
       ⚠️ 泵用**独立的 raf 槽**（pumpRaf），不与变体循环的 raf 混用 ——
          否则两个循环会互相 cancel，表现为「切到像素场就静止了」。 */
    this.pixelApi.stop();
    if (reduce) { this.pixelApi.render(1.0); return; }
    var t0 = 0;
    this.pump = function (now) {
      if (!self.pixelApi) return;
      if (!t0) t0 = now;
      self.pixelApi.render((now - t0) / 1000);
      self.pumpRaf = global.requestAnimationFrame(self.pump);
    };
    this.pumpRaf = global.requestAnimationFrame(this.pump);
  };

  Field.prototype.renderOnce = function () {
    if (this.variant === 'pixelfield') return;   /* 原生引擎自己画 */
    var def = VARIANTS[this.variant];
    if (!def) return;
    /* ⚠️ 降级动效（prefers-reduced-motion）时只画**一帧**。
       像素生成类方案是「长出来」的 —— 一帧之前它还没长，
       直接画 ⇒ 整片黑屏，用户看到的是「背景坏了」。
       ⇒ 这里先按正常步长空跑 warm 帧，把形态长出来，再定格。
       warm 是「空跑多少帧」，不是毫秒数；各变体自己定。 */
    var warm = def.warm || 0;
    for (var i = 0; i < warm; i++) def.update(this, this.state, 0.016);
    def.update(this, this.state, 0);
    this.paint();
  };

  /* 上色 + 放大 */
  Field.prototype.paint = function () {
    var d = this.data, n = this.cols * this.rows;
    var base = this.base;
    /* 增益在 paint 里统一施加 —— 变体只管「相对亮度」，
       「最终在页面上多亮」由这一层统一决定，改一处即可全局调。 */
    var gain = this.gain;
    /* 「白度」钩子：像素生成类方案需要**渐变**（化学浓度 / 生长年龄 /
       距离边界的远近），不能只有「浪身 / 浪尖」两档。
       缺省仍是二值（crest ⇒ 白），与第一批变体逐格一致。 */
    var tint = null;
    var def = VARIANTS[this.variant];
    if (def && def.tint) tint = def.tint;
    for (var i = 0; i < n; i++) {
      var v = (this.buf[i] + (base ? base[i] : 0)) * gain;
      var o = i * 4;
      if (v <= 0.003) { d[o + 3] = 0; continue; }
      if (v > 1) v = 1;
      var w = tint ? tint(this, this.state, i, v) : (this.crest[i] ? 1 : 0);
      if (w < 0) w = 0; else if (w > 1) w = 1;
      /* 在浪身与浪尖之间插值 —— 只用同一条灰白轴，不引入新色相 */
      d[o]     = ACCENT[0] + (WHITE[0] - ACCENT[0]) * w;
      d[o + 1] = ACCENT[1] + (WHITE[1] - ACCENT[1]) * w;
      d[o + 2] = ACCENT[2] + (WHITE[2] - ACCENT[2]) * w;
      d[o + 3] = (v * 255) | 0;
    }
    this.lctx.putImageData(this.img, 0, 0);
    this.ctx.imageSmoothingEnabled = false;
    /* ⚠️ 必须先清屏再贴图 ——
     *   drawImage 是「叠加」不是「替换」：本帧为 0 的格子在目标画布上是透明的，
     *   底下的旧内容会原样透出来。
     *   原生像素场引擎每帧 fillRect 整屏（不透明底色）+ 画方块，
     *   所以从 pixelfield 切到别的变体时，它的**冻结帧**会一直挂在屏幕上 ——
     *   表现为「切过去了但画布上还有上一家的斜纹」。 */
    this.ctx.clearRect(0, 0, this.w, this.h);
    this.ctx.drawImage(this.low, 0, 0, this.w, this.h);
  };

  /* 指针反馈与悬停回声已迁到独立的 Feedback 层（见文件末尾）。
     原因：pixelfield 变体由原生引擎独占画布，写在变体缓冲里的反馈
     会被每帧覆盖 ⇒ 指针在默认变体下毫无反应。 */

  Field.prototype.step = function (now) {
    var dt = this.last ? Math.min(0.05, (now - this.last) / 1000) : 0.016;
    this.last = now;
    this.t += dt;
    var def = VARIANTS[this.variant];
    if (def && def.update) {
      if (this.rebuild && def.rebuild) def.rebuild(this, this.state);
      this.rebuild = false;
      def.update(this, this.state, dt);
    }
    this.paint();

    this.frames++;
    this.fpsT += dt;
    if (this.fpsT >= 0.5) { this.fps = Math.round(this.frames / this.fpsT); this.frames = 0; this.fpsT = 0; }
  };

  Field.prototype.start = function () {
    if (this.raf) return;
    if (this.variant === 'pixelfield') {
      /* 像素场的泵已经在 mountPixelField 里起好了，这里不要重复起 */
      return;
    }
    if (this.reduce) { this.renderOnce(); return; }
    var self = this;
    var loop = function (now) {
      self.step(now);
      self.raf = global.requestAnimationFrame(loop);
    };
    this.raf = global.requestAnimationFrame(loop);
  };

  Field.prototype.stop = function () {
    if (this.raf) { global.cancelAnimationFrame(this.raf); this.raf = 0; }
    if (this.pumpRaf) { global.cancelAnimationFrame(this.pumpRaf); this.pumpRaf = 0; }
    if (this.pixelApi) this.pixelApi.stop();
  };

  Field.prototype.destroy = function () {
    this.stop();
    if (this.pixelApi) { try { this.pixelApi.destroy(); } catch (e) { /* 忽略 */ } this.pixelApi = null; }
  };

  /* ══════════════════════════════════════════════════════════
     变体
     每个变体实现 init(f, st) 与 update(f, st, dt)。
     f.buf 是 0..1 的强度缓冲，f.crest 标记「浪尖」（用白色画）。
     ══════════════════════════════════════════════════════════ */

function makeLane(f, rng, spread) {
    return {
      x: rng.int(0, f.cols - 1),
      y: spread ? rng.range(-f.rows * 0.5, f.rows) : -rng.range(0, 12),
      v: rng.range(9, 26),            /* 行/秒 */
      len: rng.int(8, 30),           /* 尾长 */
      ph: rng.range(0, 6.283),
      wob: rng.range(0, 1.6),
    };
  }
function makeEdge(f, a, b) {
    var path = [];
    var dx = b.x - a.x, dy = b.y - a.y;
    var steps = Math.max(2, Math.ceil(Math.sqrt(dx * dx + dy * dy)));
    for (var i = 0; i <= steps; i++) {
      var x = clamp(Math.round(a.x + dx * i / steps), 0, f.cols - 1);
      var y = clamp(Math.round(a.y + dy * i / steps), 0, f.rows - 1);
      path.push(y * f.cols + x);
    }
    return { path: path };
  }
function newPulse(f, st) {
    return {
      edge: st.edges[f.rng.int(0, st.edges.length - 1)],
      t: 0, dir: 1, v: f.rng.range(0.5, 1.5),
    };
  }
function makeLogLine(f, rng) {
    var w = rng.int(24, Math.max(30, f.cols));
    var segs = [];
    var x = 0;
    while (x < w) {
      var len = rng.int(2, 9);
      segs.push({
        a: x, b: x + len,
        v: rng.range(0.16, 0.52),
        p: rng.range(0, 6.283),
      });
      x += len + rng.int(2, 8);
    }
    return {
      x: rng.range(-w, f.cols),
      y: rng.int(0, Math.max(1, f.rows - 1)),
      v: rng.range(6, 22),
      w: w, segs: segs,
    };
  }

  /* 代码行：一行「代码」由若干 token 段组成，段间留空。
     与 makeLogLine 的区别：日志行是**横着滚**的（带 x 偏移），
     代码行是**原地逐格写出来**的 —— 要的是「正在写」这件事。 */
  function makeCodeRow(f, rng) {
    var segs = [];
    var x = Math.round(rng.range(0, 4));      /* 缩进 */
    var w = f.cols - 2;
    while (x < w - 5) {
      /* 段要短、段间要空 ——
         早先段长 2~11、间隔 2~7，一行下来 90% 的格子都被填满，
         画面上是一坨灰色实心块，完全读不出「代码」。
         代码的观感来自**疏密节奏**：短的 token + 更长的空隙。 */
      var len = rng.int(2, 7);
      if (x + len > w - 1) break;
      segs.push({
        a: x, b: x + len,
        /* 代码段本身要够亮：终端是「有内容的区域」，
           太暗就只剩一条上沿亮线，看不出在写代码。 */
        v: rng.range(0.42, 0.92),
      });
      x += len + rng.int(2, 6);
    }
    return { segs: segs, total: x };
  }

  var VARIANTS = {

    /* ── 0. 像素场（复用原生引擎，见 mountPixelField）──────── */
    pixelfield: { label: '像素场', hint: '现状基线 · 光带扫过方块场' },

    /* ── 1. 数据流 BYTESTREAM ───────────────────────────────
       竖向字节流：每条流有自己的速度与长度，流头亮、尾巴暗。
       偶尔分叉出一条支流 —— 网关转发流量的既视感。 */
    bytestream: {
      label: '数据流', hint: '字节流下落 · 偶尔分叉',
      gain: 3.4,
      init: function (f, st) {
        st.lanes = [];
        st.target = Math.max(4, Math.round(f.cols * 0.09));
        st.nextBranch = 1.5;
      },
      rebuild: function (f, st) {
        st.lanes = [];
        st.target = Math.max(4, Math.round(f.cols * 0.09));
      },
      update: function (f, st, dt) {
        f.buf.fill(0); f.crest.fill(0);
        var rng = f.rng;
        if (!st.lanes.length) {
          for (var i = 0; i < st.target; i++) st.lanes.push(makeLane(f, rng, true));
        }
        st.nextBranch -= dt;
        if (st.nextBranch <= 0) {
          st.nextBranch = rng.range(1.2, 3.0);
          /* 分叉：从一条活着的流上长出一条支流 */
          if (st.lanes.length) {
            var src = st.lanes[rng.int(0, st.lanes.length - 1)];
            var child = makeLane(f, rng, false);
            child.x = clamp(src.x + (rng.next() < 0.5 ? -1 : 1), 0, f.cols - 1);
            child.y = src.y;
            st.lanes.push(child);
          }
        }
        for (var j = st.lanes.length - 1; j >= 0; j--) {
          var L = st.lanes[j];
          L.y += L.v * dt;
          if (L.y - L.len > f.rows + 2) { st.lanes.splice(j, 1); continue; }
          for (var k = 0; k < L.len; k++) {
            var row = (L.y - k) | 0;
            if (row < 0 || row >= f.rows) continue;
            /* 每一行有一点点横向抖动 ⇒ 不是死板的竖线 */
            var xx = (L.x + Math.sin(row * 0.21 + L.ph) * L.wob) | 0;
            if (xx < 0 || xx >= f.cols) continue;
            var idx = row * f.cols + xx;
            var a = Math.pow(1 - k / L.len, 1.7);
            if (a > f.buf[idx]) {
              f.buf[idx] = a;
              f.crest[idx] = k < 2 ? 1 : 0;
            }
          }
        }
      },
    },

    /* ── 2. 拓扑脉冲 TOPOLOGY ───────────────────────────────
       极淡的节点网格 + 节点之间跑的脉冲（带彗尾）。
       这是一张「活的网络拓扑」—— 正好是网关这个东西本身。 */
    topology: {
      label: '拓扑脉冲', hint: '节点网格 · 光脉冲沿边跑',
      gain: 3.0,
      rebuild: function (f, st) {
        st.nodes = [];
        st.edges = [];
        st.pulses = [];
        var step = 7;
        var colsN = Math.floor(f.cols / step);
        var rowsN = Math.floor(f.rows / step);
        for (var y = 0; y < rowsN; y++) {
          for (var x = 0; x < colsN; x++) {
            st.nodes.push({
              x: 2 + x * step + (f.rng.next() - 0.5) * 3,
              y: 2 + y * step + (f.rng.next() - 0.5) * 3,
            });
          }
        }
        /* 边 = 网格上的相邻节点；每条边预先算出沿途的格子索引 */
        for (var yy = 0; yy < rowsN; yy++) {
          for (var xx = 0; xx < colsN; xx++) {
            var id = yy * colsN + xx;
            if (xx + 1 < colsN) st.edges.push(makeEdge(f, st.nodes[id], st.nodes[id + 1]));
            if (yy + 1 < rowsN) st.edges.push(makeEdge(f, st.nodes[id], st.nodes[id + colsN]));
          }
        }
        /* 网格底纹：极淡，静态 */
        st.base = new Float32Array(f.cols * f.rows);
        for (var n = 0; n < st.nodes.length; n++) {
          var nd = st.nodes[n];
          var ix = clamp(nd.x | 0, 0, f.cols - 1);
          var iy = clamp(nd.y | 0, 0, f.rows - 1);
          st.base[iy * f.cols + ix] = 0.10;
        }
        for (var e = 0; e < st.edges.length; e++) {
          var path = st.edges[e].path;
          for (var q = 0; q < path.length; q++) st.base[path[q]] = 0.055;
        }
        st.pulses = [];
        for (var p = 0; p < 14; p++) st.pulses.push(newPulse(f, st));
        f.base = st.base;          /* 网格底纹走静态层，不参与衰减 */
      },
      update: function (f, st, dt) {
        var i, q;
        for (i = 0; i < f.buf.length; i++) {
          /* 只衰减动态部分（脉冲余辉）；底纹在 f.base 里，不碰 */
          f.buf[i] *= 0.93;
          f.crest[i] = 0;
        }
        for (i = 0; i < st.pulses.length; i++) {
          var P = st.pulses[i];
          P.t += P.v * dt;
          if (P.t >= 1) {
            /* 到节点了 ⇒ 换一条边接着跑（形成「网络」而不是「流星」） */
            var edge = st.edges[f.rng.int(0, st.edges.length - 1)];
            P.edge = edge; P.t = 0; P.dir = 1;
            P.v = f.rng.range(0.5, 1.4);
          }
          var path = P.edge.path;
          var pos = P.t * (path.length - 1);
          var a = pos | 0;
          var b = Math.min(path.length - 1, a + 1);
          var frac = pos - a;
          var idx0 = path[a];
          var idx1 = path[b];
          var v0 = f.buf[idx0] + 1;
          if (v0 > 1) v0 = 1;
          f.buf[idx0] = v0;
          f.crest[idx0] = 1;
          if (idx1 !== idx0) {
            var v1 = f.buf[idx1] + 0.55;
            if (v1 > f.buf[idx1]) f.buf[idx1] = v1 > 1 ? 1 : v1;
          }
          /* 彗尾：后面几格也带一点亮度 */
          for (q = 1; q <= 3; q++) {
            var pa = a - q;
            if (pa < 0) break;
            var tt = path[pa];
            var vv = f.buf[tt] + 0.34 - q * 0.09;
            if (vv > f.buf[tt]) { f.buf[tt] = vv > 1 ? 1 : vv; }
          }
        }
      },
    },

    /* ── 3. 日志流 LOGSTREAM ────────────────────────────────
       一行行「代码」从右向左滚，新行写入时头部亮一下。
       这是「代码生成」的实感 —— 终端在出内容。 */
    logstream: {
      label: '日志流', hint: '代码行右→左滚动 · 新行写入闪一下',
      gain: 3.6,
      rebuild: function (f, st) {
        st.lines = [];
        st.rowGap = 5;
        for (var y = 0; y < f.rows; y += st.rowGap) st.lines.push(makeLogLine(f, f.rng));
      },
      update: function (f, st, dt) {
        f.buf.fill(0); f.crest.fill(0);
        for (var i = 0; i < st.lines.length; i++) {
          var L = st.lines[i];
          L.x -= L.v * dt;
          if (L.x < -L.w - 4) {
            /* 滚出左边 ⇒ 从右边重新进来，内容也换掉 */
            var nl = makeLogLine(f, f.rng);
            nl.y = L.y; nl.v = L.v; nl.w = L.w;
            nl.x = f.cols + f.rng.range(0, 30);
            st.lines[i] = nl;
            L = nl;
          }
          /* 写入闪光：行首有个亮块往右走，像刚敲下去的一行 */
          var head = L.x;
          var hx = head | 0;
          if (hx >= 0 && hx < f.cols) {
            var hi = L.y * f.cols + hx;
            f.buf[hi] = 1; f.crest[hi] = 1;
            if (hx + 1 < f.cols) { f.buf[hi + 1] = 0.5; }
          }
          /* 行内容：一段段 token，中间留空 —— 看着像代码 */
          for (var t = 0; t < L.segs.length; t++) {
            var s = L.segs[t];
            var x0 = Math.round(s.a + L.x);
            var x1 = Math.round(s.b + L.x);
            for (var x = x0; x <= x1; x++) {
              if (x < 0 || x >= f.cols) continue;
              var idx = L.y * f.cols + x;
              var a2 = s.v * (0.72 + 0.28 * Math.sin(x * 0.7 + s.p));
              if (a2 > f.buf[idx]) { f.buf[idx] = a2; }
            }
          }
        }
      },
    },

    /* ── 4. 示波器 OSCILLOSCOPE ─────────────────────────────
       两条 1px 波形在仪表网格上扫，余辉拖尾。
       精确、量测、克制 —— 与前几��「生成感」相反的一极。 */
    oscilloscope: {
      label: '示波器', hint: '双波形扫描 · 仪表网格余辉',
      gain: 1.7,
      rebuild: function (f, st) {
        st.traces = [
          { base: 0.36, amp: 0.10, f1: 0.85, f2: 2.3, sp: 34, ph: 0 },
          { base: 0.68, amp: 0.07, f1: 1.35, f2: 3.1, sp: 41, ph: 1.7 },
        ];
        /* 网格：疏一点、暗一点。
         * ⚠️ 早先每 10 列 × 每 9 行都画一条 0.07 的线，密到整个屏幕像一张
         *    灰网，把波形压没了 —— 背景不能抢内容的戏。 */
        st.grid = new Float32Array(f.cols * f.rows);
        for (var x = 0; x < f.cols; x += 13) {
          for (var y = 0; y < f.rows; y++) st.grid[y * f.cols + x] = 0.05;
        }
        for (var y2 = 0; y2 < f.rows; y2 += 11) {
          for (var x2 = 0; x2 < f.cols; x2++) st.grid[y2 * f.cols + x2] = 0.05;
        }
        f.base = st.grid;          /* 仪表网格走静态层 */
      },
      update: function (f, st, dt) {
        var i, x, y;
        /* 磷光余辉：直接用 f.buf 当衰减缓冲。
         * ⚠️ 早先另开了一个 st.acc，衰减写 acc、显示读 acc*0.9，
         *    结果「显示」比「缓冲」晚一帧，且稳态会被累到接近饱和（实测亮格
         *    占比 12.76%，整屏发灰）。现在一帧一帧地衰减 + 重绘，所见即所得。 */
        for (i = 0; i < f.buf.length; i++) {
          f.buf[i] *= 0.86;
          f.crest[i] = 0;
        }
        for (var t = 0; t < st.traces.length; t++) {
          var T = st.traces[t];
          for (x = 0; x < f.cols; x++) {
            var u = (x + f.t * T.sp) * 0.06;
            var v = Math.sin(u * T.f1 + T.ph) * 0.6 +
                    Math.sin(u * T.f2 + T.ph * 1.7) * 0.3 +
                    Math.sin(u * 0.37 + T.ph) * 0.5;
            var yy = Math.round((T.base + v * T.amp) * f.rows);
            for (y = yy - 1; y <= yy + 1; y++) {
              if (y < 0 || y >= f.rows) continue;
              var idx = y * f.cols + x;
              /* 中心线亮（白），上下两侧只是余晖（暗）——
                 这样波形是「一条线」而不是「一条粗带」。 */
              var a = y === yy ? 0.95 : 0.17;
              if (a > f.buf[idx]) {
                f.buf[idx] = a;
                if (y === yy) f.crest[idx] = 1;
              }
            }
          }
        }
      },
    },

    /* ── 5. 雷达扫描 RADAR ──────────────────────────────────
       扫描线绕枢轴转，扫过的扇区亮起再衰减。
       安全控制台的监视感 —— 「有人在看这块屏」。

       ⚠️ 枢轴必须在**画面内**。
          早先放在 rows*1.25（画面下方外面），可见角只有 -2.8..-0.3 这一段，
          扫描线有 60% 的时间在屏幕外空转 ⇒ 画面看着「卡住不动」。
          现在枢轴在画面中下部，整圈 360° 都扫得到。 */
    radar: {
      label: '雷达扫描', hint: '全周扫描 · 距离环 · 目标闪现',
      gain: 2.2,
      rebuild: function (f, st) {
        st.px = f.cols * 0.5;
        st.py = f.rows * 0.68;            /* 枢轴在画面中下部 */
        st.head = 0;                      /* 扫描线当前角 */
        st.speed = 0.52;                 /* rad/s，一圈约 12 秒 */
        st.trail = 1.15;                  /* 拖尾角宽（弧度） */
        st.angTab = new Float32Array(f.cols * f.rows);
        st.distTab = new Float32Array(f.cols * f.rows);
        for (var y = 0; y < f.rows; y++) {
          for (var x = 0; x < f.cols; x++) {
            var dx = x - st.px, dy = y - st.py;
            st.angTab[y * f.cols + x] = Math.atan2(dy, dx);
            st.distTab[y * f.cols + x] = Math.sqrt(dx * dx + dy * dy);
          }
        }
        /* 距离环（静态底纹）：每 9 格一圈 */
        st.base = new Float32Array(f.cols * f.rows);
        for (var i = 0; i < st.distTab.length; i++) {
          var d = st.distTab[i] / 9;
          var fr = d - Math.floor(d);
          if (fr < 0.14) st.base[i] = 0.17;
        }
        /* 方位辐条（静态底纹）：每 45° 一条，让画面有「仪表」的方向感 */
        for (var a = 0; a < 8; a++) {
          var ang = a * Math.PI / 4;
          for (var j = 0; j < st.angTab.length; j++) {
            var dd = st.angTab[j] - ang;
            while (dd > Math.PI) dd -= Math.PI * 2;
            while (dd < -Math.PI) dd += Math.PI * 2;
            if (Math.abs(dd) < 0.035 && st.base[j] < 0.10) st.base[j] = 0.10;
          }
        }
        f.base = st.base;         /* 距离环走静态层 */

        /* 目标（blip）：扫描线扫过时闪一下。
           这是雷达最有说服力的细节 —— 说明「有东西在看」。 */
        st.blips = [];
        for (var b = 0; b < 4; b++) {
          var ba = f.rng.range(-Math.PI, Math.PI);
          var br = f.rng.range(0.18, 0.85) * f.rows;
          st.blips.push({
            x: st.px + Math.cos(ba) * br,
            y: st.py + Math.sin(ba) * br,
            ang: ba,
            flash: 0,
          });
        }
      },
      update: function (f, st, dt) {
        st.head += st.speed * dt;
        if (st.head > Math.PI * 2) st.head -= Math.PI * 2;
        var i;
        f.buf.fill(0); f.crest.fill(0);
        for (i = 0; i < f.buf.length; i++) {
          /* da = 从扫描线往回退的角度。0 = 正在被扫，trail = 拖尾尽头 */
          var da = st.head - st.angTab[i];
          if (da < 0) da += Math.PI * 2;
          if (da > st.trail) continue;
          var rel = 1 - da / st.trail;
          /* 近处弱、远处亮一点 —— 远处的目标更值得看。
             ⚠️ 下限不能太低：乘上 pow(rel,1.5) 的衰减后，
                弱端会落到几乎看不见，整条扫描线只剩一小截。 */
          var radial = 0.55 + 0.45 * Math.min(1, st.distTab[i] / (f.rows * 1.15));
          var a = Math.pow(rel, 1.3) * radial * 1.05;
          if (a > f.buf[i]) f.buf[i] = a > 1 ? 1 : a;
          /* 最前沿的一条线用白色 —— 扫描线本身要能一眼看见 */
          if (da < 0.055) f.crest[i] = 1;
        }
        /* 目标闪现 */
        for (var b = 0; b < st.blips.length; b++) {
          var B = st.blips[b];
          var db = st.head - B.ang;
          if (db < 0) db += Math.PI * 2;
          if (db < 0.09) B.flash = 1;
          B.flash *= 0.90;
          if (B.flash < 0.02) continue;
          var bx = Math.round(B.x), by = Math.round(B.y);
          /* 十字准星 + 中心点，像真的目标回波 */
          for (var k = -1; k <= 1; k++) {
            var idx1 = by * f.cols + (bx + k);
            var idx2 = (by + k) * f.cols + bx;
            if (bx + k >= 0 && bx + k < f.cols && by >= 0 && by < f.rows) {
              if (B.flash > f.buf[idx1]) { f.buf[idx1] = B.flash; f.crest[idx1] = 1; }
            }
            if (by + k >= 0 && by + k < f.rows && bx >= 0 && bx < f.cols) {
              if (B.flash > f.buf[idx2]) { f.buf[idx2] = B.flash; f.crest[idx2] = 1; }
            }
          }
        }
      },
    },

    /* ── 6. 代码生成 CODEGEN ────────────────────────────────
       屏幕中下部一条终端：一行行「代码」被**逐格写出来**，
       写头一个方块光标，写完的行往后退成暗的历史。
       这是「代码生成」最直接的实感 —— 不是滚动，是正在敲。

       ⚠️ 终端条不能贴着屏幕最底边。
          .pix-scrim 的 linear-gradient 在 100% 处是 rgba(10,10,11,.88)
          ⇒ 那里只放行 12% 亮度，终端条会整个沉进黑里。
          实测放在最底时 canvasMeanAlpha 只有 4.61（其余变体 12~26），
          画面上只剩一条上沿亮线。
          现在上移到 rows*0.62 附近 —— 那里 scrim 放行 ~50%，
          且刚好在卡片区下方，不抢内容。 */
    codegen: {
      label: '代码生成', hint: '终端逐字写入 · 方块光标 · 历史淡出',
      gain: 4.2,
      rebuild: function (f, st) {
        /* 终端条高度（含上沿 + 行距）。行距 2 ⇒ 一行代码占 2 格。 */
        st.h = Math.min(16, Math.max(9, Math.round(f.rows * 0.24)));
        /* 终端条顶部所在行：避开 scrim 最暗的上下两带，
           放在中下部（scrim 在 70% 处只压 50%）。 */
        st.top = Math.round(f.rows * 0.58);
        if (st.top + st.h > f.rows - 1) st.top = f.rows - st.h - 1;
        st.rows = [];              /* 已写完的历史行 */
        st.cur = null;             /* 当前正在写的行 */
        st.wait = 0;
        st.speed = 30;             /* 每秒写多少格 */
        st.rng = f.rng;
        /* 预填几行历史：终端一上来就该是「已经在跑」的样子，
           而不是空屏幕等第一行写完（前 3 秒画面是空的）。 */
        var seed = Math.max(2, Math.floor((st.h - 4) / 2));
        for (var s = 0; s < seed; s++) {
          var r0 = makeCodeRow(f, st.rng);
          r0.done = r0.total;
          r0.hold = 0;
          st.rows.push(r0);
        }
      },
      update: function (f, st, dt) {
        f.buf.fill(0); f.crest.fill(0);
        var rng = st.rng;

        if (!st.cur) {
          st.cur = makeCodeRow(f, rng);
          st.cur.done = 0;         /* 已写出的格数 */
          st.cur.hold = 0;
        }
        var C = st.cur;
        /* 逐格写入 */
        C.done = Math.min(C.total, C.done + st.speed * dt);
        /* 写完这一行后停一下（像人在想） */
        if (C.done >= C.total) {
          C.hold += dt;
          if (C.hold > 0.45) {
            st.rows.push(C);
            st.cur = null;
          }
        }
        /* 历史行只留最近的 h-3 行，更早的淡出 */
        var keep = Math.max(2, Math.floor((st.h - 4) / 2));
        while (st.rows.length > keep) st.rows.shift();

        /* 左侧提示符栏：每行开头一个「›」标记，当前行亮、历史行暗。
           这是终端最强的识别符号 —— 没有它，一堆横条看着像故障。
           ⚠️ 单格宽度（1 格 = 12px）在缩略图上几乎看不见，
           改成 **2 格宽的竖条**，才能在视觉上把「行」和「行」分开。
           提示符栏整体右移 2 格：贴着屏幕左缘会被裁掉半格，看不见。
           行距用 2 格（一行代码 + 一格空行）：挤在一起会连成灰带。 */
        var indent = 2;            /* 整条终端的左缩进 */
        var gutter = 2;            /* 提示符栏宽度 */
        var ROW_STEP = 2;

        /* 画历史行（越老越暗） */
        for (var r = 0; r < st.rows.length; r++) {
          var age = st.rows.length - r;
          var dim = Math.max(0.22, 0.80 - age * 0.11);
          var yy = st.top + 2 + r * ROW_STEP;
          if (yy < 0 || yy >= f.rows) continue;
          var gi = yy * f.cols + indent;
          f.buf[gi] = 0.75 * dim;
          f.buf[gi + 1] = 0.45 * dim;
          if (dim > 0.55) f.crest[gi] = 1;
          drawCodeRow(f, st.rows[r], yy, dim, 1, indent + gutter);
        }
        /* 画当前行 */
        var cy = st.top + 2 + st.rows.length * ROW_STEP;
        if (cy < f.rows) {
          var cgi = cy * f.cols + indent;
          f.buf[cgi] = 1; f.crest[cgi] = 1;
          f.buf[cgi + 1] = 0.7;
          drawCodeRow(f, C, cy, 1, 0, indent + gutter);
          /* 方块光标：写头处一个 1×1 的白块，随写头移动 */
          var hx = Math.round(C.done) + indent + gutter;
          if (hx < f.cols) {
            var idx = cy * f.cols + hx;
            f.buf[idx] = 1; f.crest[idx] = 1;
          }
        }
        /* 终端上沿：一条**断续**的细线 + 几个「窗口按钮」点。
           ⚠️ 不能画成整条实线 —— 满宽白杠太扎眼，
           而且和下面整行代码连成一片，看着像一条横线不像窗口边框。 */
        for (var x = indent; x < f.cols - indent; x++) {
          if (x % 3 === 0) {
            var t = st.top * f.cols + x;
            f.buf[t] = 0.30;
          }
        }
        for (var b = 0; b < 3; b++) {
          var bi = st.top * f.cols + indent + 2 + b * 4;
          f.buf[bi] = 0.75; f.crest[bi] = 1;
        }
      },
    },
  };

  /* ══════════════════════════════════════════════════════════
     第二批：像素生成方案
     ──────────────────────────────────────────────────────────
     第一批（数据流 / 拓扑 / 日志 / 示波器 / 雷达 / 代码生成）都是
     「有语义的界面元素」；第二批全是**生成艺术**路线 ——
     没有文字、没有仪表，只有像素自己长出来的形态。

     但**美术语言必须与像素场一致**，否则切过去像换了个网站：
       · 同一套低分辨率缓冲 + 整数放大（方块颗粒感）
       · 同一套银白月白两色 + 同一条压暗层
       · 同样是「稀疏成簇的亮块」，不是满屏实心
     所以这批的差别只在**生成算法**，不在观感基调。

     算法来源都是创意编程里的经典方案：
       反应扩散 Gray-Scott / 元胞自动机 / 随机游走 / 噪声流场 /
       Eden 生长 / 极坐标对称 / Voronoi 剖分
     ══════════════════════════════════════════════════════════ */

  /* 确定性 hash：同一个 (x,y) 永远给同一个 0..1。
     用 Math.imul 做 32 位乘法 —— 写成 x * 374761393 会被双精度
     截断成不同的值（同 seed 不再可复现），截图前后对比就废了。 */
  function hash2(x, y, s) {
    var h = Math.imul(x | 0, 374761393) ^ Math.imul(y | 0, 668265263) ^
            Math.imul(s | 0, 2246822519);
    h = Math.imul(h ^ (h >>> 13), 1274126177);
    return ((h ^ (h >>> 16)) >>> 0) / 4294967296;
  }

  /* 双线性插值的值噪声：比逐格 hash 连续，粒子走起来才成流。 */
  function vnoise(x, y, s) {
    var xi = Math.floor(x), yi = Math.floor(y);
    var xf = x - xi, yf = y - yi;
    var u = xf * xf * (3 - 2 * xf), v = yf * yf * (3 - 2 * yf);
    var a = hash2(xi, yi, s), b = hash2(xi + 1, yi, s);
    var c = hash2(xi, yi + 1, s), d = hash2(xi + 1, yi + 1, s);
    return (a * (1 - u) + b * u) * (1 - v) + (c * (1 - u) + d * u) * v;
  }

  /* 生长类方案共用的「痕迹场」：
     一张 float 图，新长出来的格子写 1，旧的按秒衰减。
     衰减率用「每秒剩余比例」的幂：dec = pow(k, dt)，
     这样不管帧率是 30 还是 60，淡出速度都一样。 */
  function fadeField(m, dt, keep) {
    var dec = Math.pow(keep, dt);
    for (var i = 0; i < m.length; i++) {
      m[i] *= dec;
      if (m[i] < 0.004) m[i] = 0;
    }
  }

  /* 晶核播种：init 与 rebuild 都要用，写成两遍以后改参数很容易只改一处。 */
  function seedCores(f, st) {
    var rng = f.rng;
    var k = 4;
    for (var s = 0; s < k; s++) {
      var cx = rng.int(2, f.cols - 3);
      var cy = rng.int(Math.floor(f.rows * 0.22), Math.floor(f.rows * 0.84));
      /* owner 存的是**晶核 id**，不是占领步数 ——
         存步数的话每个格子的 owner 都不同 ⇒ 每一格都算「缝」
         ⇒ 整片晶体全亮（实测 lit 68%）。 */
      var id = st.seedId++;
      st.owner[cy * f.cols + cx] = id;
      st.age[cy * f.cols + cx] = st.step;
      st.front.push({ x: cx, y: cy, id: id });
    }
  }

  /* 把角度折进「一个扇区的前半」—— 屏幕查找与触须写入
     **必须用同一条规则**，否则写进去的触须有一大半永远查不到。
     早先写入时直接取 round(a/2π*A)，读取时却做了镜像折叠，
     两边的角向索引对不上 ⇒ 触须只显示 1/4，曼陀罗只长了一半。 */
  function foldAngle(a, sector) {
    var m = a % sector;
    if (m < 0) m += sector;
    if (m > sector / 2) m = sector - m;
    return m;
  }

  var GEN_VARIANTS = {

    /* ── 7. 反应扩散 DIFFUSION ──────────────────────────────
       Gray-Scott：两种化学物质 A/B 互相喂给与消耗。
       A 均匀铺满，B 撒几个种子，然后每一代算一次「扩散 + 反应」：
         lap = 0.2 * (上下左右之和) - 自己
         A' = A + (1.0*lapA - A·B² + feed·(1-A))
         B' = B + (0.5*lapB + A·B² - (kill+feed)·B)
       feed/kill 一调，形态就在「斑点 / 迷宫 / 珊瑚 / 蠕虫」之间跳。
       这是生成艺术里最著名的「有机纹理」算法，
       出来的斑块边缘全是随机涨落 ⇒ 天然的「随机生成」观感。 */
    diffusion: {
      warm: 40,
      label: '反应扩散', hint: 'Gray-Scott 双化学物质 · 有机斑点',
      gain: 2.6,
      init: function (f, st) {
        st.u = new Float32Array(f.cols * f.rows);
        st.v = new Float32Array(f.cols * f.rows);
        st.u2 = new Float32Array(f.cols * f.rows);
        st.v2 = new Float32Array(f.cols * f.rows);
        st.u.fill(1);
        st.seeded = false;
      },
      rebuild: function (f, st) {
        st.u = new Float32Array(f.cols * f.rows);
        st.v = new Float32Array(f.cols * f.rows);
        st.u2 = new Float32Array(f.cols * f.rows);
        st.v2 = new Float32Array(f.cols * f.rows);
        st.u.fill(1);
        st.seeded = false;
      },
      update: function (f, st, dt) {
        var W = f.cols, H = f.rows, n = W * H;
        var u = st.u, v = st.v, u2 = st.u2, v2 = st.v2;
        var rng = f.rng;
        if (!st.seeded) {
          st.seeded = true;
          /* 种子撒在「看得见的高度带」里 ——
             .pix-scrim 的 linear-gradient 在 30% 处最亮（alpha .34），
             顶部 .90、底部 .88 都压得很死。
             种子撒到 15%~20% 那段，等于一开始就长在看不见的地方。 */
          for (var s = 0; s < 6; s++) {
            var cx = rng.int(3, W - 4);
            var cy = rng.int(Math.floor(H * 0.24), Math.floor(H * 0.82));
            for (var dy = -2; dy <= 2; dy++) {
              for (var dx = -2; dx <= 2; dx++) {
                var i = ((cy + dy + H) % H) * W + ((cx + dx + W) % W);
                v[i] = 0.9; u[i] = 0.4;
              }
            }
          }
        }
        /* 参数选「分裂」(mitosis)：斑块会自己一分为二、再分，
           所以形态一直在变，不会长成一大坨占满屏幕。
           珊瑚参数(0.0545/0.062)长出来的是连成片的大胞，
           亮度压不住 —— 背景抢内容的注意力。 */
        var FEED = 0.0545, KILL = 0.062;
        for (var k = 0; k < 2; k++) {
          for (var y = 0; y < H; y++) {
            var yc = y * W;
            var yUp = ((y - 1 + H) % H) * W, yDn = ((y + 1) % H) * W;
            for (var x = 0; x < W; x++) {
              var xl = (x - 1 + W) % W, xr = (x + 1) % W;
              var xul = (x - 1 + W) % W, xur = (x + 1) % W;
              var i = yc + x;
              var au = u[i], av = v[i];
              /* ⚠️ 必须是**九点守恒** Laplacian：
                   lap = 0.2*(上下左右) + 0.05*(四个角) - 自己
                   权重和 = 0.2*4 + 0.05*4 = 1.0，减去自身正好抵消 ⇒
                   常量场的 lap = 0，A/B 不会凭空流失。
                   早先写成五点 0.2*(上下左右) - 自己（权重和只有 0.8）⇒
                   常量场 lap = -0.2 ⇒ A 每步掉 0.2，几秒后整场 A=0 ⇒
                   A·B² 恒为 0 ⇒ B 全部死掉，画面全黑（实测 vMax=0）。
                   这就是「权重必须凑够 1」的坑。 */
              var lu = 0.2 * (u[yc + xl] + u[yc + xr] + u[yUp + x] + u[yDn + x]) +
                       0.05 * (u[yUp + xul] + u[yUp + xur] + u[yDn + xul] + u[yDn + xur]) - au;
              var lv = 0.2 * (v[yc + xl] + v[yc + xr] + v[yUp + x] + v[yDn + x]) +
                       0.05 * (v[yUp + xul] + v[yUp + xur] + v[yDn + xul] + v[yDn + xur]) - av;
              var uvv = au * av * av;
              var nu = au + (1.0 * lu - uvv + FEED * (1 - au));
              var nv = av + (0.5 * lv + uvv - (KILL + FEED) * av);
              u2[i] = nu < 0 ? 0 : (nu > 1 ? 1 : nu);
              v2[i] = nv < 0 ? 0 : (nv > 1 ? 1 : nv);
            }
          }
          u.set(u2); v.set(v2);
        }
        f.buf.fill(0); f.crest.fill(0);
        for (var i = 0; i < n; i++) {
          var b = v[i];
          /* ⚠️ 用**带通**而不是「大于阈值就亮」：
             实测 B 的分布是双峰的 —— 背景 0~0.045（41%）、
             细胞**内部** 0.27~0.40（29%）、**过渡带** 0.09~0.27（20%）。
             若按「b > 阈值」点亮 ⇒ 亮的是实心胞体 ⇒ 一大片灰团。
             改成「只点亮过渡带」⇒ 亮的正好是**细胞的轮廓线**，
             整片变成黑底 + 白色蕾丝网格（生成艺术里的经典形态）。 */
          var a = 1 - Math.abs(b - 0.18) / 0.07;
          if (a > 0) f.buf[i] = a;
        }
      },
      tint: function (f, st, i, val) { return Math.min(1, val * 1.3); }
    },

    /* ── 8. 随机生长 GROWTH ─────────────────────────────────
       用户点名要的那种：**沿随机方向生长**。
       几个「生长尖端」各自带一个朝向，每步随机转向、随机分叉、
       能量耗尽就死；长过的路径留在痕迹场里缓慢淡出。
       分叉角与转向角都是随机的 ⇒ 每次刷新出来的形态都不一样，
       但同一 seed 可复现（便于前后对比）。 */
    growth: {
      warm: 70,
      label: '随机生长', hint: '尖端沿随机方向生长 · 分叉与转向',
      gain: 3.2,
      init: function (f, st) {
        st.map = new Float32Array(f.cols * f.rows);
        st.tips = [];
        st.cool = 0;
        st.spin = 0;
      },
      rebuild: function (f, st) {
        st.map = new Float32Array(f.cols * f.rows);
        st.tips = [];
        st.cool = 0;
        st.spin = 0;
      },
      update: function (f, st, dt) {
        var W = f.cols, H = f.rows, rng = f.rng, m = st.map;
        /* 痕迹留存久一点：0.20/s 意味着 1 秒后只剩 20%，
           长出来的枝很快消失 ⇒ 画面上只剩「一小撮刚长出来的」，
           看不到生长的整体形态。 */
        fadeField(m, dt, 0.42);
        st.spin += dt * 0.06;
        st.cool -= dt;
        if (!st.tips.length && st.cool <= 0) {
          st.cool = 0.35;
          var seeds = 5 + (rng.next() < 0.5 ? 0 : 3);
          for (var s = 0; s < seeds; s++) {
            st.tips.push({
              x: rng.range(W * 0.10, W * 0.90),
              y: rng.range(H * 0.24, H * 0.80),
              a: rng.range(0, 6.283),
              life: rng.range(3.0, 7.0),
              sp: rng.range(9, 20),
              w: rng.next() < 0.3 ? 2 : 1,
            });
          }
        }
        var keep = [];
        for (var t = 0; t < st.tips.length; t++) {
          var p = st.tips[t];
          p.life -= dt;
          if (p.life <= 0) continue;
          /* 随机转向 —— 「随机方向」的来源 */
          p.a += (rng.next() - 0.5) * 1.7 * dt;
          /* 叠一个极慢的整体自转，让随机转向不至于立刻变成一团乱麻 */
          p.a += st.spin * dt * 0.5;
          var nx = p.x + Math.cos(p.a) * p.sp * dt;
          var ny = p.y + Math.sin(p.a) * p.sp * dt;
          var steps = Math.max(1, Math.ceil(Math.max(Math.abs(nx - p.x), Math.abs(ny - p.y))));
          for (var q = 0; q <= steps; q++) {
            var gx = Math.round(p.x + (nx - p.x) * q / steps);
            var gy = Math.round(p.y + (ny - p.y) * q / steps);
            for (var dy = 0; dy < p.w; dy++) {
              for (var dx = 0; dx < p.w; dx++) {
                var xx = gx + dx, yy = gy + dy;
                if (xx < 0 || xx >= W || yy < 0 || yy >= H) continue;
                var id = yy * W + xx;
                if (m[id] < 1) m[id] = 1;
              }
            }
          }
          p.x = nx; p.y = ny;
          if (nx < -3 || nx > W + 3 || ny < -3 || ny > H + 3) continue;
          keep.push(p);
          /* 分叉：一分为二，各自缩短寿命、稍微减速 */
          if (rng.next() < 0.028 && keep.length < 40) {
            var spread = rng.range(0.45, 1.15);
            keep.push({ x: p.x, y: p.y, a: p.a + spread,
                        life: p.life * rng.range(0.35, 0.62),
                        sp: p.sp * rng.range(0.7, 1.05), w: 1 });
            keep.push({ x: p.x, y: p.y, a: p.a - spread,
                        life: p.life * rng.range(0.35, 0.62),
                        sp: p.sp * rng.range(0.7, 1.05), w: 1 });
          }
        }
        st.tips = keep;
        f.buf.fill(0); f.crest.fill(0);
        for (var i = 0; i < m.length; i++) {
          if (m[i] > 0.002) {
            f.buf[i] = Math.min(1, m[i]);
            /* 刚长出来的（还接近满值）当浪尖画白，老的留灰 */
            if (m[i] > 0.985) f.crest[i] = 1;
          }
        }
      },
      tint: function (f, st, i, val) { return Math.min(1, val * 1.15); }
    },

    /* ── 9. 生命游戏 LIFE ───────────────────────────────────
       元胞自动机：下一代活 = (邻居 2 或 3)（自己是活的）
                            或 (邻居正好 3)（自己是死的）。
       规则 B3/S23。随机初盘会收敛成若干稳定块 + 滑翔机 + 闪烁子，
       画面上就是「稀疏的方块群在呼吸」。 */
    life: {
      warm: 30,
      label: '生命游戏', hint: '元胞自动机 · 生生不息',
      gain: 2.2,
      init: function (f, st) {
        st.g = new Uint8Array(f.cols * f.rows);
        st.ng = new Uint8Array(f.cols * f.rows);
        st.fade = new Float32Array(f.cols * f.rows);
        st.acc = 0;
        var rng = f.rng;
        for (var i = 0; i < st.g.length; i++) st.g[i] = rng.next() < 0.08 ? 1 : 0;
      },
      rebuild: function (f, st) {
        st.g = new Uint8Array(f.cols * f.rows);
        st.ng = new Uint8Array(f.cols * f.rows);
        st.fade = new Float32Array(f.cols * f.rows);
        st.acc = 0;
        var rng = f.rng;
        for (var i = 0; i < st.g.length; i++) st.g[i] = rng.next() < 0.08 ? 1 : 0;
      },
      update: function (f, st, dt) {
        var W = f.cols, H = f.rows, n = W * H, rng = f.rng;
        var g = st.g, ng = st.ng, fade = st.fade;
        st.acc += dt;
        /* 纯生命游戏会收敛成一片死寂的稳定块。
           定期撒几个随机活细胞 ⇒ 画面一直有新的东西冒出来，
           也更贴「随机生成」的主题。 */
        st.seedAcc = (st.seedAcc || 0) + dt;
        if (st.seedAcc > 0.6) {
          st.seedAcc = 0;
          for (var q = 0; q < 10; q++) {
            var sx = rng.int(0, W - 1), sy = rng.int(0, H - 1);
            g[sy * W + sx] = 1;
          }
        }
        while (st.acc > 0.10) {
          st.acc -= 0.10;
          for (var y = 0; y < H; y++) {
            var yc = y * W;
            var yUp = ((y - 1 + H) % H) * W, yDn = ((y + 1) % H) * W;
            for (var x = 0; x < W; x++) {
              var xl = (x - 1 + W) % W, xr = (x + 1) % W;
              var c = g[yc + xl] + g[yc + xr] + g[yUp + x] + g[yDn + x] +
                      g[yUp + xl] + g[yUp + xr] + g[yDn + xl] + g[yDn + xr];
              var i = yc + x;
              var alive = g[i] ? (c === 2 || c === 3) : (c === 3);
              ng[i] = alive ? 1 : 0;
              /* 刚死的格子留一点余晖，不然生灭是硬跳变 */
              if (!alive && g[i]) fade[i] = 0.42;
            }
          }
          g.set(ng);
        }
        fadeField(fade, dt, 0.10);
        f.buf.fill(0); f.crest.fill(0);
        for (var i = 0; i < n; i++) {
          /* 活格别给满亮度：0.9 × 增益会整片糊成白斑，
             背景抢内容的注意力。压到 0.5 让它退回「底噪」的位置。 */
          if (g[i]) { f.buf[i] = 0.34; f.crest[i] = 1; }
          else if (fade[i] > 0.01) f.buf[i] = fade[i] * 0.5;
        }
      }
    },

    /* ── 10. 游丝 WALK ───────────────────────────────────────
       十几个粒子各自随机游走，留下会淡出的轨迹。
       转向率比「随机生长」低很多 ⇒ 轨迹是长长的弧而不是折线，
       观感接近「电路板上的蚀刻线」。 */
    walk: {
      warm: 70,
      label: '游丝', hint: '粒子随机游走 · 留下蚀刻般的拖尾',
      gain: 3.0,
      init: function (f, st) {
        st.map = new Float32Array(f.cols * f.rows);
        st.ps = [];
      },
      rebuild: function (f, st) {
        st.map = new Float32Array(f.cols * f.rows);
        st.ps = [];
      },
      update: function (f, st, dt) {
        var W = f.cols, H = f.rows, rng = f.rng, m = st.map;
        fadeField(m, dt, 0.24);
        if (st.ps.length < 14 && rng.next() < 0.45) {
          st.ps.push({
            x: rng.range(0, W), y: rng.range(H * 0.18, H * 0.92),
            a: rng.range(0, 6.283), sp: rng.range(5, 15),
            life: rng.range(4, 11),
          });
        }
        var keep = [];
        for (var k = 0; k < st.ps.length; k++) {
          var p = st.ps[k];
          p.life -= dt;
          if (p.life <= 0) continue;
          p.a += (rng.next() - 0.5) * 1.9 * dt;
          p.x += Math.cos(p.a) * p.sp * dt;
          p.y += Math.sin(p.a) * p.sp * dt;
          if (p.x < 0 || p.x >= W || p.y < 0 || p.y >= H) continue;
          var id = (p.y | 0) * W + (p.x | 0);
          if (m[id] < 0.92) m[id] = 0.92;
          keep.push(p);
        }
        st.ps = keep;
        f.buf.fill(0); f.crest.fill(0);
        for (var i = 0; i < m.length; i++) if (m[i] > 0.002) f.buf[i] = Math.min(1, m[i]);
      },
      tint: function (f, st, i, val) { return Math.min(1, val * 1.1); }
    },

    /* ── 11. 流场 FLOW ───────────────────────────────────────
       噪声场给出每个位置一个流向，粒子顺着流漂。
       与「游丝」的区别：轨迹方向由**场**决定 ⇒ 粒子聚成漩涡与云，
       而不是各自乱窜。场随时间缓慢平移 ⇒ 形态一直在换。 */
    flow: {
      warm: 70,
      label: '流场', hint: '噪声流场 · 粒子随流漂成漩涡',
      gain: 3.0,
      init: function (f, st) {
        st.map = new Float32Array(f.cols * f.rows);
        st.ps = [];
        st.t = 0;
      },
      rebuild: function (f, st) {
        st.map = new Float32Array(f.cols * f.rows);
        st.ps = [];
        st.t = 0;
      },
      update: function (f, st, dt) {
        var W = f.cols, H = f.rows, rng = f.rng, m = st.map;
        fadeField(m, dt, 0.22);
        st.t += dt * 0.12;
        if (st.ps.length < 20 && rng.next() < 0.55) {
          st.ps.push({ x: rng.range(0, W), y: rng.range(H * 0.15, H * 0.92), life: rng.range(3, 9) });
        }
        var SC = 0.085, keep = [];
        for (var k = 0; k < st.ps.length; k++) {
          var p = st.ps[k];
          p.life -= dt;
          if (p.life <= 0) continue;
          var ang = vnoise(p.x * SC + st.t * 0.8, p.y * SC - st.t * 0.6, 1337) * 6.283185;
          p.x += Math.cos(ang) * 10 * dt;
          p.y += Math.sin(ang) * 10 * dt;
          if (p.x < 0 || p.x >= W || p.y < 0 || p.y >= H) continue;
          var id = (p.y | 0) * W + (p.x | 0);
          if (m[id] < 0.88) m[id] = 0.88;
          keep.push(p);
        }
        st.ps = keep;
        f.buf.fill(0); f.crest.fill(0);
        for (var i = 0; i < m.length; i++) if (m[i] > 0.002) f.buf[i] = Math.min(1, m[i]);
      },
      tint: function (f, st, i, val) { return Math.min(1, val * 1.1); }
    },

    /* ── 12. 结晶 CRYSTAL ────────────────────────────────────
       Eden 生长：几个晶核同时往外长，每步随机挑一个方向推进一格。
       谁先到某格，那格就归谁 ⇒ 形成**多边形晶域**，
       域与域之间的交界就是最早被抢到的那些格子（最亮）。
       这是「扩散受限聚集」家族的简化版，也是芯片/矿物照片里那种纹路。 */
    crystal: {
      warm: 70,
      label: '结晶', hint: '多晶核竞争生长 · 晶界分明',
      gain: 2.6,
      init: function (f, st) {
        st.owner = new Int32Array(f.cols * f.rows);
        st.owner.fill(-1);
        st.age = new Int32Array(f.cols * f.rows);
        st.front = [];
        st.step = 0;
        st.acc = 0;
        st.seedId = 0;
        seedCores(f, st);
      },
      rebuild: function (f, st) {
        st.owner = new Int32Array(f.cols * f.rows);
        st.owner.fill(-1);
        st.age = new Int32Array(f.cols * f.rows);
        st.front = [];
        st.step = 0;
        st.acc = 0;
        st.seedId = 0;
        seedCores(f, st);
      },
      update: function (f, st, dt) {
        var W = f.cols, H = f.rows, n = W * H, rng = f.rng;
        st.acc += dt;
        var DX = [1, -1, 0, 0], DY = [0, 0, 1, -1];
        while (st.acc > 0.07) {
          st.acc -= 0.07;
          st.step++;
          var nf = [];
          /* ⚠️ 每步只准长固定数量的格子。
             Eden 生长是**指数扩张**（前沿每步大约 ×1.5），
             不限量的话 4 个晶核 52 步就把 9000 格填满 90%
             （实测 lit 90.5%，整屏糊成一片）。
             限成每步 16 格 ⇒ 枝晶慢慢长，形态始终是「树枝」不是「色块」。 */
          var budget = 18;
          /* ⚠️ 必须让父细胞**留在前沿**，否则生长退化成
             「一条自己会把自己堵死的随机游走」：
             每个细胞只长一个新邻居 ⇒ 链条会绕回自己身边，
             四邻全被占 ⇒ 整条链死掉 ⇒ 重开一轮。
             实测那样只有 step=22、画面上几根小短桩。
             父细胞保留 ⇒ 同一处可以反复分叉 ⇒ 真正的树枝状晶体。 */
          for (var k = 0; k < st.front.length && budget > 0 && nf.length < 800; k++) {
            var c = st.front[k];
            var start = rng.int(0, 3);
            for (var d = 0; d < 4; d++) {
              var dd = (start + d) & 3;
              var nx = c.x + DX[dd], ny = c.y + DY[dd];
              if (nx < 0 || nx >= W || ny < 0 || ny >= H) continue;
              var id = ny * W + nx;
              if (st.owner[id] >= 0) continue;
              st.owner[id] = c.id;
              st.age[id] = st.step;
              nf.push({ x: nx, y: ny, id: c.id });
              nf.push(c);          /* 父细胞保留，下一轮还能继续分叉 */
              budget--;
              break;
            }
          }
          st.front = nf;
          /* 长满了就重开一轮 */
          if (!st.front.length) { seedCores(f, st); st.step = 0; st.owner.fill(-1); }
        }
        /* 上色：晶域本体压暗，只把**晶界**点亮。
           早先的写法是「越新越亮」⇒ 只有刚长出来的一圈亮，
           长了几十代的老晶体全暗下去 ⇒ 画面上只剩几根短桩。
           真正的结晶观感是「大片暗晶体 + 一条条亮缝」，
           所以这里反过来：本体给很低的底噪，接缝给满亮度。 */
        f.buf.fill(0); f.crest.fill(0);
        for (var y = 0; y < H; y++) {
          var yc = y * W;
          var yUp = ((y - 1 + H) % H) * W, yDn = ((y + 1) % H) * W;
          for (var x = 0; x < W; x++) {
            var i = yc + x;
            var o = st.owner[i];
            if (o < 0) continue;
            var xl = (x - 1 + W) % W, xr = (x + 1) % W;
            /* 晶界：邻居**已被别的晶核占领** ⇒ 两个晶体接上了。
               未占领的邻居不算缝 —— 那是生长前沿，不是晶界。 */
            var oL = st.owner[yc + xl], oR = st.owner[yc + xr];
            var oU = st.owner[yUp + x], oD = st.owner[yDn + x];
            var seam = (oL >= 0 && oL !== o) || (oR >= 0 && oR !== o) ||
                       (oU >= 0 && oU !== o) || (oD >= 0 && oD !== o);
            var age = st.step - st.age[i];
            if (seam) {
              f.buf[i] = 0.92; f.crest[i] = 1;
            } else if (age < 6) {
              /* 刚长出来的晶面：亮 ⇒ 看得见晶体在往外长 */
              f.buf[i] = 0.72; f.crest[i] = 1;
            } else {
              /* 晶域本体不能太暗（0.09 几乎看不见 ⇒ 整片像没长），
                 给到 0.30 才看得出枝晶的**形状**。 */
              f.buf[i] = 0.20;
            }
          }
        }
      },
      tint: function (f, st, i, val) { return Math.min(1, val * 1.25); }
    },

    /* ── 13. 万花筒 KALEIDO ──────────────────────────────────
       极坐标折叠：把画面按 N 个扇区镜像对称，
       再把「一个楔形」里的随机生长纹样映射回全屏。
       楔形里的触须从中心往外长、角度带随机抖动 ⇒
       出来的曼陀罗既严格对称又有随机细节。 */
    kaleido: {
      warm: 70,
      label: '万花筒', hint: '极坐标镜像 · 随机纹样长成曼陀罗',
      gain: 2.6,
      init: function (f, st) {
        st.R = 74; st.A = 20; st.N = 8;
        st.wedge = new Float32Array(st.R * st.A);
        st.tendrils = [];
        st.rot = 0;
        st.cool = 0;      /* 0 ⇒ 第一帧就长触须（预热期内必须出现东西） */
      },
      rebuild: function (f, st) {
        st.R = 74; st.A = 20; st.N = 8;
        st.wedge = new Float32Array(st.R * st.A);
        st.tendrils = [];
        st.rot = 0;
        st.cool = 0;
      },
      update: function (f, st, dt) {
        var W = f.cols, H = f.rows, rng = f.rng;
        st.rot += dt * 0.07;
        /* 楔形内容缓慢淡出，长途奔跑才会一直有变化 */
        /* 楔形是**镜像 8 次**才铺到全屏的 ——
           楔形里占 20% ⇒ 屏幕上就占 20%。
           所以楔形必须很空：早先 42 条触须 × 宽 5 格把楔形塞满，
           屏幕直接泛白（实测 lit 74%）。 */
        fadeField(st.wedge, dt, 0.30);
        st.cool -= dt;
        if (st.cool <= 0) {
          st.cool = 1.4;
          for (var s = 0; s < 1; s++) {
            st.tendrils.push({
              r: 0, a: rng.range(0, 6.283),
              /* 触须要能一路长到屏幕边缘（r 最大 74），
                 所以径向速度给到 7~16 格/秒 —— 早先 0.9~2.1
                 只能长到半径十几格，曼陀罗缩成屏幕中央一小团。 */
              v: rng.range(7, 16),
              life: rng.range(3, 6),
              jit: rng.range(0.04, 0.14),
            });
          }
        }
        var keep = [];
        for (var k = 0; k < st.tendrils.length; k++) {
          var p = st.tendrils[k];
          p.life -= dt;
          if (p.life <= 0) continue;
          p.a += (rng.next() - 0.5) * p.jit;
          p.r += p.v * dt;
          if (p.r > st.R - 1) continue;
          var ri = p.r | 0;
          var sector = 6.283185 / st.N;
          var aw = Math.round(foldAngle(p.a, sector) / sector * st.A) % st.A;
          if (aw < 0) aw += st.A;
          var ai = aw;
          /* 触须在楔形里只占**一个角向格**（不铺宽）。
             楔形宽 20 格覆盖 45°，一格 = 2.25°，
             映射到半径 50 的屏幕上约 2 格宽 —— 刚好是一条细射线。
             早先给角向 ±1、径向再占一格 ⇒ 一条触须就吃掉
             210/1480 个楔形格，5 条直接把楔形塞满
             ⇒ 镜像 8 次之后整屏泛白（实测 lit 74% / 38%）。 */
          var id = ri * st.A + ai;
          if (st.wedge[id] < 0.85) st.wedge[id] = 0.85;
          keep.push(p);
        }
        st.tendrils = keep;
        /* 楔形 → 全屏 */
        f.buf.fill(0); f.crest.fill(0);
        var cx = W / 2, cy = H / 2;
        var sector = 6.283185 / st.N;
        for (var y = 0; y < H; y++) {
          for (var x = 0; x < W; x++) {
            var dx = x - cx, dy = y - cy;
            var r = Math.sqrt(dx * dx + dy * dy);
            var ri = r | 0;
            if (ri >= st.R) continue;
            var a = Math.atan2(dy, dx) + st.rot;
            var m = foldAngle(a, sector);            /* 镜像 */
            var ai = Math.round(m / sector * st.A) % st.A;
            if (ai < 0) ai += st.A;
            var v = st.wedge[ri * st.A + ai];
            if (v > 0.004) {
              f.buf[y * W + x] = Math.min(1, v);
              if (v > 0.85) f.crest[y * W + x] = 1;
            }
          }
        }
      },
      tint: function (f, st, i, val) { return Math.min(1, val * 1.2); }
    },

    /* ── 14. 晶格 VORONOI ────────────────────────────────────
       十几个「站点」各自缓慢随机游走；
       每格找最近与次近站点，距离差很小的地方就是**边界**，
       只把边界点亮 ⇒ 画面是一张会呼吸的活网格。
       （整块 Voronoi 填色太满；只画边界才符合像素场的稀疏观感。） */
    voronoi: {
      warm: 12,
      label: '晶格', hint: '移动站点 · 只点亮剖分边界',
      gain: 2.6,
      init: function (f, st) {
        st.pts = [];
        st.seeded = false;
      },
      rebuild: function (f, st) {
        st.pts = [];
        st.seeded = false;
      },
      update: function (f, st, dt) {
        var W = f.cols, H = f.rows, n = W * H, rng = f.rng;
        if (!st.seeded) {
          st.seeded = true;
          var k = 11;
          for (var s = 0; s < k; s++) {
            st.pts.push({
              x: rng.range(0, W), y: rng.range(H * 0.15, H * 0.9),
              a: rng.range(0, 6.283), v: rng.range(2.5, 6),
            });
          }
        }
        for (var p = 0; p < st.pts.length; p++) {
          var q = st.pts[p];
          q.a += (rng.next() - 0.5) * 1.6 * dt;
          q.x += Math.cos(q.a) * q.v * dt;
          q.y += Math.sin(q.a) * q.v * dt;
          if (q.x < -4) q.x = W + 4; else if (q.x > W + 4) q.x = -4;
          if (q.y < -4) q.y = H + 4; else if (q.y > H + 4) q.y = -4;
        }
        f.buf.fill(0); f.crest.fill(0);
        var pts = st.pts, np = pts.length;
        for (var y = 0; y < H; y++) {
          for (var x = 0; x < W; x++) {
            var d1 = 1e9, d2 = 1e9;
            for (var i = 0; i < np; i++) {
              var dx = x - pts[i].x, dy = y - pts[i].y;
              var d = dx * dx + dy * dy;
              if (d < d1) { d2 = d1; d1 = d; }
              else if (d < d2) { d2 = d; }
            }
            /* 边界：到最近与次近站点的距离差小 */
            var edge = Math.sqrt(d2) - Math.sqrt(d1);
            if (edge < 1.6) {
              var v = 1 - edge / 1.6;
              var id = y * W + x;
              f.buf[id] = v * 0.9;
              if (v > 0.7) f.crest[id] = 1;
            }
          }
        }
      }
    },
  };

  /* 把第二批并进变体表。
     不用 Object.assign —— 这个文件通篇 ES5 风格（var + function），
     保持一致免得哪天在旧内核上炸。 */
  (function () {
    for (var k in GEN_VARIANTS) {
      if (Object.prototype.hasOwnProperty.call(GEN_VARIANTS, k)) VARIANTS[k] = GEN_VARIANTS[k];
    }
  })();

  /* 把一行「代码」画到画布上。
     limitFull = 1 → 整行都画（历史行）；0 → 只画已写出的部分（当前行）。
     dim = 亮度系数；gutter = 左侧提示符占的格数（内容从这里开始）。 */
  function drawCodeRow(f, row, y, dim, limitFull, gutter) {
    var segs = row.segs;
    var off = gutter || 0;
    for (var s = 0; s < segs.length; s++) {
      var S = segs[s];
      var stop = limitFull ? S.b : Math.min(S.b, row.done);
      for (var x = S.a; x < stop; x++) {
        var gx = x + off;
        if (gx < 0 || gx >= f.cols) continue;
        var idx = y * f.cols + gx;
        var v = S.v * dim;
        if (v > f.buf[idx]) f.buf[idx] = v;
      }
    }
  }

  /* ══════════════════════════════════════════════════════════
     对外接口
     ══════════════════════════════════════════════════════════ */
  function mount(canvas, variantKey, opts) {
    if (!canvas) return null;
    var f = new Field(canvas, variantKey, opts);
    f.start();
    return f;
  }

  /* ══════════════════════════════════════════════════════════
     反馈层：指针跟随 + 卡片悬停回声
     ══════════════════════════════════════════════════════════

     ⚠️ 为什么反馈必须画在**独立的画布**上，不能塞进变体缓冲：
        pixelfield 变体走的是原生引擎，它每帧 fillRect 整屏 + 重画方块，
        直接霸占了同一个 canvas 的全部像素。
        把指针光晕写进变体的 buf 里，等于写进一块每帧被覆盖的画布 ——
        结果就是「指针反馈在 pixelfield 下完全没反应」。
        独立画布则是所有变体共用的，不受变体实现影响。
  */
  function Feedback(canvas) {
    this.host = canvas;
    /* 反馈层画布：复用 .pixfield 的样式（fixed 全屏 + 不吃指针），
       插在 .pix-scrim 之后、.layer 之前 ⇒
         · 在压暗层之上 ⇒ 光效不被压暗，反馈看得见
         · 在内容层之下 ⇒ 卡片文字永远压得住背景
       ⚠️ 不能用 innerHTML / 内联 style —— 真机 CSP 是
          style-src 'self'，内联样式会被直接拦掉。 */
    this.canvas = document.createElement('canvas');
    this.canvas.className = 'pixfield';
    this.canvas.setAttribute('aria-hidden', 'true');
    this.ctx = this.canvas.getContext('2d');
    this.low = document.createElement('canvas');
    this.lctx = this.low.getContext('2d');
    this.img = null; this.data = null;
    this.buf = new Float32Array(0);
    this.crest = new Uint8Array(0);
    this.cols = 0; this.rows = 0; this.w = 0; this.h = 0; this.cell = TARGET_CELL;
    this.pointer = { x: -1, y: -1, on: false };
    this.pings = [];
    this.raf = 0;
    this.last = 0;
    this.t = 0;
    /* 反馈层自己也要提亮：它盖在 scrim 之上，不受压暗层打折，
       但仍要和变体的观感一致，所以用同一个量级的增益。 */
    this.gain = 2.4;
    this.reduce = !!(global.matchMedia &&
      global.matchMedia('(prefers-reduced-motion: reduce)').matches);
    this.insertAfterScrim(canvas);
  }

  /* 把反馈层画布插到「压暗层之后、内容层之前」。
     ⚠️ 找锚点必须**跳过文本节点**：
        HTML 源码里标签之间有换行和缩进，nextSibling 拿到的第一个
        常常是 Text 节点而不是元素 —— 只看 nextSibling 会插到错的位置，
        反馈层跑到 body 末尾（内容层之上），卡片文字会被光晕糊住。 */
  Feedback.prototype.insertAfterScrim = function (canvas) {
    var parent = canvas.parentNode;
    if (!parent) return;
    var node = canvas.nextSibling;
    var scrim = null;
    while (node) {
      if (node.nodeType === 1 &&
          String(node.className || '').indexOf('pix-scrim') >= 0) {
        scrim = node;
        break;
      }
      node = node.nextSibling;
    }
    if (scrim && scrim.parentNode === parent) {
      parent.insertBefore(this.canvas, scrim.nextSibling);
    } else {
      /* 找不到压暗层就退回到「紧跟主画布」——
         至少不会跑到内容层上面去。 */
      parent.insertBefore(this.canvas, canvas.nextSibling);
    }
  };

  Feedback.prototype.resize = function () {
    var rect = this.host.getBoundingClientRect();
    var w = Math.max(1, Math.floor(rect.width));
    var h = Math.max(1, Math.floor(rect.height));
    var dpr = Math.min(global.devicePixelRatio || 1, DPR_MAX);
    this.canvas.width = Math.floor(w * dpr);
    this.canvas.height = Math.floor(h * dpr);
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.ctx.imageSmoothingEnabled = false;
    this.w = w; this.h = h;
    var cols = Math.ceil(w / TARGET_CELL);
    var rows = Math.ceil(h / TARGET_CELL);
    if (cols !== this.cols || rows !== this.rows || !this.buf.length) {
      this.cols = cols; this.rows = rows;
      this.low.width = cols; this.low.height = rows;
      this.buf = new Float32Array(cols * rows);
      this.crest = new Uint8Array(cols * rows);
      this.img = this.lctx.createImageData(cols, rows);
      this.data = this.img.data;
    }
  };

  /* 指针附近加亮：背景要「对鼠标有反应」，否则再好看也是一张壁纸。 */
  Feedback.prototype.applyPointer = function () {
    var p = this.pointer;
    if (!p.on) return;
    var r = 7;
    var cx = p.x, cy = p.y;
    var x0 = Math.max(0, (cx - r) | 0), x1 = Math.min(this.cols - 1, (cx + r) | 0);
    var y0 = Math.max(0, (cy - r) | 0), y1 = Math.min(this.rows - 1, (cy + r) | 0);
    for (var y = y0; y <= y1; y++) {
      for (var x = x0; x <= x1; x++) {
        var dx = x - cx, dy = y - cy;
        var q = 1 - Math.sqrt(dx * dx + dy * dy) / r;
        if (q <= 0) continue;
        var idx = y * this.cols + x;
        var add = q * q * 0.30;
        if (this.buf[idx] + add < 1) this.buf[idx] += add;
      }
    }
  };

  /* 卡片悬停的「回声」：从悬停位置扩散的一圈亮环。
     这是给操作者的反馈 —— 悬停有回应，界面才是活的。 */
  Feedback.prototype.ping = function (gx, gy) {
    this.pings.push({ x: gx, y: gy, r: 0, max: 16, life: 0 });
    if (this.pings.length > 8) this.pings.shift();
  };

  Feedback.prototype.applyPings = function (dt) {
    var out = [];
    for (var i = 0; i < this.pings.length; i++) {
      var p = this.pings[i];
      p.r += 34 * dt;
      p.life += dt;
      if (p.r > p.max) continue;
      out.push(p);
      var x0 = Math.max(0, (p.x - p.r - 1) | 0), x1 = Math.min(this.cols - 1, (p.x + p.r + 1) | 0);
      var y0 = Math.max(0, (p.y - p.r - 1) | 0), y1 = Math.min(this.rows - 1, (p.y + p.r + 1) | 0);
      for (var y = y0; y <= y1; y++) {
        for (var x = x0; x <= x1; x++) {
          var dx = x - p.x, dy = y - p.y;
          var dist = Math.sqrt(dx * dx + dy * dy);
          var d = Math.abs(dist - p.r);
          if (d > 1.6) continue;
          var a = (1 - d / 1.6) * (1 - p.r / p.max) * 0.9;
          var idx = y * this.cols + x;
          if (a > this.buf[idx]) { this.buf[idx] = a; this.crest[idx] = 1; }
        }
      }
    }
    this.pings = out;
  };

  Feedback.prototype.paint = function () {
    var d = this.data, n = this.cols * this.rows;
    for (var i = 0; i < n; i++) {
      var v = this.buf[i] * this.gain;
      var o = i * 4;
      if (v <= 0.004) { d[o + 3] = 0; continue; }
      if (v > 1) v = 1;
      var c = this.crest[i] ? WHITE : ACCENT;
      d[o] = c[0]; d[o + 1] = c[1]; d[o + 2] = c[2];
      d[o + 3] = (v * 255) | 0;
    }
    this.lctx.putImageData(this.img, 0, 0);
    this.ctx.clearRect(0, 0, this.w, this.h);
    this.ctx.imageSmoothingEnabled = false;
    this.ctx.drawImage(this.low, 0, 0, this.w, this.h);
  };

  Feedback.prototype.step = function (now) {
    var dt = this.last ? Math.min(0.05, (now - this.last) / 1000) : 0.016;
    this.last = now;
    this.t += dt;
    this.buf.fill(0);
    this.crest.fill(0);
    this.applyPointer();
    this.applyPings(dt);
    this.paint();
  };

  Feedback.prototype.start = function () {
    if (this.raf) return;
    if (this.reduce) { this.paint(); return; }
    var self = this;
    var loop = function (now) {
      self.step(now);
      self.raf = global.requestAnimationFrame(loop);
    };
    this.raf = global.requestAnimationFrame(loop);
  };

  Feedback.prototype.stop = function () {
    if (this.raf) { global.cancelAnimationFrame(this.raf); this.raf = 0; }
  };

  global.GhostFX = {
    mount: mount,
    Field: Field,
    Feedback: Feedback,
    VARIANTS: VARIANTS,
    order: ['pixelfield', 'bytestream', 'topology', 'logstream', 'oscilloscope', 'radar', 'codegen',
            'diffusion', 'growth', 'life', 'walk', 'flow', 'crystal', 'kaleido', 'voronoi'],
    /* 指针位置 → 格坐标（供反馈层用） */
    setPointer: function (fb, gx, gy) {
      if (!fb) return;
      fb.pointer.x = gx; fb.pointer.y = gy; fb.pointer.on = true;
    },
    clearPointer: function (fb) { if (fb) fb.pointer.on = false; },
  };
})(typeof window !== 'undefined' ? window : this);
