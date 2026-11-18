// motion.js — 共享动效基建：粒子背景、流光扫描、视差层次、逐字入场。
//
// 约束（与 common.js 相同）：画面必须是 t 的纯函数。
// 这里没有 Math.random / Date.now —— 粒子的初始位置用 hash01 按序号播种，
// 同一 t 永远得到同一帧。
import { clamp, ease, TAU, hash01 } from './common.js';

// ---------- 粒子背景 ----------
// 三层深度的光点，层与层速度不同 ⇒ 天然带视差。
// area 限定粒子的活动范围；越靠前的层越大越亮。
export function drawParticleField(ctx, opts = {}) {
  const {
    x = 0, y = 0, w = 1920, h = 1080, u = 0, count = 110, seed = 7,
    color = '217,119,87', baseAlpha = 0.5, drift = 26, size = 2.6, wrap = true,
  } = opts;
  if (count <= 0) return;
  ctx.save();
  for (let i = 0; i < count; i++) {
    const depth = hash01(i, seed);                 // 0 最远 1 最近
    const px = hash01(i, seed + 101);
    const py = hash01(i, seed + 211);
    const sp = 0.25 + depth * 1.15;                // 近的走得快
    const sx = ((px + u * sp * (0.4 + drift / 40)) % 1 + 1) % 1;
    const sy = ((py + u * sp * 0.18) % 1 + 1) % 1;
    const cxp = x + sx * w;
    const cyp = y + sy * h;
    const r = size * (0.45 + depth * 0.9);
    const a = baseAlpha * (0.12 + depth * 0.55);
    ctx.fillStyle = `rgba(${color},${a.toFixed(3)})`;
    ctx.beginPath();
    ctx.arc(cxp, cyp, r, 0, TAU);
    ctx.fill();
    // 近景粒子带一点光晕
    if (depth > 0.72) {
      ctx.fillStyle = `rgba(${color},${(a * 0.16).toFixed(3)})`;
      ctx.beginPath();
      ctx.arc(cxp, cyp, r * 3.4, 0, TAU);
      ctx.fill();
    }
  }
  ctx.restore();
}

// ---------- 流光扫描 ----------
// 一条斜着扫过矩形的光带：柔和的带 + 一道更亮的芯。
// 用于让静态卡片「活」起来 —— 每 5 秒扫过一次。
export function drawLightSweep(ctx, opts = {}) {
  const {
    x = 0, y = 0, w = 1920, h = 1080, u = 0, period = 5.5,
    color = '245,240,232', strength = 0.10, band = 0.32, angle = 0.22,
  } = opts;
  const cyc = (u % period) / period;
  const fade = Math.sin(Math.PI * cyc);            // 两端淡出，循环不突兀
  if (fade <= 0.01) return;
  const span = w + h * 1.6;
  const head = -span * 0.35 + cyc * span * 1.7;
  const bw = span * band;

  ctx.save();
  ctx.beginPath();
  ctx.rect(x, y, w, h);
  ctx.clip();
  ctx.translate(x, y);
  ctx.rotate(angle);
  const g = ctx.createLinearGradient(head - bw, 0, head + bw, 0);
  g.addColorStop(0, `rgba(${color},0)`);
  g.addColorStop(0.42, `rgba(${color},${(strength * 0.5 * fade).toFixed(3)})`);
  g.addColorStop(0.5, `rgba(${color},${(strength * fade).toFixed(3)})`);
  g.addColorStop(0.58, `rgba(${color},${(strength * 0.5 * fade).toFixed(3)})`);
  g.addColorStop(1, `rgba(${color},0)`);
  ctx.fillStyle = g;
  ctx.fillRect(-span, -h * 2, span * 3, h * 5);
  ctx.restore();
}

// ---------- 边缘流光 ----------
// 一道亮线沿卡片上沿来回跑，像光在边框上走。
export function drawEdgeSweep(ctx, opts = {}) {
  const {
    x = 0, y = 0, w = 200, u = 0, period = 4.2, color = '240,180,156',
    strength = 0.85, width = 2, r = 12,
  } = opts;
  const cyc = (u % period) / period;
  const fade = Math.sin(Math.PI * cyc);
  if (fade <= 0.01) return;
  const seg = w * 0.28;
  const head = -seg + cyc * (w + seg * 2);
  ctx.save();
  ctx.strokeStyle = `rgba(${color},${(strength * fade).toFixed(3)})`;
  ctx.lineWidth = width;
  ctx.lineCap = 'round';
  ctx.beginPath();
  ctx.moveTo(x + head, y);
  ctx.lineTo(x + head + seg, y);
  ctx.stroke();
  // 亮线端点的小光点
  ctx.fillStyle = `rgba(${color},${(strength * fade * 0.5).toFixed(3)})`;
  ctx.beginPath();
  ctx.arc(x + head + seg * 0.5, y, width * 2.2, 0, TAU);
  ctx.fill();
  ctx.restore();
}

// ---------- 视差 ----------
// 深度越大越靠近镜头，跟随镜头推进走得越多。
// 镜头推进本身很慢（120 秒推进 5%），所以这里再叠一点横向漂移让层次读得出来。
export function parallax(u, depth = 1, opts = {}) {
  const { amp = 16, drift = 6, scale = 0 } = opts;
  const push = (u / 60) * scale;                  // 随时间缓慢推近
  const sway = Math.sin(u * 0.32 + depth * 1.7) * drift * depth;
  return {
    dx: sway,
    dy: Math.cos(u * 0.24 + depth * 2.3) * amp * depth * 0.35,
    scale: 1 + push * depth * 0.01,
  };
}

// 在视差变换里画一段内容
// 注意：平移必须成对（先移到中心、画完再移回来），否则 scale==1 时内容会整体偏移
export function withParallax(ctx, u, depth, cx, cy, fn, opts = {}) {
  const p = parallax(u, depth, opts);
  ctx.save();
  ctx.translate(cx + p.dx, cy + p.dy);
  ctx.scale(p.scale, p.scale);
  ctx.translate(-cx, -cy);
  fn();
  ctx.restore();
}

// ---------- 逐字入场 ----------
// 把一句话拆成字，按拍点错开入场：每字先向上滑一点再落位。
// 文案本身不被改动 —— 拆分只发生在绘制时，源码里仍是完整字符串。
export function kineticText(ctx, str, x, y, opts = {}) {
  const {
    u = 0, t0 = 0, step = 0.045, dur = 0.5, size = 64, weight = 700,
    color = '#f5f0e8', family = '"Noto Sans SC", sans-serif', align = 'left',
    rise = 22, glow = null, alpha = 1,
  } = opts;
  const chars = Array.from(str);
  ctx.save();
  ctx.font = `${weight} ${size}px ${family}`;
  ctx.textAlign = 'left';
  ctx.textBaseline = 'alphabetic';
  const widths = chars.map((c) => ctx.measureText(c).width);
  const total = widths.reduce((a, b) => a + b, 0);
  let cx = align === 'center' ? x - total / 2 : align === 'right' ? x - total : x;

  for (let i = 0; i < chars.length; i++) {
    const p = clamp((u - (t0 + i * step)) / dur, 0, 1);
    if (p <= 0) { cx += widths[i]; continue; }
    const e = ease.outBack(p);
    ctx.save();
    ctx.globalAlpha = alpha * clamp(p * 2.2, 0, 1);
    ctx.translate(0, (1 - e) * rise);
    if (glow) {
      ctx.shadowColor = glow;
      ctx.shadowBlur = 18 * (1 - p * 0.4);
    }
    ctx.fillStyle = color;
    ctx.fillText(chars[i], cx, y);
    ctx.restore();
    cx += widths[i];
  }
  ctx.restore();
}

// ---------- 呼吸光点 ----------
// 一个持续明暗呼吸的点，用在「当前」「在线」这类状态上。
export function breathe(u, speed = 2.2, lo = 0.45, hi = 1) {
  return lo + (hi - lo) * (0.5 + 0.5 * Math.sin(u * speed));
}
