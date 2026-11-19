// terminal.js — 终端风视觉语言的共享组件。
//
// 这一套替换旧的「粒子 + 流光 + 视差」：深底、单一终端窗口、等宽字、
// 命令逐字打出、输出整行刷出、光标闪烁。画面仍然是 t 的纯函数。
import { clamp } from './common.js';

export const TC = {
  bg: '#0e0e0d',
  panel: '#121211',
  head: 'rgba(245,240,232,0.05)',
  border: 'rgba(245,240,232,0.16)',
  borderSoft: 'rgba(245,240,232,0.09)',
  ink: '#f5f0e8',
  muted: '#8f8981',
  dim: '#5f5a54',
  accent: '#d97757',
};

// 终端窗口外壳：底 + 边框 + 标题栏
export function termWindow(ctx, o = {}) {
  const { x = 0, y = 0, w = 0, h = 0, title = '', right = '', font, alpha = 1, headH = 54 } = o;
  ctx.save();
  ctx.globalAlpha = alpha;
  ctx.fillStyle = TC.panel;
  ctx.fillRect(x, y, w, h);
  ctx.strokeStyle = TC.border;
  ctx.lineWidth = 1;
  ctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
  ctx.fillStyle = TC.head;
  ctx.fillRect(x + 1, y + 1, w - 2, headH);
  ctx.strokeStyle = TC.borderSoft;
  ctx.beginPath();
  ctx.moveTo(x + 1, y + headH + 0.5);
  ctx.lineTo(x + w - 1, y + headH + 0.5);
  ctx.stroke();
  // 标题栏左侧三个小圆点：终端窗口的通用记号
  ctx.fillStyle = 'rgba(245,240,232,0.18)';
  for (let i = 0; i < 3; i++) {
    ctx.beginPath();
    ctx.arc(x + 30 + i * 24, y + headH / 2, 6, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.font = `500 24px ${font}`;
  ctx.textBaseline = 'middle';
  ctx.textAlign = 'left';
  ctx.fillStyle = TC.dim;
  ctx.fillText(title, x + 118, y + headH / 2 + 1);
  ctx.textAlign = 'right';
  ctx.fillText(right, x + w - 28, y + headH / 2 + 1);
  ctx.restore();
}

// 逐字打出：返回已打出部分的宽度（光标要跟在后面）
export function typeText(ctx, text, x, y, o = {}) {
  const { p = 1, size = 26, weight = 400, color = TC.ink, font, alpha = 1 } = o;
  const chars = Array.from(text);
  const n = Math.round(clamp(p) * chars.length);
  const shown = chars.slice(0, n).join('');
  ctx.save();
  ctx.globalAlpha = alpha;
  ctx.font = `${weight} ${size}px ${font}`;
  ctx.textBaseline = 'alphabetic';
  ctx.textAlign = 'left';
  ctx.fillStyle = color;
  if (shown) ctx.fillText(shown, x, y);
  const w = shown ? ctx.measureText(shown).width : 0;
  ctx.restore();
  return w;
}

// 闪烁光标：方块，1.06 秒一个周期
export function drawCursor(ctx, x, y, u, o = {}) {
  const { size = 26, alpha = 1, on = true } = o;
  if (!on) return;
  if (Math.floor(u / 0.53) % 2) return;
  ctx.save();
  ctx.globalAlpha = alpha;
  ctx.fillStyle = TC.accent;
  ctx.fillRect(x, y - size * 0.76, size * 0.55, size * 0.88);
  ctx.restore();
}

// 段头：段号 + 章节 + 品牌
export function termHUD(ctx, o = {}) {
  const { index = 1, chapter = '', font, alpha = 1, x = 140, y = 78 } = o;
  const num = String(index).padStart(2, '0');
  ctx.save();
  ctx.globalAlpha = alpha;
  ctx.textBaseline = 'middle';
  ctx.textAlign = 'left';
  ctx.font = `600 26px ${font}`;
  ctx.fillStyle = TC.accent;
  ctx.fillText(num, x, y);
  const w = ctx.measureText(num).width;
  ctx.font = `400 26px ${font}`;
  ctx.fillStyle = TC.muted;
  ctx.fillText(chapter, x + w + 16, y);
  ctx.font = `500 22px ${font}`;
  ctx.textAlign = 'right';
  ctx.fillStyle = TC.dim;
  ctx.fillText('GHOST FIREWALL', 1780, y);
  ctx.restore();
}

// 底部进度条 + 时间码：终端风的段落进度指示
export function termProgress(ctx, o = {}) {
  const { u = 0, duration = 1, font, x = 140, y = 996, w = 1640 } = o;
  const p = clamp(duration > 0 ? u / duration : 0);
  ctx.save();
  ctx.fillStyle = 'rgba(245,240,232,0.07)';
  ctx.fillRect(x, y, w, 3);
  ctx.fillStyle = TC.accent;
  ctx.fillRect(x, y, w * p, 3);
  ctx.font = `400 22px ${font}`;
  ctx.textAlign = 'right';
  ctx.textBaseline = 'alphabetic';
  ctx.fillStyle = TC.dim;
  ctx.fillText(`${fmtTime(u)} / ${fmtTime(duration)}`, x + w, y - 14);
  ctx.restore();
}

function fmtTime(s) {
  const m = Math.floor(s / 60);
  const ss = Math.floor(s % 60);
  return `${String(m).padStart(2, '0')}:${String(ss).padStart(2, '0')}`;
}
