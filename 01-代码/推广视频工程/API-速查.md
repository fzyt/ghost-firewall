# 页面 API 速查（Ghost Firewall 推广片）

> 每个页面是**独立单文件 HTML**，放在 `segments/` 下。
> 渲染时由 `render-segment.mjs` 起一个静态服务器打开它，逐帧调 `window.renderFrame(t)` 截图。
> **画面必须是 `t` 的纯函数** —— 同一 t 重绘两次，像素必须完全一致。

---

## 1. 文件骨架（照抄这个结构）

```html
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="/shared/fonts.css">
<title>段名</title>
<style>
  html, body { margin: 0; padding: 0; background: #0e0e0d; overflow: hidden; }
  #stage { position: relative; width: 1920px; height: 1080px; overflow: hidden; }
  canvas#c { position: absolute; inset: 0; width: 1920px; height: 1080px; }
</style>
</head>
<body>
<div id="stage"><canvas id="c" width="1920" height="1080"></canvas></div>

<script type="module">
import { createSegment, loadFonts, clamp, lerp, smoothstep, ease, TAU } from '../common.js';
import { themeFromURL, chrome } from '../themes.js';

const W = 1920, H = 1080;
const canvas = document.getElementById('c');
const ctx = canvas.getContext('2d');
const theme = themeFromURL(location.search);
const HUD = chrome(theme);
const seg = createSegment();          // 读 URL 的 seg/t0/speed/dur

window.DURATION = seg.duration;
window.__ready = false;
window.__bootError = null;

// ... 你的绘制代码 ...

window.renderFrame = (u) => { /* 用 u 画这一帧 */ };

(async () => {
  try {
    await loadFonts(['Noto Sans SC', 'JetBrains Mono', 'Inter']);
    window.__ready = true;
  } catch (e) {
    window.__bootError = String(e);
  }
})();
</script>
</body>
</html>
```

**必须导出这四样**（渲染器靠它们判断成功与否）：

| 名字 | 要求 |
|---|---|
| `window.renderFrame` | `(u) => void`，`u` 是**段内时间**（秒），0 ≤ u ≤ 段长 |
| `window.DURATION` | 本段总秒数（与 timeline 的 `duration` 一致） |
| `window.__ready` | 字体就绪后置 `true` |
| `window.__bootError` | 出错时置错误字符串 |

> 渲染器等 `window.__ready === true || window.__bootError`，两者都没设就**超时 120 秒**。

## 2. 硬约束（违反会渲染失败或画面不对）

| 禁止 | 原因 |
|---|---|
| `Math.random()` | 破坏纯函数 ⇒ 同一 t 两帧不一致 |
| `Date.now()` / `new Date()` | 同上 |
| `requestAnimationFrame` / `setTimeout` / `setInterval` | 画面变成「随时间漂移」，没法逐帧复现 |
| 底部字幕条 | 本项目规范：不加字幕 |
| 外部字体 CDN / 外部图片 | 字体必须本地（`/shared/fonts.css` 已声明 10 个 OFL 家族） |

**随机感**用固定种子：`mulberry32(seed)` / `hash01(n, seed)`（common.js 已导出）。
**噪声**用 `noise1 / noise2 / fbm1 / fbm2`（同样是固定种子的纯函数）。

## 3. 主题色板（`coral-noir`，与 Ghost Firewall 讲解页完全一致）

```
bg        #0e0e0d      surface   #1a1917      ink      #f5f0e8
muted     #8f8981      accent    #d97757      accentSoft #f0b49c
paper     #f4efe6      paperInk  #141311      bgDeep   #060605
accentInk #0e0e0d      flash     #ffffff
```

辅助强调色（来自主题 `accents`）：暖金 `#ffcf5c` / 冰蓝 `#58c4dd` / 紫罗兰 `#a58bff` / 霓虹粉 `#ff2bd6`。

字体：
- 正文 / 中文 → `"Noto Sans SC"`
- 代码 / 数字 / 标签 → `"JetBrains Mono"`
- 装饰性标题 → 可用 `"Orbitron"`（拉丁）、`"ZCOOL KuaiLe"`、`"ZCOOL QingKe HuangYou"`、`"Ma Shan Zheng"`（中文书法）、`"Long Cang"`（中文行书）、`"Playfair Display"`（衬线）

## 4. HUD 组件（common.js）

```js
drawCapsuleLabel(ctx, index, name, category = '', opts = {})
//   opts: x=96 y=72 h=58 padX=26 font numberColor textColor bg border
//   例：drawCapsuleLabel(ctx, 3, '端口敲门', '安全', {
//         numberColor: HUD.capsule.numberColor, textColor: HUD.capsule.textColor,
//         bg: HUD.capsule.bg, border: HUD.capsule.border });

drawStamp(ctx, text, opts = {})       // 右上角小字，opts: x=1824 y=72 size=20 align='right' color
drawFlash(ctx, alpha, W, H, color)    // 全屏白闪，alpha 0..1
applyImpact2D(ctx, fx, W, H)          // 入场冲击（缩放+抖动），fx 来自 seg.sample(u).fx
```

> ⚠️ **`drawCountdown` 不要用**：它的实现是 `00:0${Math.min(9, remain)}`，秒数封顶 9。
> 本片单段最长 28 秒，段内没问题；但如果你要显示整片时间码请自己写。

**胶囊安全区**：左上 `(96,72)-(约 400,130)` 是章节胶囊的位置，**主标题不要压它**。
右上 `(1824,72)` 是印章位（brand 小字）。

## 5. 时间与「拍」

`seg.sample(u)` → `{ u, t, fx }`：

- `u` = 段内时间（0..段长），**你直接用 u 推进动画**
- `t` = 场景时间（`t0 + u*speed`）；本片 `t0=0, speed=1`，所以 **t === u**
- `fx` = 入场冲击参数（flash / scale / shakeX / shakeY / push）

**本片每段 14–28 秒，节奏按 120 BPM 组织 ⇒ 每 0.5 秒一拍**：

```js
const beat = u / 0.5;                 // 第几拍
const p = clamp(u - beatStart, 0, 1); // 这一拍走了多少（0..1）
```

设计要求：
- **动作落在拍点上**（元素出现、位移、闪断都放在整拍边界）
- 每段分 **4–8 个动作节拍**，中间保持静止让观众读字
- 一个节拍内用 `ease.outCubic / outBack / outQuad` 推进，`smoothstep` 用于镜头类过渡
- 段末留 0.5–1 秒静帧再切

## 6. 必须自测的三个坑（上一批页面全踩过）

1. **NaN 传染**：`clamp` 不挡 NaN（`Math.min(b, Math.max(a, NaN))` === NaN）。
   任何除法/开方/取模的结果参与后续计算前，先 `Number.isFinite` 检查，
   或者用 `clamp(Number.isFinite(v) ? v : fallback, lo, hi)`。

2. **速率公式的方向**：如果常量叫 `CPS`（每秒几个），那么
   `已打字数 = 经过秒数 × CPS`，**不是除**。写反了不报错，结果恒为 0 或 NaN。

3. **文字宽度要实测**：`ctx.measureText(s).width`，不要按「字数 × 估计字宽」算。
   92px 等宽下「1830」宽 220px，固定间距会压字。

4. **DOM 覆盖层**：如果用 DOM（而非 canvas）做元素，
   - **不要**把初始 `opacity` 设成 0（JS 出错时元素就永远不可见，且看不出原因）
   - 多个元素必须**显式给 `top`/`left`**，不能指望默认定位

5. **同一 t 重绘两次像素必须一致** —— 自测时抓两次 canvas.toDataURL 比对。

## 7. 自测与验收

```bash
cd /home/kirito/main/项目/nftables-web-v2/01-代码/推广视频工程

# 静态体检：查「用了 common.js/themes.js 的导出但没 import」
node check-imports.mjs

# 渲三张静帧看构图（本机就有 playwright-core，不需要 ffmpeg）
node render-segment.mjs --page "/segments/s01-problem.html?theme=coral-noir" \
  --still 1.0,7.0,13.0 --outdir stills/s01
```

渲染器 URL 会自动带上 `?seg=1&t0=0&speed=1&dur=<段长>`，
`createSegment()` 会读它，所以页面里 `window.DURATION` 就是段长。

## 8. 每段的内容

**文案以 `timeline.json` 的 `copy` 字段为唯一真相源**，逐字照抄，不要自己改写或润色。
`s01-problem.html` 是已验收的样板段，照它的代码密度与排版层级写。
