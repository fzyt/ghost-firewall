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
    /* ── 薄荷（借鉴 TRAE 首页，2026-11-03）────────────────────
       取值直接来自 TRAE 运行时截获的着色器 uniform 真值：
         uColor1 = rgb(50, 240, 140)  uColor2 = rgb(255, 255, 255)
         页面底色 = rgb(10, 11, 13)
       ⇒ 青绿↔白双色，点阵在深底上。 */
    mint:      { bg: [10, 11, 13],  accent: [50, 240, 140],  white: [255, 255, 255], bloom: [70, 200, 140] },
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
      note: '银白单色，波速 −16% ⇒ 波长更长、段落更缓。对比最高。登录页用这一档。',
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
    /* ── 月白·流（服务门户用，2026-11-03）────────────────────
     *
     * 用户原话：「现在的原版有固定方向流动的感觉，新版设计一下随机方向流动的试试」。
     * ⇒ 这一档的做法是：**原版 moonstone 一个字不改，只把「固定方向」换成
     *   「方向随机游走」**。别的什么都不动。
     *
     * 为什么基线是 moonstone 而不是 moonstone-swirl（踩过的坑）：
     *   改版前（6596764）门户用的就是 moonstone + dirSwing=0，
     *   那才是用户说的「原版」「固定方向流动」；
     *   moonstone-swirl 带着 dirSwing（正弦来回扫）+ 遮罩双层旋转 +
     *   整片自转，是改版过程中的产物，拿它当基线等于连换了三样东西。
     *
     * 与 moonstone 的**唯一**差别（其余参数逐条照抄）：
     *   ① waves[].dir 由绝对角变成**相对基准角的偏角**：
     *      原版 -0.30 / -0.25 / -0.35 ⇒ 基准 -0.30 + 偏角 0 / +0.05 / -0.05。
     *      三道波之间的夹角一字未改 ⇒ 光带的相对排布与原版完全一致。
     *   ② dirField=1：方向挂在**一张全屏共享**的方向场上（空间上统一）。
     *      必须共享：每波各一张方向场 ⇒ 遮罩采样帧跟着「每格胜出的波」
     *      跳变 ⇒ 亮块拉长效果互相抵消 ⇒ 画面退回一堆散点（2026-11-02 踩过）。
     *   ③ dirTurnPeriod + dirTurnRate：方向走「随机目标角 + 限速逼近」，
     *      每 8 秒抽一个**整圈均匀**的随机目标角 ⇒ 上下左右都会出现。
     *      不用噪声切片 / 三正弦叠加（都试过：前者角速度是原版的 3~12 倍，
     *      后者值域只有 ±0.45，要摆满 360° 得把角速度拉到原版的 8 倍 ⇒ 在甩）。
     *   ④ speedTurnPeriod + speedTurnRate + speedRange：速度随机起伏
     *      （0.45~1.55 倍），用**累计相位**兑现 ⇒ 变速时波前不跳变。
     *   ⑤ dirPivot=0：旋转中心留在原点 ⇒ 几何与原版逐位一致。
     *
     * ⚠ 密度、像素尺寸、遮罩、余晖全部照抄原版：
     *   pxBody/pxCrest 不传（= 2/3 原版小点）、pickBlock 不传（= 逐格随机）、
     *   patchDrift 0.011 / trail 0.80 / hyst 0.035 / distortAmp 0.85
     *   ⇒ 「一块一块各自生成」的成因一个都没被带进来。 */
    'moonstone-flow': {
      label: '月白·流',
      note: '原版几何，只把固定方向换成缓慢随机游走 ⇒ 仍是同一条浪在流，只是流的方向在变。',
      palette: 'moonstone',
      params: {
        waves: [
          /* ⚠ dirField>0 时 dir 是**相对共享方向的偏角**（不是绝对角）。
             偏角 0 / +0.05 / -0.05 ⇒ 与原版的 -0.30 / -0.25 / -0.35 完全等价。 */
          { k: 0.00580, om: 0.504, off: 0.00, dir:  0.00, w: 1.00 },
          { k: 0.00625, om: 0.563, off: 2.10, dir:  0.05, w: 0.90 },
          { k: 0.00545, om: 0.454, off: 4.20, dir: -0.05, w: 0.78 },
        ],
        distortAmp: 0.85,
        dirField: 1,
        dirFieldBase: -0.30,
        /* 方向换向周期（秒）：每 8 秒抽一个**整圈均匀**的随机目标方向。
           ⇒ 方向会走遍上下左右，不再挤在「偏下」那一小段。
           ⚠ 上一版（dirFieldRange + 噪声/正弦游走）实测 48 秒里方向角
             只在 +23.7° ~ -10.3° 之间晃，运动方向 cos d 恒为 0.90~0.98
             ⇒ **永远朝下、从不向上、从不横向** ⇒ 用户的投诉客观成立。 */
        dirTurnPeriod: 8,
        /* 转向角速度上限（rad/s）：0.16 ⇒ 每秒最多转 9.2°，
           一个 8 秒周期最多转 73° ⇒ 转向上下左右要 2~4 个周期，
           看得见「在拐」，又不是「甩」。
           原版 dirSwing 的角速度峰值是 0.053 rad/s ⇒ 这一档快约 3 倍。 */
        dirTurnRate: 0.16,
        /* 速度换挡周期（秒）：每 6 秒抽一个目标倍率。 */
        speedTurnPeriod: 6,
        /* 速度变化率上限（倍率/秒）：0.18 ⇒ 从 1.00 走到 0.45 要 3 秒
           ⇒ 是「慢慢提速降速」。改成 0 就是「瞬间换挡」。 */
        speedTurnRate: 0.18,
        /* 速度倍率幅度（±）：0.55 ⇒ 速度在 0.45 ~ 1.55 倍之间随机起伏
           （原版恒为 1.00 倍）。 */
        speedRange: 0.55,
        /* 旋转中心：0 = 原点（与原版逐位一致）、1 = 画布中心（四周流速均匀）。
           默认取 0 ⇒ 保持「只换方向与速度、几何一字不改」的承诺。 */
        dirPivot: 0,
        lit: 0.12,
      },
    },
    /* ── 像素流（借鉴 TRAE 首页，2026-11-03）──────────────────
     *
     * 这是**独立的一档**，moonstone / moonstone-flow 一字未动 ——
     * 用户要求「复制当前方案，单独做一份借鉴方案」。
     *
     * TRAE 首页那套是怎么做的（hook WebGL2 截获的着色器真值，
     * 不是看图猜的）：
     *   ① 连续噪声场（simplex + 3 层 FBM + domain warping）
     *      uDensity=0.5  uSpeed=0.18  uFrequency=4
     *   ② 像素化后处理：**硬阈值**切成规整点阵
     *      e1PixelSize=5  e1PixelGap=2  e1Threshold=0.87
     *   ③ 颜色按同一个场连续插值 uColor1=rgb(50,240,140) → 白
     *
     * 与本引擎原来做法的**核心差别**：
     *   原来 = 每格一个固定随机门槛（rSel）⇒ 点是**随机散点**
     *          ⇒ 看着像「一块一块各自生成」，不像「设计过的像素艺术」
     *   这一档 = 连续场 > 阈值 ⇒ 点是**规整网格**上的硬切结果
     *
     * 几何仍照抄原版 moonstone（三道波的 k/om/off/w 一字未改），
     * 方向与速度沿用 moonstone-flow 的随机换向 + 随机变速。
     * ⚠ 鼠标交互**不做**（用户明确不要）。 */
    'pixel-flow': {
      label: '像素流 Pixel',
      note: '借鉴 TRAE 首页：规整点阵（连续场硬阈值）+ 青绿↔白双色插值。',
      palette: 'mint',
      params: {
        waves: [
          /* ⚠ dirField>0 时 dir 是**相对共享方向的偏角**（不是绝对角），
             偏角 0 / +0.05 / -0.05 ⇒ 与原版的 -0.30 / -0.25 / -0.35 等价。 */
          { k: 0.00580, om: 0.504, off: 0.00, dir:  0.00, w: 1.00 },
          { k: 0.00625, om: 0.563, off: 2.10, dir:  0.05, w: 0.90 },
          { k: 0.00545, om: 0.454, off: 4.20, dir: -0.05, w: 0.78 },
        ],
        distortAmp: 0.85,
        /* ── 网格加密 ──────────────────────────────────────
           1440 / 190 ⇒ cell = 8px（默认 118 列 ⇒ 12px）。
           TRAE 的点阵周期是 5px 点 + 2px 间隙 = 7px，
           我们 8px 周期 + 2px 间隙 ⇒ 密度接近。 */
        columns: 190,
        /* 点占 cell 的 3/4（3 亚像素 / 4）= 75%，
           TRAE 是 5/7 = 71% ⇒ 接近。 */
        pxBody: 3,
        pxCrest: 3,
        /* 规整量化：去掉每格随机门槛 / 随机亮度因子 / 抖动。 */
        pixelQuant: 1,
        /* 阈值（0~1 表述，引擎内部换算到噪声域 -1..1）。
           TRAE 的 e1Threshold = 0.87，它作用在**亮度域**：
             brightness = 0.562 + 0.438 * noise  （noise ∈ [0,1]）
             ⇒ noise > (0.87 - 0.562) / 0.438 = 0.703
           换算到本引擎的 [-1,1] 域：0.703 ⇒ pixelThresh = (0.703+1)/2 = 0.70。
           实测本引擎的域分布与 TRAE 略有差异，最终取 0.76（实测密度对得上）。 */
        pixelThresh: 0.76,
        /* ── TRAE 像素化着色器的另两条 ──────────────────────────
           ① 阈值按块随机抖动：dynamicThreshold = e1Threshold - 0.08 * rand
              换算：TRAE 的 0.08 在亮度域（跨度 0.438）⇒ 本引擎 [-1,1] 域
              里的等价幅度 = 0.08 × (2 / 0.438) ≈ 0.365。
              ⚠ 这个值**不是可有可无的**：TRAE 的绿白是**同一个 rand** 定的，
                rand 小 ⇒ 阈值高 ⇒ 绿块更容易被淘汰 ⇒ 白块占绝对多数。
                实测：抖动 0.12 ⇒ 绿占 39%；抖动 0.36 ⇒ 绿占 19%（TRAE 是 17%）。
           ② 颜色按块随机二选一（绿 / 白），绿占 49%（TRAE e1GreenRatio=0.49）
           ⚠ **不是**按场值连续插值 —— TRAE 着色器里唯一的连续 mix
             出现在鼠标交互那两处，而用户明确说不要鼠标交互。 */
        pixelJitter: 0.36,
        pixelGreen: 0.49,
        /* ── TRAE 同款流场（域扭曲 FBM）─────────────────────
           域扭曲是 TRAE 那个观感的**真正来源**：
           不用它 ⇒ 亮点是轴对齐的方块簇（值噪声的晶格形状）；
           用了它 ⇒ 等值线被掰成有机曲线，跟 TRAE 一个路子。
           flowDensity = 0.25：屏幕宽 = 0.25 贴图单位
           flowWarp = 0.5：域扭曲强度（TRAE 名义值 4，换算到贴图单位是 1.0，
                            这里取一半，等值线不至于扭成一团）
           flowSpeed = 0.02：漂移速度（贴图单位/秒） */
        flowDensity: 0.25,
        flowWarp: 0.50,
        flowSpeed: 0.020,
        /* ── 亮度切点：硬边模式下调的是「亮/不亮」的分界 ──────────
           量化模式下 alpha 是**两态**的（满亮 / 全黑），没有斜坡 ⇒
           accentT 不再管「亮度」，只管「从哪儿开始算亮」。
           tLo1 = accentT - fade/2，取 0.08 ⇒ 切点落在原斜坡刚到满亮处
           ⇒ **亮区大小基本不变**，只是边界从渐变变成硬边。
           ⚠ 别把它调大：accentT 越大 ⇒ 切点越高 ⇒ 亮区越小。 */
        accentT: 0.08,
        /* 连续双色插值（单层绘制，颜色与点的存在同源）。
           保留成开关：想看「按场值连续渐变」时把它开成 1。 */
        pixelBlend: 0,
        /* ── 随机换向 + 随机变速（沿用 moonstone-flow）───────── */
        dirField: 1,
        dirFieldBase: -0.30,
        dirTurnPeriod: 8,
        dirTurnRate: 0.16,
        speedTurnPeriod: 6,
        speedTurnRate: 0.18,
        speedRange: 0.55,
        dirPivot: 0,
        lit: 0.12,
      },
    },
    /* ── 月白·乱晶（服务门户专用，2026-11-02）──────────────────
     *
     * 为什么不直接改 moonstone 那一档：
     *   登录页（login.js）和门户页共用同一个引擎、同一个 style 名。
     *   改 moonstone = 顺手把登录页的背景也改了 —— 那是**另一个页面**，
     *   改版范围不该从「服务门户」溢出到「登录页」。
     *   ⇒ 新开一档，moonstone 一字不动（登录页视觉零变化），
     *     门户改用这一档。
     *
     * 这一档改了三件事：
     *   ① 波速 ×1.9（om 0.504 → 0.958）：原来一轮 12 秒、整屏几乎看不出
     *      在动；现在一轮 ~6.5 秒，光带明显在走。
     *   ② 方块晶向杂乱：两层遮罩各转一个角度 + 整片遮罩缓慢自转。
     *      原来两层遮罩比例固定 ⇒ 全屏方块是同一个晶向，看着像一片
     *      梳过的斜纹，不像「长出来」的。
     *   ③ 生成快慢：遮罩漂移 0.011 → 0.030（方块重新长成快约 2.7 倍），
     *      余晖 0.80 → 0.72。画面动快了，alpha 下降的限速也得跟上
     *      （hyst 0.05），否则卡在阈值上的格子降不下来 ⇒ 一片糊。
     */
    'moonstone-swirl': {
      label: '月白·乱晶',
      note: '银白单色。波速 ×1.9，光带明显在走；方块晶向杂乱（遮罩双层旋转 + 整片缓慢自转）。',
      palette: 'moonstone',
      params: {
        waves: [
          { k: 0.00580, om: 0.958, off: 0.00, dir: -0.30, w: 1.00 },
          { k: 0.00625, om: 1.070, off: 2.10, dir: -0.25, w: 0.90 },
          { k: 0.00545, om: 0.863, off: 4.20, dir: -0.35, w: 0.78 },
        ],
        distortAmp: 0.85,
        /* 两层遮罩各自的旋转角（弧度）：0.22 ≈ 13°，0.88 ≈ 50°。
           交叠出来的方块才有杂乱的晶向。 */
        patchRot1: 0.22,
        patchRot2: 0.88,
        /* 整片遮罩缓慢自转（rad/s）：0.020 ⇒ 一圈约 5 分钟。
           慢到几乎察觉不到，但看久了会觉得「背景在活」。 */
        patchSpin: 0.020,
        /* 波向摆动：光带斜度来回扫，而不是钉死一个角度。 */
        dirSwing: 0.13,
        dirSwingFreq: 0.065,
        patchDrift: 0.030,
        trail: 0.72,
        hyst: 0.05,
        lit: 0.15,
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
    /* ── 分片遮罩的**方向**（2026-11-01 门户背景优化）────────
       原来两层遮罩的采样比例是固定常量（x 1.15 / 0.77，y 1.05 / 1.05），
       于是整屏方块是**同一个晶向**的拉长纹理 —— 看着像一片梳过的斜纹，
       方块不是「长出来」的，是同一把梳子梳出来的。
       现在给两层各一个独立的旋转角（patchRot1 / patchRot2），
       再让整片遮罩随时间缓慢自转（patchSpin）：
       方块的晶向既有空间上的差异，也有时间上的缓慢变化。
       这几个值默认全是 0 ⇒ 不传时行为与原来逐位一致。 */
    patchRot1: 0.0,
    patchRot2: 0.0,
    patchSpin: 0.0,        /* rad/s，整片遮罩的自转角速度 */
    /* ── 波向摆动 ──────────────────────────────────────────
       几道光带的法线角随时间缓慢摆动 ⇒ 光带的斜度来回扫，
       而不是永远钉在同一个角度上。摆动只跟时间有关，
       所以在「每步」里算一次就够，不必每格算。 */
    dirSwing: 0.0,        /* 摆幅（弧度） */
    /* 摆动频率（Hz）。⚠️ 默认必须是 0.0：
       这一组新增参数的默认值**全是 0**，是「不传时与改版前逐位一致」的保证。
       摆幅为 0 时频率取多少都不影响结果（0 × sin(...) 恒为 0），
       但默认值非 0 会让那句话不成立，也会让人以为「不传也会摆」。
       需要摆动的档（moonstone-swirl）自己显式写 0.065。 */
    dirSwingFreq: 0.0,
    /* ── 随机方向波浪（2026-11-02）────────────────────────
     * 原来三道波的 dir 是**全局常量**（-0.30 / -0.25 / -0.35），
     * 三个值非常接近 ⇒ 几道波前几乎平行 ⇒ 亮块只能沿同一批方向
     * 排成规则珠串，看着像「一块一块各自生成」。
     *
     * 现在让**每道波各有一张方向场**：方向随位置变化、随时间漂移。
     *   · 同一道波在不同位置方向不同 ⇒ 波浪是湍流状，没有统一走向
     *   · 几道波用各自的噪声偏移 ⇒ 互不平行
     * 这两项合起来才是用户要的「随机方向波浪」。
     *
     * dirField 三档：
     *   0 = 关闭（默认）→ 走原路径，行为与改版前**逐位一致**
     *   1 = 方向只随时间变（空间上统一）⇒ 整片波浪换个朝向
     *   2 = 方向随位置变 + 随时间漂移 ⇒ 湍流状，无统一走向
     *
     * ⚠️ 新参数的默认值**全是 0**，是「不传时与改版前逐位一致」的保证。 */
    dirField: 0,           /* 0=关闭 1=仅时间随机 2=空间局部方向场 */
    dirFieldBase: 0.0,     /* 方向场的基准角（rad）；dirField>0 时 waves[].dir 变成偏角 */
    dirFieldScale: 0.0,    /* 方向场空间频率（噪声坐标 / px） */
    dirFieldRange: 0.0,    /* 方向偏离基准角的幅度（rad） */
    dirFieldDrift: 0.0,    /* 方向场自身的时间漂移（噪声坐标 / 秒） */
    dirFieldStep: 24,      /* 方向场粗网格步长（px） */
    dirWalkFreq: 0.0,      /* dirField=1 时的时间随机游走频率（Hz） */
    /* ── 随机换向（2026-11-03）────────────────────────────────
     * 用户原话：「没有上下或者更多其他方向的随机流动了」。
     *
     * 为什么不用「噪声切片」或「三正弦叠加」来随机化方向（都试过，否决）：
     *   · 噪声切片：角速度是原版的 3~12 倍 ⇒ 那是在抖不是在流；
     *   · 三正弦叠加：合成信号的实际值域只有 ±0.45，
     *     要摆满 360° 就得把角速度拉到 0.4 rad/s（原版的 8 倍）⇒ 在甩不是流。
     * 而且两者的方向区间都挤在「偏下」那一小段：
     *   实测 48 秒里方向角只在 +23.7° ~ -10.3° 之间晃，
     *   运动方向 cos d 恒为 0.90~0.98 ⇒ **永远朝下，从不向上、从不横向**。
     *
     * 现在改成「**随机目标角 + 限速逼近**」：
     *   ① 每 dirTurnPeriod 秒抽一个**整圈均匀**的随机目标角；
     *   ② 当前角以不超过 dirTurnRate 的角速度朝它靠（取短弧，
     *      免得为了 350° 绕远路）；
     *   ③ 换向速度与换向周期**分开可调** ⇒「突然拐一下」（dirTurnRate=0）
     *      和「慢慢飘过去」（dirTurnRate>0）都是参数的事。
     *
     * ⚠ dirTurnPeriod = 0（默认）⇒ 走老路（噪声切片），
     *   不传时行为与改版前逐位一致。 */
    dirTurnPeriod: 0,      /* 方向换向周期（秒）；0 = 关闭 */
    dirTurnRate: 0.0,      /* 转向角速度上限（rad/s）；0 = 不限速（一步到位） */
    /* ── 随机变速（2026-11-03）────────────────────────────────
     * 用户原话：「速度快慢也可以加入随机，目前看好像是始终一个速度的，
     * 也就是流动可能突然提速降速，也可能慢慢提速降速」。
     *
     * 每 speedTurnPeriod 秒抽一个目标倍率（1 ± speedRange），
     * 当前倍率以不超过 speedTurnRate 的速率靠拢，
     * 再用它推进**每道波的累计相位**（见 computeGeometry 里的 wPh）。
     *
     * ⚠ 为什么必须用累计相位：原来的相位是闭式的 om*t，
     *   速度一变，波前位置会**跳变**（画面会「闪一下」）。
     *   改成 wPh += om·倍率·dt 之后，速度变化是连续的，
     *   即使 speedTurnRate=0（瞬间换挡）波前也不会跳。
     *
     * ⚠ 默认 0 ⇒ 不传时仍走 om*t，与改版前逐位一致。 */
    speedTurnPeriod: 0,    /* 速度换挡周期（秒）；0 = 关闭 */
    speedTurnRate: 0.0,    /* 速度变化率上限（倍率/秒）；0 = 不限速（瞬间换挡） */
    speedRange: 0.0,       /* 速度倍率幅度（±）；0.5 ⇒ 速度在 0.5~1.5 倍之间 */
    /* ── 方向场的旋转中心（2026-11-03）───────────────────────
     * 波前的法线坐标 uy = px·sin(d) + py·cos(d) ⇒ 亮带是**一组过原点
     * 的平行线**（原版 dir 固定时就是这样）。方向 d 一旦随时间变，
     * 这组线就绕原点转 ⇒ 离原点越远转得越快、离原点越近越慢
     * ⇒ 左上角几乎不动、右下角飞快扫 ⇒ 整屏「流速」严重不均匀。
     *
     * dirPivot = 1 时把旋转中心挪到画布中心 ⇒ 四周等距、转速均匀，
     * 看起来像「整片洋流在拐弯」，而不是「一角在甩」。
     *
     * ⚠ 默认 0（原点）⇒ 不传时行为与改版前逐位一致。 */
    dirPivot: 0,
    /* ── 遮罩跟随波向（2026-11-02）────────────────────────
     * 原来分片遮罩是**屏幕空间**的各向异性噪声：晶向由全局常量
     * patchRot1/patchRot2 决定 ⇒ 所有地方的方块是同一个朝向，
     * 与波前无关。波被遮罩切碎之后，屏幕上就只剩一堆散点 ——
     * 这正是「像一块一块各自生成」的另一半原因。
     *
     * patchFollow = 1 时，遮罩的采样坐标**转进波帧**：
     *   切向（沿波前）低频 ⇒ 噪声沿波前拉长
     *   法向（垂直波前）高频 ⇒ 横向收紧
     * ⇒ 亮块沿波前拉成**长条**，整条光带就是一条流动的像素流。
     * 配合 dirField（方向随位置变）⇒ 不同区域的像素流朝向不同。
     *
     * ⚠️ 默认 0（关闭）⇒ 走原路径，逐位一致。 */
    patchFollow: 0,       /* 0=关闭 1=遮罩晶向跟随局部波向 */
    patchTangent: 1.0,    /* 切向频率系数（<1 ⇒ 沿波前拉长） */
    patchNormal: 1.0,     /* 法向频率系数 */
    patchTangent2: 1.0,   /* 第二层遮罩的切向系数 */
    patchNormal2: 1.0,    /* 第二层遮罩的法向系数 */
    /* ── 像素块尺寸（2026-11-02）──────────────────────────
     * 原来每格只画 2×2（浪身）/ 3×3（浪尖）个亚像素，
     * 而一格是 12px（SS=4 × 3px）⇒ 实际亮点只有 2~3px，
     * 满屏看着像**噪点**而不是像素块。
     * pxBody / pxCrest = 0 时保持原尺寸（2 / 3），
     * 不传时逐位一致；填 3 则画 9×9 的方块（留 1.5px 间隙 ⇒ 有像素网格感）。 */
    pxBody: 0,            /* 浪身方块边长（亚像素；0 = 原版 2） */
    pxCrest: 0,           /* 浪尖方块边长（亚像素；0 = 原版 3） */
    /* ── 块状选取（2026-11-02）────────────────────────────
     * pickBlock = 0（默认）⇒ 每格一个独立随机门槛（原版行为，
     * 逐位一致，不传时什么都不变）。
     * pickBlock = N > 0 ⇒ 每 N×N 格共用一个门槛 ⇒ 同一块里的格子
     * 亮灭一致 ⇒ 亮区是**实心小方块**而不是雪花点。
     *
     * 为什么要它：原版「块内随机疏密的点群」这个做法，
     * 在**任何**遮罩/波参数下都会把光带打成等密度雪花 ——
     * 屏幕上读不出「一条浪」，只剩「一块一块各自生成」。
     * 而 pickGain 是自适应的（按 lit 目标自动增减），
     * 调 pickSoft 或遮罩阈值都改不了这一点。 */
    pickBlock: 0,
    /* ── 规整量化点阵（2026-11-03，借鉴 TRAE 首页）────────────
     * 背景：TRAE 首页的像素场是「**连续噪声场 → 像素化后处理**」，
     *   实测参数（hook WebGL2 截获的着色器真值）：
     *     e1PixelSize=5  e1PixelGap=2  e1Threshold=0.87
     *     uDensity=0.5   uSpeed=0.18   uFrequency=4
     *     uColor1=rgb(50,240,140)  uColor2=白
     *   ⇒ 它的点是**规整网格**上的硬阈值结果，颜色按场值连续插值。
     *
     * 本引擎原来的做法是「**每格一个固定随机门槛**」（rSel）
     *   ⇒ 点是随机散点，看起来像「一块一块各自生成」而不是
     *     「设计过的像素艺术」。这是两者的核心差别。
     *
     * pixelQuant = 1 时：
     *   ① 不再用 rSel 随机门槛 ⇒ 亮灭只由**连续场**决定；
     *   ② 不再用 rAmp 每格随机亮度因子、不用 jitter 抖动
     *      ⇒ 点的亮度与颜色**完全由场**决定 ⇒ 规整、有形态；
     *   ③ 点的存在由「遮罩噪声 n1 > pixelThresh」硬切（TRAE 同款），
     *      颜色按波前强度在 accent↔white 之间**连续插值**（pixelBlend=1）。
     *
     * ⚠ 默认全为 0 ⇒ 不传时行为与改版前**逐位一致**。 */
    pixelQuant: 0,          /* 0 = 关（走老的随机选点）；1 = 规整量化 */
    pixelThresh: 0.0,       /* 量化阈值（0~1，作用在遮罩噪声上） */
    pixelBlend: 0,          /* 0 = 两档色叠加；1 = 连续双色插值（单层） */
    /* ── TRAE 像素化着色器的另外两条（2026-11-03 补）────────────
     * 读了 TRAE 的像素化着色器真值（e1MainImage）之后补的：
     *
     *   float dynamicThreshold = e1Threshold - 0.08 * rand;
     *   if (brightness > dynamicThreshold) {
     *     if (rand < e1GreenRatio) { 绿 #32F08C } else { 白 }
     *   }
     *
     * ⇒ 阈值带**按块随机抖动**（不是一刀切的硬边）；
     * ⇒ 颜色是**按块随机二选一**（绿/白），**不是**按场值连续插值
     *   （着色器里唯一的连续 mix 是鼠标交互那两处，用户明确不要）。
     *
     * ⚠ pixelGreen = 0 ⇒ 不做绿白二选一（点全是 accent 色）；
     *   pixelJitter = 0 ⇒ 阈值不抖动（一刀切）。
     * ⚠ 默认全为 0 ⇒ 不传时行为与改版前**逐位一致**。 */
    pixelGreen: 0,          /* >0 = 按块随机，绿的占比（TRAE 0.49） */
    pixelJitter: 0,         /* 阈值按块随机抖动幅度（场域 -1..1） */
    /* ── TRAE 同款「流场」（2026-11-03）──────────────────────
     * 为什么需要它（实测出来的）：
     *   遮罩噪声 n1 是**值噪声**（方格晶格上的插值）⇒ 它的等值线
     *   天然**轴对齐** ⇒ 直接拿它当阈值源，亮点连出来是**方形小块**
     *   （实测：thr=0.65 时是一堆 5~7 格的方簇，像「一堆小方块」）。
     *   TRAE 的流体场是 **simplex + 3 层 FBM + 域扭曲**，
     *   域扭曲（domain warping）把坐标先扭一下再采样噪声，
     *   等值线就被掰成**有机曲线** ⇒ 这才是 TRAE 那个观感的来源。
     *
     *   实现（零依赖，照抄 TRAE 的 fbm/fbm 公式）：
     *     q.x = fbm(st*density + (0, 0.2t))
     *     q.y = fbm(st*density + (1.2, -0.3t))
     *     f   = fbm(st*density + q*warp)
     *
     *   ⚠ 单位换算（别照抄数字）：TRAE 的 simplex 噪声在 p 空间周期为 1，
     *     本引擎的噪声贴图**基频周期是 0.25 个贴图单位**（256 贴图 / 4 倍频）
     *     ⇒ 1 个 p 单位 = 0.25 个贴图单位。下面 flowDensity / flowWarp
     *     都直接用**贴图单位**，不要跟 TRAE 的 uniform 名义值混着填。
     *
     * ⚠ flowDensity = 0 ⇒ 不启用流场，沿用遮罩噪声 n1 当阈值源。
     * ⚠ 默认全为 0 ⇒ 不传时行为与改版前**逐位一致**。 */
    flowDensity: 0,         /* 流场基础尺度（贴图单位 / 屏宽） */
    flowWarp: 0,            /* 域扭曲强度（贴图单位 / 单位 q） */
    flowSpeed: 0,           /* 流场漂移速度（贴图单位 / 秒） */
    /* 档位自定网格密度：0 = 用 opt.columns；>0 = 自己说了算。
     * 为什么要它：TRAE 的点阵周期是 5px 点 + 2px 间隙 = 7px，
     * 而本引擎默认 118 列 ⇒ cell 12px ⇒ 点阵偏稀。
     * ⚠ 默认 0 ⇒ 不传时与改版前逐位一致。 */
    columns: 0,
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

    /* ── 网格密度：档位可以自己定 ──────────────────────────
     * p.columns > 0 ⇒ 档位说了算（TRAE 式规整点阵需要更密的网格）；
     * 否则沿用 opt.columns。
     * ⚠ p.columns 默认 0 ⇒ 不传时与改版前**逐位一致**。 */
    var COLUMNS = p.columns > 0 ? (p.columns | 0) : (opt.columns || 112);

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
    /* 量化模式下的**颜色系数**（=-1..1 的遮罩噪声 n1）。
       TRAE 的颜色是 mix(color1, color2, noise) —— 位置与颜色**同源**，
       所以这里必须把 n1 从几何步传到渲染步。
       ⚠ 只在 pixelQuant > 0 时写，其余情况保持 0（不传 ⇒ 逐位一致）。 */
    var qNorm = new Float32Array(0);
    /* 每道波当前的方向（sin/cos 各存一份）：方向摆动只跟时间有关，
       每步算一次就够，不必每格重复算三角函数。
       ⚠️ 用 Float64Array 而不是 Float32Array：Float32 只有 24 位有效位，
          sin(-0.30) 存进去会变成 -0.29552021622657776（真值 -0.29552020666133955，
          相对误差 3.2e-8）⇒ 采样点末位不同 ⇒ 「新参数不传时与改版前
          **逐位一致**」这句话就不成立了。
          这里只存 8 个数，内存不是问题，换成双精度没有代价。 */
    var wSin = new Float64Array(8);
    var wCos = new Float64Array(8);

    /* 方向场（随机方向波浪）：每道波一张粗网格，存 (sin, cos) 分量。
       存分量而不是角度，是为了让逐格插值时不会在 ±π 处翻折。
       只在 dirField>0 时分配，其余情况保持 null（零开销）。 */
    var dirSin = null, dirCos = null, dirFW = 0, dirFH = 0, dirStep = 24;
    /* 当前共享方向场的基准角（rad）。dirField=1 时这是**全屏统一**的方向；
       dirField=2 时方向随位置变，这里报的是基准角（整体取向）。
       debug() 把它吐出去，是为了让「方向条对比图」的箭头直接读引擎的真值，
       而不是外部脚本另算一份公式（实测踩过：另算 ⇒ 图上的角与实际不符）。 */
    var dirAngleNow = 0;
    /* ── 随机换向 / 随机变速的状态（2026-11-03）──────────────
     * dirAng     当前方向角（rad）
     * dirTarget  本轮的目标方向角（整圈均匀抽样）
     * dirTurnIdx 换向计数（决定抽第几个目标角）
     * turnInit   是否已把 dirAng 对齐到原版基准角
     * spdF       当前速度倍率（1 = 与原版同速）
     * spdTarget  本轮的目标倍率
     * spdTurnIdx 换挡计数
     * spdInit    累计相位是否已初始化
     * lastGeomT  上一次几何计算的绝对时间（算 dt 用）
     * wPh        每道波的**累计相位**（有随机变速时用它，否则沿用 om*t） */
    var dirAng = 0, dirTarget = 0, dirTurnIdx = -1, turnInit = false;
    var spdF = 1, spdTarget = 1, spdTurnIdx = -1, spdInit = false;
    var lastGeomT = 0;
    var wPh = new Float64Array(8);
    /* 每道波在**共享方向**上的偏角（dirField>0 时 waves[].dir 是偏角，不是绝对角） */
    var wOffS = new Float64Array(8);
    var wOffC = new Float64Array(8);

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
        qNorm = new Float32Array(n);
        /* ⚠️ pickBlock > 0 时，**同一块里的格子共享同一个随机门槛**，
         *   亮区于是变成**实心小方块**，而不是逐格随机的点阵。
         *
         *   为什么需要它（2026-11-02 实测）：
         *   选取门槛 rSel 原本是**每格独立**的随机数 ⇒ 任何一条光带
         *   都被打成等密度的雪花点 ⇒ 屏幕上根本读不出「一条浪」，
         *   只剩「一块一块各自生成」—— 正是用户抱怨的那个观感。
         *
         *   踩过的坑：以为调 pickSoft（软门宽度）就能把点连成片，
         *   结果**无效** —— 因为 pickGain 是**自适应**的（引擎按 lit
         *   目标自动增减），pickSoft 抬高多少它就压回去多少；
         *   把遮罩阈值（patchA1/A2）调低也只会得到更均匀的雪花。
         *   ⇒ 唯一的办法是让**相邻格的亮灭决策相关**，也就是共享门槛。
         *
         *   ⚠️ pickBlock = 0（默认）时必须与原版**逐位一致**：
         *   门槛仍按 rnd(i, ...) 逐格生成，一个字节都不变。 */
        var pb = p.pickBlock | 0;
        for (var i = 0; i < n; i++) {
          var si = i;
          if (pb > 0) {
            /* 块坐标 → 一个不重复的整数索引。
               行距取 8191（素数，且远大于任何可能的块列数），
               避免 (bx,by) 与 (bx',by') 撞成同一个索引。 */
            var bx = Math.floor((i % cols) / pb);
            var by = Math.floor(Math.floor(i / cols) / pb);
            si = bx * 8191 + by;
          }
          rSel[i] = rnd(si, 1013904223);
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

    /* ── 方向场分配 ──────────────────────────────────────────
     * 粗网格：每 dirFieldStep 像素一格。
     * 步长越大越省算力、方向过渡越柔；越小方向变化越碎。
     * 24px 是个折中：整屏约 60×38 = 2280 格/波，4 道波不到 1 万点，
     * 每几何步重算一次（30Hz）⇒ 30 万次噪声采样/秒，完全够用。 */
    function ensureDirField() {
      if (p.dirField <= 0) {
        dirFW = dirFH = 0;
        dirSin = dirCos = null;
        return false;
      }
      dirStep = Math.max(8, p.dirFieldStep || 24);
      var nfw = Math.max(2, Math.ceil(w / dirStep) + 1);
      var nfh = Math.max(2, Math.ceil(h / dirStep) + 1);
      if (nfw !== dirFW || nfh !== dirFH || !dirSin) {
        dirFW = nfw; dirFH = nfh;
        dirSin = new Float32Array(dirFW * dirFH);
        dirCos = new Float32Array(dirFW * dirFH);
      }
      return true;
    }

    /* ── 几何：波 + 遮罩 + 随机选取 + 余晖 ────────────────
     * 只在**几何步**变化时跑（默认 30 次/秒）。渲染在帧间插值，
     * 所以画面连续，但算力比原来还省一半。 */
    function computeGeometry(tq) {
      var waves = p.waves;
      var nw = waves.length;
      var idx = 0;
      var bandCells = 0;

      /* ── 方向随机化：两项都只跟时间有关，每步算一次 ────────
         ① 波向摆动：每道波的法线角缓慢摆动，三道波各带一个
            固定相位（wi * 2.1）⇒ 不同步，不会整片一起转。
         ② 遮罩晶向：两层遮罩各自的旋转角 + 整片遮罩的缓慢自转。
            旋转矩阵同理，每步算一次 cos/sin 就够。
         这两项放进「每格」里算就是白算 —— 9000 格 × 30Hz = 27 万次
         三角函数，挪到这一步里每步只有几次。 */
      var swingT = tq * p.dirSwingFreq * 6.2831853;
      for (var wi = 0; wi < nw; wi++) {
        var wv0 = waves[wi];
        var dir = wv0.dir + p.dirSwing * Math.sin(swingT + wi * 2.1);
        wSin[wi] = Math.sin(dir);
        wCos[wi] = Math.cos(dir);
      }
      var spin = p.patchSpin * tq;
      var c1 = Math.cos(p.patchRot1 + spin), s1 = Math.sin(p.patchRot1 + spin);
      var c2 = Math.cos(p.patchRot2 + spin), s2 = Math.sin(p.patchRot2 + spin);

      /* ── 随机方向波浪：一张**共享**的空间局部方向场 ──────────
       * 所有波共用同一张方向场（每波只带一个小偏角 waves[].dir），
       * 所以几道波在局部仍然平行，但**整体走向随位置变、随时间漂移**
       * ⇒ 屏幕上没有统一的波向，但每一处都还是「一道浪」。
       *
       * ⚠️ 为什么必须共享（踩过的坑）：
       *   最初给每道波各算一张方向场，结果分片遮罩的采样帧
       *   跟着「每格胜出的那道波」跳变 ⇒ 遮罩的拉长方向在相邻格
       *   完全对不上 ⇒ 拉长效果互相抵消 ⇒ 画面还是一堆圆疙瘩散点，
       *   波浪完全看不出来。共享之后，遮罩的拉长方向与波的走向
       *   严格一致 ⇒ 亮块才拉成长条。
       *
       * dirField>0 时 waves[].dir 的语义从「绝对法线角」变成
       * 「相对共享方向的偏角」；dirField=0 时语义不变（逐位一致）。 */
      var useField = ensureDirField();
      /* 方向场的旋转中心：默认原点（= 原版行为），dirPivot=1 时挪到画布中心。
         只有 useField 时才有意义（方向不变时旋转中心不产生任何差别），
         且偏移为 0 时 (px-0) 与 px 逐位相等 ⇒ 原路径不受影响。 */
      var pivX = 0, pivY = 0;
      if (useField && p.dirPivot > 0) { pivX = w * 0.5; pivY = h * 0.5; }

      /* ── 本几何步的实际时间间隔 dt ──────────────────────────
         用它（而不是 p.step）来推进方向与相位：
         引擎在标签页隐藏时 rAF 会停 ⇒ 几何步会被**跳过**，
         若按 p.step 累加，方向与相位就会比真实时间慢一大截。 */
      var geoDt = tq - lastGeomT;
      if (!(geoDt > 0)) geoDt = 0;
      lastGeomT = tq;

      /* ── 随机变速（2026-11-03）─────────────────────────────
         每 speedTurnPeriod 秒抽一个目标倍率，按 speedTurnRate 逼近。
         倍率用**累计相位**兑现（见下面 wPh），否则速度一变波前会跳变。 */
      var useSpeedWalk = p.speedTurnPeriod > 0 && p.speedRange > 0;
      if (useSpeedWalk) {
        var sid = Math.floor(tq / p.speedTurnPeriod);
        if (sid !== spdTurnIdx) {
          spdTurnIdx = sid;
          /* 索引乘一个质数步长再哈希 ⇒ 相邻两档的目标不会相关 */
          spdTarget = 1 + (rnd(sid * 104729 + 13, 22695477) * 2 - 1) * p.speedRange;
        }
        var sdiff = spdTarget - spdF;
        /* speedTurnRate = 0 ⇒ 不限速 ⇒ 瞬间换挡（「啪」地一下）
           限速时是「慢慢提速降速」。两种都由这一个参数控制。 */
        var smax = p.speedTurnRate > 0 ? p.speedTurnRate * geoDt : 1e9;
        if (sdiff > smax) sdiff = smax; else if (sdiff < -smax) sdiff = -smax;
        spdF += sdiff;
        if (!spdInit) {
          /* 第一次启用：对齐到闭式 om*t ⇒ 启用瞬间波前不跳变 */
          spdInit = true;
          for (var sgi = 0; sgi < nw; sgi++) wPh[sgi] = waves[sgi].om * tq;
        } else {
          /* 累计相位：速度是它的推进速率。
             ⚠ 必须累计，不能用闭式 om*t —— 否则速度一变波前位置会跳。 */
          for (var spi = 0; spi < nw; spi++) {
            wPh[spi] += waves[spi].om * spdF * geoDt;
          }
        }
      }

      /* ── 随机换向（2026-11-03）─────────────────────────────
         dirTurnPeriod > 0 ⇒ 每周期抽一个整圈均匀的随机目标角，
         当前角按不超过 dirTurnRate 的角速度朝它靠（取短弧）。 */
      var useTurnWalk = p.dirTurnPeriod > 0;
      if (useTurnWalk) {
        if (!turnInit) {
          /* 起始朝向对齐原版基准角 ⇒ 第一帧与原版一致，
             之后才慢慢被随机目标带走（否则一上来就跳到随机角）。 */
          turnInit = true;
          dirAng = p.dirFieldBase || 0;
          dirTarget = dirAng;
        }
        var did = Math.floor(tq / p.dirTurnPeriod);
        if (did !== dirTurnIdx) {
          dirTurnIdx = did;
          /* 目标角在整圈上均匀抽样 ⇒ 上下左右都会抽到 */
          dirTarget = rnd(did * 7919 + 13, 1013904223) * 6.2831853;
        }
        var tdiff = dirTarget - dirAng;
        /* 取短弧：否则为了 350° 的差别会绕远路 */
        while (tdiff > Math.PI) tdiff -= 6.2831853;
        while (tdiff < -Math.PI) tdiff += 6.2831853;
        /* dirTurnRate = 0 ⇒ 不限速 ⇒ 一步到位（「突然拐一下」）
           dirTurnRate > 0 ⇒ 限速 ⇒「慢慢飘过去」。 */
        var tmax = p.dirTurnRate > 0 ? p.dirTurnRate * geoDt : 1e9;
        if (tdiff > tmax) tdiff = tmax; else if (tdiff < -tmax) tdiff = -tmax;
        dirAng += tdiff;
        while (dirAng > Math.PI) dirAng -= 6.2831853;
        while (dirAng < -Math.PI) dirAng += 6.2831853;
      }

      if (useField) {
        var dsc = p.dirFieldScale || 0.003;
        var drg = p.dirFieldRange || 0;
        var ddr = p.dirFieldDrift || 0;
        var dwf = p.dirWalkFreq || 0;
        var fj, fi, ddx, ddy, dang, dn, do2, dstep = dirStep;
        var dbase = (p.dirFieldBase || 0) + p.dirSwing * Math.sin(swingT);
        for (fj = 0; fj < dirFH; fj++) {
          ddy = fj * dstep;
          for (fi = 0; fi < dirFW; fi++) {
            ddx = fi * dstep;
            if (p.dirField === 1) {
              /* 方向只随时间变（空间上统一）⇒ 整片波浪换个朝向。
                 两条取值路径：
                   · 随机目标角（dirTurnPeriod > 0）= 主路，能摆满整圈
                   · 噪声切片（默认）                = 原始实现，带高频抖动 */
              if (useTurnWalk) {
                /* 保留 dirSwing 的微摆（该档若设了的话） */
                dang = dirAng + p.dirSwing * Math.sin(swingT);
              } else {
                dn = sample(tex, NOISE_N, tq * dwf, 0.37);
                dang = dbase + dn * drg;
              }
            } else {
              /* 方向随位置变 + 随时间漂移 ⇒ 湍流状 */
              dn = sample(tex, NOISE_N, ddx * dsc + tq * ddr,
                                      ddy * dsc + tq * ddr * 0.7);
              dang = dbase + dn * drg;
            }
            dirAngleNow = dang;
            do2 = fj * dirFW + fi;
            dirSin[do2] = Math.sin(dang);
            dirCos[do2] = Math.cos(dang);
          }
        }
        /* 每道波在共享方向上的偏角 */
        for (var fo = 0; fo < nw; fo++) {
          wOffC[fo] = Math.cos(waves[fo].dir);
          wOffS[fo] = Math.sin(waves[fo].dir);
        }
      }

      /* 流场开关：量化模式 + flowDensity > 0 才启用。
         提到逐格循环外算 —— 它每步只取决于参数，不取决于格子。 */
      var useFlow = p.pixelQuant > 0 && p.flowDensity > 0;

      for (var cy = 0; cy < rows; cy++) {
        var py = cy * cell + cell * 0.5;
        for (var cx = 0; cx < cols; cx++) {
          var px = cx * cell + cell * 0.5;

          /* ── 相位扭曲：让波前是曲线而不是直线 ───────────── */
          var dz = sample(tex, NOISE_N,
            px * p.distortScale + tq * p.distortDrift,
            py * p.distortScale * 1.25 + tq * p.distortDrift * 0.6);

          /* ── 取共享方向场（逐格双线性插值）──────────────
             插的是 (sin, cos) 分量，插完再归一化 ——
             直接插角度会在 ±π 处翻折，插出来的方向会突然反向。 */
          var fs = 0, fc = 0;
          if (useField) {
            var gx = px / dirStep, gy = py / dirStep;
            var i0 = gx | 0; if (i0 > dirFW - 2) i0 = dirFW - 2;
            var j0 = gy | 0; if (j0 > dirFH - 2) j0 = dirFH - 2;
            var txf = gx - i0, tyf = gy - j0;
            var q00 = j0 * dirFW + i0, q10 = q00 + 1;
            var q01 = q00 + dirFW, q11 = q01 + 1;
            var sA = (dirSin[q00] * (1 - txf) + dirSin[q10] * txf) * (1 - tyf) +
                     (dirSin[q01] * (1 - txf) + dirSin[q11] * txf) * tyf;
            var cA = (dirCos[q00] * (1 - txf) + dirCos[q10] * txf) * (1 - tyf) +
                     (dirCos[q01] * (1 - txf) + dirCos[q11] * txf) * tyf;
            var mm = Math.sqrt(sA * sA + cA * cA);
            /* mm 极小 ⇒ 两侧方向几乎相反且等权 ⇒ 退回全局方向 */
            if (mm > 1e-6) { fs = sA / mm; fc = cA / mm; }
          }

          /* ── 多道错相平行浪，取最强的一道 ───────────────── */
          var band = 0;
          for (var wi2 = 0; wi2 < nw; wi2++) {
            var wv = waves[wi2];
            var wsn = wSin[wi2], wcn = wCos[wi2];
            if (useField) {
              /* 共享方向 + 本波偏角 ⇒ 局部仍平行，整体走向随位置变 */
              wsn = fs * wOffC[wi2] + fc * wOffS[wi2];
              wcn = fc * wOffC[wi2] - fs * wOffS[wi2];
            }
            var uy = (px - pivX) * wsn + (py - pivY) * wcn;
            var ph = wv.k * uy - (useSpeedWalk ? wPh[wi2] : wv.om * tq)
                   + wv.off + dz * p.distortAmp;
            var s = Math.sin(ph);
            if (s <= p.edge0) continue;
            var b = sstep(p.edge0, p.edge1, s) * wv.w;
            if (b > band) band = b;
          }

          /* ── 分片遮罩：把带碎成一块块 ─────────────────── */
          if (band > 0) {
            bandCells++;
            /* 两层遮罩各带一个旋转角：采样坐标**先按各自角度转过去**，
               再乘各向异性比例。转的是「纹理本身的方向」，
               而漂移仍留在屏幕空间 —— 于是方块内部晶向杂乱，
               整体仍朝一个方向流动（漂移方向不跟着转，
               否则整片会像转盘一样旋）。 */
            var u1x = px * p.patchScale, u1y = py * p.patchScale * 1.15;
            var u2x = px * p.patchScale * 0.77 + 37.1, u2y = py * p.patchScale * 1.05 + 11.3;
            var n1, n2;
            if (p.patchFollow > 0) {
              /* ── 遮罩晶向跟随**局部波向** ──────────────────
                 把屏幕坐标转进波帧：
                   切向 tan = 沿波前（垂直于法向）
                   法向 nor = 沿法向
                 切向用低频（噪声沿波前变化慢 ⇒ 斑块沿波前拉长），
                 法向用高频（横向收紧）。
                 ⇒ 亮块沿波前拉成**长条**，整条光带就是一条流动的像素流。
                 而波向本身随位置变（dirField）⇒ 不同区域朝向不同。 */
              var tanX = px * fc - py * fs;
              var norX = px * fs + py * fc;
              n1 = sample(tex, NOISE_N,
                tanX * p.patchScale * p.patchTangent + tq * p.patchDrift,
                norX * p.patchScale * p.patchNormal + tq * p.patchDrift * 0.8);
              n2 = sample(tex, NOISE_N,
                tanX * p.patchScale * p.patchTangent2 + 37.1 + tq * p.patchDrift * 0.55,
                norX * p.patchScale * p.patchNormal2 + 11.3 + tq * p.patchDrift * 0.9);
            } else {
              n1 = sample(tex, NOISE_N,
                u1x * c1 - u1y * s1 + tq * p.patchDrift,
                u1x * s1 + u1y * c1 + tq * p.patchDrift * 0.8);
              n2 = sample(tex, NOISE_N,
                u2x * c2 - u2y * s2 + tq * p.patchDrift * 0.55,
                u2x * s2 + u2y * c2 + tq * p.patchDrift * 0.9);
            }
            var m1 = sstep(p.patchA1, p.patchA1 + (p.patchB1 - p.patchA1) / p.patchSoft, n1);
            var m2 = sstep(p.patchA2, p.patchA2 + (p.patchB2 - p.patchA2) / p.patchSoft, n2);
            var mask = m1 * m2;
            /* ── 规整量化（pixelQuant = 1，借鉴 TRAE 首页）──────
               TRAE 的做法是「**连续噪声场 → 阈值硬切 → 规整点阵**」，
               点的位置与亮度**完全由场决定**，没有任何每格随机量。
               这里照搬那三件事：
                 ① 不乘遮罩 ⇒ 去掉「一块一块」的块状明暗
                 ② 不用 rSel 每格随机门槛 ⇒ 用 n1 > 阈值硬切
                 ③ 不乘 rAmp 每格随机亮度因子
               ⚠ pixelQuant = 0（默认）⇒ 整段老路不走 ⇒ 逐位一致。 */
            var quant = p.pixelQuant > 0;
            if (quant) {
              /* ── 阈值源：TRAE 同款流场（域扭曲 FBM）──────────
                 flowDensity > 0 才启用；否则沿用遮罩噪声 n1。
                 ⚠ 三个采样都在**屏幕归一化坐标**里算 ⇒ 场与波无关，
                   只跟时间漂移 ⇒ 形状连续稳定（TRAE 的流体场也是这样）。 */
              var qf = n1;
              if (useFlow) {
                var sxq = px / w, syq = py / h;
                var ubq = sxq * p.flowDensity, vbq = syq * p.flowDensity;
                var ftq = tq * p.flowSpeed;
                /* q 的两条通道：各自偏移 + 反向漂移 ⇒ 两两不相关 */
                var qxq = sample(tex, NOISE_N, ubq, vbq + 0.05 * ftq);
                var qyq = sample(tex, NOISE_N, ubq + 0.30, vbq - 0.0375 * ftq);
                /* 域扭曲：坐标先被 q 掰一下再采样 ⇒ 等值线成有机曲线 */
                qf = sample(tex, NOISE_N, ubq + qxq * p.flowWarp, vbq + qyq * p.flowWarp);
              }
              /* ⚠ 噪声值域是 **[-1, 1]**（makeNoise 末尾做了归一化），
                 而 pixelThresh 用 [0, 1] 表述（跟 TRAE 的 0.87 同尺度）
                 ⇒ 这里做一次域转换，别让人填 0.87 结果一个点都没有。 */
              var qth = (p.pixelThresh > 0 ? p.pixelThresh : 0.5) * 2 - 1;
              /* ── 阈值按块随机抖动（TRAE 同款）──────────────
                 TRAE 像素化着色器：`dynamicThreshold = e1Threshold - 0.08 * rand`
                 其中 rand 是**按 blockId 稳定**的伪随机。
                 作用：硬边被随机削掉一点 ⇒ 亮区边界是参差的，
                       而不是一刀切出来的光滑轮廓。
                 ⚠ 用的是 rSel[idx]（每格固定的伪随机，resize 后不变）
                   —— 正好当 TRAE 的 rand(blockId)。 */
              if (p.pixelJitter > 0) qth -= p.pixelJitter * rSel[idx];
              /* 颜色系数：跟点的存在**同源**（TRAE 的 mix(c1, c2, noise) 同款）*/
              qNorm[idx] = qf;
              if (qf > qth) {
                band *= p.patchGain;
              } else {
                band = 0;
              }
            } else if (mask < 0.08) {
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
          /* ⚠ 量化模式（pixelQuant = 1）下**不留余晖**。
             余晖的作用是让刚熄灭的点按 trail 慢慢衰减 ⇒ 渲出来是一条
             alpha 渐变带 ⇒ 边缘看着像「水打上去的印记」。
             TRAE 的像素块是**硬开关**（亮 / 不亮两态，中间灰没有）
             ⇒ 这里 peak 直接取 band，不做衰减。
             ⚠ 只改渲染的 alpha 斜坡是不够的 —— 余晖会把已经熄灭的格
               继续顶在阈值之上，硬边做不出来。 */
          var e = quant ? band : (band > prev ? band : prev * p.trail);
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
      /* ⚠ 量化模式（pixelQuant > 0）下选点不再吃 pickGain ——
         点的亮灭由「连续场 > 阈值」决定 ⇒ 伺服是空转，
         继续调只会把 pickGain 顶到上限、还会污染 debug() 的读数。
         ⇒ 直接跳过，密度由 pixelThresh 自己说了算。 */
      if (p.pixelQuant > 0) return 0;
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
      /* 像素块边长（亚像素）。0 = 原版尺寸（浪身 2 / 浪尖 3）。
         原版每格 12px 却只画 2px 的点 ⇒ 满屏噪点感；
         填 3 则是 9×9 的方块，留 1.5px 间隙 ⇒ 有像素网格。 */
      var b1s = p.pxBody > 0 ? Math.min(SS, p.pxBody | 0) : 2;
      var b2s = p.pxCrest > 0 ? Math.min(SS, p.pxCrest | 0) : 3;
      /* ── 规整量化 / 连续双色插值（借鉴 TRAE，2026-11-03）────────
         quant：点阵去掉所有每格随机量（门槛、亮度因子、抖动），
                亮灭与颜色完全由连续场决定 ⇒ 规整、有形态。
         blend：颜色按场的值在 accent↔white 之间**连续插值**，
                且只画**一层**（TRAE 的 mix(c1, c2, noise) 同款，
                原来这里是「accent 层 + white 层」两档叠加）。
         ⚠ 两者默认都是 0 ⇒ 走的还是原路径 ⇒ 逐位一致。 */
      var quant = p.pixelQuant > 0;
      var blend = p.pixelBlend > 0;
      /* TRAE 同款的「按块随机绿白二选一」：pixelGreen > 0 才开。
         ⚠ 必须在 quant 模式里才有意义（老路径的绿白分层是另一回事）。 */
      var greenBin = quant && p.pixelGreen > 0;

      for (var cy = 0; cy < rows; cy++) {
        var by0 = cy * SS;
        for (var cx = 0; cx < cols; cx++) {
          /* ── 连续插值：几何按 1/30 秒采样，渲染在步间线性过渡 */
          var v = prevPeak[idx] + (peak[idx] - prevPeak[idx]) * lerp;
          /* ── 抖动：每格固定相位的时间平滑摆动 + 每格固定的空间偏移
             ⚠ 量化模式下必须关掉 —— 它是「每格随机量」之一，
               留着点阵就还是随机疏密，而不是规整网格。 */
          var off = quant ? 0
            : (Math.sin(t * dRate + dphase[idx]) * dth + rJit[idx] * jitAmp);
          var vv = v + off;

          /* ── 色阶的 alpha 斜坡（对称，边界是渐变不是硬切）── */
          var a1, a2;
          if (quant) {
            /* ⚠ 量化模式是**硬开关**：要么满亮、要么全黑，没有中间态。
               TRAE 的像素化层只有两态（vec4(color,1.0) / vec4(bg,1.0)），
               中间灰是没有的 ⇒ 边缘不会出现「水印记」式的灰度过渡。
               切点取 tLo1（= accentT - fade/2）：正好落在原来斜坡
               刚到满亮的位置上 ⇒ **亮区大小基本不变**，只是边界由
               渐变变成硬边。 */
            a1 = vv > tLo1 ? 1 : 0;
            /* 没有「浪尖」层 ⇒ 也不出辉光（TRAE 那边同样没有辉光） */
            a2 = 0;
          } else {
            a1 = (vv - tLo1) / fade;
            if (a1 < 0) a1 = 0; else if (a1 > 1) a1 = 1;
            a2 = (vv - tLo2) / fade;
            if (a2 < 0) a2 = 0; else if (a2 > 1) a2 = 1;
          }

          /* ── 迟滞：alpha 下降按帧限速，卡在阈值上的格子
                不会一帧掉到 0 ⇒ 消掉闪烁。 ─────────────── */
          /* ⚠ 量化模式下**不能**用迟滞：迟滞把「1 → 0」压成
             「1 → 0.965 → …」⇒ 又变回灰度过渡，跟硬边相悖。 */
          if (!quant) {
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
          }
          aPrev[idx] = a1;
          wPrev[idx] = a2;

          if (a1 <= 0.002 && a2 <= 0.002) { idx++; continue; }
          litCount++;

          /* ── 画：浪身铺底，浪尖叠在上面 ─────────────────
             两层都画 ⇒ accent→white 的切换也是渐变，不会闪。 */
          var b1 = b1s;
          var inset1 = ((SS - b1) / 2) | 0;
          var bx1 = cx * SS + inset1;
          var by1 = by0 + inset1;
          if (bx1 + b1 <= sw && by1 + b1 <= rows * SS) {
            var a255 = (a1 * 255) | 0;
            var o;
            /* 颜色：blend 模式按场的值连续插值 accent↔white，
               非 blend 模式沿用常量 accent 色（逐位一致）。
               插值系数用**遮罩噪声 n1**（qNorm，值域 -1..1 归一到 0..1）——
               跟点的存在同源，和 TRAE 的 mix(c1, c2, noise) 一个路子。
               ⚠ 但 TRAE 的像素化着色器里**颜色不是连续插值**，
                 是 `if (rand < e1GreenRatio) 绿 else 白` 的**按块随机二选一**
                 —— 唯一的连续 mix 出现在鼠标交互里（用户明确不要）。
                 ⇒ pixelGreen > 0 时走「按块随机二选一」，pixelBlend = 1 时走连续插值。 */
            var cr = acc[0], cg = acc[1], cb = acc[2];
            if (blend) {
              var kk = (qNorm[idx] + 1) * 0.5;
              if (kk < 0) kk = 0; else if (kk > 1) kk = 1;
              cr = (acc[0] + (wht[0] - acc[0]) * kk) | 0;
              cg = (acc[1] + (wht[1] - acc[1]) * kk) | 0;
              cb = (acc[2] + (wht[2] - acc[2]) * kk) | 0;
            } else if (greenBin) {
              /* TRAE 同款：按块随机二选一。rand 用 rSel[idx]（每格固定）。
                 ⚠ 同一个 rand 也参与阈值抖动（见 computeGeometry），
                   所以「绿块」的阈值略高一点、白块略低一点 ——
                   这正是 TRAE 原着色器的行为（同一个 rand 两处用）。 */
              if (rSel[idx] < p.pixelGreen) {
                cr = acc[0]; cg = acc[1]; cb = acc[2];
              } else {
                cr = wht[0]; cg = wht[1]; cb = wht[2];
              }
            }
            for (var yy = 0; yy < b1; yy++) {
              o = ((by1 + yy) * sw + bx1) * 4;
              for (var xx = 0; xx < b1; xx++) {
                fineData[o] = cr; fineData[o + 1] = cg; fineData[o + 2] = cb; fineData[o + 3] = a255;
                o += 4;
              }
            }
          }

          /* ⚠ blend / greenBin 模式只画**一层**（颜色已经在上面定好了），
             再叠一层 white 会把插值/二选一冲掉。
             非量化模式仍是原来的「浪身铺底 + 浪尖叠上」两档。 */
          if (!blend && !greenBin && a2 > 0.002) {
            var b2 = b2s;
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
          dirAngle: dirAngleNow, dirAngleDeg: dirAngleNow * 180 / Math.PI,
          speedFactor: spdF, dirTarget: dirTarget,
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
