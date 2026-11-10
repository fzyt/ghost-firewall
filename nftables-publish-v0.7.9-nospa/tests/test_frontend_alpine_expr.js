/* Alpine 求值语义判据：模板表达式不能踩「以 if/let/const 开头」的陷阱
 *
 * 运行: node tests/test_frontend_alpine_expr.js
 *
 * 背景（2026-11-10，系统信息页数据面扩充时踩到）
 * -------------------------------------------------
 * 本轮给接口明细加了个格式化方法，命名叫 `ifaceDetail(iface)`。
 * 结果页面上「接口明细」那一行**永远是空的** ——
 * 不报错、不白屏、控制台干净，所有文本层面的测试全绿。
 *
 * 根因：Alpine 3.15.8 的求值器
 * （frontend/assets/alpine.js 的 generateEvaluatorFromString，压缩后叫 Jn）：
 *
 *     n = /^[\n\s]*if.*\(.*\)/.test(t.trim()) || /^(let|const)\s/.test(t.trim())
 *         ? `(async()=>{ ${t} })()` : t
 *
 * 表达式**以字母 "if" 开头**就会被当成 if 语句 —— 注意 Alpine 的正则
 * **没有词边界**，所以 `ifaceDetail(iface)` 这种「以 if 打头的方法名」
 * 一样中招。
 *
 * ⚠️ 关键：**这条正则在不同位置上语义完全不同**
 * -------------------------------------------------
 * 判据第一版把「模板里所有表达式」一锅端地扫一遍，结果报了两条 FAIL：
 *   · @click="if(confirm('确定退出登录？')) doLogout()"  ← 报错了
 *   · app.js 里 6 个 "if" 方法名                          ← 也报错了
 *
 * 用**真实浏览器**（tmp/alpine-probe.js / alpine-probe2.js / alpine-probe3.js，
 * 把真 alpine.js 塞进页面逐项试）测出来的地面真值是：
 *
 *   位置类型          Alpine 走的求值器      以 if 开头 + 带括号
 *   ──────────────────────────────────────────────────────────────
 *   值位              Jn：(async()=>{...})()  **值被丢弃** ⇒ 渲染成空
 *     x-text / x-html / :class / x-show / x-if / x-model
 *     / x-for 的 items 部分
 *   副作用位          xr：(()=>{...})()       副作用保留 ⇒ **正常**
 *     @click / @change / @input / x-init
 *   字面量位          不求值                  不适用
 *     x-transition:enter* / x-ref
 *
 * 也就是说：
 *   · 值位表达式以 if/let/const 开头 ⇒ **致命**（值没了）
 *   · 副作用位表达式以 if 开头 ⇒ **Alpine 的官方写法**（`if (confirm(...)) ...`
 *     本来就是 Alpine 文档推荐的写法），改成非 if 开头反而是画蛇添足
 *   · 所以第一版判据把副作用位一起扫 ⇒ **判据写宽了，不是代码有坑**
 *
 * 另外第一版还有第二个错：方法名正则 `/^\s{4}([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/`
 * 抓的是 app.js 里 4 空格缩进的 `if (this.ddns.editingIsNew) {` 这类**语句**，
 * 被当成了「方法名」—— 报出来的 6 个 "if" 全是这种误抓。
 *
 * ⇒ 所以判据必须**按位置语义分类**，不能一锅端。
 *
 * 判据的两条硬要求
 * ----------------
 * 1. **正则必须从 alpine.js 里抽出来**，不能手抄 ——
 *    手抄的会和 Alpine 实际行为脱节，那比没有判据更坏
 *    （它会给人「已经验过了」的错觉）。抽不到 ⇒ 判据直接失败。
 * 2. **判据要比被测对象更强** ——
 *    只查「当前模板里有没有踩坑」是不够的：
 *    下次有人新增一个 `ifFoo()` 方法、或新增一条 `x-text="ifBar(x)"`，
 *    判据必须当场抓住。所以还要查 app.js 里的方法名。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const INDEX_HTML = fs.readFileSync(path.join(ROOT, 'frontend', 'index.html'), 'utf8');
const APP_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');
const ALPINE_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'assets', 'alpine.js'), 'utf8');

const PASS = [], FAIL = [];
const check = (name, ok, detail = '') => {
  (ok ? PASS : FAIL).push(name);
  console.log((ok ? '  [PASS] ' : '  [FAIL] ') + name + (detail ? '  — ' + detail : ''));
};
const sec = (t) => console.log('\n=== ' + t + ' ===');

// ================================================================
// 第 1 组：从 alpine.js 抽出求值器用的正则（不手抄）
// ================================================================
sec('第 1 组：正则必须从 alpine.js 里抽出来（手抄的会脱节）');

/**
 * ⚠️ 抽取方式必须是**锚定到具体路径**，不能扫全文件找「唯一字面量」。
 *
 * 第一版就是这么写的（扫全文件 → 取唯一字面量），被自己的变异脚本抓出漏洞：
 * 把 alpine.js 里**值位路径**的那条正则换成宽松版，全文件仍然存在
 * 另一条一样的旧正则 ⇒ 判据照样抽得到、照样全绿 ⇒
 * **判据默默接受了错误的行为**。
 *
 * 正确做法：锚定到 Alpine 的**值位求值路径**。
 * 该路径在压缩源码里的标志是 `__self.result = `（全文件只出现 1 次），
 * 它前面紧跟着的就是值位求值器用的 detector：
 *
 *     n=/^[\n\s]*if.*\(.*\)/.test(t.trim())||/^(let|const)\s/.test(t.trim())
 *         ? `(async()=>{ ${t} })()` : t
 *     ...
 *     __self.result = <上面那个 n>
 *
 * ⇒ 从这个锚点**往前**取 detector，就是值位路径真正在用的那条。
 */

/** Alpine 值位求值路径的锚点（压缩源码里唯一）。 */
const VALUE_PATH_ANCHOR = '__self.result = ';

/** detector 的形状：正则字面量 + .test( */
const DETECTOR_RE = /\/\^[^/]*\/[a-z]*\.test\(/g;

function extractDetectorsBefore(anchor) {
  const pos = ALPINE_JS.indexOf(anchor);
  if (pos < 0) return null;
  // 往前取 800 字符：足够覆盖 detector，又不会串到别的函数
  const win = ALPINE_JS.slice(Math.max(0, pos - 800), pos);
  return [...win.matchAll(DETECTOR_RE)].map((m) => m[0]);
}

check('在 alpine.js 里找到了值位求值路径的锚点',
  ALPINE_JS.indexOf(VALUE_PATH_ANCHOR) >= 0, VALUE_PATH_ANCHOR);
check('值位求值路径的锚点在 alpine.js 里唯一',
  ALPINE_JS.split(VALUE_PATH_ANCHOR).length - 1 === 1,
  '出现 ' + (ALPINE_JS.split(VALUE_PATH_ANCHOR).length - 1) + ' 次');

const pathDetectors = extractDetectorsBefore(VALUE_PATH_ANCHOR) || [];
check('值位路径上抽到了 2 条 detector（if 一条 + let/const 一条）',
  pathDetectors.length === 2, '抽到 ' + pathDetectors.length + ' 条: ' +
  JSON.stringify(pathDetectors));

// 从 detector 字面量里取出正则本体（去掉结尾的 .test( ）
function detectorToLiteral(det) {
  return det.replace(/\.test\($/, '');
}

const ifDetector = pathDetectors.find((d) => /if/.test(d)) || null;
const declDetector = pathDetectors.find((d) => /let\|const/.test(d)) || null;

check('从值位路径抽到了 if detector', !!ifDetector, ifDetector || '');
check('从值位路径抽到了 let/const detector', !!declDetector, declDetector || '');

/**
 * 额外断言：值位路径的 detector 必须与**全文件**其它路径的 detector 一致。
 *
 * Alpine 有三条求值路径（值位 Jn / 原始求值器 xr 的两个分支），
 * 它们用的是同一条正则 —— 这是 Alpine 的实现细节，但我们的判据
 * 依赖「值位路径那条能识别出危险表达式」这一事实。
 *
 * 如果 Alpine 改了某一条而不改其它条 ⇒ 说明实现变了 ⇒
 * 判据必须**失败并要求人工复核**，而不是继续默默用旧规则。
 */
const allDetectors = [...new Set(
  [...ALPINE_JS.matchAll(DETECTOR_RE)].map((m) => m[0])
)];
const ifDetectorsAll = allDetectors.filter((d) => /if/.test(d));
check('alpine.js 里所有 if detector 都是同一条（实现未分叉）',
  ifDetectorsAll.length > 0 && ifDetectorsAll.every((d) => d === ifDetector),
  ifDetectorsAll.length + ' 条: ' + JSON.stringify(ifDetectorsAll));

const declDetectorsAll = allDetectors.filter((d) => /let\|const/.test(d));
check('alpine.js 里所有 let/const detector 都是同一条（实现未分叉）',
  declDetectorsAll.length > 0 && declDetectorsAll.every((d) => d === declDetector),
  declDetectorsAll.length + ' 条: ' + JSON.stringify(declDetectorsAll));

// 把 detector 字面量（形如 /^[\n\s]*if.*\(.*\)/.test( ）还原成 RegExp。
// alpine.js 里写的是 `/^[\n\s]*if.*\(.*\)/` —— 反斜杠是**字面反斜杠**，
// 所以去掉头尾斜杠就是正则源码。
function literalToRegExp(det) {
  if (!det) return null;
  const body = detectorToLiteral(det).slice(1, -1);
  try {
    return new RegExp(body);
  } catch (e) {
    return null;
  }
}

const ALPINE_IF_RE = literalToRegExp(ifDetector);
const ALPINE_DECL_RE = literalToRegExp(declDetector);

check('抽到的 if detector 能编译成 RegExp', !!ALPINE_IF_RE, ifDetector || '');
check('抽到的 let/const detector 能编译成 RegExp', !!ALPINE_DECL_RE, declDetector || '');

/** 表达式会不会被 Alpine 当成语句包起来（判据核心）。 */
function alpineWrapsAsStatement(expr) {
  if (!ALPINE_IF_RE || !ALPINE_DECL_RE) return false;
  const t = String(expr).trim();
  return ALPINE_IF_RE.test(t) || ALPINE_DECL_RE.test(t);
}

// ================================================================
// 第 2 组：位置语义分类
// ================================================================
sec('第 2 组：位置语义分类（值位 / 副作用位 / 字面量位）');

/**
 * 属性按 Alpine 的求值语义分三类。
 *
 * 分类依据是**实测**（tmp/alpine-probe*.js，把真 alpine.js 塞进浏览器逐项试），
 * 不是猜的：
 *
 *   值位（VALUE）—— 求值结果会被**消费**（显示出来 / 当条件用 / 当集合用）
 *     Alpine 走 Jn：`(async()=>{ ... })()` ⇒ **块体里的表达式值被丢弃**
 *     ⇒ 表达式以 if/let/const 开头 ⇒ 结果恒 undefined ⇒ 页面显示空白
 *
 *   副作用位（SIDE）—— 只关心**副作用**，返回值没人要
 *     Alpine 走 xr：`()=>{ ... })()` ⇒ 语句正常执行
 *     ⇒ `@click="if (confirm('...')) doLogout()"` 是 Alpine 官方推荐写法，
 *       **本来就该以 if 开头**
 *
 *   字面量位（LITERAL）—— 根本不求值，值是字符串字面量
 *     x-transition:enter="nfx-enter" / x-ref="someName"
 *     ⇒ 判据不能把它们当表达式扫
 */

/** 值位：属性名 → 提取表达式的正则（捕获组 1 = 表达式）。 */
/** 副作用位：允许（且常常应当）以 if/let/const 开头。 */
/** 字面量位：不求值，判据不管。 */
const LITERAL_ATTRS = [
  'x-transition:enter', 'x-transition:enter-start', 'x-transition:enter-end',
  'x-ref', 'x-cloak',
];

/**
 * Alpine 已知属性的全集（不在这张表里的属性 ⇒ 归类失败 ⇒ 判据报错）。
 *
 * 这张表是**故意留白**的：Alpine 将来加了新属性，我们不会自动放行，
 * 而是要求人工确认它的求值语义 —— 因为「归错类」的后果是
 * 静默漏检（比误报危险得多）。
 */
const KNOWN_ALPINE_ATTRS = new Set([
  'x-data', 'x-init', 'x-bind', 'x-on', 'x-model', 'x-modelable', 'x-show',
  'x-text', 'x-html', 'x-if', 'x-for', 'x-ref', 'x-cloak', 'x-ignore',
  'x-transition', 'x-teleport',
]);

/**
 * x-for 的求值对象是 **items 那半**（in / of 右边），不是整条表达式。
 *
 * 实测依据（tmp/alpine-probe2.js）：
 *   x-for="(i, idx) in ifList.filter(x => x > 7)" ⇒ 渲染 0 项（被当成语句）
 *   x-for="(i, idx) in ifList"                   ⇒ 渲染 3 项（没括号，不中招）
 *   x-for="(i, idx) in list.filter(...)"         ⇒ 渲染 2 项（正常）
 *
 * Alpine 的 x-for 解析（压缩后 mo()）把表达式切成 item / items，
 * 然后**只对 items 求值**。所以判据必须按同样的规则切。
 */
function splitForExpression(expr) {
  const m = String(expr).match(/([\s\S]*?)\s+(?:in|of)\s+([\s\S]*)/);
  return m ? m[2].trim() : null;
}

// ================================================================
// 第 3 组：值位表达式不得踩坑
// ================================================================
sec('第 3 组：值位表达式都不能以 if / let / const 开头');

/**
 * ⚠️ 这一组必须是**按属性分类驱动**的，不能靠「预先列好一串正则去抠」。
 *
 * 原因：自己变异脚本里的 A2 暴露过 ——
 * 往模板里塞一个**新属性**（x-data-x="ifBogus(iface)"），
 * 结果它不是被「值位检查」抓住的，是被末尾那条「属性分类完备性」兜底抓住的。
 *
 * 兜底能兜住只是一次运气 —— 兜底那条的语义是「这个属性我还没分类」，
 * 而它报出来的原因跟「表达式踩坑」完全是两回事。
 *
 * ⇒ 正确做法：**先把模板里每个 Alpine 属性归类，再按归类结果决定要不要查它的值**。
 *   · 归到值位的 ⇒ 它的表达式必须查
 *   · 归到副作用位的 ⇒ 不查（那是 Alpine 官方写法）
 *   · 归到字面量位的 ⇒ 不查（根本不求值）
 *   · 归不出来的 ⇒ 直接判失败（不许默默放过）
 */

/**
 * 一个属性名归到哪一类。
 *
 * 判定顺序有讲究 —— 先看前缀，再看具体名：
 *   @xxx / x-on:xxx   ⇒ 副作用位（事件处理器）
 *   :xxx / x-bind:xxx ⇒ 值位（绑定）
 *   x-transition:* / x-ref / x-cloak ⇒ 字面量位
 *   x-text / x-show / x-if / x-model / x-for ⇒ 值位
 *   x-data / x-init ⇒ x-data 是值位（组件对象），x-init 是副作用位
 */
function classifyAttr(n) {
  if (n.startsWith('@')) return '副作用位';
  if (n.startsWith(':')) return '值位';
  if (n.startsWith('x-on:')) return '副作用位';
  if (n.startsWith('x-bind:')) return '值位';
  if (n.startsWith('x-transition')) return '字面量位';
  if (LITERAL_ATTRS.includes(n)) return '字面量位';
  if (['x-text', 'x-html', 'x-show', 'x-if', 'x-model', 'x-for', 'x-data',
       'x-modelable'].includes(n)) return '值位';
  if (n === 'x-init') return '副作用位';
  if (KNOWN_ALPINE_ATTRS.has(n)) return '值位';
  return null;
}

// 把模板里所有 Alpine 属性连同它们的值抠出来。
// 属性名要带上修饰符（@click.self / x-model.number），
// 但归类时要把修饰符剥掉。
const ALL_ATTR_RE = /([:@]?[a-zA-Z][-a-zA-Z0-9_:.]*)\s*=\s*"([^"]*)"/g;
const allAlpineAttrs = [];
let ar;
while ((ar = ALL_ATTR_RE.exec(INDEX_HTML)) !== null) {
  const raw = ar[1];
  if (!raw.startsWith('x-') && !raw.startsWith(':') && !raw.startsWith('@')) continue;
  // 剥掉修饰符：@click.self → @click；x-model.number → x-model
  const base = raw.replace(/\.[a-z0-9.]+$/, '');
  allAlpineAttrs.push({ raw, base, value: ar[2] });
}

// 归类：分三桶，并单独收集「归不出来」的
const valueAttrs = [], sideAttrs = [], literalAttrs = [], unclassifiedAttrs = [];
for (const a of allAlpineAttrs) {
  const kind = classifyAttr(a.base);
  if (kind === '值位') valueAttrs.push(a);
  else if (kind === '副作用位') sideAttrs.push(a);
  else if (kind === '字面量位') literalAttrs.push(a);
  else unclassifiedAttrs.push(a);
}

check('模板里确实有 Alpine 属性（不为零，否则本文件是空转）',
  allAlpineAttrs.length > 0, '共 ' + allAlpineAttrs.length + ' 处');
check('模板里每个 Alpine 属性都能归类（不许默默放过新属性）',
  unclassifiedAttrs.length === 0,
  unclassifiedAttrs.length
    ? [...new Set(unclassifiedAttrs.map((a) => a.raw))].join(', ')
    : '值位 ' + valueAttrs.length + ' / 副作用位 ' + sideAttrs.length +
      ' / 字面量位 ' + literalAttrs.length);

// 值位表达式：x-for 特殊 —— 只查 items 那半
const valueExprs = [];
for (const a of valueAttrs) {
  if (!a.value.trim()) continue;
  if (a.base === 'x-for') {
    const items = splitForExpression(a.value);
    if (items) valueExprs.push({ kind: 'x-for:items', expr: items });
    continue;
  }
  valueExprs.push({ kind: a.base, expr: a.value });
}

check('抠到了值位表达式（不为零，否则本组是空转）', valueExprs.length > 0,
  '找到 ' + valueExprs.length + ' 条');

const badValue = valueExprs.filter((e) => alpineWrapsAsStatement(e.expr));
check('值位表达式里没有会被 Alpine 当成 if/let/const 语句的',
  badValue.length === 0,
  badValue.length ? badValue.map((e) => e.kind + ': ' + e.expr.slice(0, 70)).join(' ; ') : '');

if (badValue.length) {
  console.log('  （逐条列出）');
  badValue.forEach((e) => console.log('    ✗ [' + e.kind + '] ' + e.expr.slice(0, 110)));
}

// ================================================================
// 第 4 组：副作用位允许 if 开头（这是 Alpine 官方写法，不是 bug）
// ================================================================
sec('第 4 组：副作用位允许以 if 开头（判据不该在这里误报）');

const sideExprs = sideAttrs.filter((a) => a.value.trim())
  .map((a) => ({ kind: a.base, expr: a.value }));
check('抠到了副作用位表达式（不为零，否则第 4 组是空转）', sideExprs.length > 0,
  '找到 ' + sideExprs.length + ' 条');

// 副作用位里以 if 开头的**不是错误** —— 恰恰是 Alpine 文档推荐的写法。
// 这里断言它们确实存在（说明这条豁免是真的被用上了，不是空规则）。
const sideWithIf = sideExprs.filter((e) => alpineWrapsAsStatement(e.expr));
check('副作用位里确实有以 if 开头的语句式处理器（豁免规则被真实用到）',
  sideWithIf.length > 0,
  sideWithIf.length ? sideWithIf.map((e) => e.expr.slice(0, 60)).join(' ; ') : '一条都没有');

// 但反过来：**副作用位里也不该出现「看起来像求值却其实是语句」的东西**
// —— 比如 `x-init="foo()"` 是好的，`x-init="let x = 1"` 也没问题，
// 唯一要防的是把副作用位写成需要返回值的表达式（那是值位的活）。
// 这条靠「值位清单覆盖了所有消费值的位置」来保证 —— 见第 6 组。

// ================================================================
// 第 5 组：字面量位不参与求值判据
// ================================================================
sec('第 5 组：字面量位不进判据（否则会把 CSS 类名当表达式）');

let literalHits = literalAttrs.length;
check('模板里确实有用到字面量位属性（这条分类不是空规则）', literalHits > 0,
  '找到 ' + literalHits + ' 处');

// 字面量位的值即使长得像表达式，也不该被求值。
// 断言判据确实没把它们扫进来：把它们全部喂给 alpineWrapsAsStatement，
// 看有多少会被判为「语句」—— 如果这个数不为 0，说明判据**必须**把它们排除，
// 也就说明「排除字面量位」这条分类是必需的，而不是多余的严格。
const literalLooksRisky = literalAttrs
  .filter((a) => alpineWrapsAsStatement(a.value))
  .map((a) => a.base + '="' + a.value + '"');
check('字面量位的值不会被误判（说明按位置分类是必要的）',
  literalLooksRisky.length === 0,
  literalLooksRisky.length ? literalLooksRisky.join(' ; ') : '');

// ================================================================
// 第 6 组：app.js 里的方法名也不能踩这个坑（防患于未然）
// ================================================================
sec('第 6 组：app.js 方法名不能以 if/let/const 开头（比模板更早抓到）');

/**
 * 为什么查方法名：
 *   模板里 `x-text="ifaceDetail(iface)"` 是**症状**；
 *   真正该改的是**方法名** —— 名字叫 ifaceDetail 的方法，
 *   将来任何人写 `x-text="ifaceDetail(x)"` 都会中招。
 *   所以判据要比被测对象更强：在方法定义处就拦住。
 *
 * ⚠️ 提取方法名必须避开 **JS 语句**：
 *   app.js 里 4 空格缩进的 `if (this.ddns.editingIsNew) {` 这种语句，
 *   用宽松正则会连它一起抓走（第一版就误报了 6 个 "if"）。
 *   ⇒ 这里用**行首锚定 + 排除关键字**的方式提取。
 */
const JS_KEYWORDS = new Set([
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
  'return', 'break', 'continue', 'function', 'try', 'catch', 'finally',
  'throw', 'new', 'delete', 'typeof', 'instanceof', 'in', 'of', 'void',
  'await', 'async', 'class', 'extends', 'super', 'this', 'const', 'let', 'var',
]);

// 方法定义的形状：行首（可缩进）→ 标识符 → ( → 参数 → ) → {
// 排除关键字 ⇒ `if (...) {` 这类语句不会被当成方法。
const methodRe = /^[ \t]*([A-Za-z_$][\w$]*)[ \t]*\([^()]*\)[ \t]*\{/gm;
const methodNames = [];
let mm;
while ((mm = methodRe.exec(APP_JS)) !== null) {
  if (JS_KEYWORDS.has(mm[1])) continue;
  methodNames.push(mm[1]);
}
check('从 app.js 抠到了方法名（不为零，否则本组是空转）', methodNames.length > 0,
  '找到 ' + methodNames.length + ' 个');

const riskyMethods = methodNames.filter((n) => alpineWrapsAsStatement(n + '(x)'));
check('没有方法名会让 Alpine 把调用当成 if 语句', riskyMethods.length === 0,
  riskyMethods.length ? riskyMethods.join(', ') : '');

// 顺带自证：提取方法名时确实排除了 JS 关键字
check('提取方法名时排除了 JS 关键字（if/for/while 等没被当方法）',
  !methodNames.some((n) => JS_KEYWORDS.has(n)),
  methodNames.filter((n) => JS_KEYWORDS.has(n)).join(', ') || '');

// ================================================================
// 第 7 组：判据自证（拿抽出来的正则做自证）
// ================================================================
sec('第 7 组：判据自证（Alpine 正则的实际行为）');

check('`ifaceDetail(iface)` 会被当成语句（这正是本轮踩的坑）',
  alpineWrapsAsStatement('ifaceDetail(iface)'));
check('`if (a) b` 会被当成语句',
  alpineWrapsAsStatement('if (a) b'));
check('`fmtRate(2048)` 不会（不以 if 开头）',
  !alpineWrapsAsStatement('fmtRate(2048)'));
check('`fmtRate(iface.rx_bps)` 不会（if 不在开头）',
  !alpineWrapsAsStatement('fmtRate(iface.rx_bps)'));
check('`let x = 1` 会被当成语句',
  alpineWrapsAsStatement('let x = 1'));
check('`const x = 1` 会被当成语句',
  alpineWrapsAsStatement('const x = 1'));
check('`letThing(v)` 不会（let 后面没有空格，正则要求 let+空白）',
  !alpineWrapsAsStatement('letThing(v)'));
check('`detailOf(iface)` 不会（改名后的方法名是安全的）',
  !alpineWrapsAsStatement('detailOf(iface)'));

// ================================================================
// 收尾
// ================================================================
console.log('\n' + '='.repeat(60));
console.log('  通过 ' + PASS.length + ' / 失败 ' + FAIL.length);
if (FAIL.length) console.log('  失败项: ' + JSON.stringify(FAIL));
console.log('='.repeat(60));
process.exit(FAIL.length ? 1 : 0);
