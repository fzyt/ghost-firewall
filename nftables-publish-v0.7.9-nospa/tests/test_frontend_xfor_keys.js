/* Alpine x-for 的 :key 不能用「内容」当键 —— 内容会重复，重复键会让 Alpine 崩
 *
 * 运行: node tests/test_frontend_xfor_keys.js
 *
 * 背景（2026-10-30 在 .232 真机上用 Playwright 抓到）
 * ---------------------------------------------------------------
 * 在面板上点「保存配置」，**7 个页面全部**抛同一个 JS 异常：
 *
 *     Alpine Expression Error: Cannot read properties of undefined (reading 'after')
 *     Expression: "diffModal.diff?.added_sample || []"
 *     Alpine Warning: Duplicate key on x-for
 *
 * 根因在 Alpine 3.15.8 的 x-for 重排逻辑（alpine.js 第 5 行）：
 *
 *     for (let f = 0; f < v.length; f++) {
 *         let [m, b] = v[f], E = a[m], C = a[b], nt = document.createElement("div");
 *         h(() => {
 *             C || w('x-for ":key" is undefined or invalid', o, b, a),
 *             C.after(nt), E.after(C), ...
 *
 * 键重复时 `a[b]` 取到 undefined ⇒ `C` 是 undefined ⇒ Alpine **只是警告**，
 * 然后继续执行 `C.after(nt)` ⇒ TypeError。整个弹窗的渲染就断了。
 *
 * 而前端的写法是：
 *     <template x-for="line in diffModal.diff?.added_sample || []" :key="line">
 *                                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *                                  键 = 行内容
 *
 * `added_sample` 是**规则文本的行**（后端 app.py: added[:15]）。
 * 规则里空行、重复的 `}`、重复的注释都有 —— 实测规则模板
 * （backend/templates/nftables.conf）**前 15 行里空行就出现 3 次**
 * ⇒ 用行内容当键，**必然**重复 ⇒ 必然崩。
 *
 * 这就是为什么 curl 级验收查不出来：HTTP 200、配置也确实存下去了，
 * 崩的是浏览器里的 Alpine 渲染。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const HTML = fs.readFileSync(path.join(ROOT, 'frontend', 'index.html'), 'utf8');
const TPL = fs.readFileSync(path.join(ROOT, 'backend', 'templates', 'nftables.conf'), 'utf8');

const PASS = [], FAIL = [];
const check = (name, ok, detail = '') => {
  (ok ? PASS : FAIL).push(name);
  console.log((ok ? '  ✅ ' : '  ❌ ') + name + (detail ? '  — ' + detail : ''));
};
const sec = (t) => console.log('\n=== ' + t + ' ===');

console.log('='.repeat(74));
console.log('Alpine x-for 的 :key 不能用内容当键（重复键会让整页渲染崩掉）');
console.log('='.repeat(74));

/* ---------- 1. 把所有 x-for 连同 :key 抠出来 ---------- */
sec('1. frontend/index.html 里所有 x-for 的 :key');

const xfors = [];
const tagRe = /<template\b[^>]*\bx-for="([^"]*)"[^>]*>/g;
let m;
while ((m = tagRe.exec(HTML)) !== null) {
  const tag = m[0];
  const km = tag.match(/:key="([^"]*)"/) || tag.match(/x-bind:key="([^"]*)"/);
  xfors.push({
    expr: m[1],
    key: km ? km[1] : null,
    pos: HTML.slice(0, m.index).split('\n').length,
    tag,
  });
}
check('页面上有 x-for（否则下面的断言是空的）', xfors.length > 0, `${xfors.length} 处`);

// 允许的 :key 形式：
//   1) 索引变量本身（index / idx）
//   2) 含索引变量的拼接式（log.epoch + '_' + idx + ...）
//   3) <元素变量>.<字段>，字段 ∈ {id, key, ip} —— 这些字段在各自的数据结构里唯一
//   4) 恰好是 source —— 那是 Object.entries() 的键，天然唯一
const INDEX_RE = /^(index|idx)$/;
const FIELD_RE = /^[A-Za-z_$][\w$]*\.(id|key|ip)$/;
function keyIsSafe(k) {
  if (k === null) return false;
  if (INDEX_RE.test(k)) return true;
  if (FIELD_RE.test(k)) return true;
  if (/\b(idx|index)\b/.test(k)) return true;      // 拼接式里含索引
  if (k === 'source') return true;                  // Object.entries 的键
  return false;
}

const noKey = xfors.filter(x => x.key === null);
const unsafe = xfors.filter(x => x.key !== null && !keyIsSafe(x.key));
check('每个 x-for 都写了 :key', noKey.length === 0,
  noKey.length ? noKey.map(x => `L${x.pos} ${x.expr}`).join('; ') : '');
check('每个 :key 都是「唯一」的形式（索引 / id / key / ip，不用内容本身）',
  unsafe.length === 0,
  unsafe.length ? unsafe.map(x => `L${x.pos} ${x.expr} :key="${x.key}"`).join('; ') : '');

console.log('  （逐条列出，key 为索引或稳定 id 的都合法）');
xfors.forEach(x => {
  const ok = x.key !== null && keyIsSafe(x.key);
  console.log(`    ${ok ? '·' : '✗'} L${x.pos} :key=${x.key}   ← ${x.expr}`);
});

/* ---------- 2. 证明「内容当键」必然撞车 ---------- */
sec('2. 证明 added_sample/removed_sample 的内容**不可能**唯一');

const tplLines = TPL.split('\n');
const first15 = tplLines.slice(0, 15);
const counts = {};
first15.forEach(l => { counts[l] = (counts[l] || 0) + 1; });
const dups = Object.entries(counts).filter(([, v]) => v > 1);

check('规则模板的前 15 行里确实有重复行（所以「行内容当键」必然撞车）',
  dups.length > 0,
  dups.length ? dups.map(([k, v]) => `${JSON.stringify(k)}×${v}`).join(' ') : '没有重复');
check('重复的是空行（最常见的来源）',
  dups.some(([k]) => k === ''),
  dups.length ? `${dups.length} 个重复值` : '');

/* ---------- 3. 具体到出事的三个 x-for ---------- */
sec('3. 出事的三个 x-for 必须用索引当键');

function findXfor(fragment) {
  return xfors.find(x => x.expr.includes(fragment));
}
const sampleAdded = findXfor('added_sample');
const sampleRemoved = findXfor('removed_sample');
const risks = findXfor('diffModal.risks');

check('找得到 added_sample 那个 x-for', !!sampleAdded);
check('找得到 removed_sample 那个 x-for', !!sampleRemoved);
check('找得到 diffModal.risks 那个 x-for', !!risks);

if (sampleAdded) {
  check('added_sample 用索引当键（不能用行内容）',
    INDEX_RE.test(sampleAdded.key || ''),
    `:key="${sampleAdded.key}"`);
}
if (sampleRemoved) {
  check('removed_sample 用索引当键（不能用行内容）',
    INDEX_RE.test(sampleRemoved.key || ''),
    `:key="${sampleRemoved.key}"`);
}
if (risks) {
  // risk.message 也可能是重复的（两条告警文案相同就撞）⇒ 同样用索引
  check('risks 用索引当键（message 可能重复）',
    INDEX_RE.test(risks.key || ''),
    `:key="${risks.key}"`);
}

/* ---------- 4. 迭代变量必须带下标 ---------- */
sec('4. 用索引当键的前提：x-for 必须解出下标');

for (const [name, xf] of [['added_sample', sampleAdded], ['removed_sample', sampleRemoved], ['risks', risks]]) {
  if (!xf) continue;
  // x-for="(line, idx) in ..." —— 第二个变量就是下标
  const vm = xf.expr.match(/^\(([^)]*)\)\s+in\s+/);
  const vars = vm ? vm[1].split(',').map(s => s.trim()) : [];
  check(`${name} 的 x-for 解出了下标变量`,
    vars.length >= 2 && INDEX_RE.test(vars[1]),
    `x-for="${xf.expr}" → 变量 [${vars.join(', ')}]`);
}

console.log('\n' + '='.repeat(74));
console.log(`通过 ${PASS.length} / 失败 ${FAIL.length}`);
if (FAIL.length) {
  console.log('失败项:');
  FAIL.forEach((f) => console.log('  - ' + f));
  process.exit(1);
}
console.log('全部通过');
