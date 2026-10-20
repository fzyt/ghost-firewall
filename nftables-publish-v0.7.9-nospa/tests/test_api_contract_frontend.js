/* 前端解包契约的行为测试（Node + 最小桩，无 npm 依赖）
 *
 * 运行: node tests/test_api_contract_frontend.js
 *
 * 为什么要有这个
 * --------------
 * `tests/test_api_contract.py` 做的是**静态对账**：后端每个 (路由,方法) 的
 * 返回形状，跟前端每个调用点实际取的字段逐一对账。它管的是「读哪一层」。
 *
 * 但它管不到**解包函数本身**是不是还在干活 ——
 * 如果 `unwrap()` 哪天被改成空操作（`const unwrap = (r) => r || {}`），
 * 静态对账照样全绿（因为它只关心"前端写了 unwrap(...)"这个形式），
 * 而界面上所有读信封的字段会集体失效 —— 预设列表、历史、规则健康
 * 全部回到"永远空"的老样子。
 *
 * 所以这里用**行为**把 unwrap 的语义钉死：
 *   信封式 → 钻进去拿到内层
 *   平铺式 → 原样返回
 *   空值   → 返回 {}，不让调用方炸在 undefined 上
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

let P = 0, F = 0;
const ok = (n, c, x) => {
  if (c) { P++; console.log('  ✅ ' + n); }
  else { F++; console.log('  ❌ ' + n + '  ' + (x || '')); }
};
const eq = (n, a, b) => ok(n, JSON.stringify(a) === JSON.stringify(b),
  `实际=${JSON.stringify(a)} 期望=${JSON.stringify(b)}`);

const DIR = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(DIR, 'frontend', 'app.js'), 'utf8');

// ── 最小桩 ────────────────────────────────────────────────
let fetchImpl = null;
const sandbox = {
  console,
  fetch: (...a) => fetchImpl(...a),
  document: { addEventListener: () => {} },
  window: { addEventListener: () => {}, dispatchEvent: () => {} },
  CustomEvent: function (type, init) {
    this.type = type;
    this.detail = init && init.detail;
  },
  setTimeout, clearTimeout, setInterval, clearInterval,
  URL, URLSearchParams, Blob: function () {}, FormData: function () {},
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

// 把 unwrap / api 暴露出来（模块级 const 不会自动挂到全局）
vm.runInContext(SRC + '\n;globalThis.__unwrap = unwrap; globalThis.__api = api;',
  sandbox, { filename: 'app.js' });

const unwrap = sandbox.__unwrap;
const api = sandbox.__api;

console.log('\n▶ unwrap() 的语义');

// 信封式：{success, data:{...}} → 拿到内层
eq('unwrap 钻 data 信封',
  unwrap({ success: true, data: { presets: [1, 2] } }),
  { presets: [1, 2] });

// 平铺式：{success, presets:[...]} → 原样
eq('unwrap 对平铺式原样返回',
  unwrap({ success: true, presets: [1, 2] }),
  { success: true, presets: [1, 2] });

// 空值：不让调用方炸在 undefined 上
eq('unwrap(null) → {}', unwrap(null), {});
eq('unwrap(undefined) → {}', unwrap(undefined), {});

// data 是 null 时不能返回 null（调用方会接着 .presets 炸掉）
ok('unwrap({data:null}) 不返回 null',
  unwrap({ data: null }) && typeof unwrap({ data: null }) === 'object');

// data 是非对象（标量）时保持原样，不吞掉
eq('unwrap({data:"x"}) 保持原样',
  unwrap({ data: 'x' }), { data: 'x' });

// 内层是数组时也要能拿到
ok('unwrap 对数组型 data 生效',
  Array.isArray(unwrap({ data: [1, 2, 3] })));

// 不能把内层的字段弄丢
eq('unwrap 保留内层全部字段',
  Object.keys(unwrap({ data: { a: 1, b: 2, c: 3 } })).sort(),
  ['a', 'b', 'c']);

console.log('\n▶ api.request 的行为（用 mock fetch）');

function mockFetch(status, body) {
  fetchImpl = async () => ({
    status,
    headers: { get: () => null },
    json: async () => body,
  });
}

(async () => {
  // 信封式：api.request 只剥顶层 success/message，data 信封原样保留
  mockFetch(200, { success: true, data: { presets: [{ ip: '1.2.3.4' }] } });
  const env = await api.get('/api/lists/presets');
  ok('api.request 保留 data 信封（这是契约的前提）',
    env && env.data && Array.isArray(env.data.presets),
    JSON.stringify(env));
  eq('unwrap(信封) 拿到内层 presets',
    unwrap(env).presets, [{ ip: '1.2.3.4' }]);

  // 平铺式
  mockFetch(200, { success: true, presets: [{ ip: '5.6.7.8' }] });
  const flat = await api.get('/api/lists/whitelist');
  eq('unwrap(平铺) 拿到顶层 presets',
    unwrap(flat).presets, [{ ip: '5.6.7.8' }]);

  // 错误分支
  mockFetch(400, { success: false, message: '参数错误' });
  let threw = null;
  try { await api.get('/api/x'); } catch (e) { threw = e; }
  ok('success=false 会抛错', threw && /参数错误/.test(threw.message || ''),
    threw ? threw.message : '没抛');

  // 401
  mockFetch(401, { success: false, code: 'AUTH_REQUIRED', message: '未登录' });
  threw = null;
  try { await api.get('/api/x'); } catch (e) { threw = e; }
  ok('401 会抛错且带 code',
    threw && threw.code === 'AUTH_REQUIRED', threw ? JSON.stringify(threw.message) : '没抛');

  console.log('\n' + '='.repeat(60));
  console.log(` 合计: ✅ ${P}   ❌ ${F}`);
  console.log(F ? ' 有失败' : ' 全部通过');
  console.log('='.repeat(60));
  process.exit(F ? 1 : 0);
})();
