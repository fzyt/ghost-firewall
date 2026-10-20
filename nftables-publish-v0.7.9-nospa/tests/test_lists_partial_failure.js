/* 名单面板「部分失败不能整片空白」的接线测试
 *
 * 运行: node tests/test_lists_partial_failure.js
 *
 * 为什么要有这个
 * --------------
 * 用户报的原始症状是「预设加进去了依旧不显示」，页面上写着「暂无预设」。
 * 第十七节定位到根因是**读错一层**（信封没拆），已由 unwrap() + 契约测试修掉。
 *
 * 但 2026-10-19 搭 Docker 测试环境时又撞见**第二个**能造成一模一样症状的缺陷：
 *
 *   loadLists() 里
 *     const [whitelist, blacklist, presets, history] = await Promise.all([
 *       api.get('/api/lists/whitelist'),        ← 没有 .catch()
 *       api.get('/api/lists/blacklist'),        ← 没有 .catch()
 *       api.get('/api/lists/presets').catch(...),
 *       api.get('/api/lists/history?...').catch(...),
 *     ]);
 *
 * 白名单/黑名单要读 nft 规则集。读不到时（nft 没装 / 规则集临时不可读 /
 * 正在重载）这两个请求会抛错，而 Promise.all 是**一错全错** ——
 * 整个 Promise.all 直接 reject，下面那四行赋值**一行都不执行**，
 * ipPresets 也就永远停在初始的 []。
 *
 * 结果：预设明明在后端存着，界面上却是「暂无预设」。
 * 和第十七节那个 bug 的**症状一模一样**，但根因完全无关 ——
 * 用户没法从界面分辨「没有预设」和「没读到预设」，
 * 而这两件事的处理方式完全相反。
 *
 * 这个测试测的是**接线**，不是 helper：
 *   · 真的调用组件的 loadLists() 方法
 *   · 真的断言组件状态（ipPresets / listsData / toast）
 *   · 用的是从 Docker 环境抓下来的**真实响应**（tests/fixtures/lists_responses.json）
 *
 * 只判 unwrap 之类的 helper 是**不够**的 —— 第十七节已经证明过：
 * 静态/单元断言全绿，界面照样是空的。
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
const FIX = JSON.parse(fs.readFileSync(
  path.join(DIR, 'tests', 'fixtures', 'lists_responses.json'), 'utf8'));

// ── 最小桩 ────────────────────────────────────────────────
// fetchImpl 由每个用例设置：url → {status, body}
let fetchImpl = null;
let fetchCalls = [];
const sandbox = {
  console,
  fetch: (url) => { fetchCalls.push(url); return fetchImpl(url); },
  document: { addEventListener: () => {}, querySelectorAll: () => [] },
  window: { addEventListener: () => {}, dispatchEvent: () => {} },
  CustomEvent: function (type, init) {
    this.type = type;
    this.detail = init && init.detail;
  },
  setTimeout, clearTimeout, setInterval, clearInterval,
  URL, URLSearchParams, Blob: function () {}, FormData: function () {},
  confirm: () => true,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(SRC + '\n;globalThis.__app = app; globalThis.__api = api;',
  sandbox, { filename: 'app.js' });

const makeApp = sandbox.__app;

/** 让某个 URL 失败（后端 500：nft 读不到），其余正常 */
function route(map) {
  fetchImpl = async (url) => {
    const key = Object.keys(map).find((k) => url.includes(k));
    const r = key ? map[key] : { status: 200, body: { success: true, data: {} } };
    return {
      status: r.status,
      headers: { get: () => null },
      json: async () => r.body,
    };
  };
}

function newApp() {
  const c = makeApp();
  c.toast = { show: false, message: '', type: '' };
  c.showToast = function (message, type) {
    this.toast = { show: true, message, type };
  };
  return c;
}

(async () => {
  console.log('\n▶ 用例 1：四个接口全部正常');

  {
    const c = newApp();
    fetchCalls = [];
    route({
      '/api/lists/presets': { status: 200, body: FIX.presets },
      '/api/lists/whitelist': { status: 200, body: FIX.whitelist_ok },
      '/api/lists/blacklist': { status: 200, body: FIX.blacklist_ok },
      '/api/lists/history': { status: 200, body: FIX.history },
    });
    await c.loadLists();

    eq('确实请求了 4 个接口（自我证明：别让桩把测试变成空转）',
      fetchCalls.length, 4);
    eq('ipPresets 读到 2 条预设', c.ipPresets.length, 2);
    eq('第一条预设的 IP 正确', c.ipPresets[0] && c.ipPresets[0].ip, '203.0.113.10');
    eq('第二条预设的标签正确', c.ipPresets[1] && c.ipPresets[1].label, 'docker测试');
    ok('listHistory 是数组', Array.isArray(c.listHistory));
    // ⚠️ 这些断言必须能区分「读到了真实数据」和「读失败退化成空」——
    // 组件初始值就是空的，fixture 里的内容也必须非空。
    // 否则「少读一层」「没兜底」这类变异会从缝里漏过去。
    eq('白名单读到 2 个真实 IP（不是退化的空）',
      Object.keys(c.listsData.whitelist.ipv4).length, 2);
    eq('黑名单读到 1 个真实 IP',
      Object.keys(c.listsData.blacklist.ipv4).length, 1);
    eq('最近操作读到 1 条',
      c.listHistory.length, 1);
    ok('没有报错 toast', !c.toast.show, c.toast.message || '');
  }

  console.log('\n▶ 用例 2：白名单/黑名单读不到（Docker 场景：没装 nft）');
  console.log('   —— 这是本次要修的核心：不能把整个名单面板拖成空白');

  {
    const c = newApp();
    fetchCalls = [];
    route({
      '/api/lists/presets': { status: 200, body: FIX.presets },
      '/api/lists/whitelist': { status: 503, body: FIX.nft_unavailable },
      '/api/lists/blacklist': { status: 503, body: FIX.nft_unavailable },
      '/api/lists/history': { status: 200, body: FIX.history },
    });
    await c.loadLists();

    eq('ipPresets 仍然读到 2 条预设（关键断言）', c.ipPresets.length, 2);
    eq('预设内容没被清空', c.ipPresets[0] && c.ipPresets[0].ip, '203.0.113.10');
    eq('白名单退化成空（0 个 IP）而不是 undefined',
      Object.keys(c.listsData.whitelist.ipv4 || {}).length, 0);
    eq('黑名单退化成空（0 个 IP）而不是 undefined',
      Object.keys(c.listsData.blacklist.ipv4 || {}).length, 0);
    // 「没有 nft」是**环境固有**不是故障 ⇒ 不该弹红色 toast，
    // 但必须在卡片里给出说明（listsNftUnavailable）。
    ok('没有弹红色 toast（环境固有，不是故障）',
      !c.toast.show, c.toast.message || '');
    eq('标记了「nft 不可用」，前端据此显示内联说明',
      c.listsNftUnavailable, true);
  }

  console.log('\n▶ 用例 2b：真故障（不是 nft 缺失）仍然要报警');

  {
    const c = newApp();
    route({
      '/api/lists/presets': { status: 200, body: FIX.presets },
      '/api/lists/whitelist': { status: 500, body: FIX.generic_failure },
      '/api/lists/blacklist': { status: 500, body: FIX.generic_failure },
      '/api/lists/history': { status: 200, body: FIX.history },
    });
    await c.loadLists();

    eq('ipPresets 仍然读到 2 条预设（失败没传染）', c.ipPresets.length, 2);
    ok('真故障**要**弹 toast 报警',
      c.toast.show === true, 'toast 没弹');
    ok('toast 里提到了读取失败',
      /失败|读不到/.test(c.toast.message || ''), c.toast.message || '(空)');
    eq('没有标记成「nft 不可用」（那是环境固有的说法）',
      c.listsNftUnavailable, false);
  }

  console.log('\n▶ 用例 3：预设接口本身失败（不能装作「没有预设」）');

  {
    const c = newApp();
    route({
      '/api/lists/presets': { status: 500, body: FIX.generic_failure },
      '/api/lists/whitelist': { status: 200, body: FIX.whitelist_ok },
      '/api/lists/blacklist': { status: 200, body: FIX.blacklist_ok },
      '/api/lists/history': { status: 200, body: FIX.history },
    });
    await c.loadLists();

    eq('ipPresets 退化成空数组', c.ipPresets.length, 0);
    ok('仍然有 toast 说明读不到',
      c.toast.show === true, 'toast 没弹');
    // 关键：失败**不能传染**给别的请求。
    // 白名单和历史这时都读得到，读到的必须是真实数据（2 个 IP / 1 条历史），
    // 而不是"没赋值所以还是初始的空"。
    eq('白名单仍读到 2 个真实 IP（失败没传染）',
      Object.keys(c.listsData.whitelist.ipv4 || {}).length, 2);
    eq('最近操作仍读到 1 条（失败没传染）',
      c.listHistory.length, 1);
  }

  console.log('\n▶ 用例 5：最近操作接口失败（四个端点都得有失败场景）');

  {
    const c = newApp();
    route({
      '/api/lists/presets': { status: 200, body: FIX.presets },
      '/api/lists/whitelist': { status: 200, body: FIX.whitelist_ok },
      '/api/lists/blacklist': { status: 200, body: FIX.blacklist_ok },
      '/api/lists/history': { status: 500, body: FIX.generic_failure },
    });
    await c.loadLists();

    eq('ipPresets 仍读到 2 条预设（失败没传染）', c.ipPresets.length, 2);
    eq('白名单仍读到 2 个真实 IP（失败没传染）',
      Object.keys(c.listsData.whitelist.ipv4 || {}).length, 2);
    eq('最近操作退化成空数组', c.listHistory.length, 0);
    ok('有 toast 说明读不到',
      c.toast.show === true, 'toast 没弹');
  }

  console.log('\n▶ 用例 6：loadListPresets 单读也不受牵连');

  {
    const c = newApp();
    route({ '/api/lists/presets': { status: 200, body: FIX.presets } });
    await c.loadListPresets();
    eq('loadListPresets 读到 2 条', c.ipPresets.length, 2);
  }

  console.log('\n' + '='.repeat(60));
  console.log(` 合计: ✅ ${P}   ❌ ${F}`);
  console.log(F ? ' 有失败' : ' 全部通过');
  console.log('='.repeat(60));
  process.exit(F ? 1 : 0);
})();
