/* 批 C（面板可用性）的前端行为测试（Node + 最小桩，无 npm 依赖）
 *
 * 运行: node tests/test_frontend_aliyun_batch_c.js
 *
 * 测两条
 * ------
 * M5  CNAME / TXT 的「测试」按钮传了空 value ⇒ 后端恒 400 ⇒ 按钮完全不可用
 * L8  点「获取记录」会把 localRecords **清空** ⇒ 随后的保存把
 *     enabled / ipv6_source 全丢掉 ⇒ 用户配的记录全变成未启用
 *
 * 为什么是行为级
 * --------------
 * 「源码里出现了某个字符串」这种断言在下面这些改法下**照样通过**：
 *   · 把 value 的三元表达式换成另一个写法；
 *   · 把 localRecords 的赋值挪到别的地方；
 *   · 把 `|| []` 换成 `|| this.aliyun.localRecords`（这恰恰是**要**的修法，
 *     但源码里同样会出现 `localRecords`）。
 * ⇒ 判据落在**真的发出去的那个请求体**上，和**真的被清空的那个数组**上。
 *
 * ⚠ 不碰网络：fetch 被换成桩，只记录调用。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

let P = 0, F = 0;
const ok = (n, c, x) => {
  if (c) { P++; console.log('  [PASS] ' + n); }
  else { F++; console.log('  [FAIL] ' + n + '  ' + (x || '')); }
};
const eq = (n, a, b) => ok(n, JSON.stringify(a) === JSON.stringify(b),
  `实际=${JSON.stringify(a)} 期望=${JSON.stringify(b)}`);

const DIR = path.join(__dirname, '..');
const SRC = fs.readFileSync(path.join(DIR, 'frontend', 'app.js'), 'utf8');

// ── 最小桩 ────────────────────────────────────────────────
let fetchCalls = [];
let fetchImpl = null;
const sandbox = {
  console,
  fetch: (...a) => { fetchCalls.push(a); return fetchImpl(...a); },
  document: { addEventListener: () => {}, querySelectorAll: () => [] },
  window: { addEventListener: () => {}, dispatchEvent: () => {} },
  CustomEvent: function (type, init) { this.type = type; this.detail = init && init.detail; },
  setTimeout, clearTimeout, setInterval, clearInterval,
  URL, URLSearchParams, Blob: function () {}, FormData: function () {},
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(SRC, sandbox, { filename: 'app.js' });

function resp(body, status) {
  return {
    status: status === undefined ? 200 : status,
    headers: { get: () => null },
    json: async () => body,
  };
}

// ── M5：测试按钮传的 value ─────────────────────────────────
console.log('\n=== M5：CNAME / TXT 的测试按钮传的 value ===');

async function callTest(rec) {
  const comp = sandbox.app();
  comp.aliyun.records = [rec];
  comp.aliyun.localRecords = [];
  comp.ddns = { loaded: true, ipv6Sources: [] };
  fetchCalls = [];
  fetchImpl = async () => resp({ success: true, message: 'ok' });
  await comp.testAliyunRecord(0);
  const call = fetchCalls.find(c => c[0] === '/api/aliyun-ddns/test');
  if (!call) return null;
  return JSON.parse(call[1].body);
}

(async () => {
  const a = await callTest({ RR: 'www', Type: 'A', Value: '1.1.1.1', RecordId: '1' });
  ok('A 记录传空 value（让后端去取当前公网 IP）',
    a && a.value === '', JSON.stringify(a));
  ok('A 记录带上了精确的 record_id',
    a && a.record_id === '1', JSON.stringify(a));

  const aaaa = await callTest({ RR: 'www6', Type: 'AAAA', Value: '::1', RecordId: '2' });
  ok('AAAA 记录传空 value（让后端读中转文件）',
    aaaa && aaaa.value === '', JSON.stringify(aaaa));

  const cname = await callTest({ RR: 'www', Type: 'CNAME', Value: 'target.example.com', RecordId: '3' });
  ok('CNAME 记录传**阿里云上现存的**值（不再传空）',
    cname && cname.value === 'target.example.com', JSON.stringify(cname));

  const txt = await callTest({ RR: 'txt', Type: 'TXT', Value: '"v=spf1 ~all"', RecordId: '4' });
  ok('TXT 记录传**阿里云上现存的**值（不再传空）',
    txt && txt.value === '"v=spf1 ~all"', JSON.stringify(txt));

  const lower = await callTest({ rr: 'www', type: 'CNAME', value: 'lower.example.com' });
  ok('小写的类型名也认（本地配置里可能是小写）',
    lower && lower.value === 'lower.example.com', JSON.stringify(lower));

  const lowerA = await callTest({ rr: 'www', type: 'A', value: '1.1.1.1' });
  ok('小写的 a 也算 A 记录（传空值让后端自动取）',
    lowerA && lowerA.value === '', JSON.stringify(lowerA));

  // ── L8：点「获取记录」不能清空 localRecords ───────────────
  console.log('\n=== L8：点「获取记录」不能清空 localRecords ===');

  // 后端返回了 localRecords
  let comp = sandbox.app();
  comp.ddns = { loaded: true, ipv6Sources: [] };
  comp.aliyun.localRecords = [{ rr: 'www', type: 'A', enabled: true, ipv6_source: 'router' }];
  fetchCalls = [];
  fetchImpl = async () => resp({
    success: true,
    records: [{ rr: 'www', type: 'A', value: '1.1.1.1', enabled: true, ipv6_source: 'router' }],
    localRecords: [{ rr: 'www', type: 'A', value: '1.1.1.1', enabled: true, ipv6_source: 'router' }],
  });
  await comp.loadAliyunRecords();
  ok('后端返回 localRecords 时被采用',
    comp.aliyun.localRecords.length === 1
    && comp.aliyun.localRecords[0].enabled === true,
    JSON.stringify(comp.aliyun.localRecords));

  // 后端**没有**返回 localRecords（旧后端 / 缓存）—— 绝不能清空
  comp = sandbox.app();
  comp.ddns = { loaded: true, ipv6Sources: [] };
  comp.aliyun.localRecords = [{ rr: 'www', type: 'A', enabled: true, ipv6_source: 'router' }];
  fetchCalls = [];
  fetchImpl = async () => resp({
    success: true,
    records: [{ rr: 'www', type: 'A', value: '1.1.1.1' }],
  });
  await comp.loadAliyunRecords();
  ok('后端没返回 localRecords 时**保留**原有那份（不被清空）',
    comp.aliyun.localRecords.length === 1
    && comp.aliyun.localRecords[0].enabled === true,
    JSON.stringify(comp.aliyun.localRecords));

  // 记录列表本身还是要更新
  ok('记录列表正常刷新',
    Array.isArray(comp.aliyun.records) && comp.aliyun.records.length === 1,
    JSON.stringify(comp.aliyun.records));

  console.log('\n' + '='.repeat(60));
  console.log(`  通过 ${P} / 失败 ${F}`);
  console.log('='.repeat(60));
  process.exit(F ? 1 : 0);
})().catch(e => {
  console.log('  [FAIL] 测试脚本自身抛异常: ' + (e && e.stack ? e.stack : e));
  console.log('='.repeat(60));
  process.exit(1);
});
