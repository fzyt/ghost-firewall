/* 路由器「系统信息」页的前后端契约与展示逻辑测试
 *
 * 运行: node tests/test_frontend_system_info.js
 *
 * 测什么有效
 * ----------
 * 这个页面的字段**全部**来自后端 `backend/device_info.py`，
 * 前端模板里写的是 `deviceInfo.data.os.pretty_name` 这样的路径。
 * 两边只要有一个字段名对不上，页面上就是一片空白 ——
 * 而且是**静默**的空白（Alpine 的 x-text 遇到 undefined 不报错）。
 *
 * 所以光「能打开」不够，必须验：
 *   1. 后端实际返回的字段名，与前端模板里引用的字段名**逐一对应**
 *   2. 格式化函数遇到 null/undefined/0 时的行为
 *      （读不到要显示「未知」，显示 0 是**撒谎** —— 内存 0 KB 会被
 *       误读成「设备没有内存」）
 *
 * 为什么格式化函数要**真跑**而不是文本匹配
 * ---------------------------------------
 * 文本匹配只能证明「代码里写了 fmtKb」，
 * 证明不了「fmtKb(null) 真的返回 '未知' 而不是 'null KB'」。
 * 所以这里把方法体抽出来、在一个假的 this 上**真跑一遍**。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const APP_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');
const INDEX_HTML = fs.readFileSync(path.join(ROOT, 'frontend', 'index.html'), 'utf8');

const PASS = [], FAIL = [];
const check = (name, ok, detail = '') => {
  (ok ? PASS : FAIL).push(name);
  console.log((ok ? '  [PASS] ' : '  [FAIL] ') + name + (detail ? '  — ' + detail : ''));
};
const sec = (t) => console.log('\n=== ' + t + ' ===');

/** 从 app.js 里抽出某个方法的**方法体**（不含签名），花括号配平。 */
function extractMethod(src, name) {
  const re = new RegExp('(?:async\\s+)?' + name + '\\s*\\([^)]*\\)\\s*\\{');
  const m = re.exec(src);
  if (!m) return null;
  let i = m.index + m[0].length;   // 指向方法体的第一个字符
  const start = i;
  let depth = 1;
  while (i < src.length && depth > 0) {
    const c = src[i];
    if (c === "'" || c === '"' || c === '`') {
      const quote = c;
      i++;
      while (i < src.length && src[i] !== quote) {
        if (src[i] === '\\') i++;      // 跳过转义
        i++;
      }
      i++;
      continue;
    }
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') depth--;
    i++;
  }
  return src.slice(start, i - 1);
}

/**
 * 把方法变成可执行的函数（带参数）。
 *
 * ⚠️ 两种错法都踩过：
 *   ① 只抽方法体、丢掉签名 ⇒ `kb is not defined`（参数没了）
 *   ② 把整个方法简写当表达式 ⇒ `new Function` 抛 SyntaxError，
 *      而 catch 只会返回 null，看起来像「方法不存在」，排查方向完全跑偏
 * ⇒ 正确做法：抽出「参数列表 + 方法体」，包成一个普通函数。
 */
function makeMethod(name) {
  const re = new RegExp('(?:async\\s+)?' + name + '\\s*\\(([^)]*)\\)');
  const m = re.exec(APP_JS);
  if (!m) return null;
  const params = m[1];
  const body = extractMethod(APP_JS, name);
  if (body === null) return null;
  try {
    return new Function('return function(' + params + ') {' + body + '}')();
  } catch (e) {
    console.log('    （' + name + ' 执行失败: ' + e.message + '）');
    return null;
  }
}

sec('第 1 组：格式化函数必须把「读不到」显示成「未知」，不能显示 0');

const fmtKb = makeMethod('fmtKb');
check('fmtKb 能被抽出来并执行', !!fmtKb);
if (fmtKb) {
  check('fmtKb(null) = 未知', fmtKb(null) === '未知', '得到 ' + fmtKb(null));
  check('fmtKb(undefined) = 未知', fmtKb(undefined) === '未知');
  check('fmtKb(NaN) = 未知', fmtKb(NaN) === '未知');
  check('fmtKb(0) = 0 KB（真的是 0 就该显示 0）', fmtKb(0) === '0 KB', '得到 ' + fmtKb(0));
  check('fmtKb(512) = 512 KB', fmtKb(512) === '512 KB', '得到 ' + fmtKb(512));
  check('fmtKb(1024) = 1.0 MB', fmtKb(1024) === '1.0 MB', '得到 ' + fmtKb(1024));
  check('fmtKb 大数值带 GB', fmtKb(1024 * 1024 * 3) === '3.00 GB', '得到 ' + fmtKb(1024 * 1024 * 3));
}

const fmtBytes = makeMethod('fmtBytes');
check('fmtBytes 能被抽出来并执行', !!fmtBytes);
if (fmtBytes) {
  check('fmtBytes(null) = 未知', fmtBytes(null) === '未知', '得到 ' + fmtBytes(null));
  check('fmtBytes(0) = 0 B', fmtBytes(0) === '0 B', '得到 ' + fmtBytes(0));
  check('fmtBytes(1024) = 1.0 KB', fmtBytes(1024) === '1.0 KB', '得到 ' + fmtBytes(1024));
}

const fmtUptime = makeMethod('fmtUptime');
check('fmtUptime 能被抽出来并执行', !!fmtUptime);
if (fmtUptime) {
  check('fmtUptime(null) = 未知', fmtUptime(null) === '未知', '得到 ' + fmtUptime(null));
  check('fmtUptime(-1) = 未知（负数是坏数据，不显示「-1 分」）',
    fmtUptime(-1) === '未知', '得到 ' + fmtUptime(-1));
  check('fmtUptime(0) = 0 分', fmtUptime(0) === '0 分', '得到 ' + fmtUptime(0));
  check('fmtUptime(90) = 1 分', fmtUptime(90) === '1 分', '得到 ' + fmtUptime(90));
  check('fmtUptime(3661) 含「1 小时」「1 分」',
    /1 小时/.test(fmtUptime(3661)) && /1 分/.test(fmtUptime(3661)),
    '得到 ' + fmtUptime(3661));
  check('fmtUptime(90000) 含「1 天」', /1 天/.test(fmtUptime(90000)),
    '得到 ' + fmtUptime(90000));
}

const usagePercent = makeMethod('usagePercent');
check('usagePercent 能被抽出来并执行', !!usagePercent);
if (usagePercent) {
  check('usagePercent(null, 100) = null（不是 0）', usagePercent(null, 100) === null,
    '得到 ' + usagePercent(null, 100));
  check('usagePercent(50, 100) = 50', usagePercent(50, 100) === 50);
  check('usagePercent(50, 0) = null（除零不崩）', usagePercent(50, 0) === null,
    '得到 ' + usagePercent(50, 0));
}

const usageColor = makeMethod('usageColor');
check('usageColor 能被抽出来并执行', !!usageColor);
if (usageColor) {
  check('usageColor(null) 是灰的（不是绿/红）',
    usageColor(null) === 'bg-gray-300', '得到 ' + usageColor(null));
  check('usageColor(50) 是绿', usageColor(50) === 'bg-green-500', '得到 ' + usageColor(50));
  check('usageColor(80) 是黄', usageColor(80) === 'bg-amber-500', '得到 ' + usageColor(80));
  check('usageColor(95) 是红', usageColor(95) === 'bg-red-500', '得到 ' + usageColor(95));
}

sec('第 2 组：模板引用的字段，后端必须真的产出');

// 后端 device_info.collect_all() 的字段集合（写死在此处，
// 变更时这个测试会红 —— 那正是要提醒人的时候）。
const BACKEND_FIELDS = [
  'model',
  'os.pretty_name', 'os.version', 'os.distro', 'os.kernel',
  'cpu.model', 'cpu.cores', 'cpu.mhz', 'cpu.arch',
  'memory.total_kb', 'memory.free_kb', 'memory.used_kb',
  'storage.total_kb', 'storage.used_kb', 'storage.free_kb', 'storage.path',
  'uptime_seconds',
  'interfaces',
  // v0.19.8 新增：面板自身的开关（由 /api/system/info 的 data.panel 提供）
  'panel', 'panel.access_mode', 'panel.deploy_mode', 'panel.switches',
  'panel.counts', 'panel.ddns_configured', 'panel.cert_ready',
  // v0.19.8 新增：设备侧服务状态与包清单
  'services', 'packages', 'packages.total', 'packages.world',
];

// 模板里实际引用的字段路径
const templateRefs = [];
const re = /deviceInfo\.data\.((?:[a-z_]+\.)*[a-z_]+)/g;
let m;
while ((m = re.exec(INDEX_HTML)) !== null) {
  if (!templateRefs.includes(m[1])) templateRefs.push(m[1]);
}

check('模板确实引用了 deviceInfo.data.*', templateRefs.length > 0,
  '找到 ' + templateRefs.length + ' 个');

for (const ref of templateRefs) {
  // 数组/对象的**属性**（interfaces.length、interfaces[].name 等）
  // 不是后端字段，跳过 —— 只校验「字段路径」。
  if (ref.includes('length') || ref.endsWith('[]')) continue;
  const ok = BACKEND_FIELDS.includes(ref);
  check('模板字段 ' + ref + ' 后端有对应产出', ok,
    ok ? '' : '后端字段清单里没有它');
}

// 顺带确认「数组元素用到的属性」后端真的产出
const IFACE_FIELDS = ['name', 'state', 'ipv4', 'ipv6', 'rx_bytes', 'tx_bytes',
                      // v0.19.8 新增：速率（模板直接引用）
                      'rx_bps', 'tx_bps'];
for (const f of IFACE_FIELDS) {
  check('接口字段 ' + f + ' 在模板里被用到了',
    new RegExp('iface\\.' + f + '\\b').test(INDEX_HTML));
}

// 这几个是在 **detailOf 方法内部**用的 ⇒ 要在 app.js 里找，不在模板里
const IFACE_DETAIL_FIELDS = ['mtu', 'mac', 'master', 'speed', 'duplex',
                             'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors'];
for (const f of IFACE_DETAIL_FIELDS) {
  check('接口明细字段 ' + f + ' 在 app.js 里被用到了',
    new RegExp('iface\\.' + f + '\\b').test(APP_JS));
}

// 服务列表的字段
const SVC_FIELDS = ['name', 'enabled', 'running'];
for (const f of SVC_FIELDS) {
  check('服务字段 ' + f + ' 在模板里被用到了',
    new RegExp('svc\\.' + f + '\\b').test(INDEX_HTML));
}
check('服务字段 priority 在 app.js 里被用到了（svcPriority 方法内）',
  /svc\.priority\b/.test(APP_JS));

// 开关徽章的字段
for (const f of ['key', 'label', 'on']) {
  check('开关字段 ' + f + ' 在模板里被用到了',
    new RegExp('sw\\.' + f + '\\b').test(INDEX_HTML));
}

sec('第 3 组：页面结构');

check('index.html 里有系统信息页的容器',
  /currentNav === 'system-info'/.test(INDEX_HTML));
check('navItems 里有 system-info 这一项',
  /id:\s*'system-info'/.test(APP_JS));
check('切换到该页会调用 loadDeviceInfo()',
  /item\.id === 'system-info'\) loadDeviceInfo\(\)/.test(INDEX_HTML));
check('app.js 里有 loadDeviceInfo 方法', /async loadDeviceInfo\(isAuto\)/.test(APP_JS));
check('app.js 里有 deviceInfo 状态', /deviceInfo:\s*\{/.test(APP_JS));
check('调用的是 /api/system/info', /api\/system\/info/.test(APP_JS));
check('失败时显示错误而不是空白', /deviceInfo\.error/.test(INDEX_HTML));
check('页面上说明数据来源只读', /只读采集/.test(INDEX_HTML));

check('页面有「功能开关」板块', /功能开关/.test(INDEX_HTML));

// 「交换」列必须**同时**用上收和发 —— 只算一边的话这一列就是错的，
// 而且页面上看数字完全正常（不会报错），只有对账才发现。
check('「交换」列是收+发（rx_bytes + tx_bytes）',
  /fmtBytes\(\(iface\.rx_bytes \|\| 0\) \+ \(iface\.tx_bytes \|\| 0\)\)/.test(INDEX_HTML),
  '没找到收发相加的表达式');

sec('第 4 组：新增的格式化函数（2026-11-10 系统信息页数据面扩充）');
const fmtRate = makeMethod('fmtRate');
check('fmtRate 能被抽出来并执行', !!fmtRate);
if (fmtRate) {
  // ⚠️ 关键：速率读不到必须是「采样中」，**不是 0** ——
  // 0 会被读成「这条链路没有流量」，那是撒谎。
  check('fmtRate(null) = 采样中', fmtRate(null) === '采样中', '得到 ' + fmtRate(null));
  check('fmtRate(undefined) = 采样中', fmtRate(undefined) === '采样中');
  check('fmtRate(NaN) = 采样中', fmtRate(NaN) === '采样中');
  check('fmtRate(0) = 0 B/s（真的是 0 就该显示 0）', fmtRate(0) === '0 B/s',
    '得到 ' + fmtRate(0));
  check('fmtRate(512) = 512 B/s', fmtRate(512) === '512 B/s', '得到 ' + fmtRate(512));
  check('fmtRate(2048) = 2.0 KB/s', fmtRate(2048) === '2.0 KB/s', '得到 ' + fmtRate(2048));
  check('fmtRate(5MB) 含「MB/s」', /MB\/s/.test(fmtRate(5 * 1024 * 1024)),
    '得到 ' + fmtRate(5 * 1024 * 1024));
}

const detailOf = makeMethod('detailOf');
check('detailOf 能被抽出来并执行', !!detailOf);
if (detailOf) {
  const d = detailOf({
    mtu: 1500, mac: 'bc:24:11:48:32:5b', master: 'br-lan',
    speed: 1000, duplex: 'full', rx_dropped: 3, tx_dropped: 0,
    rx_errors: 0, tx_errors: 1,
  });
  check('明细里有 MTU', /MTU 1500/.test(d), d);
  check('明细里有 MAC', /bc:24:11:48:32:5b/.test(d), d);
  check('明细里有桥归属', /桥 br-lan/.test(d), d);
  check('明细里有链路速率', /1000 Mbps/.test(d), d);
  check('明细里有丢包数', /丢包 3/.test(d), d);
  check('明细里有错误数', /错误 1/.test(d), d);
  // 读不到的项**不出现**（而不是显示「未知」）
  const empty = detailOf({});
  check('读不到时明细为空串', empty === '', JSON.stringify(empty));
  check('null 接口不炸', detailOf(null) === '');
  // 0 丢包不算「有丢包」⇒ 不该显示「丢包 0」
  const zero = detailOf({ rx_dropped: 0, tx_dropped: 0, rx_errors: 0, tx_errors: 0 });
  check('丢包/错误都是 0 时不显示这两项', !/丢包/.test(zero) && !/错误/.test(zero), zero);
}

const panelCount = makeMethod('panelCount');
check('panelCount 能被抽出来并执行', !!panelCount);
if (panelCount) {
  const p = { counts: { forward_rules: 0, whitelist: 3 } };
  // ⚠️ 0 是合法值（「一条转发规则都没有」是真实状态）⇒ 必须显示「0 条」
  check('计数为 0 时显示「0 条」（不是「未知」）',
    panelCount(p, 'forward_rules') === '0 条', '得到 ' + panelCount(p, 'forward_rules'));
  check('计数为 3 时显示「3 条」',
    panelCount(p, 'whitelist') === '3 条', '得到 ' + panelCount(p, 'whitelist'));
  check('panel 为 null 时显示「未知」', panelCount(null, 'whitelist') === '未知');
  check('panel 没有 counts 时显示「未知」', panelCount({}, 'whitelist') === '未知');
  check('counts 里没有这个键时显示「未知」',
    panelCount(p, 'nonexistent') === '未知');
}

const svcPriority = makeMethod('svcPriority');
check('svcPriority 能被抽出来并执行', !!svcPriority);
if (svcPriority) {
  check('序号 50 显示 50', svcPriority({ priority: 50 }) === '50');
  // ⚠️ 0 是合法序号（S00sysfixtime）⇒ 不能显示成「—」
  check('序号 0 显示 0（不是「—」）', svcPriority({ priority: 0 }) === '0',
    '得到 ' + svcPriority({ priority: 0 }));
  check('没有序号时显示「—」', svcPriority({ priority: null }) === '—');
  check('整个对象缺失时显示「—」', svcPriority(null) === '—');
}

sec('第 5 组：系统信息页的自动刷新（速率要连续采样才有意义）');

check('有排下一次刷新的方法', /scheduleDeviceInfoRefresh\(\)/.test(APP_JS));
check('定时器只在系统信息页上排（离开就停）',
  /currentNav !== 'system-info'/.test(APP_JS));
check('刷新间隔有定义', /deviceInfoRefreshMs/.test(APP_JS));
check('自动刷新不进 loading 态（免得按钮每 5 秒闪一次）',
  /if \(!isAuto\) this\.deviceInfo\.loading = true;/.test(APP_JS));

console.log('\n' + '='.repeat(60));
console.log('  通过 ' + PASS.length + ' / 失败 ' + FAIL.length);
if (FAIL.length) console.log('  失败项: ' + JSON.stringify(FAIL));
console.log('='.repeat(60));
process.exit(FAIL.length ? 1 : 0);
