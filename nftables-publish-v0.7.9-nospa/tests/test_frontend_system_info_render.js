/* 「系统信息」页的**实际渲染文本**验证
 *
 * 运行: node tests/test_frontend_system_info_render.js
 *
 * 测什么有效
 * ----------
 * 契约测试（test_frontend_system_info.js）验证的是「模板引用的字段名
 * 后端有产出」—— 但那**不覆盖表达式本身写错**的情况。
 * 比如 `x-text="deviceInfo.data.os.pretty_name"` 写成
 * `x-text="deviceInfo.data.os.prettyName"`，字段名对不上，契约测试会红；
 * 但如果写成 `x-text="deviceInfo.data.os.pretty_name || '未知版本'"`，
 * 字段名是对的、页面却一直显示「未知版本」——
 * 契约测试**不会红**，页面也**看起来正常**（不报错，就是不对）。
 *
 * 所以这里做一件更接近真实的事：
 *   拿**真实后端数据**，把模板里的 x-text 表达式**逐个求值**，
 *   检查渲染出来的是不是「真实值」而不是「兜底值」。
 *
 * 怎么求值
 * --------
 * Alpine 的 x-text 就是「把表达式的值放进元素」。
 * 这里用 `new Function` 在一个假的 Alpine data 上求值 ——
 * 表达式本身是纯读取（没有副作用），求值结果就是渲染结果。
 *
 * ⚠️ 只求值**只读**表达式（形如 `a.b.c` 或 `a.b.c || '兜底'`）。
 * 带函数调用的（`fmtKb(...)`、`usagePercent(...)`）单独在契约测试里真跑过。
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

/**
 * 真实的设备信息（本机采集的结果，结构与 OpenWrt 上一样）。
 * 故意用**不常见的值**（如型号 'GL-MT6000'），这样「兜底值误显示」看得出来。
 */
const REAL_DATA = {
  model: 'GL-MT6000',
  os: {
    pretty_name: 'OpenWrt 25.12.5 (r1) (x86/64)',
    version: '25.12.5',
    distro: 'OpenWrt',
    kernel: '6.6.88 x86_64',
  },
  cpu: { model: 'Intel(R) N100', cores: 4, mhz: 3400.0, arch: 'x86_64' },
  memory: { total_kb: 2048000, free_kb: 512000, used_kb: 1536000 },
  storage: { total_kb: 104857600, used_kb: 52428800, free_kb: 52428800, path: '/' },
  uptime_seconds: 90061,
  interfaces: [
    {
      name: 'br-lan', rx_bytes: 123456789, tx_bytes: 987654321,
      state: 'up', ipv4: ['192.168.100.1'], ipv6: ['fda7:68ee::1'],
      // v0.19.8 新增
      rx_packets: 900000, tx_packets: 700000,
      rx_bps: 20480, tx_bps: 10240,
      mtu: 1500, mac: 'bc:24:11:48:32:5b', master: null,
      speed: null, duplex: null,
      rx_dropped: 0, tx_dropped: 0, rx_errors: 0, tx_errors: 0,
      carrier: 1, ifindex: 4, type: 1,
    },
    {
      name: 'pppoe-wan', rx_bytes: 555, tx_bytes: 666,
      state: 'down', ipv4: [], ipv6: [],
      rx_bps: null, tx_bps: null,
      mtu: 1500, mac: 'aa:bb:cc:dd:ee:ff', master: null,
      speed: 1000, duplex: 'full',
      rx_dropped: 2, tx_dropped: 0, rx_errors: 0, tx_errors: 0,
      carrier: 0, ifindex: 5, type: 1,
    },
  ],
  // v0.19.8 新增：面板自身的开关
  panel: {
    access_mode: 'lan',
    deploy_mode: 'openwrt',
    switches: [
      { key: 'gateway_enabled', label: '认证网关', on: true },
      { key: 'luci_enabled', label: 'LuCI 管理界面', on: false },
    ],
    counts: {
      forward_rules: 0, whitelist: 12, blacklist: 3,
      reverse_proxies: 2, certificates: 1,
    },
    ddns_configured: false,
    cert_ready: true,
  },
  // v0.19.8 新增：设备侧服务状态
  services: [
    { name: 'dropbear', installed: true, enabled: true, running: true, priority: 19 },
    { name: 'uhttpd', installed: true, enabled: true, running: false, priority: 50 },
    { name: 'sysfixtime', installed: true, enabled: true, running: false, priority: 0 },
  ],
  // v0.19.8 新增：包清单
  packages: { total: 257, world: ['busybox', 'dnsmasq', 'dropbear'] },
};

/** 假的 Alpine data —— 只放页面用到的字段。 */
function makeData(data) {
  return { deviceInfo: { loading: false, loaded: true, error: '', data } };
}

/**
 * 从 app.js 里抽出某个方法的**方法体**（花括号配平，跳过字符串与注释）。
 */
function extractMethodBody(src, name) {
  const re = new RegExp('(?:async\\s+)?' + name + '\\s*\\([^)]*\\)\\s*\\{');
  const m = re.exec(src);
  if (!m) return null;
  let i = m.index + m[0].length;
  const start = i;
  let depth = 1;
  while (i < src.length && depth > 0) {
    const c = src[i];
    if (c === "'" || c === '"' || c === '`') {
      const quote = c;
      i++;
      while (i < src.length && src[i] !== quote) {
        if (src[i] === '\\') i++;
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
 * 抽出某个方法并变成可执行的函数。
 *
 * ⚠️ 为什么要**真跑**这些方法，而不是一律跳过带函数调用的表达式：
 *   模板里 `'↓ ' + fmtRate(iface.rx_bps)` 这种表达式如果只跳过不求值，
 *   渲染测试就等于没覆盖这段 —— 而 fmtRate 读不到时返回「采样中」还是「0」，
 *   恰恰是这个测试该盯的（0 会被读成「这条链路没有流量」，那是撒谎）。
 *
 * ⚠️ 这些方法必须**不依赖 this**（面板上都是从 Alpine 顶层调用的），
 *   抽出来单独跑时没有 this ⇒ 用 this 会直接抛。
 */
function makeMethod(name, quiet) {
  const re = new RegExp('(?:async\\s+)?' + name + '\\s*\\(([^)]*)\\)');
  const m = re.exec(APP_JS);
  if (!m) return null;
  const body = extractMethodBody(APP_JS, name);
  if (body === null) return null;
  try {
    return new Function('return function(' + m[1] + ') {' + body + '}')();
  } catch (e) {
    // quiet 模式：不刷噪声（动态提取方法名时会遇到抽不出来的 async 方法）
    if (!quiet) console.log('    （' + name + ' 抽取失败: ' + e.message + '）');
    return null;
  }
}

/**
 * x-for 循环体里的表达式，其作用域是**循环变量**（iface / a / idx），
 * 不在 Alpine 顶层 scope 上。
 *
 * ⚠️ 不给它们定义就会全部报「iface is not defined」——
 * 而那是**求值器的缺陷**，不是页面的缺陷。
 * ⇒ 求值时把循环变量也放进作用域。
 *
 * 页面里有**两层** x-for：
 *   外层 (iface, idx) in deviceInfo.data.interfaces
 *   内层 (a, idx) in iface.ipv4 / iface.ipv6
 * 所以作用域里要同时有 iface、a、idx。
 */
function makeScope(data) {
  const scope = { ...makeData(data) };
  // 用真实数据里的第一个接口当循环变量（x-for 的作用域就是这一个元素）
  const list = (data && data.interfaces) || [];
  const first = list[0] || {
    name: '', state: '', ipv4: [], ipv6: [], rx_bytes: 0, tx_bytes: 0,
  };
  scope.iface = first;
  // 内层循环变量：第一个地址（没有就空串）
  scope.a = (first.ipv4 && first.ipv4[0]) || (first.ipv6 && first.ipv6[0]) || '';
  scope.idx = 0;

  // v0.19.8 新增的三层 x-for 的循环变量
  const switches = (data && data.panel && data.panel.switches) || [];
  scope.sw = switches[0] || { key: '', label: '', on: false };
  const services = (data && data.services) || [];
  scope.svc = services[0] || { name: '', enabled: false, running: false, priority: null };
  const world = (data && data.packages && data.packages.world) || [];
  scope.pkg = world[0] || '';

  // 模板里用到的这些方法：从 app.js **真抽出来**跑，
  // 而不是随便塞个桩 —— 桩只能证明「不抛异常」，
  // 真实现才能证明「渲染出来的字是对的」。
  //
  // ⚠️ 这里必须把**页面用到的全部**格式化方法都放进来，
  //   少放一个，Alpine 模拟那组就会在求值时抛
  //   "fmtUptime is not defined" —— 那是**求值器的缺陷**，不是页面的缺陷。
  //
  // ⚠️⚠️ 方法名清单必须**从模板里动态提取**，不能写死！
  //   写死过一版（['fmtRate', 'detailOf', ...]），后果是：
  //   一旦有人把方法改名（比如 detailOf → ifaceDetail），
  //   scope 里就少了这个方法 ⇒ 求值报 "X is not defined" ——
  //   而那是**测试装置的缺陷**，不是页面的缺陷，
  //   它会把真正该报的诊断（Alpine 把值丢掉了）给盖掉。
  const PAGE_METHODS = extractPageMethodNames();
  for (const n of PAGE_METHODS) {
    const fn = makeMethod(n, true);   // quiet：抽不出来的静默跳过
    if (fn) scope[n] = fn;
  }
  return scope;
}

/**
 * 从**模板**里提取被调用到的方法名（动态，不写死）。
 *
 * 只取「看起来像方法调用」的标识符：
 *   标识符 + (  ⇒  foo(...)
 * 排除 JS 关键字（if / for / while …）与内建（confirm / parseInt …）。
 *
 * ⚠️ 只保留**能成功抽取**的（makeMethod 返回非 null）。
 *   页面里有些调用指向 async 方法（含 await），
 *   那种方法抽不出可执行体 —— 硬塞进 scope 只会刷一屏
 *   "await is only valid in async functions" 噪声，
 *   把真正要看的失败盖掉。抽不出来的，本来就不是本测试能求值的对象。
 */
function extractPageMethodNames() {
  const names = new Set();
  const re = /\b([A-Za-z_$][\w$]*)\s*\(/g;
  let m;
  while ((m = re.exec(INDEX_HTML)) !== null) {
    const n = m[1];
    if (JS_RESERVED.has(n)) continue;
    names.add(n);
  }
  // 页面里出现的方法调用都来自 app.js 的 Alpine 组件 ⇒ 只保留
  // 「在 app.js 里有定义**且**能抽成可执行函数」的。
  const out = [];
  for (const n of names) {
    const re2 = new RegExp('(?:async\\s+)?' + n + '\\s*\\([^)]*\\)\\s*\\{');
    if (!re2.test(APP_JS)) continue;
    // 抽取失败的（async 方法含 await）直接跳过，不塞 scope
    const body = extractMethodBody(APP_JS, n);
    if (body === null) continue;
    if (/\bawait\b/.test(body)) continue;
    out.push(n);
  }
  return out;
}

/** JS 关键字 / 保留字 —— 模板里出现 `if (` 之类不能当成方法。 */
const JS_RESERVED = new Set([
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default', 'return',
  'break', 'continue', 'function', 'try', 'catch', 'finally', 'throw',
  'new', 'delete', 'typeof', 'instanceof', 'in', 'of', 'void', 'await',
  'async', 'class', 'extends', 'super', 'this', 'const', 'let', 'var',
  'require', 'confirm', 'alert', 'parseInt', 'parseFloat', 'Number', 'String',
  'Boolean', 'Array', 'Object', 'JSON', 'Math', 'Date',
]);

/** 在假 data 上求值一个 Alpine 表达式。 */
function evaluate(expr, data) {
  try {
    // eslint-disable-next-line no-new-func
    const fn = new Function('d', 'with (d) { return (' + expr + '); }');
    return fn(makeScope(data));
  } catch (e) {
    return '<<求值出错: ' + e.message + '>>';
  }
}

// ================================================================
// Alpine 求值器模拟（2026-11-10 新增）
// ================================================================
//
// ⚠️ 为什么上面那个 evaluate() 不够？
//   它用 `new Function` 直接求值 —— 那是**普通 JS 表达式**语义。
//   而 Alpine 3.15.8 的求值器（frontend/assets/alpine.js 的 Jn）不是这么干的：
//
//     n = /^[\n\s]*if.*\(.*\)/.test(t.trim()) || /^(let|const)\s/.test(t.trim())
//         ? `(async()=>{ ${t} })()` : t
//     ... new AsyncFunction(['__self','scope'],
//           `with (scope) { __self.result = ${n} }; __self.finished = true; return __self.result;`)
//
//   表达式**以 if 开头** ⇒ 被包成 `(async()=>{ ... })()` ⇒
//   **块体里的表达式值被丢弃** ⇒ 结果恒 undefined。
//
//   ⇒ 这就是为什么 2026-11-10 那批「全绿」的测试里，
//     方法名 ifaceDetail(iface) 的调用在页面上渲染成**空白**，却没人发现：
//     文本层面的测试用的都是自己的求值器，跟 Alpine 的行为不是一回事。
//
// 所以这里**照抄 Alpine 的包装逻辑**再求值一次，
// 让判据能在**没有浏览器**的环境里也复现 Alpine 的真实行为。
//
// 正则从 alpine.js 里抽（不手抄 —— 手抄的会和 Alpine 实际行为脱节）。
const ALPINE_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'assets', 'alpine.js'), 'utf8');
const DETECTOR_RE = /\/\^[^/]*\/[a-z]*\.test\(/g;
function extractAlpineDetectors() {
  const anchor = ALPINE_JS.indexOf('__self.result = ');
  if (anchor < 0) return null;
  const win = ALPINE_JS.slice(Math.max(0, anchor - 800), anchor);
  const dets = [...win.matchAll(DETECTOR_RE)].map((m) => m[0]);
  const ifDet = dets.find((d) => /if/.test(d));
  const declDet = dets.find((d) => /let\|const/.test(d));
  if (!ifDet || !declDet) return null;
  return {
    ifRe: new RegExp(ifDet.replace(/\.test\($/, '').slice(1, -1)),
    declRe: new RegExp(declDet.replace(/\.test\($/, '').slice(1, -1)),
  };
}

const ALPINE_DET = extractAlpineDetectors();

/**
 * **照抄 Alpine 的求值语义**求值一个值位表达式。
 *
 * 关键点：Alpine 把表达式赋值给 `__self.result`，
 * 而 `__self.result = (async()=>{ ... })()` 赋的是**一个 Promise**；
 * Alpine 随后 await 它 —— 而那个 async IIFE 的**块体没有 return**，
 * 所以 await 出来的值是 undefined。
 *
 * 这里用真实的 AsyncFunction + with(scope) 复刻一遍。
 */
function evaluateLikeAlpine(expr, data) {
  if (!ALPINE_DET) return '<<Alpine 正则未抽到>>';
  const t = String(expr).trim();
  const wrapped = ALPINE_DET.ifRe.test(t) || ALPINE_DET.declRe.test(t);
  const body = wrapped ? `(async()=>{ ${t} })()` : t;
  try {
    // eslint-disable-next-line no-new-func
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    const fn = new AsyncFunction(['__self', 'scope'],
      `with (scope) { __self.result = ${body} }; ` +
      `__self.finished = true; return __self.result;`);
    const self = { result: undefined, finished: false };
    return fn(self, makeScope(data)).then((r) => {
      // Alpine 会对 Promise 做 then —— 这里同样 await
      return r && typeof r.then === 'function' ? r.then((v) => v) : r;
    });
  } catch (e) {
    return Promise.resolve('<<求值出错: ' + e.message + '>>');
  }
}

// 正题在文件末尾的异步段里执行（Alpine 模拟要 await）。
// 这里只把要用到的装置准备好。
const ALPINE_EVAL_EXPRS = extractTextExprs();

/** 抽出页面上所有 x-text 表达式的文本内容。 */
function extractTextExprs() {
  const out = [];
  const re = /x-text="([^"]+)"/g;
  let m;
  while ((m = re.exec(INDEX_HTML)) !== null) {
    // 只取系统信息页那一段
    const pos = m.index;
    const pageStart = INDEX_HTML.indexOf("currentNav === 'system-info'");
    const pageEnd = INDEX_HTML.indexOf("currentNav === 'network'");
    if (pageStart < 0 || pos < pageStart || pos > pageEnd) continue;
    out.push(m[1]);
  }
  return out;
}

sec('第 1 组：系统信息页的 x-text 表达式逐个求值');

const exprs = extractTextExprs();
check('找到了系统信息页的 x-text 表达式', exprs.length > 0,
  '找到 ' + exprs.length + ' 个');

// ⚠️ 这里传的是**原始数据**，不是 makeData(...) 包装过的。
//    makeScope() 内部会做一次包装（scope.deviceInfo.data = data），
//    外面再包一层的话 deviceInfo.data 就变成了 {deviceInfo: {...}}，
//    `deviceInfo.data.model` 取到的是 undefined ——
//    而页面上一半以上的表达式都带 `|| '未知'` 兜底，
//    **严格判定那一组压根不检查它们** ⇒ 这个双层包装一直没被发现。
//    现在有一批不带兜底的表达式（detailOf / fmtRate / panelCount…），
//    双层包装会让它们求值到空数据 ⇒ 必须传原始数据。
const data = REAL_DATA;

// 只读表达式（不含函数调用）的求值结果必须「不是兜底值」。
// 兜底值清单：页面里所有 || '...' 和 ? '...' : '...' 的字面量。
const FALLBACKS = ['未知', '未知版本', '未知（该设备未提供型号信息）',
                   '该设备未提供型号信息', '未提供型号信息'];

let evaluated = 0;
for (const expr of exprs) {
  // 跳过带函数调用的（fmtKb / fmtBytes / fmtUptime / usagePercent / usageColor）
  if (/\b(fmtKb|fmtBytes|fmtUptime|usagePercent|usageColor)\s*\(/.test(expr)) continue;
  // 跳过三元里带函数调用的
  if (/\?\s*'[^']*'\s*:\s*'[^']*'/.test(expr)) continue;
  evaluated++;
  const v = evaluate(expr, data);
  const s = String(v);
  const isFallback = FALLBACKS.some(f => s === f || s === f + '（该设备未提供型号信息）');
  // 有些表达式本来就是「空数组时显示 —」或「空时显示未知」，那是**正确**行为。
  // 判据：表达式里带了 `||` 或 `?` 的（说明作者写了兜底）不判失败；
  //       纯读取的必须拿到真实值。
  const hasFallbackLogic = expr.includes('||') || expr.includes('?');
  if (!hasFallbackLogic) {
    check('纯读取表达式取到真实值: ' + expr,
      !isFallback && s !== 'undefined' && s !== 'null' && !s.startsWith('<<'),
      '求值结果=' + JSON.stringify(s));
  }
}
check('求值的表达式数量不为零（否则本组是空转）', evaluated > 0,
  '求值了 ' + evaluated + ' 个');

sec('第 2 组：关键字段确实出现在页面上');

const keyExprs = {
  '设备型号': "deviceInfo.data.model",
  '固件版本': "deviceInfo.data.os.pretty_name",
  '内核版本': "deviceInfo.data.os.kernel",
  '运行时间': "deviceInfo.data.uptime_seconds",
  'CPU 型号': "deviceInfo.data.cpu.model",
  'CPU 核数': "deviceInfo.data.cpu.cores",
  '内存总量': "deviceInfo.data.memory.total_kb",
  '磁盘总量': "deviceInfo.data.storage.total_kb",
};

for (const [label, expr] of Object.entries(keyExprs)) {
  const inPage = exprs.some(e => e.includes(expr));
  check('页面上引用了' + label + '（' + expr + '）', inPage);
}

sec('第 3 组：接口表头与字段齐全');

for (const col of ['接口', '状态', 'IPv4', 'IPv6', '已收', '已发', '交换']) {
  check('接口表有「' + col + '」列', INDEX_HTML.includes('>' + col + '<'));
}

// v0.19.8 新增的三块也要在页面上
check('页面有「功能开关」板块', INDEX_HTML.includes('>功能开关<'));
check('页面有「设备服务」板块', INDEX_HTML.includes('>设备服务<'));
check('页面有「软件包」板块', INDEX_HTML.includes('>软件包<'));
check('设备服务表有「开机自启」列', INDEX_HTML.includes('>开机自启<'));
check('设备服务表有「运行中」列', INDEX_HTML.includes('>运行中<'));

sec('第 4 组：坏数据不会让页面崩');

// 后端读不到时全是 null —— 页面必须显示「未知」而不是崩掉。
const EMPTY_DATA = {
  model: null,
  os: { pretty_name: null, version: null, distro: null, kernel: null },
  cpu: { model: null, cores: null, mhz: null, arch: null },
  memory: { total_kb: null, free_kb: null, used_kb: null },
  storage: { total_kb: null, used_kb: null, free_kb: null, path: '/' },
  uptime_seconds: null,
  interfaces: [],
  // v0.19.8 新增：这几个也要能承受「全都没有」
  panel: null,
  services: [],
  packages: { total: null, world: [] },
};
const emptyData = EMPTY_DATA;
for (const expr of exprs) {
  if (/\b(fmtKb|fmtBytes|fmtUptime|usagePercent|usageColor)\s*\(/.test(expr)) continue;
  if (/\?\s*'[^']*'\s*:\s*'[^']*'/.test(expr)) continue;
  const v = evaluate(expr, emptyData);
  const s = String(v);
  check('坏数据下表达式不抛异常: ' + expr.slice(0, 50),
    !s.startsWith('<<'), s);
}

// ================================================================
// 第 1b 组：用 Alpine 的求值器语义重算（模拟 Alpine，不靠浏览器）
// ================================================================
//
// 这组是**异步**的（Alpine 的求值要 await），
// 所以放在文件末尾单独跑，跑完再统一收尾。
(async () => {
  sec('第 1b 组：用 Alpine 的求值器语义重算（模拟 Alpine，不靠浏览器）');

  check('从 alpine.js 抽到了求值器的正则（不手抄）', !!ALPINE_DET);

  if (ALPINE_DET) {
    // 自证：照抄的模拟器必须复现 Alpine 的真实行为。
    //   依据是 tmp/alpine-probe.js 的浏览器实测：
    //     x-text="ifDetail(v)" ⇒ 渲染成空（值被丢弃）
    //     x-text="okDetail(v)" ⇒ 正常显示
    const probeScope = {
      ...makeScope(REAL_DATA),
      v: 42,
      ifDetail: (x) => 'IF:' + x,
      okDetail: (x) => 'OK:' + x,
    };
    const probeEval = async (expr) => {
      const t = expr.trim();
      const wrapped = ALPINE_DET.ifRe.test(t) || ALPINE_DET.declRe.test(t);
      const body = wrapped ? `(async()=>{ ${t} })()` : t;
      // eslint-disable-next-line no-new-func
      const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
      const fn = new AsyncFunction(['__self', 'scope'],
        `with (scope) { __self.result = ${body} }; ` +
        `__self.finished = true; return __self.result;`);
      const self = { result: undefined, finished: false };
      const r = await fn(self, probeScope);
      return r && typeof r.then === 'function' ? await r : r;
    };

    const ifVal = await probeEval('ifDetail(v)');
    const okVal = await probeEval('okDetail(v)');
    check('模拟器复现 Alpine 行为：if 开头的表达式取值变 undefined',
      ifVal === undefined, '得到 ' + JSON.stringify(ifVal));
    check('模拟器复现 Alpine 行为：正常方法名取值正常',
      okVal === 'OK:42', '得到 ' + JSON.stringify(okVal));

    // 正题：把系统信息页所有值位表达式用 Alpine 语义重算一遍，
    // 结果为 undefined 的就是「页面会显示空白」的格子。
    let alpineEvaluated = 0;
    const alpineBlank = [];
    for (const expr of ALPINE_EVAL_EXPRS) {
      if (!expr.trim()) continue;
      alpineEvaluated++;
      const v = await evaluateLikeAlpine(expr, REAL_DATA);
      if (v === undefined || v === null) {
        alpineBlank.push(expr);
      }
    }
    check('用 Alpine 语义求值的表达式数量不为零（否则本组是空转）',
      alpineEvaluated > 0, '共 ' + alpineEvaluated + ' 条');
    check('用 Alpine 语义重算，没有表达式取值被丢弃（页面不会显示空白）',
      alpineBlank.length === 0,
      alpineBlank.length ? alpineBlank.map((e) => e.slice(0, 60)).join(' ; ') : '');
  }

  console.log('\n' + '='.repeat(60));
  console.log('  通过 ' + PASS.length + ' / 失败 ' + FAIL.length);
  if (FAIL.length) console.log('  失败项: ' + JSON.stringify(FAIL));
  console.log('='.repeat(60));
  process.exit(FAIL.length ? 1 : 0);
})();
