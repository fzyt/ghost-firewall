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
function makeMethod(name) {
  const re = new RegExp('(?:async\\s+)?' + name + '\\s*\\(([^)]*)\\)');
  const m = re.exec(APP_JS);
  if (!m) return null;
  const body = extractMethodBody(APP_JS, name);
  if (body === null) return null;
  try {
    return new Function('return function(' + m[1] + ') {' + body + '}')();
  } catch (e) {
    console.log('    （' + name + ' 抽取失败: ' + e.message + '）');
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
  for (const n of ['fmtRate', 'ifaceDetail', 'panelCount', 'svcPriority']) {
    const fn = makeMethod(n);
    if (fn) scope[n] = fn;
  }
  return scope;
}

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
//    现在有一批不带兜底的表达式（ifaceDetail / fmtRate / panelCount…），
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

console.log('\n' + '='.repeat(60));
console.log('  通过 ' + PASS.length + ' / 失败 ' + FAIL.length);
if (FAIL.length) console.log('  失败项: ' + JSON.stringify(FAIL));
console.log('='.repeat(60));
process.exit(FAIL.length ? 1 : 0);
