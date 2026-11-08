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
const IFACE_FIELDS = ['name', 'state', 'ipv4', 'ipv6', 'rx_bytes', 'tx_bytes'];
for (const f of IFACE_FIELDS) {
  check('接口字段 ' + f + ' 在模板里被用到了',
    new RegExp('iface\\.' + f + '\\b').test(INDEX_HTML));
}

sec('第 3 组：页面结构');

check('index.html 里有系统信息页的容器',
  /currentNav === 'system-info'/.test(INDEX_HTML));
check('navItems 里有 system-info 这一项',
  /id:\s*'system-info'/.test(APP_JS));
check('切换到该页会调用 loadDeviceInfo()',
  /item\.id === 'system-info'\) loadDeviceInfo\(\)/.test(INDEX_HTML));
check('app.js 里有 loadDeviceInfo 方法', /async loadDeviceInfo\(\)/.test(APP_JS));
check('app.js 里有 deviceInfo 状态', /deviceInfo:\s*\{/.test(APP_JS));
check('调用的是 /api/system/info', /api\/system\/info/.test(APP_JS));
check('失败时显示错误而不是空白', /deviceInfo\.error/.test(INDEX_HTML));
check('页面上说明数据来源只读', /只读采集/.test(INDEX_HTML));

console.log('\n' + '='.repeat(60));
console.log('  通过 ' + PASS.length + ' / 失败 ' + FAIL.length);
if (FAIL.length) console.log('  失败项: ' + JSON.stringify(FAIL));
console.log('='.repeat(60));
process.exit(FAIL.length ? 1 : 0);
