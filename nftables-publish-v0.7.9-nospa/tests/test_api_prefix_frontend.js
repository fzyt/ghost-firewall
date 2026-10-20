/* 「上游 API 路径前缀」探测 —— 前后端响应契约一致性测试
 *
 * 运行: node tests/test_api_prefix_frontend.js
 *
 * 为什么要单独写这个测试（而不是在 test_frontend.js 里加两行）：
 *
 *   第十七节记录的那个 bug —— 前端读的 JSON 层级比后端浅一层 —— 是
 *   这个项目里**已经犯过一次**的错误：api.request 只剥顶层的
 *   {success, message}，data 信封原样留着，而后端 31 个路由都把业务
 *   数据放在 data 里。于是 `data.presets` 恒为 undefined，列表永远空。
 *
 *   同一个坑在探测端点上再犯一次的后果是：探测明明成功了，页面却显示
 *   「没探测到」，用户以为自己填错了，去手填一个错的路径。
 *
 * 所以这个测试不靠正则断言「代码里有没有 .data」，而是：
 *   1. 从 backend/app.py 里**真的把该端点的返回结构解析出来**
 *   2. 复刻 api.request 的解包逻辑，算出调用方实际拿到的对象
 *   3. 把前端的取值表达式**真的求值一遍**，看能不能拿到 prefixes
 * 两边形状对不上，或前端少剥一层，测试立刻失败。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.dirname(__dirname);
const APP_PY = fs.readFileSync(path.join(ROOT, 'backend', 'app.py'), 'utf8');
const APP_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');
const INDEX_HTML = fs.readFileSync(path.join(ROOT, 'frontend', 'index.html'), 'utf8');

const PASS = [], FAIL = [];
const check = (name, ok, detail = '') => {
  (ok ? PASS : FAIL).push(name);
  console.log((ok ? '  ✅ ' : '  ❌ ') + name + (detail ? '  — ' + detail : ''));
};
const sec = (t) => console.log('\n=== ' + t + ' ===');

console.log('='.repeat(74));
console.log('上游 API 路径前缀探测：前后端响应契约一致性');
console.log('='.repeat(74));

/* ---------- 1. 解析后端真实的返回形状 ---------- */
sec('1. 后端 /api/reverse-proxy/detect-api-prefix 的返回结构');

const fnStart = APP_PY.indexOf('def rp_detect_api_prefix');
check('能找到 rp_detect_api_prefix', fnStart >= 0);

let nestedUnderData = false;
let backendFields = [];
if (fnStart >= 0) {
  const body = APP_PY.slice(fnStart, APP_PY.indexOf('\n@app.route', fnStart + 10));
  const jsonifyStart = body.lastIndexOf('return jsonify(');
  const retBlock = jsonifyStart >= 0 ? body.slice(jsonifyStart, jsonifyStart + 700) : '';

  // 后端可能用单引号+True、双引号+True、单引号+true 等等各种写法，
  // 断言必须全认 —— 只认一种写法的话，后端改个引号风格测试就假失败，
  // 假失败多了就没人信这个测试了。
  const SUCCESS_RE = /(['"])success\1\s*:\s*(True|true)\b/;
  const NESTED_RE = /(['"])success\1\s*:\s*(True|true)\s*,\s*(['"])data\3\s*:/;

  nestedUnderData = NESTED_RE.test(retBlock);
  check('后端成功返回里有 success 字段', SUCCESS_RE.test(retBlock),
    retBlock.slice(0, 120).replace(/\n/g, ' '));
  check('后端把 prefixes / error 放在 data 信封里', nestedUnderData,
    '平铺的话前端就该读 res.prefixes —— 形状变了测试要同步改');

  backendFields = ['prefixes', 'error'].filter(
    (f) => new RegExp("(['\"])" + f + "\\1\\s*:").test(retBlock));
  check('后端确实返回了 prefixes / error',
    backendFields.length === 2, `实际: [${backendFields.join(', ')}]`);
}
console.log(`  → 后端形状: ${nestedUnderData ? '嵌套在 data 下' : '平铺'}`);

/* ---------- 2. 复刻 api.request 的剥离逻辑 ---------- */
sec('2. api.request 剥离后调用方拿到什么');

const destructureMatch = APP_JS.match(/const\s*\{\s*success\s*,\s*message\s*,\s*\.\.\.\w+\s*\}\s*=\s*json/);
check('app.js 里有 api.request 的解构剥离', !!destructureMatch,
  destructureMatch ? destructureMatch[0] : '没找到');

// 后端真会返回的夹具。prefixes 必须非空 —— 空数组会让
// `|| []` 这类「读错层级」的写法蒙混过关，断言就永远抓不到 bug。
const FIXTURE = { prefixes: ['/api/'], error: null };

const rawResponse = nestedUnderData
  ? { success: true, data: { ...FIXTURE } }
  : { success: true, ...FIXTURE };

const { success, message, ...rest } = rawResponse;   // 与 app.js 同构
const apiReturns = rest;

check('api.request 之后 success/message 已剥离',
  !('success' in apiReturns) && !('message' in apiReturns));
check('api.request 之后 data 字段仍在（后端嵌套时）',
  nestedUnderData ? ('data' in apiReturns) : true,
  `实际键: [${Object.keys(apiReturns).join(', ')}]`);

/* ---------- 3. 前端取值表达式真的求值 ---------- */
sec('3. 前端取值表达式能否拿到 prefixes（核心断言）');

const callIdx = APP_JS.indexOf("api.post('/api/reverse-proxy/detect-api-prefix'");
check('能找到探测端点的调用点', callIdx >= 0);

if (callIdx >= 0) {
  const afterCall = APP_JS.slice(callIdx);
  // 赋值区 = 这次 api 调用之后、catch 之前的那段
  const tryEnd = afterCall.indexOf('} catch');
  const assignRegion = tryEnd > 0 ? afterCall.slice(0, tryEnd) : afterCall;

  // 抠出 const 声明（含剥 data 的那一步）
  const declRe = /const\s+(\w+)\s*=\s*([^;]+);/g;
  const decls = [];
  let dm;
  while ((dm = declRe.exec(assignRegion)) !== null) decls.push([dm[1], dm[2].trim()]);
  console.log(`  中间变量: ${decls.length ? decls.map(d => `${d[0]} = ${d[1]}`).join(' | ') : '（无）'}`);

  const ctx = vm.createContext({ res: apiReturns });
  let evalOk = true;
  for (const [name, rhs] of decls) {
    try {
      const v = vm.runInContext(rhs, ctx);
      ctx[name] = v;
      console.log(`    ${name} = ${JSON.stringify(v)}`);
    } catch (e) {
      evalOk = false;
      check(`中间链路「${name}」可求值`, false, e.message);
    }
  }
  check('中间链路全部可求值', evalOk);

  // 前端拿 prefixes 的那条语句
  const prefixesDecl = decls.find(([n]) => /prefix/i.test(n));
  check('前端有取 prefixes 的语句', !!prefixesDecl,
    decls.length ? decls.map(d => d[0]).join(', ') : '没有任何 const 声明');

  if (prefixesDecl) {
    const got = ctx[prefixesDecl[0]];
    check('取到的 prefixes 与后端完全一致',
      JSON.stringify(got) === JSON.stringify(FIXTURE.prefixes),
      `实际: ${JSON.stringify(got)}（期望: ${JSON.stringify(FIXTURE.prefixes)}）`);
    check('取到的 prefixes 非空（夹具非空，读错层级会被抓住）',
      Array.isArray(got) && got.length > 0, JSON.stringify(got));
  }

  // 关键回归点：取值链路里必须真的处理了 res.data 这一层
  check('取值链路里显式处理了 res.data 嵌套',
    decls.some(([, rhs]) => /\.data/.test(rhs)),
    decls.length ? decls.map(d => d[1]).join(' | ') : '没有任何中间声明 —— 说明仍在用未剥层的 res');

  // err 也得能取到（探测失败时前端要显示原因）
  const errDecl = decls.find(([n]) => /err/i.test(n));
  check('前端有取 error 的语句（探测失败要显示原因）', !!errDecl,
    decls.length ? decls.map(d => d[0]).join(', ') : '无');
  if (errDecl) {
    // 后端成功时给 error = null，前端用 `|| ''` 归一成空串 —— 两者在
    // 前端语义上等价（都是「没有错误」），所以这里判「空」而不是判
    // 「严格等于 null」。真正要防的是读错层级导致错误信息丢失，
    // 那由下面第 4 节「探测失败时能拿到原因」覆盖。
    check('探测成功时 error 为空（表示无错误）',
      !ctx[errDecl[0]], `实际: ${JSON.stringify(ctx[errDecl[0]])}`);
  }
}

/* ---------- 4. 探测失败时前端能显示原因 ---------- */
sec('4. 探测失败时前端拿得到原因');

if (callIdx >= 0) {
  const failResponse = nestedUnderData
    ? { success: true, data: { prefixes: [], error: '读取 http://x/openapi.json 失败：URLError' } }
    : { success: true, prefixes: [], error: '读取 http://x/openapi.json 失败：URLError' };
  const { success: _s, message: _m, ...failRest } = failResponse;
  const fctx = vm.createContext({ res: failRest });
  const afterCall2 = APP_JS.slice(callIdx);
  const tryEnd2 = afterCall2.indexOf('} catch');
  const region2 = tryEnd2 > 0 ? afterCall2.slice(0, tryEnd2) : afterCall2;
  const declRe2 = /const\s+(\w+)\s*=\s*([^;]+);/g;
  let dm2;
  let errVal;
  while ((dm2 = declRe2.exec(region2)) !== null) {
    const name = dm2[1];
    try {
      fctx[name] = vm.runInContext(dm2[2].trim(), fctx);
      if (/err/i.test(name)) errVal = fctx[name];
    } catch (e) { /* 求值失败在看错误里报 */ }
  }
  check('探测失败时 error 不为空（前端会显示它）',
    typeof errVal === 'string' && errVal.length > 0, JSON.stringify(errVal));
}

/* ---------- 5. 规则表单：字段必须真的存在 ---------- */
sec('5. 规则表单与列表的字段接线');

const newRuleIdx = APP_JS.indexOf('newRpRule()');
check('能找到 newRpRule', newRuleIdx >= 0);
if (newRuleIdx >= 0) {
  const seg = APP_JS.slice(newRuleIdx, newRuleIdx + 900);
  check('newRpRule 里有 api_path_prefix 字段',
    /api_path_prefix\s*:/.test(seg));
  check('newRpRule 的 api_path_prefix 默认空串',
    /api_path_prefix\s*:\s*''/.test(seg));
}

const editRuleIdx = APP_JS.indexOf('editRpRule(index)');
check('能找到 editRpRule', editRuleIdx >= 0);
if (editRuleIdx >= 0) {
  const seg = APP_JS.slice(editRuleIdx, editRuleIdx + 600);
  check('editRpRule 里有 api_path_prefix 归一化',
    /api_path_prefix\s*=\s*r\.api_path_prefix\s*\|\|\s*''/.test(seg),
    '少了归一化的话老规则编辑时是 undefined');
}

// 探测结果要真的回填到表单字段
const detectIdx = APP_JS.indexOf('async detectRpApiPrefix()');
check('能找到 detectRpApiPrefix', detectIdx >= 0);
if (detectIdx >= 0) {
  const seg = APP_JS.slice(detectIdx, detectIdx + 1400);
  check('探测结果回填到 r.api_path_prefix',
    /r\.api_path_prefix\s*=\s*prefixes\[0\]/.test(seg));
  // 只判「出现过 rpDetectingPrefix」是不够的：finally 里的
  // `this.rpDetectingPrefix = false` 也含这个词，删掉「置 true」那行
  // （也就是并发保护失效）照样能通过。必须判「置 true」确实在。
  check('探测开始时置 pending（防连点并发）',
    /this\.rpDetectingPrefix\s*=\s*true/.test(seg),
    'finally 里的 = false 不算数，要的是开头置 true');
  check('探测失败进 catch 提示（不是静默）', /catch/.test(seg));
  // 静默吞掉异常是最难发现的坏法：界面上一片安静，用户以为没配，
  // 于是去手填一个错的路径前缀，比直接报错更浪费时间。
  check('探测异常时给出可见提示（不是静默吞掉）',
    /rpApiPrefixHint\s*=\s*'探测失败/.test(seg),
    'catch 里必须给用户看得到的东西');
}

/* ---------- 6. 页面：输入框 + 按钮 + 列表显示 ---------- */
sec('6. index.html 的表单与列表');

check('页面有 API 路径前缀输入框',
  /x-model="rpEditingRule\.api_path_prefix"/.test(INDEX_HTML));
check('页面有「自动探测」按钮',
  /@click="detectRpApiPrefix\(\)"/.test(INDEX_HTML));
check('按钮在探测中禁用',
  /:disabled="rpDetectingPrefix"/.test(INDEX_HTML));
check('列表里显示已配置的 API 路径前缀',
  /x-text="rule\.api_path_prefix"/.test(INDEX_HTML));
check('输入框有示例提示（用户知道填什么）',
  /placeholder="[^"]*\/api\/[^"]*"/.test(INDEX_HTML));

/* ---------- 7. 端点必须真的在（不是前端写了但后端没实现） ---------- */
sec('7. 后端端点确实注册了');

check('后端注册了 /api/reverse-proxy/detect-api-prefix',
  /@app\.route\('\/api\/reverse-proxy\/detect-api-prefix',\s*methods=\['POST'\]\)/.test(APP_PY));

console.log('\n' + '='.repeat(74));
console.log(`通过 ${PASS.length} / 失败 ${FAIL.length}`);
if (FAIL.length) {
  console.log('失败项:');
  FAIL.forEach((f) => console.log('  - ' + f));
  process.exit(1);
}
console.log('全部通过');
