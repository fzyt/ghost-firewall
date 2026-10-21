/* 「根绝对路径改写 + 协议相对 URL 预检」的前后端契约一致性测试
 *
 * 运行: node tests/test_gateway_path_rewrite_frontend.js
 *
 * 为什么单独写这个文件（而不是在 test_frontend.js 里加两行）：
 *
 *   第十七节那个 bug —— 前端读的 JSON 层级比后端浅一层 —— 是这个项目里
 *   **已经犯过一次**的错误：api.request 只剥顶层的 {success, message}，
 *   data 信封原样留着，而后端把业务数据都放在 data 里。同一类错误在
 *   新的预检端点上再犯一次，症状是「探测成功了，页面却说没探测到」。
 *
 *   而且前端还有两处**归一**逻辑（newRpRule / editRpRule），它们跟后端的
 *   布尔校验是配套的：后端只认 true/false，前端必须把 undefined、字符串
 *   'false' 之类归一成布尔，否则「关掉开关」这个动作可能传成真值。
 *   这两处正则断言很容易写漏，所以这里**真的把函数取出来求值一遍**。
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
console.log('根绝对路径改写 / 协议相对 URL 预检：前后端契约');
console.log('='.repeat(74));

/* ---------- 1. 后端预检端点的返回形状 ---------- */
sec('1. 后端 /api/reverse-proxy/detect-protocol-relative 的返回结构');

const fnStart = APP_PY.indexOf('def rp_detect_protocol_relative');
check('能找到 rp_detect_protocol_relative', fnStart >= 0);

let nestedUnderData = false;
if (fnStart >= 0) {
  const body = APP_PY.slice(fnStart, APP_PY.indexOf('\n@app.route', fnStart + 10));
  const jsonifyStart = body.lastIndexOf('return jsonify(');
  const retBlock = jsonifyStart >= 0 ? body.slice(jsonifyStart, jsonifyStart + 700) : '';

  const SUCCESS_RE = /(['"])success\1\s*:\s*(True|true)\b/;
  const NESTED_RE = /(['"])success\1\s*:\s*(True|true)\s*,\s*(['"])data\3\s*:/;
  nestedUnderData = NESTED_RE.test(retBlock);

  check('后端成功返回里有 success 字段', SUCCESS_RE.test(retBlock),
    retBlock.slice(0, 120).replace(/\n/g, ' '));
  check('后端把 count/samples/error 放在 data 信封里', nestedUnderData,
    '平铺的话前端就该读 res.count —— 形状变了测试要同步改');

  for (const f of ['count', 'samples', 'error']) {
    check(`后端确实返回了 ${f}`,
      new RegExp("(['\"])" + f + "\\1\\s*:").test(retBlock));
  }
}

/* ---------- 2. 复刻 api.request 的剥离逻辑 ---------- */
sec('2. api.request 剥离后调用方拿到什么');

const destructureMatch = APP_JS.match(/const\s*\{\s*success\s*,\s*message\s*,\s*\.\.\.\w+\s*\}\s*=\s*json/);
check('app.js 里有 api.request 的解构剥离', !!destructureMatch,
  destructureMatch ? destructureMatch[0] : '没找到');

// 夹具：count 必须非 0 —— 空数组/0 会让「读错层级」的写法蒙混过关。
const FIXTURE = { count: 3, samples: ['href="//cdn/x.css'], error: null };

const rawResponse = nestedUnderData
  ? { success: true, data: { ...FIXTURE } }
  : { success: true, ...FIXTURE };
const { success, message, ...rest } = rawResponse;
const apiReturns = rest;

check('api.request 之后 success/message 已剥离',
  !('success' in apiReturns) && !('message' in apiReturns));
check('api.request 之后 data 字段仍在', 'data' in apiReturns,
  `实际键: [${Object.keys(apiReturns).join(', ')}]`);

/* ---------- 3. 前端取值表达式真的求值 ---------- */
sec('3. 前端取值表达式能否拿到 count/samples（核心断言）');

const callIdx = APP_JS.indexOf("api.post('/api/reverse-proxy/detect-protocol-relative'");
check('能找到预检端点的调用点', callIdx >= 0);

if (callIdx >= 0) {
  const afterCall = APP_JS.slice(callIdx);
  const tryEnd = afterCall.indexOf('} catch');
  const assignRegion = tryEnd > 0 ? afterCall.slice(0, tryEnd) : afterCall;

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
  check('取值链路里显式处理了 res.data 嵌套',
    decls.some(([, rhs]) => /\.data/.test(rhs)),
    decls.length ? decls.map(d => d[1]).join(' | ') : '没有任何中间声明');

  const countDecl = decls.find(([n]) => /^count$/i.test(n));
  const samplesDecl = decls.find(([n]) => /samples/i.test(n));
  const errDecl = decls.find(([n]) => /err/i.test(n));

  check('前端有取 count 的语句', !!countDecl,
    decls.length ? decls.map(d => d[0]).join(', ') : '没有任何 const 声明');
  check('前端有取 samples 的语句', !!samplesDecl);
  check('前端有取 err 的语句', !!errDecl);

  if (countDecl) {
    const got = ctx[countDecl[0]];
    check('取到的 count 与后端完全一致', got === FIXTURE.count,
      `实际: ${JSON.stringify(got)}（期望: ${FIXTURE.count}）`);
    check('取到的 count 非 0（夹具非 0，读错层级会被抓住）', got === 3, JSON.stringify(got));
  }
  if (samplesDecl) {
    const got = ctx[samplesDecl[0]];
    check('取到的 samples 与后端完全一致',
      JSON.stringify(got) === JSON.stringify(FIXTURE.samples),
      `实际: ${JSON.stringify(got)}`);
    check('取到的 samples 非空', Array.isArray(got) && got.length > 0, JSON.stringify(got));
  }
}

/* ---------- 4. 开关字段的归一 ---------- */
sec('4. rewrite_root_paths 字段的归一（与后端布尔校验配套）');

// newRpRule() 里必须显式给 false —— 不给的话表单的 checkbox 拿到
// undefined，虽然行为一样，但「新增规则」和「编辑规则」的字段形状就不一致了。
const newRuleBody = APP_JS.slice(APP_JS.indexOf('newRpRule()'));
const newRuleEnd = newRuleBody.indexOf('},', newRuleBody.indexOf('this.rpEditingRule = {'));
const newRuleSrc = newRuleBody.slice(0, newRuleEnd > 0 ? newRuleEnd : 1200);
check('newRpRule() 里有 rewrite_root_paths 字段',
  /rewrite_root_paths\s*:\s*false/.test(newRuleSrc),
  newRuleSrc.match(/rewrite_root_paths[^\n]*/) ? newRuleSrc.match(/rewrite_root_paths[^\n]*/)[0] : '没有');

// editRpRule() 必须用 === true 归一：后端只认 true/false，
// undefined / 'false' / 1 这类杂值传过去会被当成关（安全侧降级），
// 但如果前端不做归一，后端就永远收不到 true，开关打不开。
const editBody = APP_JS.slice(APP_JS.indexOf('editRpRule('));
const editEnd = editBody.indexOf('this.rpEditingRule = r;');
const editSrc = editBody.slice(0, editEnd > 0 ? editEnd : 1200);
check('editRpRule() 里对 rewrite_root_paths 做了 === true 归一',
  /rewrite_root_paths\s*=\s*[^;]*===\s*true/.test(editSrc),
  editSrc.match(/rewrite_root_paths[^\n]*/) ? editSrc.match(/rewrite_root_paths[^\n]*/)[0] : '没有');

/* ---------- 5. 表单与列表 ---------- */
sec('5. 表单绑定与列表显示');

check('编辑表单里 checkbox 绑定了 rewrite_root_paths',
  /type="checkbox"[^>]*x-model="rpEditingRule\.rewrite_root_paths"/.test(INDEX_HTML));
check('编辑表单里引入了预检按钮',
  /detectRpProtocolRelative\(\)/.test(INDEX_HTML));
check('预检按钮的状态变量已声明',
  /rpDetectingProtoRel\s*:\s*false/.test(APP_JS));
check('预检提示变量已声明',
  /rpProtoRelHint\s*:\s*''/.test(APP_JS));
check('列表里显示了「根绝对路径改写」这一项',
  /<div x-show="rule\.rewrite_root_paths">/.test(INDEX_HTML),
  '锚定到显示块那一行 —— 只查子串的话，同名表达式在别处出现就会蒙混过关');
check('列表里那一项的文案随开关切换',
  /x-text="rule\.rewrite_root_paths \? /.test(INDEX_HTML));

/* ---------- 6. 后端字段白名单 ---------- */
sec('6. 后端字段清洗');

const vrStart = APP_PY.indexOf('def _validate_rp_service');
check('能找到 _validate_rp_service', vrStart >= 0);
if (vrStart >= 0) {
  const body = APP_PY.slice(vrStart, APP_PY.indexOf('\ndef ', vrStart + 10));
  check('字段清洗里有 rewrite_root_paths',
    /clean\["rewrite_root_paths"\]/.test(body));
  check('非布尔值降级为 False',
    /isinstance\(rrp,\s*\(bool,\s*int\)\)/.test(body),
    body.match(/clean\["rewrite_root_paths"\][^\n]*/) ?
      body.match(/clean\["rewrite_root_paths"\][^\n]*/)[0] : '没有');
}

console.log('\n' + '='.repeat(74));
console.log(`合计: ✅ ${PASS.length}   ❌ ${FAIL.length}`);
if (FAIL.length) {
  for (const f of FAIL) console.log('  ❌ ' + f);
  process.exit(1);
}
console.log('全部通过');
