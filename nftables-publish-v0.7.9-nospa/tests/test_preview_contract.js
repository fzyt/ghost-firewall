/* 配置变更预览弹窗 —— 前后端契约一致性测试
 *
 * 运行: node tests/test_preview_contract.js
 *
 * 背景（2026-10-16 实测修复）：
 *   「配置变更预览」弹窗打开是**完全空的** —— 只有标题和两个按钮。
 *
 *   根因不是配色也不是数据缺失，是**前端读的 JSON 层级比后端浅一层**：
 *     后端  /api/rules/preview-changes
 *              → {"success": true, "data": {"diff":…, "risks":…, "new_rules_text":…}}
 *     api.request  const {success, message, ...data} = json; return data;
 *              → {"data": {"diff":…, "risks":…, "new_rules_text":…}}
 *     调用点     this.diffModal.diff = data.diff;          // ← 恒为 undefined
 *
 *   三个字段全是 undefined，于是弹窗六个区块的 x-show 条件全部不成立，
 *   一起隐藏 —— 而赋 undefined 完全合法，不报任何错。
 *   同文件的 /api/rules/preview 返回 {success, rules}（平铺）所以能正常显示，
 *   两个端点形状不一致正是这个 bug 能潜伏这么久的原因。
 *
 * 这个测试不做正则匹配 —— 那改个变量名就绕过去了。它做两件事：
 *   1. 从 backend/app.py 里**真的把该端点的返回结构解析出来**（是不是嵌在 data 下）
 *   2. 把前端的取值表达式**真的求值一遍**，看能不能拿到 diff/risks/new_rules_text
 * 只要两边形状对不上，或者前端少剥一层，测试立刻失败。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.dirname(__dirname);
const APP_PY = fs.readFileSync(path.join(ROOT, 'backend', 'app.py'), 'utf8');
const APP_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');

const PASS = [], FAIL = [];
const check = (name, ok, detail = '') => {
  (ok ? PASS : FAIL).push(name);
  console.log((ok ? '  ✅ ' : '  ❌ ') + name + (detail ? '  — ' + detail : ''));
};
const sec = (t) => console.log('\n=== ' + t + ' ===');

console.log('='.repeat(74));
console.log('配置变更预览：前后端响应契约一致性');
console.log('='.repeat(74));

/* ---------- 1. 解析后端真实的返回形状 ---------- */
sec('1. 后端 /api/rules/preview-changes 的返回结构');

// 截出 preview_rules_changes 函数体
const fnStart = APP_PY.indexOf('def preview_rules_changes');
if (fnStart < 0) {
  check('能找到 preview_rules_changes', false);
} else {
  check('能找到 preview_rules_changes', true);

  const body = APP_PY.slice(fnStart, APP_PY.indexOf("\n@app.route", fnStart + 10));
  // 取函数体里最后一个 jsonify( ... ) —— 成功返回那个
  const jsonifyStart = body.lastIndexOf('return jsonify(');
  const retBlock = jsonifyStart >= 0 ? body.slice(jsonifyStart, jsonifyStart + 700) : '';

  const nestedUnderData = /'success'\s*:\s*True\s*,\s*'data'\s*:/.test(retBlock)
                       || /"success"\s*:\s*true\s*,\s*"data"\s*:/.test(retBlock);
  check('后端成功返回里有 success 字段', /'success'\s*:\s*True|"success"\s*:\s*true/.test(retBlock));

  // 后端实际塞进响应体的字段名（不管嵌不嵌）
  const backendFields = ['diff', 'risks', 'new_rules_text'].filter(
    (f) => new RegExp("'" + f + "'\\s*:|\"" + f + "\"\\s*:").test(retBlock)
  );
  check('后端确实返回了 diff / risks / new_rules_text',
    backendFields.length === 3, `实际: [${backendFields.join(', ')}]`);

  console.log(`  → 后端形状: ${nestedUnderData ? "嵌套在 data 下" : "平铺"}`);

  /* ---------- 2. 复刻 api.request 的剥离逻辑 ---------- */
  sec('2. api.request 剥离后调用方拿到什么');

  // 真实从 app.js 里抠出那一行解构
  const destructureMatch = APP_JS.match(/const\s*\{\s*success\s*,\s*message\s*,\s*\.\.\.\w+\s*\}\s*=\s*json/);
  check('app.js 里有 api.request 的解构剥离', !!destructureMatch,
    destructureMatch ? destructureMatch[0] : '没找到');

  // 后端真会返回的那三个字段 —— 夹具里 risks 故意给非空数组：
  // 空数组会让 `x.risks || []` 这种「读错层级」的写法蒙混过关（退化后仍是数组），
  // 断言就永远抓不到 bug。值必须严丝合缝地等于这里，不能只判 truthy。
  const FIXTURE = {
    diff: { added: ['a'], removed: [], modified: 0 },
    risks: [{ level: 'warn', msg: 'r' }],
    new_rules_text: 'table inet filter { ... }',
  };

  // 用后端真实形状 + api.request 真实逻辑，求出调用方实际拿到的对象
  const rawResponse = nestedUnderData
    ? { success: true, data: { ...FIXTURE } }
    : { success: true, ...FIXTURE };

  const sandbox = { json: rawResponse };
  const { success, message, ...rest } = rawResponse;   // 与 app.js 同构
  const apiReturns = rest;

  check('api.request 之后 success/message 已剥离',
    !('success' in apiReturns) && !('message' in apiReturns));
  check('api.request 之后 data 字段仍在（后端嵌套时）',
    nestedUnderData ? ('data' in apiReturns) : true,
    `实际键: [${Object.keys(apiReturns).join(', ')}]`);

  /* ---------- 3. 前端取值表达式真的求值 ---------- */
  sec('3. 前端取值表达式能否拿到数据（核心断言）');

  // 从 app.js 里抠出 preview-changes 调用之后、赋值之前的全部中间语句，
  // 连同 diffModal.diff 的赋值一起**按顺序求值**。
  //
  // 不能只抠 `diffModal.diff = <expr>` 那一行：修复后的实现是两步的
  //     const data = (resp && resp.data) || resp || {};   ← 剥两层在这里
  //     this.diffModal.diff = data.diff;                  ← 这一行只是消费它
  // 只评估后半段的话，测的是 data.diff，而 data 的正确值根本没被算出来。
  const callIdx = APP_JS.indexOf("api.post('/api/rules/preview-changes'");
  check('能找到 preview-changes 调用点', callIdx >= 0);

  const afterCall = callIdx >= 0 ? APP_JS.slice(callIdx) : '';

  // 赋值区 = 这次 api 调用之后、catch 之前的那段。
  // 只能止于 catch：catch 里还有 this.diffModal.show = false，会混进来。
  const tryEnd = afterCall.indexOf('} catch');
  const assignRegion = tryEnd > 0 ? afterCall.slice(0, tryEnd) : afterCall;

  // 三个字段是三条独立赋值，不能只抠 diff 那一条 —— 否则测的是
  // data.diff 取到了没有，而不是整个弹窗内容能不能填满。
  const assignRe = /this\.diffModal\.(\w+)\s*=\s*([^;]+);/g;
  const assigns = [];
  let am;
  while ((am = assignRe.exec(assignRegion)) !== null) assigns.push([am[1], am[2].trim()]);

  check('能找到 preview 调用之后的 diffModal 赋值', assigns.length > 0,
    assigns.length ? assigns.map(a => `diff.${a[0]} = ${a[1]}`).join(' | ') : '没找到');
  assigns.forEach(([f, e]) => console.log(`  赋值: this.diffModal.${f} = ${e}`));

  // 调用点与赋值之间的中间 const 声明（剥 data 的那一步就在里面）
  const middle = assigns.length ? assignRegion.slice(0, assignRegion.indexOf('this.diffModal.')) : '';
  const declRe = /const\s+(\w+)\s*=\s*([^;]+);/g;
  const decls = [];
  let dm;
  while ((dm = declRe.exec(middle)) !== null) decls.push([dm[1], dm[2].trim()]);

  console.log(`  中间变量: ${decls.length ? decls.map(d => `${d[0]} = ${d[1]}`).join(' | ') : '（无）'}`);

  if (assigns.length) {
    const ctx = vm.createContext({ resp: apiReturns });
    try {
      // 先按顺序算完中间声明，再逐条算赋值右值
      for (const [name, rhs] of decls) {
        const v = vm.runInContext(rhs, ctx);
        ctx[name] = v;
        console.log(`    ${name} = ${JSON.stringify(v)}`);
      }
    } catch (e) {
      check('中间链路可求值', false, e.message);
    }

    // 每个字段各自求值 —— 弹窗的三个区块是靠这三个值决定显不显示的。
    // 判定用「和后端返回值完全相等」而不是 truthy/是数组：
    // 读错层级时 x.risks 会退化成 []，Array.isArray 照样为真，truthy 判定会漏放。
    const EXPECTED = {
      diff:         { label: 'diff（变更摘要）',          want: FIXTURE.diff },
      risks:        { label: 'risks（风险提示）',         want: FIXTURE.risks },
      newRulesText: { label: 'new_rules_text（完整规则）', want: FIXTURE.new_rules_text },
    };
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    const got = {};
    for (const [field, rhs] of assigns) {
      try {
        got[field] = vm.runInContext(rhs, ctx);
      } catch (e) {
        got[field] = { __error: e.message };
      }
    }

    for (const [field, spec] of Object.entries(EXPECTED)) {
      if (!(field in got)) {
        check(`能取到 ${spec.label}`, false, '代码里没有给 this.diffModal.' + field + ' 赋值');
        continue;
      }
      check(`能取到 ${spec.label}`, same(got[field], spec.want),
        `实际: ${JSON.stringify(got[field])}（期望: ${JSON.stringify(spec.want)}）`);
    }

    // 关键回归点：链条里必须真的处理了 resp.data 这一层
    check('取值链路里显式处理了 resp.data 嵌套',
      decls.some(([, rhs]) => /\.data/.test(rhs)),
      decls.length ? decls.map(d => d[1]).join(' | ') : '没有任何中间声明 —— 说明仍在用未剥层的 resp');
  }

  /* ---------- 4. 防回归：形状不一致这个温床 ---------- */
  sec('4. 同类端点形状一致性（这才是 bug 的温床）');

  // 找出所有后端端点里 return jsonify 用了 'data' 嵌套的
  const nestedEndpoints = [];
  const re = /@app\.route\('([^']+)'[\s\S]{0,4000}?return jsonify\(/g;
  let m;
  while ((m = re.exec(APP_PY)) !== null) {
    const chunk = APP_PY.slice(m.index, m.index + 4200);
    if (/'success'\s*:\s*True\s*,\s*'data'\s*:/.test(chunk)) nestedEndpoints.push(m[1]);
  }
  console.log(`  使用 {success, data:{...}} 嵌套形状的端点: ${nestedEndpoints.length} 个`);
  nestedEndpoints.slice(0, 8).forEach((e) => console.log('    - ' + e));

  // 预览端点必须在其中，且前端必须能处理嵌套
  check('preview-changes 属于嵌套端点（前端需剥两层）',
    nestedEndpoints.includes('/api/rules/preview-changes'),
    '不属于说明后端改过形状，测试要同步更新');

  check('前端取值对「嵌套」和「平铺」两种形状都能工作',
    decls.some(([, rhs]) => /\.data/.test(rhs) && /\|\|/.test(rhs)),
    decls.length ? decls.map(d => d[1]).join(' | ') : '无中间声明');
}

console.log('\n' + '='.repeat(74));
console.log(`通过 ${PASS.length} / 失败 ${FAIL.length}`);
if (FAIL.length) {
  console.log('失败项:');
  FAIL.forEach((f) => console.log('  - ' + f));
  process.exit(1);
}
console.log('全部通过');
