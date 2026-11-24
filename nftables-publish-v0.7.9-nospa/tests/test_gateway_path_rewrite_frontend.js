/* 「根绝对路径改写」的后端契约 + 字段归一测试
 *
 * 运行: node tests/test_gateway_path_rewrite_frontend.js
 *
 * 2026-11-24 变更：界面上手填的这两个字段（输入框 + 勾选框）已撤掉，
 * 改成**新建时由后端自动探测上游后决定**（见 backend 的
 * _rp_autofill_path_rewrite 与 test_api_prefix_frontend.js）。
 *
 * 本文件保留的是**仍然属于这一侧**的断言：
 *   · 诊断端点 /api/reverse-proxy/detect-protocol-relative 的返回形状
 *     （端点保留为诊断入口，返回结构不能变）；
 *   · 后端字段白名单与非布尔值降级；
 *   · 前端 newRpRule / editRpRule 的字段归一（后端只认 true/false）；
 *   · 列表里的显示。
 * 而「前端手动调用预检端点」那几节已随界面改动一起作废。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const APP_PY = fs.readFileSync(path.join(ROOT, 'backend', 'app.py'), 'utf8');
const APP_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');
const INDEX_HTML = fs.readFileSync(path.join(ROOT, 'frontend', 'index.html'), 'utf8');

const PASS = [], FAIL = [];
const check = (name, ok, detail = '') => {
  (ok ? PASS : FAIL).push(name);
  console.log((ok ? '  [PASS] ' : '  [FAIL] ') + name + (detail ? '  — ' + detail : ''));
};
const sec = (t) => console.log('\n=== ' + t + ' ===');

/* 去注释（与 tests/test_aliyun_ddns_update.py 同一套算法）：
 * 「不该出现的东西」类断言必须基于去注释版源码，
 * 否则注释里写一句「原来这里有勾选框」就误判。 */
function stripJsComments(src) {
  let out = '', i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      out += c; i += 1;
      while (i < n) {
        out += src[i];
        if (src[i] === '\\') {
          i += 1;
          if (i < n) { out += src[i]; i += 1; }
          continue;
        }
        if (src[i] === quote) { i += 1; break; }
        i += 1;
      }
      continue;
    }
    if (c === '/' && i + 1 < n && src[i + 1] === '/') {
      while (i < n && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '/' && i + 1 < n && src[i + 1] === '*') {
      i += 2;
      while (i + 1 < n && !(src[i] === '*' && src[i + 1] === '/')) i += 1;
      i += 2;
      continue;
    }
    out += c; i += 1;
  }
  return out;
}
const JS_CODE = stripJsComments(APP_JS);
const HTML_CODE = INDEX_HTML.replace(/<!--[\s\S]*?-->/g, '');

console.log('='.repeat(74));
console.log('根绝对路径改写：后端契约与字段归一');
console.log('='.repeat(74));

/* ---------- 1. 后端预检端点的返回形状 ---------- */
sec('1. 后端 /api/reverse-proxy/detect-protocol-relative 的返回结构');

const fnStart = APP_PY.indexOf('def rp_detect_protocol_relative');
check('能找到 rp_detect_protocol_relative', fnStart >= 0);

if (fnStart >= 0) {
  const body = APP_PY.slice(fnStart, APP_PY.indexOf('\n@app.route', fnStart + 10));
  const jsonifyStart = body.lastIndexOf('return jsonify(');
  const retBlock = jsonifyStart >= 0 ? body.slice(jsonifyStart, jsonifyStart + 700) : '';

  const SUCCESS_RE = /(['"])success\1\s*:\s*(True|true)\b/;
  const NESTED_RE = /(['"])success\1\s*:\s*(True|true)\s*,\s*(['"])data\3\s*:/;
  const nestedUnderData = NESTED_RE.test(retBlock);

  check('后端成功返回里有 success 字段', SUCCESS_RE.test(retBlock),
    retBlock.slice(0, 120).replace(/\n/g, ' '));
  check('后端把 count/samples/error 放在 data 信封里', nestedUnderData,
    '平铺的话调用方就该读 res.count —— 形状变了测试要同步改');

  for (const f of ['count', 'samples', 'error']) {
    check(`后端确实返回了 ${f}`,
      new RegExp("(['\"])" + f + "\\1\\s*:").test(retBlock));
  }
}

/* ---------- 2. 开关字段的归一 ---------- */
sec('2. rewrite_root_paths 字段的归一（与后端布尔校验配套）');

// newRpRule() 里必须显式给 false —— 不给的话规则对象的字段形状
// 与「编辑规则」不一致，后端收到的键也就不是一个样。
const newRuleBody = JS_CODE.slice(JS_CODE.indexOf('newRpRule()'));
const newRuleEnd = newRuleBody.indexOf('},', newRuleBody.indexOf('this.rpEditingRule = {'));
const newRuleSrc = newRuleBody.slice(0, newRuleEnd > 0 ? newRuleEnd : 1200);
check('newRpRule() 里有 rewrite_root_paths 字段',
  /rewrite_root_paths\s*:\s*false/.test(newRuleSrc),
  newRuleSrc.match(/rewrite_root_paths[^\n]*/) ? newRuleSrc.match(/rewrite_root_paths[^\n]*/)[0] : '没有');

// editRpRule() 必须用 === true 归一：后端只认 true/false，
// undefined / 'false' / 1 这类杂值传过去会被当成关（安全侧降级），
// 但如果前端不做归一，后端就永远收不到 true，开关打不开。
const editBody = JS_CODE.slice(JS_CODE.indexOf('editRpRule('));
const editEnd = editBody.indexOf('this.rpEditingRule = r;');
const editSrc = editBody.slice(0, editEnd > 0 ? editEnd : 1200);
check('editRpRule() 里对 rewrite_root_paths 做了 === true 归一',
  /rewrite_root_paths\s*=\s*[^;]*===\s*true/.test(editSrc),
  editSrc.match(/rewrite_root_paths[^\n]*/) ? editSrc.match(/rewrite_root_paths[^\n]*/)[0] : '没有');

/* ---------- 3. 界面：勾选框与预检按钮必须不在 ---------- */
sec('3. 界面上的手动入口已撤掉');

check('编辑表单里不再有 rewrite_root_paths 勾选框',
  !/x-model="rpEditingRule\.rewrite_root_paths"/.test(HTML_CODE));
check('界面上不再有「检测协议相对 URL」按钮',
  !/@click="detectRpProtocolRelative\(\)"/.test(HTML_CODE));
check('前端不再有 detectRpProtocolRelative 方法',
  !/detectRpProtocolRelative/.test(JS_CODE));
check('前端不再有预检用的状态变量',
  !/rpDetectingProtoRel/.test(JS_CODE) && !/rpProtoRelHint/.test(JS_CODE));

/* ---------- 4. 列表显示 ---------- */
sec('4. 列表显示');

check('列表里显示了「根绝对路径改写」这一项',
  /<div x-show="rule\.rewrite_root_paths">/.test(HTML_CODE),
  '锚定到显示块那一行 —— 只查子串的话，同名表达式在别处出现就会蒙混过关');
check('列表里那一项的文案随开关切换',
  /x-text="rule\.rewrite_root_paths \? /.test(HTML_CODE));

/* ---------- 5. 后端字段白名单 ---------- */
sec('5. 后端字段清洗');

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

/* ---------- 6. 自动装配的判定口径 ---------- */
sec('6. 后端自动装配的判定口径');

const afStart = APP_PY.indexOf('def _rp_autofill_path_rewrite');
check('能找到 _rp_autofill_path_rewrite', afStart >= 0);
if (afStart >= 0) {
  const body = APP_PY.slice(afStart, APP_PY.indexOf('\ndef ', afStart + 10));
  check('自动装配用 _detect_upstream_api_prefixes 探 API 前缀',
    /_detect_upstream_api_prefixes\s*\(/.test(body));
  check('自动装配用 _detect_upstream_path_shapes 探根绝对路径',
    /_detect_upstream_path_shapes\s*\(/.test(body));
  check('自动装配受 LAN 网段限制（P2-9 的同一条边界）',
    /_detect_target_allowed\s*\(/.test(body),
    '探测本质是用面板去抓 URL，放开就是通用抓取器');
  check('探测不出来时不动这两个字段',
    /探测失败|err2/.test(body) && !/clean\["api_path_prefix"\]\s*=\s*""/.test(body),
    '探测失败 ≠ 结论是「不需要」，不能把已有值清掉');
  check('有协议相对 URL 时不开根绝对路径改写',
    /proto_rel\s*>\s*0/.test(body),
    '宽模式的 sub_filter 是字面量匹配，必然把 href="// 一起改坏');
}

console.log('\n' + '='.repeat(74));
console.log(`合计: 通过 ${PASS.length}   失败 ${FAIL.length}`);
if (FAIL.length) {
  for (const f of FAIL) console.log('  [FAIL] ' + f);
  process.exit(1);
}
console.log('全部通过');
