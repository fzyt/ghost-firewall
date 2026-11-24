/* 「上游 API 路径前缀 / 根绝对路径改写」—— 2026-11-24 改成自动探测后的契约测试
 *
 * 运行: node tests/test_api_prefix_frontend.js
 *
 * 背景：这两个字段原来是**界面上手填**的（一个输入框 + 一个勾选框），
 * 填错的后果是「页面能开、数据接口全 404」，症状极具迷惑性。
 * 2026-11-24 起改为：**新建规则时由后端自动探测上游后决定**，
 * 界面上的两个框撤掉。
 *
 * 所以本测试的断言方向整个反过来了：
 *   ① 「该出现」—— 后端自动装配在、探测结论能回填到界面；
 *   ② 「不该出现」—— 界面上那两个框、手动探测按钮必须**真的不在**。
 *
 * ⚠️ 「不该出现」类断言必须基于**去注释后的源码**：
 *    否则注释里写一句「原来这里有 detectRpApiPrefix 按钮」就误判。
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

/* 去掉 JS 注释（行注释 + 块注释），保留字符串字面量里的内容。
 * 与 tests/test_aliyun_ddns_update.py 里的 strip_js_comments 同一套算法。 */
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

/* 去掉 HTML 注释 */
function stripHtmlComments(src) {
  return src.replace(/<!--[\s\S]*?-->/g, '');
}

const JS_CODE = stripJsComments(APP_JS);
const HTML_CODE = stripHtmlComments(INDEX_HTML);

console.log('='.repeat(74));
console.log('路径改写自动探测：前后端契约');
console.log('='.repeat(74));

/* ---------- 1. 后端：自动装配存在，且只在新建路径上调用 ---------- */
sec('1. 后端 _rp_autofill_path_rewrite');

check('后端定义了 _rp_autofill_path_rewrite',
  /def\s+_rp_autofill_path_rewrite\s*\(/.test(APP_PY));

/* 取 POST / PUT 两个路由的函数体（到下一个 @app.route 为止） */
function routeBody(marker) {
  const idx = APP_PY.indexOf(marker);
  if (idx < 0) return '';
  const rest = APP_PY.slice(idx + marker.length);
  const next = rest.indexOf('\n@app.route');
  return next >= 0 ? rest.slice(0, next) : rest;
}
const createBody = routeBody("def rp_create_rule():");
const updateBody = routeBody("def rp_update_rule(rule_id):");

check('能找到 POST 新建路由', createBody.length > 0);
check('能找到 PUT 更新路由', updateBody.length > 0);
check('POST（新建）调用了自动装配',
  /_rp_autofill_path_rewrite\s*\(\s*clean\s*\)/.test(createBody),
  '新建时必须由后端探测后决定这两个字段');
check('PUT（编辑）**不**调用自动装配',
  !/_rp_autofill_path_rewrite\s*\(/.test(updateBody),
  '编辑时不覆盖：内置 /fw 规则的硬编码值会被探测结论改坏'
    + '（面板首页正文里写着 href="//cdn.example.com/x.css 这句说明文字，'
    + '按协议相对规则会判成「不能开」）');

/* 自动装配的返回值要回传给前端，否则界面显示与实际生效值对不上 */
check('POST 把探测结论回传给前端',
  /"autofill_note"\s*:/.test(createBody)
  && /"api_path_prefix"\s*:/.test(createBody)
  && /"rewrite_root_paths"\s*:/.test(createBody),
  '少了任一个，前端列表就显示不出实际生效的改写');

/* ---------- 2. 界面：两个框必须真的不在 ---------- */
sec('2. 界面上不再有手动输入框与勾选框');

check('没有「上游 API 路径前缀」输入框',
  !/x-model="rpEditingRule\.api_path_prefix"/.test(HTML_CODE));
check('没有「根绝对路径改写」勾选框',
  !/x-model="rpEditingRule\.rewrite_root_paths"/.test(HTML_CODE));
check('没有「自动探测」按钮',
  !/@click="detectRpApiPrefix\(\)"/.test(HTML_CODE));
check('没有「检测协议相对 URL」按钮',
  !/@click="detectRpProtocolRelative\(\)"/.test(HTML_CODE));
check('前端不再有 detectRpApiPrefix 方法',
  !/detectRpApiPrefix/.test(JS_CODE));
check('前端不再有 detectRpProtocolRelative 方法',
  !/detectRpProtocolRelative/.test(JS_CODE));
check('前端不再有探测用的状态变量',
  !/rpApiPrefixHint/.test(JS_CODE)
  && !/rpProtoRelHint/.test(JS_CODE)
  && !/rpDetectingPrefix/.test(JS_CODE)
  && !/rpDetectingProtoRel/.test(JS_CODE));

/* ---------- 3. 界面：探测结论要看得见 ---------- */
sec('3. 界面上的只读展示');

check('编辑表单里展示当前 API 路径前缀',
  /x-text="rpEditingRule\?\.api_path_prefix"/.test(HTML_CODE));
check('编辑表单里展示当前是否开了根绝对路径改写',
  /x-show="rpEditingRule\?\.rewrite_root_paths"/.test(HTML_CODE));
check('列表里仍显示已配置的 API 路径前缀',
  /x-text="rule\.api_path_prefix"/.test(HTML_CODE));
check('列表里仍显示根绝对路径改写的开关状态',
  /x-show="rule\.rewrite_root_paths"/.test(HTML_CODE));

/* ---------- 4. 前端：字段与回填 ---------- */
sec('4. 前端字段与探测结论回填');

const newRuleIdx = JS_CODE.indexOf('newRpRule()');
check('能找到 newRpRule', newRuleIdx >= 0);
if (newRuleIdx >= 0) {
  const seg = JS_CODE.slice(newRuleIdx, newRuleIdx + 900);
  check('newRpRule 里仍有 api_path_prefix 字段（后端要收）',
    /api_path_prefix\s*:/.test(seg));
  check('newRpRule 里仍有 rewrite_root_paths 字段（后端要收）',
    /rewrite_root_paths\s*:/.test(seg));
}

const editRuleIdx = JS_CODE.indexOf('editRpRule(index)');
check('能找到 editRpRule', editRuleIdx >= 0);
if (editRuleIdx >= 0) {
  const seg = JS_CODE.slice(editRuleIdx, editRuleIdx + 600);
  check('editRpRule 里有 api_path_prefix 归一化',
    /api_path_prefix\s*=\s*r\.api_path_prefix\s*\|\|\s*''/.test(seg),
    '少了归一化的话老规则编辑时是 undefined');
}

/* ⚠️ 这一条是本批最容易漏的：不回填的话，列表里显示的还是保存前的空值，
 *    而服务端其实已经按探测结论填好了 —— 界面与实际生效值对不上。
 *
 * ⚠️ 断言必须判**赋的值**，不能只判「出现过这行赋值」：
 *    把 `= created.api_path_prefix` 改成 `= ''` 照样能通过只判赋值的断言。
 */
const saveIdx = JS_CODE.indexOf('async saveRpRules()');
check('能找到 saveRpRules', saveIdx >= 0);
if (saveIdx >= 0) {
  const seg = JS_CODE.slice(saveIdx, saveIdx + 2000);
  check('保存后把后端返回的 api_path_prefix 写回本地规则对象',
    /this\.rp\.rules\[\s*i\s*\]\.api_path_prefix\s*=\s*created\.api_path_prefix/.test(seg),
    '必须真的取后端返回的值，不能赋空串');
  check('保存后把后端返回的 rewrite_root_paths 写回本地规则对象',
    /this\.rp\.rules\[\s*i\s*\]\.rewrite_root_paths\s*=\s*!!?created\.rewrite_root_paths/.test(seg),
    '必须真的取后端返回的值');
  check('自动探测结论（autofill_note）回显给用户',
    /autofill_note/.test(seg)
    && /showToast\(\s*'反代规则已保存'[^;]*autofillNote/s.test(seg),
    '探测结论不显示 = 用户不知道系统替它做了什么决定');
}

/* ---------- 5. 诊断端点仍然在（前后端契约没破） ---------- */
sec('5. 诊断端点仍注册、返回形状不变');

check('后端注册了 /api/reverse-proxy/detect-api-prefix',
  /@app\.route\('\/api\/reverse-proxy\/detect-api-prefix',\s*methods=\['POST'\]\)/.test(APP_PY));
check('后端注册了 /api/reverse-proxy/detect-protocol-relative',
  /@app\.route\('\/api\/reverse-proxy\/detect-protocol-relative',\s*methods=\['POST'\]\)/.test(APP_PY));

const fnStart = APP_PY.indexOf('def rp_detect_api_prefix');
check('能找到 rp_detect_api_prefix', fnStart >= 0);
if (fnStart >= 0) {
  const body = APP_PY.slice(fnStart, APP_PY.indexOf('\n@app.route', fnStart + 10));
  const jsonifyStart = body.lastIndexOf('return jsonify(');
  const retBlock = jsonifyStart >= 0 ? body.slice(jsonifyStart, jsonifyStart + 700) : '';
  // 后端可能用单引号+True、双引号+True 等等各种写法，断言必须全认。
  const SUCCESS_RE = /(['"])success\1\s*:\s*(True|true)\b/;
  const NESTED_RE = /(['"])success\1\s*:\s*(True|true)\s*,\s*(['"])data\3\s*:/;
  check('后端成功返回里有 success 字段', SUCCESS_RE.test(retBlock),
    retBlock.slice(0, 120).replace(/\n/g, ' '));
  check('后端把 prefixes / error 放在 data 信封里', NESTED_RE.test(retBlock),
    '平铺的话调用方就该读 res.prefixes —— 形状变了测试要同步改');
  const backendFields = ['prefixes', 'error'].filter(
    (f) => new RegExp("(['\"])" + f + "\\1\\s*:").test(retBlock));
  check('后端确实返回了 prefixes / error',
    backendFields.length === 2, `实际: [${backendFields.join(', ')}]`);
}

console.log('\n' + '='.repeat(74));
console.log(`通过 ${PASS.length} / 失败 ${FAIL.length}`);
if (FAIL.length) {
  console.log('失败项:');
  FAIL.forEach((f) => console.log('  - ' + f));
  process.exit(1);
}
console.log('全部通过');
