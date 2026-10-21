/* 「配置保存：版本闸 + reverse_proxy 归属」的前后端契约测试
 *
 * 运行: node tests/test_config_ownership_frontend.js
 *
 * 2026-10-21 .1 事故的另一半在前端：
 *
 *   ① 前端把**整份** config（含 reverse_proxy）原样回传 POST /api/config，
 *      而它那份 reverse_proxy 是页面加载时的旧快照
 *      （`grep reverse_proxy frontend/` 命中 0 处 —— 前端根本不认识这个词，
 *        它只是作为 this.config 里一个不透明 blob 被动跟着走）；
 *   ② 后端整份覆盖 ⇒ 磁盘上刚建好的反代规则和证书被旧快照静默清空。
 *
 * 主防线在后端（无条件剔除 reverse_proxy）。前端这一侧要钉的是：
 *   · 保存成功后**换掉**手里的版本号（否则连点两次保存，第二次撞 409）
 *   · 后端返回 CONFIG_STALE 时说清楚并让用户重新加载
 *
 * 这里把 confirmSaveConfig **真的取出来求值一遍**（沙箱 + 假 api），
 * 而不是只 grep 源码 —— 第十七节那个「读的 JSON 层级比后端浅一层」的 bug
 * 就是只靠 grep 放过去的。
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
console.log('配置保存：版本闸 + reverse_proxy 归属（前后端契约）');
console.log('='.repeat(74));

/* ---------- 1. 后端契约 ---------- */
sec('1. 后端 /api/config 的 config_rev 契约');

check('后端有 _config_rev 函数', /def _config_rev\(/.test(APP_PY));
check('后端有 RP_OWNED_CONFIG_KEYS 常量', /RP_OWNED_CONFIG_KEYS\s*=\s*frozenset\(/.test(APP_PY));
check("RP_OWNED_CONFIG_KEYS 里含 'reverse_proxy'",
  /RP_OWNED_CONFIG_KEYS\s*=\s*frozenset\(\{\s*'reverse_proxy',?\s*\}\)/.test(APP_PY),
  '少了它，主防线就没了');

const getCfgIdx = APP_PY.indexOf("def get_config()");
const getCfgBody = getCfgIdx >= 0
  ? APP_PY.slice(getCfgIdx, APP_PY.indexOf('\n@app.route', getCfgIdx + 10)) : '';
check('GET /api/config 的返回里带 config_rev',
  /config_rev\s*=\s*_config_rev\(/.test(getCfgBody),
  '前端要靠它判断快照是不是过期');

const postIdx = APP_PY.indexOf('def post_config()');
const postBody = postIdx >= 0
  ? APP_PY.slice(postIdx, APP_PY.indexOf('\n@app.route', postIdx + 10)) : '';
check('POST /api/config 会拒收过期快照（CONFIG_STALE）',
  /'code':\s*'CONFIG_STALE'/.test(postBody));
check('POST /api/config 会把 reverse_proxy 从提交里剔除',
  /for k in RP_OWNED_CONFIG_KEYS:\s*\n\s*incoming\.pop\(k, None\)/.test(postBody),
  '主防线：无条件剔除，不看调用方是谁');
check('POST /api/config 的响应里带新的 config_rev',
  /'config_rev':\s*_config_rev\(new_cfg\)/.test(postBody));

/* ---------- 2. 把 confirmSaveConfig 取出来求值 ---------- */
sec('2. confirmSaveConfig 的真实行为（沙箱求值）');

/** 取出一个方法定义（含配对的大括号），忽略字符串里的括号 */
function extractMethod(src, name) {
  const start = src.indexOf(name + '(');
  if (start < 0) return null;
  const open = src.indexOf('{', start);
  if (open < 0) return null;
  let depth = 0, i = open, quote = null;
  for (; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === '\\') { i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '\'' || c === '"' || c === '`') { quote = c; continue; }
    if (c === '{') depth++;
    else if (c === '}') { depth--; if (depth === 0) { i++; break; } }
  }
  return src.slice(start, i);
}

const methodSrc = extractMethod(APP_JS, 'async confirmSaveConfig');
check('能从 app.js 里取出 confirmSaveConfig', !!methodSrc);

function makeApp() {
  return {
    config: { config_rev: 'OLDREV', whitelist_timeout: 18000 },
    diffModal: {
      pendingConfig: { config_rev: 'OLDREV', whitelist_timeout: 18000 },
      show: true, risks: [], loading: false, diff: null, newRulesText: '',
    },
    saving: false,
    toasts: [],
    loaded: 0,
    showToast(msg, kind) { this.toasts.push({ msg, kind }); },
    async loadConfig() {
      this.loaded++;
      this.config.config_rev = 'REV_FROM_RELOAD';
    },
  };
}

async function runConfirm(app, apiStub, confirmResult = false) {
  const ctx = vm.createContext({
    api: apiStub,
    confirm: () => confirmResult,
    console,
  });
  const fnSrc = methodSrc.replace('confirmSaveConfig()', 'function confirmSaveConfig()');
  const fn = vm.runInContext('(' + fnSrc + ')', ctx);
  await fn.call(app);
}

/* 2a. 成功路径：必须换掉版本号 */
(async () => {
  const sent = [];
  const apiStub = {
    post: async (url, body) => {
      sent.push({ url, body });
      return { data: { config_rev: 'NEWREV', risks: [] } };
    },
  };
  const app = makeApp();
  await runConfirm(app, apiStub);

  check('POST 打到 /api/config', sent.length === 1 && sent[0].url === '/api/config',
    `实际=${sent.length ? sent[0].url : '没发'}`);
  check('POST 体里带上了 config_rev（版本闸靠它）',
    sent.length === 1 && sent[0].body.config_rev === 'OLDREV',
    `实际=${sent.length ? JSON.stringify(sent[0].body.config_rev) : 'N/A'}`);
  check('POST 体里带上了 confirm=true',
    sent.length === 1 && sent[0].body.confirm === true);
  check('★ 保存成功后换掉了手里的版本号',
    app.config.config_rev === 'NEWREV',
    `实际=${app.config.config_rev}（期望 NEWREV）`);
  check('保存成功后弹了成功提示',
    app.toasts.some(t => t.kind === 'success'),
    JSON.stringify(app.toasts));

  /* 2b. CONFIG_STALE：说清楚 + 让用户重新加载 */
  const sent2 = [];
  const staleApi = {
    post: async (url, body) => {
      sent2.push({ url, body });
      const err = new Error('配置在你打开页面之后被改过');
      err.code = 'CONFIG_STALE';
      err.data = { success: false, code: 'CONFIG_STALE', data: { config_rev: 'SERVER_REV' } };
      throw err;
    },
  };
  const app2 = makeApp();
  await runConfirm(app2, staleApi, true);

  check('CONFIG_STALE 时也发了请求（错误来自后端）', sent2.length === 1);
  check('★ CONFIG_STALE 时关闭了 diff 弹窗', app2.diffModal.show === false);
  check('★ CONFIG_STALE 时清掉了 pendingConfig', app2.diffModal.pendingConfig === null);
  check('★ CONFIG_STALE 时提示了用户',
    app2.toasts.some(t => t.kind === 'error'),
    JSON.stringify(app2.toasts));
  check('★ 用户确认后重新加载了配置', app2.loaded === 1,
    `loadConfig 调用次数=${app2.loaded}`);
  check('★ 重新加载后版本号是新的',
    app2.config.config_rev === 'REV_FROM_RELOAD',
    `实际=${app2.config.config_rev}`);

  /* 2c. 用户选择不重新加载 → 不许偷偷放行旧快照 */
  const app3 = makeApp();
  await runConfirm(app3, staleApi, false);
  check('用户选择不重新加载时不调用 loadConfig', app3.loaded === 0,
    `loadConfig 调用次数=${app3.loaded}`);
  check('用户选择不重新加载时版本号保持原样（下次保存仍会被拒）',
    app3.config.config_rev === 'OLDREV',
    `实际=${app3.config.config_rev}`);

  /* ---------- 3. loadConfig 不能把 config_rev 删掉 ---------- */
  sec('3. loadConfig 必须保留 config_rev');
  const loadIdx = APP_JS.indexOf('async loadConfig()');
  const loadBody = loadIdx >= 0
    ? APP_JS.slice(loadIdx, APP_JS.indexOf('\n    async ', loadIdx + 10)) : '';
  check('loadConfig 里没有删掉 config_rev',
    !/delete\s+\w+\.config_rev/.test(loadBody),
    '删了的话前端就永远带不上版本号，版本闸形同虚设');
  check('loadConfig 把整份 data 赋给 this.config（含 config_rev）',
    /this\.config\s*=\s*data/.test(loadBody));

  /* ---------- 4. 汇总 ---------- */
  console.log('\n' + '='.repeat(74));
  console.log(`  合计: ✅ ${PASS.length}   ❌ ${FAIL.length}`);
  if (FAIL.length) {
    for (const f of FAIL) console.log('  ❌ ' + f);
    process.exit(1);
  }
  console.log('  全部通过');
})();
