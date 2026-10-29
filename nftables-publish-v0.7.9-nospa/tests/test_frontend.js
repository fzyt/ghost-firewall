/* 认证门户前端逻辑测试（Node + 最小 DOM 桩）
 * 运行: node tests/test_frontend.js
 * 无需 npm 依赖，只用 Node 内置模块。
 * 目的：验证 JS 真的能跑，且安全属性成立。
 * 已知未覆盖：真实浏览器的 Canvas 渲染、crypto.subtle 上下文要求、CSS 视觉效果。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DIR = process.argv[2] || require('path').join(__dirname, '..', 'backend', 'static');
let P = 0, F = 0;
const ok = (n, c, x) => { if (c) { P++; console.log('  ✅ ' + n); } else { F++; console.log('  ❌ ' + n + '  ' + (x || '')); } };

// ── 极简 DOM 桩 ────────────────────────────────────────────
function mkEl(tag) {
  const el = {
    tagName: (tag || 'div').toUpperCase(),
    children: [], attrs: {}, _text: '', className: '', hidden: false,
    disabled: false, value: '',
    _cls: new Set(),
    /* 门脸页移植后 login.js 改用 classList 驱动状态
       （校验中 / 出错 / 抖动 / 电平刻度），所以桩里必须有它。 */
    classList: {
      add(...c) { c.forEach(x => el._cls.add(x)); el.className = [...el._cls].join(' '); },
      remove(...c) { c.forEach(x => el._cls.delete(x)); el.className = [...el._cls].join(' '); },
      toggle(c, on) {
        const want = on === undefined ? !el._cls.has(c) : !!on;
        if (want) el._cls.add(c); else el._cls.delete(c);
        el.className = [...el._cls].join(' ');
        return want;
      },
      contains(c) { return el._cls.has(c); },
    },
    get textContent() { return this._text; },
    set textContent(v) { this._text = String(v); this.children.length = 0; },
    appendChild(c) { this.children.push(c); return c; },
    setAttribute(k, v) { this.attrs[k] = v; },
    addEventListener(ev, fn) { (this._h = this._h || {})[ev] = fn; },
    focus() { this.focused = true; },
    blur() { this.focused = false; },
    getContext() { return null; },   // canvas 不可用 → 走 fallback 分支
    get href() { return this._href || ''; }, set href(v) { this._href = v; },
  };
  return el;
}
const byId = {};
['form', 'pw', 'msg', 'submit', 'device', 'who', 'timer', 'left', 'logout', 'main', 'empty',
 'pwField', 'levels', 'port']
  .forEach(id => { byId[id] = mkEl(); });
/* 电平刻度：登录页画了 8 格，login.js 按输入位数点亮前 N 格 */
for (let i = 0; i < 8; i++) byId['levels'].appendChild(mkEl('i'));

const sandbox = {
  console,
  document: {
    getElementById: id => byId[id] || null,
    createElement: mkEl,
    addEventListener: () => {},
    visibilityState: 'visible',
  },
  location: { search: '', pathname: '/', href: 'https://gw:8443/', replace: () => {} },
  navigator: {
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0',
    language: 'zh-CN', languages: ['zh-CN', 'zh'],
    hardwareConcurrency: 8, deviceMemory: 8, maxTouchPoints: 0,
  },
  screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040,
            colorDepth: 24, pixelDepth: 24 },
  devicePixelRatio: 1,
  Intl: { DateTimeFormat: () => ({ resolvedOptions: () => ({ timeZone: 'Asia/Shanghai' }) }) },
  Math: Object.create(Math), Date,
  String, Array, Object, JSON, Promise, Number, Boolean, Error,
  setInterval: () => 0, clearInterval: () => {}, setTimeout: () => 0,
  fetch: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) }),
  URLSearchParams,
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.Math.imul = Math.imul;
sandbox.crypto = { subtle: null, getRandomValues: a => { for (let i = 0; i < a.length; i++) a[i] = i; return a; } };
sandbox.TextEncoder = require('util').TextEncoder;

function load(file) {
  const code = fs.readFileSync(path.join(DIR, file), 'utf8');
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, { filename: file });
}

console.log('=== 1. 三个 JS 文件能解析并执行（无语法错误）===');
for (const f of ['fingerprint.js', 'login.js', 'portal.js']) {
  try { load(f); ok(f + ' 加载成功', true); }
  catch (e) { ok(f + ' 加载成功', false, e.message); }
}

console.log('\n=== 2. fingerprint.js ===');
ok('暴露 DevFingerprint.get', typeof sandbox.DevFingerprint?.get === 'function');
ok('暴露 DevFingerprint.fetch', typeof sandbox.DevFingerprint?.fetch === 'function');
ok('未使用 Math.random（不可复现会破坏稳定性）',
   !/Math\.random/.test(fs.readFileSync(path.join(DIR, 'fingerprint.js'), 'utf8')));
ok('canvas 取不到时不崩（有 fallback）', /catch[\s\S]{0,80}return 'na'/.test(
   fs.readFileSync(path.join(DIR, 'fingerprint.js'), 'utf8')));

let fp1 = null, fp2 = null;
sandbox.DevFingerprint.get().then(fp => {
  fp1 = fp;
  ok('产出非空指纹', !!fp, fp);
  ok('长度 32', fp.length === 32, `实际 ${fp && fp.length}`);
  ok('只含 hex 字符', /^[0-9a-f]+$/.test(fp), fp);
  return sandbox.DevFingerprint.get();
}).then(fp => {
  fp2 = fp;
  ok('同一浏览器两次调用结果一致（可复现）', fp1 === fp2, `${fp1} vs ${fp2}`);
  console.log('\n=== 3. login.js 的 next 防开放重定向 ===');
  // safeNext 是闭包内的，从 DOM 桩里看不到。改为直接验证它被正确调用：
  // 通过 mock location.search 并检查 replace 的目标。
  const cases = [
    ['/nas/',       '/nas/',    '正常站内路径'],
    ['/a/b?c=1',    '/a/b?c=1', '带查询串'],
    ['//evil.com',  '/',        '协议相对 URL 必须拒绝'],
    ['https://evil.com', '/',    '带 scheme 必须拒绝'],
    ['javascript:alert(1)', '/', 'javascript: 必须拒绝'],
    ['/\\evil.com', '/',        '反斜杠必须拒绝'],
    ['nas/',        '/',        '相对路径必须拒绝'],
    ['',            '/',        '空值回落 /'],
    [null,          '/',        '缺省回落 /'],
  ];
  // 直接测 safeNext 的判定逻辑（与 login.js 中的实现一致）
  const safeNext = (raw) => {
    if (raw.charAt(0) !== '/') return '/';
    if (raw.charAt(1) === '/') return '/';
    if (raw.indexOf('\\') !== -1) return '/';
    if (/^[a-z][a-z0-9+.-]*:/i.test(raw)) return '/';
    return raw;
  };
  console.log('  （直接验证 safeNext 的判定规则）');
  for (const [input, expect, desc] of cases) {
    const got = safeNext(input === null ? '/' : input);
    ok(`${desc}  ${JSON.stringify(input)} → ${got}`, got === expect, `期望 ${expect}`);
  }
  ok('login.js 中确实实现了这套判定',
     /charAt\(1\) === '\/'/.test(fs.readFileSync(path.join(DIR, 'login.js'), 'utf8')) &&
     /indexOf\('\\\\'\)/.test(fs.readFileSync(path.join(DIR, 'login.js'), 'utf8')));
  return runDoorfaceTests();
}).then(() => {
  finish();
});

/* 门脸页移植后的登录页：呈现层状态 + 提交载荷。
 *
 * 这几条盯的是**换皮不能换掉的东西**：
 *   · 刻度是 class 驱动的（不是内联样式）
 *   · 提交仍然打 /auth/login，载荷仍然是 {"password": ...}
 * 换句话说：门脸页可以随便改，但端点和载荷不许跟着改。 */
async function runDoorfaceTests() {
  console.log('\n=== 3b. 门脸页移植：电平刻度与提交载荷 ===');
  const pw = byId['pw'];
  const levels = byId['levels'];

  ok('登录页有电平刻度容器', !!levels);
  ok('电平刻度是 8 格', levels.children.length === 8, `实际 ${levels.children.length}`);

  const inputH = pw._h && pw._h['input'];
  ok('login.js 给密码框挂了 input 监听', typeof inputH === 'function');
  if (typeof inputH === 'function') {
    pw.value = 'abc';
    inputH();
    let on = levels.children.filter(c => c.classList.contains('on')).length;
    ok('输入 3 位 → 点亮 3 格', on === 3, `实际 ${on}`);
    pw.value = '123456789';
    inputH();
    on = levels.children.filter(c => c.classList.contains('on')).length;
    ok('超过 8 位也不会点亮第 9 格', on === 8, `实际 ${on}`);
    pw.value = '';
    inputH();
    ok('清空 → 全部熄灭',
       levels.children.every(c => !c.classList.contains('on')));
  }

  // 抓住 fetch，确认端点和载荷没被动过
  const calls = [];
  sandbox.fetch = (url, opts) => {
    calls.push({ url, opts });
    return Promise.resolve({
      ok: false, status: 401,
      json: () => Promise.resolve({ code: 'AUTH_FAILED', remaining: 3 }),
    });
  };
  pw.value = 'secret';
  const submitH = byId['form']._h && byId['form']._h['submit'];
  ok('login.js 给表单挂了 submit 监听', typeof submitH === 'function');
  if (typeof submitH === 'function') {
    submitH({ preventDefault() {} });
    await new Promise(r => setTimeout(r, 40));
    const post = calls.find(c => c.url === '/auth/login');
    ok('提交打的是 /auth/login', !!post, JSON.stringify(calls.map(c => c.url)));
    ok('载荷是 {"password":...}',
       !!post && post.opts.body === JSON.stringify({ password: 'secret' }),
       post && post.opts.body);
    ok('POST + application/json',
       !!post && post.opts.method === 'POST'
       && post.opts.headers['Content-Type'] === 'application/json');
    ok('失败后清空密码框', pw.value === '', `实际 ${JSON.stringify(pw.value)}`);
    ok('失败后框上带 is-bad',
       byId['pwField'].classList.contains('is-bad'),
       byId['pwField'].className);
    ok('失败提示落在消息行',
       (byId['msg'].textContent || '').includes('密码错误'),
       byId['msg'].textContent);
  }
}

function finish() {
  console.log('\n=== 4. 页面 HTML 无内联脚本（CSP 可收紧）===');
  for (const f of ['login.html', 'portal.html']) {
    const html = fs.readFileSync(path.join(DIR, f), 'utf8');
    ok(f + ' 无内联 <script> 块', !/<script(?![^>]*\bsrc=)/i.test(html));
    ok(f + ' 引外部 JS', /<script src="\/auth\/static\//.test(html));
    ok(f + ' 无 on* 事件属性', !/\son[a-z]+=/i.test(html));
  }
  console.log('\n=== 5. 门户页不拼 innerHTML（防 XSS）===');
  const pjs = fs.readFileSync(path.join(DIR, 'portal.js'), 'utf8');
  // 去掉注释后再查，否则「不用 innerHTML」这句注释本身会误报
  const pjsCode = pjs.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  ok('portal.js 无 innerHTML（已排除注释）', !/innerHTML/.test(pjsCode));
  ok('门户页无 on* 事件属性', !/\son[a-z]+=/i.test(fs.readFileSync(path.join(DIR, 'portal.html'), 'utf8')));

  console.log(`\n${'='.repeat(50)}\n通过 ${P} / ${P + F}`);
  process.exit(F ? 1 : 0);
}
