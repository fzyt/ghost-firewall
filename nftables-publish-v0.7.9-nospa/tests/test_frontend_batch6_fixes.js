/* 第六批前端判据（手机端反代卡片显示 + 公网 IPv4 首屏自动查）
 *
 * 运行: node tests/test_frontend_batch6_fixes.js
 *
 * 两条线
 * ------
 * 1. 反代规则卡片在手机上「URL 一行几个字」——
 *    375px 窄屏下右边 4 个按钮 shrink-0，把左边内容压到几十像素宽，
 *    URL 又是 break-all（任意字符断行）⇒ 一个字一个字往下掉。
 *    这里对**真实 index.html** 里的卡片做结构契约。
 *
 * 2. 公网 IPv4 一直显示「未知」——
 *    deviceInfo.publicIp 只有 loadPublicIp() 会写，而它只被「查询」按钮
 *    调用 ⇒ 不点按钮就永远是「未知」（.1 实测：面板日志里从未出现
 *    ?public_ip=1）。修法是首屏**并行**查一次，自动刷新绝不出网。
 *    这里在 node 的 vm 里**真跑** app.js 的 loadDeviceInfo/loadPublicIp。
 *
 * ⚠️ 「不该出现」类断言一律用**去注释版**源码 ——
 *    否则注释里写着「以前是 break-all」就会被当成页面里还有 break-all。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.dirname(__dirname);
const INDEX_HTML = fs.readFileSync(path.join(ROOT, 'frontend', 'index.html'), 'utf8');
const APP_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');

const PASS = [], FAIL = [];
const check = (name, ok, detail = '') => {
  (ok ? PASS : FAIL).push(name);
  console.log((ok ? '  [PASS] ' : '  [FAIL] ') + name + (detail ? '  — ' + detail : ''));
};
const sec = (t) => console.log('\n=== ' + t + ' ===');

/* ── 反代规则卡片：抽真实模板、剥注释 ────────────────────────── */

// 卡片是 <template x-for="(rule, index) in rp.rules"> 里的内容。
// 卡片内部没有嵌套 <template>（实测），所以第一个 </template> 就是它的结尾。
function rpCardRaw() {
  const i = INDEX_HTML.indexOf('<template x-for="(rule, index) in rp.rules"');
  if (i < 0) throw new Error('index.html 里找不到反代规则卡片模板');
  const j = INDEX_HTML.indexOf('</template>', i);
  if (j < 0) throw new Error('反代规则卡片模板没有闭合');
  return INDEX_HTML.slice(i, j);
}

function stripComments(s) {
  return s.replace(/<!--[\s\S]*?-->/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

const CARD = stripComments(rpCardRaw());

/** 取第一个 class 里含指定词的元素的 class 串 */
function classOfFirst(re, label) {
  const m = CARD.match(re);
  if (!m) throw new Error('卡片里找不到：' + label);
  return m[1];
}

/** class 串按空白切开后是否含有某个类 */
const hasClass = (cls, name) => cls.split(/\s+/).includes(name);

sec('1. 反代规则卡片：手机端布局契约');

const rowCls = classOfFirst(/<div class="([^"]*\bflex\b[^"]*)"/, '卡片主行');
check('1-1 主行是「手机纵向、桌面横向」（flex-col sm:flex-row）',
  hasClass(rowCls, 'flex-col') && hasClass(rowCls, 'sm:flex-row'),
  rowCls);

check('1-2 手机上左列撑满整行（items-stretch sm:items-start）',
  hasClass(rowCls, 'items-stretch') && hasClass(rowCls, 'sm:items-start'),
  rowCls);

const colCls = classOfFirst(/<div class="(min-w-0[^"]*)"/, '左列');
check('1-3 左列保留 min-w-0（不写 flex-1：flex-1 的 basis 是 0 会让按钮组不换行）',
  hasClass(colCls, 'min-w-0') && !hasClass(colCls, 'flex-1'),
  colCls);

// 访问路径那个 <p>：x-text 里带 gatewayPreviewUrl()
const urlP = CARD.match(/<p class="([^"]*)"[^>]*\n?\s*x-text="gatewayPreviewUrl\(\)/);
check('1-4 访问路径用 break-words（break-all 会一个字一个字断行）',
  !!urlP && hasClass(urlP[1], 'break-words'),
  urlP ? urlP[1] : '(没找到那个 p)');

// 域名入口那个 <p>：同样不能 break-all
const hostP = CARD.match(/<p class="([^"]*)"[^>]*\n?\s*x-show="rule\.host"/);
check('1-5 域名入口同样用 break-words',
  !!hostP && hasClass(hostP[1], 'break-words'),
  hostP ? hostP[1] : '(没找到那个 p)');

// 目标地址那个 <dd>：在「目标地址」这个 dt 之后
const ddMatch = CARD.match(/<dt class="[^"]*">目标地址<\/dt>\s*<dd class="([^"]*)"/);
check('1-6 目标地址用 break-words',
  !!ddMatch && hasClass(ddMatch[1], 'break-words'),
  ddMatch ? ddMatch[1] : '(没找到那个 dd)');

const dlCls = classOfFirst(/<dl class="([^"]*)"/, '属性表');
check('1-7 属性表在手机上是单列（grid-cols-1 sm:grid-cols-2 md:grid-cols-4）',
  hasClass(dlCls, 'grid-cols-1') && hasClass(dlCls, 'sm:grid-cols-2')
  && hasClass(dlCls, 'md:grid-cols-4'),
  dlCls);

// 按钮组：含 editRpRule(index) 的那个 div 的父 div
const btnBlock = CARD.match(/<div class="([^"]*)"[^>]*>\s*<button @click="editRpRule\(index\)"/);
check('1-8 按钮组自身 flex-wrap（极窄屏时按钮内部换行）',
  !!btnBlock && hasClass(btnBlock[1], 'flex-wrap'),
  btnBlock ? btnBlock[1] : '(没找到按钮组)');

check('1-9 卡片里不再有 break-all（去注释后逐字核对）',
  !/\bbreak-all\b/.test(CARD),
  CARD.match(/[^"]*break-all[^"]*/) ? CARD.match(/[^"]*break-all[^"]*/)[0].trim() : '');

check('1-10 卡片里不再有 flex-1（那是上一版踩过的坑）',
  !/\bflex-1\b/.test(CARD));

/* ── 公网 IPv4：真跑 app.js ─────────────────────────────────── */

sec('2. 公网 IPv4：首屏自动查，自动刷新不出网');

/** 建一个能跑 app.js 的沙箱；每次 api 请求都记进 calls */
function makeSandbox(calls, opts) {
  const sandbox = {
    console,
    setTimeout, clearTimeout, setInterval, clearInterval,
    queueMicrotask,
    Event, CustomEvent,
    navigator: { userAgent: 'node-test' },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    fetch: async (url) => {
      calls.push(url);
      let body;
      if (url.indexOf('public_ip=1') >= 0) {
        // 只有「问公网 IP」这一个请求会失败/成功，
        // 普通的系统信息请求不能跟着变（否则测的就不是公网 IP 了）
        body = { success: true, public_ip: opts.publicIpFail ? null : '183.141.193.10' };
      } else {
        body = {
          success: true, hostname: 'OpenWrt', model: 'GL-MT6000',
          os: { pretty_name: 'OpenWrt 25.12.5' }, interfaces: [], public_ip: null,
        };
      }
      return { status: 200, json: async () => body, headers: { get: () => null } };
    },
  };
  sandbox.window = {
    addEventListener: () => {}, removeEventListener: () => {},
    dispatchEvent: () => true, location: { href: '', reload: () => {} },
    matchMedia: () => ({ matches: false, addEventListener: () => {} }),
    innerWidth: 375, devicePixelRatio: 1,
  };
  sandbox.document = {
    addEventListener: () => {}, removeEventListener: () => {},
    querySelectorAll: () => [], querySelector: () => null,
    getElementById: () => null,
    documentElement: { style: {}, classList: { add: () => {}, remove: () => {} } },
    body: { classList: { add: () => {}, remove: () => {} } },
  };
  return sandbox;
}

/** 载入 app.js 并拿到 app() 的状态对象 */
function loadApp(calls, opts) {
  const sandbox = makeSandbox(calls, opts || {});
  vm.createContext(sandbox);
  vm.runInContext(APP_JS, sandbox, { filename: 'frontend/app.js' });
  return sandbox.app();
}

/** 让没被 await 的并行请求把微任务跑完 */
const flush = () => new Promise((r) => setTimeout(r, 0));

(async () => {
  // ① 首屏：应并行问一次公网 IP
  let calls = [];
  let st = loadApp(calls);
  await st.loadDeviceInfo();
  await flush();
  check('2-1 首屏会问一次公网 IP（老代码：永远不问 ⇒ 一直「未知」）',
    calls.indexOf('/api/system/info?public_ip=1') >= 0,
    calls.join(' , '));

  check('2-2 采到的公网 IP 填进了 publicIp（页面那一栏不再是「未知」）',
    st.deviceInfo.publicIp === '183.141.193.10',
    String(st.deviceInfo.publicIp));

  check('2-3 首屏也照常拉系统信息（不能为了公网 IP 把首屏数据丢了）',
    calls.indexOf('/api/system/info') >= 0,
    calls.join(' , '));

  check('2-4 其它字段没被冲掉',
    st.deviceInfo.data && st.deviceInfo.data.hostname === 'OpenWrt',
    JSON.stringify(st.deviceInfo.data && st.deviceInfo.data.hostname));

  // ② 自动刷新：绝不出网
  calls = [];
  st = loadApp(calls);
  await st.loadDeviceInfo(true);
  await flush();
  check('2-5 自动刷新不查公网 IP（否则每 5 秒问一次外网）',
    calls.indexOf('/api/system/info?public_ip=1') < 0,
    calls.join(' , '));

  // ③ 已经有值了：不再重复问
  calls = [];
  st = loadApp(calls);
  st.deviceInfo.publicIp = '1.2.3.4';
  await st.loadDeviceInfo();
  await flush();
  check('2-6 已经有公网 IP 时不重复问外网',
    calls.indexOf('/api/system/info?public_ip=1') < 0,
    calls.join(' , '));

  check('2-7 刷新后原有的公网 IP 没被清空',
    st.deviceInfo.publicIp === '1.2.3.4',
    String(st.deviceInfo.publicIp));

  // ④ 采不到公网 IP：如实显示「未知」，不编数字、不影响其它字段
  calls = [];
  st = loadApp(calls, { publicIpFail: true });
  await st.loadDeviceInfo();
  await flush();
  check('2-8 采不到公网 IP 时如实留空（页面显示「未知」，不编数字）',
    st.deviceInfo.publicIp === '',
    JSON.stringify(st.deviceInfo.publicIp));

  check('2-9 采不到公网 IP 不影响系统信息本身',
    st.deviceInfo.data && st.deviceInfo.data.hostname === 'OpenWrt',
    JSON.stringify(st.deviceInfo.data && st.deviceInfo.data.hostname));

  console.log('\n合计: [PASS] ' + PASS.length + '   [FAIL] ' + FAIL.length);
  if (FAIL.length) {
    FAIL.forEach((f) => console.log('  [FAIL] ' + f));
    process.exit(1);
  }
})().catch((e) => {
  console.log('  [FAIL] 测试自身崩了: ' + (e && e.stack ? e.stack : e));
  process.exit(1);
});
