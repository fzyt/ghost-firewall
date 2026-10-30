/* 打开面板的默认页必须是「防火墙状态」，而且数据没到齐之前不许渲染红点
 *
 * 运行: node tests/test_frontend_default_tab.js
 *
 * 需求
 * ----
 * 2026-10-30 用户要求：进面板第一眼看到「防火墙状态」，不是「网络接口」。
 *
 * 为什么这件事不只是改一行默认值
 * ------------------------------
 * 防火墙状态页显示的字段（fw4Active / nftablesLoaded / initExists / initUpToDate …）
 * 在 Alpine state 里的初值**全是 false**，而 false 在模板里被渲染成
 * **红点 +「未加载」/「不存在」**。
 *
 * 也就是说，只要把默认页换成防火墙状态、而不管数据什么时候到，
 * 打开面板的那一瞬间用户看到的就是：
 *     nftables 规则：未加载      ← 红点
 *     init 脚本：不存在          ← 红点
 * 而真相是「**还没查**」，不是「没加载」。
 *
 * 这个假状态比白屏更坏：它会让用户以为防火墙挂了、面板坏了，
 * 然后去设备上一通排查 —— 而实际上防火墙好得很。
 *
 * 所以这个需求必须连着「数据没到齐就整页不渲染」一起做，
 * 而且查询失败时也必须显示错误，而不是静默退回红点。
 *
 * 为什么这个测试要**真求值**而不是匹配文本
 * -----------------------------------------
 * 文本匹配只能证明「代码里写了 firewallStatusLoaded」。
 * 证明不了「数据没到时这一页真的不显示」。
 *
 * 所以这里把 index.html 里那一页的 x-show 表达式**抽出来、用假的 Alpine
 * 上下文真跑一遍** —— 表达式里的 && 和 || 的短路行为、变量的真假值，
 * 全部按浏览器里的实际语义算。
 * 同样，loadFirewallStatus 的方法体也抽出来**真执行**：
 * 分别喂一个成功响应和一个抛异常的 api.get，看状态字段到底怎么变。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const APP_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');
const INDEX_HTML = fs.readFileSync(path.join(ROOT, 'frontend', 'index.html'), 'utf8');

const PASS = [], FAIL = [];
const check = (name, ok, detail = '') => {
  (ok ? PASS : FAIL).push(name);
  console.log((ok ? '  ✅ ' : '  ❌ ') + name + (detail ? '  — ' + detail : ''));
};
const sec = (t) => console.log('\n=== ' + t + ' ===');

/* 从源码里抽出方法体。
 *
 * 朴素的花括号计数会被字符串里的花括号骗到，所以这里跳过
 * ' " ` 三种字符串和 // 注释。
 *
 * prefix 用来把匹配锚得更死（比如 init 可能被 initEnabled 之类误伤），
 * 给定时直接用 prefix 当正则。
 */
function extractMethod(src, name, prefix) {
  const pat = prefix || ('(?:async\\s+)?' + name + '\\s*\\([^)]*\\)\\s*\\{');
  const re = new RegExp(pat);
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

/* 从 app.js 的 state 里读出一个布尔字段的**真实初值**。
 *
 * 为什么必须从源码里读，而不是在测试里写死
 * ------------------------------------------
 * 第一版这里写死了 `firewallStatusLoaded: false` 再拿去求值，
 * 结果「门控初值被改成 true」这条变异**漏网了** ——
 * 因为测试根本没看 app.js 里的初值，自己编了一个 false，
 * 变异把源码里的 true 改掉，测试浑然不觉。
 *
 * 初值本身就是这次改动的一部分契约（门控初值必须是 false，
 * 否则等于没有门控），所以必须由源码驱动。
 */
function parseStateBool(src, key) {
  const re = new RegExp('^\\s*' + key + ':\\s*(true|false)\\s*,', 'm');
  const m = re.exec(src);
  return m ? (m[1] === 'true') : null;
}

/* 去掉注释。
 *
 * 为什么必须去：init() 里那段说明文字提到了别的函数名，
 * 直接 indexOf 会把**注释里的那个**当成真正的调用点，
 * 顺序判断会得出完全相反的结论 —— 而且改一次注释就翻车。
 *
 * '//' 的处理要避开 URL：'https://x' 里的 '//' 前面是冒号，不是注释。
 */
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

/* 抽出某个 x-show 属性的表达式值。
 *
 * marker 用来定位是哪一页 —— 比如 'firewall-status'。
 * 注意 x-show 的值里用的是单引号，属性本身用双引号包着，
 * 所以 [^"]* 能完整取到值。
 */
function extractXShow(html, marker) {
  const re = new RegExp('x-show="([^"]*' + marker + '[^"]*)"');
  const m = re.exec(html);
  return m ? m[1] : null;
}

/* 把 x-show 表达式按浏览器的语义真求值。
 *
 * 用 with + 普通对象，让表达式里的 currentNav / loading / firewallStatusLoaded
 * 直接按属性名读到。短路、类型转换全部是 JS 原生行为，
 * 不是我们用 if 模拟出来的近似。
 */
function evalXShow(expr, ctx) {
  try {
    const fn = new Function('ctx', 'with (ctx) { return (' + expr + '); }');
    return { value: !!fn(ctx) };
  } catch (e) {
    return { error: e.message };
  }
}

(async () => {
  console.log('='.repeat(66));
  console.log('默认页 = 防火墙状态（且数据没到齐不许渲染红点）');
  console.log('='.repeat(66));

  /* ───────────────────────────────────────────────────────────── */
  sec('1. 默认页是「防火墙状态」');

  const navMatch = /currentNav:\s*'([^']*)'/.exec(APP_JS);
  check('能从 app.js 里读出 currentNav 的默认值',
    navMatch !== null, navMatch ? navMatch[1] : '没找到');
  const DEFAULT_NAV = navMatch ? navMatch[1] : '';
  check('默认页是 firewall-status', DEFAULT_NAV === 'firewall-status', '实际=' + DEFAULT_NAV);

  const navIds = [...APP_JS.matchAll(/\{\s*id:\s*'([^']+)',\s*label:\s*'([^']+)'/g)]
    .map(m => ({ id: m[1], label: m[2] }));
  check('navItems 里有 firewall-status', navIds.some(i => i.id === 'firewall-status'));
  check('firewall-status 的标签文案是「防火墙状态」',
    (navIds.find(i => i.id === 'firewall-status') || {}).label === '防火墙状态');
  // 网络接口必须还在 —— 它是配置页，PPPoE、网关 IP 还得能改。
  // 「不默认显示」≠「从导航里删掉」。
  check('navItems 里 network（网络接口）仍然保留',
    navIds.some(i => i.id === 'network'),
    '只是不再默认打开，不是删掉入口');

  // 导航顺序：状态页提到第一（2026-10-30）
  // —— 默认页 = 导航第一项 = 最该先看的那页，三者要一致。
  check('防火墙状态排在导航第一位',
    navIds[0] && navIds[0].id === 'firewall-status',
    '第一项=' + (navIds[0] ? navIds[0].id : '无'));
  check('网络接口紧随其后（配置项之间的次序没被打乱）',
    navIds[1] && navIds[1].id === 'network',
    '第二项=' + (navIds[1] ? navIds[1].id : '无'));
  check('导航项没有重复',
    new Set(navIds.map(i => i.id)).size === navIds.length,
    '共 ' + navIds.length + ' 项');
  check('防火墙状态在导航里只出现一次',
    navIds.filter(i => i.id === 'firewall-status').length === 1);

  /* ───────────────────────────────────────────────────────────── */
  sec('2. 数据没到齐之前，默认页不渲染（真求值 x-show）');

  // 门控初值必须由**源码里的真实值**驱动 —— 写死 false 会让
  // 「初值被改成 true」这条变异漏网（第一版就踩了这个坑）。
  const FS_INIT = parseStateBool(APP_JS, 'firewallStatusLoaded');
  check('能从 app.js 里读出 firewallStatusLoaded 的初值',
    FS_INIT !== null, '实际=' + FS_INIT);
  check('firewallStatusLoaded 初值是 false（门控一开始就生效）',
    FS_INIT === false, '实际=' + FS_INIT);

  const fwShow = extractXShow(INDEX_HTML, 'firewall-status');
  check('能从 index.html 里抽出防火墙状态页的 x-show', fwShow !== null,
    fwShow === null ? '没找到' : fwShow);

  if (fwShow !== null) {
    // 数据没到（源码里的初值）→ 整页隐藏
    const before = evalXShow(fwShow, {
      currentNav: DEFAULT_NAV, loading: false, firewallStatusLoaded: FS_INIT,
    });
    check('数据未到齐时默认页不显示（不闪「未加载」红点）',
      before.value === false, before.error || ('求值结果=' + before.value));

    // 数据到了 → 显示
    const after = evalXShow(fwShow, {
      currentNav: DEFAULT_NAV, loading: false, firewallStatusLoaded: true,
    });
    check('数据到齐后默认页显示',
      after.value === true, after.error || ('求值结果=' + after.value));

    // 切到别的页 → 这一页必须收起来
    const other = evalXShow(fwShow, {
      currentNav: 'network', loading: false, firewallStatusLoaded: true,
    });
    check('切到别的页时防火墙状态页收起来',
      other.value === false, other.error || ('求值结果=' + other.value));
  }

  const netShow = extractXShow(INDEX_HTML, "currentNav === 'network'");
  check('能从 index.html 里抽出网络接口页的 x-show', netShow !== null, netShow || '');
  if (netShow !== null) {
    const net = evalXShow(netShow, { currentNav: DEFAULT_NAV, loading: false });
    check('默认不再打开网络接口页',
      net.value === false, net.error || ('求值结果=' + net.value));
  }

  /* ───────────────────────────────────────────────────────────── */
  sec('3. loadFirewallStatus 真跑一遍：成功与失败两条路');

  const lfsBody = extractMethod(APP_JS, 'loadFirewallStatus',
    'async\\s+loadFirewallStatus\\s*\\(\\s*\\)\\s*\\{');
  check('能从 app.js 里抽出 loadFirewallStatus 方法体', lfsBody !== null);

  if (lfsBody !== null) {
    const mk = new Function('api', 'return async function() {' + lfsBody + '};');
    const fn = mk;

    // —— 成功路径
    const okApi = {
      get: async () => ({
        fw4_active: true, nftables_loaded: true,
        init_exists: true, init_enabled: true,
        init_has_fw4_stop: false, init_up_to_date: true,
        recovery: { state: 'ok' },
      }),
    };
    const stOk = {
      firewallStatusLoaded: false, firewallStatusError: '旧错误',
      healthCalled: 0,
      loadRulesHealth: async function () { this.healthCalled++; },
    };
    await fn(okApi).call(stOk);
    check('成功时状态字段被真正赋值（fw4Active=true）', stOk.fw4Active === true,
      '实际=' + stOk.fw4Active);
    check('成功时 initUpToDate 被真正赋值', stOk.initUpToDate === true,
      '实际=' + stOk.initUpToDate);
    check('成功时清掉上一次残留的错误', stOk.firewallStatusError === '',
      '实际=' + JSON.stringify(stOk.firewallStatusError));
    check('成功后放开这一页（firewallStatusLoaded=true）',
      stOk.firewallStatusLoaded === true);
    check('成功后仍然拉取规则集健康', stOk.healthCalled === 1,
      '调用次数=' + stOk.healthCalled);

    // —— 失败路径
    const badApi = { get: async () => { throw new Error('设备无响应'); } };
    const stBad = {
      firewallStatusLoaded: false, firewallStatusError: '',
      healthCalled: 0,
      loadRulesHealth: async function () { this.healthCalled++; },
    };
    await fn(badApi).call(stBad);
    check('查询失败时记下原因（不再静默吞掉）',
      stBad.firewallStatusError === '设备无响应',
      '实际=' + JSON.stringify(stBad.firewallStatusError));
    check('查询失败时也放开这一页（用户能看到错误，而不是永远空白）',
      stBad.firewallStatusLoaded === true);
    check('查询失败时规则集健康仍然照拉',
      stBad.healthCalled === 1, '调用次数=' + stBad.healthCalled);
  }

  /* ───────────────────────────────────────────────────────────── */
  sec('4. 默认页的数据排在最前面取');

  const initBody = extractMethod(APP_JS, 'init', 'async\\s+init\\s*\\(\\s*\\)\\s*\\{');
  const allBody = extractMethod(APP_JS, 'loadAllData',
    'async\\s+loadAllData\\s*\\(\\s*\\)\\s*\\{');
  check('能抽出 init() 方法体', initBody !== null);
  check('能抽出 loadAllData() 方法体', allBody !== null);

  if (initBody !== null) {
    const clean = stripComments(initBody);
    const iFs = clean.indexOf('loadFirewallStatus');
    const iCfg = clean.indexOf('loadConfig');
    check('init() 里 loadFirewallStatus 排在 loadConfig 之前',
      iFs !== -1 && iCfg !== -1 && iFs < iCfg,
      'loadFirewallStatus@' + iFs + ' loadConfig@' + iCfg);
  }
  if (allBody !== null) {
    const clean = stripComments(allBody);
    const aFs = clean.indexOf('loadFirewallStatus');
    const aCfg = clean.indexOf('loadConfig');
    check('loadAllData() 里 loadFirewallStatus 排在 loadConfig 之前',
      aFs !== -1 && aCfg !== -1 && aFs < aCfg,
      'loadFirewallStatus@' + aFs + ' loadConfig@' + aCfg);
  }

  /* ───────────────────────────────────────────────────────────── */
  sec('5. 查询失败时显示错误，而不是一堆红点');

  check('index.html 里有 firewallStatusError 的错误提示块',
    /x-show="firewallStatusError"/.test(INDEX_HTML));
  check('错误提示块里真的带上了错误文案',
    /firewallStatusError\s*\|\|\s*'未知错误'/.test(INDEX_HTML));

  const dotsGuard = /<div class="bg-gray-50 border rounded-lg p-5 space-y-5"\s+x-show="!firewallStatusError">/.test(INDEX_HTML);
  check('fw4 / nftables / init 那几个状态点被 !firewallStatusError 包住',
    dotsGuard);

  console.log('\n' + '='.repeat(66));
  console.log(` 合计: ✅ ${PASS.length}   ❌ ${FAIL.length}`);
  if (FAIL.length) {
    console.log(' 有失败:');
    FAIL.forEach(f => console.log('   - ' + f));
  } else {
    console.log(' 全部通过');
  }
  console.log('='.repeat(66));
  process.exit(FAIL.length ? 1 : 0);
})().catch(e => {
  console.error('测试自身抛异常:', e);
  process.exit(1);
});
