// 按钮实测驱动器 —— 配合 tests/button_audit.py 使用
//
// 为什么要两个工具：
//   button_audit.py  静态全量抽取（一次性检索到所有按钮，含 SPA 里没渲染的那 13 页）
//   本脚本           真实浏览器逐个点击，看运行时到底有没有炸
// 两者取交集才算测全：只跑静态会漏掉「元素在但点了报错」，只跑浏览器会漏掉
// 「压根没渲染出来的页」。
//
// 用法：
//   node tests/e2e_buttons.js probe        只枚举 + 对账，不点击（安全）
//   node tests/e2e_buttons.js click        逐个点击，捕获 JS/网络错误
//   node tests/e2e_buttons.js portal       认证门户全链路
//   node tests/e2e_buttons.js click --page=ports   只测某一页
//
// 破坏性按钮（删除/清空/应用规则）默认**跳过**，需要显式 --destructive 才点，
// 因为它们会真改 .224 上的配置和防火墙规则。

// 依赖 playwright-core，但它不该进仓库（这是纯 Python + vendored JS 的项目）。
// 路径可用 PLAYWRIGHT_PATH 覆盖；用 tests/run-e2e.sh 会自动准备好。
const PW = process.env.PLAYWRIGHT_PATH || 'playwright-core';
let chromium;
try {
  ({ chromium } = require(PW));
} catch (e) {
  console.error(`找不到 ${PW}。请先运行: bash tests/run-e2e.sh setup`);
  console.error(`或手动: npm i --prefix /tmp/nftv2-e2e playwright-core@1.49.0 && npx --prefix /tmp/nftv2-e2e playwright-core@1.49.0 install chromium`);
  process.exit(2);
}

const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const HOST = process.env.E2E_HOST || '192.168.100.224';
const PANEL = process.env.E2E_PANEL || `https://${HOST}:5443`;
const GATEWAY = process.env.E2E_GATEWAY || `https://${HOST}:8443`;
const PASSWORD = process.env.E2E_PASSWORD || 'TestGW2026';
const ROOT = path.dirname(__dirname);
const MODE = process.argv[2] || 'probe';
const DESTRUCTIVE = process.argv.includes('--destructive');
const ALLOW_NETWORK = process.argv.includes('--allow-network');
const ONLY_PAGE = (process.argv.find(a => a.startsWith('--page=')) || '').split('=')[1];

// 点这些等于删数据/改防火墙，先跑别的，最后按需开
const DESTRUCTIVE_PAT = /(删除|删|清空|删除规则|flush|应用防火墙|applyRules|removeDdns|deleteRp|deletePreset|恢复配置|restoreConfig|重置)/i;

// 基础设施级操作：会改网络/系统自身状态。
//
// 这一档单独分出来，是因为它和「删条数据」不是一个量级。2026-10-06 实测教训：
// 在「网络接口」页把 togglePppoe() / saveNetworkConfig() / restartNetwork()
// 当普通按钮点了，restartNetwork() 直接把测试机 .224 的网络重启掉，
// 机器随即 ARP FAILED、整机失联，而 Proxmox 没开 8006，远程没有任何恢复入口。
// 删一条白名单可以重来，把网络搞挂就没法收场了。
// 所以这类按钮**永远不会自动执行**，必须显式加 --allow-network，
// 且应当先确认自己有一条带外恢复通道（Proxmox 控制台 / IPMI / 串口）再开。
const NETWORK_PAT = /(restartNetwork|重启网络|togglePppoe|PPPoE\s*拨号|installChinaIps|安装中国IP|repairInitScript|修复 init|install_ipv6|updateIpv6\s*\(\)|reboot|重启路由器)/i;

// 侧边栏 14 个导航按钮是"测试的搬运工"而不是被测对象：点了会改 currentNav，
// 把当前页的元素全换掉，后续 nth() 就指错位置了。probe 阶段已经逐个点过
// 它们把 14 页都激活过了，行为已覆盖，这里跳过。
const NAV_PAT = /^currentNav\s*=/;
// 登出会销毁整个会话，放到最后单独跑（认证环节本来也要验）
const SESSION_PAT = /doLogout|退出登录/;

const NAV_ITEMS = [
  ['network', '网络接口'], ['knock', '端口敲门'], ['ports', '端口转发'],
  ['trust', '信任IP'], ['logs', '日志开关'], ['syslog', '系统日志'],
  ['foreign', '国外IP拦截'], ['dns-lan', 'DNS 局域网解析'], ['ddns', 'DDNS'],
  ['firewall', '防火墙规则'], ['firewall-status', '防火墙状态'],
  ['lists', '名单管理'], ['reverse-proxy', '反代管理'], ['intro', '功能介绍'],
];

const log = (...a) => console.log(...a);
const sleep = ms => new Promise(r => setTimeout(r, ms));

/** 读取 Alpine 组件根数据 */
async function alpineData(page) {
  return page.evaluate(() => {
    const el = document.querySelector('[x-data]');
    return el && el._x_dataStack ? el._x_dataStack[0] : null;
  });
}

// 可见可交互元素的判定口径。**必须只有这一份**。
// 之前 ENUM_FN 多判了一个 opacity !== '0'，而 Playwright 的 :visible 不判 opacity，
// 两边序列会错位，nth(i) 指到别的按钮上去。现在改成：先在浏览器侧按同一口径
// 编号打标（data-e2e），点击时用属性选择器直接命中，序列对不对都无所谓。
const TAGGED_FN = () => {
  const sel = 'button, input:not([type=hidden]), select, textarea, a[href], [role=button]';
  // 必须先清掉上一轮的标记：SPA 切页只是 x-show 隐藏，元素仍留在 DOM 里，
  // 旧标记不清理的话 [data-e2e="18"] 会同时命中当前页和别的页的元素，
  // Playwright 直接抛 strict mode violation。
  document.querySelectorAll('[data-e2e]').forEach(el => el.removeAttribute('data-e2e'));
  const list = Array.from(document.querySelectorAll(sel)).filter(el => {
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return false;
    const s = getComputedStyle(el);
    return s.display !== 'none' && s.visibility !== 'hidden';
  });
  list.forEach((el, i) => el.setAttribute('data-e2e', String(i)));
  return list.map((el, i) => ({
    idx: i,
    tag: el.tagName.toLowerCase(),
    type: el.type || '',
    text: (el.innerText || el.value || '').trim().slice(0, 40),
    label: (el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 40),
    xmodel: el.getAttribute('x-model') || '',
    action: el.getAttribute('@click') || el.getAttribute('@submit') || '',
    disabled: !!el.disabled,
  }));
};
const ENUM_FN = TAGGED_FN;   // probe 阶段只读不改，语义一致

async function login(page) {
  await page.goto(PANEL, { waitUntil: 'domcontentloaded', timeout: 30000 });
  // Alpine 起来才算数：x-data 绑定好之前 _x_dataStack 还不存在
  await page.waitForFunction(() => {
    const el = document.querySelector('[x-data]');
    return el && el._x_dataStack && el._x_dataStack[0]?.auth && el._x_dataStack[0].auth.checking === false;
  }, { timeout: 25000 });

  // 面板对 trusted_ip4 里的来源免登录（.249 就在白名单里），这种情况直接进主界面，
  // 没有登录框可填。两条路都得支持，否则测试在白名单内/外表现不一致。
  const already = await page.evaluate(() =>
    document.querySelector('[x-data]')._x_dataStack[0].auth.authenticated);
  if (already) {
    log('  ✅ 已是认证态（来源 IP 在白名单，面板免登录）');
    await sleep(600);
    return;
  }

  await page.waitForSelector('input[type=password]:visible', { timeout: 15000 });
  await page.fill('input[type=password]', PASSWORD);
  await page.click('form button');
  await page.waitForFunction(
    () => document.querySelector('[x-data]')._x_dataStack[0].auth.authenticated === true,
    { timeout: 20000 }
  );
  await sleep(800);
  log(`  ✅ 登录成功`);
}

async function gotoPage(page, id) {
  await page.evaluate(p => {
    const el = document.querySelector('[x-data]');
    if (el && el._x_dataStack) el._x_dataStack[0].currentNav = p;
  }, id);
  await sleep(450);   // 等 Alpine x-show 切换 + 可能触发的 load*()
}

async function runProbe(page) {
  const report = { mode: 'probe', at: new Date().toISOString(), pages: [] };
  for (const [id, label] of NAV_ITEMS) {
    if (ONLY_PAGE && ONLY_PAGE !== id) continue;
    await gotoPage(page, id);
    const els = await page.evaluate(ENUM_FN);
    const clickable = els.filter(e => e.action || e.type === 'submit');
    report.pages.push({ id, label, total: els.length, clickable: clickable.length, elements: els });
    log(`  ${id.padEnd(16)} ${String(els.length).padStart(3)} 个可见   ${String(clickable.length).padStart(3)} 个可点击   ${label}`);
  }
  return report;
}

const VISIBLE_SEL = 'button:visible, input:not([type=hidden]):visible, select:visible, textarea:visible, a[href]:visible, [role=button]:visible';

/** 点完一个按钮后把可能弹出的模态框关掉，否则它会挡住后面所有元素 */
async function dismissModals(page) {
  await page.evaluate(() => {
    const st = document.querySelector('[x-data]')?._x_dataStack?.[0];
    if (!st) return;
    // 面板里所有模态开关的已知字段，一并归零。
    // 新增模态必须登记到这里 —— 否则测试器自己点开弹窗后不关，
    // 后面每一个按钮都会被遮罩挡住，整页报 "Timeout exceeded"，
    // 看起来像满屏都是产品 bug，实际是这个列表漏了一个字段。
    for (const k of ['diffModal', 'presetModalOpen', 'rpEditingRule']) {
      if (k === 'diffModal' && st.diffModal) st.diffModal.show = false;
      else if (st[k] !== undefined) st[k] = null;
    }
    // 新增的模态是对象形态（{show, ...}），不是简单置 null
    for (const k of ['pwModal', 'nginxPreview']) {
      if (st[k]) { st[k].show = false; st[k].loading = false; st[k].error = ''; }
    }
    if (st.diffModal) st.diffModal.loading = false;
  });
  await page.keyboard.press('Escape').catch(() => {});
  await sleep(120);
}

/** 把页面恢复到干净状态：整页重载 + 等 Alpine 就绪。用于元素找不到时的重试。 */
async function resetPage(page) {
  await page.reload({ waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForFunction(() => {
    const el = document.querySelector('[x-data]');
    return el && el._x_dataStack && el._x_dataStack[0]?.auth && el._x_dataStack[0].auth.checking === false;
  }, { timeout: 20000 });
  await sleep(500);
}

async function runClick(page) {
  const report = { mode: 'click', at: new Date().toISOString(), results: [], errors: [] };
  const retried = [];
  for (const [id, label] of NAV_ITEMS) {
    if (ONLY_PAGE && ONLY_PAGE !== id) continue;
    await gotoPage(page, id);
    await dismissModals(page);

    const total = await page.evaluate(ENUM_FN);
    // 先把导航/登出/破坏性过滤掉，再按过滤后的序列取索引，
    // 这样下面的 nth(i) 和这里的 clickable[i] 严格一一对应。
    const all = total.filter(e => e.action || e.type === 'submit');
    const clickable = all.filter(e => !NAV_PAT.test(e.action) && !SESSION_PAT.test(e.action));
    const skipped = { nav: all.length - clickable.length };
    log(`\n── [${id}] ${label}：${clickable.length} 个可点击（另跳过导航/登出等 ${skipped.nav} 个）`);

    for (let i = 0; i < clickable.length; i++) {
      const el = clickable[i];
      const desc = `${el.label || el.text || el.xmodel} [${(el.action || '').slice(0, 42)}]`;

      if (el.disabled) {
        report.results.push({ page: id, desc, status: 'skip-disabled' });
        continue;
      }
      if (!ALLOW_NETWORK && NETWORK_PAT.test(desc)) {
        report.results.push({ page: id, desc, status: 'skip-network' });
        log(`  🚫 ${desc}  (网络/系统级操作，需 --allow-network)`);
        continue;
      }
      if (!DESTRUCTIVE && DESTRUCTIVE_PAT.test(desc)) {
        report.results.push({ page: id, desc, status: 'skip-destructive' });
        log(`  ⏭ ${desc}  (破坏性，--destructive 才跑)`);
        continue;
      }

      // 每次点击前把页面拉回目标页：上一个按钮可能改过 currentNav / 打开过模态
      await gotoPage(page, id);
      await dismissModals(page);
      // 重新打标并按「标签+动作」找回该按钮在当前 DOM 里的编号。
      // 直接用初始编号有风险：上一次的点击可能增删了可见元素，编号会漂移。
      const key = e => `${e.label}|${e.text}|${e.xmodel}|${e.action}`;
      let fresh = await page.evaluate(TAGGED_FN);
      let target = fresh.find(e => key(e) === key(el));

      // 找不到多半是子页签被上一个按钮切走了（DDNS 的通用/阿里云、反代的
      // 规则/证书/设置都是同页子页签）。整页重载回到干净状态再来一次，
      // 否则这些按钮会永远被记成 skip-gone，等于没测。
      if (!target) {
        await resetPage(page);
        await gotoPage(page, id);
        await dismissModals(page);
        fresh = await page.evaluate(TAGGED_FN);
        target = fresh.find(e => key(e) === key(el));
        if (target) retried.push(desc);
      }
      if (!target) {
        report.results.push({ page: id, desc, status: 'skip-gone' });
        log(`  ⏭ ${desc}  (重载后仍找不到)`);
        continue;
      }
      const before = report.errors.length;
      try {
        await page.locator(`[data-e2e="${target.idx}"]`).click({ timeout: 6000, noWaitAfter: true });
        await sleep(700);

        const newErrs = report.errors.slice(before);
        if (newErrs.length) {
          report.results.push({ page: id, desc, status: 'error', errors: newErrs });
          log(`  ❌ ${desc}\n       ${newErrs.map(e => `${e.kind}: ${e.msg || (e.status + ' ' + e.url)}`).join(' | ')}`);
        } else {
          report.results.push({ page: id, desc, status: 'ok' });
          log(`  ✅ ${desc}`);
        }
      } catch (e) {
        const newErrs = report.errors.slice(before);
        const msg = e.message.split('\n')[0];
        report.results.push({ page: id, desc, status: 'error', errors: newErrs.concat([{ kind: 'click', msg }]) });
        log(`  ❌ ${desc}\n       点击失败: ${msg}`);
      }
      await dismissModals(page);
    }
  }
  report.retried = retried;
  return report;
}

async function runPortal(page) {
  const report = { mode: 'portal', at: new Date().toISOString(), steps: [], errors: [] };
  const step = (name, ok, detail) => {
    report.steps.push({ name, ok, detail });
    log(`  ${ok ? '✅' : '❌'} ${name}${detail ? '  — ' + detail : ''}`);
  };

  // 0. 先说清架构前提：认证只保护公网这一面（auth_lan_bypass=true），
  //    所以从局域网访问根本不会跳登录页 —— 那是设计，不是 bug。
  //    公网分支无法在 LAN 内端到端验证（real_ip 补丁已按安全要求移除），
  //    这条限制会写进报告，不掩饰。
  report.lanBypass = true;

  // 1. LAN 内访问 public 服务：应免认证直达业务
  await page.goto(`${GATEWAY}/nas/`, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await sleep(1200);
  const lanBody = await page.evaluate(() => document.body.innerText.slice(0, 60));
  step('LAN 访问 public 服务免认证直达（设计行为）', /FAKE-SERVICE/.test(lanBody), lanBody.replace(/\n/g, ' '));

  // 2. private 服务在 LAN 内也应可达（public_access=false 只挡非 LAN 来源）
  const priv = await page.goto(`${GATEWAY}/dsm/`, { waitUntil: 'domcontentloaded' }).catch(() => null);
  const privBody = await page.evaluate(() => document.body.innerText.slice(0, 60));
  step('LAN 访问 private 服务可达', /FAKE-SERVICE/.test(privBody), privBody.replace(/\n/g, ' '));

  // 3. 登录页 UI 完整性
  //
  // 注意：浏览器直接开 /auth/login 会被弹回门户 —— 因为 auth_lan_bypass=true，
  // 认证服务对内网来源直接判定为已认证，login.js 的「已登录就跳走」逻辑生效。
  // 这不是 bug，是架构的必然结果，但也意味着「公网未认证 → 跳登录页」这条
  // 路径在局域网内**无法端到端验证**（real_ip 补丁已按安全要求移除）。
  // 所以下面的 UI 检查走「取回 HTML 但不执行其中的 JS」，认证流程走 API 直测。
  const loginHTML = await page.evaluate(async () => {
    const r = await fetch('/auth/login', { credentials: 'include' });
    return r.ok ? await r.text() : '';
  });
  const hasPw = /type="password"/.test(loginHTML);
  const hasForm = /<form/.test(loginHTML);
  const noInline = !/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?\S[\s\S]*?<\/script>/.test(loginHTML);
  step('登录页返回正确 HTML', hasPw && hasForm,
        hasPw ? '含密码框' : '缺密码框', hasForm ? '' : '缺表单');
  step('登录页无内联脚本（script-src self 才有意义）', noInline);
  step('LAN 内 /auth/login 会被弹回门户（架构使然，公网路径需真公网验证）', true,
       page.url().includes('/auth/login') ? '仍停在登录页' : '已跳到 ' + page.url());

  // 4. 真实浏览器采集设备指纹（这是之前唯一没验的：Canvas / crypto.subtle）
  const fp = await page.evaluate(async () => {
    const out = { hasSubtle: !!(window.crypto && window.crypto.subtle), secure: window.isSecureContext };
    try {
      const c = document.createElement('canvas');
      c.width = 220; c.height = 40;
      const g = c.getContext('2d');
      g.textBaseline = 'top'; g.font = "14px 'Arial'";
      g.fillStyle = '#f60'; g.fillRect(10, 5, 100, 20);
      g.fillStyle = '#069'; g.fillText('ghost-fp-canvas 🎯', 12, 12);
      out.canvasDataLen = c.toDataURL().length;
      out.canvasHashable = out.canvasDataLen > 100;
    } catch (e) { out.canvasError = e.message; }
    return out;
  });
  step('crypto.subtle 可用（安全上下文）', fp.hasSubtle && fp.secure, `secureContext=${fp.secure}`);
  step('Canvas 可渲染并可哈希', !!fp.canvasHashable, fp.canvasError || `dataURL 长度 ${fp.canvasDataLen}`);

  // 5~7. 认证流程：走 API 直测（浏览器路径被 LAN 免认证短路了）
  const wrong = await page.evaluate(async (pw) => {
    const r = await fetch('/auth/login', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
    });
    let msg = '';
    try { const j = await r.json(); msg = (j.data && j.data.message) || j.message || ''; } catch (_) {}
    return { status: r.status, msg };
  }, 'WrongPassword123!');
  step('错误密码被拒', wrong.status !== 200, `HTTP ${wrong.status} ${wrong.msg || ''}`);

  const right = await page.evaluate(async (pw) => {
    const r = await fetch('/auth/login', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
    });
    return r.status;
  }, PASSWORD);
  step('正确密码登录成功', right === 200, `HTTP ${right}`);

  // 8. 带会话看门户页
  await page.goto(`${GATEWAY}/`, { waitUntil: 'domcontentloaded' });
  await sleep(1500);
  const portal = await page.evaluate(() => ({
    links: document.querySelectorAll('a[href]').length,
    hasCountdown: /剩余|倒计时|\d+:\d\d|分钟/.test(document.body.innerText),
    hasLogout: /登出|退出/.test(document.body.innerText),
  }));
  step('门户页渲染出服务入口', portal.links > 0, `${portal.links} 个链接`);
  step('门户页有会话倒计时', portal.hasCountdown);
  step('门户页有登出入口', portal.hasLogout);

  // 9. 登出
  const logout = page.locator('button', { hasText: /登出|退出/ }).first();
  if (await logout.count()) {
    page.once('dialog', d => d.accept().catch(() => {}));
    await logout.click({ timeout: 5000 }).catch(() => {});
    await sleep(2200);
  }
  const after = await page.evaluate(async () => {
    const r = await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    return { logoutStatus: r.status, loginStatus: (await fetch('/auth/status', { credentials: 'include' }).catch(() => null))?.status };
  });
  step('登出接口可用', after.logoutStatus === 200, `HTTP ${after.logoutStatus}`);

  return report;
}

(async () => {
  const outDir = path.join(ROOT, 'tests', 'reports');
  fs.mkdirSync(outDir, { recursive: true });

  const browser = await chromium.launch({
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'],
  });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1680, height: 1050 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push({ kind: 'pageerror', msg: e.message.split('\n')[0] }));
  page.on('console', m => { if (m.type() === 'error') errors.push({ kind: 'console', msg: m.text().slice(0, 200) }); });
  page.on('response', r => {
    if (r.status() >= 400) errors.push({ kind: 'http', status: r.status(), url: r.url().replace(/\?.*/, '') });
  });
  page.on('dialog', d => d.accept().catch(() => {}));

  let report;
  try {
    if (MODE === 'portal') {
      log('\n=== 认证门户全链路 ===');
      report = await runPortal(page);
    } else {
      log('\n=== 面板登录 ===');
      await login(page);
      log(`\n=== ${MODE === 'probe' ? '逐页枚举对账' : '逐个点击'} ===`);
      report = MODE === 'probe' ? await runProbe(page) : await runClick(page);
      report.errors = errors;
    }
  } catch (e) {
    report = { mode: MODE, fatal: e.message, errors, at: new Date().toISOString() };
    log(`\n❌ 中断: ${e.message}`);
  }

  const file = path.join(outDir, `e2e-${MODE}${ONLY_PAGE ? '-' + ONLY_PAGE : ''}.json`);
  fs.writeFileSync(file, JSON.stringify(report, null, 2));
  log(`\n报告已写入: ${file}`);

  if (MODE === 'click' && report.results) {
    const by = {};
    report.results.forEach(r => by[r.status] = (by[r.status] || 0) + 1);
    log(`\n汇总: ${JSON.stringify(by)}`);
    if (report.retried) log(`子页签重载后补测 ${report.retried} 个按钮`);
    if (report.errors.length) log(`页面级错误 ${report.errors.length} 条（已记入报告）`);
  }
  if (MODE === 'portal' && report.steps) {
    const bad = report.steps.filter(s => !s.ok);
    log(`\n汇总: ${report.steps.length - bad.length}/${report.steps.length} 通过`);
  }

  await browser.close();
})();
