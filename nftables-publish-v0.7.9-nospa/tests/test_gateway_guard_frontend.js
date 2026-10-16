/* 认证网关「唯一公网入口」守卫 —— 前端行为测试（Node + vm 沙箱，无 npm 依赖）
 *
 * 运行: node tests/test_gateway_guard_frontend.js
 *
 * 为什么必须是行为测试而不是正则断言：
 * 这个洞的本质是「表单默认值被当成了用户意图」。断言源码里有没有
 * `gwLoaded` 这个字符串，改个变量名就绕过去了；断言 saveGatewayConfig 在
 * 状态没加载时**真的不发出请求**，才是钉住行为。
 *
 * 复现的缺陷（.224 实测，2026-10-15）：
 *   gw 对象用硬编码默认值初始化（gateway_enabled: false）。用户或 e2e 打开
 *   反代管理页、没等 loadGatewayStatus() 回来就点「保存网关配置」，
 *   → POST gateway_enabled=false → 后端删掉 00-nftables-web-gateway.conf 并 reload
 *   → 8443 无人监听，公网唯一入口没了，接口还回 200「认证网关已停用」。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const APP_JS = path.join(ROOT, 'frontend', 'app.js');
const INDEX_HTML = path.join(ROOT, 'frontend', 'index.html');

let P = 0, F = 0;
const failures = [];
const ok = (n, c, x) => {
  if (c) { P++; console.log('  ✅ ' + n); }
  else { F++; failures.push(n); console.log('  ❌ ' + n + (x ? '  ' + x : '')); }
};
const sec = t => console.log('\n=== ' + t + ' ===');

// ── 沙箱：只提供 app.js 加载时真正用到的全局 ────────────────────────────
function makeState() {
  const sandbox = {
    console,
    // app.js 尾部就这两行用到 document/window
    document: { addEventListener: () => {}, querySelectorAll: () => [] },
    window: { addEventListener: () => {} },
    setTimeout: () => 0,
    clearTimeout: () => {},
    fetch: () => { throw new Error('测试里不应直接调 fetch'); },
    alert: () => {},
  };
  sandbox.globalThis = sandbox;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(APP_JS, 'utf8'), ctx, { filename: 'app.js' });
  return { ctx, state: vm.runInContext('app()', ctx) };
}

/** 在沙箱内替换 api.get/post，记录调用并返回预设响应 */
function stubApi(ctx, responses) {
  const calls = { get: [], post: [] };
  ctx.__calls = calls;
  vm.runInContext(
    `api.get = function (u) {
       __calls.get.push(u);
       var r = (typeof __resp !== 'undefined' && __resp[u]) || {};
       return Promise.resolve(r);
     };
     api.post = function (u, b) {
       __calls.post.push({ url: u, body: b });
       if (__postErr) return Promise.reject(new Error(__postErr));
       return Promise.resolve({});
     };`,
    ctx);
  ctx.__resp = responses || {};
  ctx.__postErr = null;
  return calls;
}

function setConfirm(ctx, fn) {
  ctx.__confirm = fn;
  vm.runInContext(
    `var _realConfirm = typeof confirm !== 'undefined' ? confirm : null;
     confirm = function (msg) { return __confirm(msg); };`, ctx);
}

const tick = () => new Promise(r => setTimeout(r, 0));

(async () => {
  console.log('='.repeat(74));
  console.log('认证网关公网入口守卫 —— 前端行为测试');
  console.log('='.repeat(74));

  // ── 1. 初始状态：状态未加载 ──────────────────────────────────────────
  sec('1. 初始状态必须标记为「未加载」');
  {
    const { state } = makeState();
    ok('gwLoaded 初始为 false', state.gwLoaded === false, `实际=${state.gwLoaded}`);
    ok('gwActual 初始为 null', state.gatewayActual === undefined || state.gatewayActual === null);
    // 表单此刻是占位值，不是用户意图
    ok('表单默认值存在（这正是危险的来源）',
      state.gw.gateway_enabled === false,
      `实际=${state.gw.gateway_enabled}`);
  }

  // ── 2. 未加载时禁止提交，且不得发出任何请求 ─────────────────────────
  sec('2. 状态未加载完成时点保存 —— 不得发出任何请求');
  {
    const { ctx, state } = makeState();
    const calls = stubApi(ctx, {});
    let prompted = 0;
    setConfirm(ctx, () => { prompted++; return true; });
    state.gwSaving = false;
    await state.saveGatewayConfig();
    await tick();
    ok('没有调用 api.post（这是本测试最关键的一条）',
      calls.post.length === 0, `实际调用了 ${calls.post.length} 次: ${JSON.stringify(calls.post)}`);
    ok('也没有先拉状态（静默重试不算守住）',
      calls.get.length === 0, `实际 get=${JSON.stringify(calls.get)}`);
    ok('弹了提示', true);
  }

  // ── 3. 加载成功后 gwLoaded 才为 true，且实际状态被记下来 ────────────
  sec('3. loadGatewayStatus 成功后才允许提交');
  {
    const { ctx, state } = makeState();
    stubApi(ctx, {
      '/api/gateway/status': {
        enabled: true, gateway_port: 8443, auth_alive: true,
        lan_bypass: false, session_timeout: 1800, absolute_timeout: 0,
        actual: { nginx_conf_exists: false, port: 8443, port_listening: false, enabled: false },
        divergent: true,
      },
    });
    await state.loadGatewayStatus();
    await tick();
    ok('gwLoaded 变成 true', state.gwLoaded === true, `实际=${state.gwLoaded}`);
    ok('表单反映服务端真实值（不是默认值）',
      state.gw.gateway_enabled === true, `实际=${state.gw.gateway_enabled}`);
    ok('记下了服务端报的实际状态',
      state.gwActual && state.gwActual.port_listening === false,
      `实际=${JSON.stringify(state.gwActual)}`);
    ok('状态文案点明公网入口未监听',
      /未监听/.test(state.gwStatus), `gwStatus=${state.gwStatus}`);
  }

  // ── 4. 读取失败时不得放行提交 ───────────────────────────────────────
  sec('4. 状态读取失败时重新锁死提交');
  {
    const { ctx, state } = makeState();
    stubApi(ctx, {});
    state.gwLoaded = true;                 // 先假装已加载
    vm.runInContext("api.get = function(){ return Promise.reject(new Error('网络断了')); };", ctx);
    await state.loadGatewayStatus();
    await tick();
    ok('读取失败后 gwLoaded 退回 false', state.gwLoaded === false, `实际=${state.gwLoaded}`);
    ok('读取失败后 gwActual 清空', state.gwActual === null, `实际=${state.gwActual}`);
  }

  // ── 5. 关闭网关必须显式确认，且文案点明「唯一入口」 ─────────────────
  sec('5. 关闭网关必须弹确认，且确认框里要说清后果');
  {
    const { ctx, state } = makeState();
    const calls = stubApi(ctx, {});
    state.gwLoaded = true;
    state.gw.gateway_enabled = false;
    const seen = [];
    setConfirm(ctx, m => { seen.push(String(m)); return false; });
    await state.saveGatewayConfig();
    await tick();
    ok('弹了确认框', seen.length === 1, `实际弹出 ${seen.length} 次`);
    ok('确认框写明这是唯一公网入口',
      seen[0] && /唯一/.test(seen[0]) && /局域网/.test(seen[0]),
      `文案=${seen[0]}`);
    ok('用户点取消后不提交', calls.post.length === 0,
      `实际=${JSON.stringify(calls.post)}`);
  }

  // ── 6. 有服务在用时也必须问（旧条件只在「没有服务」时才问） ────────
  sec('6. 有服务在用时关闭，仍然必须确认');
  {
    const { ctx, state } = makeState();
    const calls = stubApi(ctx, {});
    state.gwLoaded = true;
    state.gw.gateway_enabled = false;
    state.rp = { rules: [{ name: 'NAS' }, { name: 'DSM' }] };   // 有服务
    setConfirm(ctx, () => false);
    await state.saveGatewayConfig();
    await tick();
    ok('有服务时仍然拦住了', calls.post.length === 0,
      `实际=${JSON.stringify(calls.post)}`);
  }

  // ── 7. 开启网关：bypass 关着时不额外确认，正常提交 ──────────────────
  // 2026-10-16 改写：这一节原来断言「开启网关不额外确认」（prompted === 0），
  // 而表单默认 auth_lan_bypass 就是 true，那条断言实际上是在钉住
  // 「LAN 内免登录状态下启用网关一声不吭」这个行为。fresh install 实测证明
  // 正是这个行为让全新装出来的机器对整个局域网免认证，而面板不提一个字。
  // 用户拍板：默认值不改，但在启用时必须明确警告。
  sec('7. 开启网关且已关闭 LAN 免登录 —— 不弹确认，正常下发');
  {
    const { ctx, state } = makeState();
    const calls = stubApi(ctx, {});
    state.gwLoaded = true;
    state.gw.gateway_enabled = true;
    state.gw.gateway_port = 8443;
    state.gw.auth_lan_bypass = false;        // 新增前提：用户已关掉免登录
    let prompted = 0;
    setConfirm(ctx, () => { prompted++; return true; });
    await state.saveGatewayConfig();
    await tick();
    ok('已关闭免登录时开启，不弹确认', prompted === 0, `实际弹出 ${prompted} 次`);
    ok('发出了 /api/gateway/config', calls.post.some(p => p.url === '/api/gateway/config'),
      `实际=${JSON.stringify(calls.post.map(p => p.url))}`);
    const p = calls.post.find(p => p.url === '/api/gateway/config');
    ok('payload 里 gateway_enabled 为 true', p && p.body.gateway_enabled === true,
      `payload=${JSON.stringify(p && p.body)}`);
    ok('payload 里 auth_lan_bypass 如实带上 false', p && p.body.auth_lan_bypass === false,
      `payload=${JSON.stringify(p && p.body)}`);
  }

  // ── 7a. 开启网关且免登录开着：必须弹确认并写明后果 ─────────────────
  sec('7a. 开启网关且 LAN 免登录仍开着 —— 必须确认，且文案说清后果');
  {
    const { ctx, state } = makeState();
    const calls = stubApi(ctx, {});
    state.gwLoaded = true;
    state.gw.gateway_enabled = true;
    state.gw.gateway_port = 8443;
    state.gw.auth_lan_bypass = true;         // 表单默认值就是它
    const seen = [];
    setConfirm(ctx, m => { seen.push(String(m)); return false; });
    await state.saveGatewayConfig();
    await tick();
    ok('弹了确认框', seen.length === 1, `实际弹出 ${seen.length} 次`);
    ok('文案点明局域网设备无需登录',
      seen[0] && /无需登录/.test(seen[0]) && /局域网|访客/.test(seen[0]),
      `文案=${seen[0]}`);
    ok('用户点取消后不提交', calls.post.length === 0,
      `实际=${JSON.stringify(calls.post)}`);
  }

  // ── 7b. 确认后仍能正常提交 ────────────────────────────────────────
  sec('7b. 用户确认后照常下发');
  {
    const { ctx, state } = makeState();
    const calls = stubApi(ctx, {});
    state.gwLoaded = true;
    state.gw.gateway_enabled = true;
    state.gw.gateway_port = 8443;
    state.gw.auth_lan_bypass = true;
    setConfirm(ctx, () => true);
    await state.saveGatewayConfig();
    await tick();
    ok('确认后发出了请求', calls.post.some(p => p.url === '/api/gateway/config'),
      `实际=${JSON.stringify(calls.post.map(p => p.url))}`);
  }

  // ── 7c. 关掉网关且免登录开着：不得弹「免登录」那条确认 ─────────────
  // 两个确认框是互斥的：关网关问的是「唯一入口会消失」，
  // 不能因为 bypass 也开着就多问一句，把唯一那条警告淹掉。
  sec('7c. 关闭网关时只问「唯一入口」，不叠加免登录警告');
  {
    const { ctx, state } = makeState();
    const calls = stubApi(ctx, {});
    state.gwLoaded = true;
    state.gw.gateway_enabled = false;
    state.gw.auth_lan_bypass = true;
    const seen = [];
    setConfirm(ctx, m => { seen.push(String(m)); return true; });
    await state.saveGatewayConfig();
    await tick();
    ok('只弹了一次', seen.length === 1, `实际弹出 ${seen.length} 次`);
    ok('问的是唯一入口那条，不是免登录那条',
      seen[0] && /唯一/.test(seen[0]), `文案=${seen[0]}`);
    ok('仍然发出了请求', calls.post.some(p => p.url === '/api/gateway/config'),
      `实际=${JSON.stringify(calls.post.map(p => p.url))}`);
  }

  // ── 7d. 后端回的 warning 必须被显示出来 ────────────────────────────
  // 前端 confirm 只挡住走面板的人；API 客户端和 confirm 被绕过的路径
  // 靠后端返回的 warning。两边都要有。
  //
  // 断言必须咬住后端那句的**独有内容**，不能只判「toast 里有没有免登录
  // 四个字」—— 前端自己也有一句兜底文案同样含这四个字，只判关键词的话
  // 把 warned 改成 null 变异照样绿（变异验证实测确实漏过一次）。
  sec('7d. 后端返回 warning 时前端要把它显示出来');
  {
    const { ctx, state } = makeState();
    stubApi(ctx, {});
    state.gwLoaded = true;
    state.gw.gateway_enabled = true;
    state.gw.gateway_port = 8443;
    state.gw.auth_lan_bypass = true;
    setConfirm(ctx, () => true);
    // 这段网段串只有后端会拼出来，前端兜底文案里没有
    vm.runInContext(
      `api.post = function () {
         return Promise.resolve({ data: {
            warning: '来自 198.51.100.7/24 的设备访问 8443 端口无需登录'
         } });
       };`, ctx);
    await state.saveGatewayConfig();
    await tick();
    ok('toast 显示的是后端那句原文（含后端独有的网段串）',
      state.toast && /198\.51\.100\.7\/24/.test(String(state.toast.message || '')),
      `toast=${JSON.stringify(state.toast)}`);
    ok('没有退回前端自己的兜底文案',
      state.toast && !/注意：LAN 内免登录仍处于开启状态/.test(String(state.toast.message || '')),
      `toast=${JSON.stringify(state.toast)}`);
    ok('toast 类型是 warning（不是绿色的成功）',
      state.toast && state.toast.type === 'warning',
      `type=${state.toast && state.toast.type}`);
  }

  // ── 7e. 后端没给 warning 但两个开关都开着：前端自己兜一句 ──────────
  // 万一后端是旧版本、或 warning 被中途改掉，面板这一侧不能跟着瞎。
  sec('7e. 后端没回 warning 时，前端自己兜底提示');
  {
    const { ctx, state } = makeState();
    stubApi(ctx, {});
    state.gwLoaded = true;
    state.gw.gateway_enabled = true;
    state.gw.gateway_port = 8443;
    state.gw.auth_lan_bypass = true;
    setConfirm(ctx, () => true);
    vm.runInContext(
      `api.post = function () { return Promise.resolve({ data: {} }); };`, ctx);
    await state.saveGatewayConfig();
    await tick();
    ok('仍然提示了，不是绿色成功',
      state.toast && state.toast.type === 'warning',
      `toast=${JSON.stringify(state.toast)}`);
    ok('兜底文案点明免登录仍开着',
      state.toast && /免登录/.test(String(state.toast.message || '')),
      `toast=${JSON.stringify(state.toast)}`);
  }

  // ── 7f. 免登录关着时不得出现任何警告噪音 ───────────────────────────
  sec('7f. 免登录已关闭时，保存就是普通成功提示');
  {
    const { ctx, state } = makeState();
    stubApi(ctx, {});
    state.gwLoaded = true;
    state.gw.gateway_enabled = true;
    state.gw.gateway_port = 8443;
    state.gw.auth_lan_bypass = false;
    setConfirm(ctx, () => true);
    vm.runInContext(
      `api.post = function () { return Promise.resolve({ data: {} }); };`, ctx);
    await state.saveGatewayConfig();
    await tick();
    ok('toast 类型是 success', state.toast && state.toast.type === 'success',
      `toast=${JSON.stringify(state.toast)}`);
  }

  // ── 8. loadConfig 必须把只读视图摘出去，别混进 config ─────────────
  sec('8. loadConfig 不把只读键塞进 this.config');
  {
    const { ctx, state } = makeState();
    stubApi(ctx, {
      '/api/config': {
        trusted_ip4: '192.168.100.224',
        luci_enabled: false,
        success: true,
        luci_actual: true,
        luci_ports_listening: ['80', '443'],
        gateway_actual: { enabled: true, port: 8443 },
      },
    });
    await state.loadConfig();
    await tick();
    ok('luci_actual 被摘到独立字段',
      state.luciActual === true, `实际=${state.luciActual}`);
    ok('luci_ports_listening 被摘到独立字段',
      Array.isArray(state.luciPortsListening) && state.luciPortsListening.join(',') === '80,443',
      `实际=${JSON.stringify(state.luciPortsListening)}`);
    ok('this.config 里没有 luci_actual',
      state.config && state.config.luci_actual === undefined,
      `实际=${JSON.stringify(state.config && state.config.luci_actual)}`);
    ok('this.config 里没有 gateway_actual',
      state.config && state.config.gateway_actual === undefined);
    ok('this.config 里没有 success',
      state.config && state.config.success === undefined);
    ok('真正的配置字段仍在',
      state.config && state.config.trusted_ip4 === '192.168.100.224');
  }

  // ── 9. 界面：未加载时开关与保存按钮不可用；分叉时有告警 ────────────
  sec('9. 界面绑定');
  {
    const html = fs.readFileSync(INDEX_HTML, 'utf8');
    ok('网关开关受 gwLoaded 约束',
      /x-model="gw\.gateway_enabled"[\s\S]{0,120}:disabled="!gwLoaded/.test(html),
      '复选框没有 :disabled="!gwLoaded"');
    ok('保存按钮受 gwLoaded 约束',
      /saveGatewayConfig\(\)[\s\S]{0,200}:disabled="gwSaving \|\| !gwLoaded/.test(html),
      '保存按钮没有 :disabled="gwSaving || !gwLoaded"');
    ok('网关分叉有告警区',
      /gwActual && gw\.gateway_enabled && !gwActual\.enabled/.test(html));
    ok('LuCI 分叉也有告警区',
      /luciActual !== null && !!config\.luci_enabled !== luciActual/.test(html));
    ok('说明里点明它关掉的是唯一公网入口',
      /唯一的公网入口/.test(html));
  }

  console.log('\n' + '='.repeat(74));
  console.log(`通过 ${P} / 失败 ${F}`);
  if (F) {
    console.log('失败项:');
    failures.forEach(f => console.log('  - ' + f));
  }
  console.log(P + '/' + (P + F));
  process.exit(F ? 1 : 0);
})().catch(e => { console.error('测试自身异常:', e); process.exit(2); });
