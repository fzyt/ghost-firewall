/* 「系统信息」页 v0.19.18 新增功能的判据
 *   —— 设备概览 / 局域网设备 / DHCP 静态绑定的增删
 *
 * 运行: node tests/test_frontend_system_info_dhcp.js
 *
 * 测什么有效
 * ----------
 * 这一批功能里有几处**光看源码看不出来**的地方：
 *
 *  1. **提示条的位置**：重载 dnsmasq 失败时要说「已保存，但没生效」。
 *     这句话如果写在表单容器**里面** ⇒ 保存成功后表单一关，提示也跟着没了
 *     ⇒ 用户看到的是「什么都没发生」。源码里两处写法长得几乎一样，
 *     只有**DOM 嵌套关系**不同 ⇒ 必须查嵌套，不能查文本。
 *
 *  2. **删除只用段名**：显示名可能是中文，而 uci 段名不接受非 ASCII
 *     ⇒ 前端要是拿显示名兜底，后端会拒，用户看到一句难懂的报错。
 *
 *  3. **刷新不能冲掉表单**：5 秒一次的自动刷新如果整份替换 deviceInfo，
 *     用户填了一半的表单就没了 ⇒ 判据要**真跑** loadDeviceInfo 看字段还在不在。
 *
 * ⇒ 所以这个文件分三组：
 *   A. 结构（index.html 的 DOM 嵌套）
 *   B. 行为（把 app.js 的方法体**抽出来真跑**，喂假的 api/this）
 *   C. 静态契约（app.js 源码）
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const APP_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');
const INDEX_HTML = fs.readFileSync(path.join(ROOT, 'frontend', 'index.html'), 'utf8');

const PASS = [], FAIL = [];
const check = (name, ok, detail = '') => {
  (ok ? PASS : FAIL).push(name);
  console.log((ok ? '  [PASS] ' : '  [FAIL] ') + name + (detail ? '  — ' + detail : ''));
};
const sec = (t) => console.log('\n=== ' + t + ' ===');

/* ── 从 app.js 抽出方法体并变成可执行的函数 ────────────────── */

function extractMethodBody(src, name) {
  const re = new RegExp('(?:async\\s+)?' + name + '\\s*\\([^)]*\\)\\s*\\{');
  const m = re.exec(src);
  if (!m) return null;
  let i = m.index + m[0].length;
  const start = i;
  let depth = 1;
  while (i < src.length && depth > 0) {
    const c = src[i];
    if (c === "'" || c === '"' || c === '`') {
      const quote = c;
      i++;
      while (i < src.length && src[i] !== quote) {
        if (src[i] === '\\') i++;
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

/**
 * 抽出方法并变成可执行的 async 函数。
 *
 * ⚠️ api / unwrap / window 是 app.js 的**模块级**变量，不是全局的
 *   ⇒ 必须作为参数注入，否则方法体里的 api.get 会报 not defined
 *   （那是测试装置的缺陷，不是页面的缺陷）。
 * ⚠️ 方法体里用 this ⇒ 调用时用 .call(fakeSelf, ...) 绑定。
 */
function makeMethod(name, apiObj, unwrapFn, windowObj) {
  const re = new RegExp('(?:async\\s+)?' + name + '\\s*\\(([^)]*)\\)');
  const m = re.exec(APP_JS);
  if (!m) return null;
  const body = extractMethodBody(APP_JS, name);
  if (body === null) return null;
  try {
    return new Function('api', 'unwrap', 'window',
      'return async function(' + m[1] + ') {' + body + '}')(
        apiObj, unwrapFn, windowObj);
  } catch (e) {
    console.log('    （' + name + ' 抽取失败: ' + e.message + '）');
    return null;
  }
}

/* ── 假的 api / unwrap / window ────────────────────────────── */

const unwrap = (r) => {
  if (r && typeof r === 'object' && r.data !== undefined && r.data !== null
      && typeof r.data === 'object') {
    return r.data;
  }
  return r || {};
};

function makeApi(handlers = {}) {
  const calls = [];
  return {
    calls,
    async get(url) {
      calls.push({ method: 'get', url });
      return handlers.get ? handlers.get(url) : { success: true, data: {} };
    },
    async post(url, body) {
      calls.push({ method: 'post', url, body });
      return handlers.post ? handlers.post(url, body) : { success: true, data: {} };
    },
    async delete(url) {
      calls.push({ method: 'delete', url });
      return handlers.delete ? handlers.delete(url) : { success: true, data: {} };
    },
  };
}

function makeSelf(apiObj, opts = {}) {
  return {
    deviceInfo: Object.assign({
      loading: false, loaded: false, error: '', data: null,
      publicIp: '', loadingPublicIp: false,
      dhcpFormOpen: false, dhcpForm: { name: '', ip: '', mac: '' },
      dhcpFormError: '', dhcpSaving: false,
    }, opts.deviceInfo || {}),
    // 刷新用假实现：只把 data 换掉（真实现会整个替换 deviceInfo）
    async loadDeviceInfo() {
      this.deviceInfo = { ...this.deviceInfo, data: { refreshed: true } };
    },
    scheduleDeviceInfoRefresh() {},
    ...(opts.methods || {}),
  };
}

const fakeWindow = { confirm: () => true };

/* ══════════════════════════════════════════════════════════════
 * A. 结构（DOM 嵌套关系）
 * ══════════════════════════════════════════════════════════════ */
sec('A. 页面结构');

/** 某个位置之前，所有 div 的嵌套深度（开 -1，闭 +1 抵消）。 */
function divDepthBefore(html, pos) {
  const head = html.slice(0, pos);
  let depth = 0;
  const re = /<\/?div\b[^>]*>/g;
  let m;
  while ((m = re.exec(head)) !== null) {
    if (m[0].startsWith('</')) depth--;
    else depth++;
  }
  return depth;
}

const formPos = INDEX_HTML.indexOf('x-show="deviceInfo.dhcpFormOpen"');
const errPos = INDEX_HTML.indexOf('x-text="deviceInfo.dhcpFormError"');
check('页面里能找到表单容器与提示条', formPos > 0 && errPos > 0,
  'formPos=' + formPos + ' errPos=' + errPos);

if (formPos > 0 && errPos > 0) {
  // 表单容器 div 的起始深度 = D，它**内部**的深度 ≥ D+1
  const dForm = divDepthBefore(INDEX_HTML, formPos);
  const dErr = divDepthBefore(INDEX_HTML, errPos);
  // 提示条在表单**外面** ⇒ 它的深度 ≤ 表单 div 的起始深度
  check('提示条在表单容器**外面**（表单关闭后提示也还在）',
    dErr <= dForm,
    '表单起始深度 ' + dForm + '，提示条所在深度 ' + dErr +
    (dErr > dForm ? '（提示条被关在表单里了！）' : ''));
}

check('删除按钮只在有段名时显示（匿名段不给删）',
  /x-show="h\.section"/.test(INDEX_HTML));
check('删除按钮旁边说明了匿名段怎么办',
  INDEX_HTML.includes('匿名段，手动改'));
check('设备名输入框绑的是 dhcpForm.name',
  /x-model="deviceInfo\.dhcpForm\.name"/.test(INDEX_HTML));
check('IP 输入框绑的是 dhcpForm.ip',
  /x-model="deviceInfo\.dhcpForm\.ip"/.test(INDEX_HTML));
check('MAC 输入框绑的是 dhcpForm.mac',
  /x-model="deviceInfo\.dhcpForm\.mac"/.test(INDEX_HTML));
check('设备名输入框的提示说明了可以用中文',
  INDEX_HTML.includes('可用中文'));
check('表单说明了会改 /etc/config/dhcp',
  INDEX_HTML.includes('/etc/config/dhcp'));
check('表单说明了会备份、失败会回滚',
  INDEX_HTML.includes('备份') && INDEX_HTML.includes('回滚'));
check('页面有「设备概览」板块', INDEX_HTML.includes('>设备概览<'));
check('页面有「局域网设备」板块', INDEX_HTML.includes('>局域网设备<'));

/* ══════════════════════════════════════════════════════════════
 * B. 行为（真跑方法体）
 * ══════════════════════════════════════════════════════════════ */
sec('B. 行为：删除绑定');

(async () => {
  // ── B1. 有段名 ⇒ 删正确的 URL ────────────────────────────
  {
    const api = makeApi({
      delete: () => ({ success: true, data: { section: 'host_aabbccddee01', reload: { ok: true, message: 'dnsmasq 已重载' } } }),
    });
    const self = makeSelf(api);
    const fn = makeMethod('deleteDhcpHost', api, unwrap, fakeWindow);
    check('deleteDhcpHost 方法能抽出来并执行', !!fn);
    if (fn) {
      await fn.call(self, { section: 'host_aabbccddee01', name: '我的NAS' });
      const dels = api.calls.filter(c => c.method === 'delete');
      check('删绑定 ⇒ 发了 DELETE 请求', dels.length === 1,
        '实际 ' + JSON.stringify(api.calls));
      check('删除的 URL 用的是段名',
        dels.length === 1 && dels[0].url === '/api/system/dhcp-hosts/host_aabbccddee01',
        dels.length ? dels[0].url : '没发请求');
    }
  }

  // ── B2. 匿名段（没有段名）⇒ 不发请求，给出说明 ──────────
  {
    const api = makeApi();
    const self = makeSelf(api);
    const fn = makeMethod('deleteDhcpHost', api, unwrap, fakeWindow);
    if (fn) {
      await fn.call(self, { section: '', name: '没有标识的绑定' });
      check('匿名段 ⇒ 不发请求（没有可传的标识）',
        api.calls.length === 0, '实际 ' + JSON.stringify(api.calls));
      check('匿名段 ⇒ 给出「删不了」的说明',
        /匿名段/.test(self.deviceInfo.dhcpFormError),
        self.deviceInfo.dhcpFormError);
    }
  }

  // ── B3. 只有中文显示名、没有段名 ⇒ 不能拿显示名兜底 ──────
  {
    const api = makeApi();
    const self = makeSelf(api);
    const fn = makeMethod('deleteDhcpHost', api, unwrap, fakeWindow);
    if (fn) {
      await fn.call(self, { name: '我的NAS' });
      check('没有段名时不拿显示名兜底（uci 不接受非 ASCII 段名）',
        api.calls.length === 0, '实际 ' + JSON.stringify(api.calls));
    }
  }

  // ── B4. 重载失败 ⇒ 必须如实提示 ──────────────────────────
  {
    const api = makeApi({
      delete: () => ({ success: true, data: { section: 'x', reload: { ok: false, message: '重载 dnsmasq 返回非零（绑定已写入，可能未生效）' } } }),
    });
    const self = makeSelf(api);
    const fn = makeMethod('deleteDhcpHost', api, unwrap, fakeWindow);
    if (fn) {
      await fn.call(self, { section: 'host_x', name: '设备' });
      check('重载失败 ⇒ 有提示',
        self.deviceInfo.dhcpFormError.length > 0,
        'dhcpFormError=' + JSON.stringify(self.deviceInfo.dhcpFormError));
      check('重载失败 ⇒ 提示里带后端的原话',
        self.deviceInfo.dhcpFormError.includes('绑定已写入'),
        self.deviceInfo.dhcpFormError);
    }
  }

  sec('C. 行为：新增绑定');

  // ── C1. 正常新增 ⇒ POST 的字段对 ─────────────────────────
  {
    const api = makeApi({
      post: () => ({ success: true, data: { section: 'host_aabbccddee01', name: '我的NAS', reload: { ok: true, message: 'dnsmasq 已重载' } } }),
    });
    const self = makeSelf(api, {
      deviceInfo: { dhcpFormOpen: true, dhcpForm: { name: '  我的NAS  ', ip: ' 192.168.100.11 ', mac: 'AA:BB:CC:DD:EE:01' } },
    });
    const fn = makeMethod('saveDhcpHost', api, unwrap, fakeWindow);
    check('saveDhcpHost 方法能抽出来并执行', !!fn);
    if (fn) {
      await fn.call(self);
      const posts = api.calls.filter(c => c.method === 'post');
      check('新增 ⇒ 发了 POST', posts.length === 1, JSON.stringify(api.calls));
      check('POST 到正确的地址',
        posts.length === 1 && posts[0].url === '/api/system/dhcp-hosts',
        posts.length ? posts[0].url : '没发请求');
      check('POST 的 body 是 name/ip/mac 且去掉了首尾空白',
        posts.length === 1
        && posts[0].body.name === '我的NAS'
        && posts[0].body.ip === '192.168.100.11'
        && posts[0].body.mac === 'AA:BB:CC:DD:EE:01',
        posts.length ? JSON.stringify(posts[0].body) : '没发请求');
      check('新增成功 ⇒ 表单关闭', self.deviceInfo.dhcpFormOpen === false);
      check('新增成功 ⇒ 没有错误提示',
        self.deviceInfo.dhcpFormError === '',
        JSON.stringify(self.deviceInfo.dhcpFormError));
    }
  }

  // ── C2. 重载失败 ⇒ 提示「已保存，但…」，且**不能**假装全成功 ──
  {
    const api = makeApi({
      post: () => ({ success: true, data: { section: 'host_x', reload: { ok: false, message: '重载 dnsmasq 失败（绑定已写入）' } } }),
    });
    const self = makeSelf(api, {
      deviceInfo: { dhcpFormOpen: true, dhcpForm: { name: '设备', ip: '192.168.100.11', mac: 'aa:bb:cc:dd:ee:01' } },
    });
    const fn = makeMethod('saveDhcpHost', api, unwrap, fakeWindow);
    if (fn) {
      await fn.call(self);
      check('重载失败 ⇒ 提示里写明「已保存」',
        /已保存/.test(self.deviceInfo.dhcpFormError),
        JSON.stringify(self.deviceInfo.dhcpFormError));
      check('重载失败 ⇒ 提示里带后端的原话',
        self.deviceInfo.dhcpFormError.includes('绑定已写入'),
        self.deviceInfo.dhcpFormError);
    }
  }

  // ── C3. 后端报错 ⇒ 原样显示后端的话，不自己编 ────────────
  {
    const api = makeApi({
      post: () => { const e = new Error('MAC aa:bb:cc:dd:ee:01 已经绑在「nas」上了，不能绑两次'); throw e; },
    });
    const self = makeSelf(api, {
      deviceInfo: { dhcpFormOpen: true, dhcpForm: { name: '设备', ip: '192.168.100.11', mac: 'aa:bb:cc:dd:ee:01' } },
    });
    const fn = makeMethod('saveDhcpHost', api, unwrap, fakeWindow);
    if (fn) {
      await fn.call(self);
      check('后端报错 ⇒ 显示后端的消息',
        self.deviceInfo.dhcpFormError.includes('不能绑两次'),
        JSON.stringify(self.deviceInfo.dhcpFormError));
      check('后端报错 ⇒ 表单还开着（让用户能改）',
        self.deviceInfo.dhcpFormOpen === true);
    }
  }

  sec('D. 行为：自动刷新不能冲掉表单');

  {
    const api = makeApi({
      get: () => ({ success: true, data: { hostname: 'OpenWrt', neighbors: [], connections: [], dhcp_hosts: [] } }),
    });
    const self = makeSelf(api, {
      deviceInfo: {
        publicIp: '203.0.113.45',
        dhcpFormOpen: true,
        dhcpForm: { name: '我的NAS', ip: '192.168.100.11', mac: 'aa:bb:cc:dd:ee:01' },
        dhcpFormError: '刚才那条提示',
      },
    });
    const fn = makeMethod('loadDeviceInfo', api, unwrap, fakeWindow);
    check('loadDeviceInfo 方法能抽出来并执行', !!fn);
    if (fn) {
      await fn.call(self, true);
      check('刷新后公网 IP 还在（不该每次重问外网）',
        self.deviceInfo.publicIp === '203.0.113.45',
        JSON.stringify(self.deviceInfo.publicIp));
      check('刷新后表单内容还在',
        self.deviceInfo.dhcpForm.name === '我的NAS'
        && self.deviceInfo.dhcpForm.ip === '192.168.100.11'
        && self.deviceInfo.dhcpForm.mac === 'aa:bb:cc:dd:ee:01',
        JSON.stringify(self.deviceInfo.dhcpForm));
      check('刷新后表单仍是打开状态',
        self.deviceInfo.dhcpFormOpen === true);
      check('刷新后错误提示还在',
        self.deviceInfo.dhcpFormError === '刚才那条提示',
        JSON.stringify(self.deviceInfo.dhcpFormError));
      check('刷新后数据确实换了新的',
        self.deviceInfo.data && self.deviceInfo.data.hostname === 'OpenWrt',
        JSON.stringify(self.deviceInfo.data));
    }
  }

  sec('E. 静态契约');

  check('api 对象有 delete 方法（不是 del）',
    /^\s*delete\s*\(url\)\s*\{/m.test(APP_JS));
  check('没有用 api.del（不存在这个方法）',
    !/api\.del\(/.test(APP_JS));
  check('前端调用的是 /api/system/dhcp-hosts',
    /\/api\/system\/dhcp-hosts/.test(APP_JS));
  check('公网 IP 是按需查询（带 public_ip=1）',
    /\/api\/system\/info\?public_ip=1/.test(APP_JS));
  check('普通刷新不带 public_ip（不随刷新问外网）',
    /api\.get\('\/api\/system\/info'\)/.test(APP_JS));

  console.log('\n' + '='.repeat(60));
  console.log('  通过 ' + PASS.length + ' / 失败 ' + FAIL.length);
  if (FAIL.length) console.log('  失败项: ' + JSON.stringify(FAIL));
  console.log('='.repeat(60));
  process.exit(FAIL.length ? 1 : 0);
})();
