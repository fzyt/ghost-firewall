/* 登出 / 会话过期后，凭据必须真的从浏览器里消失（P2-20）
 *
 * 运行: node tests/test_frontend_credential_clear.js
 *
 * 背景
 * ----
 * 面板的 Alpine state 里存着这些凭据：
 *   · aliyun.accessKeySecret            —— 阿里云 AccessKey secret
 *   · ddns.services[].password           —— DDNS 服务商口令
 *   · networkConfig.wan_pppoe_password   —— PPPoE 宽带口令
 *   · rp.dnsCredentials                  —— 反代用的 DNS 服务商 token
 *   · config                             —— 整份防火墙配置
 *
 * 原来的 doLogout() / handleAuthExpired() 只清了 config 和 rp，
 * **漏了 aliyun / ddns / networkConfig**。
 *
 * 漏掉的后果不是「页面上少显示几个字」：这些值还在 Alpine state 里，
 * 就还在 DOM 的 input value 里 —— 共享电脑上的下一个使用者按一下方向键
 * 就能翻出来，或者直接在控制台里 Alpine.$data 一眼看全。
 * 「登出」必须真的把凭据从浏览器里抹掉，不能只是把界面盖住。
 *
 * 为什么这个测试要**执行**代码而不是匹配文本
 * -----------------------------------------
 * 文本匹配只能证明「代码里写了 clearSensitiveState()」，
 * 证明不了「它真的把 aliyun.accessKeySecret 清空了」。
 * 所以这里把方法体抽出来、在一个假的 this 上**真跑一遍**，
 * 再看凭据到底还在不在。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.dirname(__dirname);
const APP_JS = fs.readFileSync(path.join(ROOT, 'frontend', 'app.js'), 'utf8');

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
 */
function extractMethod(src, name) {
  const re = new RegExp('(?:async\\s+)?' + name + '\\s*\\([^)]*\\)\\s*\\{');
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

function buildFakeThis() {
  return {
    auth: { authenticated: true, loginPassword: 'typed-password' },
    config: { lan_subnet4: '192.168.100.0/24' },
    rp: { rules: [{ name: 'x' }], certificates: [{ id: 'cert_1' }],
          settings: { cookie_domain: '.fzyto.top' },
          dnsCredentials: { token: 'DNS-TOKEN' } },
    aliyun: {
      installed: true, configured: true,
      accessKeyId: 'AKID', accessKeySecret: 'AK-SECRET',
      regionId: 'cn-hangzhou', domain: 'fzyto.top',
      records: [{ rr: 'x' }], localRecords: [], ipv6Sources: [], loading: false,
    },
    ddns: { services: [{ name: 'svc1', username: 'u', password: 'DDNS-PW',
                         param_enc: 'ENC-BLOB' }] },
    networkConfig: { wan_pppoe_username: 'user@isp', wan_pppoe_password: 'PPPOE-PW' },
    pwModal: { show: true, old_password: 'OLD', new_password: 'NEW',
               confirm_password: 'NEW', loading: false, error: '' },
  };
}

function freshState() {
  return buildFakeThis();
}

console.log('='.repeat(66));
console.log('登出/会话过期后凭据必须真的被清掉（P2-20）');
console.log('='.repeat(66));

sec('1. clearSensitiveState 存在且真的清了凭据');

const body = extractMethod(APP_JS, 'clearSensitiveState');
check('能从 app.js 里抽出 clearSensitiveState 方法体', body !== null);
if (body === null) {
  console.log('\n 合计: ✅ ' + PASS.length + '   ❌ ' + FAIL.length);
  process.exit(1);
}

const fn = new Function('return function() {' + body + '}')();

const st = freshState();
fn.call(st);

check('config 被清空', st.config && Object.keys(st.config).length === 0,
  JSON.stringify(st.config));
check('rp 被清空（含 dnsCredentials）',
  st.rp && Array.isArray(st.rp.rules) && st.rp.rules.length === 0
  && Array.isArray(st.rp.certificates) && st.rp.certificates.length === 0
  && st.rp.settings && Object.keys(st.rp.settings).length === 0
  && !st.rp.dnsCredentials,
  JSON.stringify(st.rp));
check('阿里云 AccessKey secret 被清空',
  st.aliyun.accessKeySecret === '', JSON.stringify(st.aliyun.accessKeySecret));
check('阿里云 AccessKey id 被清空',
  st.aliyun.accessKeyId === '', JSON.stringify(st.aliyun.accessKeyId));
check('DDNS 服务口令被清空',
  st.ddns.services.every(s => !s.password), JSON.stringify(st.ddns.services));
check('DDNS 加密凭据块被清空',
  st.ddns.services.every(s => !s.param_enc), JSON.stringify(st.ddns.services));
check('PPPoE 宽带口令被清空',
  st.networkConfig.wan_pppoe_password === '',
  JSON.stringify(st.networkConfig.wan_pppoe_password));
check('改密码弹窗里的三个口令被清空',
  st.pwModal.old_password === '' && st.pwModal.new_password === ''
  && st.pwModal.confirm_password === '',
  JSON.stringify(st.pwModal));

sec('2. 两个出口都调用了它');

// 出口的行为由上面的「真跑一遍」保证；这里只验证**接线**没漏。
const logoutBody = extractMethod(APP_JS, 'doLogout') || '';
const expiredBody = extractMethod(APP_JS, 'handleAuthExpired') || '';
check('doLogout 调用了 clearSensitiveState',
  /clearSensitiveState\s*\(\s*\)/.test(logoutBody));
check('handleAuthExpired 调用了 clearSensitiveState',
  /clearSensitiveState\s*\(\s*\)/.test(expiredBody));

sec('3. 出口本身仍然把「已登录」置否');

const logoutSrc = APP_JS.slice(APP_JS.indexOf('async doLogout('),
  APP_JS.indexOf('async doLogout(') + 400);
check('doLogout 把 auth.authenticated 置为 false',
  /authenticated\s*=\s*false/.test(logoutSrc));
check('handleAuthExpired 把 auth.authenticated 置为 false',
  /authenticated\s*=\s*false/.test(expiredBody));

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
